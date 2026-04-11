#ifndef FATCRYPT_H
#define FATCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
//#include <wolfssl/wolfcrypt/sha256.h>

#define FATCRYPT_MAGIC "FATCRYPT"
#define FATCRYPT_VERSION 0x01
#define FATCRYPT_MASTER_KEY_SIZE 32  // 256 bits
#define FATCRYPT_NONCE_SIZE 12       // 96 bits for GCM
#define FATCRYPT_TAG_SIZE 16         // 128 bits for GCM
#define FATCRYPT_UUID_SIZE 16        // 128 bits
#define FATCRYPT_SALT_SIZE 16        // 128 bits for Argon2
#define FATCRYPT_HASH_ALG WC_SHA256
#define FATCRYPT_3DS_ITERATIONS 1500
#define FATCRYPT_ITERATIONS 100000
#define FATCRYPT_KEY_NONCE_SIZE 24

// Master key blob magic
#define FATCRYPT_MASTER_MAGIC "FCMASTER"
#define FATCRYPT_MASTER_VERSION 0x01

// Structure for encrypted file header
typedef struct {
	uint8_t magic[8];           // "FATCRYPT"
	uint8_t version;            // 0x01
	uint8_t file_uuid[16];      // 128-bit UUID
	uint8_t nonce[12];          // 96-bit nonce for AES-GCM
	uint16_t aad_len;           // Length of AAD (big-endian)
	// Followed by AAD bytes, then ciphertext || tag
} __attribute__((packed)) fatcrypt_header_t;

// Keygen configuration
typedef struct {
	char *mountpoint_dir;       // Directory where .fat_crypt will be created
	char *passphrase;           // Optional passphrase (NULL if none)
	int interactive;            // Prompt for passphrase if true
	int use_3ds_defaults;       // Add 3DS-specific plaintext files
	char **plaintext_files;     // Array of plaintext file patterns
	size_t plaintext_files_count;
	char **plaintext_dirs;      // Array of plaintext directory patterns
	size_t plaintext_dirs_count;
} fatcrypt_keygen_config_t;

// KDF configuration from config.json
typedef struct {
	char *name;                 // KDF name (e.g., "argon2id")
	unsigned long long iterations;
} fatcrypt_kdf_config_t;

// Plaintext file/directory patterns
typedef struct {
	char **files;               // Array of file patterns
	size_t files_count;
	char **directories;         // Array of directory patterns
	size_t directories_count;
} fatcrypt_plaintext_t;

// Runtime configuration from config.json
typedef struct {
	int version;
	fatcrypt_kdf_config_t kdf;
	fatcrypt_plaintext_t plaintext;
} fatcrypt_config_t;

// Functions
int fatcrypt_keygen(const fatcrypt_keygen_config_t *config);
int fatcrypt_generate_master_key(uint8_t *key_out, size_t key_size);
int fatcrypt_generate_uuid(uint8_t *uuid_out);
int fatcrypt_is_metadata_path(const char *path);

// Configuration loading
int fatcrypt_load_config(const char *mountpoint_dir, fatcrypt_config_t *config);
void fatcrypt_free_config(fatcrypt_config_t *config);

// Configuration signing and verification
int fatcrypt_sign_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size);
int fatcrypt_verify_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size);

// Key derivation (helper function, not called yet)
int fatcrypt_derive_key(const char *mountpoint_dir, const char *passphrase,
                        uint8_t *key_out, size_t key_size);

// Path checking
int fatcrypt_is_plaintext_path(const char *path, const fatcrypt_plaintext_t *plaintext);

// Master key loading for FATFS structure (called after fuse layer verifies config)
// Loads master key from master.blob into the provided buffer
int fatcrypt_load_master_key(const char *master_key_path, const char *passphrase,
                              fatcrypt_config_t *config,
                              uint8_t *master_key_out, size_t key_size);

// Per-file key derivation using HKDF-SHA256
// Derives a per-file encryption key from master key and file UUID
// info = "fatcrypt-file:" + UUID
int fatcrypt_derive_file_key(const uint8_t *master_key, size_t master_key_size,
                              const uint8_t *file_uuid, size_t uuid_size,
                              uint8_t *file_key_out, size_t file_key_size);

// Derive nonce from starting cluster number
// Uses SHA256 to derive a deterministic 12-byte nonce
void fatcrypt_derive_file_nonce(uint32_t sclust, uint8_t *nonce_out);

// File header operations
int fatcrypt_write_header(uint8_t *buffer, size_t buffer_size,
                           const uint8_t *file_uuid, const uint8_t *nonce,
                           const uint8_t *aad, size_t aad_len);
int fatcrypt_read_header(const uint8_t *buffer, size_t buffer_size,
                          uint8_t *file_uuid_out, uint8_t *nonce_out,
                          size_t *header_size_out);
int fatcrypt_verify_header(const uint8_t *buffer, size_t buffer_size);

// AES-GCM encryption/decryption
int fatcrypt_encrypt_block(const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *ciphertext_out, uint8_t *tag_out);
int fatcrypt_decrypt_block(const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *tag,
                            uint8_t *plaintext_out);

#endif // FATCRYPT_H
