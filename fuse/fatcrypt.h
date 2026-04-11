#ifndef FATCRYPT_H
#define FATCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FATCRYPT_MAGIC "FATCRYPT"
#define FATCRYPT_VERSION 0x01

// file encryption
#define FATCRYPT_NONCE_SIZE 12       // 96 bits for GCM
#define FATCRYPT_TAG_SIZE 16         // 128 bits for GCM
#define FATCRYPT_UUID_SIZE 16        // 128 bits

// key derivation for master key password
#define FATCRYPT_HASH_ALG WC_SHA256
#define FATCRYPT_3DS_ITERATIONS 1500
#define FATCRYPT_ITERATIONS 100000
#define FATCRYPT_SALT_SIZE 16        // 128 bits for pbkdf2

#define CHACHA20_POLY1305_AEAD_NONCE_SIZE 12
#define CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 16
#define CHACHA20_POLY1305_AEAD_KEYSIZE 32

// Master key blob magic
#define FATCRYPT_MASTER_MAGIC "FCMASTER"
#define FATCRYPT_MASTER_VERSION 0x01

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

// Configuration management
int fatcrypt_load_config(const char *mountpoint_dir, fatcrypt_config_t *config);
void fatcrypt_free_config(fatcrypt_config_t *config);
int fatcrypt_sign_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size);
int fatcrypt_verify_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size);

// Path checking
int fatcrypt_is_plaintext_path(const char *path, const fatcrypt_plaintext_t *plaintext);
int fatcrypt_is_metadata_path(const char *path);

// Master key management
int fatcrypt_keygen(const fatcrypt_keygen_config_t *config);
int fatcrypt_load_master_key(const char *master_key_path, const char *passphrase,
                              fatcrypt_config_t *config,
                              uint8_t *master_key_out, size_t key_size);

// File / block encryption management
int fatcrypt_derive_file_key(const uint8_t *master_key, size_t master_key_size,
                              const uint8_t *file_uuid, size_t uuid_size,
                              uint8_t *file_key_out, size_t file_key_size);
void fatcrypt_derive_file_nonce(uint32_t sclust, uint8_t *nonce_out);
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
