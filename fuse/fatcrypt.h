#ifndef FATCRYPT_H
#define FATCRYPT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef unsigned char	BYTE;

#define FATCRYPT_MAGIC "FATCRYPT"
#define FATCRYPT_VERSION 0x01

// key derivation for master key password
#define FATCRYPT_SALT_SIZE 16        // 128 bits for scrypt
// scrypt parameters for normal usage (moderate security)
#define FATCRYPT_SCRYPT_COST 15      // N = 2^15 = 32768
#define FATCRYPT_SCRYPT_BLOCK_SIZE 8 // r = 8
#define FATCRYPT_SCRYPT_PARALLEL 1   // p = 1
// scrypt parameters for 3DS (lower memory)
#define FATCRYPT_3DS_SCRYPT_COST 13  // N = 2^13 = 8192
#define FATCRYPT_3DS_SCRYPT_BLOCK_SIZE 8
#define FATCRYPT_3DS_SCRYPT_PARALLEL 1

// master key + file encryption
#define XCHACHA20_POLY1305_AEAD_NONCE_SIZE 24
#define XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE 16
#define XCHACHA20_POLY1305_AEAD_KEYSIZE 32

// Master key blob magic
#define FATCRYPT_MASTER_MAGIC "FCMASTER"
#define FATCRYPT_MASTER_VERSION 0x01

// File header [section (bytes)]
// [magic (8)][version (1)][logical size (8)][nonce (24)]
#define FATCRYPT_MAGIC_SIZE 8
#define FATCRYPT_VERSION_SIZE 1
#define FATCRYPT_LSIZE_SIZE 8

#define FATCRYPT_HEADER_SIZE 41

typedef struct {
	char magic[FATCRYPT_MAGIC_SIZE]; // FATCRYPT
	uint8_t version; // 0x01
	uint64_t logical_size; // should really be FSIZE_t but the largest that can be is QWORD and I don't want to deal with the header conflicts between fatfs and wolfcrypt
    BYTE base_nonce[XCHACHA20_POLY1305_AEAD_NONCE_SIZE];
} fatcrypt_header_t;

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
	char *name;                 // KDF name (e.g., "scrypt")
	int cost;                   // scrypt cost parameter (N = 2^cost)
	int blockSize;              // scrypt block size parameter (r)
	int parallel;               // scrypt parallelization parameter (p)
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
int fatcrypt_load_config(const void *buf, size_t buf_size, fatcrypt_config_t *config);
void fatcrypt_free_config(fatcrypt_config_t *config);
int fatcrypt_sign_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size);
int fatcrypt_verify_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size);

// Path checking
int fatcrypt_is_plaintext_path(const char *path, const fatcrypt_plaintext_t *plaintext);
int fatcrypt_is_metadata_path(const char *path);

// Master key management
int fatcrypt_keygen(const fatcrypt_keygen_config_t *config);
int fatcrypt_load_master_key(const void *buf, size_t buf_size, const char *passphrase,
                              fatcrypt_config_t *config,
                              uint8_t *master_key_out, size_t key_size);

// File / block encryption management
int fatcrypt_derive_file_key(const uint8_t *master_key, size_t master_key_size,
                              const uint8_t *file_nonce, size_t nonce_size,
                              uint8_t *file_key_out);
void fatcrypt_derive_block_nonce(const uint8_t *base_nonce, uint32_t block_idx, uint8_t *block_nonce_out);
int fatcrypt_encrypt_block(const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *ciphertext_out);
int fatcrypt_decrypt_block(const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *plaintext_out);

// misc
int fatcrypt_read_random_bytes(uint8_t *key_out, size_t key_size);

#endif // FATCRYPT_H
