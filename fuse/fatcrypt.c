#include "fatcrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <json-c/json.h>
#include <fnmatch.h>
#include <sodium.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/blake2-impl.h>

// Normalize a path by resolving . and .. components
// Returns 0 on success, -1 on error (path traversal above root)
static int normalize_path(const char *path, char *normalized, size_t normalized_size) {
	if (!path || !normalized || normalized_size == 0) {
		return -1;
	}

	// Handle absolute vs relative paths
	int is_absolute = (path[0] == '/');
	const char *p = is_absolute ? path + 1 : path;

	// Stack to track path components
	char *components[256];
	int component_count = 0;

	// Temporary buffer for component extraction
	char component[256];
	size_t comp_idx = 0;

	while (*p) {
		if (*p == '/') {
			// End of component
			if (comp_idx > 0) {
				component[comp_idx] = '\0';

				if (strcmp(component, ".") == 0) {
					// Skip current directory
				} else if (strcmp(component, "..") == 0) {
					// Parent directory
					if (component_count > 0) {
						// Pop the last component
						free(components[--component_count]);
					} else if (is_absolute) {
						// Trying to go above root
						for (int i = 0; i < component_count; i++) {
							free(components[i]);
						}
						return -1;
					}
					// For relative paths, we can't go below starting point safely
				} else {
					// Regular component
					components[component_count++] = strdup(component);
					if (component_count >= 256) {
						// Too many path components
						for (int i = 0; i < component_count; i++) {
							free(components[i]);
						}
						return -1;
					}
				}
				comp_idx = 0;
			}
			p++;
		} else {
			if (comp_idx < sizeof(component) - 1) {
				component[comp_idx++] = *p;
			}
			p++;
		}
	}

	// Handle last component
	if (comp_idx > 0) {
		component[comp_idx] = '\0';
		if (strcmp(component, ".") == 0) {
			// Skip
		} else if (strcmp(component, "..") == 0) {
			if (component_count > 0) {
				free(components[--component_count]);
			} else if (is_absolute) {
				for (int i = 0; i < component_count; i++) {
					free(components[i]);
				}
				return -1;
			}
		} else {
			components[component_count++] = strdup(component);
		}
	}

	// Build normalized path
	size_t offset = 0;
	if (is_absolute) {
		if (offset < normalized_size - 1) {
			normalized[offset++] = '/';
		}
	}

	for (int i = 0; i < component_count; i++) {
		size_t len = strlen(components[i]);
		if (offset + len + (i < component_count - 1 ? 1 : 0) >= normalized_size) {
			// Not enough space
			for (int j = 0; j < component_count; j++) {
				free(components[j]);
			}
			return -1;
		}
		memcpy(normalized + offset, components[i], len);
		offset += len;
		if (i < component_count - 1) {
			normalized[offset++] = '/';
		}
		free(components[i]);
	}

	normalized[offset] = '\0';

	// Handle root or empty path
	if (offset == 0) {
		if (is_absolute) {
			if (normalized_size < 2) return -1;
			normalized[0] = '/';
			normalized[1] = '\0';
		} else {
			if (normalized_size < 2) return -1;
			normalized[0] = '.';
			normalized[1] = '\0';
		}
	}

	return 0;
}

// Check if a path is under .fat_crypt directory
// Returns 1 if yes, 0 if no, -1 on error
int fatcrypt_is_metadata_path(const char *path) {
	if (!path) {
		return -1;
	}

	// Normalize the path
	char normalized[1024];
	if (normalize_path(path, normalized, sizeof(normalized)) != 0) {
		return -1;
	}

	// Check if path starts with /.fat_crypt/ or is /.fat_crypt
	const char *check_path = normalized;
	if (check_path[0] == '/') {
		check_path++;
	}

	// Check for exact match or prefix match with /
	if (strcmp(check_path, ".fat_crypt") == 0) {
		return 1;
	}

	const char *prefix = ".fat_crypt/";
	size_t prefix_len = strlen(prefix);
	if (strncmp(check_path, prefix, prefix_len) == 0) {
		return 1;
	}

	return 0;
}

int fatcrypt_read_random_bytes(uint8_t *key_out, size_t key_size) {
	FILE *urandom = fopen("/dev/urandom", "rb");
	if (!urandom) {
		fprintf(stderr, "Failed to open /dev/urandom: %s\n", strerror(errno));
		return -1;
	}

	size_t bytes_read = fread(key_out, 1, key_size, urandom);
	fclose(urandom);

	if (bytes_read != key_size) {
		fprintf(stderr, "Failed to read enough random bytes\n");
		return -1;
	}

	return 0;
}

// Generate a random master key using /dev/urandom
int fatcrypt_generate_master_key(uint8_t *key_out, size_t key_size) {
	return fatcrypt_read_random_bytes(key_out, key_size);
}

// Generate a random UUID (version 4)
int fatcrypt_generate_uuid(uint8_t *uuid_out) {
	if (fatcrypt_read_random_bytes(uuid_out, FATCRYPT_UUID_SIZE) != 0) {
		return -1;
	}

	// Set version 4 (random) and variant bits
	uuid_out[6] = (uuid_out[6] & 0x0F) | 0x40;  // Version 4
	uuid_out[8] = (uuid_out[8] & 0x3F) | 0x80;  // Variant 10

	return 0;
}

// Read passphrase from terminal without echoing
static int read_passphrase(char *buf, size_t bufsize, const char *prompt) {
	struct termios old_term, new_term;
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) {
		fprintf(stderr, "Failed to open /dev/tty: %s\n", strerror(errno));
		return -1;
	}

	fprintf(tty, "%s", prompt);
	fflush(tty);

	// Disable echo
	if (tcgetattr(fileno(tty), &old_term) != 0) {
		fclose(tty);
		return -1;
	}
	new_term = old_term;
	new_term.c_lflag &= ~ECHO;
	if (tcsetattr(fileno(tty), TCSANOW, &new_term) != 0) {
		fclose(tty);
		return -1;
	}

	// Read password
	char *result = fgets(buf, bufsize, tty);

	// Restore terminal
	tcsetattr(fileno(tty), TCSANOW, &old_term);
	fprintf(tty, "\n");
	fclose(tty);

	if (!result) {
		return -1;
	}

	// Remove trailing newline
	size_t len = strlen(buf);
	if (len > 0 && buf[len-1] == '\n') {
		buf[len-1] = '\0';
	}

	return 0;
}

// Create directory if it doesn't exist
static int mkdir_p(const char *path) {
	struct stat st;
	if (stat(path, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			return 0;  // Already exists
		}
		fprintf(stderr, "%s exists but is not a directory\n", path);
		return -1;
	}

	if (mkdir(path, 0755) != 0) {
		fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}

// Write a JSON file
static int write_json_file(const char *path, const char *content) {
	FILE *f = fopen(path, "w");
	if (!f) {
		fprintf(stderr, "Failed to create %s: %s\n", path, strerror(errno));
		return -1;
	}

	size_t len = strlen(content);
	if (fwrite(content, 1, len, f) != len) {
		fprintf(stderr, "Failed to write to %s: %s\n", path, strerror(errno));
		fclose(f);
		return -1;
	}

	if (fclose(f) != 0) {
		fprintf(stderr, "Failed to close %s: %s\n", path, strerror(errno));
		return -1;
	}

	return 0;
}

static int store_master_key(const char *path, const uint8_t *key, size_t key_size,
                            const char *passphrase, unsigned long long iterations) {
	FILE *f = fopen(path, "wb");
	if (!f) {
		fprintf(stderr, "Failed to create master key file %s: %s\n", path, strerror(errno));
		return -1;
	}

	// Write magic
	if (fwrite(FATCRYPT_MASTER_MAGIC, 1, 8, f) != 8) {
		goto write_err;
	}

	// Write version
	uint8_t version = FATCRYPT_MASTER_VERSION;
	if (fwrite(&version, 1, 1, f) != 1) {
		goto write_err;
	}

	// Write encrypted flag (0 = plaintext, 1 = encrypted)
	uint8_t encrypted = (passphrase != NULL && strlen(passphrase) > 0) ? 1 : 0;
	if (fwrite(&encrypted, 1, 1, f) != 1) {
		goto write_err;
	}

	if (encrypted) {
		uint8_t salt[FATCRYPT_SALT_SIZE];
		uint8_t derived_key[FATCRYPT_MASTER_KEY_SIZE];

		// Generate random salt
		fatcrypt_read_random_bytes(salt, sizeof(salt));

		if (wc_PBKDF2(derived_key, (const unsigned char *)passphrase, strlen(passphrase),
		                  salt, sizeof(salt), iterations, FATCRYPT_MASTER_KEY_SIZE, FATCRYPT_HASH_ALG) != 0) {
			fprintf(stderr, "PBKDF2 key derivation failed\n");
			fclose(f);
			unlink(path);
			return -1;
		}

		// Write salt
		if (fwrite(salt, 1, sizeof(salt), f) != sizeof(salt)) {
			goto write_err;
		}

		// Encrypt master key with derived key using crypto_secretbox (XSalsa20-Poly1305)
		uint8_t nonce[crypto_secretbox_NONCEBYTES];
		fatcrypt_read_random_bytes(nonce, sizeof(nonce));

		uint8_t ciphertext[crypto_secretbox_MACBYTES + key_size];
		if (crypto_secretbox_easy(ciphertext, key, key_size, nonce, derived_key) != 0) {
			fprintf(stderr, "Encryption failed\n");
			secure_zero_memory(derived_key, sizeof(derived_key));
			fclose(f);
			unlink(path);
			return -1;
		}

		secure_zero_memory(derived_key, sizeof(derived_key));

		// Write nonce
		if (fwrite(nonce, 1, sizeof(nonce), f) != sizeof(nonce)) {
			goto write_err;
		}

		// Write encrypted key size (original size, big-endian)
		uint8_t size_bytes[2] = {(key_size >> 8) & 0xFF, key_size & 0xFF};
		if (fwrite(size_bytes, 1, 2, f) != 2) {
			goto write_err;
		}

		// Write ciphertext (includes MAC)
		if (fwrite(ciphertext, 1, sizeof(ciphertext), f) != sizeof(ciphertext)) {
			goto write_err;
		}
	} else {
		// Store plaintext
		// Write key size
		uint8_t size_bytes[2] = {(key_size >> 8) & 0xFF, key_size & 0xFF};
		if (fwrite(size_bytes, 1, 2, f) != 2) {
			goto write_err;
		}

		// Write key
		if (fwrite(key, 1, key_size, f) != key_size) {
			goto write_err;
		}
	}

	if (fclose(f) != 0) {
		fprintf(stderr, "Failed to close master key file: %s\n", strerror(errno));
		return -1;
	}

	// Set restrictive permissions
	if (chmod(path, 0600) != 0) {
		fprintf(stderr, "Warning: Failed to set permissions on master key file: %s\n", strerror(errno));
	}

	return 0;

write_err:
	fprintf(stderr, "Failed to write master key file: %s\n", strerror(errno));
	fclose(f);
	unlink(path);
	return -1;
}

// Load config.json from mountpoint directory (for keygen)
int fatcrypt_load_config(const char *config_path, fatcrypt_config_t *config) {
	// Initialize plaintext arrays
	config->plaintext.files = NULL;
	config->plaintext.files_count = 0;
	config->plaintext.directories = NULL;
	config->plaintext.directories_count = 0;

	struct json_object *root = json_object_from_file(config_path);
	if (!root) {
		fprintf(stderr, "Failed to load config.json from %s\n", config_path);
		return -1;
	}

	// Parse version
	struct json_object *version_obj;
	if (!json_object_object_get_ex(root, "version", &version_obj)) {
		fprintf(stderr, "config.json missing 'version' field\n");
		json_object_put(root);
		return -1;
	}
	config->version = json_object_get_int(version_obj);

	// Parse kdf
	struct json_object *kdf_obj;
	if (!json_object_object_get_ex(root, "kdf", &kdf_obj)) {
		fprintf(stderr, "config.json missing 'kdf' field\n");
		json_object_put(root);
		return -1;
	}

	struct json_object *kdf_name_obj;
	if (!json_object_object_get_ex(kdf_obj, "name", &kdf_name_obj)) {
		fprintf(stderr, "config.json kdf missing 'name' field\n");
		json_object_put(root);
		return -1;
	}
	config->kdf.name = strdup(json_object_get_string(kdf_name_obj));

	struct json_object *iterations_obj;
	if (!json_object_object_get_ex(kdf_obj, "iterations", &iterations_obj)) {
		fprintf(stderr, "config.json kdf missing 'iterations' field\n");
		free(config->kdf.name);
		json_object_put(root);
		return -1;
	}
	config->kdf.iterations = json_object_get_uint64(iterations_obj);

	// Parse plaintext (optional)
	struct json_object *plaintext_obj;
	if (json_object_object_get_ex(root, "plaintext", &plaintext_obj)) {
		// Parse files array
		struct json_object *files_obj;
		if (json_object_object_get_ex(plaintext_obj, "files", &files_obj)) {
			if (json_object_is_type(files_obj, json_type_array)) {
				size_t n_files = json_object_array_length(files_obj);
				for (size_t i = 0; i < n_files; i++) {
					struct json_object *item = json_object_array_get_idx(files_obj, i);
					const char *filename = json_object_get_string(item);
					if (filename) {
						config->plaintext.files = realloc(config->plaintext.files,
							sizeof(char*) * (config->plaintext.files_count + 1));
						config->plaintext.files[config->plaintext.files_count++] = strdup(filename);
					}
				}
			}
		}

		// Parse directories array
		struct json_object *directories_obj;
		if (json_object_object_get_ex(plaintext_obj, "directories", &directories_obj)) {
			if (json_object_is_type(directories_obj, json_type_array)) {
				size_t n_dirs = json_object_array_length(directories_obj);
				for (size_t i = 0; i < n_dirs; i++) {
					struct json_object *item = json_object_array_get_idx(directories_obj, i);
					const char *dirname = json_object_get_string(item);
					if (dirname) {
						config->plaintext.directories = realloc(config->plaintext.directories,
							sizeof(char*) * (config->plaintext.directories_count + 1));
						config->plaintext.directories[config->plaintext.directories_count++] = strdup(dirname);
					}
				}
			}
		}
	}

	json_object_put(root);
	return 0;
}

// Free config structure
void fatcrypt_free_config(fatcrypt_config_t *config) {
	if (config->kdf.name) {
		free(config->kdf.name);
		config->kdf.name = NULL;
	}

	// Free plaintext arrays
	for (size_t i = 0; i < config->plaintext.files_count; i++) {
		free(config->plaintext.files[i]);
	}
	free(config->plaintext.files);

	for (size_t i = 0; i < config->plaintext.directories_count; i++) {
		free(config->plaintext.directories[i]);
	}
	free(config->plaintext.directories);

	config->plaintext.files = NULL;
	config->plaintext.files_count = 0;
	config->plaintext.directories = NULL;
	config->plaintext.directories_count = 0;
}

// Sign config.json with master key
int fatcrypt_sign_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size) {
	if (key_size != FATCRYPT_MASTER_KEY_SIZE) {
		fprintf(stderr, "Invalid key size for signing\n");
		return -1;
	}

	// Read config.json
	char config_path[1024];
	snprintf(config_path, sizeof(config_path), "%s/.fat_crypt/config.json", mountpoint_dir);

	FILE *f = fopen(config_path, "rb");
	if (!f) {
		fprintf(stderr, "Failed to open config.json for signing: %s\n", strerror(errno));
		return -1;
	}

	// Get file size
	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (file_size <= 0 || file_size > 1024 * 1024) {
		fprintf(stderr, "Invalid config.json file size\n");
		fclose(f);
		return -1;
	}

	// Read file contents
	uint8_t *config_data = malloc(file_size);
	if (!config_data) {
		fprintf(stderr, "Failed to allocate memory for config data\n");
		fclose(f);
		return -1;
	}

	if (fread(config_data, 1, file_size, f) != (size_t)file_size) {
		fprintf(stderr, "Failed to read config.json\n");
		free(config_data);
		fclose(f);
		return -1;
	}
	fclose(f);

	// Compute SHA256 hash
	uint8_t hash[WC_SHA256_DIGEST_SIZE];
	wc_Sha256Hash(config_data, file_size, hash);
	free(config_data);

	// Compute HMAC of the hash using master key
	uint8_t signature[crypto_auth_BYTES];
	crypto_auth(signature, hash, sizeof(hash), master_key);

	// Write signature to config.sig
	char sig_path[1024];
	snprintf(sig_path, sizeof(sig_path), "%s/.fat_crypt/config.sig", mountpoint_dir);

	FILE *sig_file = fopen(sig_path, "wb");
	if (!sig_file) {
		fprintf(stderr, "Failed to create config.sig: %s\n", strerror(errno));
		return -1;
	}

	if (fwrite(signature, 1, sizeof(signature), sig_file) != sizeof(signature)) {
		fprintf(stderr, "Failed to write signature\n");
		fclose(sig_file);
		unlink(sig_path);
		return -1;
	}

	fclose(sig_file);

	// Set restrictive permissions
	chmod(sig_path, 0600);

	return 0;
}

// Verify config.json signature
int fatcrypt_verify_config(const char *mountpoint_dir, const uint8_t *master_key, size_t key_size) {
	if (key_size != FATCRYPT_MASTER_KEY_SIZE) {
		fprintf(stderr, "Invalid key size for verification\n");
		return -1;
	}

	// Read config.json
	char config_path[1024];
	snprintf(config_path, sizeof(config_path), "%s/.fat_crypt/config.json", mountpoint_dir);

	FILE *f = fopen(config_path, "rb");
	if (!f) {
		fprintf(stderr, "Failed to open config.json for verification: %s\n", strerror(errno));
		return -1;
	}

	// Get file size
	fseek(f, 0, SEEK_END);
	long file_size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (file_size <= 0 || file_size > 1024 * 1024) {
		fprintf(stderr, "Invalid config.json file size\n");
		fclose(f);
		return -1;
	}

	// Read file contents
	uint8_t *config_data = malloc(file_size);
	if (!config_data) {
		fprintf(stderr, "Failed to allocate memory for config data\n");
		fclose(f);
		return -1;
	}

	if (fread(config_data, 1, file_size, f) != (size_t)file_size) {
		fprintf(stderr, "Failed to read config.json\n");
		free(config_data);
		fclose(f);
		return -1;
	}
	fclose(f);

	// Compute SHA256 hash
	uint8_t hash[WC_SHA256_DIGEST_SIZE];
	wc_Sha256Hash(config_data, file_size, hash);
	free(config_data);

	// Read signature from config.sig
	char sig_path[1024];
	snprintf(sig_path, sizeof(sig_path), "%s/.fat_crypt/config.sig", mountpoint_dir);

	FILE *sig_file = fopen(sig_path, "rb");
	if (!sig_file) {
		fprintf(stderr, "Failed to open config.sig for verification: %s\n", strerror(errno));
		return -1;
	}

	uint8_t signature[crypto_auth_BYTES];
	if (fread(signature, 1, sizeof(signature), sig_file) != sizeof(signature)) {
		fprintf(stderr, "Failed to read signature\n");
		fclose(sig_file);
		return -1;
	}
	fclose(sig_file);

	// Verify HMAC
	if (crypto_auth_verify(signature, hash, sizeof(hash), master_key) != 0) {
		fprintf(stderr, "Config signature verification failed - config may have been tampered with\n");
		return -1;
	}

	return 0;
}

int fatcrypt_load_master_key(const char *master_key_path, const char *passphrase,
                        fatcrypt_config_t *config,
                        uint8_t *key_out, size_t key_size) {
	if (key_size != FATCRYPT_MASTER_KEY_SIZE) {
		fprintf(stderr, "Invalid key size: %zu (expected %d)\n", key_size, FATCRYPT_MASTER_KEY_SIZE);
		return -1;
	}

	FILE *f = fopen(master_key_path, "rb");
	if (!f) {
		fprintf(stderr, "Failed to open master key file %s: %s\n", master_key_path, strerror(errno));
		return -1;
	}

	// Read and verify magic
	uint8_t magic[8];
	if (fread(magic, 1, 8, f) != 8 || memcmp(magic, FATCRYPT_MASTER_MAGIC, 8) != 0) {
		fprintf(stderr, "Invalid magic bytes in master key file\n");
		fclose(f);
		return -1;
	}

	// Read version
	uint8_t version;
	if (fread(&version, 1, 1, f) != 1) {
		fprintf(stderr, "Failed to read version from master key file\n");
		fclose(f);
		return -1;
	}

	// Read encrypted flag
	uint8_t encrypted;
	if (fread(&encrypted, 1, 1, f) != 1) {
		fprintf(stderr, "Failed to read encrypted flag from master key file\n");
		fclose(f);
		return -1;
	}

	if (!encrypted) {
		// Plaintext key - read size and key directly
		uint8_t size_bytes[2];
		if (fread(size_bytes, 1, 2, f) != 2) {
			fprintf(stderr, "Failed to read key size\n");
			fclose(f);
			return -1;
		}
		size_t stored_key_size = (size_bytes[0] << 8) | size_bytes[1];

		if (stored_key_size != key_size) {
			fprintf(stderr, "Key size mismatch: %zu != %zu\n", stored_key_size, key_size);
			fclose(f);
			return -1;
		}

		if (fread(key_out, 1, key_size, f) != key_size) {
			fprintf(stderr, "Failed to read key\n");
			fclose(f);
			return -1;
		}

		fclose(f);
		return 0;
	}

	// Encrypted key - need passphrase
	if (!passphrase || strlen(passphrase) == 0) {
		fprintf(stderr, "Master key is encrypted but no passphrase provided\n");
		fclose(f);
		return -1;
	}

	// Read salt
	uint8_t salt[crypto_pwhash_SALTBYTES];
	if (fread(salt, 1, sizeof(salt), f) != sizeof(salt)) {
		fprintf(stderr, "Failed to read salt\n");
		fclose(f);
		return -1;
	}

	// Read nonce
	uint8_t nonce[crypto_secretbox_NONCEBYTES];
	if (fread(nonce, 1, sizeof(nonce), f) != sizeof(nonce)) {
		fprintf(stderr, "Failed to read nonce\n");
		fclose(f);
		return -1;
	}

	// Read size
	uint8_t size_bytes[2];
	if (fread(size_bytes, 1, 2, f) != 2) {
		fprintf(stderr, "Failed to read key size\n");
		fclose(f);
		return -1;
	}
	size_t stored_key_size = (size_bytes[0] << 8) | size_bytes[1];

	if (stored_key_size != key_size) {
		fprintf(stderr, "Key size mismatch: %zu != %zu\n", stored_key_size, key_size);
		fclose(f);
		return -1;
	}

	// Read ciphertext
	uint8_t ciphertext[crypto_secretbox_MACBYTES + FATCRYPT_MASTER_KEY_SIZE];
	if (fread(ciphertext, 1, sizeof(ciphertext), f) != sizeof(ciphertext)) {
		fprintf(stderr, "Failed to read ciphertext\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	// Derive key from passphrase using config parameters
	uint8_t derived_key[crypto_secretbox_KEYBYTES];
	if (crypto_pwhash(derived_key, sizeof(derived_key),
	                  passphrase, strlen(passphrase),
	                  salt,
	                  config->kdf.iterations,
	                  config->kdf.iterations,
	                  config->kdf.iterations) != 0) {
		fprintf(stderr, "Key derivation failed (out of memory)\n");
		return -1;
	}

	// Decrypt master key
	if (crypto_secretbox_open_easy(key_out, ciphertext, sizeof(ciphertext),
	                                nonce, derived_key) != 0) {
		fprintf(stderr, "Decryption failed (wrong passphrase or corrupted data)\n");
		secure_zero_memory(derived_key, sizeof(derived_key));
		return -1;
	}

	secure_zero_memory(derived_key, sizeof(derived_key));
	return 0;
}

// Check if path matches plaintext patterns
int fatcrypt_is_plaintext_path(const char *path, const fatcrypt_plaintext_t *plaintext) {
	if (!path || !plaintext) {
		return 0;
	}

	// Skip leading slash for comparison
	const char *check_path = path;
	if (check_path[0] == '/') {
		check_path++;
	}

	// Check exact file matches
	for (size_t i = 0; i < plaintext->files_count; i++) {
		if (strcmp(check_path, plaintext->files[i]) == 0) {
			return 1;
		}
	}

	// Check if path is under any plaintext directory
	for (size_t i = 0; i < plaintext->directories_count; i++) {
		const char *dir = plaintext->directories[i];
		size_t dir_len = strlen(dir);

		// Remove trailing slash from directory pattern if present
		char dir_normalized[1024];
		strncpy(dir_normalized, dir, sizeof(dir_normalized) - 1);
		dir_normalized[sizeof(dir_normalized) - 1] = '\0';

		if (dir_len > 0 && dir_normalized[dir_len - 1] == '/') {
			dir_normalized[dir_len - 1] = '\0';
			dir_len--;
		}

		// Check if path starts with directory
		if (strncmp(check_path, dir_normalized, dir_len) == 0) {
			// Check if it's an exact match or path continues with /
			if (check_path[dir_len] == '\0' || check_path[dir_len] == '/') {
				return 1;
			}
		}
	}

	return 0;
}

// Derive per-file encryption key using HKDF-SHA256
// K_file = HKDF-SHA256(MK, info = "fatcrypt-file:" + UUID)
// Uses wolfSSL's wc_HKDF_Extract and wc_HKDF_Expand
int fatcrypt_derive_file_key(const uint8_t *master_key, size_t master_key_size,
                              const uint8_t *file_uuid, size_t uuid_size,
                              uint8_t *file_key_out, size_t file_key_size) {
	if (!master_key || !file_uuid || !file_key_out) {
		fprintf(stderr, "Invalid parameters for file key derivation\n");
		return -1;
	}

	if (master_key_size != FATCRYPT_MASTER_KEY_SIZE) {
		fprintf(stderr, "Invalid master key size: %zu (expected %d)\n",
		        master_key_size, FATCRYPT_MASTER_KEY_SIZE);
		return -1;
	}

	if (uuid_size != FATCRYPT_UUID_SIZE) {
		fprintf(stderr, "Invalid UUID size: %zu (expected %d)\n",
		        uuid_size, FATCRYPT_UUID_SIZE);
		return -1;
	}

	if (file_key_size != 32) {
		fprintf(stderr, "Invalid file key size: %zu (expected 32)\n", file_key_size);
		return -1;
	}

	// Build info string: "fatcrypt-file:" + UUID
	const char *prefix = "fatcrypt-file:";
	size_t prefix_len = strlen(prefix);
	size_t info_len = prefix_len + uuid_size;
	uint8_t *info = malloc(info_len);
	if (!info) {
		fprintf(stderr, "Failed to allocate memory for info string\n");
		return -1;
	}

	memcpy(info, prefix, prefix_len);
	memcpy(info + prefix_len, file_uuid, uuid_size);

	// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
	// For our use case: salt = NULL (use zeros), IKM = master_key
	uint8_t prk[WC_SHA256_DIGEST_SIZE];
	int ret = wc_HKDF_Extract(WC_HASH_TYPE_SHA256,
	                          NULL, 0,                    // No salt
	                          (byte*)master_key, master_key_size,  // IKM = master key
	                          prk);
	if (ret != 0) {
		fprintf(stderr, "HKDF-Extract failed: %d\n", ret);
		free(info);
		return -1;
	}

	// HKDF-Expand: OKM = HMAC-SHA256(PRK, info || counter)
	ret = wc_HKDF_Expand(WC_HASH_TYPE_SHA256,
	                     prk, sizeof(prk),                // PRK from extract
	                     info, info_len,                  // Info = "fatcrypt-file:" || UUID
	                     file_key_out, file_key_size);    // Output key
	if (ret != 0) {
		fprintf(stderr, "HKDF-Expand failed: %d\n", ret);
		free(info);
		memset(prk, 0, sizeof(prk));  // Clear sensitive data
		return -1;
	}

	// Clean up
	free(info);
	memset(prk, 0, sizeof(prk));  // Clear sensitive data

	return 0;
}

// Derive per-file nonce from starting cluster number
// TODO: implement nonce file for proper per-file nonces
// For now, use a fixed nonce (insecure but allows testing)
void fatcrypt_derive_file_nonce(uint32_t sclust, uint8_t *nonce_out) {
	(void)sclust;  // Unused for now
	memset(nonce_out, 0, 12);
}

// Write encrypted file header to buffer
// Returns the total header size, or -1 on error
int fatcrypt_write_header(uint8_t *buffer, size_t buffer_size,
                           const uint8_t *file_uuid, const uint8_t *nonce,
                           const uint8_t *aad, size_t aad_len) {
	if (!buffer || !file_uuid || !nonce) {
		fprintf(stderr, "Invalid parameters for write_header\n");
		return -1;
	}

	// Calculate total header size
	size_t header_size = 8 + 1 + 16 + 12 + 2 + aad_len;
	if (buffer_size < header_size) {
		fprintf(stderr, "Buffer too small for header: %zu < %zu\n", buffer_size, header_size);
		return -1;
	}

	if (aad_len > 65535) {
		fprintf(stderr, "AAD too large: %zu\n", aad_len);
		return -1;
	}

	size_t offset = 0;

	// Write magic
	memcpy(buffer + offset, FATCRYPT_MAGIC, 8);
	offset += 8;

	// Write version
	buffer[offset++] = FATCRYPT_VERSION;

	// Write UUID
	memcpy(buffer + offset, file_uuid, FATCRYPT_UUID_SIZE);
	offset += FATCRYPT_UUID_SIZE;

	// Write nonce
	memcpy(buffer + offset, nonce, FATCRYPT_NONCE_SIZE);
	offset += FATCRYPT_NONCE_SIZE;

	// Write AAD length (big-endian)
	buffer[offset++] = (aad_len >> 8) & 0xFF;
	buffer[offset++] = aad_len & 0xFF;

	// Write AAD if present
	if (aad && aad_len > 0) {
		memcpy(buffer + offset, aad, aad_len);
		offset += aad_len;
	}

	return (int)header_size;
}

// Read and parse encrypted file header from buffer
// Returns header size on success, -1 on error
int fatcrypt_read_header(const uint8_t *buffer, size_t buffer_size,
                          uint8_t *file_uuid_out, uint8_t *nonce_out,
                          size_t *header_size_out) {
	if (!buffer || !file_uuid_out || !nonce_out || !header_size_out) {
		fprintf(stderr, "Invalid parameters for read_header\n");
		return -1;
	}

	// Minimum header size without AAD
	size_t min_size = 8 + 1 + 16 + 12 + 2;
	if (buffer_size < min_size) {
		fprintf(stderr, "Buffer too small for header: %zu < %zu\n", buffer_size, min_size);
		return -1;
	}

	size_t offset = 0;

	// Verify magic
	if (memcmp(buffer + offset, FATCRYPT_MAGIC, 8) != 0) {
		fprintf(stderr, "Invalid magic bytes in file header\n");
		return -1;
	}
	offset += 8;

	// Verify version
	if (buffer[offset] != FATCRYPT_VERSION) {
		fprintf(stderr, "Unsupported version: 0x%02x\n", buffer[offset]);
		return -1;
	}
	offset++;

	// Read UUID
	memcpy(file_uuid_out, buffer + offset, FATCRYPT_UUID_SIZE);
	offset += FATCRYPT_UUID_SIZE;

	// Read nonce
	memcpy(nonce_out, buffer + offset, FATCRYPT_NONCE_SIZE);
	offset += FATCRYPT_NONCE_SIZE;

	// Read AAD length
	uint16_t aad_len = ((uint16_t)buffer[offset] << 8) | buffer[offset + 1];
	offset += 2;

	// Calculate total header size
	size_t header_size = min_size + aad_len;
	if (buffer_size < header_size) {
		fprintf(stderr, "Buffer too small for AAD: %zu < %zu\n", buffer_size, header_size);
		return -1;
	}

	*header_size_out = header_size;
	return 0;
}

// Verify file header magic and version
// Returns 0 if valid, -1 if invalid
int fatcrypt_verify_header(const uint8_t *buffer, size_t buffer_size) {
	if (!buffer || buffer_size < 9) {
		return -1;
	}

	// Check magic
	if (memcmp(buffer, FATCRYPT_MAGIC, 8) != 0) {
		return -1;
	}

	// Check version
	if (buffer[8] != FATCRYPT_VERSION) {
		return -1;
	}

	return 0;
}

// Encrypt a block of data using AES-256-GCM
// ciphertext_out must have space for plaintext_len bytes
// tag_out must have space for FATCRYPT_TAG_SIZE (16) bytes
int fatcrypt_encrypt_block(const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *ciphertext_out, uint8_t *tag_out) {
	if (!plaintext || !key || !nonce || !ciphertext_out || !tag_out) {
		fprintf(stderr, "Invalid parameters for encrypt_block\n");
		return -1;
	}

	if (key_len != 32) {
		fprintf(stderr, "Invalid key size for AES-256-GCM: %zu\n", key_len);
		return -1;
	}

	if (nonce_len != FATCRYPT_NONCE_SIZE) {
		fprintf(stderr, "Invalid nonce size: %zu (expected %d)\n", nonce_len, FATCRYPT_NONCE_SIZE);
		return -1;
	}

	Aes aes;
	int ret;

	// Initialize AES-GCM
	ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
	if (ret != 0) {
		fprintf(stderr, "wc_AesInit failed: %d\n", ret);
		return -1;
	}

	// Set key
	ret = wc_AesGcmSetKey(&aes, key, key_len);
	if (ret != 0) {
		fprintf(stderr, "wc_AesGcmSetKey failed: %d\n", ret);
		wc_AesFree(&aes);
		return -1;
	}

	// Encrypt
	ret = wc_AesGcmEncrypt(&aes, ciphertext_out, plaintext, plaintext_len,
	                       nonce, nonce_len, tag_out, FATCRYPT_TAG_SIZE,
	                       aad, aad_len);
	if (ret != 0) {
		fprintf(stderr, "wc_AesGcmEncrypt failed: %d\n", ret);
		wc_AesFree(&aes);
		return -1;
	}

	wc_AesFree(&aes);
	return 0;
}

// Decrypt a block of data using AES-256-GCM
// plaintext_out must have space for ciphertext_len bytes
// Returns 0 on success, -1 on failure (including auth tag mismatch)
int fatcrypt_decrypt_block(const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *tag,
                            uint8_t *plaintext_out) {
	if (!ciphertext || !key || !nonce || !tag || !plaintext_out) {
		fprintf(stderr, "Invalid parameters for decrypt_block\n");
		return -1;
	}

	if (key_len != 32) {
		fprintf(stderr, "Invalid key size for AES-256-GCM: %zu\n", key_len);
		return -1;
	}

	if (nonce_len != FATCRYPT_NONCE_SIZE) {
		fprintf(stderr, "Invalid nonce size: %zu (expected %d)\n", nonce_len, FATCRYPT_NONCE_SIZE);
		return -1;
	}

	Aes aes;
	int ret;

	// Initialize AES-GCM
	ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
	if (ret != 0) {
		fprintf(stderr, "wc_AesInit failed: %d\n", ret);
		return -1;
	}

	// Set key
	ret = wc_AesGcmSetKey(&aes, key, key_len);
	if (ret != 0) {
		fprintf(stderr, "wc_AesGcmSetKey failed: %d\n", ret);
		wc_AesFree(&aes);
		return -1;
	}

	// Decrypt and verify
	ret = wc_AesGcmDecrypt(&aes, plaintext_out, ciphertext, ciphertext_len,
	                       nonce, nonce_len, tag, FATCRYPT_TAG_SIZE,
	                       aad, aad_len);
	if (ret != 0) {
		fprintf(stderr, "wc_AesGcmDecrypt failed (auth tag mismatch or error): %d\n", ret);
		wc_AesFree(&aes);
		return -1;
	}

	wc_AesFree(&aes);
	return 0;
}

int fatcrypt_keygen(const fatcrypt_keygen_config_t *config) {
	char path_buf[1024];
	char master_key_path[1024];
	uint8_t master_key[FATCRYPT_MASTER_KEY_SIZE];
	char passphrase_buf[256] = {0};
	const char *passphrase = config->passphrase;

	printf("FatCrypt Key Generation\n");
	printf("=======================\n\n");

	// Prompt for passphrase if interactive and not provided
	if (config->interactive && !passphrase) {
		printf("A passphrase protects your master key.\n");
		printf("Leave empty to store the key without passphrase protection.\n\n");

		if (read_passphrase(passphrase_buf, sizeof(passphrase_buf), "Enter passphrase (optional): ") == 0) {
			if (strlen(passphrase_buf) > 0) {
				char confirm_buf[256];
				if (read_passphrase(confirm_buf, sizeof(confirm_buf), "Confirm passphrase: ") == 0) {
					if (strcmp(passphrase_buf, confirm_buf) == 0) {
						passphrase = passphrase_buf;
					} else {
						fprintf(stderr, "Passphrases do not match.\n");
						return -1;
					}
				}
				secure_zero_memory(confirm_buf, sizeof(confirm_buf));
			}
		}
	}

	// Generate master key
	printf("Generating master key...\n");
	if (fatcrypt_generate_master_key(master_key, FATCRYPT_MASTER_KEY_SIZE) != 0) {
		return -1;
	}

	// Create .fat_crypt directory structure
	printf("Creating .fat_crypt directory structure at %s...\n", config->mountpoint_dir);

	snprintf(path_buf, sizeof(path_buf), "%s/.fat_crypt", config->mountpoint_dir);
	if (mkdir_p(path_buf) != 0) {
		goto cleanup;
	}

	snprintf(path_buf, sizeof(path_buf), "%s/.fat_crypt/keys", config->mountpoint_dir);
	if (mkdir_p(path_buf) != 0) {
		goto cleanup;
	}

	snprintf(path_buf, sizeof(path_buf), "%s/.fat_crypt/meta", config->mountpoint_dir);
	if (mkdir_p(path_buf) != 0) {
		goto cleanup;
	}

	unsigned long long iterations = config->use_3ds_defaults ? FATCRYPT_3DS_ITERATIONS : FATCRYPT_ITERATIONS;

	printf("Writing config.json...\n");
	snprintf(path_buf, sizeof(path_buf), "%s/.fat_crypt/config.json", config->mountpoint_dir);

	// Build config.json using json-c
	struct json_object *root = json_object_new_object();
	json_object_object_add(root, "version", json_object_new_int(1));

	// Add KDF section
	struct json_object *kdf = json_object_new_object();
	json_object_object_add(kdf, "name", json_object_new_string("pbkdf2"));
	json_object_object_add(kdf, "iterations", json_object_new_uint64(iterations));
	json_object_object_add(root, "kdf", kdf);

	// Add plaintext section
	struct json_object *plaintext = json_object_new_object();
	struct json_object *files = json_object_new_array();
	struct json_object *directories = json_object_new_array();

	// Add 3DS defaults if requested
	if (config->use_3ds_defaults) {
		json_object_array_add(files, json_object_new_string("boot.firm"));
		json_object_array_add(files, json_object_new_string("kernel.bin"));
		json_object_array_add(directories, json_object_new_string("luma/payloads/"));
	}

	// Add user-specified plaintext files
	for (size_t i = 0; i < config->plaintext_files_count; i++) {
		json_object_array_add(files, json_object_new_string(config->plaintext_files[i]));
	}

	// Add user-specified plaintext directories
	for (size_t i = 0; i < config->plaintext_dirs_count; i++) {
		json_object_array_add(directories, json_object_new_string(config->plaintext_dirs[i]));
	}

	json_object_object_add(plaintext, "files", files);
	json_object_object_add(plaintext, "directories", directories);
	json_object_object_add(root, "plaintext", plaintext);

	// Write to file
	const char *config_json = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PRETTY);
	if (write_json_file(path_buf, config_json) != 0) {
		json_object_put(root);
		goto cleanup;
	}
	json_object_put(root);

	// Store master key at .fat_crypt/keys/master.blob
	snprintf(master_key_path, sizeof(master_key_path), "%s/.fat_crypt/keys/master.blob", config->mountpoint_dir);
	printf("Storing master key to %s...\n", master_key_path);
	if (store_master_key(master_key_path, master_key, FATCRYPT_MASTER_KEY_SIZE, passphrase, iterations) != 0) {
		goto cleanup;
	}

	// Sign config.json with master key
	printf("Signing config.json...\n");
	if (fatcrypt_sign_config(config->mountpoint_dir, master_key, FATCRYPT_MASTER_KEY_SIZE) != 0) {
		fprintf(stderr, "Failed to sign config.json\n");
		goto cleanup;
	}

	printf("\nKey generation completed successfully!\n");
	printf("\nIMPORTANT:\n");
	printf("  1. Back up your master key file: %s\n", master_key_path);
	printf("     Without this file, encrypted data cannot be recovered.\n");
	printf("     Store the backup in a secure location.\n");
	printf("  2. You MUST umount and re-mount this filesystem.\n");
	printf("     to load the generated key and encrypt newly written files.\n");

	// Clear sensitive data
	secure_zero_memory(master_key, sizeof(master_key));
	secure_zero_memory(passphrase_buf, sizeof(passphrase_buf));
	return 0;

cleanup:
	secure_zero_memory(master_key, sizeof(master_key));
	secure_zero_memory(passphrase_buf, sizeof(passphrase_buf));
	return -1;
}
