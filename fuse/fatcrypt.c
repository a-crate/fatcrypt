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
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/blake2-impl.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

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

// Wrapper for encrypting disk keys with XChaCha20-Poly1305
// Output format: nonce (24 bytes) || ciphertext || mac (16 bytes)
int secretbox_easy(
    byte *out,
    const byte *plaintext, word32 plaintext_len,
    const byte *key
) {
    byte *nonce      = out;
    byte *ciphertext = out + XCHACHA20_POLY1305_AEAD_NONCE_SIZE;
    size_t ciphertext_len = plaintext_len + XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;

    if (fatcrypt_read_random_bytes(nonce, XCHACHA20_POLY1305_AEAD_NONCE_SIZE) != 0) {
	    return -1;
    }

    return wc_XChaCha20Poly1305_Encrypt(ciphertext, ciphertext_len,
										plaintext, plaintext_len,
                                        NULL, 0,
                                        nonce, XCHACHA20_POLY1305_AEAD_NONCE_SIZE,
                                        key, XCHACHA20_POLY1305_AEAD_KEYSIZE);
}

int secretbox_open_easy(
    byte *out,
    const byte *ciphertext, word32 ciphertext_len,
    const byte *key
) {
    const word32 overhead = XCHACHA20_POLY1305_AEAD_NONCE_SIZE + XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;
    if (ciphertext_len < overhead) return -1;

    const byte *nonce      = ciphertext;
    const byte *ctext      = ciphertext + XCHACHA20_POLY1305_AEAD_NONCE_SIZE;
    size_t      ctext_len  = ciphertext_len - XCHACHA20_POLY1305_AEAD_NONCE_SIZE;
    size_t        out_len  = ctext_len - XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE;

    return wc_XChaCha20Poly1305_Decrypt(out, out_len,
                                       ctext, ctext_len,
                                       NULL, 0,
                                       nonce, XCHACHA20_POLY1305_AEAD_NONCE_SIZE,
                                       key, XCHACHA20_POLY1305_AEAD_KEYSIZE);
}

static int store_master_key(const char *path, const uint8_t *key, size_t key_size,
                            const char *passphrase, int cost, int blockSize, int parallel) {
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
		uint8_t derived_key[XCHACHA20_POLY1305_AEAD_KEYSIZE];

		// Generate random salt
		if (fatcrypt_read_random_bytes(salt, sizeof(salt)) != 0){
			return -1;
		}

		if (wc_scrypt(derived_key, (const unsigned char *)passphrase, strlen(passphrase),
		              salt, sizeof(salt), cost, blockSize, parallel, XCHACHA20_POLY1305_AEAD_KEYSIZE) != 0) {
			fprintf(stderr, "scrypt key derivation failed\n");
			fclose(f);
			unlink(path);
			return -1;
		}

		// Write salt
		if (fwrite(salt, 1, sizeof(salt), f) != sizeof(salt)) {
			goto write_err;
		}

		// Write encrypted key size (original size, big-endian)
		uint8_t size_bytes[2] = {(key_size >> 8) & 0xFF, key_size & 0xFF};
		if (fwrite(size_bytes, 1, 2, f) != 2) {
			goto write_err;
		}

		// Encrypt key (output includes nonce + mac + ciphertext)
		uint8_t ciphertext[XCHACHA20_POLY1305_AEAD_NONCE_SIZE + XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE + key_size];
		if (secretbox_easy(ciphertext, key, key_size, derived_key) != 0) {
			fprintf(stderr, "Encryption failed\n");
			secure_zero_memory(derived_key, sizeof(derived_key));
			fclose(f);
			unlink(path);
			return -1;
		}

		secure_zero_memory(derived_key, sizeof(derived_key));

		// Write ciphertext (includes nonce + MAC + encrypted key)
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

// Load config from buffer
int fatcrypt_load_config(const void *buf, size_t buf_size, fatcrypt_config_t *config) {
	// Initialize plaintext arrays
	config->plaintext.files = NULL;
	config->plaintext.files_count = 0;
	config->plaintext.directories = NULL;
	config->plaintext.directories_count = 0;

	struct json_tokener *tok = json_tokener_new();
	if (!tok) {
		fprintf(stderr, "Failed to create JSON tokener\n");
		return -1;
	}

	struct json_object *root = json_tokener_parse_ex(tok, buf, buf_size);
	json_tokener_free(tok);
	if (!root) {
		fprintf(stderr, "Failed to parse config.json\n");
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

	struct json_object *cost_obj;
	if (!json_object_object_get_ex(kdf_obj, "cost", &cost_obj)) {
		fprintf(stderr, "config.json kdf missing 'cost' field\n");
		free(config->kdf.name);
		json_object_put(root);
		return -1;
	}
	config->kdf.cost = json_object_get_int(cost_obj);

	struct json_object *blockSize_obj;
	if (!json_object_object_get_ex(kdf_obj, "blockSize", &blockSize_obj)) {
		fprintf(stderr, "config.json kdf missing 'blockSize' field\n");
		free(config->kdf.name);
		json_object_put(root);
		return -1;
	}
	config->kdf.blockSize = json_object_get_int(blockSize_obj);

	struct json_object *parallel_obj;
	if (!json_object_object_get_ex(kdf_obj, "parallel", &parallel_obj)) {
		fprintf(stderr, "config.json kdf missing 'parallel' field\n");
		free(config->kdf.name);
		json_object_put(root);
		return -1;
	}
	config->kdf.parallel = json_object_get_int(parallel_obj);

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
	if (key_size != XCHACHA20_POLY1305_AEAD_KEYSIZE) {
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
	Hmac hmac;
	byte mac[WC_SHA256_DIGEST_SIZE];
	wc_HmacSetKey(&hmac, WC_SHA256, master_key, sizeof(master_key));
	wc_HmacUpdate(&hmac, hash, sizeof(hash));
	wc_HmacFinal(&hmac, mac);

	// Write signature to config.sig
	char sig_path[1024];
	snprintf(sig_path, sizeof(sig_path), "%s/.fat_crypt/config.sig", mountpoint_dir);

	FILE *sig_file = fopen(sig_path, "wb");
	if (!sig_file) {
		fprintf(stderr, "Failed to create config.sig: %s\n", strerror(errno));
		return -1;
	}

	if (fwrite(mac, 1, sizeof(mac), sig_file) != sizeof(mac)) {
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
	if (key_size != XCHACHA20_POLY1305_AEAD_KEYSIZE) {
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

	uint8_t signature[WC_SHA256_DIGEST_SIZE];
	if (fread(signature, 1, sizeof(signature), sig_file) != sizeof(signature)) {
		fprintf(stderr, "Failed to read signature\n");
		fclose(sig_file);
		return -1;
	}
	fclose(sig_file);

	// Verify HMAC
	Hmac hmac;
	byte expected[WC_SHA256_DIGEST_SIZE];
	wc_HmacSetKey(&hmac, WC_SHA256, master_key, sizeof(master_key));
	wc_HmacUpdate(&hmac, hash, sizeof(hash));
	wc_HmacFinal(&hmac, expected);

	if (memcmp(hash, expected, WC_SHA256_DIGEST_SIZE) != 0) {
		fprintf(stderr, "Config signature verification failed - config may have been tampered with\n");
		return -1;
	}

	return 0;
}

int fatcrypt_load_master_key(const void *buf, size_t buf_size, const char *passphrase,
                        fatcrypt_config_t *config,
                        uint8_t *key_out, size_t key_size) {
	if (key_size != XCHACHA20_POLY1305_AEAD_KEYSIZE) {
		fprintf(stderr, "Invalid key size: %zu (expected %d)\n", key_size, XCHACHA20_POLY1305_AEAD_KEYSIZE);
		return -1;
	}

	const uint8_t *p = buf;
	size_t remaining = buf_size;

	// Verify minimum size for header (magic + version + encrypted flag)
	if (remaining < 10) {
		fprintf(stderr, "Master key buffer too small\n");
		return -1;
	}

	// Read and verify magic
	if (memcmp(p, FATCRYPT_MASTER_MAGIC, 8) != 0) {
		fprintf(stderr, "Invalid magic bytes in master key\n");
		return -1;
	}
	p += 8;
	remaining -= 8;

	// Read version
	uint8_t version = *p++;
	remaining--;
	(void)version;

	// Read encrypted flag
	uint8_t encrypted = *p++;
	remaining--;

	if (!encrypted) {
		// Plaintext key - read size and key directly
		if (remaining < 2) {
			fprintf(stderr, "Master key buffer too small for size field\n");
			return -1;
		}
		size_t stored_key_size = (p[0] << 8) | p[1];
		p += 2;
		remaining -= 2;

		if (stored_key_size != key_size) {
			fprintf(stderr, "Key size mismatch: %zu != %zu\n", stored_key_size, key_size);
			return -1;
		}

		if (remaining < key_size) {
			fprintf(stderr, "Master key buffer too small for key\n");
			return -1;
		}

		memcpy(key_out, p, key_size);
		return 0;
	}

	// Encrypted key - need passphrase
	if (!passphrase || strlen(passphrase) == 0) {
		fprintf(stderr, "Master key is encrypted but no passphrase provided\n");
		return -1;
	}

	// Read salt
	if (remaining < FATCRYPT_SALT_SIZE) {
		fprintf(stderr, "Master key buffer too small for salt\n");
		return -1;
	}
	const uint8_t *salt = p;
	p += FATCRYPT_SALT_SIZE;
	remaining -= FATCRYPT_SALT_SIZE;

	// Read size
	if (remaining < 2) {
		fprintf(stderr, "Master key buffer too small for size field\n");
		return -1;
	}
	size_t stored_key_size = (p[0] << 8) | p[1];
	p += 2;
	remaining -= 2;

	if (stored_key_size != key_size) {
		fprintf(stderr, "Key size mismatch: %zu != %zu\n", stored_key_size, key_size);
		return -1;
	}

	// Read ciphertext (includes nonce + mac + encrypted key)
	size_t ciphertext_size = XCHACHA20_POLY1305_AEAD_NONCE_SIZE + XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE + XCHACHA20_POLY1305_AEAD_KEYSIZE;
	if (remaining < ciphertext_size) {
		fprintf(stderr, "Master key buffer too small for ciphertext\n");
		return -1;
	}
	const uint8_t *ciphertext = p;

	// Derive key from passphrase using config parameters
	uint8_t derived_key[XCHACHA20_POLY1305_AEAD_KEYSIZE];
	if (wc_scrypt(derived_key, (const unsigned char *)passphrase, strlen(passphrase),
	              salt, FATCRYPT_SALT_SIZE, config->kdf.cost, config->kdf.blockSize, config->kdf.parallel,
	              XCHACHA20_POLY1305_AEAD_KEYSIZE) != 0) {
		fprintf(stderr, "Key derivation failed\n");
		return -1;
	}

	// Decrypt master key
	if (secretbox_open_easy(key_out, ciphertext, ciphertext_size, derived_key) != 0) {
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

// Derive per-block nonce by XORing block index into last 4 bytes of base nonce
void fatcrypt_derive_block_nonce(const uint8_t *base_nonce, uint32_t block_idx, uint8_t *block_nonce_out) {
	memcpy(block_nonce_out, base_nonce, XCHACHA20_POLY1305_AEAD_NONCE_SIZE);
	block_nonce_out[20] ^= (block_idx >> 24) & 0xFF;
	block_nonce_out[21] ^= (block_idx >> 16) & 0xFF;
	block_nonce_out[22] ^= (block_idx >> 8) & 0xFF;
	block_nonce_out[23] ^= block_idx & 0xFF;
}

// Encrypt a block of data using XChaCha20-Poly1305
// ciphertext_out must have space for plaintext_len + XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE bytes
int fatcrypt_encrypt_block(const uint8_t *plaintext, size_t plaintext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *ciphertext_out) {
	if (!plaintext || !key || !nonce || !ciphertext_out) {
		fprintf(stderr, "Invalid parameters for encrypt_block\n");
		return -1;
	}

	return wc_XChaCha20Poly1305_Encrypt(
		ciphertext_out, plaintext_len + XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE,
		plaintext, plaintext_len,
		aad, aad_len,
		nonce, nonce_len,
		key, key_len
	);
}

// Decrypt a block of data using XChaCha20-Poly1305
// ciphertext_len includes the tag (plaintext will be ciphertext_len - XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE bytes)
int fatcrypt_decrypt_block(const uint8_t *ciphertext, size_t ciphertext_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *nonce, size_t nonce_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *plaintext_out) {
	if (!ciphertext || !key || !nonce || !plaintext_out) {
		fprintf(stderr, "Invalid parameters for decrypt_block\n");
		return -1;
	}

	return wc_XChaCha20Poly1305_Decrypt(
		plaintext_out, ciphertext_len - XCHACHA20_POLY1305_AEAD_AUTHTAG_SIZE,
		ciphertext, ciphertext_len,
		aad, aad_len,
		nonce, nonce_len,
		key, key_len
	);
}

int fatcrypt_keygen(const fatcrypt_keygen_config_t *config) {
	char path_buf[1024];
	char master_key_path[1024];
	uint8_t master_key[XCHACHA20_POLY1305_AEAD_KEYSIZE];
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
	if (fatcrypt_read_random_bytes(master_key, XCHACHA20_POLY1305_AEAD_KEYSIZE) != 0) {
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

	int cost = config->use_3ds_defaults ? FATCRYPT_3DS_SCRYPT_COST : FATCRYPT_SCRYPT_COST;
	int blockSize = config->use_3ds_defaults ? FATCRYPT_3DS_SCRYPT_BLOCK_SIZE : FATCRYPT_SCRYPT_BLOCK_SIZE;
	int parallel = config->use_3ds_defaults ? FATCRYPT_3DS_SCRYPT_PARALLEL : FATCRYPT_SCRYPT_PARALLEL;

	printf("Writing config.json...\n");
	snprintf(path_buf, sizeof(path_buf), "%s/.fat_crypt/config.json", config->mountpoint_dir);

	// Build config.json using json-c
	struct json_object *root = json_object_new_object();
	json_object_object_add(root, "version", json_object_new_int(1));

	// Add KDF section
	struct json_object *kdf = json_object_new_object();
	json_object_object_add(kdf, "name", json_object_new_string("scrypt"));
	json_object_object_add(kdf, "cost", json_object_new_int(cost));
	json_object_object_add(kdf, "blockSize", json_object_new_int(blockSize));
	json_object_object_add(kdf, "parallel", json_object_new_int(parallel));
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
	if (store_master_key(master_key_path, master_key, XCHACHA20_POLY1305_AEAD_KEYSIZE, passphrase, cost, blockSize, parallel) != 0) {
		goto cleanup;
	}

	// Sign config.json with master key
	printf("Signing config.json...\n");
	if (fatcrypt_sign_config(config->mountpoint_dir, master_key, XCHACHA20_POLY1305_AEAD_KEYSIZE) != 0) {
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
