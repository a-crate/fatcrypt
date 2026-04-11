#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* Minimal wolfSSL configuration for fatcrypt */

/* Features we need */
#define HAVE_HKDF
#define HAVE_PBKDF2
#define HAVE_AESGCM
#define HAVE_AES_DECRYPT
#define WOLFSSL_SHA256
#define HAVE_ARGON2

/* Features we don't need - disable to reduce code size */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_DH
#define NO_PSK
#define NO_OLD_TLS
#define NO_RSA
#define NO_DES3
#define NO_RABBIT
#define NO_HC128
#define NO_WRITEV

/* Hardening options for timing resistance / side-channel attack prevention */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#endif /* USER_SETTINGS_H */
