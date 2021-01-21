#ifndef RZ_CRYPTO_H
#define RZ_CRYPTO_H

#include "rz_types.h"
#include "rz_list.h"
#include "rz_crypto/rz_des.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_crypto);

enum {
	RZ_CRYPTO_MODE_ECB,
	RZ_CRYPTO_MODE_CBC,
	RZ_CRYPTO_MODE_OFB,
	RZ_CRYPTO_MODE_CFB,
};

enum {
	RZ_CRYPTO_DIR_CIPHER,
	RZ_CRYPTO_DIR_DECIPHER,
};

typedef struct rz_crypto_t {
	struct rz_crypto_plugin_t *h;
	ut8 *key;
	ut8 *iv;
	int key_len;
	ut8 *output;
	int output_len;
	int output_size;
	int dir;
	void *user;
	RzList *plugins;
} RzCrypto;

typedef struct rz_crypto_plugin_t {
	const char *name;
	const char *license;
	int (*get_key_size)(RzCrypto *cry);
	bool (*set_iv)(RzCrypto *cry, const ut8 *iv, int ivlen);
	bool (*set_key)(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction);
	bool (*update)(RzCrypto *cry, const ut8 *buf, int len);
	bool (*final)(RzCrypto *cry, const ut8 *buf, int len);
	bool (*use)(const char *algo);
	int (*fini)(RzCrypto *cry);
} RzCryptoPlugin;

typedef ut64 RzCryptoSelector;

#ifdef RZ_API
RZ_API RzCrypto *rz_crypto_init(RzCrypto *cry, int hard);
RZ_API RzCrypto *rz_crypto_as_new(RzCrypto *cry);
RZ_API int rz_crypto_add(RzCrypto *cry, RzCryptoPlugin *h);
RZ_API RzCrypto *rz_crypto_new(void);
RZ_API RzCrypto *rz_crypto_free(RzCrypto *cry);
RZ_API bool rz_crypto_use(RzCrypto *cry, const char *algo);
RZ_API bool rz_crypto_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction);
RZ_API bool rz_crypto_set_iv(RzCrypto *cry, const ut8 *iv, int ivlen);
RZ_API int rz_crypto_update(RzCrypto *cry, const ut8 *buf, int len);
RZ_API int rz_crypto_final(RzCrypto *cry, const ut8 *buf, int len);
RZ_API int rz_crypto_append(RzCrypto *cry, const ut8 *buf, int len);
RZ_API ut8 *rz_crypto_get_output(RzCrypto *cry, int *size);
RZ_API const char *rz_crypto_name(const RzCryptoSelector bit);
RZ_API const char *rz_crypto_codec_name(const RzCryptoSelector bit);
#endif

/* plugin pointers */
extern RzCryptoPlugin rz_crypto_plugin_aes;
extern RzCryptoPlugin rz_crypto_plugin_des;
extern RzCryptoPlugin rz_crypto_plugin_rc4;
extern RzCryptoPlugin rz_crypto_plugin_xor;
extern RzCryptoPlugin rz_crypto_plugin_blowfish;
extern RzCryptoPlugin rz_crypto_plugin_rc2;
extern RzCryptoPlugin rz_crypto_plugin_rot;
extern RzCryptoPlugin rz_crypto_plugin_rol;
extern RzCryptoPlugin rz_crypto_plugin_ror;
extern RzCryptoPlugin rz_crypto_plugin_base64;
extern RzCryptoPlugin rz_crypto_plugin_base91;
extern RzCryptoPlugin rz_crypto_plugin_aes_cbc;
extern RzCryptoPlugin rz_crypto_plugin_punycode;
extern RzCryptoPlugin rz_crypto_plugin_rc6;
extern RzCryptoPlugin rz_crypto_plugin_cps2;
extern RzCryptoPlugin rz_crypto_plugin_serpent;

#define RZ_CRYPTO_NONE     0ULL
#define RZ_CRYPTO_RC2      1ULL
#define RZ_CRYPTO_RC4      1ULL << 1
#define RZ_CRYPTO_RC6      1ULL << 2
#define RZ_CRYPTO_AES_ECB  1ULL << 3
#define RZ_CRYPTO_AES_CBC  1ULL << 4
#define RZ_CRYPTO_ROR      1ULL << 5
#define RZ_CRYPTO_ROL      1ULL << 6
#define RZ_CRYPTO_ROT      1ULL << 7
#define RZ_CRYPTO_BLOWFISH 1ULL << 8
#define RZ_CRYPTO_CPS2     1ULL << 9
#define RZ_CRYPTO_DES_ECB  1ULL << 10
#define RZ_CRYPTO_XOR      1ULL << 11
#define RZ_CRYPTO_SERPENT  1ULL << 12
#define RZ_CRYPTO_ALL      0xFFFF

#define RZ_CODEC_NONE     0ULL
#define RZ_CODEC_B64      1ULL
#define RZ_CODEC_B91      1ULL << 1
#define RZ_CODEC_PUNYCODE 1ULL << 2
#define RZ_CODEC_ALL      0xFFFF

#ifdef __cplusplus
}
#endif

#endif
