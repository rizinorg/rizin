#ifndef RZ_CRYPTO_H
#define RZ_CRYPTO_H

#include <rz_types.h>
#include <rz_util/ht_sp.h>
#include <rz_crypto/rz_des.h>

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

/* Defines in which direction the set_key methods needs to run */
enum {
	RZ_CRYPTO_DIR_ENCRYPT = 0,
	RZ_CRYPTO_DIR_DECRYPT,
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
	HtSP /*<RzCryptoPlugin *>*/ *plugins;
} RzCrypto;

typedef struct rz_crypto_plugin_t {
	const char *name;
	const char *license;
	const char *author;
	int (*get_key_size)(RzCrypto *cry);
	bool (*set_iv)(RzCrypto *cry, const ut8 *iv, int ivlen);
	bool (*set_key)(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction);
	bool (*update)(RzCrypto *cry, const ut8 *buf, int len);
	bool (*final)(RzCrypto *cry, const ut8 *buf, int len);
	bool (*use)(const char *algo);
	bool (*init)(RzCrypto *cry);
	bool (*fini)(RzCrypto *cry);
} RzCryptoPlugin;

typedef ut64 RzCryptoSelector;

#ifdef RZ_API
RZ_API bool rz_crypto_plugin_add(RZ_NONNULL RzCrypto *cry, RZ_NONNULL RzCryptoPlugin *h);
RZ_API bool rz_crypto_plugin_del(RZ_NONNULL RzCrypto *cry, RZ_NONNULL RzCryptoPlugin *h);
RZ_API RZ_OWN RzCrypto *rz_crypto_new(void);
RZ_API void rz_crypto_free(RZ_NULLABLE RzCrypto *cry);
RZ_API void rz_crypto_reset(RZ_NONNULL RzCrypto *cry);
RZ_API bool rz_crypto_use(RZ_NONNULL RzCrypto *cry, RZ_NONNULL const char *algo);
RZ_API bool rz_crypto_set_key(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *key, int keylen, int mode, int direction);
RZ_API bool rz_crypto_set_iv(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *iv, int ivlen);
RZ_API int rz_crypto_update(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *buf, int len);
RZ_API int rz_crypto_final(RZ_NULLABLE RzCrypto *cry, RZ_NULLABLE const ut8 *buf, int len);
RZ_API int rz_crypto_append(RZ_NONNULL RzCrypto *cry, RZ_NONNULL const ut8 *buf, int len);
RZ_API RZ_BORROW const ut8 *rz_crypto_get_output(RZ_NONNULL RzCrypto *cry, RZ_NULLABLE int *size);
RZ_API RZ_BORROW const char *rz_crypto_name(const RzCryptoSelector bit);
RZ_API RZ_BORROW const char *rz_crypto_codec_name(const RzCryptoSelector bit);
RZ_API RZ_BORROW const RzCryptoPlugin *rz_crypto_plugin_by_index(RZ_NONNULL RzCrypto *cry, size_t index);
#endif

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
#define RZ_CRYPTO_SM4_ECB  1ULL << 13
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
