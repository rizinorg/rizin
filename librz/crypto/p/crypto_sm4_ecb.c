#include <rz_lib.h>
#include <rz_crypto.h>
#include "crypto_sm4.h"

static void sm4_ecb_encrypt(struct sm4_state* ctx,ut8* in,ut8* out){

}

static void sm4_ecb_decrypt(struct sm4_state* ctx,ut8* in,ut8* out){

}

static bool sm4_ecb_set_key(RzCrypto *cry, const ut8 *key, int keylen, int mode, int direction) {
	return true;
}

static int sm4_ecb_get_key_size(RzCrypto *cry) {
    return 128;
}

static bool sm4_use(const char *algo) {
	return !strcmp(algo, "sm4-ecb");
}


static bool update(RzCrypto *cry, const ut8 *buf, int len) {
    return true;
}

static bool final(RzCrypto *cry, const ut8 *buf, int len) {
	return update(cry, buf, len);
}

static bool sm4_ecb_init(RzCrypto *cry) {
	rz_return_val_if_fail(cry,false);

	cry->user = RZ_NEW0(struct sm4_state);
    return cry->user!=NULL;
}

static bool sm4_ecb_fini(RzCrypto *cry) {
	rz_return_val_if_fail(cry,false);

	free(cry->user);
	return true;
}

RzCryptoPlugin rz_crypto_plugin_sm4_ecb = {
	.name = "sm4-ecb",
	.author = "0xSh4dy",
	.license = "LGPL-3",
	.set_key = sm4_ecb_set_key,
	.get_key_size = sm4_ecb_get_key_size,
	.use = sm4_use,
	.update = update,
	.final = final,
	.init = sm4_ecb_init,
	.fini = sm4_ecb_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CRYPTO,
	.data = &rz_crypto_plugin_sm4_ecb,
	.version = RZ_VERSION
};
#endif