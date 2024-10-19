// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MSG_DIGEST_H
#define RZ_MSG_DIGEST_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/ht_sp.h>
#include <rz_util/rz_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_hash);

typedef enum {
	RZ_MSG_DIGEST_STATUS_ALLOC = 0,
	RZ_MSG_DIGEST_STATUS_INIT,
	RZ_MSG_DIGEST_STATUS_UPDATE,
	RZ_MSG_DIGEST_STATUS_FINAL,
} RzHashStatus;

typedef ut32 RzHashSize;

typedef struct rz_hash_plugin_t {
	const char *name;
	const char *license;
	const char *author;
	bool support_hmac;
	void *(*context_new)();
	void (*context_free)(void *context);
	RzHashSize (*digest_size)(void *context);
	RzHashSize (*block_size)(void *context);
	bool (*init)(void *context);
	bool (*update)(void *context, const ut8 *data, ut64 size);
	bool (*final)(void *context, ut8 *digest);
	bool (*small_block)(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size);
} RzHashPlugin;

typedef struct rz_hash_t {
	HtSP /*<RzHashPlugin *>*/ *plugins;
} RzHash;

typedef struct rz_hash_cfg_t {
	RzList /*<HashCfgConfig *>*/ *configurations;
	RzHashStatus status;
	RzHash *hash;
} RzHashCfg;

#ifdef RZ_API

RZ_API RzHash *rz_hash_new(void);
RZ_API void rz_hash_free(RZ_NULLABLE RzHash *rh);
RZ_API bool rz_hash_plugin_add(RZ_NONNULL RzHash *rh, RZ_NONNULL RZ_OWN RzHashPlugin *plugin);
RZ_API bool rz_hash_plugin_del(RZ_NONNULL RzHash *rh, RZ_NONNULL RzHashPlugin *plugin);
RZ_API RZ_BORROW const RzHashPlugin *rz_hash_plugin_by_name(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name);

RZ_API RZ_OWN RzHashCfg *rz_hash_cfg_new(RZ_NONNULL RzHash *rh);
RZ_API RZ_OWN RzHashCfg *rz_hash_cfg_new_with_algo(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name, RZ_NULLABLE const ut8 *key, ut64 key_size);
#define rz_hash_cfg_new_with_algo2(rh, name) rz_hash_cfg_new_with_algo(rh, name, NULL, 0);
RZ_API void rz_hash_cfg_free(RZ_NONNULL RzHashCfg *md);

RZ_API bool rz_hash_cfg_configure(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name);
RZ_API bool rz_hash_cfg_hmac(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const ut8 *key, ut64 key_size);
RZ_API bool rz_hash_cfg_init(RZ_NONNULL RzHashCfg *md);
RZ_API bool rz_hash_cfg_update(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const ut8 *data, ut64 size);
RZ_API bool rz_hash_cfg_final(RZ_NONNULL RzHashCfg *md);
RZ_API bool rz_hash_cfg_iterate(RZ_NONNULL RzHashCfg *md, size_t iterate);
RZ_API RZ_BORROW const ut8 *rz_hash_cfg_get_result(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name, RZ_NONNULL RzHashSize *size);
RZ_API RZ_OWN char *rz_hash_cfg_get_result_string(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name, RZ_NULLABLE ut32 *size, bool invert);
RZ_API RzHashSize rz_hash_cfg_size(RZ_NONNULL RzHashCfg *md, RZ_NONNULL const char *name);
RZ_API RZ_OWN ut8 *rz_hash_cfg_calculate_small_block(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name, RZ_NONNULL const ut8 *buffer, ut64 bsize, RZ_NONNULL RzHashSize *osize);
RZ_API RZ_OWN char *rz_hash_cfg_calculate_small_block_string(RZ_NONNULL RzHash *rh, RZ_NONNULL const char *name, RZ_NONNULL const ut8 *buffer, ut64 bsize, RZ_NULLABLE ut32 *size, bool invert);
RZ_API RZ_OWN char *rz_hash_cfg_randomart(RZ_NONNULL const ut8 *buffer, ut32 length, ut64 address);

RZ_API double rz_hash_ssdeep_compare(RZ_NONNULL const char *hash1, RZ_NONNULL const char *hash2);
RZ_API RZ_OWN char *rz_hash_ssdeep(RZ_NONNULL const ut8 *input, size_t size);
RZ_API ut32 rz_hash_xxhash(RZ_NONNULL const ut8 *input, size_t size);
RZ_API double rz_hash_entropy(RZ_NONNULL const ut8 *data, ut64 len);
RZ_API double rz_hash_entropy_fraction(RZ_NONNULL const ut8 *data, ut64 len);

#endif

/* importing all message digest plugins */
extern RzHashPlugin rz_hash_plugin_md2;
extern RzHashPlugin rz_hash_plugin_md4;
extern RzHashPlugin rz_hash_plugin_md5;
extern RzHashPlugin rz_hash_plugin_sha1;
extern RzHashPlugin rz_hash_plugin_sha256;
extern RzHashPlugin rz_hash_plugin_sha384;
extern RzHashPlugin rz_hash_plugin_sha512;
extern RzHashPlugin rz_hash_plugin_fletcher8;
extern RzHashPlugin rz_hash_plugin_fletcher16;
extern RzHashPlugin rz_hash_plugin_fletcher32;
extern RzHashPlugin rz_hash_plugin_fletcher64;
extern RzHashPlugin rz_hash_plugin_adler32;
extern RzHashPlugin rz_hash_plugin_crca_crc8smbus;
extern RzHashPlugin rz_hash_plugin_crca_crc8cdma2000;
extern RzHashPlugin rz_hash_plugin_crca_crc8darc;
extern RzHashPlugin rz_hash_plugin_crca_crc8dvbs2;
extern RzHashPlugin rz_hash_plugin_crca_crc8ebu;
extern RzHashPlugin rz_hash_plugin_crca_crc8icode;
extern RzHashPlugin rz_hash_plugin_crca_crc8itu;
extern RzHashPlugin rz_hash_plugin_crca_crc8maxim;
extern RzHashPlugin rz_hash_plugin_crca_crc8rohc;
extern RzHashPlugin rz_hash_plugin_crca_crc8wcdma;
extern RzHashPlugin rz_hash_plugin_crca_crc15can;
extern RzHashPlugin rz_hash_plugin_crca_crc16;
extern RzHashPlugin rz_hash_plugin_crca_crc16citt;
extern RzHashPlugin rz_hash_plugin_crca_crc16usb;
extern RzHashPlugin rz_hash_plugin_crca_crc16hdlc;
extern RzHashPlugin rz_hash_plugin_crca_crc16augccitt;
extern RzHashPlugin rz_hash_plugin_crca_crc16buypass;
extern RzHashPlugin rz_hash_plugin_crca_crc16cdma2000;
extern RzHashPlugin rz_hash_plugin_crca_crc16dds110;
extern RzHashPlugin rz_hash_plugin_crca_crc16dectr;
extern RzHashPlugin rz_hash_plugin_crca_crc16dectx;
extern RzHashPlugin rz_hash_plugin_crca_crc16dnp;
extern RzHashPlugin rz_hash_plugin_crca_crc16en13757;
extern RzHashPlugin rz_hash_plugin_crca_crc16genibus;
extern RzHashPlugin rz_hash_plugin_crca_crc16maxim;
extern RzHashPlugin rz_hash_plugin_crca_crc16mcrf4xx;
extern RzHashPlugin rz_hash_plugin_crca_crc16riello;
extern RzHashPlugin rz_hash_plugin_crca_crc16t10dif;
extern RzHashPlugin rz_hash_plugin_crca_crc16teledisk;
extern RzHashPlugin rz_hash_plugin_crca_crc16tms37157;
extern RzHashPlugin rz_hash_plugin_crca_crca;
extern RzHashPlugin rz_hash_plugin_crca_crc16kermit;
extern RzHashPlugin rz_hash_plugin_crca_crc16modbus;
extern RzHashPlugin rz_hash_plugin_crca_crc16x25;
extern RzHashPlugin rz_hash_plugin_crca_crc16xmodem;
extern RzHashPlugin rz_hash_plugin_crca_crc24;
extern RzHashPlugin rz_hash_plugin_crca_crc32;
extern RzHashPlugin rz_hash_plugin_crca_crc32ecma267;
extern RzHashPlugin rz_hash_plugin_crca_crc32c;
extern RzHashPlugin rz_hash_plugin_crca_crc32bzip2;
extern RzHashPlugin rz_hash_plugin_crca_crc32d;
extern RzHashPlugin rz_hash_plugin_crca_crc32mpeg2;
extern RzHashPlugin rz_hash_plugin_crca_crc32posix;
extern RzHashPlugin rz_hash_plugin_crca_crc32q;
extern RzHashPlugin rz_hash_plugin_crca_crc32jamcrc;
extern RzHashPlugin rz_hash_plugin_crca_crc32xfer;
extern RzHashPlugin rz_hash_plugin_crca_crc64;
extern RzHashPlugin rz_hash_plugin_crca_crc64ecma182;
extern RzHashPlugin rz_hash_plugin_crca_crc64we;
extern RzHashPlugin rz_hash_plugin_crca_crc64xz;
extern RzHashPlugin rz_hash_plugin_crca_crc64iso;
extern RzHashPlugin rz_hash_plugin_xor8;
extern RzHashPlugin rz_hash_plugin_xor16;
extern RzHashPlugin rz_hash_plugin_xxhash32;
extern RzHashPlugin rz_hash_plugin_parity;
extern RzHashPlugin rz_hash_plugin_entropy;
extern RzHashPlugin rz_hash_plugin_entropy_fract;
extern RzHashPlugin rz_hash_plugin_blake3;
extern RzHashPlugin rz_hash_plugin_ssdeep;
extern RzHashPlugin rz_hash_plugin_sm3;

#ifdef __cplusplus
}
#endif

#endif /* RZ_MSG_DIGEST_H */
