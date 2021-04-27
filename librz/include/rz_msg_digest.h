// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_MSG_DIGEST_H
#define RZ_MSG_DIGEST_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_mem.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_msg_digest);

typedef enum {
	RZ_MSG_DIGEST_STATUS_ALLOC = 0,
	RZ_MSG_DIGEST_STATUS_INIT,
	RZ_MSG_DIGEST_STATUS_UPDATE,
	RZ_MSG_DIGEST_STATUS_FINAL,
} RzMsgDigestStatus;

typedef ut32 RzMsgDigestSize;

typedef struct rz_msg_digest_plugin_t {
	const char *name;
	const char *license;
	const char *author;
	bool support_hmac;
	void *(*context_new)();
	void (*context_free)(void *context);
	RzMsgDigestSize (*digest_size)(void *context);
	RzMsgDigestSize (*block_size)(void *context);
	bool (*init)(void *context);
	bool (*update)(void *context, const ut8 *data, ut64 size);
	bool (*final)(void *context, ut8 *digest);
	bool (*small_block)(const ut8 *data, ut64 size, ut8 **digest, RzMsgDigestSize *digest_size);
} RzMsgDigestPlugin;

typedef struct rz_msg_digest_t {
	RzList *configurations;
	RzMsgDigestStatus status;
} RzMsgDigest;

#ifdef RZ_API

RZ_API ut32 rz_hash_xxhash(const ut8 *input, size_t size);
RZ_API double rz_hash_entropy(const ut8 *data, ut64 len);
RZ_API double rz_hash_entropy_fraction(const ut8 *data, ut64 len);

RZ_API const RzMsgDigestPlugin *rz_msg_digest_plugin_by_index(size_t index);
RZ_API const RzMsgDigestPlugin *rz_msg_digest_plugin_by_name(const char *name);
RZ_API RzMsgDigest *rz_msg_digest_new();
RZ_API RzMsgDigest *rz_msg_digest_new_with_algo(const char *name, const ut8 *key, ut64 key_size);
#define rz_msg_digest_new_with_algo2(name) rz_msg_digest_new_with_algo(name, NULL, 0);
RZ_API void rz_msg_digest_free(RzMsgDigest *md);
RZ_API bool rz_msg_digest_configure(RzMsgDigest *md, const char *name);
RZ_API bool rz_msg_digest_hmac(RzMsgDigest *md, const ut8 *key, ut64 key_size);

RZ_API bool rz_msg_digest_init(RzMsgDigest *md);
RZ_API bool rz_msg_digest_update(RzMsgDigest *md, const ut8 *data, ut64 size);
RZ_API bool rz_msg_digest_final(RzMsgDigest *md);
RZ_API bool rz_msg_digest_iterate(RzMsgDigest *md, size_t iterate);
RZ_API const ut8 *rz_msg_digest_get_result(RzMsgDigest *md, const char *name, RzMsgDigestSize *size);
RZ_API char *rz_msg_digest_get_result_string(RzMsgDigest *md, const char *name, ut32 *size, bool invert);
RZ_API RzMsgDigestSize rz_msg_digest_size(RzMsgDigest *md, const char *name);
RZ_API ut8 *rz_msg_digest_calculate_small_block(const char *name, const ut8 *buffer, ut64 bsize, RzMsgDigestSize *osize);
RZ_API char *rz_msg_digest_calculate_small_block_string(const char *name, const ut8 *buffer, ut64 bsize, ut32 *size, bool invert);

#endif

/* importing all message digest plugins */
extern RzMsgDigestPlugin rz_msg_digest_plugin_md4;
extern RzMsgDigestPlugin rz_msg_digest_plugin_md5;
extern RzMsgDigestPlugin rz_msg_digest_plugin_sha1;
extern RzMsgDigestPlugin rz_msg_digest_plugin_sha256;
extern RzMsgDigestPlugin rz_msg_digest_plugin_sha384;
extern RzMsgDigestPlugin rz_msg_digest_plugin_sha512;
extern RzMsgDigestPlugin rz_msg_digest_plugin_fletcher8;
extern RzMsgDigestPlugin rz_msg_digest_plugin_fletcher16;
extern RzMsgDigestPlugin rz_msg_digest_plugin_fletcher32;
extern RzMsgDigestPlugin rz_msg_digest_plugin_fletcher64;
extern RzMsgDigestPlugin rz_msg_digest_plugin_adler32;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8smbus;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8cdma2000;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8darc;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8dvbs2;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8ebu;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8icode;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8itu;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8maxim;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8rohc;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc8wcdma;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc15can;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16citt;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16usb;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16hdlc;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16augccitt;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16buypass;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16cdma2000;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16dds110;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16dectr;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16dectx;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16dnp;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16en13757;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16genibus;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16maxim;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16mcrf4xx;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16riello;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16t10dif;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16teledisk;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16tms37157;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crca;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16kermit;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16modbus;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16x25;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc16xmodem;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc24;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32ecma267;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32c;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32bzip2;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32d;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32mpeg2;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32posix;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32q;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32jamcrc;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc32xfer;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc64;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc64ecma182;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc64we;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc64xz;
extern RzMsgDigestPlugin rz_msg_digest_plugin_crca_crc64iso;
extern RzMsgDigestPlugin rz_msg_digest_plugin_xor8;
extern RzMsgDigestPlugin rz_msg_digest_plugin_xor16;
extern RzMsgDigestPlugin rz_msg_digest_plugin_xxhash32;
extern RzMsgDigestPlugin rz_msg_digest_plugin_parity;
extern RzMsgDigestPlugin rz_msg_digest_plugin_entropy;
extern RzMsgDigestPlugin rz_msg_digest_plugin_entropy_fract;

#ifdef __cplusplus
}
#endif

#endif /* RZ_MSG_DIGEST_H */
