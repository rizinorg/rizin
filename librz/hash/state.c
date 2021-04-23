// SPDX-FileCopyrightText: 2009-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>

#if HAVE_LIB_SSL
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#else
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#endif

#define if_has_flag(x) if (!flags || flags & (x))

RZ_API RzHash *rz_hash_new(bool rst, ut64 flags) {
	RzHash *ctx = RZ_NEW0(RzHash);
	if (ctx) {
		rz_hash_do_begin(ctx, flags);
		ctx->rst = rst;
	}
	return ctx;
}

RZ_API void rz_hash_do_begin(RzHash *ctx, ut64 flags) {
	if_has_flag(RZ_HASH_MD4) {
		rz_md4_init(&ctx->md4);
	}
	if_has_flag(RZ_HASH_MD5) {
		MD5_Init(&ctx->md5);
	}
	if_has_flag(RZ_HASH_SHA1) {
		rz_sha1_init(&ctx->sha1);
	}
	if_has_flag(RZ_HASH_SHA256) {
		SHA256_Init(&ctx->sha256);
	}
	if_has_flag(RZ_HASH_SHA384) {
		SHA384_Init(&ctx->sha384);
	}
	if_has_flag(RZ_HASH_SHA512) {
		SHA512_Init(&ctx->sha512);
	}
	ctx->rst = false;
}

#define HANDLE_CRC_PRESET(rbits, aname) \
	do { \
		if (algobit & RZ_HASH_##aname) { \
			ut##rbits res = rz_hash_crc_preset(buf, len, CRC_PRESET_##aname); \
			rz_write_be##rbits(ctx->digest, res); \
		} \
	} while (0)

RZ_API void rz_hash_do_update(RzHash *ctx, ut64 algobit, const ut8 *buf, ut64 len) {
	if (algobit & RZ_HASH_MD4) {
		rz_md4_update(&ctx->md4, buf, len);
	}
	if (algobit & RZ_HASH_MD5) {
		MD5_Update(&ctx->md5, buf, len);
	}
	if (algobit & RZ_HASH_SHA1) {
		rz_sha1_update(&ctx->sha1, buf, len);
	}
	if (algobit & RZ_HASH_SHA256) {
		SHA256_Update(&ctx->sha256, buf, len);
	}
	if (algobit & RZ_HASH_SHA384) {
		SHA384_Update(&ctx->sha384, buf, len);
	}
	if (algobit & RZ_HASH_SHA512) {
		SHA512_Update(&ctx->sha512, buf, len);
	}
	if (algobit & RZ_HASH_XXHASH) {
		ut32 res = rz_hash_xxhash(buf, len);
		rz_write_le32(ctx->digest, res);
	}
	if (algobit & RZ_HASH_FLETCHER8) {
		ut8 res = rz_hash_fletcher8(buf, len);
		rz_write_le8(ctx->digest, res);
	}
	if (algobit & RZ_HASH_FLETCHER16) {
		ut16 res = rz_hash_fletcher16(buf, len);
		rz_write_le16(ctx->digest, res);
	}
	if (algobit & RZ_HASH_FLETCHER32) {
		ut32 res = rz_hash_fletcher32(buf, len);
		rz_write_le32(ctx->digest, res);
	}
	if (algobit & RZ_HASH_FLETCHER64) {
		ut64 res = rz_hash_fletcher64(buf, len);
		rz_write_le64(ctx->digest, res);
	}
	if (algobit & RZ_HASH_ADLER32) {
		ut32 res = rz_hash_adler32(buf, len);
		rz_write_le32(ctx->digest, res);
	}
	if (algobit & RZ_HASH_HAMDIST) {
		*ctx->digest = rz_hash_hamdist(buf, len);
	}
	if (algobit & RZ_HASH_PCPRINT) {
		*ctx->digest = rz_hash_pcprint(buf, len);
	}
	if (algobit & RZ_HASH_PARITY) {
		*ctx->digest = rz_hash_parity(buf, len);
	}
	if (algobit & RZ_HASH_ENTROPY) {
		rz_mem_memzero(ctx->digest, sizeof(ctx->entropy));
		ctx->entropy = rz_hash_entropy(buf, len);
	}
	if (algobit & RZ_HASH_XOR) {
		*ctx->digest = rz_hash_xor(buf, len);
	}
	if (algobit & RZ_HASH_XORPAIR) {
		ut16 res = rz_hash_xorpair(buf, len);
		rz_write_le16(ctx->digest, res);
	}
	if (algobit & RZ_HASH_MOD255) {
		*ctx->digest = rz_hash_mod255(buf, len);
	}
	if (algobit & RZ_HASH_LUHN) {
		*ctx->digest = rz_hash_luhn(buf, len);
	}

	if (algobit & RZ_HASH_CRC8_SMBUS) {
		ut8 res = rz_hash_crc_preset(buf, len, CRC_PRESET_8_SMBUS);
		rz_write_le8(ctx->digest, res);
	}
#if RZ_HAVE_CRC8_EXTRA
	HANDLE_CRC_PRESET(8, CRC8_CDMA2000);
	HANDLE_CRC_PRESET(8, CRC8_CDMA2000);
	HANDLE_CRC_PRESET(8, CRC8_DARC);
	HANDLE_CRC_PRESET(8, CRC8_DVB_S2);
	HANDLE_CRC_PRESET(8, CRC8_EBU);
	HANDLE_CRC_PRESET(8, CRC8_ICODE);
	HANDLE_CRC_PRESET(8, CRC8_ITU);
	HANDLE_CRC_PRESET(8, CRC8_MAXIM);
	HANDLE_CRC_PRESET(8, CRC8_ROHC);
	HANDLE_CRC_PRESET(8, CRC8_WCDMA);
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
	if (algobit & RZ_HASH_CRC15_CAN) {
		ut16 res = rz_hash_crc_preset(buf, len, CRC_PRESET_15_CAN);
		rz_write_be16(ctx->digest, res);
	}
#endif /* #if RZ_HAVE_CRC15_EXTRA */

	if (algobit & RZ_HASH_CRC16) {
		ut16 res = rz_hash_crc_preset(buf, len, CRC_PRESET_16);
		rz_write_be16(ctx->digest, res);
	}
	if (algobit & RZ_HASH_CRC16_HDLC) {
		ut16 res = rz_hash_crc_preset(buf, len, CRC_PRESET_16_HDLC);
		rz_write_be16(ctx->digest, res);
	}
	if (algobit & RZ_HASH_CRC16_USB) {
		ut16 res = rz_hash_crc_preset(buf, len, CRC_PRESET_16_USB);
		rz_write_be16(ctx->digest, res);
	}
	if (algobit & RZ_HASH_CRC16_CITT) {
		ut16 res = rz_hash_crc_preset(buf, len, CRC_PRESET_16_CITT);
		rz_write_be16(ctx->digest, res);
	}
#if RZ_HAVE_CRC16_EXTRA
	HANDLE_CRC_PRESET(16, CRC16_AUG_CCITT);
	HANDLE_CRC_PRESET(16, CRC16_BUYPASS);
	HANDLE_CRC_PRESET(16, CRC16_CDMA2000);
	HANDLE_CRC_PRESET(16, CRC16_DDS110);
	HANDLE_CRC_PRESET(16, CRC16_DECT_R);
	HANDLE_CRC_PRESET(16, CRC16_DECT_X);
	HANDLE_CRC_PRESET(16, CRC16_DNP);
	HANDLE_CRC_PRESET(16, CRC16_EN13757);
	HANDLE_CRC_PRESET(16, CRC16_GENIBUS);
	HANDLE_CRC_PRESET(16, CRC16_MAXIM);
	HANDLE_CRC_PRESET(16, CRC16_MCRF4XX);
	HANDLE_CRC_PRESET(16, CRC16_RIELLO);
	HANDLE_CRC_PRESET(16, CRC16_T10_DIF);
	HANDLE_CRC_PRESET(16, CRC16_TELEDISK);
	HANDLE_CRC_PRESET(16, CRC16_TMS37157);
	HANDLE_CRC_PRESET(16, CRCA);
	HANDLE_CRC_PRESET(16, CRC16_KERMIT);
	HANDLE_CRC_PRESET(16, CRC16_MODBUS);
	HANDLE_CRC_PRESET(16, CRC16_X25);
	HANDLE_CRC_PRESET(16, CRC16_XMODEM);
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
	if (algobit & RZ_HASH_CRC24) {
		ut32 res = rz_hash_crc_preset(buf, len, CRC_PRESET_24);
		rz_write_be24(ctx->digest, res);
	}
#endif /* #if RZ_HAVE_CRC24 */

	if (algobit & RZ_HASH_CRC32) {
		ut32 res = rz_hash_crc_preset(buf, len, CRC_PRESET_32);
		rz_write_be32(ctx->digest, res);
	}
	if (algobit & RZ_HASH_CRC32C) {
		ut32 res = rz_hash_crc_preset(buf, len, CRC_PRESET_32C);
		rz_write_be32(ctx->digest, res);
	}
	if (algobit & RZ_HASH_CRC32_ECMA_267) {
		ut32 res = rz_hash_crc_preset(buf, len, CRC_PRESET_32_ECMA_267);
		rz_write_be32(ctx->digest, res);
	}
#if RZ_HAVE_CRC32_EXTRA
	HANDLE_CRC_PRESET(32, CRC32_BZIP2);
	HANDLE_CRC_PRESET(32, CRC32D);
	HANDLE_CRC_PRESET(32, CRC32_MPEG2);
	HANDLE_CRC_PRESET(32, CRC32_POSIX);
	HANDLE_CRC_PRESET(32, CRC32Q);
	HANDLE_CRC_PRESET(32, CRC32_JAMCRC);
	HANDLE_CRC_PRESET(32, CRC32_XFER);
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
	HANDLE_CRC_PRESET(64, CRC64);
#endif /* #if RZ_HAVE_CRC64 */

#if RZ_HAVE_CRC64_EXTRA
	HANDLE_CRC_PRESET(64, CRC64_ECMA182);
	HANDLE_CRC_PRESET(64, CRC64_WE);
	HANDLE_CRC_PRESET(64, CRC64_XZ);
	HANDLE_CRC_PRESET(64, CRC64_ISO);
#endif /* #if RZ_HAVE_CRC64_EXTRA */
}

RZ_API void rz_hash_do_end(RzHash *ctx, ut64 flags) {
	if_has_flag(RZ_HASH_MD4) {
		rz_md4_fini(ctx->digest, &ctx->md4);
	}
	if_has_flag(RZ_HASH_MD5) {
		MD5_Final(ctx->digest, &ctx->md5);
	}
	if_has_flag(RZ_HASH_SHA1) {
		rz_sha1_fini(ctx->digest, &ctx->sha1);
	}
	if_has_flag(RZ_HASH_SHA256) {
		SHA256_Final(ctx->digest, &ctx->sha256);
	}
	if_has_flag(RZ_HASH_SHA384) {
		SHA384_Final(ctx->digest, &ctx->sha384);
	}
	if_has_flag(RZ_HASH_SHA512) {
		SHA512_Final(ctx->digest, &ctx->sha512);
	}
	ctx->rst = true;
}

RZ_API void rz_hash_free(RzHash *ctx) {
	free(ctx);
}

RZ_API ut8 *rz_hash_do_sha1(RzHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		rz_sha1_init(&ctx->sha1);
	}
	rz_sha1_update(&ctx->sha1, input, len);
	if (ctx->rst || len == 0) {
		rz_sha1_fini(ctx->digest, &ctx->sha1);
	}
	return ctx->digest;
}

RZ_API ut8 *rz_hash_do_sha256(RzHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA256_Init(&ctx->sha256);
	}
	SHA256_Update(&ctx->sha256, input, len);
	if (ctx->rst || len == 0) {
		SHA256_Final(ctx->digest, &ctx->sha256);
	}
	return ctx->digest;
}

RZ_API ut8 *rz_hash_do_sha384(RzHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA384_Init(&ctx->sha384);
	}
	SHA384_Update(&ctx->sha384, input, len);
	if (ctx->rst || len == 0) {
		SHA384_Final(ctx->digest, &ctx->sha384);
	}
	return ctx->digest;
}

RZ_API ut8 *rz_hash_do_sha512(RzHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		SHA512_Init(&ctx->sha512);
	}
	SHA512_Update(&ctx->sha512, input, len);
	if (ctx->rst || len == 0) {
		SHA512_Final(ctx->digest, &ctx->sha512);
	}
	return ctx->digest;
}

RZ_API ut8 *rz_hash_do_md5(RzHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		if (len == -1) {
			MD5_Init(&ctx->md5);
		} else if (len == -2) {
			MD5_Final(ctx->digest, &ctx->md5);
		}
		return NULL;
	}
	if (ctx->rst) {
		MD5_Init(&ctx->md5);
	}
	if (len > 0) {
		MD5_Update(&ctx->md5, input, len);
	} else {
		MD5_Update(&ctx->md5, (const ut8 *)"", 0);
	}
	if (ctx->rst) {
		MD5_Final(ctx->digest, &ctx->md5);
	}
	return ctx->digest;
}

RZ_API ut8 *rz_hash_do_md4(RzHash *ctx, const ut8 *input, int len) {
	if (len < 0) {
		return NULL;
	}
	if (ctx->rst) {
		rz_md4_init(&ctx->md4);
	}
	rz_md4_update(&ctx->md4, input, len);
	if (ctx->rst || len == 0) {
		rz_md4_fini(ctx->digest, &ctx->md4);
	}
	return ctx->digest;
}

RZ_API ut8 *rz_hash_do_hmac_sha256(RzHash *ctx, const ut8 *input, int len, const ut8 *key, int klen) {
	if (len < 0 || klen < 0) {
		return NULL;
	}

	size_t i;
	ut8 bskey[SHA256_BLOCK_LENGTH]; // block-sized key
	ut8 kpad[SHA256_BLOCK_LENGTH]; // keypad for opad, ipad

	// If klen > block-size, bskey = Hash(key)
	memset(bskey, 0, SHA256_BLOCK_LENGTH);
	if (klen > SHA256_BLOCK_LENGTH) {
		SHA256_Init(&ctx->sha256);
		SHA256_Update(&ctx->sha256, key, klen);
		SHA256_Final(ctx->digest, &ctx->sha256);
		memcpy(bskey, ctx->digest, RZ_HASH_SIZE_SHA256);
	} else {
		memcpy(bskey, key, klen);
	}

	// XOR block-sized key with ipad 0x36
	memset(kpad, 0, SHA256_BLOCK_LENGTH);
	memcpy(kpad, bskey, SHA256_BLOCK_LENGTH);
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x36;
	}

	// Inner hash (key ^ ipad || input)
	SHA256_Init(&ctx->sha256);
	SHA256_Update(&ctx->sha256, kpad, SHA256_BLOCK_LENGTH);
	SHA256_Update(&ctx->sha256, input, len);
	SHA256_Final(ctx->digest, &ctx->sha256);

	// XOR block-sized key with opad 0x5c
	memset(kpad, 0, SHA256_BLOCK_LENGTH);
	memcpy(kpad, bskey, SHA256_BLOCK_LENGTH);
	for (i = 0; i < SHA256_BLOCK_LENGTH; i++) {
		kpad[i] ^= 0x5c;
	}

	// Outer hash (key ^ opad || Inner hash)
	SHA256_Init(&ctx->sha256);
	SHA256_Update(&ctx->sha256, kpad, SHA256_BLOCK_LENGTH);
	SHA256_Update(&ctx->sha256, ctx->digest, RZ_HASH_SIZE_SHA256);
	SHA256_Final(ctx->digest, &ctx->sha256);

	return ctx->digest;
}
