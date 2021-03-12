// SPDX-FileCopyrightText: 2007-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include "rz_util.h"
#include <xxhash.h>

RZ_LIB_VERSION(rz_hash);

static const struct {
	const char *name;
	ut64 bit;
} hash_name_bytes[] = {
	{ "all", UT64_MAX },
	{ "xor", RZ_HASH_XOR },
	{ "xorpair", RZ_HASH_XORPAIR },
	{ "md4", RZ_HASH_MD4 },
	{ "md5", RZ_HASH_MD5 },
	{ "sha1", RZ_HASH_SHA1 },
	{ "sha256", RZ_HASH_SHA256 },
	{ "sha384", RZ_HASH_SHA384 },
	{ "sha512", RZ_HASH_SHA512 },
	{ "adler32", RZ_HASH_ADLER32 },
	{ "xxhash", RZ_HASH_XXHASH },
	{ "parity", RZ_HASH_PARITY },
	{ "entropy", RZ_HASH_ENTROPY },
	{ "hamdist", RZ_HASH_HAMDIST },
	{ "pcprint", RZ_HASH_PCPRINT },
	{ "mod255", RZ_HASH_MOD255 },
	// {"base64", RZ_HASH_BASE64},
	// {"base91", RZ_HASH_BASE91},
	// {"punycode", RZ_HASH_PUNYCODE},
	{ "luhn", RZ_HASH_LUHN },

	{ "fletcher8", RZ_HASH_FLETCHER8 },
	{ "fletcher16", RZ_HASH_FLETCHER16 },
	{ "fletcher32", RZ_HASH_FLETCHER32 },
	{ "fletcher64", RZ_HASH_FLETCHER64 },

	{ "crc8smbus", RZ_HASH_CRC8_SMBUS },
#if RZ_HAVE_CRC8_EXTRA
	{ /* CRC-8/CDMA2000     */ "crc8cdma2000", RZ_HASH_CRC8_CDMA2000 },
	{ /* CRC-8/DARC         */ "crc8darc", RZ_HASH_CRC8_DARC },
	{ /* CRC-8/DVB-S2       */ "crc8dvbs2", RZ_HASH_CRC8_DVB_S2 },
	{ /* CRC-8/EBU          */ "crc8ebu", RZ_HASH_CRC8_EBU },
	{ /* CRC-8/I-CODE       */ "crc8icode", RZ_HASH_CRC8_ICODE },
	{ /* CRC-8/ITU          */ "crc8itu", RZ_HASH_CRC8_ITU },
	{ /* CRC-8/MAXIM        */ "crc8maxim", RZ_HASH_CRC8_MAXIM },
	{ /* CRC-8/ROHC         */ "crc8rohc", RZ_HASH_CRC8_ROHC },
	{ /* CRC-8/WCDMA        */ "crc8wcdma", RZ_HASH_CRC8_WCDMA },
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
	{ "crc15can", RZ_HASH_CRC15_CAN },
#endif /* #if RZ_HAVE_CRC15_EXTRA */

	{ "crc16", RZ_HASH_CRC16 },
	{ "crc16hdlc", RZ_HASH_CRC16_HDLC },
	{ /* CRC-16/USB         */ "crc16usb", RZ_HASH_CRC16_USB },
	{ /* CRC-16/CCITT-FALSE */ "crc16citt", RZ_HASH_CRC16_CITT },
#if RZ_HAVE_CRC16_EXTRA
	{ /* CRC-16/AUG-CCITT   */ "crc16augccitt", RZ_HASH_CRC16_AUG_CCITT },
	{ /* CRC-16/BUYPASS     */ "crc16buypass", RZ_HASH_CRC16_BUYPASS },
	{ /* CRC-16/CDMA2000    */ "crc16cdma2000", RZ_HASH_CRC16_CDMA2000 },
	{ /* CRC-16/DDS-110     */ "crc16dds110", RZ_HASH_CRC16_DDS110 },
	{ /* CRC-16/RECT-R      */ "crc16dectr", RZ_HASH_CRC16_DECT_R },
	{ /* CRC-16/RECT-X      */ "crc16dectx", RZ_HASH_CRC16_DECT_X },
	{ /* CRC-16/DNP         */ "crc16dnp", RZ_HASH_CRC16_DNP },
	{ /* CRC-16/EN-13757    */ "crc16en13757", RZ_HASH_CRC16_EN13757 },
	{ /* CRC-16/GENIBUS     */ "crc16genibus", RZ_HASH_CRC16_GENIBUS },
	{ /* CRC-16/MAXIM       */ "crc16maxim", RZ_HASH_CRC16_MAXIM },
	{ /* CRC-16/MCRF4XX     */ "crc16mcrf4xx", RZ_HASH_CRC16_MCRF4XX },
	{ /* CRC-16/RIELLO      */ "crc16riello", RZ_HASH_CRC16_RIELLO },
	{ /* CRC-16/T10-DIF     */ "crc16t10dif", RZ_HASH_CRC16_T10_DIF },
	{ /* CRC-16/TELEDISK    */ "crc16teledisk", RZ_HASH_CRC16_TELEDISK },
	{ /* CRC-16/TMS37157    */ "crc16tms37157", RZ_HASH_CRC16_TMS37157 },
	{ /* CRC-A              */ "crca", RZ_HASH_CRCA },
	{ /* CRC-16/KERMIT      */ "crc16kermit", RZ_HASH_CRC16_KERMIT },
	{ /* CRC-16/MODBUS      */ "crc16modbus", RZ_HASH_CRC16_MODBUS },
	{ /* CRC-16/X-25        */ "crc16x25", RZ_HASH_CRC16_X25 },
	{ /* CRC-16/XMODEM      */ "crc16xmodem", RZ_HASH_CRC16_XMODEM },
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
	{ "crc24", RZ_HASH_CRC24 },
#endif /* #if RZ_HAVE_CRC24 */

	{ "crc32", RZ_HASH_CRC32 },
	{ "crc32c", RZ_HASH_CRC32C },
	{ "crc32ecma267", RZ_HASH_CRC32_ECMA_267 },
#if RZ_HAVE_CRC32_EXTRA
	{ /* CRC-32/BZIP2       */ "crc32bzip2", RZ_HASH_CRC32_BZIP2 },
	{ /* CRC-32D            */ "crc32d", RZ_HASH_CRC32D },
	{ /* CRC-32/MPEG2       */ "crc32mpeg2", RZ_HASH_CRC32_MPEG2 },
	{ /* CRC-32/POSIX       */ "crc32posix", RZ_HASH_CRC32_POSIX },
	{ /* CRC-32Q            */ "crc32q", RZ_HASH_CRC32Q },
	{ /* CRC-32/JAMCRC      */ "crc32jamcrc", RZ_HASH_CRC32_JAMCRC },
	{ /* CRC-32/XFER        */ "crc32xfer", RZ_HASH_CRC32_XFER },
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
	{ /* CRC-64             */ "crc64", RZ_HASH_CRC64 },
#endif /* #if RZ_HAVE_CRC64 */

#if RZ_HAVE_CRC64_EXTRA
	{ /* CRC-64/ECMA-182    */ "crc64ecma", RZ_HASH_CRC64_ECMA182 },
	{ /* CRC-64/WE          */ "crc64we", RZ_HASH_CRC64_WE },
	{ /* CRC-64/XZ          */ "crc64xz", RZ_HASH_CRC64_XZ },
	{ /* CRC-64/ISO         */ "crc64iso", RZ_HASH_CRC64_ISO },
#endif /* #if RZ_HAVE_CRC64_EXTRA */
	{ NULL, 0 }
};

/* returns 0-100 */
RZ_API int rz_hash_pcprint(const ut8 *buffer, ut64 len) {
	const ut8 *end = buffer + len;
	int n;
	if (len < 1) {
		return 0;
	}
	for (n = 0; buffer < end; buffer++) {
		if (IS_PRINTABLE(*buffer)) {
			n++;
		}
	}
	return ((100 * n) / len);
}

RZ_API int rz_hash_parity(const ut8 *buf, ut64 len) {
	const ut8 *end = buf + len;
	ut32 ones = 0;
	for (; buf < end; buf++) {
		ut8 x = buf[0];
		ones += ((x & 128) ? 1 : 0) + ((x & 64) ? 1 : 0) + ((x & 32) ? 1 : 0) + ((x & 16) ? 1 : 0) +
			((x & 8) ? 1 : 0) + ((x & 4) ? 1 : 0) + ((x & 2) ? 1 : 0) + ((x & 1) ? 1 : 0);
	}
	return ones % 2;
}

/* These functions comes from 0xFFFF */
/* fmi: nopcode.org/0xFFFF */
RZ_API ut16 rz_hash_xorpair(const ut8 *a, ut64 len) {
	ut16 result = 0, *b = (ut16 *)a;
	for (len >>= 1; len--; b++) {
		result ^= *b;
	}
	return result;
}

RZ_API ut8 rz_hash_xor(const ut8 *b, ut64 len) {
	ut8 res = 0;
	for (; len--; b++) {
		res ^= *b;
	}
	return res;
}

RZ_API ut8 rz_hash_mod255(const ut8 *b, ut64 len) {
	int i, c = 0;
	/* from gdb */
	for (i = 0; i < len; i++) {
		c += b[i];
	}
	return c % 255;
}

RZ_API ut32 rz_hash_xxhash(const ut8 *buf, ut64 len) {
	return XXH32(buf, (size_t)len, 0);
}

RZ_API ut8 rz_hash_deviation(const ut8 *b, ut64 len) {
	int i, c;
	for (c = i = 0, len--; i < len; i++) {
		c += RZ_ABS(b[i + 1] - b[i]);
	}
	return c;
}

RZ_API const char *rz_hash_name(ut64 bit) {
	int i;
	for (i = 1; hash_name_bytes[i].bit; i++) {
		if (bit & hash_name_bytes[i].bit) {
			return hash_name_bytes[i].name;
		}
	}
	return "";
}

RZ_API int rz_hash_size(ut64 algo) {
#define ALGOBIT(x) \
	if (algo & RZ_HASH_##x) { \
		return RZ_HASH_SIZE_##x; \
	}
	ALGOBIT(FLETCHER8);
	ALGOBIT(FLETCHER16);
	ALGOBIT(FLETCHER32);
	ALGOBIT(FLETCHER64);
	ALGOBIT(MD4);
	ALGOBIT(MD5);
	ALGOBIT(SHA1);
	ALGOBIT(SHA256);
	ALGOBIT(SHA384);
	ALGOBIT(SHA512);
	ALGOBIT(XXHASH);
	ALGOBIT(ADLER32);
	ALGOBIT(PARITY);
	ALGOBIT(ENTROPY);
	ALGOBIT(HAMDIST);
	ALGOBIT(XOR);
	ALGOBIT(XORPAIR);
	ALGOBIT(MOD255);
	ALGOBIT(PCPRINT);
	ALGOBIT(LUHN);

	ALGOBIT(CRC8_SMBUS);
#if RZ_HAVE_CRC8_EXTRA
	ALGOBIT(CRC8_CDMA2000);
	ALGOBIT(CRC8_DARC);
	ALGOBIT(CRC8_DVB_S2);
	ALGOBIT(CRC8_EBU);
	ALGOBIT(CRC8_ICODE);
	ALGOBIT(CRC8_ITU);
	ALGOBIT(CRC8_MAXIM);
	ALGOBIT(CRC8_ROHC);
	ALGOBIT(CRC8_WCDMA);
#endif /* #if RZ_HAVE_CRC8_EXTRA */

#if RZ_HAVE_CRC15_EXTRA
	ALGOBIT(CRC15_CAN);
#endif /* #if RZ_HAVE_CRC15_EXTRA */

	ALGOBIT(CRC16);
	ALGOBIT(CRC16_HDLC);
	ALGOBIT(CRC16_USB);
	ALGOBIT(CRC16_CITT);
#if RZ_HAVE_CRC16_EXTRA
	ALGOBIT(CRC16_AUG_CCITT);
	ALGOBIT(CRC16_BUYPASS)
	ALGOBIT(CRC16_CDMA2000);
	ALGOBIT(CRC16_DDS110);
	ALGOBIT(CRC16_DECT_R);
	ALGOBIT(CRC16_DECT_X);
	ALGOBIT(CRC16_DNP);
	ALGOBIT(CRC16_EN13757);
	ALGOBIT(CRC16_GENIBUS);
	ALGOBIT(CRC16_MAXIM);
	ALGOBIT(CRC16_MCRF4XX);
	ALGOBIT(CRC16_RIELLO);
	ALGOBIT(CRC16_T10_DIF);
	ALGOBIT(CRC16_TELEDISK);
	ALGOBIT(CRC16_TMS37157);
	ALGOBIT(CRCA);
	ALGOBIT(CRC16_KERMIT);
	ALGOBIT(CRC16_MODBUS);
	ALGOBIT(CRC16_X25);
	ALGOBIT(CRC16_XMODEM);
#endif /* #if RZ_HAVE_CRC16_EXTRA */

#if RZ_HAVE_CRC24
	ALGOBIT(CRC24);
#endif /* #if RZ_HAVE_CRC24 */

	ALGOBIT(CRC32);
	ALGOBIT(CRC32C);
	ALGOBIT(CRC32_ECMA_267);
#if RZ_HAVE_CRC32_EXTRA
	ALGOBIT(CRC32_BZIP2);
	ALGOBIT(CRC32D);
	ALGOBIT(CRC32_MPEG2);
	ALGOBIT(CRC32_POSIX);
	ALGOBIT(CRC32Q);
	ALGOBIT(CRC32_JAMCRC);
	ALGOBIT(CRC32_XFER);
#endif /* #if RZ_HAVE_CRC32_EXTRA */

#if RZ_HAVE_CRC64
	ALGOBIT(CRC64);
#endif /* #if RZ_HAVE_CRC64 */

#if RZ_HAVE_CRC64_EXTRA
	ALGOBIT(CRC64_ECMA182);
	ALGOBIT(CRC64_WE);
	ALGOBIT(CRC64_XZ);
	ALGOBIT(CRC64_ISO);
#endif /* #if RZ_HAVE_CRC64_EXTRA */
	return 0;
}

/* Converts a comma separated list of names to the respective bit combination */
RZ_API ut64 rz_hash_name_to_bits(const char *name) {
	char tmp[128];
	int i;
	const char *ptr = name;
	ut64 ret = 0;

	if (!ptr) {
		return ret;
	}

	do {
		/* Eat everything up to the comma */
		for (i = 0; *ptr && *ptr != ',' && i < sizeof(tmp) - 1; i++) {
			tmp[i] = tolower((ut8)*ptr++);
		}

		/* Safety net */
		tmp[i] = '\0';

		for (i = 0; hash_name_bytes[i].name; i++) {
			if (!strcmp(tmp, hash_name_bytes[i].name)) {
				ret |= hash_name_bytes[i].bit;
				break;
			}
		}

		/* Skip the trailing comma, if any */
		if (*ptr) {
			ptr++;
		}
	} while (*ptr);

	return ret;
}

RZ_API void rz_hash_do_spice(RzHash *ctx, ut64 algo, int loops, RzHashSeed *seed) {
	ut8 buf[1024];
	int i, len, hlen = rz_hash_size(algo);
	for (i = 0; i < loops; i++) {
		if (seed) {
			if (seed->prefix) {
				memcpy(buf, seed->buf, seed->len);
				memcpy(buf + seed->len, ctx->digest, hlen);
			} else {
				memcpy(buf, ctx->digest, hlen);
				memcpy(buf + hlen, seed->buf, seed->len);
			}
			len = hlen + seed->len;
		} else {
			memcpy(buf, ctx->digest, hlen);
			len = hlen;
		}
		(void)rz_hash_calculate(ctx, algo, buf, len);
	}
}

RZ_API char *rz_hash_to_string(RzHash *ctx, const char *name, const ut8 *data, int len) {
	ut64 algo = rz_hash_name_to_bits(name);
	char *digest_hex = NULL;
	RzHash *myctx = NULL;
	int i, digest_size;
	if (!algo || !data) {
		return NULL;
	}
	if (!ctx) {
		myctx = ctx = rz_hash_new(true, algo);
	}
	rz_hash_do_begin(ctx, algo);
	digest_size = rz_hash_calculate(ctx, algo, data, len);
	rz_hash_do_end(ctx, algo);
	if (digest_size == 0) {
		digest_hex = calloc(16, 1);
		snprintf(digest_hex, 15, "%02.8f", ctx->entropy);
	} else if (digest_size > 0) {
		if (digest_size * 2 < digest_size) {
			digest_hex = NULL;
		} else {
			digest_hex = malloc((digest_size * 2) + 1);
			if (digest_hex) {
				for (i = 0; i < digest_size; i++) {
					sprintf(digest_hex + (i * 2), "%02x", ctx->digest[i]);
				}
				digest_hex[digest_size * 2] = 0;
			}
		}
	}
	rz_hash_free(myctx);
	return digest_hex;
}
