// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_hash.h>
#include <rz_util/rz_assert.h>

#include "../algorithms/crc/crca.h"

#define plugin_crca_preset_context_new(crcalgo, preset) \
	static void *plugin_crca_##crcalgo##_context_new() { \
		RzCrc *crc = RZ_NEW0(RzCrc); \
		if (!crc) { \
			return NULL; \
		} \
		crc_init_preset(crc, preset); \
		return crc; \
	}

#define plugin_crca_preset_init(crcalgo, preset) \
	static bool plugin_crca_##crcalgo##_init(void *context) { \
		rz_return_val_if_fail(context, false); \
		crc_init_preset((RzCrc *)context, preset); \
		return true; \
	}

#define plugin_crca_preset_small_block(crcalgo, preset) \
	static bool plugin_crca_##crcalgo##_small_block(const ut8 *data, ut64 size, ut8 **digest, RzHashSize *digest_size) { \
		rz_return_val_if_fail(data && digest, false); \
		RzCrc ctx; \
		crc_init_preset(&ctx, preset); \
		ut8 *dgst = malloc(plugin_crca_digest_size(&ctx)); \
		if (!dgst) { \
			return false; \
		} \
		crc_update(&ctx, data, size); \
		plugin_crca_final((void *)&ctx, dgst); \
		*digest = dgst; \
		if (digest_size) { \
			*digest_size = plugin_crca_digest_size(&ctx); \
		} \
		return true; \
	}

static void plugin_crca_context_free(void *context) {
	free(context);
}

static RzHashSize plugin_crca_digest_size(void *context) {
	rz_return_val_if_fail(context, 0);
	RzCrc *ctx = (RzCrc *)context;
	if (ctx->size <= 8) {
		return 1;
	} else if (ctx->size > 8 && ctx->size <= 16) {
		return 2;
	} else if (ctx->size > 16 && ctx->size <= 32) {
		return 4;
	} else if (ctx->size > 32 && ctx->size <= 64) {
		return 8;
	}
	RZ_LOG_ERROR("msg digest: unknown size %d.\n", ctx->size);
	return 0;
}

static RzHashSize plugin_crca_block_size(void *context) {
	return 0;
}

static bool plugin_crca_update(void *context, const ut8 *data, ut64 size) {
	rz_return_val_if_fail(context && data, false);

	crc_update((RzCrc *)context, data, size);
	return true;
}

static bool plugin_crca_final(void *context, ut8 *digest) {
	rz_return_val_if_fail(context && digest, false);
	RzCrc *ctx = (RzCrc *)context;
	utcrc r;
	crc_final(ctx, &r);
	if (ctx->size <= 8) {
		rz_write_be8(digest, (ut8)r);
	} else if (ctx->size > 8 && ctx->size <= 16) {
		rz_write_be16(digest, (ut16)r);
	} else if (ctx->size > 16 && ctx->size <= 32) {
		rz_write_be32(digest, (ut32)r);
	} else if (ctx->size > 32 && ctx->size <= 64) {
		rz_write_be64(digest, r);
	} else {
		RZ_LOG_ERROR("msg digest: unknown size %d.\n", ctx->size);
	}
	return true;
}

#define rz_hash_plugin_crca_preset(crcalgo, preset, crcdesc) \
	plugin_crca_preset_context_new(crcalgo, preset); \
	plugin_crca_preset_init(crcalgo, preset); \
	plugin_crca_preset_small_block(crcalgo, preset); \
	RzHashPlugin rz_hash_plugin_crca_##crcalgo = { \
		.name = #crcalgo, \
		.license = "LGPL3", \
		.author = "deroad", \
		.description = crcdesc, \
		.support_hmac = false, \
		.context_new = plugin_crca_##crcalgo##_context_new, \
		.context_free = plugin_crca_context_free, \
		.digest_size = plugin_crca_digest_size, \
		.block_size = plugin_crca_block_size, \
		.init = plugin_crca_##crcalgo##_init, \
		.update = plugin_crca_update, \
		.final = plugin_crca_final, \
		.small_block = plugin_crca_##crcalgo##_small_block, \
	}

#ifndef RZ_PLUGIN_INCORE
#define rz_lib_plugin_crca_preset(crcalgo) \
	RZ_API RzLibStruct rizin_plugin = { \
		.type = RZ_LIB_TYPE_HASH, \
		.data = &rz_hash_plugin_crca_##crcalgo, \
		.version = RZ_VERSION \
	}
#else
#define rz_lib_plugin_crca_preset(crcalgo)
#endif

#define rz_plugin_crca_preset_definition(crcalgo, preset, crcdesc) \
	rz_hash_plugin_crca_preset(crcalgo, preset, crcdesc); \
	rz_lib_plugin_crca_preset(crcalgo)

rz_plugin_crca_preset_definition(crc8smbus, /*    */ CRC_PRESET_8_SMBUS, "CRC-8 SMBUS checksum");
rz_plugin_crca_preset_definition(crc8cdma2000, /* */ CRC_PRESET_CRC8_CDMA2000, "CRC-8 CDMA-2000 checksum");
rz_plugin_crca_preset_definition(crc8darc, /*     */ CRC_PRESET_CRC8_DARC, "CRC-8 DARC checksum");
rz_plugin_crca_preset_definition(crc8dvbs2, /*    */ CRC_PRESET_CRC8_DVB_S2, "CRC-8 DVB-S2 checksum");
rz_plugin_crca_preset_definition(crc8ebu, /*      */ CRC_PRESET_CRC8_EBU, "CRC-8 EBU checksum");
rz_plugin_crca_preset_definition(crc8icode, /*    */ CRC_PRESET_CRC8_ICODE, "CRC-8 I-CODE checksum");
rz_plugin_crca_preset_definition(crc8itu, /*      */ CRC_PRESET_CRC8_ITU, "CRC-8 ITU checksum");
rz_plugin_crca_preset_definition(crc8maxim, /*    */ CRC_PRESET_CRC8_MAXIM, "CRC-8 MAXIM checksum");
rz_plugin_crca_preset_definition(crc8rohc, /*     */ CRC_PRESET_CRC8_ROHC, "CRC-8 ROHC checksum");
rz_plugin_crca_preset_definition(crc8wcdma, /*    */ CRC_PRESET_CRC8_WCDMA, "CRC-8 WCDMA checksum");
rz_plugin_crca_preset_definition(crc15can, /*     */ CRC_PRESET_15_CAN, "CRC-15 CAN checksum");
rz_plugin_crca_preset_definition(crc16, /*        */ CRC_PRESET_16, "CRC-16 IBM/ARC checksum");
rz_plugin_crca_preset_definition(crc16citt, /*    */ CRC_PRESET_16_CITT, "CRC-16 CITT checksum");
rz_plugin_crca_preset_definition(crc16usb, /*     */ CRC_PRESET_16_USB, "CRC-16 USB checksum");
rz_plugin_crca_preset_definition(crc16hdlc, /*    */ CRC_PRESET_16_HDLC, "CRC-16 HDLC checksum");
rz_plugin_crca_preset_definition(crc16augccitt, /**/ CRC_PRESET_CRC16_AUG_CCITT, "CRC-16 AUG-CCITT checksum");
rz_plugin_crca_preset_definition(crc16buypass, /* */ CRC_PRESET_CRC16_BUYPASS, "CRC-16 BUYPASS checksum");
rz_plugin_crca_preset_definition(crc16cdma2000, /**/ CRC_PRESET_CRC16_CDMA2000, "CRC-16 CDMA-2000 checksum");
rz_plugin_crca_preset_definition(crc16dds110, /*  */ CRC_PRESET_CRC16_DDS110, "CRC-16 DDS110 checksum");
rz_plugin_crca_preset_definition(crc16dectr, /*   */ CRC_PRESET_CRC16_DECT_R, "CRC-16 DECT-R checksum");
rz_plugin_crca_preset_definition(crc16dectx, /*   */ CRC_PRESET_CRC16_DECT_X, "CRC-16 DECT-X checksum");
rz_plugin_crca_preset_definition(crc16dnp, /*     */ CRC_PRESET_CRC16_DNP, "CRC-16 DNP checksum");
rz_plugin_crca_preset_definition(crc16en13757, /* */ CRC_PRESET_CRC16_EN13757, "CRC-16 EN-13757 checksum");
rz_plugin_crca_preset_definition(crc16genibus, /* */ CRC_PRESET_CRC16_GENIBUS, "CRC-16 GENIBUS checksum");
rz_plugin_crca_preset_definition(crc16maxim, /*   */ CRC_PRESET_CRC16_MAXIM, "CRC-16 MAXIM checksum");
rz_plugin_crca_preset_definition(crc16mcrf4xx, /* */ CRC_PRESET_CRC16_MCRF4XX, "CRC-16 MCRF4XX checksum");
rz_plugin_crca_preset_definition(crc16riello, /*  */ CRC_PRESET_CRC16_RIELLO, "CRC-16 RIELLO checksum");
rz_plugin_crca_preset_definition(crc16t10dif, /*  */ CRC_PRESET_CRC16_T10_DIF, "CRC-16 T10-DIF checksum");
rz_plugin_crca_preset_definition(crc16teledisk, /**/ CRC_PRESET_CRC16_TELEDISK, "CRC-16 TELEDISK checksum");
rz_plugin_crca_preset_definition(crc16tms37157, /**/ CRC_PRESET_CRC16_TMS37157, "CRC-16 TMS37157 checksum");
rz_plugin_crca_preset_definition(crca, /*         */ CRC_PRESET_CRCA, "CRC-16/CRCA checksum");
rz_plugin_crca_preset_definition(crc16kermit, /*  */ CRC_PRESET_CRC16_KERMIT, "CRC-16 KERMIT checksum");
rz_plugin_crca_preset_definition(crc16modbus, /*  */ CRC_PRESET_CRC16_MODBUS, "CRC-16 MODBUS checksum");
rz_plugin_crca_preset_definition(crc16x25, /*     */ CRC_PRESET_CRC16_X25, "CRC-16 X25 checksum");
rz_plugin_crca_preset_definition(crc16xmodem, /*  */ CRC_PRESET_CRC16_XMODEM, "CRC-16 XMODEM checksum");
rz_plugin_crca_preset_definition(crc24, /*        */ CRC_PRESET_24, "CRC-24 checksum");
rz_plugin_crca_preset_definition(crc32, /*        */ CRC_PRESET_32, "CRC-32 checksum");
rz_plugin_crca_preset_definition(crc32ecma267, /* */ CRC_PRESET_32_ECMA_267, "CRC-32 ECMA-267 checksum (EDC for DVD sectors)");
rz_plugin_crca_preset_definition(crc32c, /*       */ CRC_PRESET_32C, "CRC-32C checksum");
rz_plugin_crca_preset_definition(crc32bzip2, /*   */ CRC_PRESET_CRC32_BZIP2, "CRC-32 BZIP2 checksum");
rz_plugin_crca_preset_definition(crc32d, /*       */ CRC_PRESET_CRC32D, "CRC-32D checksum");
rz_plugin_crca_preset_definition(crc32mpeg2, /*   */ CRC_PRESET_CRC32_MPEG2, "CRC-32 MPEG2 checksum");
rz_plugin_crca_preset_definition(crc32posix, /*   */ CRC_PRESET_CRC32_POSIX, "CRC-32 POSIX checksum");
rz_plugin_crca_preset_definition(crc32q, /*       */ CRC_PRESET_CRC32Q, "CRC-32Q checksum");
rz_plugin_crca_preset_definition(crc32jamcrc, /*  */ CRC_PRESET_CRC32_JAMCRC, "CRC-32 JAMCRC checksum");
rz_plugin_crca_preset_definition(crc32xfer, /*    */ CRC_PRESET_CRC32_XFER, "CRC-32 XFER checksum");
rz_plugin_crca_preset_definition(crc64, /*        */ CRC_PRESET_CRC64, "CRC-64 checksum");
rz_plugin_crca_preset_definition(crc64ecma182, /* */ CRC_PRESET_CRC64_ECMA182, "CRC-64 ECMA-182 checksum");
rz_plugin_crca_preset_definition(crc64we, /*      */ CRC_PRESET_CRC64_WE, "CRC-64 WE checksum");
rz_plugin_crca_preset_definition(crc64xz, /*      */ CRC_PRESET_CRC64_XZ, "CRC-64 XZ checksum");
rz_plugin_crca_preset_definition(crc64iso, /*     */ CRC_PRESET_CRC64_ISO, "CRC-64 ISO checksum");
