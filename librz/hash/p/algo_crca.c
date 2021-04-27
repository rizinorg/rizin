// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_msg_digest.h>
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
	static bool plugin_crca_##crcalgo##_small_block(const ut8 *data, ut64 size, ut8 **digest, RzMsgDigestSize *digest_size) { \
		rz_return_val_if_fail(data &&digest, false); \
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

static RzMsgDigestSize plugin_crca_digest_size(void *context) {
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

static RzMsgDigestSize plugin_crca_block_size(void *context) {
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

#define rz_msg_digest_plugin_crca_preset(crcalgo, preset) \
	plugin_crca_preset_context_new(crcalgo, preset); \
	plugin_crca_preset_init(crcalgo, preset); \
	plugin_crca_preset_small_block(crcalgo, preset); \
	RzMsgDigestPlugin rz_msg_digest_plugin_crca_##crcalgo = { \
		.name = #crcalgo, \
		.license = "LGPL3", \
		.author = "deroad", \
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
		.type = RZ_LIB_TYPE_MD, \
		.data = &rz_msg_digest_plugin_crca_##crcalgo, \
		.version = RZ_VERSION \
	}
#else
#define rz_lib_plugin_crca_preset(crcalgo)
#endif

#define rz_plugin_crca_preset_definition(crcalgo, preset) \
	rz_msg_digest_plugin_crca_preset(crcalgo, preset); \
	rz_lib_plugin_crca_preset(crcalgo)

rz_plugin_crca_preset_definition(crc8smbus, /*    */ CRC_PRESET_8_SMBUS);
rz_plugin_crca_preset_definition(crc8cdma2000, /* */ CRC_PRESET_CRC8_CDMA2000);
rz_plugin_crca_preset_definition(crc8darc, /*     */ CRC_PRESET_CRC8_DARC);
rz_plugin_crca_preset_definition(crc8dvbs2, /*    */ CRC_PRESET_CRC8_DVB_S2);
rz_plugin_crca_preset_definition(crc8ebu, /*      */ CRC_PRESET_CRC8_EBU);
rz_plugin_crca_preset_definition(crc8icode, /*    */ CRC_PRESET_CRC8_ICODE);
rz_plugin_crca_preset_definition(crc8itu, /*      */ CRC_PRESET_CRC8_ITU);
rz_plugin_crca_preset_definition(crc8maxim, /*    */ CRC_PRESET_CRC8_MAXIM);
rz_plugin_crca_preset_definition(crc8rohc, /*     */ CRC_PRESET_CRC8_ROHC);
rz_plugin_crca_preset_definition(crc8wcdma, /*    */ CRC_PRESET_CRC8_WCDMA);
rz_plugin_crca_preset_definition(crc15can, /*     */ CRC_PRESET_15_CAN);
rz_plugin_crca_preset_definition(crc16, /*        */ CRC_PRESET_16);
rz_plugin_crca_preset_definition(crc16citt, /*    */ CRC_PRESET_16_CITT);
rz_plugin_crca_preset_definition(crc16usb, /*     */ CRC_PRESET_16_USB);
rz_plugin_crca_preset_definition(crc16hdlc, /*    */ CRC_PRESET_16_HDLC);
rz_plugin_crca_preset_definition(crc16augccitt, /**/ CRC_PRESET_CRC16_AUG_CCITT);
rz_plugin_crca_preset_definition(crc16buypass, /* */ CRC_PRESET_CRC16_BUYPASS);
rz_plugin_crca_preset_definition(crc16cdma2000, /**/ CRC_PRESET_CRC16_CDMA2000);
rz_plugin_crca_preset_definition(crc16dds110, /*  */ CRC_PRESET_CRC16_DDS110);
rz_plugin_crca_preset_definition(crc16dectr, /*   */ CRC_PRESET_CRC16_DECT_R);
rz_plugin_crca_preset_definition(crc16dectx, /*   */ CRC_PRESET_CRC16_DECT_X);
rz_plugin_crca_preset_definition(crc16dnp, /*     */ CRC_PRESET_CRC16_DNP);
rz_plugin_crca_preset_definition(crc16en13757, /* */ CRC_PRESET_CRC16_EN13757);
rz_plugin_crca_preset_definition(crc16genibus, /* */ CRC_PRESET_CRC16_GENIBUS);
rz_plugin_crca_preset_definition(crc16maxim, /*   */ CRC_PRESET_CRC16_MAXIM);
rz_plugin_crca_preset_definition(crc16mcrf4xx, /* */ CRC_PRESET_CRC16_MCRF4XX);
rz_plugin_crca_preset_definition(crc16riello, /*  */ CRC_PRESET_CRC16_RIELLO);
rz_plugin_crca_preset_definition(crc16t10dif, /*  */ CRC_PRESET_CRC16_T10_DIF);
rz_plugin_crca_preset_definition(crc16teledisk, /**/ CRC_PRESET_CRC16_TELEDISK);
rz_plugin_crca_preset_definition(crc16tms37157, /**/ CRC_PRESET_CRC16_TMS37157);
rz_plugin_crca_preset_definition(crca, /*         */ CRC_PRESET_CRCA);
rz_plugin_crca_preset_definition(crc16kermit, /*  */ CRC_PRESET_CRC16_KERMIT);
rz_plugin_crca_preset_definition(crc16modbus, /*  */ CRC_PRESET_CRC16_MODBUS);
rz_plugin_crca_preset_definition(crc16x25, /*     */ CRC_PRESET_CRC16_X25);
rz_plugin_crca_preset_definition(crc16xmodem, /*  */ CRC_PRESET_CRC16_XMODEM);
rz_plugin_crca_preset_definition(crc24, /*        */ CRC_PRESET_24);
rz_plugin_crca_preset_definition(crc32, /*        */ CRC_PRESET_32);
rz_plugin_crca_preset_definition(crc32ecma267, /* */ CRC_PRESET_32_ECMA_267);
rz_plugin_crca_preset_definition(crc32c, /*       */ CRC_PRESET_32C);
rz_plugin_crca_preset_definition(crc32bzip2, /*   */ CRC_PRESET_CRC32_BZIP2);
rz_plugin_crca_preset_definition(crc32d, /*       */ CRC_PRESET_CRC32D);
rz_plugin_crca_preset_definition(crc32mpeg2, /*   */ CRC_PRESET_CRC32_MPEG2);
rz_plugin_crca_preset_definition(crc32posix, /*   */ CRC_PRESET_CRC32_POSIX);
rz_plugin_crca_preset_definition(crc32q, /*       */ CRC_PRESET_CRC32Q);
rz_plugin_crca_preset_definition(crc32jamcrc, /*  */ CRC_PRESET_CRC32_JAMCRC);
rz_plugin_crca_preset_definition(crc32xfer, /*    */ CRC_PRESET_CRC32_XFER);
rz_plugin_crca_preset_definition(crc64, /*        */ CRC_PRESET_CRC64);
rz_plugin_crca_preset_definition(crc64ecma182, /* */ CRC_PRESET_CRC64_ECMA182);
rz_plugin_crca_preset_definition(crc64we, /*      */ CRC_PRESET_CRC64_WE);
rz_plugin_crca_preset_definition(crc64xz, /*      */ CRC_PRESET_CRC64_XZ);
rz_plugin_crca_preset_definition(crc64iso, /*     */ CRC_PRESET_CRC64_ISO);
