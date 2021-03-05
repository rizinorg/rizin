// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include <rz_lib.h>
#include "luac/luac_54.h"

static int MAJOR_VERSION;
static int MINOR_VERSION;
static ut8 MAJOR_MINOR_VERSION;

static bool check_buffer(RzBuffer *buff) {
	if (rz_buf_size(buff) > 4) {
		ut8 buf[4];
		rz_buf_read_at(buff, 0, buf, sizeof(buf));
		return (!memcmp(buf, LUAC_MAGIC, sizeof(buf)));
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	rz_buf_read_at(buf, 4, &MAJOR_MINOR_VERSION, sizeof(MAJOR_MINOR_VERSION)); /* 1-byte in fact */
	MAJOR_VERSION = (MAJOR_MINOR_VERSION & 0xF0) >> 4;
	MINOR_VERSION = MAJOR_MINOR_VERSION & 0x0F;
	return check_buffer(buf);
}

static RzBinInfo *info(RzBinFile *bf) {
	if (MAJOR_VERSION != 5) {
		eprintf("currently support lua 5.x only\n");
		return NULL;
	}

	switch (MINOR_VERSION) {
	case 4:
		return info_54(bf, MAJOR_VERSION, MINOR_VERSION);
		break;
	default:
		eprintf("lua 5.%c not support now\n", MINOR_VERSION + '0');
		return NULL;
	}
}

RzBinPlugin rz_bin_plugin_luac = {
	.name = "luac",
	.desc = "LUA Compiled File",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = NULL,
	.sections = NULL,
	.info = &info
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luac,
	.version = RZ_VERSION
};
#endif