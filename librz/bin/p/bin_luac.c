// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include <rz_bin.h>
#include <rz_lib.h>
#include "luac/luac_54.h"

typedef struct version_context_t {
	st32 major;
	st32 minor;
} LuaVersion;
#define GET_VERSION_INFO_FROM_BINF(bf) ((LuaVersion *)(bf)->o->bin_obj)

static bool check_buffer(RzBuffer *buff) {
	if (rz_buf_size(buff) > 4) {
		ut8 buf[LUAC_MAGIC_SIZE];
		rz_buf_read_at(buff, LUAC_MAGIC_OFFSET, buf, LUAC_MAGIC_SIZE);
		return (!memcmp(buf, LUAC_MAGIC, LUAC_MAGIC_SIZE));
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	ut8 MAJOR_MINOR_VERSION;
        LuaVersion *version_info;

        rz_buf_read_at(buf, LUAC_VERSION_OFFSET, &MAJOR_MINOR_VERSION, sizeof(MAJOR_MINOR_VERSION)); /* 1-byte in fact */
	if ((version_info = RZ_NEW(LuaVersion)) == NULL){
		return false;
	}

	version_info->major = (MAJOR_MINOR_VERSION & 0xF0) >> 4;
	version_info->minor = (MAJOR_MINOR_VERSION & 0x0F);

	*bin_obj = version_info;

	return check_buffer(buf);
}

static RzBinInfo *info(RzBinFile *bf) {
	LuaVersion *version_info = GET_VERSION_INFO_FROM_BINF(bf);

	if (version_info->major != 5) {
		eprintf("currently support lua 5.x only\n");
		return NULL;
	}

	switch (version_info->minor) {
	case 4:
		return info_54(bf, version_info->major, version_info->minor);
		break;
	default:
		eprintf("lua 5.%c not support now\n", version_info->minor + '0');
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