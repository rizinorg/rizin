// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include <rz_bin.h>
#include <rz_lib.h>
#include "librz/bin/format/luac/luac_common.h"

#define GET_VERSION_INFO_FROM_BINF(bf) ((LuacBinInfo *)(bf)->o->bin_obj)

static bool check_buffer(RzBuffer *buff) {
	if (rz_buf_size(buff) > 4) {
		ut8 buf[LUAC_MAGIC_SIZE];
		rz_buf_read_at(buff, LUAC_MAGIC_OFFSET, buf, LUAC_MAGIC_SIZE);
		return !memcmp(buf, LUAC_MAGIC, LUAC_MAGIC_SIZE);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, void **bin_obj, RzBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	ut8 MAJOR_MINOR_VERSION;
	LuacBinInfo *bin_info_obj;

	rz_buf_read_at(buf, LUAC_VERSION_OFFSET, &MAJOR_MINOR_VERSION, sizeof(MAJOR_MINOR_VERSION)); /* 1-byte in fact */
	if ((bin_info_obj = RZ_NEW(LuacBinInfo)) == NULL) {
		return false;
	}

	ut8 *work_buf[4096];
	rz_buf_read_at(buf, 0, (ut8 *)work_buf, 4096);

	// TODO : switch version here
	LuaProto *proto;
	proto = lua_parse_body_54((ut8 *)work_buf, 0x20, 4096);

	bin_info_obj = luac_build_info(proto);

	lua_free_proto_entry(proto);
	proto = NULL;

        bin_info_obj->major = (MAJOR_MINOR_VERSION & 0xF0) >> 4;
        bin_info_obj->minor = (MAJOR_MINOR_VERSION & 0x0F);

        *bin_obj = bin_info_obj;
	return true;
}

static RzBinInfo *info(RzBinFile *bf) {
	LuacBinInfo *bin_info_obj = GET_VERSION_INFO_FROM_BINF(bf);

	if (bin_info_obj->major != 5) {
		eprintf("currently support lua 5.x only\n");
		return NULL;
	}

	switch (bin_info_obj->minor) {
	case 4:
		return lua_info_54(bf, bin_info_obj->major, bin_info_obj->minor);
		break;
	default:
		eprintf("lua 5.%c not support now\n", bin_info_obj->minor + '0');
		return NULL;
	}
}

static RzList *sections(RzBinFile *arch){
	if (!arch){
		return NULL;
	}
	LuacBinInfo *bin_info_obj = GET_VERSION_INFO_FROM_BINF(arch);
	if (!bin_info_obj){
		return NULL;
	}

	return bin_info_obj->section_list;
}

static RzList *symbols(RzBinFile *arch){
        if (!arch){
                return NULL;
        }
        LuacBinInfo *bin_info_obj = GET_VERSION_INFO_FROM_BINF(arch);
        if (!bin_info_obj){
                return NULL;
        }

	return bin_info_obj->symbol_list;
}

static RzList *entries(RzBinFile *arch){
        if (!arch){
                return NULL;
        }
        LuacBinInfo *bin_info_obj = GET_VERSION_INFO_FROM_BINF(arch);
        if (!bin_info_obj){
                return NULL;
        }

        return bin_info_obj->entry_list;
}


RzBinPlugin rz_bin_plugin_luac = {
	.name = "luac",
	.desc = "LUA Compiled File",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luac,
	.version = RZ_VERSION
};
#endif
