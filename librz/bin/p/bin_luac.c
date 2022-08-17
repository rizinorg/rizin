// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include <rz_bin.h>
#include <rz_lib.h>
#include "librz/bin/format/luac/luac_common.h"

#define GET_INTERNAL_BIN_INFO_OBJ(bf) ((LuacBinInfo *)(bf)->o->bin_obj)

static bool check_buffer(RzBuffer *buff) {
	if (rz_buf_size(buff) > 4) {
		ut8 buf[LUAC_MAGIC_SIZE];
		rz_buf_read_at(buff, LUAC_MAGIC_OFFSET, buf, LUAC_MAGIC_SIZE);
		return !memcmp(buf, LUAC_MAGIC, LUAC_MAGIC_SIZE);
	}
	return false;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ut8 MAJOR_MINOR_VERSION;
	LuacBinInfo *bin_info_obj = NULL;
	LuaProto *proto = NULL;
	RzBinInfo *general_info = NULL;
	st32 major;
	st32 minor;

	rz_buf_read_at(buf, LUAC_VERSION_OFFSET, &MAJOR_MINOR_VERSION, sizeof(MAJOR_MINOR_VERSION)); /* 1-byte in fact */
	if ((bin_info_obj = RZ_NEW(LuacBinInfo)) == NULL) {
		return false;
	}
	major = (MAJOR_MINOR_VERSION & 0xF0) >> 4;
	minor = (MAJOR_MINOR_VERSION & 0x0F);

	if (major != 5) {
		RZ_LOG_ERROR("currently support lua 5.x only\n");
		return false;
	}

	switch (minor) {
	case 4:
		proto = lua_parse_body_54(buf, 0x20, bf->size);
		general_info = lua_parse_header_54(bf, major, minor);
		break;
	case 3:
		proto = lua_parse_body_53(buf, 0x22, bf->size);
		general_info = lua_parse_header_53(bf, major, minor);
		break;
	default:
		RZ_LOG_ERROR("lua 5.%c not support now\n", minor + '0');
		return false;
	}

	bin_info_obj = luac_build_info(proto);
	if (bin_info_obj == NULL) {
		lua_free_proto_entry(proto);
		rz_bin_info_free(general_info);
		return false;
	}
	bin_info_obj->general_info = general_info;
	bin_info_obj->major = major;
	bin_info_obj->minor = minor;

	lua_free_proto_entry(proto);
	proto = NULL;

	obj->bin_obj = bin_info_obj;
	return true;
}

static RzBinInfo *info(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return bin_info_obj->general_info;
}

static RzList *sections(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return rz_list_clone(bin_info_obj->section_list);
}

static RzList *symbols(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return rz_list_clone(bin_info_obj->symbol_list);
}

static RzList *entries(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return rz_list_clone(bin_info_obj->entry_list);
}

static RzList *strings(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return rz_list_clone(bin_info_obj->string_list);
}

static void destroy(RzBinFile *bf) {
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	luac_build_info_free(bin_info_obj);
}

RzBinPlugin rz_bin_plugin_luac = {
	.name = "luac",
	.desc = "LUA Compiled File",
	.license = "LGPL3",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = NULL,
	.entries = &entries,
	.maps = &rz_bin_maps_of_file_sections,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.strings = &strings,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luac,
	.version = RZ_VERSION
};
#endif
