// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-FileCopyrightText: 2026 Arya-1-HR

#include <rz_bin.h>
#include <rz_lib.h>
#include "librz/bin/format/luac/luac_common.h"
#include "librz/bin/format/luac/luajit/luajit.h"

static int get_cpu_type(RzBuffer *buff) {
	if (rz_buf_size(buff) >= LUAC_MAGIC_SIZE) { // Max size of magic is considered.
		ut8 buf[LUAC_MAGIC_SIZE] = RZ_EMPTY;
		rz_buf_read_at(buff, 0, buf, sizeof(buf));
		if (!memcmp(buf, LUAC_MAGIC, LUAC_MAGIC_SIZE)) {
			return LUAC_CPU;
		}
		if (!memcmp(buf, LUAJIT_MAGIC, LUAJIT_MAGIC_BYTE_SIZE)) {
			return LUAJIT_CPU;
		}
	}
	return 0;
}

static int luac_cmp_sections(const void *a, const void *b) {
	const RzBinSection *s_a = a;
	const RzBinSection *s_b = b;
	return s_a->paddr - s_b->paddr;
}

static bool luac_load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	LuaHeaderInfo *header = RZ_NEW0(LuaHeaderInfo);
	if (!header) {
		return false;
	}
	const size_t header_size = parse_header(bf, header);
	if (header_size == 0) {
		RZ_LOG_ERROR("Invalid or truncated luac header\n");
		RZ_FREE(header->src_file_name);
		free(header);
		return false;
	}
	LuaProto *proto = lua_parse_body(buf, header, header_size, bf->size);
	if (!proto) {
		RZ_LOG_ERROR("Invalid luac proto\n");
		RZ_FREE(header->src_file_name);
		free(header);
		return false;
	}

	LuacBinInfo *bin_info_obj = luac_build_info(proto);
	bin_info_obj->cpu = LUAC_CPU;
	if (!bin_info_obj) {
		lua_free_proto_entry(proto);
		RZ_FREE(header->src_file_name);
		free(bin_info_obj);
		return false;
	}
	bin_info_obj->header = header;
	bin_info_obj->proto = proto;

	rz_pvector_sort(bin_info_obj->section_vec, (RzPVectorComparator)luac_cmp_sections, NULL);

	obj->bin_obj = bin_info_obj;
	return true;
}

static RzBinInfo *luac_info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuacBinInfo, bf);
	if (!bin_info_obj) {
		return NULL;
	}
	return lua_parse_bin_info(bf, (LuaHeaderInfo *)bin_info_obj->header);
}

static RzPVector /*<RzBinSection *>*/ *luac_sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuacBinInfo, bf);
	if (!bin_info_obj) {
		return NULL;
	}
	return rz_pvector_clone(bin_info_obj->section_vec);
}

static void luac_add_virtual_section(RzPVector /*<RzBinMap *>*/ *sections, const char *name, ut64 vaddr, ut64 size, int perm) {
	RzBinMap *map = (RzBinMap *)RZ_NEW0(RzBinMap);
	if (!map) {
		return;
	}
	map->name = rz_str_dup(name);
	map->vaddr = vaddr;
	map->vsize = size;
	map->perm = perm;

	if (!rz_pvector_push(sections, map)) {
		rz_bin_map_free(map);
	}
}

static RzPVector /*<RzBinMap *>*/ *luac_maps(RzBinFile *bf) {
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}

	LuacBinInfo *obj = bf->o->bin_obj;

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_map_free);
	if (!ret) {
		return NULL;
	}

	RzBinMap *map = NULL;

	void **it;
	rz_pvector_foreach (obj->section_vec, it) {
		const RzBinSection *bin_sec = (RzBinSection *)*it;

		if (!((map = RZ_NEW0(RzBinMap)))) {
			rz_pvector_free(ret);
			return NULL;
		}
		map->paddr = bin_sec->paddr;
		map->vaddr = bin_sec->vaddr;
		map->psize = map->vsize = bin_sec->size;
		map->perm = bin_sec->perm;
		map->name = rz_str_dup(bin_sec->name);
		rz_pvector_push(ret, map);
	}

	luac_add_virtual_section(ret, "lua.globals", 0x10000, 0x1000, RZ_PERM_RW);
	luac_add_virtual_section(ret, "lua.metatables", METATABLES_VOFFSET, 0x1000, RZ_PERM_R);
	luac_add_virtual_section(ret, "lua.stack", 0x20000, 0x10000, RZ_PERM_RW);
	return ret;
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->info && bf->o->info->cpu, NULL);
	if (rz_str_startswith(bf->o->info->cpu, "luajit")) {
		return NULL;
	} else {
		return luac_maps(bf);
	}
}

static RzPVector /*<RzBinSymbol *>*/ *luac_symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuacBinInfo, bf);
	if (!bin_info_obj) {
		return NULL;
	}
	RzListIter *iter;
	RzBinSymbol *sym;
	RzPVector *vec = rz_pvector_new(NULL);
	rz_list_foreach (bin_info_obj->symbol_list, iter, sym) {
		rz_pvector_push(vec, sym);
	}
	return vec;
}

static RzPVector /*<RzBinAddr *>*/ *luac_entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(LuacBinInfo, bf);
	if (!bin_info_obj) {
		return NULL;
	}
	return rz_pvector_clone(bin_info_obj->entry_vec);
}

static RzPVector /*<RzBinString *>*/ *luac_strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.string_encoding = RZ_STRING_ENC_UTF8;
	return rz_bin_file_strings(bf, &opt);
}

static void luajit_build_info_free(LuaJITBinInfo *bin_info) {
	if (!bin_info) {
		return;
	}
	RZ_FREE(bin_info->file_name);

	rz_pvector_free(bin_info->entry_vec);
	rz_list_free(bin_info->strings);
	rz_pvector_free(bin_info->sections);
	rz_list_free(bin_info->symbol_list);
	free(bin_info);
}

static void luac_get_structured_data_protos(RzStructuredData *parent, LuaProto *proto, st32 minor) {
	const ut8 instruction_size = minor == 0 ? 8 : 4;
	const size_t var_info_entries_len = rz_pvector_len(proto->local_var_info_entries);
	const size_t upvalue_entries_len = rz_pvector_len(proto->upvalue_entries);
	const size_t const_length = rz_pvector_len(proto->const_entries);

	char key[16] = { 0 };
	rz_strf(key, "fcn.%08" PFMT64x, proto->offset);
	RzStructuredData *sd = rz_structured_data_map_add_map(parent, key);
	if (!sd) {
		return;
	}
	char pn[16] = { 0 };
	rz_strf(pn, proto->line_defined ? "fcn.%08" PFMT64x : "main.%08" PFMT64x, proto->offset);
	rz_structured_data_map_add_string(sd, "proto_name", pn);

	rz_structured_data_map_add_unsigned(sd, "start_line", proto->line_defined, false);
	rz_structured_data_map_add_unsigned(sd, "last_line", proto->lastline_defined, false);
	rz_structured_data_map_add_unsigned(sd, "instructions", proto->code_size / instruction_size, false);

	rz_structured_data_map_add_unsigned(sd, "num_params", proto->num_params, false);
	rz_structured_data_map_add_unsigned(sd, "slots", proto->max_stack_size, false);
	rz_structured_data_map_add_unsigned(sd, "functions", proto->proto_entries->length, false);
	rz_structured_data_map_add_unsigned(sd, "locals", var_info_entries_len, false);
	rz_structured_data_map_add_unsigned(sd, "upvalues", upvalue_entries_len, false);
	if (!proto->const_entries) {
		return;
	}

	if (const_length > 0) {
		RzStructuredData *constants = rz_structured_data_map_add_array(sd, "constants");
		if (!constants) {
			return;
		}
		LuaConstEntry *val = NULL;
		void **it;
		rz_pvector_foreach (proto->const_entries, it) {
			val = (LuaConstEntry *)*it;
			if (!val) {
				continue;
			}
			if ((val->tag & 0x0F) == LUA_TSTRING) {
				rz_structured_data_array_add_string(constants, val->data ? (char *)val->data : "NULL");
			} else if (val->tag == LUA_VNUMINT) {
				rz_structured_data_array_add_signed(constants, *(st64 *)val->data);
			} else if (val->tag == LUA_VNUMFLT) {
				rz_structured_data_array_add_double(constants, *(double *)val->data);
			} else if ((val->tag & 0x0F) == LUA_TBOOLEAN) {
				rz_structured_data_array_add_boolean(constants, *(bool *)val->data);
			} else if ((val->tag & 0x0F) == LUA_TNIL) {
				rz_structured_data_array_add_string(constants, "NIL");
			} else if (val->tag == LUA_OPENWRT_INT32) {
				rz_structured_data_array_add_unsigned(constants, *(ut16 *)val->data, false);
			}
		}
	}
}

static RzStructuredData *luac_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->rbin && bf->o && bf->o->bin_obj && bf->o->info->cpu, NULL);
	if (rz_str_startswith(bf->o->info->cpu, "luajit")) {
		return NULL;
	}
	const LuacBinInfo *obj = GET_INTERNAL_BIN_INFO_OBJ(LuacBinInfo, bf);
	const LuaHeaderInfo *header_info = (LuaHeaderInfo *)obj->header;

	RzStructuredData *info = NULL;
	RzBinInfo *general_info = lua_parse_bin_info(bf, header_info);
	info = rz_structured_data_new_map();
	if (!general_info || !info) {
		goto fail;
	}

	RzStructuredData *modinfo = rz_structured_data_map_add_map(info, "luac-info");
	if (!modinfo) {
		goto fail;
	}

	RzStructuredData *version = rz_structured_data_map_add_map(modinfo, "version");
	if (!version) {
		goto fail;
	}

	rz_structured_data_map_add_signed(version, "major", header_info->major);
	rz_structured_data_map_add_signed(version, "minor", header_info->minor);
	rz_structured_data_map_add_string(modinfo, "compiler", general_info->compiler);

	if (general_info->guid) {
		rz_structured_data_map_add_string(modinfo, "source_file_name", general_info->guid);
	}

	rz_structured_data_map_add_unsigned(modinfo, "header_size", obj->proto->offset - 1, false);
	rz_structured_data_map_add_unsigned(modinfo, "body_size", obj->proto->size, false);
	rz_structured_data_map_add_unsigned(modinfo, "file_size", obj->proto->offset - 1 + obj->proto->size, false);

	RzStructuredData *protos = rz_structured_data_map_add_map(modinfo, "protos");
	if (!protos) {
		goto fail;
	}

	luac_get_structured_data_protos(protos, obj->proto, obj->header->minor);

	RzListIter *iter;
	LuaProto *sub_proto;
	rz_list_foreach (obj->proto->proto_entries, iter, sub_proto) {
		luac_get_structured_data_protos(protos, sub_proto, obj->header->minor);
	}

	rz_bin_info_free(general_info);
	return info;

fail:
	rz_bin_info_free(general_info);
	rz_structured_data_free(info);
	return NULL;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	switch (get_cpu_type(buf)) {
	case LUAJIT_CPU:
		return luajit_load_buffer(bf, obj, buf, sdb);
	case LUAC_CPU:
		return luac_load_buffer(bf, obj, buf, sdb);
	default:
		return false;
	}
}

static void destroy(RzBinFile *bf) {
	rz_return_if_fail(bf && bf->o && bf->o->bin_obj);
	int cpu_type = *(int *)bf->o->bin_obj;
	switch (cpu_type) {
	case LUAJIT_CPU: {
		LuaJITBinInfo *bin_info_obj_luajit = GET_INTERNAL_BIN_INFO_OBJ(LuaJITBinInfo, bf);
		rz_return_if_fail(bin_info_obj_luajit);
		luajit_build_info_free(bin_info_obj_luajit);
		break;
	}
	case LUAC_CPU: {
		LuacBinInfo *bin_info_obj_luac = GET_INTERNAL_BIN_INFO_OBJ(LuacBinInfo, bf);
		rz_return_if_fail(bin_info_obj_luac);
		luac_build_info_free(bin_info_obj_luac);
		break;
	}
	default:
		return;
	}
}

static bool check_buffer(RzBuffer *buff) {
	return get_cpu_type(buff) != 0;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->info && bf->o->info->cpu, NULL);
	if (rz_str_startswith(bf->o->info->cpu, "luajit")) {
		return luajit_entries(bf);
	} else {
		return luac_entries(bf);
	}
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->info && bf->o->info->cpu, NULL);
	if (rz_str_startswith(bf->o->info->cpu, "luajit")) {
		return luajit_sections(bf);
	} else {
		return luac_sections(bf);
	}
}

static RzPVector /*<RzBinSection *>*/ *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->info && bf->o->info->cpu, NULL);
	if (rz_str_startswith(bf->o->info->cpu, "luajit")) {
		return luajit_symbols(bf);
	} else {
		return luac_symbols(bf);
	}
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	switch (get_cpu_type(bf->buf)) {
	case LUAJIT_CPU:
		return luajit_info(bf);
	case LUAC_CPU:
		return luac_info(bf);
	default:
		return NULL;
	}
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->info && bf->o->info->cpu, NULL);
	if (rz_str_startswith(bf->o->info->cpu, "luajit")) {
		return luajit_strings(bf);
	} else {
		return luac_strings(bf);
	}
}

RzBinPlugin rz_bin_plugin_luac = {
	.name = "luac",
	.desc = "Lua compiled binary",
	.license = "LGPL3",
	.author = "Heersin",
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.info = &info,
	.bin_structure = &luac_structure,
	.strings = &strings,
	.maps = &maps,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luac,
	.version = RZ_VERSION
};
#endif
