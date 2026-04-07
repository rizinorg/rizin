// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include <rz_bin.h>
#include <rz_lib.h>
#include "librz/bin/format/luac/luac_common.h"

#define GET_INTERNAL_BIN_INFO_OBJ(bf) ((LuacBinInfo *)(bf)->o->bin_obj)

static bool check_buffer(RzBuffer *buff) {
	if (rz_buf_size(buff) > LUAC_MAGIC_SIZE) {
		ut8 buf[LUAC_MAGIC_SIZE];
		rz_buf_read_at(buff, 0, buf, LUAC_MAGIC_SIZE);
		return !memcmp(buf, LUAC_MAGIC, LUAC_MAGIC_SIZE);
	}
	return false;
}

static int cmp_sections(const void *a, const void *b) {
	const RzBinSection *s_a = a;
	const RzBinSection *s_b = b;
	return s_a->paddr - s_b->paddr;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	LuaHeaderInfo *header = RZ_NEW0(LuaHeaderInfo);
	const size_t header_size = parse_header(bf, header);
	if (header_size == 0) {
		RZ_LOG_ERROR("Invalid or truncated luac header\n");
		free(header);
		return false;
	}
	LuaProto *proto = lua_parse_body(buf, header, header_size, bf->size);
	if (!proto) {
		RZ_LOG_ERROR("Invalid luac proto\n");
		free(header);
		return false;
	}

	RzBinInfo *general_info = lua_parse_bin_info(bf, header);

	LuacBinInfo *bin_info_obj = luac_build_info(proto);
	if (!bin_info_obj) {
		lua_free_proto_entry(proto);
		rz_bin_info_free(general_info);
		free(bin_info_obj);
		return false;
	}
	bin_info_obj->header = header;
	bin_info_obj->general_info = general_info;
	bin_info_obj->proto = proto;

	rz_pvector_sort(bin_info_obj->section_vec, (RzPVectorComparator)cmp_sections, NULL);

	obj->bin_obj = bin_info_obj;
	return true;
}

static RzBinInfo *info(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return bin_info_obj->general_info;
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return rz_pvector_clone(bin_info_obj->section_vec);
}

static void add_virtual_section(RzPVector /*<RzBinMap *>*/ *sections, const char *name, ut64 vaddr, ut64 size, int perm) {
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

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
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

	add_virtual_section(ret, "lua.globals", 0x10000, 0x1000, RZ_PERM_RW);
	add_virtual_section(ret, "lua.metatables", METATABLES_VOFFSET, 0x1000, RZ_PERM_R);
	add_virtual_section(ret, "lua.stack", 0x20000, 0x10000, RZ_PERM_RW);
	return ret;
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	RzListIter *iter;
	RzBinSymbol *sym;
	RzPVector *vec = rz_pvector_new(NULL);
	rz_list_foreach (bin_info_obj->symbol_list, iter, sym) {
		rz_pvector_push(vec, sym);
	}
	return vec;
}

static RzPVector /*<RzBinAddr *>*/ *entries(RzBinFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	rz_return_val_if_fail(bin_info_obj, NULL);
	return rz_pvector_clone(bin_info_obj->entry_vec);
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinStringSearchOpt opt;
	rz_bin_string_search_opt_init(&opt);
	opt.mode = RZ_BIN_STRING_SEARCH_MODE_READ_ONLY_SECTIONS;
	opt.string_encoding = RZ_STRING_ENC_UTF8;
	return rz_bin_file_strings(bf, &opt);
}

static void destroy(RzBinFile *bf) {
	LuacBinInfo *bin_info_obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	luac_build_info_free(bin_info_obj);
}

static RzStructuredData *get_structured_data_protos(RzStructuredData *parent, LuaProto *proto, st32 minor) {
	const ut8 instruction_size = minor == 0 ? 8 : 4;
	const size_t var_info_entries_len = rz_pvector_len(proto->local_var_info_entries);
	const size_t upvalue_entries_len = rz_pvector_len(proto->upvalue_entries);
	const size_t const_length = rz_pvector_len(proto->const_entries);
#ifndef RZ_DEBUG
	char name[16] = { 0 };
	rz_strf(name, "fcn.%08llx", proto->offset);

	char pnd[16] = { 0 };
	rz_strf(pnd, "%s", proto->proto_name ? (char *)proto->proto_name + 1 : name);
	RZ_LOG_DEBUG("\n%s <%s:%" PFMT32d ",%" PFMT32d "> (%" PFMT64d " instructions at 0x%p)\n",
		proto->line_defined == 0 ? "main" : "function",
		pnd,
		proto->line_defined,
		proto->lastline_defined,
		proto->code_size / instruction_size,
		&proto);

	RZ_LOG_DEBUG("%" PFMT32d "%s param%s, %" PFMT32d " slots, %" PFMTSZu " upvalues, %" PFMTSZu " locals, %" PFMTSZu " constants, %" PFMT32d " functions\n",
		proto->num_params,
		isvararg(proto->is_vararg) ? "+" : "",
		proto->num_params > 1 ? "s" : "",
		proto->max_stack_size,
		upvalue_entries_len,
		var_info_entries_len,
		const_length,
		proto->proto_entries->length);
	RZ_LOG_DEBUG("constants (%" PFMTSZu ")\n", const_length);
	st32 i = 0;
	(void)i;
	void **it_d;
	rz_pvector_foreach (proto->const_entries, it_d) {
		if (!it_d) {
			continue;
		}
		const LuaConstEntry *val = (LuaConstEntry *)*it_d;

		if ((val->tag & 0x0F) == LUA_TSTRING) {
			RZ_LOG_DEBUG("%" PFMT32d "	%s\n", ++i, val->data ? (char *)val->data : "NULL");
		} else if (val->tag == LUA_VNUMINT) {
			RZ_LOG_DEBUG("%" PFMT32d "	%" PFMT64d "\n", ++i, *(st64 *)val->data);
		} else if (val->tag == LUA_VNUMFLT) {
			RZ_LOG_DEBUG("%" PFMT32d "	%f\n", ++i, *(double *)val->data);
		} else if ((val->tag & 0x0F) == LUA_TBOOLEAN) {
			RZ_LOG_DEBUG("%" PFMT32d "	%s\n", ++i, (bool)val->data == true ? "true" : "false");
		} else if ((val->tag & 0x0F) == LUA_TNIL) {
			RZ_LOG_DEBUG("%" PFMT32d "	%s\n", ++i, "NIL");
		} else if (val->tag == LUA_VSTRING_IDX) {
			RZ_LOG_DEBUG("%" PFMT32d "	%d\n", ++i, *(ut8 *)val->data);
		} else {
			rz_warn_if_reached();
		}
	}
#endif
	char key[16] = { 0 };
	rz_strf(key, "fcn.%08" PFMT64x, proto->offset);
	RzStructuredData *sd = rz_structured_data_map_add_map(parent, key);
	if (!sd) {
		return NULL;
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
	if (!proto->const_entries)
		return sd;

	rz_structured_data_map_add_unsigned(sd, "constants_count", const_length, false);
	if (const_length > 0) {
		RzStructuredData *constants = rz_structured_data_map_add_array(sd, "constants");
		if (!constants) {
			return NULL;
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
				rz_structured_data_array_add_boolean(constants, (bool)val->data);
			} else if ((val->tag & 0x0F) == LUA_TNIL) {
				rz_structured_data_array_add_string(constants, "NIL");
			} else if (val->tag == LUA_VSTRING_IDX) {
			} else {
				rz_warn_if_reached();
			}
		}
	}
	return sd;
}

static RzStructuredData *luac_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->rbin && bf->o && bf->o->bin_obj, NULL);
	const LuacBinInfo *obj = GET_INTERNAL_BIN_INFO_OBJ(bf);
	const LuaHeaderInfo *header_info = (LuaHeaderInfo *)obj->header;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *modinfo = rz_structured_data_map_add_map(info, "luac-info");
	if (!modinfo) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *version = rz_structured_data_map_add_map(modinfo, "version");
	if (!version) {
		rz_structured_data_free(modinfo);
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add_signed(version, "major", header_info->major);
	rz_structured_data_map_add_signed(version, "minor", header_info->minor);

	rz_structured_data_map_add_string(modinfo, "compiler", obj->general_info->compiler);

	if (obj->general_info->guid) {
		rz_structured_data_map_add_string(modinfo, "source_file_name", obj->general_info->guid);
	}

	rz_structured_data_map_add_unsigned(modinfo, "header_size", obj->proto->offset - 1, false);
	rz_structured_data_map_add_unsigned(modinfo, "body_size", obj->proto->size, false);
	rz_structured_data_map_add_unsigned(modinfo, "file_size", obj->proto->offset - 1 + obj->proto->size, false);

	RzStructuredData *protos = rz_structured_data_map_add_map(modinfo, "protos");
	if (!protos) {
		rz_structured_data_free(version);
		rz_structured_data_free(modinfo);
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *psd = get_structured_data_protos(protos, obj->proto, obj->header->minor);
	if (!psd) {
		rz_structured_data_free(protos);
		rz_structured_data_free(version);
		rz_structured_data_free(modinfo);
		rz_structured_data_free(info);
	}
	RzListIter *iter;
	LuaProto *sub_proto;
	rz_list_foreach (obj->proto->proto_entries, iter, sub_proto) {
		get_structured_data_protos(protos, sub_proto, obj->header->minor);
	}
	return info;
}

RzBinPlugin rz_bin_plugin_luac = {
	.name = "luac",
	.desc = "Lua compiled binary",
	.license = "LGPL3",
	.author = "Heersin",
	.get_sdb = NULL,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = NULL,
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
