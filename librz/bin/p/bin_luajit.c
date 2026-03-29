// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2026 Arya H R <aryagowda177@gmail.com>

#include <rz_bin.h>
#include <rz_lib.h>
#include "../format/luajit/luajit.h"

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

static void luajit_destroy(RzBinFile *bf) {
	LuaJITBinInfo *bin_info_obj = LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf);
	luajit_build_info_free(bin_info_obj);
}

static RzPVector /*<RzBinAddr *>*/ *luajit_entries(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuaJITBinInfo *bin_info_obj = LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return rz_pvector_clone(bin_info_obj->entry_vec);
}

void luajit_add_entry(RzPVector /*<RzBinAddr *>*/ *entry_vec, ut64 offset, int entry_type) {
	RzBinAddr *entry = RZ_NEW0(RzBinAddr);
	if (!entry) {
		return;
	}

	entry->vaddr = offset;
	entry->paddr = offset;
	entry->type = entry_type;

	rz_pvector_push(entry_vec, entry);
}

static void luajit_add_strings(RzList /*<RzBinString *>*/ *string_list, char *string, ut64 offset, ut64 baddr) {
	RzBinString *bin_string = RZ_NEW0(RzBinString);
	if (!bin_string || !string) {
		return;
	}

	bin_string->paddr = offset;
	bin_string->vaddr = offset + baddr;
	bin_string->size = rz_str_ansi_len(string);
	bin_string->length = rz_str_ansi_len(string);
	bin_string->string = rz_str_dup(string);
	bin_string->type = RZ_STRING_ENC_UTF8;

	rz_list_append(string_list, bin_string);
}

void luajit_add_section(RzPVector /*<RzBinSection *>*/ *section_vec, char *name, ut64 offset, ut32 size, bool is_data, bool has_strings) {
	if (RZ_STR_ISEMPTY(name)) {
		return;
	}
	RzBinSection *bin_sec = RZ_NEW0(RzBinSection);

	bin_sec->name = name;
	bin_sec->vaddr = bin_sec->paddr = offset;
	bin_sec->size = bin_sec->vsize = size;
	bin_sec->is_data = is_data;
	bin_sec->bits = 32;
	bin_sec->has_strings = has_strings;
	bin_sec->arch = "luajit";

	if (!is_data) {
		bin_sec->perm = RZ_PERM_R | RZ_PERM_X;
	} else {
		bin_sec->perm = RZ_PERM_R;
	}

	if (!rz_pvector_push(section_vec, bin_sec)) {
		rz_bin_section_free(bin_sec);
	}
}

void luajit_add_symbol(RzList /*<RzBinSymbol *>*/ *symbol_list, char *name, ut64 offset, ut64 size, const char *type) {
	RzBinSymbol *bin_sym = RZ_NEW0(RzBinSymbol);
	if (!bin_sym) {
		return;
	}

	bin_sym->name = name;
	bin_sym->vaddr = bin_sym->paddr = offset;
	bin_sym->size = size;
	bin_sym->type = type;

	rz_list_append(symbol_list, bin_sym);
}

static void free_rz_addr(RzBinAddr *addr) {
	if (!addr) {
		return;
	}
	free(addr);
}

static LuaJITBinInfo *luajit_build_info_new() {
	LuaJITBinInfo *ret = RZ_NEW0(LuaJITBinInfo);

	ret->entry_vec = rz_pvector_new((RzPVectorFree)free_rz_addr);
	ret->strings = rz_list_newf((RzListFree)rz_bin_string_free);
	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	ret->sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);

	if ((!ret->strings || !ret->entry_vec || !ret->sections || !ret->symbol_list)) {
		rz_pvector_free(ret->entry_vec);
		rz_pvector_free(ret->sections);
		rz_list_free(ret->strings);
		rz_list_free(ret->symbol_list);
		return NULL;
	}

	return ret;
}

/**
 * \brief Calculates the section size
 * \param l List of pointers of different section types defined in "LuaJITSection".
 * \param type Type of pointer the list \p l contains.
 *
 * \return size of the section sent.
 */
int luajit_get_section_size(RzList /*<void *>*/ *l, LuaJITSection type) {
	if (rz_list_empty(l)) {
		return 0;
	}
	RzListIter *iter;
	int size = 0;

	switch (type) {
	case LUAJIT_STKGCOBJ: {
		LuaJITKgcObj *Kgc_obj;
		rz_list_foreach (l, iter, Kgc_obj) {
			size += Kgc_obj->size;
		}
		break;
	}
	case LUAJIT_STTABLE: {
		LuaJITTable *table;
		rz_list_foreach (l, iter, table) {
			size += table->size;
		}
		break;
	}
	case LUAJIT_STCONSTENTR: {
		LuaJITConstEntry *constant;
		rz_list_foreach (l, iter, constant) {
			size += constant->size;
		}
		break;
	}
	case LUAJIT_STLOCALVAR: {
		LuaJITLocalVar *localvar;
		rz_list_foreach (l, iter, localvar) {
			size += localvar->size;
		}
		break;
	}
	case LUAJIT_STUPVALINFO: {
		LuaJITUpValue *up_val_info;
		rz_list_foreach (l, iter, up_val_info) {
			size += up_val_info->size;
		}
		break;
	}
	default:
		RZ_LOG_ERROR("Invalid Section Type\n");
		return 0;
		break;
	}
	return size;
}

char *get_symbol_const_name(char *proto_name, LuaJITConstEntry *const_entry) {
	rz_return_val_if_fail(proto_name || const_entry, NULL);
	ut8 tag = const_entry->type;
	char *ret;

	switch (tag) {
	case LUAJIT_TINT:
		ret = rz_str_newf("%s_const_%d", proto_name, const_entry->val.int_val);
		break;
	case LUAJIT_TFLT:
		ret = rz_str_newf("%s_const_%f", proto_name, const_entry->val.flt_val);
		break;
	default:
		ret = rz_str_newf("%s_const_0x%" PFMT64x, proto_name, const_entry->offset);
		break;
	}
	return ret;
}

char *get_value_symbol_name(char *proto_name, LuaJITValue *val) {
	rz_return_val_if_fail(proto_name || val, NULL);
	ut8 tag = val->type;
	char *ret;

	switch (tag) {
	case LUAJIT_TNILL:
		ret = rz_str_newf("%s_val_nil", proto_name);
		break;
	case LUAJIT_TTRUE:
		ret = rz_str_newf("%s_val_true", proto_name);
		break;
	case LUAJIT_TFALSE:
		ret = rz_str_newf("%s_val_false", proto_name);
		break;
	case LUAJIT_TINT:
		ret = rz_str_newf("%s_val_%d", proto_name, *(int *)val->data);
		break;
	case LUAJIT_TFLT:
		ret = rz_str_newf("%s_val_%f", proto_name, *(double *)val->data);
		break;
	default:
		ret = rz_str_newf("%s_val_0x%" PFMT64x, proto_name, val->offset);
		break;
	}
	return ret;
}

static const char *get_tag_string(LuaJITValueType tag, bool is_const) {
	switch (tag) {
	case LUAJIT_TNILL:
		return is_const ? "CONST_NIL" : "VAL_NIL";
	case LUAJIT_TTRUE:
	case LUAJIT_TFALSE:
		return is_const ? "CONST_BOOL" : "VAL_BOOL";
	case LUAJIT_TINT:
	case LUAJIT_TFLT:
		return is_const ? "CONST_NUM" : "VAL_NUM";
	default:
		return is_const ? "CONST_UNKNOWN" : "VAL_UNKNOWN";
	}
}

void add_table_string(LuaJITBinInfo *bi, LuaJITValue *val) {
	if (val->type > 5) {
		luajit_add_strings(bi->strings, val->data, val->offset, bi->baddr);
	}
}

char *get_luajit_cmplx_symbol(LuaJITKgcObj *k, char *proto_loc) {
	if (!k || !proto_loc) {
		return NULL;
	}
	return rz_str_newf("%s_kgcconst_%f%+fi", proto_loc, k->cmplx.r_bits, k->cmplx.i_bits);
}

char *get_kgc_symbol_type(LuaJITKGCTypes type) {
	if (type == LUAJIT_KGCINT || type == LUAJIT_KGCFLT) {
		return "KGC_NUM";
	} else if (type == LUAJIT_KGCCMPLX) {
		return "KGC_CMPLX";
	}
	return NULL;
}

static void build_kgc_objects(LuaJITProto *proto, LuaJITBinInfo *info, char *proto_loc) {
	rz_return_if_fail(proto_loc);
	if (rz_list_empty(proto->kgc_obj)) {
		return;
	}

	RzListIter *iter;
	LuaJITKgcObj *kgc_obj = rz_list_first_val(proto->kgc_obj);
	ut64 current_offset = kgc_obj->offset;
	ut64 current_size = luajit_get_section_size(proto->kgc_obj, LUAJIT_STKGCOBJ);

	char *section_name = rz_str_newf("%s.kgcobj", proto_loc);
	rz_return_if_fail(section_name);
	luajit_add_section(info->sections, section_name, current_offset, current_size, true, true);

	rz_list_foreach (proto->kgc_obj, iter, kgc_obj) {
		char *symbol_name = NULL;
		const char *symbol_type = get_kgc_symbol_type(kgc_obj->type);

		switch (kgc_obj->type) {
		case LUAJIT_KGCINT:
			if (kgc_obj->data) {
				symbol_name = rz_str_newf("%s_kgcconst_%" PFMT64d, proto_loc, *(ut64 *)kgc_obj->data);
			}
			break;
		case LUAJIT_KGCFLT:
			if (kgc_obj->data) {
				symbol_name = rz_str_newf("%s_kgcconst_%f", proto_loc, *(double *)kgc_obj->data);
			}
			break;
		case LUAJIT_KGCCMPLX:
			symbol_name = get_luajit_cmplx_symbol(kgc_obj, proto_loc);
			break;
		default:
			if (kgc_obj->type >= LUAJIT_KGCSTR && kgc_obj->data) {
				luajit_add_strings(info->strings, kgc_obj->data, kgc_obj->offset, info->baddr);
			}
			break;
		}

		if (symbol_name) {
			luajit_add_symbol(info->symbol_list, symbol_name, kgc_obj->offset, kgc_obj->size, symbol_type);
		}
	}
}

static void build_constant_entries(LuaJITProto *proto, LuaJITBinInfo *info, char *proto_loc) {
	if (rz_list_empty(proto->constant_entries)) {
		return;
	}

	RzListIter *iter;
	LuaJITConstEntry *constant_entry = rz_list_first_val(proto->constant_entries);
	ut64 current_offset = constant_entry->offset;
	ut64 current_size = luajit_get_section_size(proto->constant_entries, LUAJIT_STCONSTENTR);

	char *section_name = rz_str_newf("%s.const", proto_loc);
	rz_return_if_fail(section_name);
	luajit_add_section(info->sections, section_name, current_offset, current_size, true, false);

	rz_list_foreach (proto->constant_entries, iter, constant_entry) {
		char *symbol_name = get_symbol_const_name(proto_loc, constant_entry);
		if (symbol_name) {
			luajit_add_symbol(info->symbol_list, symbol_name, constant_entry->offset, constant_entry->size, get_tag_string(constant_entry->type, true));
		}
	}
}

void build_table_val(LuaJITBinInfo *info, LuaJITValue *val, char *proto_loc) {
	if (val->type >= LUAJIT_TSTR) {
		add_table_string(info, val);
		return;
	}

	char *symbol_name = get_value_symbol_name(proto_loc, val);
	if (symbol_name) {
		luajit_add_symbol(info->symbol_list, symbol_name, val->offset, val->size, get_tag_string(val->type, false));
	}
}

static void build_tables(LuaJITProto *proto, LuaJITBinInfo *info, char *proto_loc) {
	if (rz_list_empty(proto->table)) {
		return;
	}

	RzListIter *iter;
	LuaJITTable *table = rz_list_first_val(proto->table);
	ut64 current_offset = table->offset;
	ut64 current_size = luajit_get_section_size(proto->table, LUAJIT_STTABLE);

	char *section_name = rz_str_newf("%s.table", proto_loc);
	rz_return_if_fail(section_name);
	luajit_add_section(info->sections, section_name, current_offset, current_size, true, true);

	rz_list_foreach (proto->table, iter, table) {
		RzListIter *i;
		LuaJITValue *val;

		if (table->narray > 0) {
			rz_list_foreach (table->array_items, i, val) {
				build_table_val(info, val, proto_loc);
			}
		}

		if (table->nhash > 0) {
			rz_list_foreach (table->hash_keys, i, val) {
				build_table_val(info, val, proto_loc);
			}
			rz_list_foreach (table->hash_values, i, val) {
				build_table_val(info, val, proto_loc);
			}
		}
	}
}

static void build_local_vars(LuaJITProto *proto, LuaJITBinInfo *info, const char *proto_loc) {
	if (rz_list_empty(proto->local_var_entry)) {
		return;
	}

	RzListIter *iter;
	LuaJITLocalVar *local_var = rz_list_first_val(proto->local_var_entry);
	ut64 current_offset = local_var->offset;
	ut64 current_size = luajit_get_section_size(proto->local_var_entry, LUAJIT_STLOCALVAR);

	char *section_name = rz_str_newf("%s.localvar", proto_loc);
	if (section_name) {
		luajit_add_section(info->sections, section_name, current_offset, current_size, true, true);
		rz_list_foreach (proto->local_var_entry, iter, local_var) {
			luajit_add_strings(info->strings, local_var->varname, local_var->offset, info->baddr);
		}
	}
}

static void luajit_build_info_cb(LuaJITProto *proto, LuaJITBinInfo *info) {
	RzListIter *iter;
	char *section_name;
	char *proto_loc;

	ut64 current_offset;
	ut64 current_size;

	proto_loc = rz_str_newf("fcn.0x%" PFMT64x, proto->start_offset);

	current_offset = proto->start_offset;
	current_size = proto->hdr_size;
	section_name = rz_str_newf("%s.header", proto_loc);
	rz_return_if_fail(section_name);
	luajit_add_section(info->sections, section_name, current_offset, current_size, true, true);

	if (proto->hdr_dbg != NULL) {
		section_name = rz_str_newf("%s.hdr_debug", proto_loc);
		rz_return_if_fail(section_name);
		current_offset = proto->hdr_dbg->offset;
		current_size = proto->hdr_dbg->size;
		luajit_add_section(info->sections, section_name, current_offset, current_size, true, false);
	}

	if (proto->num_istr_cnt > 0) {
		section_name = rz_str_newf("%s.code", proto_loc);
		rz_return_if_fail(section_name);
		current_offset = proto->instr_offset;
		current_size = proto->num_istr_cnt * 4;
		luajit_add_section(info->sections, section_name, current_offset, current_size, false, false);
		luajit_add_entry(info->entry_vec, current_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);
	}

	if (proto->num_up_val > 0) {
		current_offset = proto->up_val_entry_offset;
		current_size = proto->num_up_val * 2;
		section_name = rz_str_newf("%s.upvalueinstr", proto_loc);
		rz_return_if_fail(section_name);
		luajit_add_section(info->sections, section_name, current_offset, current_size, true, false);
	}

	build_kgc_objects(proto, info, proto_loc);

	build_constant_entries(proto, info, proto_loc);

	build_tables(proto, info, proto_loc);

	build_local_vars(proto, info, proto_loc);

	if (!rz_list_empty(proto->up_val_info)) {
		LuaJITUpValue *up_val_info = rz_list_first_val(proto->up_val_info);
		current_offset = up_val_info->offset;
		current_size = luajit_get_section_size(proto->up_val_info, LUAJIT_STUPVALINFO);
		section_name = rz_str_newf("%s.upvalnames", proto_loc);
		luajit_add_section(info->sections, section_name, current_offset, current_size, true, true);
	}

	current_offset = proto->debug_info_offset;
	current_size = proto->dbg_info_size;
	section_name = rz_str_newf("%s.debug", proto_loc);
	luajit_add_section(info->sections, section_name, current_offset, current_size, true, false);

	LuaJITProto *sub_proto;
	rz_list_foreach (proto->proto_entries, iter, sub_proto) {
		luajit_build_info_cb(sub_proto, info);
	}

	free(proto_loc);
}

LuaJITBinInfo *luajit_build_info(LuaJITProto *proto, LuaJITBinInfo *ret) {
	if (!proto) {
		RZ_LOG_ERROR("Invalid luajit file\n");
		return NULL;
	}

	if (!ret) {
		return NULL;
	}
	if (ret->file_name) {
		luajit_add_strings(ret->strings, ret->file_name, ret->header_end - rz_str_ansi_len(ret->file_name), ret->baddr);
	}

	luajit_build_info_cb(proto, ret);

	return ret;
}

static bool luajit_load_buffer(RzBinFile *b, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	ut8 version;
	RzBinInfo *bin_info = NULL;
	LuaJITBinInfo *bin_info_obj = NULL;
	LuaJITProto *proto_info = NULL;

	RzList /*<LuaJITProto *>*/ *proto_list = rz_list_new(); // A list to keep nested protos

	rz_buf_read_at(buf, LUAJIT_VERSION_OFFSET, &version, sizeof(version));

	bin_info_obj = luajit_build_info_new();
	if (!bin_info_obj) {
		rz_list_free(proto_list);
		return false;
	}

	switch ((int)version) {
	case 1:
		RZ_LOG_ERROR("luaJIT 2.0 not supported\n");
		break;
	case 2:
		bin_info = luajit_header_parser(b, bin_info_obj, 1);
		proto_info = luajit_parse_proto(buf, proto_list, bin_info_obj->header_end, bin_info_obj->header_end, true);
		break;
	default:
		RZ_LOG_ERROR("luaJIT 2.%c not supported\n", version);
		break;
	}
	bin_info_obj->baddr = obj->opts.baseaddr;
	bin_info_obj = luajit_build_info(proto_info, bin_info_obj);
	if (bin_info_obj == NULL) {
		luajit_free_proto_entry(proto_info);
		rz_bin_info_free(bin_info);
		rz_list_free(proto_list);
		return false;
	}
	bin_info_obj->general_bin_info = bin_info;

	obj->bin_obj = bin_info_obj;
	rz_list_free(proto_list);
	luajit_free_proto_entry(proto_info);
	return true;
}

static RzPVector /*<RzBinString *>*/ *luajit_strings(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuaJITBinInfo *bin_info_obj = LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	RzPVector *pvec = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!pvec || !rz_pvector_reserve(pvec, rz_list_length(bin_info_obj->strings))) {
		rz_pvector_free(pvec);
		return NULL;
	}
	RzListIter *iter;
	RzBinString *str;
	rz_list_foreach (bin_info_obj->strings, iter, str) {
		rz_pvector_push(pvec, str);
	}
	RzListFree free_cb = bin_info_obj->strings->free;
	bin_info_obj->strings->free = NULL;
	rz_list_purge(bin_info_obj->strings);
	bin_info_obj->strings->free = free_cb;
	return pvec;
}

static RzPVector /*<RzBinSection *>*/ *luajit_sections(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuaJITBinInfo *bin_info_obj = LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf);
	if (!bin_info_obj) {
		return NULL;
	}

	return rz_pvector_clone(bin_info_obj->sections);
}

static RzPVector /*<RzBinSymbol *>*/ *luajit_symbols(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuaJITBinInfo *bin_info_obj = LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf);
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

static RzBinInfo *luajit_info(RzBinFile *bf) {
	if (!bf) {
		return NULL;
	}
	LuaJITBinInfo *bin_info_obj = LUAJIT_GET_INTERNAL_BIN_INFO_OBJ(bf);
	return bin_info_obj->general_bin_info;
}

static bool luajit_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);

	if (rz_buf_size(b) > 4) {
		ut8 buf[LUAJIT_MAGIC_BYTE_SIZE];
		rz_buf_read_at(b, LUAJIT_MAGIC_OFFSET, buf, LUAJIT_MAGIC_BYTE_SIZE);
		return !memcmp(buf, LUAJIT_MAGIC, LUAJIT_MAGIC_BYTE_SIZE);
	}
	return false;
}

RzBinPlugin rz_bin_plugin_luaJIT = {
	.name = "luaJIT",
	.desc = "LuaJIT compiled binary",
	.license = "LGPL3",
	.author = "Arya H R",
	.check_buffer = &luajit_check_buffer,
	.load_buffer = &luajit_load_buffer,
	.entries = luajit_entries,
	.baddr = NULL,
	.destroy = &luajit_destroy,
	.sections = &luajit_sections,
	.symbols = &luajit_symbols,
	.info = &luajit_info,
	.strings = &luajit_strings,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_luaJIT,
	.version = RZ_VERSION
};
#endif