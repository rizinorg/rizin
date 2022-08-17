// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>

#include "luac_common.h"

void luac_add_section(RzList *section_list, char *name, ut64 offset, ut32 size, bool is_func) {
	RzBinSection *bin_sec = RZ_NEW0(RzBinSection);
	if (!bin_sec) {
		return;
	}

	bin_sec->name = rz_str_new(name);
	bin_sec->vaddr = bin_sec->paddr = offset;
	bin_sec->size = bin_sec->vsize = size;
	bin_sec->is_data = false;
	bin_sec->bits = is_func ? sizeof(LUA_INSTRUCTION) * 8 : 8;
	// bin_sec->has_strings = !is_func;
	bin_sec->has_strings = false;
	bin_sec->arch = rz_str_new("luac");

	if (is_func) {
		bin_sec->perm = RZ_PERM_R | RZ_PERM_X;
	} else {
		bin_sec->perm = RZ_PERM_R;
	}

	rz_list_append(section_list, bin_sec);
}

void luac_add_symbol(RzList *symbol_list, char *name, ut64 offset, ut64 size, const char *type) {
	RzBinSymbol *bin_sym = RZ_NEW0(RzBinSymbol);
	if (!bin_sym) {
		return;
	}

	bin_sym->name = rz_str_new(name);
	bin_sym->vaddr = bin_sym->paddr = offset;
	bin_sym->size = size;
	bin_sym->type = type;

	rz_list_append(symbol_list, bin_sym);
}

void luac_add_entry(RzList *entry_list, ut64 offset, int entry_type) {
	RzBinAddr *entry = RZ_NEW0(RzBinAddr);
	if (!entry) {
		return;
	}

	entry->vaddr = offset;
	entry->paddr = offset;
	entry->type = entry_type;

	rz_list_append(entry_list, entry);
}

void luac_add_string(RzList *string_list, char *string, ut64 offset, ut64 size) {
	RzBinString *bin_string = RZ_NEW0(RzBinString);
	if (!bin_string) {
		return;
	}

	bin_string->paddr = offset;
	bin_string->vaddr = offset;
	bin_string->size = size;
	bin_string->length = size;
	bin_string->string = rz_str_new(string);
	bin_string->type = RZ_STRING_ENC_UTF8;

	rz_list_append(string_list, bin_string);
}

static void free_rz_section(RzBinSection *section) {
	if (!section) {
		return;
	}

	if (section->name) {
		RZ_FREE(section->name);
	}

	if (section->format) {
		RZ_FREE(section->format);
	}

	RZ_FREE(section);
}

static void free_rz_string(RzBinString *string) {
	if (!string) {
		return;
	}

	if (string->string) {
		RZ_FREE(string->string);
	}

	RZ_FREE(string);
}

static void free_rz_addr(RzBinAddr *addr) {
	if (!addr) {
		return;
	}
	RZ_FREE(addr);
}

void luac_build_info_free(LuacBinInfo *bin_info) {
	if (!bin_info) {
		return;
	}
	rz_list_free(bin_info->entry_list);
	rz_list_free(bin_info->symbol_list);
	rz_list_free(bin_info->section_list);
	rz_list_free(bin_info->string_list);
	free(bin_info);
}

LuacBinInfo *luac_build_info(LuaProto *proto) {
	if (!proto) {
		RZ_LOG_ERROR("Invalid luac file\n");
		return NULL;
	}

	LuacBinInfo *ret = RZ_NEW0(LuacBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->entry_list = rz_list_newf((RzListFree)free_rz_addr);
	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	ret->section_list = rz_list_newf((RzListFree)free_rz_section);
	ret->string_list = rz_list_newf((RzListFree)free_rz_string);

	if (!(ret->entry_list && ret->symbol_list && ret->section_list && ret->string_list)) {
		rz_list_free(ret->entry_list);
		rz_list_free(ret->symbol_list);
		rz_list_free(ret->section_list);
		rz_list_free(ret->string_list);
	}

	_luac_build_info(proto, ret);

	// add entry of main
	ut64 main_entry_offset;
	main_entry_offset = proto->code_offset + proto->code_skipped;
	luac_add_entry(ret->entry_list, main_entry_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);

	return ret;
}

static const char *get_tag_string(ut8 tag) {
	switch (tag) {
	case LUA_VNIL:
		return "CONST_NIL";
	case LUA_VTRUE:
	case LUA_VFALSE:
		return "CONST_BOOL";
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		return "CONST_STRING";
	case LUA_VNUMFLT:
	case LUA_VNUMINT:
		return "CONST_NUM";
	default:
		return "CONST_UNKNOWN";
	}
}

/* Heap allocated string */
static char *get_constant_symbol_name(char *proto_name, LuaConstEntry *entry) {
	rz_return_val_if_fail(entry || proto_name, NULL);
	ut8 tag = entry->tag;
	char *ret;
	int integer_value;
	double float_value;

	switch (tag) {
	case LUA_VNIL:
		ret = rz_str_newf("%s_const_nil", proto_name);
		break;
	case LUA_VTRUE:
		ret = rz_str_newf("%s_const_true", proto_name);
		break;
	case LUA_VFALSE:
		ret = rz_str_newf("%s_const_false", proto_name);
		break;
	case LUA_VSHRSTR:
	case LUA_VLNGSTR:
		rz_return_val_if_fail(entry->data, NULL);
		ret = rz_str_newf("%s_const_%s", proto_name, (char *)entry->data);
		break;
	case LUA_VNUMFLT:
		rz_return_val_if_fail(entry->data, NULL);
		if (entry->data_len < sizeof(double)) {
			return NULL;
		}
		float_value = *(double *)entry->data;
		ret = rz_str_newf("%s_const_%f", proto_name, float_value);
		break;
	case LUA_VNUMINT:
		rz_return_val_if_fail(entry->data, NULL);
		if (entry->data_len < sizeof(int)) {
			return NULL;
		}
		integer_value = *(int *)entry->data;
		ret = rz_str_newf("%s_const_%d", proto_name, integer_value);
		break;
	default:
		ret = rz_str_newf("%s_const_0x%llx", proto_name, entry->offset);
		break;
	}
	return ret;
}

/* Heap allocated string */
static char *simple_build_upvalue_symbol(char *proto_name, LuaUpvalueEntry *entry) {
	return rz_str_newf("%s_upvalue_0x%llx", proto_name, entry->offset);
}

static char *get_upvalue_symbol_name(char *proto_name, LuaUpvalueEntry *entry, char *debug_name) {
	rz_return_val_if_fail(proto_name || entry, NULL);
	if (debug_name == NULL) {
		return simple_build_upvalue_symbol(proto_name, entry);
	}

	return rz_str_newf("%s_upvalue_%s", proto_name, debug_name);
}

void _luac_build_info(LuaProto *proto, LuacBinInfo *info) {
	/* process proto header info */
	char *section_name;
	char *symbol_name;
	char *proto_name;
	char **upvalue_names = NULL;
	RzListIter *iter;
	int i = 0; // iter

	ut64 current_offset;
	ut64 current_size;

	// 0. check if stripped (proto name is lost)
	if (proto->name_size == 0 || proto->proto_name == NULL) {
		// replace name with current offset
		proto_name = rz_str_newf("fcn.%08llx", proto->offset);
	} else {
		proto_name = rz_str_new((char *)proto->proto_name);
	}

	// 1.1 set section name as function_name.header
	current_offset = proto->offset;
	current_size = proto->size;
	section_name = rz_str_newf("%s.header", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
	RZ_FREE(section_name);

	// 1.2 set section name as function_name.code
	current_offset = proto->code_offset;
	current_size = proto->code_size;
	section_name = rz_str_newf("%s.code", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, true);
	RZ_FREE(section_name);

	// 1.3 set const section
	current_offset = proto->const_offset;
	current_size = proto->const_size;
	section_name = rz_str_newf("%s.const", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
	RZ_FREE(section_name);

	// 1.4 upvalue section
	current_offset = proto->upvalue_offset;
	current_size = proto->upvalue_size;
	section_name = rz_str_newf("%s.upvalues", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
	RZ_FREE(section_name);

	// 1.5 inner protos section
	current_offset = proto->inner_proto_offset;
	current_size = proto->inner_proto_size;
	section_name = rz_str_newf("%s.protos", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
	RZ_FREE(section_name);

	// 1.6 debug section
	current_offset = proto->debug_offset;
	current_size = proto->debug_size;
	section_name = rz_str_newf("%s.debug", proto_name);
	luac_add_section(info->section_list, section_name, current_offset, current_size, false);
	RZ_FREE(section_name);

	// 2.1 parse local var info
	LuaLocalVarEntry *local_var_entry;
	rz_list_foreach (proto->local_var_info_entries, iter, local_var_entry) {
		luac_add_string(
			info->string_list,
			(char *)local_var_entry->varname,
			local_var_entry->offset,
			local_var_entry->varname_len);
	}

	// 2.2 parse debug_upvalues
	size_t real_upvalue_cnt = rz_list_length(proto->upvalue_entries);
	if (real_upvalue_cnt > 0) {
		LuaDbgUpvalueEntry *debug_upv_entry;
		upvalue_names = RZ_NEWS0(char *, real_upvalue_cnt);
		if (!upvalue_names) {
			free(proto_name);
			return;
		}

		i = 0;
		rz_list_foreach (proto->dbg_upvalue_entries, iter, debug_upv_entry) {
			upvalue_names[i] = (char *)debug_upv_entry->upvalue_name;
			luac_add_string(
				info->string_list,
				upvalue_names[i],
				debug_upv_entry->offset,
				debug_upv_entry->name_len);
			i++;
		}
	}

	// 3.1 construct constant symbols
	LuaConstEntry *const_entry;
	rz_list_foreach (proto->const_entries, iter, const_entry) {
		symbol_name = get_constant_symbol_name(proto_name, const_entry);
		luac_add_symbol(
			info->symbol_list,
			symbol_name,
			const_entry->offset,
			const_entry->data_len,
			get_tag_string(const_entry->tag));
		if (const_entry->tag == LUA_VLNGSTR || const_entry->tag == LUA_VSHRSTR) {
			luac_add_string(
				info->string_list,
				(char *)const_entry->data,
				const_entry->offset,
				const_entry->data_len);
		}
		RZ_FREE(symbol_name);
	}

	// 3.2 construct upvalue symbols
	LuaUpvalueEntry *upvalue_entry;
	i = 0;
	rz_list_foreach (proto->upvalue_entries, iter, upvalue_entry) {
		symbol_name = get_upvalue_symbol_name(proto_name, upvalue_entry, upvalue_names[i++]);
		luac_add_symbol(
			info->symbol_list,
			symbol_name,
			upvalue_entry->offset,
			3,
			"UPVALUE");
		RZ_FREE(symbol_name);
	}

	// 4. parse sub proto
	LuaProto *sub_proto;
	rz_list_foreach (proto->proto_entries, iter, sub_proto) {
		_luac_build_info(sub_proto, info);
	}

	free(upvalue_names);
	free(proto_name);
}
