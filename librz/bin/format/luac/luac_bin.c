// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>
// SPDX-FileCopyrightText: 2025-2026 Sergey Sharshunov <s.sharshunov@gmail.com>

#include "luac_common.h"

void luac_add_section(RzPVector /*<RzBinSection *>*/ *section_vec, char *name, ut64 poffset, ut64 voffset, ut32 size, bool is_func) {
	if (size == 0)
		return;
	RzBinSection *bin_sec = RZ_NEW0(RzBinSection);
	if (!bin_sec || !name) {
		free(bin_sec);
		return;
	}
	bin_sec->name = rz_str_dup(name);
	bin_sec->vaddr = voffset;
	bin_sec->paddr = poffset;
	bin_sec->size = size;
	bin_sec->vsize = size;
	bin_sec->is_data = is_func ? false : true;
	bin_sec->bits = 32;
	bin_sec->has_strings = false;
	bin_sec->arch = "luac";

	if (is_func) {
		bin_sec->perm = RZ_PERM_R | RZ_PERM_X;
	} else {
		bin_sec->perm = RZ_PERM_R;
	}

	if (!rz_pvector_push(section_vec, bin_sec)) {
		rz_bin_section_free(bin_sec);
	}
}

void luac_add_symbol(RzList /*<RzBinSymbol *>*/ *symbol_list, char *name, ut64 poffset, ut64 voffset, ut64 size, const char *type) {
	RzBinSymbol *bin_sym = RZ_NEW0(RzBinSymbol);
	if (!bin_sym) {
		return;
	}
	bin_sym->name = rz_str_dup(name);
	bin_sym->vaddr = voffset;
	bin_sym->paddr = poffset;
	bin_sym->size = size;
	bin_sym->type = type;
	bin_sym->bits = 32;
	rz_list_append(symbol_list, bin_sym);
}

void luac_add_entry(RzPVector /*<RzBinAddr *>*/ *entry_vec, ut64 offset, int entry_type) {
	RzBinAddr *entry = RZ_NEW0(RzBinAddr);
	if (!entry) {
		return;
	}
	entry->vaddr = offset;
	entry->paddr = offset;
	entry->type = entry_type;
	rz_pvector_push(entry_vec, entry);
}

void luac_add_string(RzList /*<RzBinString *>*/ *string_list, char *string, ut64 poffset, ut64 voffset, ut64 size) {
	RzBinString *bin_string = RZ_NEW0(RzBinString);
	if (!bin_string) {
		return;
	}
	bin_string->paddr = poffset;
	bin_string->vaddr = voffset;
	bin_string->size = size + 1;
	bin_string->length = size;
	bin_string->string = rz_str_dup(string);
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
	free(bin_info->header->src_file_name);
	free(bin_info->header);
	lua_free_proto_entry(bin_info->proto);
	bin_info->proto = NULL;
	rz_pvector_free(bin_info->protos_vec);
	rz_pvector_free(bin_info->all_const_vec);
	rz_pvector_free(bin_info->entry_vec);
	rz_list_free(bin_info->symbol_list);
	rz_pvector_free(bin_info->line_nums_vec);
	rz_pvector_free(bin_info->section_vec);
	rz_list_free(bin_info->string_list);
	free(bin_info);
}

static void free_line_nums(RzBinSourceLineSample *ln) {
	if (!ln) {
		return;
	}
	if (ln->file) {
		RZ_FREE(ln->file);
	}
	RZ_FREE(ln);
}

LuacBinInfo *luac_build_info(RZ_NONNULL LuaProto *proto) {
	if (!proto) {
		RZ_LOG_ERROR("Invalid luac file\n");
		return NULL;
	}

	LuacBinInfo *ret = RZ_NEW0(LuacBinInfo);
	rz_return_val_if_fail(ret, NULL);

	ret->protos_vec = rz_pvector_new((RzPVectorFree)NULL);
	ret->all_const_vec = rz_pvector_new((RzPVectorFree)NULL);
	ret->entry_vec = rz_pvector_new((RzPVectorFree)free_rz_addr);
	ret->symbol_list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	ret->section_vec = rz_pvector_new((RzPVectorFree)free_rz_section);
	ret->line_nums_vec = rz_pvector_new((RzPVectorFree)free_line_nums);
	ret->string_list = rz_list_newf((RzListFree)free_rz_string);

	if (!(ret->entry_vec && ret->symbol_list && ret->section_vec && ret->string_list)) {
		rz_pvector_free(ret->entry_vec);
		rz_list_free(ret->symbol_list);
		rz_pvector_free(ret->section_vec);
		rz_pvector_free(ret->line_nums_vec);
		rz_list_free(ret->string_list);
	}

	_luac_build_info(proto, ret);

	LuaConstEntry *const_entry = NULL;
	void **it;
	rz_pvector_foreach (ret->all_const_vec, it) {
		const_entry = *it;
		if (const_entry->tag == LUA_VSTRING_IDX) {
			const LuaConstEntry *tmp_const = rz_pvector_at(ret->all_const_vec, *(ut8 *)const_entry->data);
			RZ_FREE(const_entry->data);
			const int new_len = tmp_const->data_len + 1;
			const_entry->data = RZ_NEWS(ut8, new_len);
			rz_mem_copy(const_entry->data, new_len, tmp_const->data, new_len);
			const_entry->data_len = tmp_const->data_len;
			const_entry->tag = tmp_const->tag;
			const_entry->offset = tmp_const->offset;
			const_entry->prev_offset = tmp_const->prev_offset;
			const_entry->voffset = tmp_const->voffset;
			const_entry->string_start = tmp_const->string_start;
		}
	}

	// add entry of main
	ut64 main_entry_offset = 0x0 + PROTO_VBASE;
	luac_add_entry(ret->entry_vec, main_entry_offset, RZ_BIN_ENTRY_TYPE_PROGRAM);

	size_t paddr = proto->code_offset + proto->code_skipped;
	RzBinSymbol *msym = rz_bin_symbol_new("entry0", paddr, main_entry_offset);
	msym->type = RZ_BIN_TYPE_FUNC_STR;
	msym->bind = RZ_BIN_BIND_GLOBAL_STR;
	msym->size = proto->code_size; // section->size;
	msym->paddr = paddr;
	rz_list_append(ret->symbol_list, msym);
	return ret;
}

void _luac_build_info(LuaProto *proto, LuacBinInfo *info) {
	/* process proto header info */
	char *symbol_name = NULL;
	char *proto_name = NULL;
	char **upvalue_names = NULL;
	RzListIter *iter;

	ut64 current_offset = 0;
	ut64 current_size = 0;
	char *section_name = NULL;

	const ut64 proto_vaddr = PROTO_VADDRESS(proto->index);

	// 1.0 set section name as function_name.code
	current_offset = proto->code_offset + proto->code_skipped;
	current_size = proto->code_size;
	proto_name = rz_str_newf("fcn.%08llx", (ut64)proto_vaddr);
	section_name = rz_str_newf("%s.code", proto_name);
	luac_add_section(info->section_vec, section_name, current_offset, proto_vaddr, current_size, true);

	char *name = proto->line_defined == 0 ? rz_str_dup("entry0") : rz_str_newf("proto%d", proto->index);
	RzBinSymbol *proto_sym = rz_bin_symbol_new(name, current_offset, proto_vaddr);
	proto_sym->bind = RZ_BIN_BIND_GLOBAL_STR;
	proto_sym->type = RZ_BIN_TYPE_FUNC_STR;
	proto_sym->bits = 32;
	proto_sym->size = current_size;
	rz_list_append(info->symbol_list, proto_sym);
	RZ_FREE(name);
	RZ_FREE(section_name);

	// 1.2 set const section
	current_offset = proto->const_offset;
	current_size = proto->const_size;

	section_name = rz_str_newf("%s.const", proto_name);
	const ut64 const_voffset = proto_vaddr + CONST_OFFSET;
	luac_add_section(info->section_vec, section_name, current_offset, const_voffset, current_size, false);
	RZ_FREE(section_name);

	LuaLineinfoEntry *line_info_entry;
	rz_list_foreach (proto->line_info_entries, iter, line_info_entry) {
		RzBinSourceLineSample *new_line_sample = RZ_NEW0(RzBinSourceLineSample);
		if (!new_line_sample) {
			return;
		}
		new_line_sample->address = line_info_entry->offset;
		new_line_sample->column = 0;
		new_line_sample->line = line_info_entry->info_data;
		new_line_sample->file = rz_str_dup((const char *)proto->proto_name);
		rz_pvector_push(info->line_nums_vec, new_line_sample);
	}

	// 1.3 upvalue section
	current_offset = proto->upvalue_offset;
	current_size = proto->upvalue_size;
	section_name = rz_str_newf("%s.upvalues", proto_name);
	const ut64 upvalues_voffset = proto_vaddr + UPVALUE_OFFSET;
	luac_add_section(info->section_vec, section_name, current_offset, upvalues_voffset, current_size, false);
	RZ_FREE(section_name);

	// 1.4 debug section
	current_offset = proto->local_var_offset;
	current_size = proto->local_var_size;
	section_name = rz_str_newf("%s.lvars", proto_name);
	const ut64 lvars_voffset = proto_vaddr + LVARS_OFFSET;
	luac_add_section(info->section_vec, section_name, current_offset, lvars_voffset, current_size, false);
	RZ_FREE(section_name);
	RZ_FREE(proto_name);

	// 1.5 construct constant symbols
	LuaConstEntry *const_entry = NULL;
	void **it;
	rz_pvector_foreach (proto->const_entries, it) {
		const_entry = *it;
		rz_pvector_push(info->all_const_vec, const_entry);
	}

	(void)symbol_name;
	rz_pvector_push(info->protos_vec, proto);

	// 1.6 parse sub proto
	LuaProto *sub_proto;
	rz_list_foreach (proto->proto_entries, iter, sub_proto) {
		_luac_build_info(sub_proto, info);
	}

	free(upvalue_names);
	free(proto_name);
}
