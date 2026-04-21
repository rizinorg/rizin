// SPDX-FileCopyrightText: 2026 Sergey Sharshunov <s.sharshunov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
// #include <luac/lua_arch.h>
#include <bin/format/luac/luac_common.h>

static bool luac_integrate_function(void *user, const ut64 k, const void *value) {
	RZ_LOG_DEBUG("---->luac_integrate_function\n");
	return true;
}

/**
 * \brief Use parsed luac function info in the function analysis
 * \param analysis The analysis
 */
RZ_API void rz_analysis_luac_integrate_functions(RzAnalysis *analysis) {
	rz_return_if_fail(analysis);
	RzAnalysisDebugInfo *debug_info = rz_analysis_get_debug_info(analysis);
	if (!debug_info) {
		return;
	}

	ht_up_foreach(debug_info->function_by_addr, luac_integrate_function, analysis);
}

static int line_sample_cmp(const void *a, const void *b, void *user) {
	const RzBinSourceLineSample *sa = a;
	const RzBinSourceLineSample *sb = b;
	// first, sort by addr
	if (sa->address < sb->address) {
		return -1;
	}
	if (sa->address > sb->address) {
		return 1;
	}
	// then sort by line
	if (sa->line < sb->line) {
		return -1;
	}
	if (sa->line > sb->line) {
		return 1;
	}
	// and eventually by file because this is the most exponsive operation
	if (!strlen(sa->file) && !strlen(sb->file)) {
		return 0;
	}
	if (!strlen(sa->file)) {
		return -1;
	}
	if (!strlen(sb->file)) {
		return 1;
	}
	return strcmp(sa->file, sb->file);
}

RZ_API bool rz_core_bin_apply_luac_debug(RzCore *core, RzBinFile *binfile) {
	rz_return_val_if_fail(core && binfile, false);

	const char *arch = rz_config_get(core->config, "asm.arch");
	if (RZ_STR_NE(arch, "luac")) {
		return false;
	}

	const RzBinObject *binobj = rz_bin_cur_object(core->bin);
	const RzBinInfo *info = binobj ? binobj->info : NULL;

	rz_return_val_if_fail(info && info->rclass, NULL);
	if (RZ_STR_NE(info->rclass, "luac")) {
		return false;
	}

	rz_return_val_if_fail(binfile->o->bin_obj, false);
	LuacBinInfo *bi = (LuacBinInfo *)binfile->o->bin_obj;
	rz_return_val_if_fail(bi, false);

	LuacBinInfo *luac_obj = (LuacBinInfo *)binfile->o->bin_obj;
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	RzReg *rreg = rz_analysis_get_reg(core->analysis);

	rz_type_db_format_set(typedb, "LuaConstant", "bX type value");
	rz_type_db_format_set(typedb, "LuaUpvalue", "bbbz instack idx kind nam");
	rz_type_db_format_set(typedb, "LuaLocalVar", "ziIIq name len start end off");

	uint64_t meta_addr = METATABLES_VOFFSET;
	for (int i = 0; i < 25; i++) {
		const char *meta_name = get_metamethod_name(bi->header->minor, i);
		rz_return_val_if_fail(meta_name, NULL);
		rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, meta_addr, 1, "Lua Metamethod Entry");

		const RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, meta_name, meta_addr, RZ_ANALYSIS_FCN_TYPE_IMP); // ? RZ_ANALYSIS_FCN_TYPE_SYM
		(void)fcn;
		meta_addr += 4;
	}

	void **it_p;
	void **it_c;
	void **it_u;
	void **it_v;

	rz_pvector_foreach (luac_obj->protos_vec, it_p) {
		const LuaProto *proto = *it_p;
		rz_pvector_foreach (proto->const_entries, it_c) {
			const LuaConstEntry *current_entry = *it_c;
			RZ_LOG_DEBUG("[LuaConstEntry] proto: %d, offset: 0x%" PFMT64x " === tag: %d, offset: 0x%" PFMT64x ", prev_offset: 0x%" PFMT64x ", string_start: 0x%" PFMT64x ", current_entry->voffset: 0x%" PFMT64x ", `%s` (%d)\n",
				proto->index, proto->offset, current_entry->tag, current_entry->offset, current_entry->prev_offset,
				current_entry->string_start,
				current_entry->voffset, (char *)current_entry->data, current_entry->data_len);
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, current_entry->voffset, current_entry->data_len + 2, "LuaConstant");
		}
	}

	rz_pvector_foreach (luac_obj->protos_vec, it_p) {
		const LuaProto *proto = *it_p;
		char *pname = rz_str_newf("proto%d", proto->index);
		const ut64 faddr = PROTO_VADDRESS(proto->index);
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, faddr);
		if (!fcn) {
			fcn = rz_analysis_create_function(core->analysis, pname, faddr, RZ_ANALYSIS_FCN_TYPE_FCN);
			// fcn = rz_analysis_create_function(core->analysis, pname, meta_addr, RZ_ANALYSIS_FCN_TYPE_IMP);
			// RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, PROTO_VADDRESS(proto->index));
			RzAnalysisBlock *bb = rz_analysis_create_block(core->analysis, faddr, proto->code_size - proto->code_skipped);
			bb->jump = UT64_MAX;
			bb->fail = UT64_MAX;

			rz_analysis_function_add_block(fcn, bb);
		}

		rz_return_val_if_fail(fcn, NULL);
		const int reg_offset = (proto->is_vararg) ? 1 : 0;
		const int start_register = proto->num_params + reg_offset;
		int i = 0;
		rz_pvector_foreach (proto->local_var_info_entries, it_v) {
			const LuaLocalVarEntry *var = *it_v;
			RZ_LOG_DEBUG("[LuaLocalVarEntry] [%d] params: %d, pname: `%s` proto->is_vararg: %d, reg_offset: %d ---- %d === varname: `%s`, offset: 0x%" PFMT64x ", voffset: 0x%" PFMT64x ", start_pc: %d, end_pc: %d, varname_len: %d\n",
				i, proto->num_params, pname, proto->is_vararg, reg_offset,
				proto->index, (char *)var->varname, var->offset, var->voffset, var->start_pc, var->end_pc, var->varname_len);

			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, var->voffset, var->var_size, "LuaLocalVar");
			char *var_comment = rz_str_newf("Var start: %s", (char *)var->varname);
			rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, var->voffset, var->var_size, var_comment);
			RZ_FREE(var_comment);

			const int reg_idx = start_register + i;
			const char *reg_name = rz_str_newf("r%d", reg_idx);

			const RzRegItem *ri = rz_reg_get(rreg, reg_name, RZ_REG_TYPE_ANY);
			rz_return_val_if_fail(ri && ri->name, false);

			RzType *var_type = rz_type_identifier_of_base_type_str(typedb, "int");

			RzAnalysisVarStorage stor;
			rz_analysis_var_storage_init_reg(&stor, ri->name);
			// RzStackAddr stack_off; rz_analysis_var_storage_init_stack(&stor, stack_off);

			const int instruction_size = rz_asm_get_bits(core->rasm) / 8;
			const ut64 start_addr = PROTO_VADDRESS(proto->index) + (var->start_pc * instruction_size);
			const ut64 end_addr = PROTO_VADDRESS(proto->index) + (var->end_pc * instruction_size);
			(void)end_addr;
			RzAnalysisVar *avar = rz_analysis_function_set_var(
				fcn, &stor, var_type, (int)rz_analysis_guessed_mem_access_width(core->analysis),
				var->varname ? (const char *)var->varname : "unknown");
			if (avar) {
				if (i < proto->num_params) {
					avar->kind = RZ_ANALYSIS_VAR_KIND_FORMAL_PARAMETER;
				} else {
					avar->kind = RZ_ANALYSIS_VAR_KIND_VARIABLE;
				}
				const st64 addend = 0;
				rz_analysis_var_set_access(avar, ri->name, start_addr, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, addend);
			}
			rz_type_free(var_type);
			RZ_FREE(reg_name);
			i++;
		}
		RZ_FREE(pname);
	}

	rz_pvector_foreach (luac_obj->protos_vec, it_p) {
		const LuaProto *proto = *it_p;
		rz_pvector_foreach (proto->upvalue_entries, it_u) {
			const LuaUpvalueEntry *upvalue = *it_u;
			RZ_LOG_DEBUG("[LuaUpvalueEntry] proto: %d, offset: 0x%" PFMT64x " === idx: `%d`, upvalue->poffset: 0x%" PFMT64x ", voffset: 0x%" PFMT64x ", instack: %d, kind: %d, upvalue_name: `%s`, offset: 0x%" PFMT64x ", upvalue_len: %d\n",
				proto->index, proto->offset, upvalue->idx, upvalue->offset, upvalue->voffset, upvalue->instack, upvalue->kind,
				(char *)upvalue->upvalue_name, upvalue->name_offset, upvalue->name_len);
			rz_meta_set(core->analysis, RZ_META_TYPE_DATA, upvalue->voffset, sizeof(upvalue), "LuaUpvalue");
			rz_flag_set(core->flags, upvalue->upvalue_name ? (char *)upvalue->upvalue_name : "unk", upvalue->name_offset, 2);
		}
	}

	rz_pvector_foreach (luac_obj->protos_vec, it_p) {
		const LuaProto *proto = *it_p;
		rz_pvector_foreach (proto->dbg_upvalue_entries, it_u) {
			const LuaDbgUpvalueEntry *upvalue = *it_u;
			(void)upvalue;
			RZ_LOG_DEBUG("[LuaUpvalueEntry] proto: %d, offset: 0x%" PFMT64x " === dbg_upvalue_name: `%s`, offset: 0x%" PFMT64x ", upvalue_len: %d\n",
				proto->index, proto->offset, (char *)upvalue->upvalue_name, upvalue->offset, upvalue->name_len);
		}
	}

	rz_pvector_sort(luac_obj->line_nums_vec, line_sample_cmp, NULL);
	if (!binfile->o->lines) {
		RzPVector *ls = luac_obj->line_nums_vec;
		void **lit;
		ut16 index = 0;

		binfile->o->lines = RZ_NEW0(RzBinSourceLineInfo);
		const size_t lc = rz_pvector_len(luac_obj->line_nums_vec);
		binfile->o->lines->samples_count = lc;
		binfile->o->lines->samples = RZ_NEWS0(RzBinSourceLineSample, lc);

		rz_pvector_foreach (ls, lit) {
			const RzBinSourceLineSample *line_num = (RzBinSourceLineSample *)*lit;
			RzBinSourceLineSample *sample = &binfile->o->lines->samples[index];
			sample->address = line_num->address;
			sample->line = line_num->line;
			sample->column = 0;
			sample->file = line_num->file;
			index++;
		}
		rz_str_constpool_init(&binfile->o->lines->filename_pool);
	}
	return true;
}
