// SPDX-FileCopyrightText: 2010-2019 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2019 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_types_overflow.h>

#define aprintf(format, ...) \
	RZ_LOG_DEBUG(format, __VA_ARGS__)

static void apply_case(RzAnalysis *analysis, RzAnalysisBlock *block, ut64 switch_addr, ut64 offset_sz, ut64 case_addr, ut64 id, ut64 case_addr_loc) {
	// eprintf ("** apply_case: 0x%"PFMT64x " from 0x%"PFMT64x "\n", case_addr, case_addr_loc);
	rz_meta_set_data_at(analysis, case_addr_loc, offset_sz);
	rz_analysis_hint_set_immbase(analysis, case_addr_loc, 10);
	rz_analysis_xrefs_set(analysis, switch_addr, case_addr, RZ_ANALYSIS_XREF_TYPE_CODE);
	if (block) {
		rz_analysis_block_add_switch_case(block, switch_addr, id, case_addr);
	}
	if (analysis->flb.set) {
		char flagname[0x30];
		snprintf(flagname, sizeof(flagname), "case.0x%" PFMT64x ".%d", (ut64)switch_addr, (int)id);
		analysis->flb.set(analysis->flb.f, flagname, case_addr, 1);
	}
}

static void apply_switch(RzAnalysis *analysis, ut64 switch_addr, ut64 jmptbl_addr, ut64 cases_count, ut64 default_case_addr) {
	char tmp[0x30];
	snprintf(tmp, sizeof(tmp), "switch table (%" PFMT64u " cases) at 0x%" PFMT64x, cases_count, jmptbl_addr);
	rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, switch_addr, tmp);
	if (analysis->flb.set) {
		snprintf(tmp, sizeof(tmp), "switch.0x%08" PFMT64x, switch_addr);
		analysis->flb.set(analysis->flb.f, tmp, switch_addr, 1);
		if (default_case_addr != UT64_MAX) {
			rz_analysis_xrefs_set(analysis, switch_addr, default_case_addr, RZ_ANALYSIS_XREF_TYPE_CODE);
			snprintf(tmp, sizeof(tmp), "case.default.0x%" PFMT64x, switch_addr);
			analysis->flb.set(analysis->flb.f, tmp, default_case_addr, 1);
		}
	}
}

// analyze a jmptablle inside a function // maybe rename to rz_analysis_fcn_jmptbl() ?
RZ_API bool rz_analysis_jmptbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr, RzStackAddr sp) {
	RzAnalysisJmpTableParams params = {
		.jmp_address = jmpaddr,
		.case_shift = 0,
		.jmptbl_loc = table,
		.casetbl_loc = UT64_MAX,
		.jmptbl_off = table,
		.entry_size = tablesize,
		.table_count = tablesize,
		.default_case = default_addr,
		.sp = sp
	};
	return rz_analysis_walkthrough_jmptbl(analysis, fcn, block, &params);
}

static inline bool jmptable_size_is_invalid(RzAnalysisJmpTableParams *params) {
	return UT64_MUL_OVFCHK(params->table_count, params->entry_size) ||
		params->table_count * params->entry_size > ST32_MAX;
}

/**
 * \brief Marks for analysis jump table cases with a space optimization for multiple cases corresponding to the same address
 *
 * This function works similarly to `rz_analysis_walkthrough_jmptbl`,
 * with the difference that jump targets are hidden behind a indirection in the case table
 *
 * \param analysis Pointer to RzAnalysis instance
 * \param fcn Pointer to RzAnalysisFunction to add the new cases
 * \param block Pointer to RzAnalysisBlock that originates the switch table
 * \param params Pointer to RzAnalysisJmpTableParams necessary to analyze the jump table
 */
RZ_API bool rz_analysis_walkthrough_casetbl(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NONNULL RzAnalysisBlock *block, RZ_NONNULL RzAnalysisJmpTableParams *params) {
	rz_return_val_if_fail(analysis && fcn && block && params, false);
	bool ret = true;
	if (params->table_count == 0) {
		params->table_count = analysis->opt.jmptbl_maxcount;
	}
	if (params->jmptbl_loc == UT64_MAX) {
		aprintf("Invalid jump table location 0x%08" PFMT64x "\n", params->jmptbl_loc);
		return false;
	}
	if (params->casetbl_loc == UT64_MAX) {
		aprintf("Invalid case table location 0x%08" PFMT64x "\n", params->jmptbl_loc);
		return false;
	}
	if (jmptable_size_is_invalid(params)) {
		aprintf("Invalid jump table size at 0x%08" PFMT64x "\n", params->jmp_address);
		return false;
	}
	ut64 jmpptr, case_idx, jmpptr_idx;
	ut8 *jmptbl = calloc(params->table_count, params->entry_size);
	if (!jmptbl || !analysis->iob.read_at(analysis->iob.io, params->jmptbl_loc, jmptbl, params->table_count * params->entry_size)) {
		free(jmptbl);
		return false;
	}
	ut8 *casetbl = calloc(params->table_count, sizeof(ut8));
	if (!casetbl || !analysis->iob.read_at(analysis->iob.io, params->casetbl_loc, casetbl, params->table_count)) {
		free(jmptbl);
		free(casetbl);
		return false;
	}
	for (case_idx = 0; case_idx < params->table_count; case_idx++) {
		jmpptr_idx = casetbl[case_idx];

		if (jmpptr_idx >= params->table_count) {
			ret = false;
			break;
		}

		switch (params->entry_size) {
		case 1:
			jmpptr = rz_read_le8(jmptbl + jmpptr_idx);
			break;
		case 2:
			jmpptr = rz_read_le16(jmptbl + jmpptr_idx * 2);
			break;
		case 4:
			jmpptr = rz_read_le32(jmptbl + jmpptr_idx * 4);
			break;
		default:
			jmpptr = rz_read_le64(jmptbl + jmpptr_idx * 8);
			break;
		}
		if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
			break;
		}
		if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
			st32 jmpdelta = (st32)jmpptr;
			// jump tables where sign extended movs are used
			jmpptr = params->jmptbl_off + jmpdelta;
			if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
				break;
			}
		}
		if (analysis->limit) {
			if (jmpptr < analysis->limit->from || jmpptr > analysis->limit->to) {
				break;
			}
		}

		const ut64 jmpptr_idx_off = params->casetbl_loc + case_idx;
		rz_meta_set_data_at(analysis, jmpptr_idx_off, 1);
		rz_analysis_hint_set_immbase(analysis, jmpptr_idx_off, 10);

		apply_case(analysis, block, params->jmp_address, params->entry_size, jmpptr, case_idx + params->case_shift, params->jmptbl_loc + jmpptr_idx * params->entry_size);
		rz_analysis_task_item_new(analysis, params->tasks, fcn, NULL, jmpptr, params->sp);
	}

	if (case_idx > 0) {
		if (params->default_case == 0) {
			params->default_case = UT64_MAX;
		}
		apply_switch(analysis, params->jmp_address, params->jmptbl_loc, case_idx, params->default_case);
	}

	free(jmptbl);
	free(casetbl);
	return ret;
}

/**
 * \brief Marks the jump table cases for analysis
 *
 * Goes through each case on the jump table, adds necessary flags/metadata and
 * a new RzAnalysisTaskItem to `params->tasks` to be analyzed later.
 *
 * \param analysis Pointer to RzAnalysis instance
 * \param fcn Pointer to RzAnalysisFunction to add the new cases
 * \param block Pointer to RzAnalysisBlock that originates the switch table
 * \param params Pointer to RzAnalysisJmpTableParams necessary to analyze the jump table
 */
RZ_API bool rz_analysis_walkthrough_jmptbl(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NONNULL RzAnalysisBlock *block, RZ_NONNULL RzAnalysisJmpTableParams *params) {
	rz_return_val_if_fail(analysis && fcn && block && params, false);
	// table_count can not always be determined
	if (params->table_count == 0) {
		params->table_count = analysis->opt.jmptbl_maxcount;
	}
	if (params->jmptbl_loc == UT64_MAX) {
		aprintf("Invalid jump table location 0x%08" PFMT64x "\n", params->jmptbl_loc);
		return false;
	}
	if (jmptable_size_is_invalid(params)) {
		aprintf("Invalid jump table size at 0x%08" PFMT64x "\n", params->jmp_address);
		return false;
	}
	ut64 jmpptr, offs;
	ut8 *jmptbl = calloc(params->table_count, params->entry_size);
	if (!jmptbl) {
		return false;
	}
	bool is_arm = analysis->cur->arch && !strncmp(analysis->cur->arch, "arm", 3);
	// eprintf ("JMPTBL AT 0x%"PFMT64x"\n", jmptbl_loc);
	analysis->iob.read_at(analysis->iob.io, params->jmptbl_loc, jmptbl, params->table_count * params->entry_size);
	for (offs = 0; offs + params->entry_size - 1 < params->table_count * params->entry_size; offs += params->entry_size) {
		switch (params->entry_size) {
		case 1:
			jmpptr = (ut64)(ut8)rz_read_le8(jmptbl + offs);
			break;
		case 2:
			jmpptr = (ut64)rz_read_le16(jmptbl + offs);
			break;
		case 4:
			jmpptr = rz_read_le32(jmptbl + offs);
			break;
		case 8:
			jmpptr = rz_read_le64(jmptbl + offs);
			break; // XXX
		default:
			jmpptr = rz_read_le64(jmptbl + offs);
			break;
		}
		// eprintf ("WALKING %llx\n", jmpptr);
		// if we don't check for 0 here, the next check with ptr+jmpptr
		// will obviously be a good offset since it will be the start
		// of the table, which is not what we want
		if (jmpptr == 0 || jmpptr == UT32_MAX || jmpptr == UT64_MAX) {
			break;
		}
		if (params->entry_size == 2 && is_arm) {
			jmpptr = params->jmp_address + 4 + (jmpptr * 2); // tbh [pc, r2, lsl 1]  // assume lsl 1
		} else if (params->entry_size == 1 && is_arm) {
			jmpptr = params->jmp_address + 4 + (jmpptr * 2); // lbb [pc, r2]  // assume lsl 1
		} else if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
			st32 jmpdelta = (st32)jmpptr;
			// jump tables where sign extended movs are used
			jmpptr = params->jmptbl_off + jmpdelta;
			if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
				break;
			}
		}
		if (analysis->limit) {
			if (jmpptr < analysis->limit->from || jmpptr > analysis->limit->to) {
				break;
			}
		}
		apply_case(analysis, block, params->jmp_address, params->entry_size, jmpptr, (offs / params->entry_size) + params->case_shift, params->jmptbl_loc + offs);
		rz_analysis_task_item_new(analysis, params->tasks, fcn, NULL, jmpptr, params->sp);
	}

	if (offs > 0) {
		if (params->default_case == 0) {
			params->default_case = UT64_MAX;
		}
		apply_switch(analysis, params->jmp_address, params->jmptbl_loc, offs / params->entry_size, params->default_case);
	}

	free(jmptbl);
	return true;
}

static bool detect_casenum_shift(RzAnalysisOp *op, RzRegItem **cmp_reg, st64 *start_casenum_shift) {
	if (!*cmp_reg) {
		return true;
	}
	if (op->dst && op->dst->reg && op->dst->reg->offset == (*cmp_reg)->offset) {
		if (op->type == RZ_ANALYSIS_OP_TYPE_LEA && op->ptr == UT64_MAX) {
			*start_casenum_shift = -(st64)op->disp;
		} else if (op->val != UT64_MAX) {
			if (op->type == RZ_ANALYSIS_OP_TYPE_ADD) {
				*start_casenum_shift = -(st64)op->val;
			} else if (op->type == RZ_ANALYSIS_OP_TYPE_SUB) {
				*start_casenum_shift = op->val;
			}
		} else if (op->type == RZ_ANALYSIS_OP_TYPE_MOV) {
			*cmp_reg = op->src[0]->reg;
			return false;
		}
		return true;
	}
	return false;
}

/**
 * \brief Gets some necessary information about a jump table to perform analysis on
 *
 * Gets amount of cases inside a jump table, the default case address and the case shift amount
 *
 * \param analysis Pointer to RzAnalysis instance
 * \param fcn Pointer to RzAnalysisFunction where jump table ocurred
 * \param jmp_address Address of jump intruction that uses the table
 * \param lea_addr Address of lea instruction that loads the address of the jump table base
 * \param params Pointer to RzAnalysisJmpTableParams where the results of the function are stored
 */
RZ_API bool rz_analysis_get_delta_jmptbl_info(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, ut64 jmp_address, ut64 lea_address, RZ_NONNULL RzAnalysisJmpTableParams *params) {
	rz_return_val_if_fail(analysis && fcn && params, false);
	bool isValid = false;
	bool foundCmp = false;
	ut64 i;

	RzAnalysisOp tmp_aop = { 0 };
	if (lea_address > jmp_address) {
		return false;
	}

	params->jmp_address = jmp_address;

	int search_sz = jmp_address - lea_address;
	ut8 *buf = malloc(search_sz);
	if (!buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	analysis->iob.read_at(analysis->iob.io, lea_address, (ut8 *)buf, search_sz);
	RzVector v;
	rz_vector_init(&v, sizeof(ut64), NULL, NULL);
	int len = 0;
	RzRegItem *cmp_reg = NULL;
	for (i = 0; i + 8 < search_sz; i += len) {
		rz_analysis_op_init(&tmp_aop);
		len = rz_analysis_op(analysis, &tmp_aop, lea_address + i, buf + i, search_sz - i, RZ_ANALYSIS_OP_MASK_BASIC);
		if (len < 1) {
			len = 1;
		}

		if (foundCmp) {
			if (tmp_aop.type != RZ_ANALYSIS_OP_TYPE_CJMP) {
				continue;
			}

			params->default_case = tmp_aop.jump == tmp_aop.jump + len ? tmp_aop.fail : tmp_aop.jump;
			break;
		}

		ut32 type = tmp_aop.type & RZ_ANALYSIS_OP_TYPE_MASK;
		if (type != RZ_ANALYSIS_OP_TYPE_CMP) {
			continue;
		}
		// get the value of the cmp
		// for operands in op, check if type is immediate and val is sane
		// TODO: How? opex?

		// for the time being, this seems to work
		// might not actually have a value, let the next step figure out the size then
		if (tmp_aop.val == UT64_MAX && tmp_aop.refptr == 0) {
			isValid = true;
			params->table_count = 0;
		} else if (tmp_aop.refptr == 0) {
			isValid = tmp_aop.val < 0x200;
			params->table_count = tmp_aop.val + 1;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			params->table_count = tmp_aop.refptr + 1;
		}
		rz_vector_push(&v, &i);
		rz_analysis_op(analysis, &tmp_aop, lea_address + i, buf + i, search_sz - i, RZ_ANALYSIS_OP_MASK_VAL);
		if (tmp_aop.dst && tmp_aop.dst->reg) {
			cmp_reg = tmp_aop.dst->reg;
		} else if (tmp_aop.reg) {
			cmp_reg = rz_reg_get(analysis->reg, tmp_aop.reg, RZ_REG_TYPE_ANY);
		} else if (tmp_aop.src[0] && tmp_aop.src[0]->reg) {
			cmp_reg = tmp_aop.src[0]->reg;
		}
		rz_analysis_op_fini(&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		foundCmp = true;
	}
	if (isValid) {
		params->case_shift = 0;
		void **it;
		rz_vector_foreach_prev (&v, it) {
			const ut64 op_off = *(ut64 *)it;
			ut64 op_addr = lea_address + op_off;
			rz_analysis_op_init(&tmp_aop);
			rz_analysis_op(analysis, &tmp_aop, op_addr,
				buf + op_off, search_sz - op_off,
				RZ_ANALYSIS_OP_MASK_VAL);
			if (detect_casenum_shift(&tmp_aop, &cmp_reg, &params->case_shift)) {
				rz_analysis_op_fini(&tmp_aop);
				break;
			}
			rz_analysis_op_fini(&tmp_aop);
		}
	}
	rz_vector_fini(&v);
	free(buf);
	return isValid;
}

/**
 * \brief Marks for analysis ARM specific jump table cases
 *
 * This function works similarly to `rz_analysis_walkthrough_jmptbl`, but is specific to ARM
 *
 * \param analysis Pointer to RzAnalysis instance
 * \param fcn Pointer to RzAnalysisFunction to add the new cases
 * \param block Pointer to RzAnalysisBlock that originates the switch table
 * \param params Pointer to RzAnalysisJmpTableParams necessary to analyze the jump table
 */
RZ_API bool rz_analysis_walkthrough_arm_jmptbl_style(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NONNULL RzAnalysisBlock *block, RZ_NONNULL RzAnalysisJmpTableParams *params) {
	/*
	 * Example about arm jump table
	 *
	 * 0x000105b4      060050e3       cmp r0, 3
	 * 0x000105b8      00f18f90       addls pc, pc, r0, lsl 2
	 * 0x000105bc      0d0000ea       b loc.000105f8
	 * 0x000105c0      050000ea       b 0x105dc
	 * 0x000105c4      050000ea       b 0x105e0
	 * 0x000105c8      060000ea       b 0x105e8
	 * ; CODE XREF from loc._a_7 (+0x10)
	 * 0x000105dc      b6ffffea       b sym.input_1
	 * ; CODE XREF from loc._a_7 (+0x14)
	 * 0x000105e0      b9ffffea       b sym.input_2
	 * ; CODE XREF from loc._a_7 (+0x28)
	 * 0x000105e4      ccffffea       b sym.input_7
	 * ; CODE XREF from loc._a_7 (+0x18)
	 * 0x000105e8      bbffffea       b sym.input_3
	 */
	rz_return_val_if_fail(analysis && fcn && block && params, false);
	ut64 offs, jmpptr;

	if (params->table_count == 0) {
		params->table_count = analysis->opt.jmptbl_maxcount;
	}

	for (offs = 0; offs + params->entry_size - 1 < params->table_count * params->entry_size; offs += params->entry_size) {
		jmpptr = params->jmptbl_loc + offs;
		apply_case(analysis, block, params->jmp_address, params->entry_size, jmpptr, offs / params->entry_size, params->jmptbl_loc + offs);
		rz_analysis_task_item_new(analysis, params->tasks, fcn, NULL, jmpptr, params->sp);
	}

	if (offs > 0) {
		if (params->default_case == 0 || params->default_case == UT32_MAX) {
			params->default_case = UT64_MAX;
		}
		apply_switch(analysis, params->jmp_address, params->jmptbl_loc, offs / params->entry_size, params->default_case);
	}
	return true;
}

/**
 * \brief Gets some necessary information about a jump table to perform analysis on
 *
 * Gets amount of cases inside a jump table, the default case address and the case shift amount
 *
 * \param analysis Pointer to RzAnalysis instance
 * \param fcn Pointer to RzAnalysisFunction where jump table ocurred
 * \param block Pointer to RzAnalysisBlock where the jump instruction related to the jump table ocurred
 * \param jmp_address Address of jump intruction that uses the table
 * \param params Pointer to RzAnalysisJmpTableParams where the results of the function are stored
 */
RZ_API bool rz_analysis_get_jmptbl_info(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisFunction *fcn, RZ_NONNULL RzAnalysisBlock *block, ut64 jmp_address, RZ_NONNULL RzAnalysisJmpTableParams *params) {
	rz_return_val_if_fail(analysis && fcn && params && block, false);
	bool isValid = false;
	int i;
	RzAnalysisBlock *tmp_bb, *prev_bb;
	prev_bb = 0;
	if (!fcn->bbs) {
		return false;
	}

	params->jmp_address = jmp_address;

	/* if UJMP is in .plt section just skip it */
	RzBinSection *s = analysis->binb.get_vsect_at(analysis->binb.bin, jmp_address);
	if (s && s->name[0]) {
		bool in_plt = strstr(s->name, ".plt") != NULL;
		if (!in_plt && strstr(s->name, "_stubs") != NULL) {
			/* for mach0 */
			in_plt = true;
		}
		if (in_plt) {
			return false;
		}
	}

	// search for the predecessor bb
	void **iter;
	rz_pvector_foreach (fcn->bbs, iter) {
		tmp_bb = (RzAnalysisBlock *)*iter;
		if (tmp_bb->jump == block->addr || tmp_bb->fail == block->addr) {
			prev_bb = tmp_bb;
			break;
		}
	}
	// predecessor must be a conditional jump
	if (!prev_bb || !prev_bb->jump || !prev_bb->fail) {
		aprintf("Missing predecesessor on basic block conditional jump at 0x%08" PFMT64x ", required by jump table\n", jmp_address);
		return false;
	}

	// default case is the jump target of the unconditional jump
	params->default_case = prev_bb->jump == block->addr ? prev_bb->fail : prev_bb->jump;

	RzAnalysisOp tmp_aop = { 0 };
	ut8 *bb_buf = calloc(1, prev_bb->size);
	if (!bb_buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	analysis->iob.read_at(analysis->iob.io, prev_bb->addr, (ut8 *)bb_buf, prev_bb->size);
	isValid = false;

	RzAnalysisHint *hint = rz_analysis_hint_get(analysis, jmp_address);
	if (hint) {
		ut64 val = hint->val;
		rz_analysis_hint_free(hint);
		if (val != UT64_MAX) {
			params->table_count = val;
			return true;
		}
	}

	RzRegItem *cmp_reg = NULL;
	for (i = prev_bb->ninstr - 1; i >= 0; i--) {
		const ut64 prev_pos = rz_analysis_block_get_op_offset(prev_bb, i);
		const ut64 op_addr = rz_analysis_block_get_op_addr(prev_bb, i);
		if (prev_pos >= prev_bb->size) {
			continue;
		}
		int buflen = prev_bb->size - prev_pos;
		rz_analysis_op_init(&tmp_aop);
		int len = rz_analysis_op(analysis, &tmp_aop, op_addr,
			bb_buf + prev_pos, buflen,
			RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
		ut32 type = tmp_aop.type & RZ_ANALYSIS_OP_TYPE_MASK;
		if (len < 1 || type != RZ_ANALYSIS_OP_TYPE_CMP) {
			rz_analysis_op_fini(&tmp_aop);
			continue;
		}
		// get the value of the cmp
		// for operands in op, check if type is immediate and val is sane
		// TODO: How? opex?

		// for the time being, this seems to work
		// might not actually have a value, let the next step figure out the size then
		if (tmp_aop.val == UT64_MAX && tmp_aop.refptr == 0) {
			isValid = true;
			params->table_count = 0;
		} else if (tmp_aop.refptr == 0 || tmp_aop.val != UT64_MAX) {
			isValid = tmp_aop.val < 0x200;
			params->table_count = tmp_aop.val + 1;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			params->table_count = tmp_aop.refptr + 1;
		}
		if (isValid) {
			rz_analysis_op_fini(&tmp_aop);
			rz_analysis_op_init(&tmp_aop);
			rz_analysis_op(analysis, &tmp_aop, op_addr,
				bb_buf + prev_pos, buflen,
				RZ_ANALYSIS_OP_MASK_VAL);
			if (tmp_aop.dst && tmp_aop.dst->reg) {
				cmp_reg = tmp_aop.dst->reg;
			} else if (tmp_aop.reg) {
				cmp_reg = rz_reg_get(analysis->reg, tmp_aop.reg, RZ_REG_TYPE_ANY);
			} else if (tmp_aop.src[0] && tmp_aop.src[0]->reg) {
				cmp_reg = tmp_aop.src[0]->reg;
			}
		}
		rz_analysis_op_fini(&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		break;
	}
	if (isValid) {
		params->case_shift = 0;
		for (i--; i >= 0; i--) {
			const ut64 prev_pos = rz_analysis_block_get_op_offset(prev_bb, i);
			const ut64 op_addr = rz_analysis_block_get_op_addr(prev_bb, i);
			if (prev_pos >= prev_bb->size) {
				continue;
			}
			int buflen = prev_bb->size - prev_pos;
			rz_analysis_op_init(&tmp_aop);
			rz_analysis_op(analysis, &tmp_aop, op_addr,
				bb_buf + prev_pos, buflen,
				RZ_ANALYSIS_OP_MASK_VAL);
			if (detect_casenum_shift(&tmp_aop, &cmp_reg, &params->case_shift)) {
				rz_analysis_op_fini(&tmp_aop);
				break;
			}

			rz_analysis_op_fini(&tmp_aop);
		}
	}
	free(bb_buf);
	return isValid;
}
