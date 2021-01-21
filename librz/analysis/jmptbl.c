// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util.h>
#include <rz_list.h>

#define aprintf(format, ...) \
	if (analysis->verbose) \
	eprintf(format, __VA_ARGS__)

#define JMPTBL_MAXSZ 512

static void apply_case(RzAnalysis *analysis, RzAnalysisBlock *block, ut64 switch_addr, ut64 offset_sz, ut64 case_addr, ut64 id, ut64 case_addr_loc) {
	// eprintf ("** apply_case: 0x%"PFMT64x " from 0x%"PFMT64x "\n", case_addr, case_addr_loc);
	rz_meta_set_data_at(analysis, case_addr_loc, offset_sz);
	rz_analysis_hint_set_immbase(analysis, case_addr_loc, 10);
	rz_analysis_xrefs_set(analysis, switch_addr, case_addr, RZ_ANALYSIS_REF_TYPE_CODE);
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
			rz_analysis_xrefs_set(analysis, switch_addr, default_case_addr, RZ_ANALYSIS_REF_TYPE_CODE);
			snprintf(tmp, sizeof(tmp), "case.default.0x%" PFMT64x, switch_addr);
			analysis->flb.set(analysis->flb.f, tmp, default_case_addr, 1);
		}
	}
}

// analyze a jmptablle inside a function // maybe rename to rz_analysis_fcn_jmptbl() ?
RZ_API bool rz_analysis_jmptbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, ut64 jmpaddr, ut64 table, ut64 tablesize, ut64 default_addr) {
	const int depth = 50;
	return try_walkthrough_jmptbl(analysis, fcn, block, depth, jmpaddr, table, table, tablesize, tablesize, default_addr, false);
}

RZ_API bool try_walkthrough_casetbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 casetbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}
	if (jmptbl_loc == UT64_MAX) {
		aprintf("Warning: Invalid JumpTable location 0x%08" PFMT64x "\n", jmptbl_loc);
		return false;
	}
	if (casetbl_loc == UT64_MAX) {
		aprintf("Warning: Invalid CaseTable location 0x%08" PFMT64x "\n", jmptbl_loc);
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		aprintf("Warning: Invalid JumpTable size at 0x%08" PFMT64x "\n", ip);
		return false;
	}
	ut64 jmpptr, case_idx, jmpptr_idx;
	ut8 *jmptbl = calloc(jmptbl_size, sz);
	if (!jmptbl || !analysis->iob.read_at(analysis->iob.io, jmptbl_loc, jmptbl, jmptbl_size * sz)) {
		free(jmptbl);
		return false;
	}
	ut8 *casetbl = calloc(jmptbl_size, sizeof(ut8));
	if (!casetbl || !analysis->iob.read_at(analysis->iob.io, casetbl_loc, casetbl, jmptbl_size)) {
		free(jmptbl);
		free(casetbl);
		return false;
	}
	for (case_idx = 0; case_idx < jmptbl_size; case_idx++) {
		jmpptr_idx = casetbl[case_idx];

		if (jmpptr_idx >= jmptbl_size) {
			ret = false;
			break;
		}

		switch (sz) {
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
			jmpptr = jmptbl_off + jmpdelta;
			if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
				break;
			}
		}
		if (analysis->limit) {
			if (jmpptr < analysis->limit->from || jmpptr > analysis->limit->to) {
				break;
			}
		}

		const ut64 jmpptr_idx_off = casetbl_loc + case_idx;
		rz_meta_set_data_at(analysis, jmpptr_idx_off, 1);
		rz_analysis_hint_set_immbase(analysis, jmpptr_idx_off, 10);

		apply_case(analysis, block, ip, sz, jmpptr, case_idx, jmptbl_loc + jmpptr_idx * sz);
		(void)rz_analysis_fcn_bb(analysis, fcn, jmpptr, depth - 1);
	}

	if (case_idx > 0) {
		if (default_case == 0) {
			default_case = UT64_MAX;
		}
		apply_switch(analysis, ip, jmptbl_loc, case_idx, default_case);
	}

	free(jmptbl);
	free(casetbl);
	return ret;
}

RZ_API bool try_walkthrough_jmptbl(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 jmptbl_off, ut64 sz, ut64 jmptbl_size, ut64 default_case, bool ret0) {
	bool ret = ret0;
	// jmptbl_size can not always be determined
	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}
	if (jmptbl_loc == UT64_MAX) {
		aprintf("Warning: Invalid JumpTable location 0x%08" PFMT64x "\n", jmptbl_loc);
		return false;
	}
	if (jmptbl_size < 1 || jmptbl_size > ST32_MAX) {
		aprintf("Warning: Invalid JumpTable size at 0x%08" PFMT64x "\n", ip);
		return false;
	}
	ut64 jmpptr, offs;
	ut8 *jmptbl = calloc(jmptbl_size, sz);
	if (!jmptbl) {
		return false;
	}
	bool is_arm = analysis->cur->arch && !strncmp(analysis->cur->arch, "arm", 3);
	// eprintf ("JMPTBL AT 0x%"PFMT64x"\n", jmptbl_loc);
	analysis->iob.read_at(analysis->iob.io, jmptbl_loc, jmptbl, jmptbl_size * sz);
	for (offs = 0; offs + sz - 1 < jmptbl_size * sz; offs += sz) {
		switch (sz) {
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
		if (sz == 2 && is_arm) {
			jmpptr = ip + 4 + (jmpptr * 2); // tbh [pc, r2, lsl 1]  // assume lsl 1
		} else if (sz == 1 && is_arm) {
			jmpptr = ip + 4 + (jmpptr * 2); // lbb [pc, r2]  // assume lsl 1
		} else if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
			st32 jmpdelta = (st32)jmpptr;
			// jump tables where sign extended movs are used
			jmpptr = jmptbl_off + jmpdelta;
			if (!analysis->iob.is_valid_offset(analysis->iob.io, jmpptr, 0)) {
				break;
			}
		}
		if (analysis->limit) {
			if (jmpptr < analysis->limit->from || jmpptr > analysis->limit->to) {
				break;
			}
		}
		apply_case(analysis, block, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs);
		(void)rz_analysis_fcn_bb(analysis, fcn, jmpptr, depth - 1);
	}

	if (offs > 0) {
		if (default_case == 0) {
			default_case = UT64_MAX;
		}
		apply_switch(analysis, ip, jmptbl_loc, offs / sz, default_case);
	}

	free(jmptbl);
	return ret;
}

// TODO: RENAME
RZ_API bool try_get_delta_jmptbl_info(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 jmp_addr, ut64 lea_addr, ut64 *table_size, ut64 *default_case) {
	bool isValid = false;
	bool foundCmp = false;
	int i;

	RzAnalysisOp tmp_aop = { 0 };
	if (lea_addr > jmp_addr) {
		return false;
	}
	int search_sz = jmp_addr - lea_addr;
	ut8 *buf = malloc(search_sz);
	if (!buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	analysis->iob.read_at(analysis->iob.io, lea_addr, (ut8 *)buf, search_sz);

	for (i = 0; i + 8 < search_sz; i++) {
		int len = rz_analysis_op(analysis, &tmp_aop, lea_addr + i, buf + i, search_sz - i, RZ_ANALYSIS_OP_MASK_BASIC);
		if (len < 1) {
			len = 1;
		}

		if (foundCmp) {
			if (tmp_aop.type != RZ_ANALYSIS_OP_TYPE_CJMP) {
				continue;
			}

			*default_case = tmp_aop.jump == tmp_aop.jump + len ? tmp_aop.fail : tmp_aop.jump;
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
			*table_size = 0;
		} else if (tmp_aop.refptr == 0) {
			isValid = tmp_aop.val < 0x200;
			*table_size = tmp_aop.val + 1;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			*table_size = tmp_aop.refptr + 1;
		}
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		foundCmp = true;
	}
	free(buf);
	return isValid;
}

// TODO: find a better function name
RZ_API int walkthrough_arm_jmptbl_style(RzAnalysis *analysis, RzAnalysisFunction *fcn, RzAnalysisBlock *block, int depth, ut64 ip, ut64 jmptbl_loc, ut64 sz, ut64 jmptbl_size, ut64 default_case, int ret0) {
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

	ut64 offs, jmpptr;
	int ret = ret0;

	if (jmptbl_size == 0) {
		jmptbl_size = JMPTBL_MAXSZ;
	}

	for (offs = 0; offs + sz - 1 < jmptbl_size * sz; offs += sz) {
		jmpptr = jmptbl_loc + offs;
		apply_case(analysis, block, ip, sz, jmpptr, offs / sz, jmptbl_loc + offs);
		(void)rz_analysis_fcn_bb(analysis, fcn, jmpptr, depth - 1);
	}

	if (offs > 0) {
		if (default_case == 0 || default_case == UT32_MAX) {
			default_case = UT64_MAX;
		}
		apply_switch(analysis, ip, jmptbl_loc, offs / sz, default_case);
	}
	return ret;
}

RZ_API bool try_get_jmptbl_info(RzAnalysis *analysis, RzAnalysisFunction *fcn, ut64 addr, RzAnalysisBlock *my_bb, ut64 *table_size, ut64 *default_case) {
	bool isValid = false;
	int i;
	RzListIter *iter;
	RzAnalysisBlock *tmp_bb, *prev_bb;
	prev_bb = 0;
	if (!fcn->bbs) {
		return false;
	}

	/* if UJMP is in .plt section just skip it */
	RzBinSection *s = analysis->binb.get_vsect_at(analysis->binb.bin, addr);
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
	rz_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			prev_bb = tmp_bb;
			break;
		}
	}
	// predecessor must be a conditional jump
	if (!prev_bb || !prev_bb->jump || !prev_bb->fail) {
		aprintf("Warning: [analysis.jmp.tbl] Missing predecesessor cjmp bb at 0x%08" PFMT64x "\n", addr);
		return false;
	}

	// default case is the jump target of the unconditional jump
	*default_case = prev_bb->jump == my_bb->addr ? prev_bb->fail : prev_bb->jump;

	RzAnalysisOp tmp_aop = { 0 };
	ut8 *bb_buf = calloc(1, prev_bb->size);
	if (!bb_buf) {
		return false;
	}
	// search for a cmp register with a reasonable size
	analysis->iob.read_at(analysis->iob.io, prev_bb->addr, (ut8 *)bb_buf, prev_bb->size);
	isValid = false;

	RzAnalysisHint *hint = rz_analysis_hint_get(analysis, addr);
	if (hint) {
		ut64 val = hint->val;
		rz_analysis_hint_free(hint);
		if (val != UT64_MAX) {
			*table_size = val;
			return true;
		}
	}

	for (i = 0; i < prev_bb->op_pos_size; i++) {
		ut64 prev_pos = prev_bb->op_pos[i];
		ut64 op_addr = prev_bb->addr + prev_pos;
		if (prev_pos >= prev_bb->size) {
			continue;
		}
		int buflen = prev_bb->size - prev_pos;
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
			*table_size = 0;
		} else if (tmp_aop.refptr == 0 || tmp_aop.val != UT64_MAX) {
			isValid = tmp_aop.val < 0x200;
			*table_size = tmp_aop.val + 1;
		} else {
			isValid = tmp_aop.refptr < 0x200;
			*table_size = tmp_aop.refptr + 1;
		}
		rz_analysis_op_fini(&tmp_aop);
		// TODO: check the jmp for whether val is included in valid range or not (ja vs jae)
		break;
	}
	free(bb_buf);
	// eprintf ("switch at 0x%" PFMT64x "\n\tdefault case 0x%" PFMT64x "\n\t#cases: %d\n",
	// 		addr,
	// 		*default_case,
	// 		*table_size);
	return isValid;
}
