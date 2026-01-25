// SPDX-FileCopyrightText: 2014-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/sparc.h>

#include "isa/sparc/sparc_il.h"
#include "rz_il/rz_il_opcodes.h"
#include "rz_util/rz_assert.h"

static RzStructuredData *sparc_opex(csh handle, cs_insn *insn) {
	if (!insn->detail) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}

	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}

	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	cs_sparc *x = &insn->detail->sparc;
	for (st32 i = 0; i < x->op_count; i++) {
		cs_sparc_op *op = x->operands + i;
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		case SPARC_OP_REG:
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", cs_reg_name(handle, op->reg));
			break;
		case SPARC_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", op->imm);
			break;
		case SPARC_OP_MEM:
			rz_structured_data_map_add_string(operand, "type", "mem");
			if (op->mem.base != SPARC_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "base", cs_reg_name(handle, op->mem.base));
			}
			rz_structured_data_map_add_signed(operand, "disp", op->mem.disp);
			break;
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}

	return root;
}

static int parse_reg_name(RzRegItem *reg, csh handle, cs_insn *insn, int reg_num) {
	if (!reg) {
		return -1;
	}
	switch (INSOP(reg_num).type) {
	case SPARC_OP_REG:
		reg->name = (char *)cs_reg_name(handle, INSOP(reg_num).reg);
		break;
	case SPARC_OP_MEM:
		if (INSOP(reg_num).mem.base != SPARC_REG_INVALID) {
			reg->name = (char *)cs_reg_name(handle, INSOP(reg_num).mem.base);
			break;
		}
	default:
		break;
	}
	return 0;
}

static bool sparc_init(void **user) {
	RzAnalysisValueSPARC *sparc = RZ_NEW0(RzAnalysisValueSPARC);
	rz_return_val_if_fail(sparc, false);
	sparc->handle = 0;
	sparc->delayed_branch = ht_up_new(NULL, NULL);
	*user = sparc;
	return true;
}

static void op_fillval(RzAnalysis *a, RzAnalysisOp *op, csh handle, cs_insn *insn) {
	RzAnalysisValueSPARC *sparc = (RzAnalysisValueSPARC *)a->plugin_data;
	switch (op->type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		if (INSOP(0).type == SPARC_OP_MEM) {
			ZERO_FILL(sparc->reg);
			op->src[0] = rz_analysis_value_new();
			op->src[0]->type = RZ_ANALYSIS_VAL_MEM;
			op->src[0]->reg = sparc->reg;
			parse_reg_name(op->src[0]->reg, handle, insn, 0);
			op->src[0]->delta = INSOP(0).mem.disp;
		}
		break;
	case RZ_ANALYSIS_OP_TYPE_STORE:
		if (INSOP(1).type == SPARC_OP_MEM) {
			ZERO_FILL(sparc->reg);
			op->dst = rz_analysis_value_new();
			op->dst->type = RZ_ANALYSIS_VAL_MEM;
			op->dst->reg = sparc->reg;
			parse_reg_name(op->dst->reg, handle, insn, 1);
			op->dst->delta = INSOP(1).mem.disp;
		}
		break;
	}
}

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	RzAnalysisValueSPARC *sparc = (RzAnalysisValueSPARC *)a->plugin_data;
	cs_insn *insn;
	int mode = 0;
	int n, ret;

	if (a->big_endian) {
		mode = CS_MODE_BIG_ENDIAN;
	}

	if (RZ_STR_EQ(a->cpu, "v9")) {
		mode |= CS_MODE_V9;
	}
	if (a->bits == 64) {
		mode |= CS_MODE_64;
	} else {
		mode |= CS_MODE_32;
	}
	if (mode != sparc->omode) {
		cs_close(&sparc->handle);
		sparc->handle = 0;
		sparc->omode = mode;
	}
	if (sparc->handle == 0) {
		ret = cs_open(CS_ARCH_SPARC, mode, &sparc->handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
#if CS_API_MAJOR >= 6
		cs_option(sparc->handle, CS_OPT_DETAIL, CS_OPT_ON | CS_OPT_DETAIL_REAL);
#else
		cs_option(sparc->handle, CS_OPT_DETAIL, CS_OPT_ON);
#endif
	}
	// capstone-next
	n = cs_disasm(sparc->handle, (const ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		return 0;
	}
#if CS_API_MAJOR >= 6
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		bool has_delayed_branch = false;
		RzSparcDelatedBranchOp *delayed_branch = ht_up_find(sparc->delayed_branch, addr, &has_delayed_branch);

		op->il_op = rz_sparc_cs_get_il_op(sparc->handle, insn, mode, sparc);
		if (has_delayed_branch) {
			if (op->il_op && op->il_op->code == RZ_IL_OP_NOP) {
				// Unconditional jumps have often a nop instruction in the delayed slot.
				// But we should not execute it. Because it will set the PC temporarily (before the JUMP is executed)
				// to the instruction *after* the delayed slot.
				// This is semantically not correct and can lead to bugs if the IL op is used
				// in analysis.
				// So replace it with an EMPTY effect.
				// NOTE: The jump of an unconditional branch is still executed on the
				// PC of the delayed slot! This is semantically also not correct,
				// because the delayed slot instruction should never be executed for unconditional jumps.
				// But we need to wait for RzArch implementation and support for instruction packets
				// to do this properly. So I safe the time spent on a work around.
				rz_il_op_effect_free(op->il_op);
				op->il_op = rz_il_op_new_empty();
			}
			if (op->il_op && delayed_branch->cond) {
				// The branch is conditionally and annuls the delay slot if not taken (skips op->il_op).
				op->il_op = rz_il_op_new_branch(delayed_branch->cond,
					rz_il_op_new_seq(delayed_branch->set_ea, rz_il_op_new_seq(op->il_op, delayed_branch->perform_jmp)),
					delayed_branch->perform_fail_jmp);
			} else if (op->il_op) {
				op->il_op = rz_il_op_new_seq(delayed_branch->set_ea, rz_il_op_new_seq(op->il_op, delayed_branch->perform_jmp));
			}
			// Just free the RzSparcDelatedBranchOp struct.
			// The effects are freed by the SEQ handler.
			free(delayed_branch);
			ht_up_delete(sparc->delayed_branch, addr);
		}
	}
#endif
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = sparc_opex(sparc->handle, insn);
	}
	op->size = insn->size;
	op->id = insn->id;
	switch (insn->id) {
	case SPARC_INS_INVALID:
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		break;
	case SPARC_INS_MOV:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case SPARC_INS_RETT:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->delay = 1;
		break;
	case SPARC_INS_UNIMP:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case SPARC_INS_CALL:
		switch (INSOP(0).type) {
		case SPARC_OP_MEM:
			// TODO
			break;
		case SPARC_OP_REG:
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
			op->delay = 1;
			break;
		default:
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->delay = 1;
			op->jump = INSOP(0).imm;
			break;
		}
		break;
	case SPARC_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case SPARC_INS_SUBCC:
#if CS_API_MAJOR >= 6
		if (insn->alias_id == SPARC_INS_ALIAS_CMP) {
			op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		}
#else
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
#endif
		break;
	case SPARC_INS_JMPL:
		op->delay = 1;
#if CS_API_MAJOR >= 6
		if (insn->alias_id == SPARC_INS_ALIAS_RET || insn->alias_id == SPARC_INS_ALIAS_RETL) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else if (insn->alias_id == SPARC_INS_ALIAS_CALL) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		}
#else
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
#endif
		break;
#if CS_API_MAJOR >= 6
	case SPARC_INS_LDDA:
	case SPARC_INS_LDA:
	case SPARC_INS_LDQA:
	case SPARC_INS_LDSBA:
	case SPARC_INS_LDSHA:
	case SPARC_INS_LDSWA:
	case SPARC_INS_LDUBA:
	case SPARC_INS_LDUHA:
	case SPARC_INS_LDXA:
#endif
	case SPARC_INS_LDD:
	case SPARC_INS_LD:
	case SPARC_INS_LDQ:
	case SPARC_INS_LDSB:
	case SPARC_INS_LDSH:
	case SPARC_INS_LDSW:
	case SPARC_INS_LDUB:
	case SPARC_INS_LDUH:
	case SPARC_INS_LDX:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
#if CS_API_MAJOR >= 6
	case SPARC_INS_STBA:
	case SPARC_INS_STDA:
	case SPARC_INS_STA:
	case SPARC_INS_STHA:
	case SPARC_INS_STQA:
	case SPARC_INS_STXA:
#endif
	case SPARC_INS_STBAR:
	case SPARC_INS_STB:
	case SPARC_INS_STD:
	case SPARC_INS_ST:
	case SPARC_INS_STH:
	case SPARC_INS_STQ:
	case SPARC_INS_STX:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case SPARC_INS_ORCC:
	case SPARC_INS_ORNCC:
	case SPARC_INS_ORN:
	case SPARC_INS_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case SPARC_INS_B:
	case SPARC_INS_BMASK:
	case SPARC_INS_FB: {
		// See Table 6-5 in OSA 2015 - Revision: Draft D1.0.0:
		bool annul_bit = INSHINT() & SPARC_HINT_A;
		op->delay = !(INSCC_NORM() == SPARC_CC_ICC_A && annul_bit);
		switch (INSOP(0).type) {
		default:
		case SPARC_OP_REG:
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
			break;
		case SPARC_OP_IMM:
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			if (INSCC_NORM() != SPARC_CC_ICC_N) { // never
				op->jump = INSOP(0).imm;
			}
			break;
		}
		if (INSCC_NORM() != SPARC_CC_ICC_A) {
			// Conditional branches and BN
			if (INSCC_NORM() != SPARC_CC_ICC_N) {
				op->type |= RZ_ANALYSIS_OP_TYPE_COND;
			}
			op->fail = addr + 8;
		}
		// BA and BA,a don't set fail
		break;
	}
	case SPARC_INS_FHSUBD:
	case SPARC_INS_FHSUBS:
	case SPARC_INS_FPSUB16:
	case SPARC_INS_FPSUB16S:
	case SPARC_INS_FPSUB32:
	case SPARC_INS_FPSUB32S:
	case SPARC_INS_FSUBD:
	case SPARC_INS_FSUBQ:
	case SPARC_INS_FSUBS:
	case SPARC_INS_SUBX:
	case SPARC_INS_SUBXCC:
	case SPARC_INS_SUB:
	case SPARC_INS_TSUBCCTV:
	case SPARC_INS_TSUBCC:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case SPARC_INS_ADDCC:
	case SPARC_INS_ADDX:
	case SPARC_INS_ADDXCC:
	case SPARC_INS_ADDXC:
	case SPARC_INS_ADDXCCC:
	case SPARC_INS_ADD:
	case SPARC_INS_FADDD:
	case SPARC_INS_FADDQ:
	case SPARC_INS_FADDS:
	case SPARC_INS_FHADDD:
	case SPARC_INS_FHADDS:
	case SPARC_INS_FNADDD:
	case SPARC_INS_FNADDS:
	case SPARC_INS_FNHADDD:
	case SPARC_INS_FNHADDS:
	case SPARC_INS_FPADD16:
	case SPARC_INS_FPADD16S:
	case SPARC_INS_FPADD32:
	case SPARC_INS_FPADD32S:
	case SPARC_INS_FPADD64:
	case SPARC_INS_TADDCCTV:
	case SPARC_INS_TADDCC:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case SPARC_INS_FDMULQ:
	case SPARC_INS_FMUL8SUX16:
	case SPARC_INS_FMUL8ULX16:
	case SPARC_INS_FMUL8X16:
	case SPARC_INS_FMUL8X16AL:
	case SPARC_INS_FMUL8X16AU:
	case SPARC_INS_FMULD:
	case SPARC_INS_FMULD8SUX16:
	case SPARC_INS_FMULD8ULX16:
	case SPARC_INS_FMULQ:
	case SPARC_INS_FMULS:
	case SPARC_INS_FSMULD:
	case SPARC_INS_MULX:
	case SPARC_INS_SMULCC:
	case SPARC_INS_SMUL:
	case SPARC_INS_UMULCC:
	case SPARC_INS_UMULXHI:
	case SPARC_INS_UMUL:
	case SPARC_INS_XMULX:
	case SPARC_INS_XMULXHI:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case SPARC_INS_FDIVD:
	case SPARC_INS_FDIVQ:
	case SPARC_INS_FDIVS:
	case SPARC_INS_SDIVCC:
	case SPARC_INS_SDIVX:
	case SPARC_INS_SDIV:
	case SPARC_INS_UDIVCC:
	case SPARC_INS_UDIVX:
	case SPARC_INS_UDIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		op_fillval(a, op, sparc->handle, insn);
	}
	cs_free(insn, n);
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p = NULL;
	if (analysis->bits == 32) {
		// Sparc V8
		p =
			"=PC	pc\n"
			"=SP	sp\n"
			"=BP	fp\n"
			// These are defined from the callees point of view.
			// Meaning: The in-registers of the callee are the out-registers of the caller.
			"=A0	i0\n"
			"=A1	i1\n"
			"=A2	i2\n"
			"=A3	i3\n"
			"=A4	i4\n"
			"=A5	i5\n"

			"=R0	i0\n"
			"=R1	i1\n"
			"=R2	i2\n"
			"=R3	i3\n"

			/* r0-r7 are global aka g0-g7 */
			"gpr	g0	.32	0	0\n"
			"gpr	g1	.32	4	0\n"
			"gpr	g2	.32	8	0\n"
			"gpr	g3	.32	12	0\n"
			"gpr	g4	.32	16	0\n"
			"gpr	g5	.32	20	0\n"
			"gpr	g6	.32	24	0\n"
			"gpr	g7	.32	28	0\n"
			/* r8-15 are out (o0-o7) */
			"gpr	o0	.32	32	0\n"
			"gpr	o1	.32	36	0\n"
			"gpr	o2	.32	40	0\n"
			"gpr	o3	.32	44	0\n"
			"gpr	o4	.32	48	0\n"
			"gpr	o5	.32	52	0\n"
			"gpr	sp	.32	56	0\n"
			"gpr	o7	.32	60	0\n"
			/* r16-23 are local (l0-l7) */
			"gpr	l0	.32	64	0\n"
			"gpr	l1	.32	68	0\n"
			"gpr	l2	.32	72	0\n"
			"gpr	l3	.32	76	0\n"
			"gpr	l4	.32	80	0\n"
			"gpr	l5	.32	84	0\n"
			"gpr	l6	.32	88	0\n"
			"gpr	l7	.32	92	0\n"
			/* r24-31 are in (i0-i7) */
			"gpr	i0	.32	96	0\n"
			"gpr	i1	.32	100	0\n"
			"gpr	i2	.32	104	0\n"
			"gpr	i3	.32	108	0\n"
			"gpr	i4	.32	112	0\n"
			"gpr	i5	.32	116	0\n"
			"gpr	fp	.32	120	0\n"
			"gpr	i7	.32	124	0\n"
			"gpr	psr	.32	128	0\n"
			"gpr	pc	.32	132	0\n"
			"gpr	npc	.32	136	0\n"
			"gpr	y	.32  	140	0\n"
			"gpr	wim	.32	144	0\n"
			"gpr	tbr	.32	148	0\n"
			"gpr	asr	.32	152	0\n"
			"gpr	csr	.32	160	0\n"
			"gpr	asi	.32	164	0\n"
			"ctr	ccr	.8	168	0\n"
			// Those are technically not part of the Sparc V8 ISA.
			// But for simplicity we define them here so
			// the RzIL implementation is easier.
			// Also tnpc is used by rett.
			"sys	tpc					.32 180 0\n"
			"sys	tnpc				.32 184 0\n"
			"sys	tstate			.32 188 0\n"
			"sys	tt					.32 192 0\n"
			"sys	tick				.32 196 0\n"
			"sys	tba					.32 200 0\n"
			"sys	pstate			.32 204 0\n"
			"sys	tl					.32 208 0\n"
			"sys	pil					.32 212 0\n"
			"sys	cwp					.32 216 0\n"
			"sys	cansave			.32 220 0\n"
			"sys	canrestore	.32 224 0\n"
			"sys	cleanwin		.32 228 0\n"
			"sys	otherwin		.32 232 0\n"
			"sys	wstate			.32 236 0\n"
			"sys	fq					.32 240 0\n"
			"sys	ver					.32 244 0\n"
			"fpu	f0					.32 248 0\n"
			"fpu	f1					.32 252 0\n"
			"fpu	f2					.32 256 0\n"
			"fpu	f3					.32 260 0\n"
			"fpu	f4					.32 264 0\n"
			"fpu	f5					.32 268 0\n"
			"fpu	f6					.32 272 0\n"
			"fpu	f7					.32 276 0\n"
			"fpu	f8					.32 280 0\n"
			"fpu	f9					.32 284 0\n"
			"fpu	f10					.32 288 0\n"
			"fpu	f11					.32 292 0\n"
			"fpu	f12					.32 296 0\n"
			"fpu	f13					.32 300 0\n"
			"fpu	f14					.32 304 0\n"
			"fpu	f15					.32 308 0\n"
			"fpu	f16					.32 312 0\n"
			"fpu	f17					.32 316 0\n"
			"fpu	f18					.32 320 0\n"
			"fpu	f19					.32 324 0\n"
			"fpu	f20					.32 328 0\n"
			"fpu	f21					.32 332 0\n"
			"fpu	f22					.32 336 0\n"
			"fpu	f23					.32 340 0\n"
			"fpu	f24					.32 344 0\n"
			"fpu	f25					.32 348 0\n"
			"fpu	f26					.32 352 0\n"
			"fpu	f27					.32 356 0\n"
			"fpu	f28					.32 360 0\n"
			"fpu	f29					.32 364 0\n"
			"fpu	f30					.32 368 0\n"
			"fpu	f31					.32 372 0\n"
			"gpr	fsr					.32	376	0\n"
			"ctr	asr0				.32 380 0\n"
			"ctr	asr1				.32 384 0\n"
			"ctr	asr2				.32 388 0\n"
			"ctr	asr3				.32 392 0\n"
			"ctr	asr4				.32 396 0\n"
			"ctr	asr5				.32 400 0\n"
			"ctr	asr6				.32 404 0\n"
			"ctr	asr7				.32 408 0\n"
			"ctr	asr8				.32 412 0\n"
			"ctr	asr9				.32 416 0\n"
			"ctr	asr10				.32 420 0\n"
			"ctr	asr11				.32 424 0\n"
			"ctr	asr12				.32 428 0\n"
			"ctr	asr13				.32 432 0\n"
			"ctr	asr14				.32 436 0\n"
			"ctr	asr15				.32 440 0\n"
			"ctr	asr16				.32 444 0\n"
			"ctr	asr17				.32 448 0\n"
			"ctr	asr18				.32 452 0\n"
			"ctr	asr19				.32 456 0\n"
			"ctr	asr20				.32 460 0\n"
			"ctr	asr21				.32 464 0\n"
			"ctr	asr22				.32 468 0\n"
			"ctr	asr23				.32 472 0\n"
			"ctr	asr24				.32 476 0\n"
			"ctr	asr25				.32 480 0\n"
			"ctr	asr26				.32 484 0\n"
			"ctr	asr27				.32 488 0\n"
			"ctr	asr28				.32 492 0\n"
			"ctr	asr29				.32 496 0\n"
			"ctr	asr30				.32 500 0\n"
			"ctr	asr31				.32 504 0\n"
			"ctr	fprs				.3 508 0\n";
	} else if (analysis->bits == 64) {
		// Sparc V9 and later liek from Oracle
		p =
			"=PC	pc\n"
			"=SP	sp\n"
			"=BP	fp\n"
			// These are defined from the callees point of view.
			// Meaning: The in-registers of the callee are the out-registers of the caller.
			"=A0	i0\n"
			"=A1	i1\n"
			"=A2	i2\n"
			"=A3	i3\n"
			"=A4	i4\n"
			"=A5	i5\n"

			"=R0	i0\n"
			"=R1	i1\n"
			"=R2	i2\n"
			"=R3	i3\n"

			// PSR, WIM and TBR are replaced by several other registers.
			// From V9 onwards.
			/* r0-r7 are global aka g0-g7 */
			"gpr	g0	.64	0	0\n"
			"gpr	g1	.64	8	0\n"
			"gpr	g2	.64	16	0\n"
			"gpr	g3	.64	24	0\n"
			"gpr	g4	.64	32	0\n"
			"gpr	g5	.64	40	0\n"
			"gpr	g6	.64	48	0\n"
			"gpr	g7	.64	56	0\n"
			/* r8-15 are out (o0-o7) */
			"gpr	o0	.64	64	0\n"
			"gpr	o1	.64	72	0\n"
			"gpr	o2	.64	80	0\n"
			"gpr	o3	.64	88	0\n"
			"gpr	o4	.64	96	0\n"
			"gpr	o5	.64	104	0\n"
			"gpr	sp	.64	112	0\n"
			"gpr	o7	.64	120	0\n"
			/* r16-23 are local (l0-l7) */
			"gpr	l0	.64	128	0\n"
			"gpr	l1	.64	136	0\n"
			"gpr	l2	.64	144	0\n"
			"gpr	l3	.64	152	0\n"
			"gpr	l4	.64	160	0\n"
			"gpr	l5	.64	168	0\n"
			"gpr	l6	.64	176	0\n"
			"gpr	l7	.64	184	0\n"
			/* r24-31 are in (i0-i7) */
			"gpr	i0	.64	192	0\n"
			"gpr	i1	.64	200	0\n"
			"gpr	i2	.64	208	0\n"
			"gpr	i3	.64	216	0\n"
			"gpr	i4	.64	224	0\n"
			"gpr	i5	.64	232	0\n"
			"gpr	fp	.64	240	0\n"
			"gpr	i7	.64	248	0\n"
			"sys	tstate			.64 256 0\n"
			"sys	tpc					.64 264 0\n"
			"sys	tnpc				.64 272 0\n"
			"gpr	y	.64	280	0\n"
			"gpr	pc	.64	288	0\n"
			"gpr	npc	.64	296	0\n"
			"gpr	asr	.64	304	0\n"
			"gpr	csr	.64	320	0\n"
			"gpr	asi	.64	328	0\n"
			"ctr	ccr	.8	336	0\n"
			"sys	tt					.64 344 0\n"
			"sys	tick				.64 352 0\n"
			"sys	tba					.64 360 0\n"
			"sys	pstate			.64 368 0\n"
			"sys	tl					.64 376 0\n"
			"sys	pil					.64 384 0\n"
			"sys	cwp					.64 392 0\n"
			"sys	cansave			.64 400 0\n"
			"sys	canrestore	.64 408 0\n"
			"sys	cleanwin		.64 416 0\n"
			"sys	otherwin		.64 424 0\n"
			"sys	wstate			.64 432 0\n"
			"sys	fq					.64 440 0\n"
			"sys	ver					.64 448 0\n"
			"fpu	f0					.32 456 0\n"
			"fpu	f1					.32 460 0\n"
			"fpu	f2					.32 464 0\n"
			"fpu	f3					.32 468 0\n"
			"fpu	f4					.32 472 0\n"
			"fpu	f5					.32 476 0\n"
			"fpu	f6					.32 480 0\n"
			"fpu	f7					.32 484 0\n"
			"fpu	f8					.32 488 0\n"
			"fpu	f9					.32 492 0\n"
			"fpu	f10					.32 496 0\n"
			"fpu	f11					.32 500 0\n"
			"fpu	f12					.32 504 0\n"
			"fpu	f13					.32 508 0\n"
			"fpu	f14					.32 512 0\n"
			"fpu	f15					.32 516 0\n"
			"fpu	f16					.32 520 0\n"
			"fpu	f17					.32 524 0\n"
			"fpu	f18					.32 528 0\n"
			"fpu	f19					.32 532 0\n"
			"fpu	f20					.32 536 0\n"
			"fpu	f21					.32 540 0\n"
			"fpu	f22					.32 544 0\n"
			"fpu	f23					.32 548 0\n"
			"fpu	f24					.32 552 0\n"
			"fpu	f25					.32 556 0\n"
			"fpu	f26					.32 560 0\n"
			"fpu	f27					.32 564 0\n"
			"fpu	f28					.32 568 0\n"
			"fpu	f29					.32 572 0\n"
			"fpu	f30					.32 576 0\n"
			"fpu	f31					.32 580 0\n"
			"fpu	f32					.64 584 0\n"
			"fpu	f34					.64 592 0\n"
			"fpu	f36					.64 600 0\n"
			"fpu	f38					.64 608 0\n"
			"fpu	f40					.64 616 0\n"
			"fpu	f42					.64 624 0\n"
			"fpu	f44					.64 632 0\n"
			"fpu	f46					.64 640 0\n"
			"fpu	f48					.64 648 0\n"
			"fpu	f50					.64 656 0\n"
			"fpu	f52					.64 664 0\n"
			"fpu	f54					.64 672 0\n"
			"fpu	f56					.64 680 0\n"
			"fpu	f58					.64 688 0\n"
			"fpu	f60					.64 696 0\n"
			"fpu	f62					.64 704 0\n"
			"gpr	fsr					.64	712	0\n"
			"ctr	gsr					.64 720 0\n"
			"ctr	fprs				.3 728 0\n"
			"ctr	asr0				.64 736 0\n"
			"ctr	asr1				.64 744 0\n"
			"ctr	asr2				.64 752 0\n"
			"ctr	asr3				.64 760 0\n"
			"ctr	asr4				.64 768 0\n"
			"ctr	asr5				.64 776 0\n"
			"ctr	asr6				.64 784 0\n"
			"ctr	asr7				.64 792 0\n"
			"ctr	asr8				.64 800 0\n"
			"ctr	asr9				.64 808 0\n"
			"ctr	asr10				.64 816 0\n"
			"ctr	asr11				.64 824 0\n"
			"ctr	asr12				.64 832 0\n"
			"ctr	asr13				.64 840 0\n"
			"ctr	asr14				.64 848 0\n"
			"ctr	asr15				.64 856 0\n"
			"ctr	asr16				.64 864 0\n"
			"ctr	asr17				.64 872 0\n"
			"ctr	asr18				.64 880 0\n"
			"ctr	asr19				.64 888 0\n"
			"ctr	asr20				.64 896 0\n"
			"ctr	asr21				.64 904 0\n"
			"ctr	asr22				.64 912 0\n"
			"ctr	asr23				.64 920 0\n"
			"ctr	asr24				.64 928 0\n"
			"ctr	asr25				.64 936 0\n"
			"ctr	asr26				.64 944 0\n"
			"ctr	asr27				.64 952 0\n"
			"ctr	asr28				.64 960 0\n"
			"ctr	asr29				.64 968 0\n"
			"ctr	asr30				.64 976 0\n"
			"ctr	asr31				.64 984 0\n";
	} else {
		rz_warn_if_reached();
		return NULL;
	}
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static bool sparc_fini(void *user) {
	RzAnalysisValueSPARC *sparc = (RzAnalysisValueSPARC *)user;
	if (!sparc) {
		return true;
	}
	RzIterator *iter = ht_up_as_iter(sparc->delayed_branch);
	RzSparcDelatedBranchOp **eff;
	rz_iterator_foreach(iter, eff) {
		rz_il_op_effect_free((*eff)->perform_fail_jmp);
		rz_il_op_effect_free((*eff)->perform_jmp);
		rz_il_op_effect_free((*eff)->set_ea);
		free(*eff);
	}
	ht_up_free(sparc->delayed_branch);
	rz_iterator_free(iter);
	if (sparc->handle != 0) {
		cs_close(&sparc->handle);
	}

	RZ_FREE(sparc);
	return true;
}

#if CS_API_MAJOR >= 6
static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
	if (analysis->bits == 64) {
		return rz_sparc_cs_64_il_config(analysis->big_endian);
	}
	return rz_sparc_cs_32_il_config(analysis->big_endian);
}
#endif

RzAnalysisPlugin rz_analysis_plugin_sparc_cs = {
	.name = "sparc",
	.desc = "Capstone SPARC analysis",
	.esil = false,
	.license = "BSD",
	.arch = "sparc",
	.bits = 32 | 64,
	.archinfo = archinfo,
	.op = &analyze_op,
	.init = sparc_init,
	.fini = sparc_fini,
	.get_reg_profile = &get_reg_profile,
#if CS_API_MAJOR >= 6
	.il_config = il_config,
#endif
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_sparc_cs,
	.version = RZ_VERSION
};
#endif
