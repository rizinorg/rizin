// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>

#include "vax/vax.h"

// Report architecture limits (op size bounds, alignment, pointer support) to the core.
static int vax_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return VAX_MAX_OP_SIZE;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

// Build the VAX register profile (r0-r11, ap, fp, sp, pc, psl and condition flags).
static char *vax_reg_profile(RzAnalysis *a) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	fp\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=R0	r0\n"
		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	ap	.32	48	0\n"
		"gpr	fp	.32	52	0\n"
		"gpr	sp	.32	56	0\n"
		"gpr	pc	.32	60	0\n"
		"gpr	psl	.32	64	0\n"
		"flg	c	.1	512	0\n"
		"flg	v	.1	513	0\n"
		"flg	z	.1	514	0\n"
		"flg	n	.1	515	0\n";
	return rz_str_dup(p);
}

// Map a conditional-branch opcode to its RzTypeCond (RZ_TYPE_COND_AL if none).
static RzTypeCond vax_cond_for(ut16 oc) {
	switch (oc) {
	case VAX_OP_BNEQ: return RZ_TYPE_COND_NE;
	case VAX_OP_BEQL: return RZ_TYPE_COND_EQ;
	case VAX_OP_BGTR: return RZ_TYPE_COND_GT;
	case VAX_OP_BLEQ: return RZ_TYPE_COND_LE;
	case VAX_OP_BGEQ: return RZ_TYPE_COND_GE;
	case VAX_OP_BLSS: return RZ_TYPE_COND_LT;
	case VAX_OP_BGTRU: return RZ_TYPE_COND_HI;
	case VAX_OP_BLEQU: return RZ_TYPE_COND_LS;
	case VAX_OP_BVC: return RZ_TYPE_COND_VC;
	case VAX_OP_BVS: return RZ_TYPE_COND_VS;
	case VAX_OP_BGEQU: return RZ_TYPE_COND_HS; // bcc
	case VAX_OP_BLSSU: return RZ_TYPE_COND_LO; // bcs
	default: return RZ_TYPE_COND_AL;
	}
}

// Classify a data-manipulation instruction by mnemonic prefix.
static void vax_classify_data(RzAnalysisOp *op, const VaxInst *inst) {
	static const struct {
		const char *pfx;
		ut32 type;
	} map[] = {
		{ "mova", RZ_ANALYSIS_OP_TYPE_LEA },
		{ "pusha", RZ_ANALYSIS_OP_TYPE_PUSH },
		{ "pushr", RZ_ANALYSIS_OP_TYPE_PUSH },
		{ "pushl", RZ_ANALYSIS_OP_TYPE_PUSH },
		{ "popr", RZ_ANALYSIS_OP_TYPE_POP },
		{ "movz", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "movpsl", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "mov", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "clr", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "cvt", RZ_ANALYSIS_OP_TYPE_CAST },
		{ "adwc", RZ_ANALYSIS_OP_TYPE_ADD },
		{ "add", RZ_ANALYSIS_OP_TYPE_ADD },
		{ "inc", RZ_ANALYSIS_OP_TYPE_ADD },
		{ "sbwc", RZ_ANALYSIS_OP_TYPE_SUB },
		{ "sub", RZ_ANALYSIS_OP_TYPE_SUB },
		{ "dec", RZ_ANALYSIS_OP_TYPE_SUB },
		{ "mneg", RZ_ANALYSIS_OP_TYPE_SUB },
		{ "emul", RZ_ANALYSIS_OP_TYPE_MUL },
		{ "mul", RZ_ANALYSIS_OP_TYPE_MUL },
		{ "ediv", RZ_ANALYSIS_OP_TYPE_DIV },
		{ "div", RZ_ANALYSIS_OP_TYPE_DIV },
		{ "bispsw", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "bicpsw", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "bis", RZ_ANALYSIS_OP_TYPE_OR },
		{ "bic", RZ_ANALYSIS_OP_TYPE_AND },
		{ "xor", RZ_ANALYSIS_OP_TYPE_XOR },
		{ "mcom", RZ_ANALYSIS_OP_TYPE_NOT },
		{ "cmp", RZ_ANALYSIS_OP_TYPE_CMP },
		{ "tst", RZ_ANALYSIS_OP_TYPE_CMP },
		{ "bit", RZ_ANALYSIS_OP_TYPE_CMP },
		{ "ash", RZ_ANALYSIS_OP_TYPE_SHL },
		{ "rotl", RZ_ANALYSIS_OP_TYPE_ROL },
		{ "editpc", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "ext", RZ_ANALYSIS_OP_TYPE_MOV },
		{ "insv", RZ_ANALYSIS_OP_TYPE_MOV },
		{ NULL, 0 },
	};
	const char *n = inst->name;
	if (!n) {
		return;
	}
	for (int i = 0; map[i].pfx; i++) {
		if (!strncmp(n, map[i].pfx, strlen(map[i].pfx))) {
			op->type = map[i].type;
			return;
		}
	}
}

/**
 * \brief Set op type, family, condition, stack effect and control-flow targets.
 * \param a the RzAnalysis instance
 * \param op the analysis op to populate
 * \param inst the decoded instruction
 * \param addr the instruction address (used to compute fall-through targets)
 */
static void vax_set_type(RzAnalysis *a, RzAnalysisOp *op, const VaxInst *inst, ut64 addr) {
	ut16 oc = inst->opcode;
	int sz = inst->size;
	ut8 b0 = (ut8)(oc & 0xff);
	op->type = RZ_ANALYSIS_OP_TYPE_UNK;
	op->family = RZ_ANALYSIS_OP_FAMILY_CPU;

	switch (oc) {
	case VAX_OP_HALT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->eob = true;
		return;
	case VAX_OP_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		return;
	case VAX_OP_BPT:
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		op->eob = true;
		return;
	case VAX_OP_REI:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		op->eob = true;
		return;
	case VAX_OP_RET:
	case VAX_OP_RSB:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->eob = true;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4;
		return;
	case VAX_OP_LDPCTX:
	case VAX_OP_SVPCTX:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		return;
	case VAX_OP_BSBB:
	case VAX_OP_BSBW:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = inst->ops[0].target;
		op->fail = addr + sz;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		return;
	case VAX_OP_BRB:
	case VAX_OP_BRW:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = inst->ops[0].target;
		op->eob = true;
		return;
	case VAX_OP_JSB:
		if (inst->ops[0].has_target) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = inst->ops[0].target;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		}
		op->fail = addr + sz;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		return;
	case VAX_OP_JMP:
		if (inst->ops[0].has_target) {
			op->type = RZ_ANALYSIS_OP_TYPE_JMP;
			op->jump = inst->ops[0].target;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		}
		op->eob = true;
		return;
	case VAX_OP_BNEQ:
	case VAX_OP_BEQL:
	case VAX_OP_BGTR:
	case VAX_OP_BLEQ:
	case VAX_OP_BGEQ:
	case VAX_OP_BLSS:
	case VAX_OP_BGTRU:
	case VAX_OP_BLEQU:
	case VAX_OP_BVC:
	case VAX_OP_BVS:
	case VAX_OP_BGEQU:
	case VAX_OP_BLSSU:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = inst->ops[0].target;
		op->fail = addr + sz;
		op->cond = vax_cond_for(oc);
		return;
	case VAX_OP_BBS:
	case VAX_OP_BBC:
	case VAX_OP_BBSS:
	case VAX_OP_BBCS:
	case VAX_OP_BBSC:
	case VAX_OP_BBCC:
	case VAX_OP_BBSSI:
	case VAX_OP_BBCCI:
	case VAX_OP_BLBS:
	case VAX_OP_BLBC:
	case VAX_OP_AOBLSS:
	case VAX_OP_AOBLEQ:
	case VAX_OP_SOBGEQ:
	case VAX_OP_SOBGTR:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (inst->n_ops > 0) {
			op->jump = inst->ops[inst->n_ops - 1].target;
		}
		op->fail = addr + sz;
		return;
	case VAX_OP_ACBW:
	case VAX_OP_ACBB:
	case VAX_OP_ACBL:
	case VAX_OP_ACBF:
	case VAX_OP_ACBD:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (inst->n_ops > 0) {
			op->jump = inst->ops[inst->n_ops - 1].target;
		}
		op->fail = addr + sz;
		if (oc == VAX_OP_ACBF || oc == VAX_OP_ACBD) {
			op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		}
		return;
	case VAX_OP_CASEB:
	case VAX_OP_CASEW:
	case VAX_OP_CASEL:
		op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		op->eob = true;
		return;
	case VAX_OP_CALLG:
	case VAX_OP_CALLS:
		if (inst->n_ops > 0 && inst->ops[inst->n_ops - 1].has_target) {
			op->type = RZ_ANALYSIS_OP_TYPE_CALL;
			op->jump = inst->ops[inst->n_ops - 1].target;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		}
		op->fail = addr + sz;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		return;
	case VAX_OP_CHMK:
	case VAX_OP_CHME:
	case VAX_OP_CHMS:
	case VAX_OP_CHMU:
	case VAX_OP_XFC:
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		return;
	case VAX_OP_MTPR:
	case VAX_OP_MFPR:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		return;
	case VAX_OP_PROBER:
	case VAX_OP_PROBEW:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
		return;
	default:
		break;
	}

	if ((b0 >= VAX_OP_ADDF2 && b0 <= VAX_OP_CVTFD) ||
		(b0 >= VAX_OP_ADDD2 && b0 <= VAX_OP_CVTDF) || oc >= 0xfd00) {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
	}
	vax_classify_data(op, inst);

	/* push of a longword / address adjusts SP by one longword */
	switch (b0) {
	case VAX_OP_PUSHL:
	case VAX_OP_PUSHAB:
	case VAX_OP_PUSHAW:
	case VAX_OP_PUSHAL:
	case VAX_OP_PUSHAQ: // and pushao on the FD page
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	default:
		break;
	}

	switch (op->type) {
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_CMP:
		op->sign = true;
		break;
	default:
		break;
	}
}

/**
 * \brief Translate a decoded operand into an RzAnalysisValue.
 * \param a the RzAnalysis instance (for register lookups)
 * \param o the decoded operand
 * \param acc the access flags to record on the value
 * \return a newly allocated RzAnalysisValue, or NULL on allocation failure
 */
static RzAnalysisValue *vax_make_value(RzAnalysis *a, const VaxOperand *o, RzAnalysisValueAccess acc) {
	RzAnalysisValue *v = rz_analysis_value_new();
	if (!v) {
		return NULL;
	}
	v->access = acc;
	switch (o->mode) {
	case VAX_AM_LITERAL:
		v->type = RZ_ANALYSIS_VAL_IMM;
		v->imm = o->disp & 0x3f;
		break;
	case VAX_AM_IMMEDIATE:
		v->type = RZ_ANALYSIS_VAL_IMM;
		v->imm = (st64)o->imm;
		break;
	case VAX_AM_REG:
		v->type = RZ_ANALYSIS_VAL_REG;
		v->reg = rz_reg_get(a->reg, rz_vax_reg_name(o->reg), RZ_REG_TYPE_ANY);
		break;
	case VAX_AM_REGDEF:
	case VAX_AM_AUTODEC:
	case VAX_AM_AUTOINC:
	case VAX_AM_AUTOINCDEF:
		v->type = RZ_ANALYSIS_VAL_MEM;
		v->reg = rz_reg_get(a->reg, rz_vax_reg_name(o->reg), RZ_REG_TYPE_ANY);
		v->memref = rz_vax_dt_size(o->dt);
		break;
	case VAX_AM_BYTEDISP:
	case VAX_AM_BYTEDISPDEF:
	case VAX_AM_WORDDISP:
	case VAX_AM_WORDDISPDEF:
	case VAX_AM_LONGDISP:
	case VAX_AM_LONGDISPDEF:
		v->type = RZ_ANALYSIS_VAL_MEM;
		v->reg = rz_reg_get(a->reg, rz_vax_reg_name(o->reg), RZ_REG_TYPE_ANY);
		v->delta = o->disp;
		v->memref = rz_vax_dt_size(o->dt);
		break;
	case VAX_AM_ABSOLUTE:
	case VAX_AM_BYTEREL:
	case VAX_AM_BYTERELDEF:
	case VAX_AM_WORDREL:
	case VAX_AM_WORDRELDEF:
	case VAX_AM_LONGREL:
	case VAX_AM_LONGRELDEF:
		v->type = RZ_ANALYSIS_VAL_MEM;
		v->base = o->target;
		v->memref = rz_vax_dt_size(o->dt);
		break;
	default:
		v->type = RZ_ANALYSIS_VAL_UNK;
		break;
	}
	if (o->indexed) {
		v->regdelta = rz_reg_get(a->reg, rz_vax_reg_name(o->index_reg), RZ_REG_TYPE_ANY);
		v->mul = rz_vax_dt_size(o->dt);
	}
	return v;
}

/**
 * \brief Populate op->src[]/op->dst and the val/ptr/disp scalar hints.
 * \param a the RzAnalysis instance
 * \param op the analysis op to populate
 * \param inst the decoded instruction
 */
static void vax_fill_vals(RzAnalysis *a, RzAnalysisOp *op, const VaxInst *inst) {
	int srci = 0;
	bool have_val = false;
	bool have_ptr = false;
	for (int i = 0; i < inst->n_ops; i++) {
		const VaxOperand *o = &inst->ops[i];
		if (o->access == VAX_AC_B) {
			continue;
		}
		if (!have_val && (o->mode == VAX_AM_LITERAL || o->mode == VAX_AM_IMMEDIATE)) {
			op->val = (o->mode == VAX_AM_LITERAL) ? (ut64)(o->disp & 0x3f) : o->imm;
			have_val = true;
		}
		if (!have_ptr && o->has_target) {
			op->ptr = (st64)o->target;
			op->refptr = rz_vax_dt_size(o->dt);
			have_ptr = true;
		}
		if (!have_ptr && (o->mode == VAX_AM_BYTEDISP || o->mode == VAX_AM_WORDDISP || o->mode == VAX_AM_LONGDISP)) {
			op->disp = o->disp;
		}
		bool is_read = (o->access == VAX_AC_R || o->access == VAX_AC_M || o->access == VAX_AC_A || o->access == VAX_AC_V);
		bool is_write = (o->access == VAX_AC_W || o->access == VAX_AC_M);
		if (is_write && !op->dst) {
			op->dst = vax_make_value(a, o, is_read ? (RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W) : RZ_ANALYSIS_ACC_W);
			if (o->mode == VAX_AM_REG) {
				op->reg = rz_vax_reg_name(o->reg);
			}
		} else if (is_read && srci < 8) {
			op->src[srci++] = vax_make_value(a, o, RZ_ANALYSIS_ACC_R);
		}
	}
}

/**
 * \brief Build the RzAnalysisOp->opex structured operand description.
 * \param inst the decoded instruction
 * \return a newly allocated RzStructuredData tree, or NULL on failure
 */
static RzStructuredData *vax_opex(const VaxInst *inst) {
	RzStructuredData *root = rz_structured_data_new_map();
	if (!root) {
		return NULL;
	}
	RzStructuredData *opex = rz_structured_data_map_add_map(root, "opex");
	if (!opex) {
		rz_structured_data_free(root);
		return NULL;
	}
	rz_structured_data_map_add_string(opex, "mnemonic", inst->name ? inst->name : "invalid");
	RzStructuredData *operands = rz_structured_data_map_add_array(opex, "operands");
	if (!operands) {
		return root;
	}
	for (int i = 0; i < inst->n_ops; i++) {
		const VaxOperand *o = &inst->ops[i];
		RzStructuredData *od = rz_structured_data_array_add_map(operands);
		if (!od) {
			continue;
		}
		switch (o->mode) {
		case VAX_AM_LITERAL:
			rz_structured_data_map_add_string(od, "type", "imm");
			rz_structured_data_map_add_signed(od, "value", o->disp & 0x3f);
			break;
		case VAX_AM_IMMEDIATE:
			rz_structured_data_map_add_string(od, "type", "imm");
			rz_structured_data_map_add_signed(od, "value", (st64)o->imm);
			break;
		case VAX_AM_BRANCH:
			rz_structured_data_map_add_string(od, "type", "imm");
			rz_structured_data_map_add_unsigned(od, "value", o->target, true);
			break;
		case VAX_AM_REG:
			rz_structured_data_map_add_string(od, "type", "reg");
			rz_structured_data_map_add_string(od, "value", rz_vax_reg_name(o->reg));
			break;
		case VAX_AM_REGDEF:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_string(od, "base", rz_vax_reg_name(o->reg));
			break;
		case VAX_AM_AUTODEC:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_string(od, "base", rz_vax_reg_name(o->reg));
			rz_structured_data_map_add_boolean(od, "autodecrement", true);
			break;
		case VAX_AM_AUTOINC:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_string(od, "base", rz_vax_reg_name(o->reg));
			rz_structured_data_map_add_boolean(od, "autoincrement", true);
			break;
		case VAX_AM_AUTOINCDEF:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_string(od, "base", rz_vax_reg_name(o->reg));
			rz_structured_data_map_add_boolean(od, "autoincrement", true);
			rz_structured_data_map_add_boolean(od, "deferred", true);
			break;
		case VAX_AM_BYTEDISP:
		case VAX_AM_WORDDISP:
		case VAX_AM_LONGDISP:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_string(od, "base", rz_vax_reg_name(o->reg));
			rz_structured_data_map_add_signed(od, "disp", o->disp);
			break;
		case VAX_AM_BYTEDISPDEF:
		case VAX_AM_WORDDISPDEF:
		case VAX_AM_LONGDISPDEF:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_string(od, "base", rz_vax_reg_name(o->reg));
			rz_structured_data_map_add_signed(od, "disp", o->disp);
			rz_structured_data_map_add_boolean(od, "deferred", true);
			break;
		case VAX_AM_ABSOLUTE:
		case VAX_AM_BYTEREL:
		case VAX_AM_WORDREL:
		case VAX_AM_LONGREL:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_unsigned(od, "target", o->target, true);
			break;
		case VAX_AM_BYTERELDEF:
		case VAX_AM_WORDRELDEF:
		case VAX_AM_LONGRELDEF:
			rz_structured_data_map_add_string(od, "type", "mem");
			rz_structured_data_map_add_unsigned(od, "target", o->target, true);
			rz_structured_data_map_add_boolean(od, "deferred", true);
			break;
		default:
			rz_structured_data_map_add_string(od, "type", "invalid");
			break;
		}
		if (o->indexed) {
			rz_structured_data_map_add_string(od, "index", rz_vax_reg_name(o->index_reg));
		}
	}
	return root;
}

/**
 * \brief Analyze a single VAX instruction (the RzAnalysisPlugin op callback).
 * \param a the RzAnalysis instance
 * \param op the analysis op to fill
 * \param addr the instruction address
 * \param buf the instruction bytes
 * \param len number of valid bytes in \p buf
 * \param mask which RzAnalysisOp fields are requested
 * \return the instruction length in bytes, or -1 on failure
 */
static int vax_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	if (!a || !op || !buf || len < 1) {
		return -1;
	}
	VaxInst inst;
	int size = rz_vax_decode(&inst, buf, len, addr);
	op->addr = addr;
	if (size < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		op->size = 1;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		return op->size;
	}
	op->size = size;
	op->id = inst.opcode;
	op->nopcode = (inst.opcode >= 0xfd00) ? 2 : 1;

	if (!inst.name) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		return op->size;
	}

	vax_set_type(a, op, &inst, addr);

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		rz_vax_format(&inst, &sb);
		op->mnemonic = rz_strbuf_drain_nofree(&sb);
		rz_strbuf_fini(&sb);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		vax_fill_vals(a, op, &inst);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = vax_opex(&inst);
	}

	return op->size;
}

RzAnalysisPlugin rz_analysis_plugin_vax = {
	.name = "vax",
	.desc = "DEC VAX-11 code analysis plugin",
	.license = "LGPL3",
	.arch = "vax",
	.bits = 32,
	.esil = false,
	.archinfo = vax_archinfo,
	.get_reg_profile = vax_reg_profile,
	.op = vax_op,
};
