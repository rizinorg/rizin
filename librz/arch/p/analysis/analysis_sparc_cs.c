// SPDX-FileCopyrightText: 2014-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/sparc.h>

#define INSDETAIL() insn->detail->sparc
#define INSOP(n)    insn->detail->sparc.operands[n]
#if CS_API_MAJOR >= 6
#define INSCC_NORM() (insn->detail->sparc.cc & ~(SPARC_CC_FCC_BEGIN | SPARC_CC_CPCC_BEGIN | SPARC_CC_REG_BEGIN))
#else
#define INSCC_NORM() (insn->detail->sparc.cc)
#endif
#define INSCC_RAW() (insn->detail->sparc.cc)
#define INSHINT()   (insn->detail->sparc.hint)

#define IN_64BIT_MODE   ((mode & CS_MODE_64) == CS_MODE_64)
#define SPARC_ARCH_BITS (IN_64BIT_MODE ? 64 : 32)

#define SPARC_INSN_SIZE 4

#define SPARC_BYTE          (8 * 1)
#define SPARC_HALF_WORD     (8 * 2)
#define SPARC_WORD          (8 * 4)
#define SPARC_DOUBLE_WORD   (8 * 8)
#define SPARC_EXTENDED_WORD (8 * 8)
#define SPARC_QUAD_WORD     (8 * 16)

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_sparc *x = &insn->detail->sparc;
	for (i = 0; i < x->op_count; i++) {
		cs_sparc_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case SPARC_OP_REG:
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case SPARC_OP_IMM:
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", op->imm);
			break;
		case SPARC_OP_MEM:
			pj_ks(pj, "type", "mem");
			if (op->mem.base != SPARC_REG_INVALID) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_ki(pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks(pj, "type", "invalid");
			break;
		}
		pj_end(pj); /* o operand */
	}
	pj_end(pj); /* a operands */
	pj_end(pj);

	rz_strbuf_init(buf);
	rz_strbuf_append(buf, pj_string(pj));
	pj_free(pj);
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

typedef struct {
	RzRegItem *reg;
	csh handle;
	int omode;
} RzAnalysisValueSPARC;

static bool sparc_init(void **user) {
	RzAnalysisValueSPARC *sparc = RZ_NEW0(RzAnalysisValueSPARC);
	rz_return_val_if_fail(sparc, false);
	sparc->handle = 0;
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
		cs_free(insn, n);
		return 0;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		opex(&op->opex, sparc->handle, insn);
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
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	fp\n"
		"=A0	i0\n"
		"=A1	i1\n"
		"=A2	i2\n"
		"=A3	i3\n"
		"=A4	i4\n"
		"=A5	i5\n"
		"=R0	i7\n"
		"gpr	psr	.32	0	0\n"
		"gpr	pc	.32	4	0\n"
		"gpr	npc	.32	8	0\n"
		"gpr	y	.32	12	0\n"
		/* r0-r7 are global aka g0-g7 */
		"gpr	g0	.32	16	0\n"
		"gpr	g1	.32	20	0\n"
		"gpr	g2	.32	24	0\n"
		"gpr	g3	.32	28	0\n"
		"gpr	g4	.32	32	0\n"
		"gpr	g5	.32	36	0\n"
		"gpr	g6	.32	40	0\n"
		"gpr	g7	.32	44	0\n"
		/* r8-15 are out (o0-o7) */
		"gpr	o0	.32	48	0\n"
		"gpr	o1	.32	52	0\n"
		"gpr	o2	.32	56	0\n"
		"gpr	o3	.32	60	0\n"
		"gpr	o4	.32	64	0\n"
		"gpr	o5	.32	68	0\n"
		"gpr	o6	.32	72	0\n"
		"gpr	sp	.32	72	0\n"
		"gpr	o7	.32	76	0\n"
		/* r16-23 are local (l0-l7) */
		"gpr	l0	.32	80	0\n"
		"gpr	l1	.32	84	0\n"
		"gpr	l2	.32	88	0\n"
		"gpr	l3	.32	92	0\n"
		"gpr	l4	.32	96	0\n"
		"gpr	l5	.32	100	0\n"
		"gpr	l6	.32	104	0\n"
		"gpr	l7	.32	108	0\n"
		/* r24-31 are in (i0-i7) */
		"gpr	i0	.32	112	0\n"
		"gpr	i1	.32	116	0\n"
		"gpr	i2	.32	120	0\n"
		"gpr	i3	.32	124	0\n"
		"gpr	i4	.32	128	0\n"
		"gpr	i5	.32	132	0\n"
		"gpr	i6	.32	136	0\n"
		"gpr	fp	.32	136	0\n"
		"gpr	i7	.32	140	0\n";
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
	if (sparc) {
		RZ_FREE(sparc);
	}
	return true;
}

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
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_sparc_cs,
	.version = RZ_VERSION
};
#endif
