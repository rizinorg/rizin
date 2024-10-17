// SPDX-FileCopyrightText: 2014-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/systemz.h>
// instruction set: http://www.tachyonsoft.com/inst390m.htm

#if CS_NEXT_VERSION < 6
#define SYSTEMZ(x)    SYSZ_##x
#define SYSTEMZ_ARCH  CS_ARCH_SYSZ
#define cs_systemz    cs_sysz
#define cs_systemz_op cs_sysz_op
#define systemz       sysz
#define INSOP(n)      insn->detail->sysz.operands[n]
#else
#define SYSTEMZ(x)   SYSTEMZ_##x
#define SYSTEMZ_ARCH CS_ARCH_SYSTEMZ
#define INSOP(n)     insn->detail->systemz.operands[n]
#endif

static void opex(RzStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_systemz *x = &insn->detail->systemz;
	for (i = 0; i < x->op_count; i++) {
		cs_systemz_op *op = x->operands + i;
		pj_o(pj);
		switch (op->type) {
		case SYSTEMZ(OP_REG):
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		case SYSTEMZ(OP_IMM):
			pj_ks(pj, "type", "imm");
			pj_kN(pj, "value", op->imm);
			break;
		case SYSTEMZ(OP_MEM):
			pj_ks(pj, "type", "mem");
			if (op->mem.base != SYSTEMZ(REG_INVALID)) {
				pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			}
			pj_kN(pj, "disp", op->mem.disp);
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

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	csh handle;
	cs_insn *insn;
	int mode = CS_MODE_BIG_ENDIAN;
	int ret = cs_open(SYSTEMZ_ARCH, mode, &handle);
	if (ret == CS_ERR_OK) {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
		int n = cs_disasm(handle, (const ut8 *)buf, len, addr, 1, &insn);
		if (n < 1) {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		} else {
			if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
				opex(&op->opex, handle, insn);
			}
			op->size = insn->size;
			switch (insn->id) {
			case SYSTEMZ(INS_BRCL):
			case SYSTEMZ(INS_BRASL):
				op->type = RZ_ANALYSIS_OP_TYPE_CALL;
				break;
			case SYSTEMZ(INS_BR):
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				break;
			case SYSTEMZ(INS_BRC):
			case SYSTEMZ(INS_BER):
			case SYSTEMZ(INS_BHR):
			case SYSTEMZ(INS_BHER):
			case SYSTEMZ(INS_BLR):
			case SYSTEMZ(INS_BLER):
			case SYSTEMZ(INS_BLHR):
			case SYSTEMZ(INS_BNER):
			case SYSTEMZ(INS_BNHR):
			case SYSTEMZ(INS_BNHER):
			case SYSTEMZ(INS_BNLR):
			case SYSTEMZ(INS_BNLER):
			case SYSTEMZ(INS_BNLHR):
			case SYSTEMZ(INS_BNOR):
			case SYSTEMZ(INS_BOR):
			case SYSTEMZ(INS_BASR):
			case SYSTEMZ(INS_BRAS):
			case SYSTEMZ(INS_BRCT):
			case SYSTEMZ(INS_BRCTG):
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				break;
#if CS_NEXT_VERSION < 6
			case SYSTEMZ(INS_JE):
			case SYSTEMZ(INS_JGE):
			case SYSTEMZ(INS_JHE):
			case SYSTEMZ(INS_JGHE):
			case SYSTEMZ(INS_JH):
			case SYSTEMZ(INS_JGH):
			case SYSTEMZ(INS_JLE):
			case SYSTEMZ(INS_JGLE):
			case SYSTEMZ(INS_JLH):
			case SYSTEMZ(INS_JGLH):
			case SYSTEMZ(INS_JL):
			case SYSTEMZ(INS_JGL):
			case SYSTEMZ(INS_JNE):
			case SYSTEMZ(INS_JGNE):
			case SYSTEMZ(INS_JNHE):
			case SYSTEMZ(INS_JGNHE):
			case SYSTEMZ(INS_JNH):
			case SYSTEMZ(INS_JGNH):
			case SYSTEMZ(INS_JNLE):
			case SYSTEMZ(INS_JGNLE):
			case SYSTEMZ(INS_JNLH):
			case SYSTEMZ(INS_JGNLH):
			case SYSTEMZ(INS_JNL):
			case SYSTEMZ(INS_JGNL):
			case SYSTEMZ(INS_JNO):
			case SYSTEMZ(INS_JGNO):
			case SYSTEMZ(INS_JO):
			case SYSTEMZ(INS_JGO):
			case SYSTEMZ(INS_JG):
#else
			case SYSTEMZ(INS_JE):
			case SYSTEMZ(INS_JH):
			case SYSTEMZ(INS_JHE):
			case SYSTEMZ(INS_JL):
			case SYSTEMZ(INS_JLE):
			case SYSTEMZ(INS_JLH):
			case SYSTEMZ(INS_JM):
			case SYSTEMZ(INS_JNE):
			case SYSTEMZ(INS_JNH):
			case SYSTEMZ(INS_JNHE):
			case SYSTEMZ(INS_JNL):
			case SYSTEMZ(INS_JNLE):
			case SYSTEMZ(INS_JNLH):
			case SYSTEMZ(INS_JNM):
			case SYSTEMZ(INS_JNO):
			case SYSTEMZ(INS_JNP):
			case SYSTEMZ(INS_JNZ):
			case SYSTEMZ(INS_JO):
			case SYSTEMZ(INS_JP):
			case SYSTEMZ(INS_JZ):
			case SYSTEMZ(INS_J_G_LU_):
			case SYSTEMZ(INS_J_G_L_E):
			case SYSTEMZ(INS_J_G_L_H):
			case SYSTEMZ(INS_J_G_L_HE):
			case SYSTEMZ(INS_J_G_L_L):
			case SYSTEMZ(INS_J_G_L_LE):
			case SYSTEMZ(INS_J_G_L_LH):
			case SYSTEMZ(INS_J_G_L_M):
			case SYSTEMZ(INS_J_G_L_NE):
			case SYSTEMZ(INS_J_G_L_NH):
			case SYSTEMZ(INS_J_G_L_NHE):
			case SYSTEMZ(INS_J_G_L_NL):
			case SYSTEMZ(INS_J_G_L_NLE):
			case SYSTEMZ(INS_J_G_L_NLH):
			case SYSTEMZ(INS_J_G_L_NM):
			case SYSTEMZ(INS_J_G_L_NO):
			case SYSTEMZ(INS_J_G_L_NP):
			case SYSTEMZ(INS_J_G_L_NZ):
			case SYSTEMZ(INS_J_G_L_O):
			case SYSTEMZ(INS_J_G_L_P):
			case SYSTEMZ(INS_J_G_L_Z):
#endif
				op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
				op->jump = INSOP(0).imm;
				op->fail = addr + op->size;
				break;
			case SYSTEMZ(INS_J):
				op->type = RZ_ANALYSIS_OP_TYPE_JMP;
				op->jump = INSOP(0).imm;
				op->fail = UT64_MAX;
				break;
			}
		}
		cs_free(insn, n);
		cs_close(&handle);
	}
	return op->size;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	r15\n"
		"=LR	r14\n"
		"=SP	r13\n"
		"=BP	r12\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=SN	r0\n"
		"gpr	sb	.32	36	0\n" // r9
		"gpr	sl	.32	40	0\n" // rl0
		"gpr	fp	.32	44	0\n" // r11
		"gpr	ip	.32	48	0\n" // r12
		"gpr	sp	.32	52	0\n" // r13
		"gpr	lr	.32	56	0\n" // r14
		"gpr	pc	.32	60	0\n" // r15

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
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n";
	return rz_str_dup(p);
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_sysz = {
	.name = "sysz",
	.desc = "Capstone SystemZ microanalysis",
	.esil = false,
	.license = "BSD",
	.arch = "sysz",
	.bits = 32 | 64,
	.op = &analyze_op,
	.archinfo = archinfo,
	.get_reg_profile = &get_reg_profile,
};
