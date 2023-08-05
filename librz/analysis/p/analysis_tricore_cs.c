// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <capstone/capstone.h>
#include <capstone/tricore.h>

#include "../../asm/arch/tricore/tricore.inc"

#define TRICORE_REG_SP TRICORE_REG_A10

static char *get_reg_profile(RzAnalysis *_) {
	const char *p =
		"=PC	pc\n"
		"=SP	a10\n"
		"=A0	a0\n"
		"gpr	p0	.64	0	0\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	p2	.64	8	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	12	0\n"
		"gpr	p4	.64	16	0\n"
		"gpr	a4	.32	16	0\n"
		"gpr	a5	.32	20	0\n"
		"gpr	p6	.64	24	0\n"
		"gpr	a6	.32	24	0\n"
		"gpr	a7	.32	28	0\n"
		"gpr	p8	.64	32	0\n"
		"gpr	a8	.32	32	0\n"
		"gpr	a9	.32	36	0\n"
		"gpr	p10	.64	40	0\n"
		"gpr	a10	.32	40	0\n"
		"gpr	a11	.32	44	0\n"
		"gpr	p12	.64	48	0\n"
		"gpr	a12	.32	48	0\n"
		"gpr	a13	.32	52	0\n"
		"gpr	p14	.64	56	0\n"
		"gpr	a14	.32	56	0\n"
		"gpr	a15	.32	60	0\n"
		"gpr	e0	.64	64	0\n"
		"gpr	d0	.32	64	0\n"
		"gpr	d1	.32	68	0\n"
		"gpr	e2	.64	72	0\n"
		"gpr	d2	.32	72	0\n"
		"gpr	d3	.32	76	0\n"
		"gpr	e4	.64	80	0\n"
		"gpr	d4	.32	80	0\n"
		"gpr	d5	.32	84	0\n"
		"gpr	e6	.64	88	0\n"
		"gpr	d6	.32	88	0\n"
		"gpr	d7	.32	92	0\n"
		"gpr	e8	.64	96	0\n"
		"gpr	d8	.32	96	0\n"
		"gpr	d9	.32	100	0\n"
		"gpr	e10	.64	104	0\n"
		"gpr	d10	.32	104	0\n"
		"gpr	d11	.32	108	0\n"
		"gpr	e12	.64	112	0\n"
		"gpr	d12	.32	112	0\n"
		"gpr	d13	.32	116	0\n"
		"gpr	e14	.64	120	0\n"
		"gpr	d14	.32	120	0\n"
		"gpr	d15	.32	124	0\n"
		"gpr	PSW	.32	128	0\n"
		"gpr	PCXI	.32	132	0\n"
		"gpr	FCX	.32	136	0\n"
		"gpr	LCX	.32	140	0\n"
		"gpr	ISP	.32	144	0\n"
		"gpr	ICR	.32	148	0\n"
		"gpr	PIPN	.32	152	0\n"
		"gpr	BIV	.32	156	0\n"
		"gpr	BTV	.32	160	0\n"
		"gpr	pc	.32	164	0\n";
	return strdup(p);
}

static void tricore_opex(RzStrBuf *ptr, csh handle, cs_insn *p_insn);

static void rz_analysis_tricore_fillval(RzAnalysis *, RzAnalysisOp *, csh, cs_insn *);

static RzAnalysisLiftedILOp rz_analysis_tricore_il_op();

static void tricore_op_set_type(RzAnalysisOp *op, csh h, cs_insn *insn);

static int
rz_analysis_tricore_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!(a && op && data && len > 0)) {
		return 0;
	}
	if (a->big_endian) {
		return -1;
	}

	csh handle = tricore_setup_cs_handle(a->cpu, NULL);
	if (handle == 0) {
		return -1;
	}

	op->size = 2;
	cs_insn *insn = NULL;
	ut32 count = cs_disasm(handle, (const ut8 *)data, len, addr, 1, &insn);
	if (count <= 0) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
		}
		return op->size;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	}

	op->size = insn->size;
	op->id = (int)insn->id;
	op->addr = insn->address;
	tricore_op_set_type(op, handle, insn);

	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		tricore_opex(&op->opex, handle, insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		rz_analysis_tricore_fillval(a, op, handle, insn);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = rz_analysis_tricore_il_op();
	}

	cs_free(insn, count);
	return op->size;
}

static inline RzTypeCond insn2cond(unsigned int insn) {
	switch (insn) {
	case TRICORE_INS_JEQ:
	case TRICORE_INS_JEQ_A:
		return RZ_TYPE_COND_EQ;
	case TRICORE_INS_JNE:
		return RZ_TYPE_COND_NE;
	case TRICORE_INS_JGE:
	case TRICORE_INS_JGEZ:
	case TRICORE_INS_JGE_U:
		return RZ_TYPE_COND_GE;
	case TRICORE_INS_JGTZ:
		return RZ_TYPE_COND_GT;
	case TRICORE_INS_JLEZ:
		return RZ_TYPE_COND_LE;
	case TRICORE_INS_JLTZ:
	case TRICORE_INS_JLT_U:
	case TRICORE_INS_JLT:
		return RZ_TYPE_COND_LT;
	case TRICORE_INS_JNED:
	case TRICORE_INS_JNEI:
	case TRICORE_INS_JNE_A:
	case TRICORE_INS_JNZ_A:
	case TRICORE_INS_JNZ_T:
	case TRICORE_INS_JNZ:
		// Jump if Not Equal to Zero
		return RZ_TYPE_COND_NE;
	case TRICORE_INS_JZ_A:
	case TRICORE_INS_JZ_T:
	case TRICORE_INS_JZ:
		// Jump if Zero
		return RZ_TYPE_COND_EQ;
	default: return RZ_TYPE_COND_AL;
	}
	return RZ_TYPE_COND_AL;
}

static inline bool is_inst_privileged(unsigned int insn) {
	switch (insn) {
	/// Kernel (Supervisor)
	case TRICORE_INS_BISR:
	case TRICORE_INS_MTCR:
	case TRICORE_INS_CACHEI_I:
	case TRICORE_INS_CACHEA_I:
	case TRICORE_INS_RFM:
	/// User-1 Mode
	case TRICORE_INS_ENABLE:
	case TRICORE_INS_DISABLE:
	case TRICORE_INS_RESTORE:
		return true;
	/// User-0 Mode
	default: return false;
	}
}

static inline bool is_inst_packed(unsigned int insn) {
	switch (insn) {
	/// ABS
	case TRICORE_INS_ABS_B:
	case TRICORE_INS_ABS_H:
	case TRICORE_INS_ABSDIF_B:
	case TRICORE_INS_ABSDIF_H:
	case TRICORE_INS_ABSDIFS_H:
	case TRICORE_INS_ABSS_H:
	/// ADD
	case TRICORE_INS_ADD_B:
	case TRICORE_INS_ADD_H:
	case TRICORE_INS_ADDS_H:
	case TRICORE_INS_ADDS_HU:
	/// CL?
	case TRICORE_INS_CLO_H:
	case TRICORE_INS_CLS_H:
	case TRICORE_INS_CLZ_H:
	case TRICORE_INS_CLO_B:
	case TRICORE_INS_CLS_B:
	case TRICORE_INS_CLZ_B:
	/// EQ
	case TRICORE_INS_EQ_B:
	case TRICORE_INS_EQ_W:
	case TRICORE_INS_EQ_H:
	/// LT
	case TRICORE_INS_LT_B:
	case TRICORE_INS_LT_BU:
	case TRICORE_INS_LT_H:
	case TRICORE_INS_LT_HU:
	case TRICORE_INS_LT_W:
	case TRICORE_INS_LT_WU:
	/// MADD
	case TRICORE_INS_MADD_H:
	case TRICORE_INS_MADDS_H:
	case TRICORE_INS_MADD_Q:
	case TRICORE_INS_MADDS_Q:
	case TRICORE_INS_MADDM_H:
	case TRICORE_INS_MADDMS_H:
	case TRICORE_INS_MADDR_H:
	case TRICORE_INS_MADDRS_H:
	case TRICORE_INS_MADDR_Q:
	case TRICORE_INS_MADDRS_Q:
	case TRICORE_INS_MADDSU_H:
	case TRICORE_INS_MADDSUS_H:
	case TRICORE_INS_MADDSUM_H:
	case TRICORE_INS_MADDSUMS_H:
	case TRICORE_INS_MADDSUR_H:
	case TRICORE_INS_MADDSURS_H:
	/// MAX
	case TRICORE_INS_MAX_B:
	case TRICORE_INS_MAX_BU:
	case TRICORE_INS_MAX_H:
	case TRICORE_INS_MAX_HU:
	/// MIN
	case TRICORE_INS_MIN_B:
	case TRICORE_INS_MIN_BU:
	case TRICORE_INS_MIN_H:
	case TRICORE_INS_MIN_HU:
	/// MSUB
	case TRICORE_INS_MSUB_H:
	case TRICORE_INS_MSUBS_H:
	case TRICORE_INS_MSUBAD_H:
	case TRICORE_INS_MSUBADS_H:
	case TRICORE_INS_MSUBADM_H:
	case TRICORE_INS_MSUBADMS_H:
	case TRICORE_INS_MSUBADR_H:
	case TRICORE_INS_MSUBADRS_H:
	case TRICORE_INS_MSUBM_H:
	case TRICORE_INS_MSUBMS_H:
	case TRICORE_INS_MSUBR_H:
	case TRICORE_INS_MSUBRS_H:
	/// MUL
	case TRICORE_INS_MUL_H:
	case TRICORE_INS_MULM_H:
	case TRICORE_INS_MULR_H:
	/// SH
	case TRICORE_INS_SH_H:
	case TRICORE_INS_SHA_B:
	case TRICORE_INS_SHA_H:
	/// SUB
	case TRICORE_INS_SUB_B:
	case TRICORE_INS_SUB_H:
		return true;
	default: return false;
	}
}

static void tricore_op_set_type(RzAnalysisOp *op, csh h, cs_insn *insn) {
	if (is_inst_privileged(insn->id)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (is_inst_packed(insn->id)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
	}

	switch (insn->id) {
	default: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_FCALLI: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->reg = tricore_get_op_regname(h, insn, 0);
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	}
	case TRICORE_INS_FCALLA:
	case TRICORE_INS_FCALL: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ut32)tricore_get_op_imm(insn, 0);
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	}
	case TRICORE_INS_FRET: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = 4;
		break;
	}
	case TRICORE_INS_FTOHP:
	case TRICORE_INS_FTOIZ:
	case TRICORE_INS_FTOI:
	case TRICORE_INS_FTOQ31Z:
	case TRICORE_INS_FTOQ31:
	case TRICORE_INS_FTOUZ:
	case TRICORE_INS_FTOU:

	case TRICORE_INS_HPTOF:
	case TRICORE_INS_ITOF:
	case TRICORE_INS_Q31TOF:
	case TRICORE_INS_UTOF: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	}
	case TRICORE_INS_CMP_F: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	}
	case TRICORE_INS_DIV_F: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	}
	case TRICORE_INS_ADD_F:
	case TRICORE_INS_MADD_F: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	}
	case TRICORE_INS_MSUB_F:
	case TRICORE_INS_SUB_F: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	}
	case TRICORE_INS_MUL_F: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	}
	case TRICORE_INS_QSEED_F:
	case TRICORE_INS_UPDFL:
	case TRICORE_INS_UNPACK:
	case TRICORE_INS_PACK: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_ABSDIFS_B:
	case TRICORE_INS_ABSDIFS_H:
	case TRICORE_INS_ABSDIFS:
	case TRICORE_INS_ABSDIF_B:
	case TRICORE_INS_ABSDIF_H:
	case TRICORE_INS_ABSDIF:
	case TRICORE_INS_ABSS_B:
	case TRICORE_INS_ABSS_H:
	case TRICORE_INS_ABSS:
	case TRICORE_INS_ABS_B:
	case TRICORE_INS_ABS_H:
	case TRICORE_INS_ABS: {
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		break;
	}
	case TRICORE_INS_ADDC:
	case TRICORE_INS_ADDIH_A:
	case TRICORE_INS_ADDIH:
	case TRICORE_INS_ADDI:
	case TRICORE_INS_ADDSC_AT:
	case TRICORE_INS_ADDSC_A:
	case TRICORE_INS_ADDS_B:
	case TRICORE_INS_ADDS_H:
	case TRICORE_INS_ADDS:
	case TRICORE_INS_ADDX:
	case TRICORE_INS_ADD_A:
	case TRICORE_INS_ADD_B:
	case TRICORE_INS_ADD_H:
	case TRICORE_INS_ADD:
	case TRICORE_INS_CADDN_A:
	case TRICORE_INS_CADDN:
	case TRICORE_INS_CADD_A:
	case TRICORE_INS_CADD:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_ADDS_HU:
	case TRICORE_INS_ADDS_BU:
	case TRICORE_INS_ADDS_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (insn->detail->tricore.op_count == 2) {
			cs_tricore_op *op1 = tricore_get_op(insn, 1);
			if (op1->type == TRICORE_OP_IMM) {
				op->val = op1->imm;
			}
		}
		break;
	}
	case TRICORE_INS_AND_LT:
	case TRICORE_INS_AND_GE:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_ANDN_T:
	case TRICORE_INS_ANDN:
	case TRICORE_INS_AND_ANDN_T:
	case TRICORE_INS_AND_AND_T:
	case TRICORE_INS_AND_EQ:
	case TRICORE_INS_AND_GE_U:
	case TRICORE_INS_AND_LT_U:
	case TRICORE_INS_AND_NE:
	case TRICORE_INS_AND_NOR_T:
	case TRICORE_INS_AND_OR_T:
	case TRICORE_INS_AND_T:
	case TRICORE_INS_AND: {
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	}
	case TRICORE_INS_BISR:
	case TRICORE_INS_SYSCALL:
	case TRICORE_INS_DISABLE:
	case TRICORE_INS_ENABLE:
	case TRICORE_INS_SVLCX:
	case TRICORE_INS_RESTORE: {
		op->type = RZ_ANALYSIS_OP_TYPE_SWI;
		op->family = RZ_ANALYSIS_OP_FAMILY_UNKNOWN;
		break;
	}

	case TRICORE_INS_CACHEA_I:
	case TRICORE_INS_CACHEA_WI:
	case TRICORE_INS_CACHEA_W:
	case TRICORE_INS_CACHEI_I:
	case TRICORE_INS_CACHEI_WI:
	case TRICORE_INS_CACHEI_W:

	case TRICORE_INS_CLO_B:
	case TRICORE_INS_CLO_H:
	case TRICORE_INS_CLO:
	case TRICORE_INS_CLS_B:
	case TRICORE_INS_CLS_H:
	case TRICORE_INS_CLS:
	case TRICORE_INS_CLZ_B:
	case TRICORE_INS_CLZ_H:
	case TRICORE_INS_CLZ: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	case TRICORE_INS_CRC32B_W:
	case TRICORE_INS_CRC32L_W:
	case TRICORE_INS_CRC32_B:
	case TRICORE_INS_CRCN: {
		op->type = RZ_ANALYSIS_OP_TYPE_CRYPTO;
		op->family = RZ_ANALYSIS_OP_FAMILY_CRYPTO;
		break;
	}
	case TRICORE_INS_CALLI: {
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->reg = tricore_get_op_regname(h, insn, 0);
		op->stackop = RZ_ANALYSIS_STACK_GET;
		break;
	}
	case TRICORE_INS_CALLA:
	case TRICORE_INS_CALL: {
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ut32)tricore_get_op_imm(insn, 0);
		op->stackop = RZ_ANALYSIS_STACK_GET;
		break;
	}
	case TRICORE_INS_DIV:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_DIV_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	}
	case TRICORE_INS_DEBUG:
	case TRICORE_INS_NOP: {
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	}
	case TRICORE_INS_NOR_T:
	case TRICORE_INS_NOR: {
		op->type = RZ_ANALYSIS_OP_TYPE_NOR;
		break;
	}
	case TRICORE_INS_EXTR:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_DEXTR:
	case TRICORE_INS_EXTR_U:
	case TRICORE_INS_INSERT:
	case TRICORE_INS_INSN_T:
	case TRICORE_INS_INS_T: {
		op->type = RZ_ANALYSIS_OP_TYPE_REG;
		break;
	}
	case TRICORE_INS_DIFSC_A: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}

	case TRICORE_INS_WAIT:
	case TRICORE_INS_ISYNC:
	case TRICORE_INS_DSYNC: {
		op->type = RZ_ANALYSIS_OP_TYPE_SYNC;
		op->family = RZ_ANALYSIS_OP_FAMILY_THREAD;
		break;
	}
	case TRICORE_INS_DVINIT_B:
	case TRICORE_INS_DVINIT_H:
	case TRICORE_INS_DVINIT:
	case TRICORE_INS_DVSTEP:
	case TRICORE_INS_IXMIN:
	case TRICORE_INS_IXMAX:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_IMASK:
	case TRICORE_INS_DVADJ:

	case TRICORE_INS_DVSTEP_U:
	case TRICORE_INS_DVINIT_U:
	case TRICORE_INS_DVINIT_HU:
	case TRICORE_INS_DVINIT_BU:
	case TRICORE_INS_IXMAX_U:
	case TRICORE_INS_IXMIN_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_JLA:
	case TRICORE_INS_JL:
	case TRICORE_INS_JA:
	case TRICORE_INS_J: {
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (ut32)tricore_get_op_imm(insn, 0);
		break;
	}
	case TRICORE_INS_JI:
	case TRICORE_INS_JLI: {
		op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
		op->reg = tricore_get_op_regname(h, insn, 0);
		break;
	}

	case TRICORE_INS_JEQ:
	case TRICORE_INS_JEQ_A:

	case TRICORE_INS_JNE:
	case TRICORE_INS_JNEI:
	case TRICORE_INS_JNED:
	case TRICORE_INS_JNE_A:

	case TRICORE_INS_JZ_T:
	case TRICORE_INS_JNZ_A:
	case TRICORE_INS_JNZ_T:

	case TRICORE_INS_JGE:
	case TRICORE_INS_JLT:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_JLT_U:
	case TRICORE_INS_JGE_U:

	case TRICORE_INS_JGEZ:
	case TRICORE_INS_JGTZ:
	case TRICORE_INS_JLEZ:
	case TRICORE_INS_JLTZ:
	case TRICORE_INS_JNZ:
	case TRICORE_INS_JZ_A:
	case TRICORE_INS_JZ: {
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = (ut32)tricore_get_op_imm(insn, tricore_op_count(insn) - 1);
		op->fail = insn->address + insn->size;
		op->cond = insn2cond(insn->id);
		break;
	}
	case TRICORE_INS_LDLCX:
	case TRICORE_INS_LDUCX:
		op->refptr = 4 * 16;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		// fallthrough
	case TRICORE_INS_LDMST:
	case TRICORE_INS_LD_A:
	case TRICORE_INS_LD_BU:
	case TRICORE_INS_LD_B:
	case TRICORE_INS_LD_DA:
	case TRICORE_INS_LD_D:
	case TRICORE_INS_LD_HU:
	case TRICORE_INS_LD_H:
	case TRICORE_INS_LD_Q:
	case TRICORE_INS_LD_W: {
		op->refptr = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		if (insn->detail->tricore.op_count >= 2) {
			cs_tricore_op *op1 = &insn->detail->tricore.operands[1];
			if (op1->type == TRICORE_OP_REG && op1->reg == TRICORE_REG_SP) {
				op->stackop = RZ_ANALYSIS_STACK_GET;
			}
		}
		break;
	}
	case TRICORE_INS_LEA:
	case TRICORE_INS_LHA: {
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	}
	case TRICORE_INS_LOOPU:
	case TRICORE_INS_LOOP: {
		op->type = RZ_ANALYSIS_OP_TYPE_REP;
		break;
	}
	case TRICORE_INS_LT_B:
	case TRICORE_INS_LT_A:
	case TRICORE_INS_LT_H:
	case TRICORE_INS_LT_W:
	case TRICORE_INS_LT:
	case TRICORE_INS_GE:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_LT_BU:
	case TRICORE_INS_LT_HU:
	case TRICORE_INS_LT_U:
	case TRICORE_INS_LT_WU:
	case TRICORE_INS_GE_A:
	case TRICORE_INS_GE_U:
	case TRICORE_INS_EQANY_B:
	case TRICORE_INS_EQANY_H:
	case TRICORE_INS_EQZ_A:
	case TRICORE_INS_EQ_A:
	case TRICORE_INS_EQ_B:
	case TRICORE_INS_EQ_H:
	case TRICORE_INS_EQ_W:
	case TRICORE_INS_EQ:
	case TRICORE_INS_CMPSWAP_W: {
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	}
	case TRICORE_INS_MADDMS_H:
	case TRICORE_INS_MADDMS:
	case TRICORE_INS_MADDM_H:
	case TRICORE_INS_MADDM_Q:
	case TRICORE_INS_MADDM:
	case TRICORE_INS_MADDRS_H:
	case TRICORE_INS_MADDRS_Q:
	case TRICORE_INS_MADDR_H:
	case TRICORE_INS_MADDR_Q:
	case TRICORE_INS_MADDSUMS_H:
	case TRICORE_INS_MADDSUM_H:
	case TRICORE_INS_MADDSURS_H:
	case TRICORE_INS_MADDSUR_H:
	case TRICORE_INS_MADDSUS_H:
	case TRICORE_INS_MADDSU_H:
	case TRICORE_INS_MADDS_H:
	case TRICORE_INS_MADDS_Q:
	case TRICORE_INS_MADDS:
	case TRICORE_INS_MADD_H:
	case TRICORE_INS_MADD_Q:
	case TRICORE_INS_MADD:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_MADDMS_U:
	case TRICORE_INS_MADDM_U:
	case TRICORE_INS_MADDS_U:
	case TRICORE_INS_MADD_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	}
	case TRICORE_INS_MAX_B:
	case TRICORE_INS_MAX_H:
	case TRICORE_INS_MAX:
	case TRICORE_INS_MIN_B:
	case TRICORE_INS_MIN_H:
	case TRICORE_INS_MIN:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_MIN_HU:
	case TRICORE_INS_MIN_BU:
	case TRICORE_INS_MAX_BU:
	case TRICORE_INS_MAX_HU:
	case TRICORE_INS_MAX_U:
	case TRICORE_INS_MIN_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_MOVH_A:
	case TRICORE_INS_MOVH:
	case TRICORE_INS_MOVZ_A:
	case TRICORE_INS_MOV_AA:
	case TRICORE_INS_MOV_A:
	case TRICORE_INS_MOV_D:
	case TRICORE_INS_MOV_U:
	case TRICORE_INS_MOV:
	case TRICORE_INS_CMOVN:
	case TRICORE_INS_CMOV: {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		cs_tricore_op *dst = tricore_get_op(insn, 0);
		if (dst->type == TRICORE_OP_REG) {
			op->reg = cs_reg_name(h, dst->reg);
		}
		if (insn->detail->tricore.op_count == 2) {
			cs_tricore_op *src = tricore_get_op(insn, 1);
			if (src->type == TRICORE_OP_IMM) {
				op->val = src->imm;
			}
		}
		break;
	}
	case TRICORE_INS_MFCR:
	case TRICORE_INS_MTCR:
	case TRICORE_INS_BMERGE:
	case TRICORE_INS_BSPLIT:
	case TRICORE_INS_SHUFFLE: {
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	}
	case TRICORE_INS_MSUBADMS_H:
	case TRICORE_INS_MSUBADM_H:
	case TRICORE_INS_MSUBADRS_H:
	case TRICORE_INS_MSUBADR_H:
	case TRICORE_INS_MSUBADS_H:
	case TRICORE_INS_MSUBAD_H:
	case TRICORE_INS_MSUBMS_H:
	case TRICORE_INS_MSUBMS:
	case TRICORE_INS_MSUBM_H:
	case TRICORE_INS_MSUBM_Q:
	case TRICORE_INS_MSUBM:
	case TRICORE_INS_MSUBRS_H:
	case TRICORE_INS_MSUBRS_Q:
	case TRICORE_INS_MSUBR_H:
	case TRICORE_INS_MSUBR_Q:
	case TRICORE_INS_MSUBS_H:
	case TRICORE_INS_MSUBS_Q:
	case TRICORE_INS_MSUBS:
	case TRICORE_INS_MSUB_H:
	case TRICORE_INS_MSUB_Q:
	case TRICORE_INS_MSUB:
	case TRICORE_INS_CSUBN_A:
	case TRICORE_INS_CSUBN:
	case TRICORE_INS_CSUB_A:
	case TRICORE_INS_CSUB:
	case TRICORE_INS_SUBC:
	case TRICORE_INS_SUBSC_A:
	case TRICORE_INS_SUBS_B:
	case TRICORE_INS_SUBS_H:
	case TRICORE_INS_SUBS:
	case TRICORE_INS_SUBX:
	case TRICORE_INS_SUB_A:
	case TRICORE_INS_SUB_B:
	case TRICORE_INS_SUB_H:
	case TRICORE_INS_SUB:
	case TRICORE_INS_RSUBS:
	case TRICORE_INS_RSUB:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_RSUBS_U:
	case TRICORE_INS_SUBS_U:
	case TRICORE_INS_SUBS_HU:
	case TRICORE_INS_SUBS_BU:
	case TRICORE_INS_MSUB_U:
	case TRICORE_INS_MSUBS_U:
	case TRICORE_INS_MSUBM_U:
	case TRICORE_INS_MSUBMS_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		cs_tricore_op *op0 = tricore_get_op(insn, 0);
		if (op0->type == TRICORE_OP_REG && op0->reg == TRICORE_REG_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = -tricore_get_op_imm(insn, 1);
		}
		if (insn->detail->tricore.op_count == 2) {
			cs_tricore_op *op1 = tricore_get_op(insn, 1);
			if (op1->type == TRICORE_OP_IMM) {
				op->val = op1->imm;
			}
		}
		break;
	}
	case TRICORE_INS_MULMS_H:
	case TRICORE_INS_MULM_H:
	case TRICORE_INS_MULM:
	case TRICORE_INS_MULR_H:
	case TRICORE_INS_MULR_Q:
	case TRICORE_INS_MULS:
	case TRICORE_INS_MUL_H:
	case TRICORE_INS_MUL_Q:
	case TRICORE_INS_MUL:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_MUL_U:
	case TRICORE_INS_MULS_U:
	case TRICORE_INS_MULM_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	}
	case TRICORE_INS_NAND_T:
	case TRICORE_INS_NAND:
	case TRICORE_INS_NEZ_A:
	case TRICORE_INS_NE_A:
	case TRICORE_INS_NE: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_NOT: {
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	}
	case TRICORE_INS_ORN_T:
	case TRICORE_INS_ORN:
	case TRICORE_INS_OR_ANDN_T:
	case TRICORE_INS_OR_AND_T:
	case TRICORE_INS_OR_EQ:
	case TRICORE_INS_OR_GE:
	case TRICORE_INS_OR_LT:
	case TRICORE_INS_OR_NE:
	case TRICORE_INS_OR_NOR_T:
	case TRICORE_INS_OR_OR_T:
	case TRICORE_INS_OR_T:
	case TRICORE_INS_OR:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_OR_LT_U:
	case TRICORE_INS_OR_GE_U: {
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	}

	case TRICORE_INS_PARITY:
	case TRICORE_INS_POPCNT_W: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_RFM:
		op->stackop = RZ_ANALYSIS_STACK_SET;
		// fallthrough
	case TRICORE_INS_RET:
	case TRICORE_INS_RFE: {
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		break;
	}

	case TRICORE_INS_SAT_H:
	case TRICORE_INS_SAT_B:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_RSLCX:
	case TRICORE_INS_RSTV:
	case TRICORE_INS_SAT_BU:
	case TRICORE_INS_SAT_HU: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_SH_LT:
	case TRICORE_INS_SH_GE:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_SELN_A:
	case TRICORE_INS_SELN:
	case TRICORE_INS_SEL_A:
	case TRICORE_INS_SEL:
	case TRICORE_INS_SHAS:
	case TRICORE_INS_SHA_B:
	case TRICORE_INS_SHA_H:
	case TRICORE_INS_SHA:

	case TRICORE_INS_SH_ANDN_T:
	case TRICORE_INS_SH_AND_T:
	case TRICORE_INS_SH_B:
	case TRICORE_INS_SH_EQ:
	case TRICORE_INS_SH_GE_U:
	case TRICORE_INS_SH_H:
	case TRICORE_INS_SH_LT_U:
	case TRICORE_INS_SH_NAND_T:
	case TRICORE_INS_SH_NE:
	case TRICORE_INS_SH_NOR_T:
	case TRICORE_INS_SH_ORN_T:
	case TRICORE_INS_SH_OR_T:
	case TRICORE_INS_SH_XNOR_T:
	case TRICORE_INS_SH_XOR_T:
	case TRICORE_INS_SH: {
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	}
	case TRICORE_INS_STLCX:
	case TRICORE_INS_STUCX:
		op->ptr = tricore_get_op_imm(insn, 0);
		op->ptrsize = 4 * 16;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		// fallthrough
	case TRICORE_INS_ST_A:
	case TRICORE_INS_ST_B:
	case TRICORE_INS_ST_DA:
	case TRICORE_INS_ST_D:
	case TRICORE_INS_ST_H:
	case TRICORE_INS_ST_Q:
	case TRICORE_INS_ST_T:
	case TRICORE_INS_ST_W: {
		op->ptrsize = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		cs_tricore_op *op0 = tricore_get_op(insn, 0);
		switch (op0->type) {
		case TRICORE_OP_MEM:
		case TRICORE_OP_INVALID:
		case TRICORE_OP_REG: {
			op->ptr = 0L;
			if (op0->reg == TRICORE_REG_SP) {
				op->stackop = RZ_ANALYSIS_STACK_SET;
			}
			break;
		}
		case TRICORE_OP_IMM: {
			op->ptr = op0->imm;
			break;
		};
		}
		break;
	}

	case TRICORE_INS_SWAPMSK_W:
	case TRICORE_INS_SWAP_A:
	case TRICORE_INS_SWAP_W:
	case TRICORE_INS_TLBDEMAP:
	case TRICORE_INS_TLBFLUSH_A:
	case TRICORE_INS_TLBFLUSH_B:
	case TRICORE_INS_TLBMAP:
	case TRICORE_INS_TLBPROBE_A:
	case TRICORE_INS_TLBPROBE_I: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_TRAPSV:
	case TRICORE_INS_TRAPV: {
		op->type = RZ_ANALYSIS_OP_TYPE_TRAP;
		break;
	}

	case TRICORE_INS_XOR_LT:
	case TRICORE_INS_XOR_EQ:
		op->sign = true;
		// fallthrough
	case TRICORE_INS_XNOR_T:
	case TRICORE_INS_XNOR:

	case TRICORE_INS_XOR_GE_U:
	case TRICORE_INS_XOR_GE:
	case TRICORE_INS_XOR_LT_U:

	case TRICORE_INS_XOR_NE:
	case TRICORE_INS_XOR:
	case TRICORE_INS_XOR_T: {
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	}
	}
}

static RzAnalysisLiftedILOp rz_analysis_tricore_il_op() {
	return NULL;
}

static inline void fill_from_tricore_op(RzReg *rz_reg, csh handle, RzAnalysisValue *av, cs_tricore_op *top) {
	switch (top->type) {
	case TRICORE_OP_INVALID:
	default:
		av->type = RZ_ANALYSIS_VAL_UNK;
		break;
	case TRICORE_OP_IMM:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = top->imm;
		break;
	case TRICORE_OP_REG:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(rz_reg, cs_reg_name(handle, top->reg), RZ_REG_TYPE_ANY);
		break;
	case TRICORE_OP_MEM:
		av->type = RZ_ANALYSIS_VAL_MEM;
		av->reg = rz_reg_get(rz_reg, cs_reg_name(handle, top->mem.base), RZ_REG_TYPE_ANY);
		av->delta = top->mem.disp;
		break;
	}
}

static void rz_analysis_tricore_fillval(RzAnalysis *a, RzAnalysisOp *op, csh handle, cs_insn *insn) {
	uint8_t srci = 0;
	cs_tricore *tc = &insn->detail->tricore;
	for (uint8_t i = 0; i < tc->op_count; ++i) {
		cs_tricore_op *top = &tc->operands[i];
		RzAnalysisValue *av = rz_analysis_value_new();
		fill_from_tricore_op(a->reg, handle, av, top);
		if (top->access & CS_AC_READ) {
			av->access |= RZ_ANALYSIS_ACC_R;
			op->src[srci++] = av;
		}
		if (top->access & CS_AC_WRITE) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (op->dst) {
				rz_warn_if_reached();
			}
			op->dst = av;
		}
	}
}

static void tricore_opex(RzStrBuf *ptr, csh handle, cs_insn *p_insn) {
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_tricore *tc = &p_insn->detail->tricore;
	for (st32 i = 0; i < tc->op_count; i++) {
		cs_tricore_op *op = tc->operands + i;
		pj_o(pj);
		switch (op->type) {
		case TRICORE_OP_INVALID: {
			pj_ks(pj, "type", "invalid");
			break;
		}
		case TRICORE_OP_REG: {
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(handle, op->reg));
			break;
		}
		case TRICORE_OP_IMM: {
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
			break;
		}
		case TRICORE_OP_MEM: {
			pj_ks(pj, "type", "mem");
			pj_ks(pj, "base", cs_reg_name(handle, op->mem.base));
			pj_ki(pj, "disp", op->mem.disp);
			break;
		}
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);

	rz_strbuf_init(ptr);
	rz_strbuf_append(ptr, pj_string(pj));
	pj_free(pj);
}

static RzAnalysisILConfig *il_config(RzAnalysis *analysis) {
	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	return cfg;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_tricore_cs = {
	.name = "tricore",
	.desc = "Capstone TRICORE analysis plugin",
	.author = "billow",
	.license = "LGPL3",
	.arch = "tricore",
	.bits = 32,
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.op = rz_analysis_tricore_op,
	.il_config = il_config,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_tricore_cs,
	.version = RZ_VERSION
};
#endif
