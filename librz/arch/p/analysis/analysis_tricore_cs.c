// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#include <tricore/tricore.inc>
#include "tricore/tricore_il.h"

#define TRICORE_REG_SP TRICORE_REG_A10

static char *tricore_reg_profile(RzAnalysis *_) {
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
		"drx	PCXI	.32	128	0\n"
		"drx	PSW	.32	132	0\n"
		"drx	pc	.32	136	0\n"
		"drx	SYSCON	.32	140	0\n"
		"drx	CPU_ID	.32	144	0\n"
		"drx	CORE_ID	.32	148	0\n"
		"drx	BIV	.32	152	0\n"
		"drx	BTV	.32	156	0\n"
		"drx	ISP	.32	160	0\n"
		"drx	ICR	.32	164	0\n"
		"drx	FCX	.32	168	0\n"
		"drx	LCX	.32	172	0\n"
		"drx	COMPAT	.32	176	0\n"
		"drx	DPR0_L	.32	180	0\n"
		"drx	DPR0_U	.32	184	0\n"
		"drx	DPR1_L	.32	188	0\n"
		"drx	DPR1_U	.32	192	0\n"
		"drx	DPR2_L	.32	196	0\n"
		"drx	DPR2_U	.32	200	0\n"
		"drx	DPR3_L	.32	204	0\n"
		"drx	DPR3_U	.32	208	0\n"
		"drx	DPR4_L	.32	212	0\n"
		"drx	DPR4_U	.32	216	0\n"
		"drx	DPR5_L	.32	220	0\n"
		"drx	DPR5_U	.32	224	0\n"
		"drx	DPR6_L	.32	228	0\n"
		"drx	DPR6_U	.32	232	0\n"
		"drx	DPR7_L	.32	236	0\n"
		"drx	DPR7_U	.32	240	0\n"
		"drx	DPR8_L	.32	244	0\n"
		"drx	DPR8_U	.32	248	0\n"
		"drx	DPR9_L	.32	252	0\n"
		"drx	DPR9_U	.32	256	0\n"
		"drx	DPR10_L	.32	260	0\n"
		"drx	DPR10_U	.32	264	0\n"
		"drx	DPR11_L	.32	268	0\n"
		"drx	DPR11_U	.32	272	0\n"
		"drx	DPR12_L	.32	276	0\n"
		"drx	DPR12_U	.32	280	0\n"
		"drx	DPR13_L	.32	284	0\n"
		"drx	DPR13_U	.32	288	0\n"
		"drx	DPR14_L	.32	292	0\n"
		"drx	DPR14_U	.32	296	0\n"
		"drx	DPR15_L	.32	300	0\n"
		"drx	DPR15_U	.32	304	0\n"
		"drx	CPR0_L	.32	308	0\n"
		"drx	CPR0_U	.32	312	0\n"
		"drx	CPR1_L	.32	316	0\n"
		"drx	CPR1_U	.32	320	0\n"
		"drx	CPR2_L	.32	324	0\n"
		"drx	CPR2_U	.32	328	0\n"
		"drx	CPR3_L	.32	332	0\n"
		"drx	CPR3_U	.32	336	0\n"
		"drx	CPR4_L	.32	340	0\n"
		"drx	CPR4_U	.32	344	0\n"
		"drx	CPR5_L	.32	348	0\n"
		"drx	CPR5_U	.32	352	0\n"
		"drx	CPR6_L	.32	356	0\n"
		"drx	CPR6_U	.32	360	0\n"
		"drx	CPR7_L	.32	364	0\n"
		"drx	CPR7_U	.32	368	0\n"
		"drx	CPR8_L	.32	372	0\n"
		"drx	CPR8_U	.32	376	0\n"
		"drx	CPR9_L	.32	380	0\n"
		"drx	CPR9_U	.32	384	0\n"
		"drx	CPR10_L	.32	388	0\n"
		"drx	CPR10_U	.32	392	0\n"
		"drx	CPR11_L	.32	396	0\n"
		"drx	CPR11_U	.32	400	0\n"
		"drx	CPR12_L	.32	404	0\n"
		"drx	CPR12_U	.32	408	0\n"
		"drx	CPR13_L	.32	412	0\n"
		"drx	CPR13_U	.32	416	0\n"
		"drx	CPR14_L	.32	420	0\n"
		"drx	CPR14_U	.32	424	0\n"
		"drx	CPR15_L	.32	428	0\n"
		"drx	CPR15_U	.32	432	0\n"
		"drx	CPXE_0	.32	436	0\n"
		"drx	CPXE_1	.32	440	0\n"
		"drx	CPXE_2	.32	444	0\n"
		"drx	CPXE_3	.32	448	0\n"
		"drx	CPXE_4	.32	452	0\n"
		"drx	CPXE_5	.32	456	0\n"
		"drx	CPXE_6	.32	460	0\n"
		"drx	CPXE_7	.32	464	0\n"
		"drx	DPRE_0	.32	468	0\n"
		"drx	DPRE_1	.32	472	0\n"
		"drx	DPRE_2	.32	476	0\n"
		"drx	DPRE_3	.32	480	0\n"
		"drx	DPRE_4	.32	484	0\n"
		"drx	DPRE_5	.32	488	0\n"
		"drx	DPRE_6	.32	492	0\n"
		"drx	DPRE_7	.32	496	0\n"
		"drx	DPWE_0	.32	500	0\n"
		"drx	DPWE_1	.32	504	0\n"
		"drx	DPWE_2	.32	508	0\n"
		"drx	DPWE_3	.32	512	0\n"
		"drx	DPWE_4	.32	516	0\n"
		"drx	DPWE_5	.32	520	0\n"
		"drx	DPWE_6	.32	524	0\n"
		"drx	DPWE_7	.32	528	0\n"
		"drx	TPS_CON	.32	532	0\n"
		"drx	TPS_TIMER0	.32	536	0\n"
		"drx	TPS_TIMER1	.32	540	0\n"
		"drx	TPS_TIMER2	.32	544	0\n"
		"drx	TPS_EXTIM_ENTRY_CVAL	.32	548	0\n"
		"drx	TPS_EXTIM_ENTRY_LVAL	.32	552	0\n"
		"drx	TPS_EXTIM_EXIT_CVAL	.32	556	0\n"
		"drx	TPS_EXTIM_EXIT_LVAL	.32	560	0\n"
		"drx	TPS_EXTIM_CLASS_EN	.32	564	0\n"
		"drx	TPS_EXTIM_STAT	.32	568	0\n"
		"drx	TPS_EXTIM_FCX	.32	572	0\n"
		"drx	MMU_CON	.32	576	0\n"
		"drx	MMU_ASI	.32	580	0\n"
		"drx	MMU_TVA	.32	584	0\n"
		"drx	MMU_TPA	.32	588	0\n"
		"drx	MMU_TPX	.32	592	0\n"
		"drx	MMU_TFA	.32	596	0\n"
		"drx	MMU_TFAS	.32	600	0\n"
		"drx	PMA01_	.32	604	0\n"
		"drx	PMA01	.32	608	0\n"
		"drx	PMA11	.32	612	0\n"
		"drx	PMA21	.32	616	0\n"
		"drx	DCON2	.32	620	0\n"
		"drx	DCON1	.32	624	0\n"
		"drx	SMACON	.32	628	0\n"
		"drx	DSTR	.32	632	0\n"
		"drx	DATR	.32	636	0\n"
		"drx	DEADD	.32	640	0\n"
		"drx	DIEAR	.32	644	0\n"
		"drx	DIETR	.32	648	0\n"
		"drx	DCON0	.32	652	0\n"
		"drx	PSTR	.32	656	0\n"
		"drx	PCON1	.32	660	0\n"
		"drx	PCON2	.32	664	0\n"
		"drx	PCON0	.32	668	0\n"
		"drx	PIEAR	.32	672	0\n"
		"drx	PIETR	.32	676	0\n"
		"drx	DBGSR	.32	680	0\n"
		"drx	EXEVT	.32	684	0\n"
		"drx	CREVT	.32	688	0\n"
		"drx	SWEVT	.32	692	0\n"
		"drx	TR0EVT	.32	696	0\n"
		"drx	TR0ADR	.32	700	0\n"
		"drx	TR1EVT	.32	704	0\n"
		"drx	TR1ADR	.32	708	0\n"
		"drx	TR2EVT	.32	712	0\n"
		"drx	TR2ADR	.32	716	0\n"
		"drx	TR3EVT	.32	720	0\n"
		"drx	TR3ADR	.32	724	0\n"
		"drx	TR4EVT	.32	728	0\n"
		"drx	TR4ADR	.32	732	0\n"
		"drx	TR5EVT	.32	736	0\n"
		"drx	TR5ADR	.32	740	0\n"
		"drx	TR6EVT	.32	744	0\n"
		"drx	TR6ADR	.32	748	0\n"
		"drx	TR7EVT	.32	752	0\n"
		"drx	TR7ADR	.32	756	0\n"
		"drx	TRIG_ACC	.32	760	0\n"
		"drx	DMS	.32	764	0\n"
		"drx	DCX	.32	768	0\n"
		"drx	TASK_ASI	.32	772	0\n"
		"drx	DBGTCR	.32	776	0\n"
		"drx	CCTRL	.32	780	0\n"
		"drx	CCNT	.32	784	0\n"
		"drx	ICNT	.32	788	0\n"
		"drx	M1CNT	.32	792	0\n"
		"drx	M2CNT	.32	796	0\n"
		"drx	M3CNT	.32	800	0\n"
		"drx	FPU_TRAP_CON	.32	804	0\n"
		"drx	FPU_TRAP_PC	.32	808	0\n"
		"drx	FPU_TRAP_OPC	.32	812	0\n"
		"drx	FPU_TRAP_SRC1	.32	816	0\n"
		"drx	FPU_TRAP_SRC2	.32	820	0\n"
		"drx	FPU_TRAP_SRC3	.32	824	0\n"
		"drx	set_FI	.1	900	0\n"
		"drx	set_FV	.1	901	0\n"
		"drx	set_FZ	.1	902	0\n"
		"drx	set_FU	.1	903	0\n"
		"drx	set_FX	.1	904	0\n";
	return rz_str_dup(p);
}

static void tricore_opex(RzAsmTriCoreContext *ctx, RzStrBuf *sb);

static void tricore_fillvals(RzAsmTriCoreContext *ctx, RzAnalysis *a, RzAnalysisOp *op);

static void tricore_op_set_type(RzAsmTriCoreContext *ctx, RzAnalysisOp *op);

static int
tricore_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!(a && op && data && len > 0)) {
		return 0;
	}
	if (a->big_endian) {
		return -1;
	}

	RzAsmTriCoreContext *ctx = a->plugin_data;
	if (!tricore_setup_cs_handle(ctx, a->cpu, NULL)) {
		return -1;
	}

	op->size = 2;

	ctx->insn = NULL;
	ctx->count = cs_disasm(ctx->h, (const ut8 *)data, len, addr, 1, &ctx->insn);
	if (ctx->count <= 0 || !ctx->insn) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = rz_str_dup("invalid");
		}
		goto beach;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s",
			ctx->insn->mnemonic, ctx->insn->op_str[0] ? " " : "", ctx->insn->op_str);
	}
	op->size = ctx->insn->size;
	op->id = (int)ctx->insn->id;
	op->addr = ctx->insn->address;
	tricore_op_set_type(ctx, op);
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		tricore_opex(ctx, &op->opex);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		tricore_fillvals(ctx, a, op);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		op->il_op = tricore_il_op(ctx, a);
	}

beach:
	cs_free(ctx->insn, ctx->count);
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

static void tricore_op_set_type(RzAsmTriCoreContext *ctx, RzAnalysisOp *op) {
	if (is_inst_privileged(ctx->insn->id)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_PRIV;
	} else if (is_inst_packed(ctx->insn->id)) {
		op->family = RZ_ANALYSIS_OP_FAMILY_MMX;
	}

	switch (ctx->insn->id) {
	default: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case TRICORE_INS_FCALLI: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->reg = tricore_op_as_reg(ctx, 0);
		op->stackop = RZ_ANALYSIS_STACK_INC;
		op->stackptr = -4;
		break;
	}
	case TRICORE_INS_FCALLA:
	case TRICORE_INS_FCALL: {
		op->family = RZ_ANALYSIS_OP_FAMILY_FPU;
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ut32)tricore_op_as_imm(ctx, 0);
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
		if (tricore_op_count(ctx->insn) >= 2) {
			const cs_tricore_op *op1 = tricore_op_get(ctx->insn, 1);
			if (op1->type == TRICORE_OP_IMM) {
				op->val = op1->imm;
				const cs_tricore_op *op0 = tricore_op_get(ctx->insn, 0);
				if (op0->type == TRICORE_OP_REG && op0->reg == TRICORE_REG_SP) {
					op->stackop = RZ_ANALYSIS_STACK_INC;
					op->stackptr = op1->imm;
				}
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
		op->reg = tricore_op_as_reg(ctx, 0);
		op->stackop = RZ_ANALYSIS_STACK_GET;
		break;
	}
	case TRICORE_INS_CALLA:
	case TRICORE_INS_CALL: {
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ut32)tricore_op_as_imm(ctx, 0);
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
		op->jump = (ut32)tricore_op_as_imm(ctx, 0);
		break;
	}
	case TRICORE_INS_JI:
	case TRICORE_INS_JLI: {
		op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
		op->reg = tricore_op_as_reg(ctx, 0);
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
		op->jump = (ut32)tricore_op_as_imm(ctx, tricore_op_count(ctx->insn) - 1);
		op->fail = ctx->insn->address + ctx->insn->size;
		op->cond = insn2cond(ctx->insn->id);
		break;
	}
	case TRICORE_INS_LDLCX:
	case TRICORE_INS_LDUCX:
		op->refptr = 4 * 16;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		break;
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
		if (ctx->insn->detail->tricore.op_count >= 2) {
			const cs_tricore_op *op1 = tricore_op_get(ctx->insn, 1);
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
		cs_tricore_op *dst = tricore_op_get(ctx->insn, 0);
		if (dst->type == TRICORE_OP_REG) {
			op->reg = cs_reg_name(ctx->h, dst->reg);
		}
		if (tricore_op_count(ctx->insn) == 2) {
			cs_tricore_op *src = tricore_op_get(ctx->insn, 1);
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
		const cs_tricore_op *op0 = tricore_op_get(ctx->insn, 0);
		if (tricore_op_count(ctx->insn) >= 2) {
			cs_tricore_op *op1 = tricore_op_get(ctx->insn, 1);
			if (op1->type == TRICORE_OP_IMM) {
				op->val = op1->imm;
				if (op0->type == TRICORE_OP_REG && op0->reg == TRICORE_REG_SP) {
					op->stackop = RZ_ANALYSIS_STACK_INC;
					op->stackptr = -op1->imm;
				}
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
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_SET;
		break;
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
	case TRICORE_INS_STLCX: {
		const cs_tricore_op *op0 = tricore_op_get(ctx->insn, 0);
		op->ptr = op0->type == TRICORE_OP_IMM
			? op0->imm
			: (op0->type == TRICORE_OP_MEM ? op0->mem.disp : -1);
		op->ptrsize = 4 * 16;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	}
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
		const cs_tricore_op *op0 = tricore_op_get(ctx->insn, 0);
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
		}
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

static inline void tricore_fillval(RzReg *rz_reg, csh handle, RzAnalysisValue *av, cs_tricore_op *top) {
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

static void tricore_fillvals(RzAsmTriCoreContext *ctx, RzAnalysis *a, RzAnalysisOp *op) {
	uint8_t srci = 0;
	cs_tricore *tc = &ctx->insn->detail->tricore;
	for (uint8_t i = 0; i < tc->op_count; ++i) {
		cs_tricore_op *top = &tc->operands[i];
		RzAnalysisValue *av = rz_analysis_value_new();
		tricore_fillval(a->reg, ctx->h, av, top);
		if (top->access & CS_AC_READ) {
			av->access |= RZ_ANALYSIS_ACC_R;
			op->src[srci++] = av;
		}
		if (top->access & CS_AC_WRITE) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (op->dst) {
				rz_warn_if_reached();
			}
			if (srci > 0 && av == op->src[srci - 1]) {
				av = rz_mem_dup(av, sizeof(RzAnalysisValue));
			}
			op->dst = av;
		}
	}
}

static void tricore_opex(RzAsmTriCoreContext *ctx, RzStrBuf *sb) {
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_tricore *tc = &ctx->insn->detail->tricore;
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
			pj_ks(pj, "value", cs_reg_name(ctx->h, op->reg));
			break;
		}
		case TRICORE_OP_IMM: {
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
			break;
		}
		case TRICORE_OP_MEM: {
			pj_ks(pj, "type", "mem");
			pj_ks(pj, "base", cs_reg_name(ctx->h, op->mem.base));
			pj_ki(pj, "disp", op->mem.disp);
			break;
		}
		}
		pj_end(pj);
	}
	pj_end(pj);
	pj_end(pj);

	rz_strbuf_init(sb);
	rz_strbuf_append(sb, pj_string(pj));
	pj_free(pj);
}

static int tricore_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
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

static bool tricore_init(void **u) {
	if (!u) {
		return false;
	}
	RzAsmTriCoreContext *ctx = RZ_NEW0(RzAsmTriCoreContext);
	if (!ctx) {
		return false;
	}
	*u = ctx;
	return true;
}

static bool tricore_fini(void *u) {
	if (!u) {
		return true;
	}
	RzAsmTriCoreContext *ctx = u;
	cs_close(&ctx->h);
	free(u);
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_tricore_cs = {
	.name = "tricore",
	.desc = "Capstone TRICORE analysis plugin",
	.author = "billow",
	.license = "LGPL3",
	.arch = "tricore",
	.bits = 32,
	.get_reg_profile = tricore_reg_profile,
	.archinfo = tricore_archinfo,
	.op = tricore_op,
	.il_config = tricore_il_config,
	.init = tricore_init,
	.fini = tricore_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_tricore_cs,
	.version = RZ_VERSION
};
#endif
