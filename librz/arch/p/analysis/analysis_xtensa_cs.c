// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_endian.h>
#include <xtensa/xtensa.h>

static int xtensa_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return 1;
	default:
		return -1;
	}
}

static char *xtensa_get_reg_profile(RzAnalysis *analysis) {
	return rz_str_dup(
		// Assuming call0 ABI
		"# a0		return address\n"
		"# a1		stack pointer\n"
		"# a2-a7	arguments\n"
		"# a2-a5	return value (call0 ABI)\n"
		"# a12-a15	callee-saved (call0 ABI)\n"
		"=PC	pc\n"
		"=BP	a14\n"
		"=SP	a1\n"
		"=A0	a2\n"
		"=A1	a3\n"
		"=A2	a4\n"
		"=A3	a5\n"
		"=A4	a6\n"
		"=A5	a7\n"
		"=R0	a2\n"
		"=R1	a3\n"
		"=R2	a4\n"
		"=R3	a5\n"
		"gpr	a0	.32	0	0\n"
		"gpr	a1	.32	4	0\n"
		"gpr	a2	.32	8	0\n"
		"gpr	a3	.32	16	0\n"
		"gpr	a4	.32	20	0\n"
		"gpr	a5	.32	24	0\n"
		"gpr	a6	.32	28	0\n"
		"gpr	a7	.32	32	0\n"
		"gpr	a8	.32	36	0\n"
		"gpr	a9	.32	40	0\n"
		"gpr	a10	.32	44	0\n"
		"gpr	a11	.32	48	0\n"
		"gpr	a12	.32	52	0\n"
		"gpr	a13	.32	56	0\n"
		"gpr	a14	.32	60	0\n"
		"gpr	a15	.32	64	0\n"

		"gpr	f0	.64	76	0\n"
		"gpr	f1	.64	84	0\n"
		"gpr	f2	.64	92	0\n"
		"gpr	f3	.64	100	0\n"
		"gpr	f4	.64	108	0\n"
		"gpr	f5	.64	116	0\n"
		"gpr	f6	.64	124	0\n"
		"gpr	f7	.64	132	0\n"
		"gpr	f8	.64	140	0\n"
		"gpr	f9	.64	148	0\n"
		"gpr	f10	.64	156	0\n"
		"gpr	f11	.64	164	0\n"
		"gpr	f12	.64	172	0\n"
		"gpr	f13	.64	180	0\n"
		"gpr	f14	.64	188	0\n"
		"gpr	f15	.64	196	0\n"

		"gpr	b0	.1	210	0\n"
		"gpr	b1	.1	211	0\n"
		"gpr	b2	.1	212	0\n"
		"gpr	b3	.1	213	0\n"
		"gpr	b4	.1	214	0\n"
		"gpr	b5	.1	215	0\n"
		"gpr	b6	.1	216	0\n"
		"gpr	b7	.1	217	0\n"
		"gpr	b8	.1	218	0\n"
		"gpr	b9	.1	219	0\n"
		"gpr	b10	.1	220	0\n"
		"gpr	b11	.1	221	0\n"
		"gpr	b12	.1	222	0\n"
		"gpr	b13	.1	223	0\n"
		"gpr	b14	.1	224	0\n"
		"gpr	b15	.1	225	0\n"

		/*Special Registers*/
		/*0*/ "gpr	lbeg	.32	226	0\n"
		/*1*/ "gpr	lend	.32	230	0\n"
		/*2*/ "gpr	lcount	.32	234	0\n"
		/*3*/ "gpr	sar	.32	238	0\n"
		/*4*/ "gpr	br	.32	242	0\n"
		/*5*/ "gpr	litbase	.32	246	0\n"
		/*12*/ "gpr	scompare1	.32	274	0\n"
		/*16*/ "gpr	acclo	.32	290	0\n"
		/*17*/ "gpr	acchi	.32	294	0\n"
		/*32*/ "gpr	m0	.32	354	0\n"
		/*33*/ "gpr	m1	.32	358	0\n"
		/*34*/ "gpr	m2	.32	362	0\n"
		/*35*/ "gpr	m3	.32	366	0\n"
		/*72*/ "gpr	windowbase	.32	514	0\n"
		/*73*/ "gpr	windowstart	.32	518	0\n"
		/*83*/ "gpr	ptevaddr	.32	546	0\n"
		/*90*/ "gpr	rasid	.32	570	0\n"
		/*91*/ "gpr	itlbcfg	.32	574	0\n"
		/*92*/ "gpr	dtlbcfg	.32	578	0\n"
		/*95*/ "gpr	eracess	.32	586	0\n"
		/*96*/ "gpr	ibreakenable	.32	590	0\n"
		/*97*/ "gpr	memctl	.32	594	0\n"
		/*99*/ "gpr	atomctl	.32	602	0\n"
		/*104*/ "gpr	ddr	.32	618	0\n"
		/*106*/ "gpr	mepc	.32	626	0\n"
		/*107*/ "gpr	meps	.32	630	0\n"
		/*108*/ "gpr	mesave	.32	634	0\n"
		/*109*/ "gpr	mesr	.32	638	0\n"
		/*110*/ "gpr	mecr	.32	642	0\n"
		/*111*/ "gpr	mevaddr	.32	646	0\n"
		/*128*/ "gpr	ibreaka0	.32	690	0\n"
		/*129*/ "gpr	ibreaka1	.32	694	0\n"
		/*144*/ "gpr	dbreaka0	.32	738	0\n"
		/*145*/ "gpr	dbreaka1	.32	742	0\n"
		/*160*/ "gpr	dbreakc0	.32	786	0\n"
		/*161*/ "gpr	dbreakc1	.32	790	0\n"
		/*177*/ "gpr	epc1	.32	934	0\n"
		/*178*/ "gpr	epc2	.32	938	0\n"
		/*179*/ "gpr	epc3	.32	942	0\n"
		/*180*/ "gpr	epc4	.32	946	0\n"
		/*181*/ "gpr	epc5	.32	950	0\n"
		/*182*/ "gpr	epc6	.32	954	0\n"
		/*183*/ "gpr	epc7	.32	958	0\n"
		/*192*/ "gpr	depc	.32	994	0\n"
		/*193*/ "gpr	eps1	.32	998	0\n"
		/*194*/ "gpr	eps2	.32	1002	0\n"
		/*195*/ "gpr	eps3	.32	1006	0\n"
		/*196*/ "gpr	eps4	.32	1010	0\n"
		/*197*/ "gpr	eps5	.32	1014	0\n"
		/*198*/ "gpr	eps6	.32	1018	0\n"
		/*199*/ "gpr	eps7	.32	1022	0\n"
		/*209*/ "gpr	excsave1	.32	1062	0\n"
		/*210*/ "gpr	excsave2	.32	1066	0\n"
		/*211*/ "gpr	excsave3	.32	1070	0\n"
		/*212*/ "gpr	excsave4	.32	1074	0\n"
		/*213*/ "gpr	excsave5	.32	1078	0\n"
		/*214*/ "gpr	excsave6	.32	1082	0\n"
		/*215*/ "gpr	excsave7	.32	1086	0\n"
		/*224*/ "gpr	cpenable	.32	1122	0\n"
		/*226*/ "gpr	interrupt	.32	1126	0\n"
		/*227*/ "gpr	intclear	.32	1130	0\n"
		/*228*/ "gpr	intenable	.32	1134	0\n"
		/*230*/ "gpr	ps	.32	1138	0\n"
		/*231*/ "gpr	vecbase	.32	1142	0\n"
		/*232*/ "gpr	exccause	.32	1146	0\n"
		/*233*/ "gpr	debugcause	.32	1150	0\n"
		/*234*/ "gpr	ccount	.32	1154	0\n"
		/*235*/ "gpr	prid	.32	1158	0\n"
		/*236*/ "gpr	icount	.32	1162	0\n"
		/*237*/ "gpr	icountlevel	.32	1166	0\n"
		/*238*/ "gpr	excvaddr	.32	1170	0\n"
		/*240*/ "gpr	ccompare0	.32	1178	0\n"
		/*241*/ "gpr	ccompare1	.32	1182	0\n"
		/*242*/ "gpr	ccompare2	.32	1186	0\n"
		/*244*/ "gpr	misc0	.32	1190	0\n"
		/*245*/ "gpr	misc1	.32	1194	0\n"
		/*246*/ "gpr	misc2	.32	1198	0\n"
		/*247*/ "gpr	misc3	.32	1202	0\n"

		"gpr	ndepc	.1	2000	0\n"
		"gpr	ResetVector	.32	2004	0\n"
		"gpr	UserExceptionVector	.32	2008	0\n"
		"gpr	KernelExceptionVector	.32	2012	0\n"
		"gpr	DoubleExceptionVector	.32	2016	0\n"
		"gpr	accx_0	.32	3000	0\n"
		"gpr	accx_1	.32	3004	0\n"
		"gpr	bithead	.32	3008	0\n"
		"gpr	bitptr	.32	3012	0\n"
		"gpr	bitsused	.32	3016	0\n"
		"gpr	cbegin0	.32	3020	0\n"
		"gpr	cend0	.32	3024	0\n"
		"gpr	cwrap	.32	3028	0\n"
		"gpr	cw_sd_no	.32	3032	0\n"
		"gpr	first_ts	.32	3036	0\n"
		"gpr	nextoffset	.32	3040	0\n"
		"gpr	overflow	.32	3044	0\n"
		"gpr	ovf_sar	.32	3048	0\n"
		"gpr	sar	.32	3052	0\n"
		"gpr	searchdone	.32	3056	0\n"
		"gpr	tablesize	.32	3060	0\n"
		"gpr	ts_fts_bu_bp	.32	3064	0\n"
		"gpr	fft_bit_width	.32	3068	0\n"
		"gpr	gpio_out	.32	3072	0\n"
		"gpr	qacc_h_0	.32	3076	0\n"
		"gpr	qacc_h_1	.32	3080	0\n"
		"gpr	qacc_h_2	.32	3084	0\n"
		"gpr	qacc_h_3	.32	3088	0\n"
		"gpr	qacc_h_4	.32	3092	0\n"
		"gpr	qacc_l_0	.32	3096	0\n"
		"gpr	qacc_l_1	.32	3100	0\n"
		"gpr	qacc_l_2	.32	3104	0\n"
		"gpr	qacc_l_3	.32	3108	0\n"
		"gpr	qacc_l_4	.32	3112	0\n"
		"gpr	sar_byte	.32	3116	0\n"
		"gpr	ua_state_0	.32	3120	0\n"
		"gpr	ua_state_1	.32	3124	0\n"
		"gpr	ua_state_2	.32	3128	0\n"
		"gpr	ua_state_3	.32	3132	0\n"
		"gpr	windowunderflow4	.32	3136	0\n"
		"gpr	windowunderflow8	.32	3140	0\n"
		"gpr	windowunderflow12	.32	3144	0\n"

		"gpr	fcr	.32	4000	0\n"
		"gpr	fsr	.32	4004	0\n"

		// pc
		"gpr	pc	.32	68	0\n"

		// sr
		"gpr	sar	.32	72	0\n");
}

static RzTypeCond xtensa_cond(xtensa_insn insn) {
	switch (insn) {
	case XTENSA_INS_BEQI: return RZ_TYPE_COND_EQ;
	case XTENSA_INS_BNEI: return RZ_TYPE_COND_NE;
	case XTENSA_INS_BGEI: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BGEUI: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTUI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BBCI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BBSI: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BEQ: return RZ_TYPE_COND_EQ;
	case XTENSA_INS_BNE: return RZ_TYPE_COND_NE;
	case XTENSA_INS_BGE: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLT: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BGEU: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTU: return RZ_TYPE_COND_LT;
	case XTENSA_INS_BANY:
	case XTENSA_INS_BNONE:
	case XTENSA_INS_BALL:
	case XTENSA_INS_BNALL:
	case XTENSA_INS_BBC:
	case XTENSA_INS_BBS: break;
	case XTENSA_INS_BEQZ: return RZ_TYPE_COND_EQ;
	case XTENSA_INS_BNEZ: return RZ_TYPE_COND_NE;
	case XTENSA_INS_BGEZ: return RZ_TYPE_COND_GE;
	case XTENSA_INS_BLTZ: return RZ_TYPE_COND_LT;
	default: break;
	}
	return RZ_TYPE_COND_AL;
}

static void xop_to_rval(RzAnalysis *a, XtensaContext *ctx, cs_xtensa_op *xop, RzAnalysisValue **prv) {
	RzAnalysisValue *rv = rz_analysis_value_new();
	if (!rv) {
		return;
	}

	if (xop->access & CS_AC_WRITE) {
		rv->access |= RZ_ANALYSIS_ACC_W;
	}
	if (xop->access & CS_AC_READ) {
		rv->access |= RZ_ANALYSIS_ACC_R;
	}
	switch (xop->type) {
	case XTENSA_OP_REG:
		rv->reg = rz_reg_get(a->reg, cs_reg_name(ctx->handle, xop->reg), RZ_REG_TYPE_ANY);
		rv->type = RZ_ANALYSIS_VAL_REG;
		break;
	case XTENSA_OP_IMM:
		rv->imm = xop->imm;
		rv->type = RZ_ANALYSIS_VAL_IMM;
		break;
	case XTENSA_OP_MEM:
		rv->reg = rz_reg_get(a->reg, cs_reg_name(ctx->handle, xop->mem.base), RZ_REG_TYPE_ANY);
		rv->delta = xop->mem.disp;
		rv->type = RZ_ANALYSIS_VAL_MEM;
		break;
	case XTENSA_OP_L32R:
		rv->reg = rz_reg_get(a->reg, "pc", RZ_REG_TYPE_ANY);
		rv->delta = xop->imm;
		rv->type = RZ_ANALYSIS_VAL_MEM;
		break;
	default:
		rv->type = RZ_ANALYSIS_VAL_UNK;
		break;
	}
	if (*prv) {
		rz_analysis_value_free(*prv);
	}
	*prv = rv;
}

static void xtensa_analyze_op(RzAnalysis *a, RzAnalysisOp *op, XtensaContext *ctx) {
	int src_count = 0;
	for (int i = 0; i < ctx->insn->detail->xtensa.op_count; ++i) {
		if (src_count >= RZ_ARRAY_SIZE(op->src)) {
			rz_warn_if_reached();
			break;
		}

		cs_xtensa_op *xop = XOP(i);
		if (xop->access & CS_AC_WRITE) {
			xop_to_rval(a, ctx, xop, &op->dst);
		}
		if (xop->access & CS_AC_READ) {
			xop_to_rval(a, ctx, xop, &op->src[src_count++]);
		}
	}

	switch (ctx->insn->id) {
	case XTENSA_INS_ADD: /* add */
	case XTENSA_INS_ADDX2: /* addx2 */
	case XTENSA_INS_ADDX4: /* addx4 */
	case XTENSA_INS_ADDX8: /* addx8 */
	case XTENSA_INS_ADD_N:
	case XTENSA_INS_ADD_S:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_SUB: /* sub */
	case XTENSA_INS_SUBX2: /* subx2 */
	case XTENSA_INS_SUBX4: /* subx4 */
	case XTENSA_INS_SUBX8: /* subx8 */
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case XTENSA_INS_MOVI:
	case XTENSA_INS_MOVI_N:
	case XTENSA_INS_MOV_S:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case XTENSA_INS_EXCW:
	case XTENSA_INS_NOP: /* nop.n */
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case XTENSA_INS_S32I: /* s32i */
	case XTENSA_INS_S16I: /* s16i */
	case XTENSA_INS_S8I: /* s8i */
	case XTENSA_INS_S32I_N:
	case XTENSA_INS_S32C1I:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		if (XOP(1)->type == XTENSA_OP_MEM && MEM(1)->base == XTENSA_REG_SP) {
			op->type = RZ_ANALYSIS_OP_TYPE_PUSH;
		}
		break;
	case XTENSA_INS_ADDI: /* addi */
	case XTENSA_INS_ADDI_N: {
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		// a1 = stack
		if (REGI(0) == XTENSA_REG_SP && REGI(1) == XTENSA_REG_SP) {
			op->val = IMM(2);
			op->stackptr = -IMM(2);
			op->stackop = RZ_ANALYSIS_STACK_INC;
		}
		break;
	}
	case XTENSA_INS_RET: /* ret */
	case XTENSA_INS_RET_N:
	case XTENSA_INS_RETW_N:
		op->eob = true;
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case XTENSA_INS_L16UI: /* l16ui */
	case XTENSA_INS_L16SI: /* l16si */
	case XTENSA_INS_L32I: /* l32i */
	case XTENSA_INS_L8UI: /* l8ui */
	case XTENSA_INS_L32I_N:
	case XTENSA_INS_L32R:
	case XTENSA_INS_L32E:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		if (XOP(1)->type == XTENSA_OP_MEM && MEM(1)->base == XTENSA_REG_SP) {
			op->type = RZ_ANALYSIS_OP_TYPE_POP;
		}
		break;
	case XTENSA_INS_ADDMI: /* addmi */
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case XTENSA_INS_AND: /* and */
	case XTENSA_INS_OR: /* or */
	case XTENSA_INS_XOR: /* xor */
		op->type = RZ_ANALYSIS_OP_TYPE_COND;
		break;
	case XTENSA_INS_BEQZ: /* beqz */
	case XTENSA_INS_BNEZ: /* bnez */
	case XTENSA_INS_BGEZ: /* bgez */
	case XTENSA_INS_BLTZ: /* bltz */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + IMM(1);
		op->fail = ctx->insn->address + ctx->insn->size;
		op->cond = xtensa_cond(ctx->insn->id);
		break;
	case XTENSA_INS_BEQ:
	case XTENSA_INS_BNE:
	case XTENSA_INS_BGE:
	case XTENSA_INS_BLT:
	case XTENSA_INS_BGEU: /* bgeu */
	case XTENSA_INS_BLTU: /* bltu */
	case XTENSA_INS_BEQI: /* beqi */
	case XTENSA_INS_BNEI: /* bnei */
	case XTENSA_INS_BGEI: /* bgei */
	case XTENSA_INS_BLTI: /* blti */
	case XTENSA_INS_BGEUI: /* bgeui */
	case XTENSA_INS_BLTUI: /* bltui */
	case XTENSA_INS_BANY: /* bany */
	case XTENSA_INS_BNONE: /* bnone */
	case XTENSA_INS_BALL: /* ball */
	case XTENSA_INS_BNALL: /* bnall */
	case XTENSA_INS_BBCI: /* bbci */
	case XTENSA_INS_BBSI: /* bbsi */
	case XTENSA_INS_BBC: /* bbc */
	case XTENSA_INS_BBS: /* bbs */
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + IMM(2);
		op->fail = ctx->insn->address + ctx->insn->size;
		op->cond = xtensa_cond(ctx->insn->id);
		break;
	case XTENSA_INS_EXTUI: /* extui */
		op->type = RZ_ANALYSIS_OP_TYPE_CAST;
		break;
	case XTENSA_INS_J: /* j */
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = ctx->insn->address + IMM(0);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case XTENSA_INS_CALLX0: /* callx0 */
	case XTENSA_INS_CALLX4:
	case XTENSA_INS_CALLX8:
	case XTENSA_INS_CALLX12:
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->reg = REGN(0);
		break;
	case XTENSA_INS_CALL0: /* call0 */
	case XTENSA_INS_CALL4:
	case XTENSA_INS_CALL8:
	case XTENSA_INS_CALL12:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ctx->insn->address + IMM(0)) & ~3;
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case XTENSA_INS_MOVEQZ: /* moveqz */
	case XTENSA_INS_MOVNEZ: /* movnez */
	case XTENSA_INS_MOVLTZ: /* movltz */
	case XTENSA_INS_MOVGEZ: /* movgez */
		op->type = RZ_ANALYSIS_OP_TYPE_CMOV;
		break;
	case XTENSA_INS_ABS: /* abs */
	case XTENSA_INS_ABS_S:
		op->type = RZ_ANALYSIS_OP_TYPE_ABS;
		break;
	case XTENSA_INS_NEG: /* neg */
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		break;
	case XTENSA_INS_SSR: /* ssr */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case XTENSA_INS_SSL: /* ssl */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case XTENSA_INS_SLLI: /* slli */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case XTENSA_INS_SRLI: /* srli */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case XTENSA_INS_SSAI: /* ssai */
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case XTENSA_INS_SLL: /* sll */
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case XTENSA_INS_SRL: /* srl */
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	}
}

static int xtensa_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	XtensaContext *ctx = analysis->plugin_data;
	if (!xtensa_open(ctx, analysis->cpu, analysis->big_endian)) {
		goto beach;
	}
	if (!xtensa_disassemble(ctx, buf, len, addr)) {
		goto beach;
	}

	op->size = ctx->insn->size;
	op->id = ctx->insn->id;
	op->addr = addr;
	xtensa_analyze_op(analysis, op, ctx);

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf(
			"%s%s%s",
			ctx->insn->mnemonic,
			ctx->insn->op_str[0] ? " " : "",
			ctx->insn->op_str);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		xtensa_analyze_op_esil(ctx, op);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		xtensa_analyze_op_rzil(ctx, op);
	}

	xtensa_disassemble_fini(ctx);
	return op->size;
beach:
	xtensa_disassemble_fini(ctx);
	return -1;
}

RzAnalysisPlugin rz_analysis_plugin_xtensa_cs = {
	.name = "xtensa",
	.desc = "Capstone Xtensa analysis plugin",
	.author = "billow",
	.license = "LGPL3",
	.arch = "xtensa",
	.bits = 8,
	.op = xtensa_op,
	.esil = true,
	.il_config = xtensa_il_config,
	.archinfo = xtensa_archinfo,
	.get_reg_profile = xtensa_get_reg_profile,
	.init = xtensa_init,
	.fini = xtensa_fini,
};
