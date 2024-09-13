// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_lib.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_endian.h>

#include <v850/v850_disas.h>
#include <v850/v850_esil.inc>
#include <v850/v850_il.h>

static int v850_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret = 0;
	V850_Inst inst = { 0 };
	inst.addr = addr;

	if (len < 1 || !memcmp(buf, "\xff\xff\xff\xff\xff\xff", RZ_MIN(len, 6))) {
		return -1;
	}

	ret = op->size = v850_decode_command(buf, len, &inst);

	if (ret < 1) {
		return ret;
	}

	op->addr = addr;

	switch (inst.id) {
	case V850_MOV:
	case V850_MOVEA:
	case V850_MOVHI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case V850_SLDB:
	case V850_SLDBU:
	case V850_SLDH:
	case V850_SLDHU:
	case V850_SLDW:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case V850_LDB:
	case V850_LDBU:
	case V850_LDH:
	case V850_LDHU:
	case V850_LDW:
	case V850_LDDW: {
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		RzAnalysisValue *v = op->src[0] = rz_analysis_value_new();
		v->type = RZ_ANALYSIS_VAL_MEM;
		v->reg = rz_reg_get(analysis->reg, GR_get(get_reg1(&inst)), RZ_REG_TYPE_ANY);
		v->delta = inst.sdisp;

		v = op->dst = rz_analysis_value_new();
		v->type = RZ_ANALYSIS_VAL_REG;
		v->reg = rz_reg_get(analysis->reg, GR_get(get_reg2(&inst)), RZ_REG_TYPE_ANY);

		if (get_reg1(&inst) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;

			switch (inst.id) {
			case V850_LDB:
			case V850_LDBU: op->ptrsize = op->refptr = 1; break;
			case V850_LDH:
			case V850_LDHU: op->ptrsize = op->refptr = 2; break;
			case V850_LDW: op->ptrsize = op->refptr = 4; break;
			case V850_LDDW: op->ptrsize = op->refptr = 8; break;
			default: break;
			}
		}
		break;
	}
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case V850_STB:
	case V850_STH:
	case V850_STW:
	case V850_STDW: {
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;

		RzAnalysisValue *v = op->dst = rz_analysis_value_new();
		v->type = RZ_ANALYSIS_VAL_MEM;
		v->reg = rz_reg_get(analysis->reg, GR_get(get_reg1(&inst)), RZ_REG_TYPE_ANY);
		v->delta = inst.sdisp;

		v = op->src[0] = rz_analysis_value_new();
		v->type = RZ_ANALYSIS_VAL_REG;
		v->reg = rz_reg_get(analysis->reg, GR_get(get_reg2(&inst)), RZ_REG_TYPE_ANY);

		if (get_reg1(&inst) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->ptr = 0;

			switch (inst.id) {
			case V850_STB: op->ptrsize = op->stackptr = 1; break;
			case V850_STH: op->ptrsize = op->stackptr = 2; break;
			case V850_STW: op->ptrsize = op->stackptr = 4; break;
			case V850_STDW: op->ptrsize = op->stackptr = 8; break;
			default: break;
			}
		}
		break;
	}
	case V850_NOT:
	case V850_NOT1:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case V850_DIV:
	case V850_DIVU:
	case V850_DIVH:
	case V850_DIVHU:
	case V850_DIVQ:
	case V850_DIVQU:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case V850_JMP:
		if (get_reg1(&inst) == 31) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		}
		op->jump = -1;
		op->reg = GR_get(get_reg1(&inst));
		op->disp = inst.disp;
		op->fail = addr + inst.byte_size;
		break;
	case V850_DISPOSE:
		if (xiii_sub_r1(&inst)) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		}
		break;
	case V850_CTRET:
	case V850_EIRET:
	case V850_FERET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case V850_CALLT:
	case V850_SYSCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->disp = -1;
		break;
	case V850_TRAP:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (get_reg1(&inst) >= 0 && get_reg1(&inst) <= 0xf) ? 0x40 : 0x50;
		op->fail = addr + inst.byte_size;
		break;
	case V850_FETRAP:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = i_vec4(&inst) + 0x30;
		op->fail = addr + inst.byte_size;
		break;
	case V850_LOOP:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr - inst.disp;
		op->fail = addr + inst.byte_size;
		break;
	case V850_JARL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + (st32)(inst.disp);
		op->fail = addr + inst.byte_size;
		break;
	case V850_SWITCH:
		op->type = RZ_ANALYSIS_OP_TYPE_IJMP;
		op->jump = -1;
		break;
	case V850_JR:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + (st32)(inst.disp);
		op->fail = addr + inst.byte_size;
		break;
	case V850_OR:
	case V850_ORI:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case V850_MULH:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case V850_XOR:
	case V850_XORI:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case V850_AND:
	case V850_ANDI:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case V850_CMP:
	case V850_TST:
	case V850_TST1:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case V850_SUB:
	case V850_SUBR:
	case V850_SATSUB:
	case V850_SATSUBI:
	case V850_SATSUBR:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case V850_ADD:
	case V850_SATADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (inst.format == II_imm_reg && get_reg2(&inst) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = (st32)inst.imm;
			op->val = op->stackptr;
		}
		break;
	case V850_ADDI:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (get_reg2(&inst) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = (st16)get_imm16(&inst);
			op->val = op->stackptr;
		}
		break;
	case V850_SHR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case V850_SAR:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case V850_SHL:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case V850_BCOND:
		op->jump = addr + (st32)(inst.disp);
		op->fail = addr + inst.byte_size;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	default: break;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		v850_esil(&op->esil, &inst);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s %s", inst.instr, inst.operands);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		V850AnalysisContext ctx = { 0 };
		ctx.a = analysis;
		ctx.x = &inst;

		op->il_op = v850_il_op(&ctx);
	}

	return ret;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=ZF	z\n"
		"=A0	r1\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=A4	r8\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"
		"gpr	zero	.32	?   0\n"
		"gpr	r0	.32	0   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	sp	.32	12  0\n"
		"gpr	gp	.32	16  0\n"
		"gpr	tp	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	ep	.32	120 0\n"
		"gpr	lp	.32	124 0\n"
		"gpr	pc	.32	128 0\n"
		"gpr	r30	.32	120 0\n"

		/*
		 * \see Section 3.3-3.5  https://www.renesas.com/us/en/document/mas/rh850g3kh-users-manual-software
		 * regID		Symbol		*/
		/*0 */ "gpr	EIPC	.32	132	0\n"
		/*1 */ "gpr	EIPSW	.32	136	0\n"
		/*2 */ "gpr	FEPC	.32	140	0\n"
		/*3 */ "gpr	FEPSW	.32	144	0\n"
		/*4 */ "gpr	ECR	.32	148	0\n"
		/*5 */ "gpr	PSW	.32	152	0\n"
		/*6 */ "gpr	FPSR	.32	156	0\n"
		/*7 */ "gpr	FPEPC	.32	160	0\n"
		/*8 */ "gpr	FPST	.32	164	0\n"
		/*9 */ "gpr	FPCC	.32	168	0\n"
		/*10*/ "gpr	FPCFG	.32	172	0\n"
		/*11*/ "gpr	FPEC	.32	176	0\n"
		/*12*/
		/*13*/ "gpr	EIIC	.32	184	0\n"
		/*14*/ "gpr	FEIC	.32	188	0\n"
		/*16*/ "gpr	CTPC	.32	196	0\n"
		/*17*/ "gpr	CTPSW	.32	200	0\n"
		/*20*/ "gpr	CTBP	.32	212	0\n"
		/*28*/ "gpr	EIWR	.32	240	0\n"
		/*29*/ "gpr	FEWR	.32	244	0\n"
		/*31*/ "gpr	BSEL	.32	256	0\n"
		/*0 */ "gpr	MCFG0	.32	260	0\n"
		/*2 */ "gpr	RBASE	.32	268	0\n"
		/*3 */ "gpr	EBASE	.32	272	0\n"
		/*4 */ "gpr	INTBP	.32	276	0\n"
		/*5 */ "gpr	MCTL	.32	280	0\n"
		/*6 */ "gpr	PID	.32	284	0\n"
		/*7 */ "gpr	FPIPR	.32	288	0\n"
		/*11*/ "gpr	SCCFG	.32	304	0\n"
		/*12*/ "gpr	SCBP	.32	308	0\n"
		/*0 */ "gpr	HTCFG0	.32	388	0\n"
		/*6 */ "gpr	MEA	.32	412	0\n"
		/*7 */ "gpr	ASID	.32	416	0\n"
		/*8 */ "gpr	MEI	.32	420	0\n"
		/*10*/ "gpr	ISPR	.32	428	0\n"
		/*11*/ "gpr	PMR	.32	432	0\n"
		/*12*/ "gpr	ICSR	.32	436	0\n"
		/*13*/ "gpr	INTCFG	.32	440	0\n"
		/*0 */ "gpr	MPM	.32	516	0\n"
		/*1 */ "gpr	MPRC	.32	520	0\n"
		/*4 */ "gpr	MPBRGN	.32	532	0\n"
		/*5 */ "gpr	MPTRGN	.32	536	0\n"
		/*8 */ "gpr	MCA	.32	548	0\n"
		/*9 */ "gpr	MCS	.32	552	0\n"
		/*10*/ "gpr	MCC	.32	556	0\n"
		/*11*/ "gpr	MCR	.32	560	0\n"
		/*0 */ "gpr	MPLA0	.32	644	0\n"
		/*1 */ "gpr	MPUA0	.32	648	0\n"
		/*2 */ "gpr	MPAT0	.32	652	0\n"
		/*4 */ "gpr	MPLA1	.32	660	0\n"
		/*5 */ "gpr	MPUT1	.32	664	0\n"
		/*6 */ "gpr	MPAT1	.32	668	0\n"
		/*8 */ "gpr	MPLA2	.32	676	0\n"
		/*9 */ "gpr	MPUA2	.32	680	0\n"
		/*10*/ "gpr	MPAT2	.32	684	0\n"
		/*12*/ "gpr	MPLA3	.32	692	0\n"
		/*13*/ "gpr	MPUA3	.32	696	0\n"
		/*14*/ "gpr	MPAT3	.32	700	0\n"
		/*16*/ "gpr	MPLA4	.32	708	0\n"
		/*17*/ "gpr	MPUA4	.32	712	0\n"
		/*18*/ "gpr	MPAT4	.32	716	0\n"
		/*20*/ "gpr	MPLA5	.32	724	0\n"
		/*21*/ "gpr	MPUA5	.32	728	0\n"
		/*22*/ "gpr	MPAT5	.32	732	0\n"
		/*24*/ "gpr	MPLA6	.32	740	0\n"
		/*25*/ "gpr	MPUA6	.32	744	0\n"
		/*26*/ "gpr	MPAT6	.32	748	0\n"
		/*28*/ "gpr	MPLA7	.32	756	0\n"
		/*29*/ "gpr	MPUA7	.32	760	0\n"
		/*30*/ "gpr	MPAT7	.32	764	0\n"
		/*0 */ "gpr	MPLA8	.32	772	0\n"
		/*1 */ "gpr	MPUA8	.32	776	0\n"
		/*2 */ "gpr	MPAT8	.32	780	0\n"
		/*4 */ "gpr	MPLA9	.32	788	0\n"
		/*5 */ "gpr	MPUT9	.32	792	0\n"
		/*6 */ "gpr	MPAT9	.32	796	0\n"
		/*8 */ "gpr	MPLA10	.32	804	0\n"
		/*9 */ "gpr	MPUA10	.32	808	0\n"
		/*10*/ "gpr	MPAT10	.32	812	0\n"
		/*12*/ "gpr	MPLA11	.32	820	0\n"
		/*13*/ "gpr	MPUA11	.32	824	0\n"
		/*14*/ "gpr	MPAT11	.32	828	0\n"
		/*16*/ "gpr	MPLA12	.32	836	0\n"
		/*17*/ "gpr	MPUA12	.32	840	0\n"
		/*18*/ "gpr	MPAT12	.32	844	0\n"
		/*20*/ "gpr	MPLA13	.32	852	0\n"
		/*21*/ "gpr	MPUA13	.32	856	0\n"
		/*22*/ "gpr	MPAT13	.32	860	0\n"
		/*24*/ "gpr	MPLA14	.32	868	0\n"
		/*25*/ "gpr	MPUA14	.32	872	0\n"
		/*26*/ "gpr	MPAT14	.32	876	0\n"
		/*28*/ "gpr	MPLA15	.32	884	0\n"
		/*29*/ "gpr	MPUA15	.32	888	0\n"
		/*30*/ "gpr	MPAT15	.32	892	0\n"
		// 32bit [   RFU   ][NP EP ID SAT CY OV S Z]
		"gpr	npi  .1 152.16 0\n" // non maskerable interrupt (NMI)
		"gpr	epi  .1 152.17 0\n" // exception processing interrupt
		"gpr	id   .1 152.18 0\n" // :? should be id
		"gpr	sat  .1 152.19 0\n" // saturation detection
		"flg	cy  .1 152.28 0\n" // carry or borrow
		"flg	ov  .1 152.29 0\n" // overflow
		"flg	s   .1 152.30 0\n" // signed result
		"flg	z   .1 152.31 0\n"; // zero result
	return rz_str_dup(p);
}

/**
 * All preludes are guessed by looking at the instruction at the beginning of the function
 */
static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);

	// movea 0xff, r0, r20
	KW("\x20\xa6\xff\x00", 4, "\xff\xff\xff\xff", 4);

	// mov r6, r7
	// ld.w ?[gp], r6
	// prepare {lp}, 0
	KW("\x06\x38\x24\x37\x01\x00\x80\x07\x21\x00", 10, "\xff\xff\xff\xff\x01\x00\xff\xff\xff\xff", 10);

	// ld.w ?[gp], r6
	// prepare {lp}, 0
	KW("\x24\x37\x01\x00\x80\x07\x21\x00", 8, "\xff\xff\x01\x00\xff\xff\xff\xff", 8);

	// prepare
	KW("\x80\x07\x01\x00", 4, "\xc0\xff\x1f\x00", 4);
	KW("\x80\x07\x03\x00", 4, "\xc0\xff\x1f\x00", 4);
	KW("\x80\x07\x0b\x00\x00\x00", 6, "\xc0\xff\x1f\x00\x00\x00", 6);
	KW("\x80\x07\x13\x00\x00\x00", 6, "\xc0\xff\x1f\x00\x00\x00", 6);
	KW("\x80\x07\x1b\x00\x00\x00\x00\x00", 8, "\xc0\xff\x1f\x00\x00\x00\x00\x00", 8);

	// trap
	KW("\xe0\x07\x00\x01", 4, "\xe0\xff\xff\xff", 4);

	// addi ?, sp, sp
	KW("\x03\x1e\xd0\xff", 4, "\xff\xff\xff\xff", 4);

	// add ?, sp
	KW("\x50\x1a", 2, "\xf0\xff", 2);
	return l;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 0;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_v850 = {
	.name = "v850",
	.desc = "V850 code analysis plugin",
	.license = "LGPL3",
	.preludes = analysis_preludes,
	.arch = "v850",
	.bits = 32,
	.op = v850_op,
	.esil = true,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.il_config = v850_il_config
};
