// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_lib.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_endian.h>

#include <v850_disas.h>
#include "../arch/v850/v850_il.h"

#include "../arch/v850/v850_esil.inc"

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
	case V850_MOV_IMM5:
	case V850_MOV:
	case V850_MOVEA:
	case V850_MOVHI:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		if (inst.reg2 == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		if (inst.reg2 == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
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
		if (inst.reg1 == 31) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		}
		op->jump = -1;
		op->reg = GR_get(inst.reg1);
		op->disp = inst.disp;
		op->fail = addr + inst.byte_size;
		break;
	case V850_JARL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + inst.disp;
		op->fail = addr + inst.byte_size;
		break;
	case V850_JR:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + inst.disp;
		op->fail = addr + inst.byte_size;
		break;
	case V850_OR:
	case V850_ORI:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case V850_MULH:
	case V850_MULH_IMM5:
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
	case V850_CMP_IMM5:
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
	case V850_SATADD_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case V850_ADD_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (inst.reg2 == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = inst.imm;
			op->val = op->stackptr;
		}
		break;
	case V850_ADDI:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (inst.reg2 == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = (st64)inst.w2;
			op->val = op->stackptr;
		}
		break;
	case V850_SHR_IMM5:
	case V850_SHR:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case V850_SAR:
	case V850_SAR_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case V850_SHL:
	case V850_SHL_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case V850_BCOND:
		op->jump = addr + inst.disp;
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

	return ret;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
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
		"gpr	r3	.32	12  0\n"
		"gpr	sp	.32	12  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	gp	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
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
		"gpr	r30	.32	120 0\n"
		"gpr	ep	.32	120 0\n"
		"gpr	lp	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		"gpr	EIPC	.32	132	0\n"
		"gpr	EIPSW	.32	136	0\n"
		"gpr	FEPC	.32	140	0\n"
		"gpr	FEPSW	.32	144	0\n"
		"gpr	ECR	.32	148	0\n"
		"gpr	PSW	.32	152	0\n"
		"gpr	RES6	.32	156	0\n"
		"gpr	RES7	.32	160	0\n"
		"gpr	RES8	.32	164	0\n"
		"gpr	RES9	.32	168	0\n"
		"gpr	RES10	.32	172	0\n"
		"gpr	RES11	.32	176	0\n"
		"gpr	RES12	.32	180	0\n"
		"gpr	RES13	.32	188	0\n"
		"gpr	RES14	.32	192	0\n"
		"gpr	RES15	.32	196	0\n"
		"gpr	RES16	.32	200	0\n"
		"gpr	RES17	.32	204	0\n"
		"gpr	RES18	.32	208	0\n"
		"gpr	RES19	.32	212	0\n"
		"gpr	RES20	.32	216	0\n"
		"gpr	RES21	.32	220	0\n"
		"gpr	RES22	.32	224	0\n"
		"gpr	RES23	.32	228	0\n"
		"gpr	RES24	.32	232	0\n"
		"gpr	RES25	.32	236	0\n"
		"gpr	RES26	.32	240	0\n"
		"gpr	RES27	.32	244	0\n"
		"gpr	RES28	.32	248	0\n"
		"gpr	RES29	.32	252	0\n"
		"gpr	RES30	.32	256	0\n"
		"gpr	RES31	.32	260	0\n"
		// 32bit [   RFU   ][NP EP ID SAT CY OV S Z]
		"gpr	npi  .1 152.16 0\n" // non maskerable interrupt (NMI)
		"gpr	epi  .1 152.17 0\n" // exception processing interrupt
		"gpr	id   .1 152.18 0\n" // :? should be id
		"gpr	sat  .1 152.19 0\n" // saturation detection
		"flg	cy  .1 152.28 0\n" // carry or borrow
		"flg	ov  .1 152.29 0\n" // overflow
		"flg	s   .1 152.30 0\n" // signed result
		"flg	z   .1 152.31 0\n"; // zero result
	return strdup(p);
}

static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	KW("\x80\x07", 2, "\xf0\xff", 2);
	KW("\x50\x1a\x63\x0f", 4, "\xf0\xff\xff\x0f", 4);
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
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_v850,
	.version = RZ_VERSION
};
#endif
