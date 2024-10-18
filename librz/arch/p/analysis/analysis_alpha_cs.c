// SPDX-FileCopyrightText: 2023 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <capstone/capstone.h>
#include <capstone/alpha.h>

#include <alpha/alpha.inc>

static char *get_reg_profile(RzAnalysis *_) {
	const char *p =
		"=PC	pc\n"
		"=SP	r30\n"
		"=R0	r0\n"
		"=A0	r16\n"
		"=A1	r17\n"
		"=A2	r18\n"
		"=A3	r19\n"
		"=A4	r20\n"
		"gpr	r0	.64	0	0\n"
		"gpr	r1	.64	8	0\n"
		"gpr	r2	.64	16	0\n"
		"gpr	r3	.64	24	0\n"
		"gpr	r4	.64	32	0\n"
		"gpr	r5	.64	40	0\n"
		"gpr	r6	.64	48	0\n"
		"gpr	r7	.64	56	0\n"
		"gpr	r8	.64	64	0\n"
		"gpr	r9	.64	72	0\n"
		"gpr	r10	.64	80	0\n"
		"gpr	r11	.64	88	0\n"
		"gpr	r12	.64	96	0\n"
		"gpr	r13	.64	104	0\n"
		"gpr	r14	.64	112	0\n"
		"gpr	r15	.64	120	0\n"
		"gpr	r16	.64	128	0\n"
		"gpr	r17	.64	136	0\n"
		"gpr	r18	.64	144	0\n"
		"gpr	r19	.64	152	0\n"
		"gpr	r20	.64	160	0\n"
		"gpr	r21	.64	168	0\n"
		"gpr	r22	.64	176	0\n"
		"gpr	r23	.64	184	0\n"
		"gpr	r24	.64	192	0\n"
		"gpr	r25	.64	200	0\n"
		"gpr	r26	.64	208	0\n"
		"gpr	r27	.64	216	0\n"
		"gpr	r28	.64	224	0\n"
		"gpr	r29	.64	232	0\n"
		"gpr	r30	.64	240	0\n"
		"gpr	r31	.64	248	0\n" // always zero
		"fpu	f0	.64	256	0\n"
		"fpu	f1	.64	264	0\n"
		"fpu	f2	.64	272	0\n"
		"fpu	f3	.64	280	0\n"
		"fpu	f4	.64	288	0\n"
		"fpu	f5	.64	296	0\n"
		"fpu	f6	.64	304	0\n"
		"fpu	f7	.64	312	0\n"
		"fpu	f8	.64	320	0\n"
		"fpu	f9	.64	328	0\n"
		"fpu	f10	.64	336	0\n"
		"fpu	f11	.64	344	0\n"
		"fpu	f12	.64	352	0\n"
		"fpu	f13	.64	360	0\n"
		"fpu	f14	.64	368	0\n"
		"fpu	f15	.64	376	0\n"
		"fpu	f16	.64	384	0\n"
		"fpu	f17	.64	392	0\n"
		"fpu	f18	.64	400	0\n"
		"fpu	f19	.64	408	0\n"
		"fpu	f20	.64	416	0\n"
		"fpu	f21	.64	424	0\n"
		"fpu	f22	.64	432	0\n"
		"fpu	f23	.64	440	0\n"
		"fpu	f24	.64	448	0\n"
		"fpu	f25	.64	456	0\n"
		"fpu	f26	.64	464	0\n"
		"fpu	f27	.64	472	0\n"
		"fpu	f28	.64	480	0\n"
		"fpu	f29	.64	488	0\n"
		"fpu	f30	.64	496	0\n"
		"fpu	f31	.64	504	0\n"
		"gpr	lr0	.64	512	0\n"
		"gpr	lr1	.64	520	0\n"
		"flg	fpcr .64	528	0\n"
		"gpr	pc .64	536	0\n";
	return strdup(p);
}

static inline void fill_from_alpha_op(RzReg *rz_reg, csh handle, RzAnalysisValue *av, cs_alpha_op *op) {
	switch (op->type) {
	case ALPHA_OP_INVALID:
	default:
		av->type = RZ_ANALYSIS_VAL_UNK;
		break;
	case ALPHA_OP_IMM:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = op->imm;
		break;
	case ALPHA_OP_REG:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(rz_reg, cs_reg_name(handle, op->reg), RZ_REG_TYPE_ANY);
		break;
	}
}

static void alpha_fillval(RzAsmAlphaContext *ctx, RzAnalysis *a, RzAnalysisOp *op) {
	if (!ctx->insn->detail) {
		return;
	}
	uint8_t srci = 0;
	cs_alpha *al = &ctx->insn->detail->alpha;
	if (!al) {
		return;
	}
	for (uint8_t i = 0; i < al->op_count; ++i) {
		cs_alpha_op *alphaop = &al->operands[i];
		RzAnalysisValue *av = rz_analysis_value_new();
		fill_from_alpha_op(a->reg, ctx->h, av, alphaop);
		if (alphaop->access & CS_AC_READ) {
			av->access |= RZ_ANALYSIS_ACC_R;
			op->src[srci++] = av;
		}
		if (alphaop->access & CS_AC_WRITE) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (op->dst) {
				rz_warn_if_reached();
			}
			if (av == op->src[srci - 1]) {
				av = rz_mem_dup(av, sizeof(RzAnalysisValue));
			}
			op->dst = av;
		}
	}
}

static void alpha_opex(RzAsmAlphaContext *ctx, RzStrBuf *ptr) {
	if (!ctx->insn->detail) {
		return;
	}
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_alpha *al = &ctx->insn->detail->alpha;
	for (st32 i = 0; i < al->op_count; i++) {
		cs_alpha_op *op = al->operands + i;
		pj_o(pj);
		switch (op->type) {
		case ALPHA_OP_INVALID: {
			pj_ks(pj, "type", "invalid");
			break;
		}
		case ALPHA_OP_REG: {
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(ctx->h, op->reg));
			break;
		}
		case ALPHA_OP_IMM: {
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
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

static void alpha_op_set_type(RzAsmAlphaContext *ctx, RzAnalysisOp *op) {
	switch (ctx->insn->id) {
	default: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case Alpha_INS_BEQ:
	case Alpha_INS_BGE:
	case Alpha_INS_BGT:
	case Alpha_INS_BLBC:
	case Alpha_INS_BLBS:
	case Alpha_INS_BLE:
	case Alpha_INS_BLT:
	case Alpha_INS_BNE:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = (ut32)alpha_op_as_imm(ctx, 1);
		op->fail = op->addr + op->size;
		break;
	case Alpha_INS_BR:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = (ut32)alpha_op_as_imm(ctx, 0);
		break;
	case Alpha_INS_BSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = (ut32)alpha_op_as_imm(ctx, 0);
		op->fail = op->addr + op->size;
		break;
	case Alpha_INS_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		op->stackptr = 8;
		op->fail = op->addr + op->size;
		break;
	case Alpha_INS_JMP:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + op->size;
		break;
	case Alpha_INS_JSR:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->stackop = RZ_ANALYSIS_STACK_SET;
		op->jump = op->addr + 4;
		op->stackptr = 8;
		op->fail = UT64_MAX;
		break;
	case Alpha_INS_JSR_COROUTINE:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		// This one is a weird one, pops from stack then pushes PC
		op->stackop = RZ_ANALYSIS_STACK_GET;
		op->fail = op->addr + op->size;
		break;
	case Alpha_INS_LDA:
	case Alpha_INS_LDAH:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	case Alpha_INS_LDBU:
	case Alpha_INS_LDL:
	case Alpha_INS_LDL_L:
	case Alpha_INS_LDQ:
	case Alpha_INS_LDQ_L:
	case Alpha_INS_LDQ_U:
	case Alpha_INS_LDS:
	case Alpha_INS_LDT:
	case Alpha_INS_LDWU:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;

	case Alpha_INS_STB:
	case Alpha_INS_STL:
	case Alpha_INS_STL_C:
	case Alpha_INS_STQ:
	case Alpha_INS_STQ_C:
	case Alpha_INS_STQ_U:
	case Alpha_INS_STW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	case Alpha_INS_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;

	case Alpha_INS_ADDL:
	case Alpha_INS_ADDQ:
	case Alpha_INS_ADDSsSU:
	case Alpha_INS_ADDTsSU:
	case Alpha_INS_AND:
	case Alpha_INS_BIC:
	case Alpha_INS_BIS:
	case Alpha_INS_CMOVEQ:
	case Alpha_INS_CMOVGE:
	case Alpha_INS_CMOVGT:
	case Alpha_INS_CMOVLBC:
	case Alpha_INS_CMOVLBS:
	case Alpha_INS_CMOVLE:
	case Alpha_INS_CMOVLT:
	case Alpha_INS_CMOVNE:
	case Alpha_INS_CMPBGE:
	case Alpha_INS_CMPEQ:
	case Alpha_INS_CMPLE:
	case Alpha_INS_CMPLT:
	case Alpha_INS_CMPTEQsSU:
	case Alpha_INS_CMPTLEsSU:
	case Alpha_INS_CMPTLTsSU:
	case Alpha_INS_CMPTUNsSU:
	case Alpha_INS_CMPULE:
	case Alpha_INS_CMPULT:
	case Alpha_INS_COND_BRANCH:
	case Alpha_INS_CPYSE:
	case Alpha_INS_CPYSN:
	case Alpha_INS_CPYS:
	case Alpha_INS_CTLZ:
	case Alpha_INS_CTPOP:
	case Alpha_INS_CTTZ:
	case Alpha_INS_CVTQSsSUI:
	case Alpha_INS_CVTQTsSUI:
	case Alpha_INS_CVTSTsS:
	case Alpha_INS_CVTTQsSVC:
	case Alpha_INS_CVTTSsSUI:
	case Alpha_INS_DIVSsSU:
	case Alpha_INS_DIVTsSU:
	case Alpha_INS_ECB:
	case Alpha_INS_EQV:
	case Alpha_INS_EXCB:
	case Alpha_INS_EXTBL:
	case Alpha_INS_EXTLH:
	case Alpha_INS_EXTLL:
	case Alpha_INS_EXTQH:
	case Alpha_INS_EXTQL:
	case Alpha_INS_EXTWH:
	case Alpha_INS_EXTWL:
	case Alpha_INS_FBEQ:
	case Alpha_INS_FBGE:
	case Alpha_INS_FBGT:
	case Alpha_INS_FBLE:
	case Alpha_INS_FBLT:
	case Alpha_INS_FBNE:
	case Alpha_INS_FCMOVEQ:
	case Alpha_INS_FCMOVGE:
	case Alpha_INS_FCMOVGT:
	case Alpha_INS_FCMOVLE:
	case Alpha_INS_FCMOVLT:
	case Alpha_INS_FCMOVNE:
	case Alpha_INS_FETCH:
	case Alpha_INS_FETCH_M:
	case Alpha_INS_FTOIS:
	case Alpha_INS_FTOIT:
	case Alpha_INS_INSBL:
	case Alpha_INS_INSLH:
	case Alpha_INS_INSLL:
	case Alpha_INS_INSQH:
	case Alpha_INS_INSQL:
	case Alpha_INS_INSWH:
	case Alpha_INS_INSWL:
	case Alpha_INS_ITOFS:
	case Alpha_INS_ITOFT:
	case Alpha_INS_MB:
	case Alpha_INS_MSKBL:
	case Alpha_INS_MSKLH:
	case Alpha_INS_MSKLL:
	case Alpha_INS_MSKQH:
	case Alpha_INS_MSKQL:
	case Alpha_INS_MSKWH:
	case Alpha_INS_MSKWL:
	case Alpha_INS_MULL:
	case Alpha_INS_MULQ:
	case Alpha_INS_MULSsSU:
	case Alpha_INS_MULTsSU:
	case Alpha_INS_ORNOT:
	case Alpha_INS_RC:
	case Alpha_INS_RPCC:
	case Alpha_INS_RS:
	case Alpha_INS_S4ADDL:
	case Alpha_INS_S4ADDQ:
	case Alpha_INS_S4SUBL:
	case Alpha_INS_S4SUBQ:
	case Alpha_INS_S8ADDL:
	case Alpha_INS_S8ADDQ:
	case Alpha_INS_S8SUBL:
	case Alpha_INS_S8SUBQ:
	case Alpha_INS_SEXTB:
	case Alpha_INS_SEXTW:
	case Alpha_INS_SLL:
	case Alpha_INS_SQRTSsSU:
	case Alpha_INS_SQRTTsSU:
	case Alpha_INS_SRA:
	case Alpha_INS_SRL:
	case Alpha_INS_STS:
	case Alpha_INS_STT:
	case Alpha_INS_SUBL:
	case Alpha_INS_SUBQ:
	case Alpha_INS_SUBSsSU:
	case Alpha_INS_SUBTsSU:
	case Alpha_INS_TRAPB:
	case Alpha_INS_UMULH:
	case Alpha_INS_WH64:
	case Alpha_INS_WH64EN:
	case Alpha_INS_WMB:
	case Alpha_INS_ZAPNOT:
		break;
	}
}

static int rz_analysis_alpha_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
if (!(a && op && data && len > 0)) {
		return -1;
	}

	RzAsmAlphaContext *ctx = a->plugin_data;
	if (!alpha_setup_cs_handle(ctx, a->cpu, NULL, a->big_endian)) {
		return -1;
	}

	op->size = 4;
	ctx->insn = NULL;
	ctx->count = cs_disasm(ctx->h, (const ut8 *)data, len, addr, 1, &ctx->insn);
	if (ctx->count <= 0) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
		}
		return op->size;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s", ctx->insn->mnemonic, ctx->insn->op_str[0] ? " " : "", ctx->insn->op_str);
	}

	op->size = ctx->insn->size;
	op->id = (int)ctx->insn->id;
	op->addr = ctx->insn->address;
	alpha_op_set_type(ctx, op);

	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		alpha_opex(ctx, &op->opex);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		alpha_fillval(ctx, a, op);
	}

	cs_free(ctx->insn, ctx->count);
	return op->size;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
	default:
		return -1;
	}
}

static bool alpha_init(void **u) {
	if (!u) {
		return false;
	}
	RzAsmAlphaContext *ctx = RZ_NEW0(RzAsmAlphaContext);
	if (!ctx) {
		return false;
	}
	*u = ctx;
	return true;
}

static bool alpha_fini(void *u) {
	if (!u) {
		return true;
	}
	RzAsmAlphaContext *ctx = u;
	cs_close(&ctx->h);
	free(u);
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_alpha_cs = {
	.name = "alpha",
	.desc = "Capstone Alpha analysis plugin",
	.license = "LGPL3",
	.arch = "alpha",
	.bits = 64,
	.get_reg_profile = get_reg_profile,
	.archinfo = archinfo,
	.op = rz_analysis_alpha_op,
	.init = alpha_init,
	.fini = alpha_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_alpha_cs,
	.version = RZ_VERSION
};
#endif
