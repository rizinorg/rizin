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

#define RZ_ALPHA_INS(name) ALPHA_INS_##name

static char *get_reg_profile(RzAnalysis *_) {
	const char *p =
		"=PC	r31\n"
		"=SP	r30\n"
		"=R0	r0\n"
		"=A0	r16\n"
		"=A1	r17\n"
		"=A2	r18\n"
		"=A3	r19\n"
		"=A4	r20\n"
		"=A5	r21\n"
		"gpr	r0	.64	0	0\n" // v0
		"gpr	r1	.64	8	0\n" // t0
		"gpr	r2	.64	16	0\n" // t1
		"gpr	r3	.64	24	0\n" // t2
		"gpr	r4	.64	32	0\n" // t3
		"gpr	r5	.64	40	0\n" // t4
		"gpr	r6	.64	48	0\n" // t5
		"gpr	r7	.64	56	0\n" // t6
		"gpr	r8	.64	64	0\n" // t7
		"gpr	r9	.64	72	0\n" // s0
		"gpr	r10	.64	80	0\n" // s1
		"gpr	r11	.64	88	0\n" // s2
		"gpr	r12	.64	96	0\n" // s3
		"gpr	r13	.64	104	0\n" // s4
		"gpr	r14	.64	112	0\n" // s5
		"gpr	r15	.64	120	0\n" // fp
		"gpr	r16	.64	128	0\n" // a0
		"gpr	r17	.64	136	0\n" // a1
		"gpr	r18	.64	144	0\n" // a2
		"gpr	r19	.64	152	0\n" // a3
		"gpr	r20	.64	160	0\n" // a4
		"gpr	r21	.64	168	0\n" // a5
		"gpr	r22	.64	176	0\n" // t8
		"gpr	r23	.64	184	0\n" // t9
		"gpr	r24	.64	192	0\n" // t10
		"gpr	r25	.64	200	0\n" // t11
		"gpr	r26	.64	208	0\n" // ra
		"gpr	r27	.64	216	0\n" // t12
		"gpr	r28	.64	224	0\n" // at
		"gpr	r29	.64	232	0\n" // gp
		"gpr	r30	.64	240	0\n" // sp
		"gpr	r31 .64	248	0\n" // linux/arch/alpha/kernel/process.c: dump_elf_thread() dest[31] = pt->pc
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
		"flg	fpcr .64	528	0\n";
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

static RzStructuredData *alpha_opex(RzAsmAlphaContext *ctx) {
	if (!ctx->insn->detail) {
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
	cs_alpha *al = &ctx->insn->detail->alpha;
	for (st32 i = 0; i < al->op_count; i++) {
		cs_alpha_op *op = al->operands + i;
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		case ALPHA_OP_REG:
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", cs_reg_name(ctx->h, op->reg));
			break;
		case ALPHA_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", op->imm);
			break;
		}
	}

	return root;
}

static ut64 alpha_calc_64bit_jump(ut64 base, RzAsmAlphaContext *ctx, int idx) {
	ut64 hi32 = base & UT64_32U;
	ut64 jump = alpha_op_as_imm(ctx, idx);
	if (!hi32) {
		// does not need any fix since upper 32 bits are zero
		return jump;
	}

	// keep only the lower 32 bits.
	jump &= UT32_MAX;
	return hi32 | jump;
}

static void alpha_op_set_type(RzAsmAlphaContext *ctx, RzAnalysisOp *op) {
	switch (ctx->insn->id) {
	default: {
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
	case RZ_ALPHA_INS(BEQ):
	case RZ_ALPHA_INS(BGE):
	case RZ_ALPHA_INS(BGT):
	case RZ_ALPHA_INS(BLBC):
	case RZ_ALPHA_INS(BLBS):
	case RZ_ALPHA_INS(BLE):
	case RZ_ALPHA_INS(BLT):
	case RZ_ALPHA_INS(BNE):
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = alpha_calc_64bit_jump(op->addr, ctx, 1);
		op->fail = op->addr + op->size;
		break;
	case RZ_ALPHA_INS(BR):
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = alpha_calc_64bit_jump(op->addr, ctx, 0);
		break;
	case RZ_ALPHA_INS(BSR):
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = alpha_calc_64bit_jump(op->addr, ctx, 0);
		op->fail = op->addr + op->size;
		break;
	case RZ_ALPHA_INS(RET):
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		op->stackop = RZ_ANALYSIS_STACK_GET;
		op->stackptr = 8;
		op->fail = op->addr + op->size;
		break;
	case RZ_ALPHA_INS(JMP):
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = op->addr + 4;
		op->fail = op->addr + op->size;
		break;
	case RZ_ALPHA_INS(JSR):
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->stackop = RZ_ANALYSIS_STACK_SET;
		op->jump = op->addr + 4;
		op->stackptr = 8;
		op->fail = UT64_MAX;
		break;
	case RZ_ALPHA_INS(JSR_COROUTINE):
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		// This one is a weird one, pops from stack then pushes PC
		op->stackop = RZ_ANALYSIS_STACK_GET;
		op->fail = op->addr + op->size;
		break;
	case RZ_ALPHA_INS(LDA):
	case RZ_ALPHA_INS(LDAH):
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	case RZ_ALPHA_INS(LDBU):
	case RZ_ALPHA_INS(LDL):
	case RZ_ALPHA_INS(LDL_L):
	case RZ_ALPHA_INS(LDQ):
	case RZ_ALPHA_INS(LDQ_L):
	case RZ_ALPHA_INS(LDQ_U):
	case RZ_ALPHA_INS(LDS):
	case RZ_ALPHA_INS(LDT):
	case RZ_ALPHA_INS(LDWU):
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;

	case RZ_ALPHA_INS(STB):
	case RZ_ALPHA_INS(STL):
	case RZ_ALPHA_INS(STL_C):
	case RZ_ALPHA_INS(STQ):
	case RZ_ALPHA_INS(STQ_C):
	case RZ_ALPHA_INS(STQ_U):
	case RZ_ALPHA_INS(STW):
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	case RZ_ALPHA_INS(XOR):
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;

	case RZ_ALPHA_INS(ADDL):
	case RZ_ALPHA_INS(ADDQ):
	case RZ_ALPHA_INS(ADDSSSU):
	case RZ_ALPHA_INS(ADDTSSU):
	case RZ_ALPHA_INS(AND):
	case RZ_ALPHA_INS(BIC):
	case RZ_ALPHA_INS(BIS):
	case RZ_ALPHA_INS(CMOVEQ):
	case RZ_ALPHA_INS(CMOVGE):
	case RZ_ALPHA_INS(CMOVGT):
	case RZ_ALPHA_INS(CMOVLBC):
	case RZ_ALPHA_INS(CMOVLBS):
	case RZ_ALPHA_INS(CMOVLE):
	case RZ_ALPHA_INS(CMOVLT):
	case RZ_ALPHA_INS(CMOVNE):
	case RZ_ALPHA_INS(CMPBGE):
	case RZ_ALPHA_INS(CMPEQ):
	case RZ_ALPHA_INS(CMPLE):
	case RZ_ALPHA_INS(CMPLT):
	case RZ_ALPHA_INS(CMPTEQSSU):
	case RZ_ALPHA_INS(CMPTLESSU):
	case RZ_ALPHA_INS(CMPTLTSSU):
	case RZ_ALPHA_INS(CMPTUNSSU):
	case RZ_ALPHA_INS(CMPULE):
	case RZ_ALPHA_INS(CMPULT):
	case RZ_ALPHA_INS(COND_BRANCH):
	case RZ_ALPHA_INS(CPYSE):
	case RZ_ALPHA_INS(CPYSN):
	case RZ_ALPHA_INS(CPYS):
	case RZ_ALPHA_INS(CTLZ):
	case RZ_ALPHA_INS(CTPOP):
	case RZ_ALPHA_INS(CTTZ):
	case RZ_ALPHA_INS(CVTQSSSUI):
	case RZ_ALPHA_INS(CVTQTSSUI):
	case RZ_ALPHA_INS(CVTSTSS):
	case RZ_ALPHA_INS(CVTTQSSVC):
	case RZ_ALPHA_INS(CVTTSSSUI):
	case RZ_ALPHA_INS(DIVSSSU):
	case RZ_ALPHA_INS(DIVTSSU):
	case RZ_ALPHA_INS(ECB):
	case RZ_ALPHA_INS(EQV):
	case RZ_ALPHA_INS(EXCB):
	case RZ_ALPHA_INS(EXTBL):
	case RZ_ALPHA_INS(EXTLH):
	case RZ_ALPHA_INS(EXTLL):
	case RZ_ALPHA_INS(EXTQH):
	case RZ_ALPHA_INS(EXTQL):
	case RZ_ALPHA_INS(EXTWH):
	case RZ_ALPHA_INS(EXTWL):
	case RZ_ALPHA_INS(FBEQ):
	case RZ_ALPHA_INS(FBGE):
	case RZ_ALPHA_INS(FBGT):
	case RZ_ALPHA_INS(FBLE):
	case RZ_ALPHA_INS(FBLT):
	case RZ_ALPHA_INS(FBNE):
	case RZ_ALPHA_INS(FCMOVEQ):
	case RZ_ALPHA_INS(FCMOVGE):
	case RZ_ALPHA_INS(FCMOVGT):
	case RZ_ALPHA_INS(FCMOVLE):
	case RZ_ALPHA_INS(FCMOVLT):
	case RZ_ALPHA_INS(FCMOVNE):
	case RZ_ALPHA_INS(FETCH):
	case RZ_ALPHA_INS(FETCH_M):
	case RZ_ALPHA_INS(FTOIS):
	case RZ_ALPHA_INS(FTOIT):
	case RZ_ALPHA_INS(INSBL):
	case RZ_ALPHA_INS(INSLH):
	case RZ_ALPHA_INS(INSLL):
	case RZ_ALPHA_INS(INSQH):
	case RZ_ALPHA_INS(INSQL):
	case RZ_ALPHA_INS(INSWH):
	case RZ_ALPHA_INS(INSWL):
	case RZ_ALPHA_INS(ITOFS):
	case RZ_ALPHA_INS(ITOFT):
	case RZ_ALPHA_INS(MB):
	case RZ_ALPHA_INS(MSKBL):
	case RZ_ALPHA_INS(MSKLH):
	case RZ_ALPHA_INS(MSKLL):
	case RZ_ALPHA_INS(MSKQH):
	case RZ_ALPHA_INS(MSKQL):
	case RZ_ALPHA_INS(MSKWH):
	case RZ_ALPHA_INS(MSKWL):
	case RZ_ALPHA_INS(MULL):
	case RZ_ALPHA_INS(MULQ):
	case RZ_ALPHA_INS(MULSSSU):
	case RZ_ALPHA_INS(MULTSSU):
	case RZ_ALPHA_INS(ORNOT):
	case RZ_ALPHA_INS(RC):
	case RZ_ALPHA_INS(RPCC):
	case RZ_ALPHA_INS(RS):
	case RZ_ALPHA_INS(S4ADDL):
	case RZ_ALPHA_INS(S4ADDQ):
	case RZ_ALPHA_INS(S4SUBL):
	case RZ_ALPHA_INS(S4SUBQ):
	case RZ_ALPHA_INS(S8ADDL):
	case RZ_ALPHA_INS(S8ADDQ):
	case RZ_ALPHA_INS(S8SUBL):
	case RZ_ALPHA_INS(S8SUBQ):
	case RZ_ALPHA_INS(SEXTB):
	case RZ_ALPHA_INS(SEXTW):
	case RZ_ALPHA_INS(SLL):
	case RZ_ALPHA_INS(SQRTSSSU):
	case RZ_ALPHA_INS(SQRTTSSU):
	case RZ_ALPHA_INS(SRA):
	case RZ_ALPHA_INS(SRL):
	case RZ_ALPHA_INS(STS):
	case RZ_ALPHA_INS(STT):
	case RZ_ALPHA_INS(SUBL):
	case RZ_ALPHA_INS(SUBQ):
	case RZ_ALPHA_INS(SUBSSSU):
	case RZ_ALPHA_INS(SUBTSSU):
	case RZ_ALPHA_INS(TRAPB):
	case RZ_ALPHA_INS(UMULH):
	case RZ_ALPHA_INS(WH64):
	case RZ_ALPHA_INS(WH64EN):
	case RZ_ALPHA_INS(WMB):
	case RZ_ALPHA_INS(ZAPNOT):
		break;
	}
}

static int rz_analysis_alpha_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!(a && op && data && len > 0)) {
		return -1;
	}

	RzAsmAlphaContext *ctx = a->plugin_data;
	if (!alpha_setup_cs_handle(ctx, rz_analysis_get_cpu(a), NULL, a->big_endian)) {
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
		op->opex = alpha_opex(ctx);
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
		return 4;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
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
	.desc = "DEC Alpha Capstone-based disassembler",
	.license = "LGPL3",
	.arch = "alpha",
	.bits = 32 | 64,
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
