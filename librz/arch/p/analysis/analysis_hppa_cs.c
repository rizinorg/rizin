// SPDX-FileCopyrightText: 2024 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <capstone/capstone.h>

#include <hppa/hppa.inc>

static char *hppa_reg_profile(RzAnalysis *analysis) {
	if (analysis->bits == 64) {
		const char *p =
			"=PC	pc\n"
			"=SP	r30\n"
			"=A0	r26\n"
			"=A1	r25\n"
			"=A2	r24\n"
			"=A3	r23\n"
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
			"gpr	r31	.64	248	0\n"
			"ctr	sr0	.64	256	0\n"
			"ctr	sr1	.64	264	0\n"
			"ctr	sr2	.64	272	0\n"
			"ctr	sr3	.64	280	0\n"
			"ctr	sr4	.64	288	0\n"
			"ctr	sr5	.64	296	0\n"
			"ctr	sr6	.64	304	0\n"
			"ctr	sr7	.64	312	0\n"
			"flg	psw	.64	320	0\n";
		return strdup(p);
	} else {
		const char *p =
			"=PC	pc\n"
			"=SP	r30\n"
			"=A0	r26\n"
			"=A1	r25\n"
			"=A2	r24\n"
			"=A3	r23\n"
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
			"gpr	r15	.32	60	0\n"
			"gpr	r16	.32	64	0\n"
			"gpr	r17	.32	68	0\n"
			"gpr	r18	.32	72	0\n"
			"gpr	r19	.32	76	0\n"
			"gpr	r20	.32	80	0\n"
			"gpr	r21	.32	84	0\n"
			"gpr	r22	.32	88	0\n"
			"gpr	r23	.32	92	0\n"
			"gpr	r24	.32	96	0\n"
			"gpr	r25	.32	100	0\n"
			"gpr	r26	.32	104	0\n"
			"gpr	r27	.32	108	0\n"
			"gpr	r28	.32	112	0\n"
			"gpr	r29	.32	116	0\n"
			"gpr	r30	.32	120	0\n"
			"gpr	r31	.32	124	0\n"
			"ctr	sr0	.32	128	0\n"
			"ctr	sr1	.32	132	0\n"
			"ctr	sr2	.32	136	0\n"
			"ctr	sr3	.32	140	0\n"
			"ctr	sr4	.32	144	0\n"
			"ctr	sr5	.32	148	0\n"
			"ctr	sr6	.32	152	0\n"
			"ctr	sr7	.32	156	0\n"
			"flg	psw	.32	160	0\n";
		return strdup(p);
	}
}

static inline void hppa_fillval(RzReg *rz_reg, csh handle, RzAnalysisValue *av, cs_hppa_op *hop) {
	switch (hop->type) {
	case HPPA_OP_INVALID:
	default:
		av->type = RZ_ANALYSIS_VAL_UNK;
		break;
	case HPPA_OP_IMM:
	case HPPA_OP_DISP:
	case HPPA_OP_TARGET:
		av->type = RZ_ANALYSIS_VAL_IMM;
		av->imm = hop->imm;
		break;
	case HPPA_OP_REG:
	case HPPA_OP_IDX_REG:
		av->type = RZ_ANALYSIS_VAL_REG;
		av->reg = rz_reg_get(rz_reg, cs_reg_name(handle, hop->reg), RZ_REG_TYPE_ANY);
		break;
	case HPPA_OP_MEM:
		av->type = RZ_ANALYSIS_VAL_MEM;
		// FIXME: Handle also the space
		av->reg = rz_reg_get(rz_reg, cs_reg_name(handle, hop->mem.base), RZ_REG_TYPE_ANY);
		av->delta = 0;
		break;
	}
}

static void hppa_fillvals(RzAsmHPPAContext *ctx, RzAnalysis *a, RzAnalysisOp *op) {
	uint8_t srci = 0;
	cs_hppa *hc = &ctx->insn->detail->hppa;
	for (uint8_t i = 0; i < hc->op_count; ++i) {
		cs_hppa_op *hop = &hc->operands[i];
		RzAnalysisValue *av = rz_analysis_value_new();
		hppa_fillval(a->reg, ctx->h, av, hop);
		if (hop->access & CS_AC_READ) {
			av->access |= RZ_ANALYSIS_ACC_R;
			op->src[srci++] = av;
		}
		if (hop->access & CS_AC_WRITE) {
			av->access |= RZ_ANALYSIS_ACC_W;
			if (srci > 0 && av == op->src[srci - 1]) {
				av = rz_mem_dup(av, sizeof(RzAnalysisValue));
			}
			op->dst = av;
		}
	}
}

static void hppa_opex(RzAsmHPPAContext *ctx, RzStrBuf *sb) {
	PJ *pj = pj_new();
	if (!pj) {
		return;
	}
	pj_o(pj);
	pj_ka(pj, "operands");
	cs_hppa *hpc = &ctx->insn->detail->hppa;
	for (st32 i = 0; i < hpc->op_count; i++) {
		cs_hppa_op *op = hpc->operands + i;
		pj_o(pj);
		switch (op->type) {
		case HPPA_OP_INVALID: {
			pj_ks(pj, "type", "invalid");
			break;
		}
		case HPPA_OP_REG: {
			pj_ks(pj, "type", "reg");
			pj_ks(pj, "value", cs_reg_name(ctx->h, op->reg));
			break;
		}
		case HPPA_OP_IDX_REG: {
			pj_ks(pj, "type", "idx_reg");
			pj_ks(pj, "value", cs_reg_name(ctx->h, op->reg));
			break;
		}
		case HPPA_OP_IMM: {
			pj_ks(pj, "type", "imm");
			pj_ki(pj, "value", op->imm);
			break;
		}
		case HPPA_OP_DISP: {
			pj_ks(pj, "type", "disp");
			pj_ki(pj, "value", op->imm);
			break;
		}
		case HPPA_OP_TARGET: {
			pj_ks(pj, "type", "target");
			pj_ki(pj, "value", op->imm);
			break;
		}
		case HPPA_OP_MEM: {
			pj_ks(pj, "type", "mem");
			pj_ks(pj, "base", cs_reg_name(ctx->h, op->mem.base));
			if (op->mem.space != HPPA_REG_INVALID) {
				pj_ks(pj, "space", cs_reg_name(ctx->h, op->mem.space));
			} else {
				pj_ks(pj, "space", "unavailable");
			}
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

static void hppa_op_set_type(RzAsmHPPAContext *ctx, RzAnalysisOp *op) {
	switch (ctx->insn->id) {
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case HPPA_INS_NOP:
		op->type = RZ_ANALYSIS_OP_TYPE_NOP;
		break;
	case HPPA_INS_ADD:
	case HPPA_INS_ADDI:
	case HPPA_INS_ADDIO:
	case HPPA_INS_ADDIT:
	case HPPA_INS_ADDITO:
	case HPPA_INS_ADDIL:
	case HPPA_INS_ADDC:
	case HPPA_INS_ADDCO:
	case HPPA_INS_ADDL:
	case HPPA_INS_ADDO:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case HPPA_INS_ADDB:
	case HPPA_INS_ADDIB:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 2);
		break;
	case HPPA_INS_ADDBT:
	case HPPA_INS_ADDBF:
	case HPPA_INS_ADDIBT:
	case HPPA_INS_ADDIBF:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 2);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case HPPA_INS_AND:
	case HPPA_INS_ANDCM:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case HPPA_INS_BB:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 2);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case HPPA_INS_BE:
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->reg = hppa_op_as_mem(ctx, 1);
		break;
	case HPPA_INS_BL:
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 0);
		break;
	case HPPA_INS_BLE:
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		op->reg = hppa_op_as_mem(ctx, 1);
		break;
	case HPPA_INS_BLR:
		op->type = RZ_ANALYSIS_OP_TYPE_IRJMP;
		op->reg = hppa_op_as_reg(ctx, 0);
		break;
	case HPPA_INS_BV:
		op->type = RZ_ANALYSIS_OP_TYPE_IRCALL;
		// FIXME: Should be result of the *two* registers actually
		op->reg = hppa_op_as_mem(ctx, 1);
		break;
	case HPPA_INS_BVB:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 1);
		break;
	case HPPA_INS_GATE:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = hppa_op_as_target(ctx, 0);
		break;
	case HPPA_INS_LDB:
	case HPPA_INS_LDBS:
	case HPPA_INS_LDCD:
	case HPPA_INS_LDCW:
	case HPPA_INS_LDCWS:
	case HPPA_INS_LDD:
	case HPPA_INS_LDDA:
	case HPPA_INS_LDH:
	case HPPA_INS_LDHS:
	case HPPA_INS_LDI:
	case HPPA_INS_LDW:
	case HPPA_INS_LDWA:
	case HPPA_INS_LDWAS:
	case HPPA_INS_LDWM:
	case HPPA_INS_LDWS:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		const cs_hppa_op *op1 = hppa_op_get(ctx->insn, 1);
		if (op1->type == HPPA_OP_REG && op1->reg == HPPA_REG_GR30 /* SP */) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = 0;
		}
		op->ptr = (st64)hppa_op_as_disp(ctx, 0);
		break;
	case HPPA_INS_LDSID:
	case HPPA_INS_LDHX:
	case HPPA_INS_LDBX:
	case HPPA_INS_LDCWX:
	case HPPA_INS_LDWAX:
	case HPPA_INS_LDWX:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case HPPA_INS_LDIL:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case HPPA_INS_LCI:
	case HPPA_INS_LDO:
		op->type = RZ_ANALYSIS_OP_TYPE_LEA;
		break;
	case HPPA_INS_MOVB:
	case HPPA_INS_MOVIB:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 2);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case HPPA_INS_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case HPPA_INS_CALL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = hppa_op_as_target(ctx, 0);
		break;
	case HPPA_INS_COMIB:
	case HPPA_INS_COMIBT:
	case HPPA_INS_COMIBF:
	case HPPA_INS_COMB:
	case HPPA_INS_COMBT:
	case HPPA_INS_COMBF:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = ctx->insn->address + hppa_op_as_target(ctx, 2);
		op->fail = ctx->insn->address + ctx->insn->size;
		break;
	case HPPA_INS_STB:
	case HPPA_INS_STBS:
	case HPPA_INS_STBY:
	case HPPA_INS_STBYS:
	case HPPA_INS_STD:
	case HPPA_INS_STDA:
	case HPPA_INS_STDBY:
	case HPPA_INS_STH:
	case HPPA_INS_STHS:
	case HPPA_INS_STW:
	case HPPA_INS_STWA:
	case HPPA_INS_STWAS:
	case HPPA_INS_STWS:
	case HPPA_INS_STWM:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		const cs_hppa_op *op2 = hppa_op_get(ctx->insn, 2);
		if (op2->type == HPPA_OP_REG && op2->reg == HPPA_REG_GR30 /* SP */) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = 0;
		}
		op->ptr = (st64)hppa_op_as_disp(ctx, 1);
		break;
	case HPPA_INS_SUB:
	case HPPA_INS_SUBB:
	case HPPA_INS_SUBBO:
	case HPPA_INS_SUBI:
	case HPPA_INS_SUBIO:
	case HPPA_INS_SUBO:
	case HPPA_INS_SUBT:
	case HPPA_INS_SUBTO:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case HPPA_INS_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	}
}

static int
hppa_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	if (!(a && op && data && len > 0)) {
		return -1;
	}

	RzAsmHPPAContext *ctx = a->plugin_data;
	if (!hppa_setup_cs_handle(ctx, a->cpu, NULL, a->big_endian)) {
		return -1;
	}

	op->size = 4;

	ctx->insn = NULL;
	ctx->count = cs_disasm(ctx->h, (const ut8 *)data, len, addr, 1, &ctx->insn);
	if (ctx->count <= 0 || !ctx->insn) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
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
	hppa_op_set_type(ctx, op);
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		hppa_opex(ctx, &op->opex);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_VAL) {
		hppa_fillvals(ctx, a, op);
	}

beach:
	cs_free(ctx->insn, ctx->count);
	return op->size;
}

static int hppa_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
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

static bool hppa_init(void **u) {
	if (!u) {
		return false;
	}
	RzAsmHPPAContext *ctx = RZ_NEW0(RzAsmHPPAContext);
	if (!ctx) {
		return false;
	}
	*u = ctx;
	return true;
}

static bool hppa_fini(void *u) {
	if (!u) {
		return true;
	}
	RzAsmHPPAContext *ctx = u;
	cs_close(&ctx->h);
	free(u);
	return true;
}

RzAnalysisPlugin rz_analysis_plugin_hppa_cs = {
	.name = "hppa",
	.desc = "Capstone HP PA-RISC analysis plugin",
	.author = "xvilka",
	.license = "LGPL3",
	.arch = "hppa",
	.bits = 32 | 64,
	.get_reg_profile = hppa_reg_profile,
	.archinfo = hppa_archinfo,
	.op = hppa_op,
	.init = hppa_init,
	.fini = hppa_fini,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_hppa_cs,
	.version = RZ_VERSION
};
#endif
