// SPDX-FileCopyrightText: 2026 Jagath-P <jagathp0210@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <capstone/capstone.h>
#include <capstone/bpf.h>

typedef struct {
	csh handle;
	cs_mode omode;
} BPFContext;

static char *cbpf_get_reg_profile(RzAnalysis *analysis) {
	const char *cbpf_reg_profile =
		"=PC    pc\n"
		"=SP    sp\n"
		"=R0    A\n" // return value is accumulator
		"=A0    A\n" // first argument
		"gpr    A    .32  0   0\n" // accumulator
		"gpr    X    .32  4   0\n" // index register
		"gpr    pc   .32  8   0\n" // program counter
		"gpr    sp   .32  12  0\n" // stack pointer
		// M[] scratch memory registers M0-M15
		"gpr    M0   .32  16  0\n"
		"gpr    M1   .32  20  0\n"
		"gpr    M2   .32  24  0\n"
		"gpr    M3   .32  28  0\n"
		"gpr    M4   .32  32  0\n"
		"gpr    M5   .32  36  0\n"
		"gpr    M6   .32  40  0\n"
		"gpr    M7   .32  44  0\n"
		"gpr    M8   .32  48  0\n"
		"gpr    M9   .32  52  0\n"
		"gpr    M10  .32  56  0\n"
		"gpr    M11  .32  60  0\n"
		"gpr    M12  .32  64  0\n"
		"gpr    M13  .32  68  0\n"
		"gpr    M14  .32  72  0\n"
		"gpr    M15  .32  76  0\n";

	return rz_str_dup(cbpf_reg_profile);
}

static RzStructuredData *cbpf_opex(csh handle, cs_insn *insn) {
	if (!insn->detail) {
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
	cs_bpf *x = &insn->detail->bpf;
	for (st32 i = 0; i < x->op_count; i++) {
		cs_bpf_op *op = x->operands + i;
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		case BPF_OP_REG: {
			const char *reg_name = cs_reg_name(handle, op->reg);
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", reg_name ? reg_name : "unknown");
			break;
		}
		case BPF_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_unsigned(operand, "value", op->imm, true);
			break;
		case BPF_OP_OFF:
			rz_structured_data_map_add_string(operand, "type", "off");
			rz_structured_data_map_add_unsigned(operand, "value", op->off, true);
			break;
		case BPF_OP_MEM: {
			const char *base_name = cs_reg_name(handle, (unsigned int)op->mem.base);
			rz_structured_data_map_add_string(operand, "type", "mem");
			rz_structured_data_map_add_string(operand, "base", base_name ? base_name : "unknown");
			rz_structured_data_map_add_unsigned(operand, "disp", op->mem.disp, true);
			break;
		}
		case BPF_OP_MMEM:
			rz_structured_data_map_add_string(operand, "type", "mmem");
			rz_structured_data_map_add_unsigned(operand, "value", op->mmem, true);
			break;
		case BPF_OP_MSH:
			rz_structured_data_map_add_string(operand, "type", "msh");
			rz_structured_data_map_add_unsigned(operand, "value", op->msh, true);
			break;
		case BPF_OP_EXT:
			rz_structured_data_map_add_string(operand, "type", "ext");
			rz_structured_data_map_add_unsigned(operand, "value", op->ext, true);
			break;
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}

	return root;
}
static bool cbpf_anal_init(void **user) {
	BPFContext *ctx = RZ_NEW0(BPFContext);
	rz_return_val_if_fail(ctx, false);
	ctx->handle = 0;
	ctx->omode = -1;
	*user = ctx;
	return true;
}

static bool cbpf_anal_fini(void *user) {
	BPFContext *ctx = (BPFContext *)user;
	if (ctx) {
		if (ctx->handle) {
			cs_close(&ctx->handle);
		}
		RZ_FREE(ctx);
	}
	return true;
}

static int cbpf_arch_info(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return false;
	default:
		return -1;
	}
}
static int cbpf_analysis_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	BPFContext *ctx = (BPFContext *)a->plugin_data;
	cs_insn *insn;
	int n;

	cs_mode mode = CS_MODE_BPF_CLASSIC | (a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
	if (mode != ctx->omode) {
		if (ctx->handle) {
			cs_close(&ctx->handle);
		}
		ctx->omode = mode;
	}
	op->size = 8;
	if (!ctx->handle) {
		cs_err err = cs_open(CS_ARCH_BPF, mode, &ctx->handle);
		if (err != CS_ERR_OK) {
			return -1;
		}
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	n = cs_disasm(ctx->handle, buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
		}
		return -1;
	}
	op->size = insn->size;
	op->id = insn->id;
	if (op->size < 1) {
		cs_free(insn, n);
		return -1;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = cbpf_opex(ctx->handle, insn);
	}
	switch (insn->id) {
	case BPF_INS_ADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case BPF_INS_SUB:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case BPF_INS_MUL:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case BPF_INS_SDIV:
		/* fall-thru */
	case BPF_INS_DIV:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case BPF_INS_OR:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case BPF_INS_AND:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case BPF_INS_LSH:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case BPF_INS_RSH:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case BPF_INS_NEG:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	case BPF_INS_MOD:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		break;
	case BPF_INS_XOR:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case BPF_INS_LD:
		/* fall-thru */
	case BPF_INS_LDX:
		/* fall-thru */
	case BPF_INS_LDH:
		/* fall-thru */
	case BPF_INS_LDB:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		break;
	case BPF_INS_ST:
		/* fall-thru */
	case BPF_INS_STX:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;
	case BPF_INS_JA:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + (insn->detail->bpf.operands[0].off + 1) * 8;
		break;
	case BPF_INS_JEQ:
		/* fall-thru */
	case BPF_INS_JGT:
		/* fall-thru */
	case BPF_INS_JGE:
		/* fall-thru */
	case BPF_INS_JSET:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		if (insn->detail->bpf.op_count >= 3) {
			op->jump = addr + (insn->detail->bpf.operands[1].off + 1) * 8; // jt
			op->fail = addr + (insn->detail->bpf.operands[2].off + 1) * 8; // jf
		}
		break;
	case BPF_INS_TAX:
		/* fall-thru */
	case BPF_INS_TXA:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case BPF_INS_RET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	default:
		op->type = RZ_ANALYSIS_OP_TYPE_NULL;
		break;
	}
	cs_free(insn, n);
	return op->size;
}
RzAnalysisPlugin rz_analysis_plugin_cbpf_cs = {
	.name = "cbpf",
	.desc = "Classic BPF analysis plugin",
	.license = "LGPL3",
	.arch = "cbpf",
	.bits = 32,
	.op = &cbpf_analysis_op,
	.init = cbpf_anal_init,
	.fini = cbpf_anal_fini,
	.archinfo = cbpf_arch_info,
	.get_reg_profile = &cbpf_get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_cbpf_cs,
	.version = RZ_VERSION
};
#endif
