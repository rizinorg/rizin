// SPDX-FileCopyrightText: 2026 Jagath-P <jagathp0210@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_assert.h"
#include "rz_util/rz_structured_data.h"
#include <rz_analysis.h>
#include <capstone/capstone.h>
#include <capstone/bpf.h>

typedef struct {
	csh handle;
	cs_mode omode;
} BPFContext;

static char *bpf_get_reg_profile(RzAnalysis *analysis) {
	const char *ebpf_reg_profile =
		"=PC pc\n"
		"=SP R10\n"
		"=R0 R0\n"
		"=A0 R1\n"
		"=A1 R2\n"
		"=A2 R3\n"
		"=A3 R4\n"
		"=A4 R5\n"
		"gpr    pc   .64  0   0\n" // program counter
		"gpr    R0   .64  8   0\n"
		"gpr    R1   .64  16  0\n"
		"gpr    R2   .64  24  0\n"
		"gpr    R3   .64  32  0\n"
		"gpr    R4   .64  40  0\n"
		"gpr    R5   .64  48  0\n"
		"gpr    R6   .64  56  0\n"
		"gpr    R7   .64  64  0\n"
		"gpr    R8   .64  72  0\n"
		"gpr    R9   .64  80  0\n"
		"gpr    R10  .64  88  0\n"; // stack pointer

	return rz_str_dup(ebpf_reg_profile);
}

static RzStructuredData *bpf_opex(csh handle, cs_insn *insn) {
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
			if (op->is_signed) {
				if (op->imm & (0xffffffff00000000)) {
					rz_structured_data_map_add_signed(operand, "value", (st64)op->imm);
				} else {
					rz_structured_data_map_add_signed(operand, "value", (st64)(st32)op->imm);
				}
			} else {
				rz_structured_data_map_add_unsigned(operand, "value", op->imm, true);
			}
			break;
		case BPF_OP_OFF:
			rz_structured_data_map_add_string(operand, "type", "off");
			if (op->is_signed) {
				rz_structured_data_map_add_signed(operand, "value", (st32)(st16)op->off);
			} else {
				rz_structured_data_map_add_unsigned(operand, "value", op->off, true);
			}
			break;
		case BPF_OP_MEM: {
			const char *base_name = cs_reg_name(handle, (unsigned int)op->mem.base);
			rz_structured_data_map_add_string(operand, "type", "mem");
			rz_structured_data_map_add_string(operand, "base", base_name ? base_name : "unknown");
			if (op->is_pkt) {
				rz_structured_data_map_add_boolean(operand, "is_packet", true);
				if (op->is_signed) {
					rz_structured_data_map_add_signed(operand, "disp", (st32)op->mem.disp);
				} else {
					rz_structured_data_map_add_unsigned(operand, "disp", op->mem.disp, true);
				}
			} else {
				if (op->is_signed) {
					rz_structured_data_map_add_signed(operand, "disp", (st32)(st16)op->mem.disp);
				} else {
					rz_structured_data_map_add_unsigned(operand, "disp", op->mem.disp, true);
				}
			}
			break;
		}
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}

	return root;
}
static bool bpf_anal_init(void **user) {
	BPFContext *ctx = RZ_NEW0(BPFContext);
	rz_return_val_if_fail(ctx, false);
	ctx->handle = 0;
	ctx->omode = -1;
	*user = ctx;
	return true;
}

static bool bpf_anal_fini(void *user) {
	BPFContext *ctx = (BPFContext *)user;
	if (ctx) {
		if (ctx->handle) {
			cs_close(&ctx->handle);
		}
		RZ_FREE(ctx);
	}
	return true;
}

static int bpf_arch_info(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 16;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

static void ebpf_op_type(RzAnalysisOp *op, ut64 addr, cs_insn *insn) {
	switch (insn->id) {
	case BPF_INS_ADD: op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
	case BPF_INS_SUB: op->type = RZ_ANALYSIS_OP_TYPE_SUB; break;
	case BPF_INS_MUL: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
	case BPF_INS_DIV: op->type = RZ_ANALYSIS_OP_TYPE_DIV; break;
	case BPF_INS_OR: op->type = RZ_ANALYSIS_OP_TYPE_OR; break;
	case BPF_INS_AND: op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
	case BPF_INS_LSH: op->type = RZ_ANALYSIS_OP_TYPE_SHL; break;
	case BPF_INS_RSH: op->type = RZ_ANALYSIS_OP_TYPE_SHR; break;
	case BPF_INS_NEG: op->type = RZ_ANALYSIS_OP_TYPE_UNK; break;
	case BPF_INS_MOD: op->type = RZ_ANALYSIS_OP_TYPE_MOD; break;
	case BPF_INS_XOR: op->type = RZ_ANALYSIS_OP_TYPE_XOR; break;
	case BPF_INS_MOV: op->type = RZ_ANALYSIS_OP_TYPE_MOV; break;
	case BPF_INS_ARSH:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		op->sign = true;
		break;

	/* ALU64 */
	case BPF_INS_ADD64: op->type = RZ_ANALYSIS_OP_TYPE_ADD; break;
	case BPF_INS_SUB64: op->type = RZ_ANALYSIS_OP_TYPE_SUB; break;
	case BPF_INS_MUL64: op->type = RZ_ANALYSIS_OP_TYPE_MUL; break;
	case BPF_INS_DIV64: op->type = RZ_ANALYSIS_OP_TYPE_DIV; break;
	case BPF_INS_OR64: op->type = RZ_ANALYSIS_OP_TYPE_OR; break;
	case BPF_INS_AND64: op->type = RZ_ANALYSIS_OP_TYPE_AND; break;
	case BPF_INS_LSH64: op->type = RZ_ANALYSIS_OP_TYPE_SHL; break;
	case BPF_INS_RSH64: op->type = RZ_ANALYSIS_OP_TYPE_SHR; break;
	case BPF_INS_NEG64: op->type = RZ_ANALYSIS_OP_TYPE_UNK; break;
	case BPF_INS_MOD64: op->type = RZ_ANALYSIS_OP_TYPE_MOD; break;
	case BPF_INS_XOR64: op->type = RZ_ANALYSIS_OP_TYPE_XOR; break;
	case BPF_INS_MOV64: op->type = RZ_ANALYSIS_OP_TYPE_MOV; break;
	case BPF_INS_ARSH64:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		op->sign = true;
		break;

	case BPF_INS_SDIV:
	case BPF_INS_SDIV64:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		op->sign = true;
		break;
	case BPF_INS_SMOD:
	case BPF_INS_SMOD64:
		op->type = RZ_ANALYSIS_OP_TYPE_MOD;
		op->sign = true;
		break;
	case BPF_INS_MOVSB:
	case BPF_INS_MOVSH:
	case BPF_INS_MOVSB64:
	case BPF_INS_MOVSH64:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->sign = true;
		break;

	/* Byte Swap */
	case BPF_INS_LE16:
	case BPF_INS_LE32:
	case BPF_INS_LE64:
	case BPF_INS_BE16:
	case BPF_INS_BE32:
	case BPF_INS_BE64:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV; // endian-swap into same reg
		break;

		/* Load */
	case BPF_INS_LDXW:
		op->refptr = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDXH:
		op->refptr = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDXB:
		op->refptr = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDXDW:
		op->refptr = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDW:
		op->refptr = 4;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDH:
		op->refptr = 2;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDB:
		op->refptr = 1;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;
	case BPF_INS_LDDW:
		op->refptr = 8;
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;

	case BPF_INS_LDABSW:
	case BPF_INS_LDABSH:
	case BPF_INS_LDABSB:
	case BPF_INS_LDINDW:
	case BPF_INS_LDINDH:
	case BPF_INS_LDINDB:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		op->direction = RZ_ANALYSIS_OP_DIR_READ;
		break;

	/* Store */
	case BPF_INS_STXW:
	case BPF_INS_STXH:
	case BPF_INS_STXB:
	case BPF_INS_STXDW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case BPF_INS_STW:
	case BPF_INS_STH:
	case BPF_INS_STB:
	case BPF_INS_STDW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;
	case BPF_INS_XADDW:
	case BPF_INS_XADDDW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		// atomic add-and-store
		op->direction = RZ_ANALYSIS_OP_DIR_WRITE;
		break;

		/*
		 * Extended atomics (AFADD, AFOR, AFAND, AFXOR, AADD, AOR, AAND, AXOR)
		 * only exist in Capstone v6 onwards.
		 */
	case BPF_INS_AADD:
	case BPF_INS_AOR:
	case BPF_INS_AAND:
	case BPF_INS_AXOR:
	case BPF_INS_AFADD:
	case BPF_INS_AFOR:
	case BPF_INS_AFAND:
	case BPF_INS_AFXOR:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		break;

	case BPF_INS_JA:
		if (insn->detail->bpf.op_count > 0) {
			op->jump = addr + (insn->detail->bpf.operands[0].off + 1) * 8;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		}
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;

	/* Conditional jump */
	case BPF_INS_JSGT:
	case BPF_INS_JSGE:
	case BPF_INS_JSLT:
	case BPF_INS_JSLE:
		op->sign = true;
		/* fall through */
	case BPF_INS_JEQ:
	case BPF_INS_JGT:
	case BPF_INS_JGE:
	case BPF_INS_JSET:
	case BPF_INS_JNE:
	case BPF_INS_JLT:
	case BPF_INS_JLE:
		if (insn->detail->bpf.op_count > 2) {
			op->jump = addr + (insn->detail->bpf.operands[2].off + 1) * 8;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		}
		op->fail = addr + 8;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;

		/* Conditional jumps 32-bit operands */
	case BPF_INS_JAL:
		if (insn->detail->bpf.op_count > 0) {
			op->jump = addr + (insn->detail->bpf.operands[0].imm + 1) * 8;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		}
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		break;

	case BPF_INS_JSLT32:
	case BPF_INS_JSLE32:
	case BPF_INS_JSGT32:
	case BPF_INS_JSGE32:
		op->sign = true;
		/* fallthrough */
	case BPF_INS_JEQ32:
	case BPF_INS_JGT32:
	case BPF_INS_JGE32:
	case BPF_INS_JNE32:
	case BPF_INS_JLT32:
	case BPF_INS_JLE32:
	case BPF_INS_JSET32:
		if (insn->detail->bpf.op_count > 2) {
			op->jump = addr + (insn->detail->bpf.operands[2].off + 1) * 8;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_ILL;
			break;
		}
		op->fail = addr + 8;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;

	case BPF_INS_CALL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		break;
	case BPF_INS_CALLX:
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;

	case BPF_INS_EXIT:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;

	default:
		op->type = RZ_ANALYSIS_OP_TYPE_UNK;
		break;
	}
}

static int bpf_analysis_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	BPFContext *ctx = (BPFContext *)a->plugin_data;
	cs_insn *insn;
	int n;
	cs_mode mode = CS_MODE_BPF_EXTENDED | (a->big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);

	if (mode != ctx->omode) {
		if (ctx->handle) {
			cs_close(&ctx->handle);
		}
		ctx->omode = mode;
	}
	if (!ctx->handle) {
		cs_err err = cs_open(CS_ARCH_BPF, mode, &ctx->handle);
		if (err != CS_ERR_OK) {
			rz_warn_if_reached();
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
		cs_free(insn, n);
		return -1;
	}
	op->size = insn->size;
	op->id = insn->id;
	if (op->size != 8 && op->size != 16) {
		cs_free(insn, n);
		return -1;
	}
	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s %s", insn->mnemonic, insn->op_str);
	}
	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = bpf_opex(ctx->handle, insn);
	}
	op->nopcode = 1;
	ebpf_op_type(op, addr, insn);
	cs_free(insn, n);
	return op->size;
}
RzAnalysisPlugin rz_analysis_plugin_bpf_cs = {
	.name = "bpf",
	.desc = "Extended BPF analysis plugin",
	.license = "LGPL3",
	.arch = "bpf",
	.bits = 64,
	.op = &bpf_analysis_op,
	.init = bpf_anal_init,
	.fini = bpf_anal_fini,
	.archinfo = bpf_arch_info,
	.get_reg_profile = &bpf_get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_bpf_cs,
	.version = RZ_VERSION
};
#endif
