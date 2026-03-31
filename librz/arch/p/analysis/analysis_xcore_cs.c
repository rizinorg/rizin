// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_lib.h>
#include <capstone/capstone.h>
#include <capstone/xcore.h>

#define INSOP(n) insn->detail->xcore.operands[n]

static char *xcore_get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	dp\n"
		"=BP	sp\n"
		"=SR	sr\n"
		"=SN	r0\n"
		"=A0	r4\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=A4	r8\n"
		"=A5	r9\n"
		"=A6	r10\n"
		"gpr	r0   .32 0 0\n"
		"gpr	r1   .32 4 0\n"
		"gpr	r2   .32 8 0\n"
		"gpr	r3   .32 12 0\n"
		"gpr	r4   .32 16 0\n"
		"gpr	r5   .32 20 0\n"
		"gpr	r6   .32 24 0\n"
		"gpr	r7   .32 28 0\n"
		"gpr	r8   .32 32 0\n"
		"gpr	r9   .32 36 0\n"
		"gpr	r10  .32 40 0\n"
		"gpr	r11  .32 44 0\n"
		"gpr	cp   .32 48 0\n" // constant pool pointer
		"gpr	dp   .32 52 0\n" // data pointer
		"gpr	sp   .32 56 0\n" // stack pointer
		"gpr	lr   .32 60 0\n" // link register
		"gpr	pc   .32 64 0\n" // program counter
		"gpr	sr   .32 68 0\n" // status register
		"gpr	spc  .32 72 0\n" // saved pc
		"gpr	ssr  .32 76 0\n" // saved status
		"gpr	et   .32 80 0\n" // exception type
		"gpr	ed   .32 84 0\n" // exception data
		"gpr	sed  .32 88 0\n" // saved exception data
		"gpr	kep  .32 92 0\n" // kernel entry pointer
		"gpr	ksp  .32 96 0\n" // kernel stack pointer
		"gpr	id   .32 100 0\n" // thread id
		"";

	return rz_str_dup(p);
}

static RzStructuredData *xcore_opex(csh handle, cs_insn *insn) {
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
	cs_xcore *x = &insn->detail->xcore;
	for (st32 i = 0; i < x->op_count; i++) {
		cs_xcore_op *op = x->operands + i;
		RzStructuredData *operand = rz_structured_data_array_add_map(operands);
		switch (op->type) {
		case XCORE_OP_REG:
			rz_structured_data_map_add_string(operand, "type", "reg");
			rz_structured_data_map_add_string(operand, "value", cs_reg_name(handle, op->reg));
			break;
		case XCORE_OP_IMM:
			rz_structured_data_map_add_string(operand, "type", "imm");
			rz_structured_data_map_add_signed(operand, "value", op->imm);
			break;
		case XCORE_OP_MEM:
			rz_structured_data_map_add_string(operand, "type", "mem");
			if (op->mem.base != XCORE_REG_INVALID) {
				rz_structured_data_map_add_string(operand, "base", cs_reg_name(handle, op->mem.base));
			}
			rz_structured_data_map_add_signed(operand, "disp", op->mem.disp);
			break;
		default:
			rz_structured_data_map_add_string(operand, "type", "invalid");
			break;
		}
	}

	return root;
}

typedef struct {
	csh handle;
	int omode;
} XCoreContext;

static bool xcore_init(void **user) {
	XCoreContext *ctx = RZ_NEW0(XCoreContext);
	rz_return_val_if_fail(ctx, false);
	ctx->handle = 0;
	ctx->omode = 0;
	*user = ctx;
	return true;
}

static int analyze_op(RzAnalysis *a, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	XCoreContext *ctx = (XCoreContext *)a->plugin_data;
	cs_insn *insn;
	int mode, n, ret;
	mode = CS_MODE_BIG_ENDIAN;
	if (mode != ctx->omode) {
		if (ctx->handle) {
			cs_close(&ctx->handle);
			ctx->handle = 0;
		}
		ctx->omode = mode;
	}
	if (ctx->handle == 0) {
		ret = cs_open(CS_ARCH_XCORE, mode, &ctx->handle);
		if (ret != CS_ERR_OK) {
			return -1;
		}
		cs_option(ctx->handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	n = cs_disasm(ctx->handle, (const ut8 *)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = RZ_ANALYSIS_OP_TYPE_ILL;
		if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
			op->mnemonic = strdup("invalid");
		}
		return -1;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s%s%s", insn->mnemonic, insn->op_str[0] ? " " : "", insn->op_str);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_OPEX) {
		op->opex = xcore_opex(ctx->handle, insn);
	}

	op->size = insn->size;
	op->id = insn->id;
	switch (insn->id) {
	case XCORE_INS_BAU: /* Branch absolute unconditional register */
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		op->fail = addr + op->size;
		break;
	case XCORE_INS_BLA: /* Branch and link absolute via register */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		op->fail = addr + op->size;
		break;
	case XCORE_INS_BLAT: /* Branch and link absolute via table */
		op->type = RZ_ANALYSIS_OP_TYPE_MEM | RZ_ANALYSIS_OP_TYPE_UCALL;
		op->fail = addr + op->size;
		break;
	case XCORE_INS_BL:
		op->type = RZ_ANALYSIS_OP_TYPE_CALL;
		op->jump = addr + (st64)(INSOP(0).imm * op->size);
		op->fail = addr + op->size;
		break;
	case XCORE_INS_BF:
		/* fall-thru */
	case XCORE_INS_BT:
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		op->jump = addr + (st64)(INSOP(1).imm * op->size);
		op->fail = addr + op->size;
		break;
	case XCORE_INS_BU:
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + (st64)(INSOP(0).imm * op->size);
		break;
	case XCORE_INS_BRU:
		op->type = RZ_ANALYSIS_OP_TYPE_RJMP;
		break;
	case XCORE_INS_DCALL:
		op->type = RZ_ANALYSIS_OP_TYPE_UCALL;
		break;
	case XCORE_INS_DRET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case XCORE_INS_ECALLF:
		op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		op->fail = addr + op->size;
		break;
	case XCORE_INS_ECALLT:
		op->type = RZ_ANALYSIS_OP_TYPE_UCCALL;
		op->fail = addr + op->size;
		break;
	case XCORE_INS_EQ: /* Compare if equal */
		/* fall-thru */
	case XCORE_INS_LSS: /* Compare if less than (signed) */
		/* fall-thru */
	case XCORE_INS_LSU: /* Compare if less than (unsigned) */
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case XCORE_INS_KCALL: /* kernel call */
		op->type = RZ_ANALYSIS_OP_TYPE_RCALL;
		break;
	case XCORE_INS_KRET:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	case XCORE_INS_LD16S:
		/* fall-thru */
	case XCORE_INS_LD8U:
		/* fall-thru */
	case XCORE_INS_LDA16:
		/* fall-thru */
	case XCORE_INS_LDAW:
		/* fall-thru */
	case XCORE_INS_LDW:
		/* fall-thru */
	case XCORE_INS_ST16:
		/* fall-thru */
	case XCORE_INS_ST8:
		/* fall-thru */
	case XCORE_INS_STW:
		op->type = RZ_ANALYSIS_OP_TYPE_MEM | RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case XCORE_INS_LDAP:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->ptr = op->val = addr + (st64)(INSOP(0).imm * op->size);
		break;
	case XCORE_INS_LDC:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		op->val = (st64)INSOP(0).imm;
		break;
	case XCORE_INS_RETSP:
		op->type = RZ_ANALYSIS_OP_TYPE_RET;
		break;
	default:
		break;
	}
	cs_free(insn, n);

	return op->size;
}

static bool xcore_fini(void *user) {
	XCoreContext *ctx = (XCoreContext *)user;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

static int xcore_archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 4;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 1;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCORE analysis",
	.license = "BSD",
	.esil = false,
	.arch = "xcore",
	.bits = 32,
	.op = &analyze_op,
	.init = xcore_init,
	.fini = xcore_fini,
	.archinfo = xcore_archinfo,
	.get_reg_profile = &xcore_get_reg_profile,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_xcore_cs,
	.version = RZ_VERSION
};
#endif
