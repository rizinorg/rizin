// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone/capstone.h>
#include <capstone/tricore.h>
#include "tricore.h"

static inline cs_mode tricore_cpu_to_cs_mode(const char *cpu_type) {
	if (RZ_STR_ISNOTEMPTY(cpu_type)) {
		if (!strcmp(cpu_type, "generic")) {
			return CS_MODE_TRICORE_162;
		}
		if (!strcmp(cpu_type, "rider-a")) {
			return CS_MODE_TRICORE_110;
		}
		if (!strcmp(cpu_type, "rider-b")) {
			return CS_MODE_TRICORE_120;
		}
		if (!strcmp(cpu_type, "rider-d")) {
			return CS_MODE_TRICORE_131;
		}
		if (!strcmp(cpu_type, "v2")) {
			return CS_MODE_TRICORE_162;
		}
	}
	return CS_MODE_TRICORE_162;
}

static inline bool tricore_setup_cs_handle(RzAsmTriCoreContext *ctx, const char *cpu, const char *features) {
	const cs_mode mode = tricore_cpu_to_cs_mode(cpu);
	if (mode != ctx->mode) {
		cs_close(&ctx->h);
		ctx->h = 0;
		ctx->mode = mode;
	}

	if (ctx->h != 0) {
		return true;
	}
	cs_err err = cs_open(CS_ARCH_TRICORE, mode, &ctx->h);
	if (err) {
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
		return false;
	}
	err = cs_option(ctx->h, CS_OPT_DETAIL,
		RZ_STR_ISNOTEMPTY(features) || features == NULL ? CS_OPT_ON : CS_OPT_OFF);
	if (err) {
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u\n", err);
		return false;
	}
	return true;
}

static inline ut8 tricore_op_count(cs_insn *insn) {
	return insn->detail->tricore.op_count;
}

static inline cs_tricore_op *tricore_op_get(cs_insn *insn, int idx) {
	if (idx >= tricore_op_count(insn)) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\"\n",
			idx, tricore_op_count(insn), insn->mnemonic, insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return &insn->detail->tricore.operands[idx];
}

static inline const char *tricore_op_as_reg(RzAsmTriCoreContext *ctx, int idx) {
	const cs_tricore_op *op = tricore_op_get(ctx->insn, idx);
	if (op->type != TRICORE_OP_REG) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [reg]\n",
			idx, tricore_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return cs_reg_name(ctx->h, op->reg);
}

static inline st32 tricore_op_as_imm(RzAsmTriCoreContext *ctx, int idx) {
	const cs_tricore_op *op = tricore_op_get(ctx->insn, idx);
	if (op->type != TRICORE_OP_IMM) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [imm]\n",
			idx, tricore_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}

typedef struct {
	const char *reg;
	ut32 disp;
} TriCoreMem;

static inline TriCoreMem tricore_op_as_mem(RzAsmTriCoreContext *ctx, int idx) {
	const cs_tricore_op *op = tricore_op_get(ctx->insn, idx);
	TriCoreMem m = { 0 };
	if (op->type != TRICORE_OP_MEM) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [mem]\n",
			idx, tricore_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return m;
	}

	m.reg = cs_reg_name(ctx->h, op->mem.base);
	m.disp = op->mem.disp;
	return m;
}
