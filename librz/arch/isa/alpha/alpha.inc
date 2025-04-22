// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-FileCopyrightText: 2024 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone/capstone.h>
#include <capstone/alpha.h>
#include "alpha.h"

static inline bool alpha_setup_cs_handle(RzAsmAlphaContext *ctx, const char *cpu, const char *features, bool big_endian) {
	const cs_mode mode = big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (mode != ctx->mode) {
		cs_close(&ctx->h);
		ctx->h = 0;
		ctx->mode = mode;
	}

	if (ctx->h != 0) {
		return true;
	}
	cs_err err = cs_open(CS_ARCH_ALPHA, mode, &ctx->h);
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

static inline ut8 alpha_op_count(cs_insn *insn) {
	return insn->detail->alpha.op_count;
}

static inline cs_alpha_op *alpha_op_get(cs_insn *insn, int idx) {
	if (idx >= alpha_op_count(insn)) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\"\n",
			idx, alpha_op_count(insn), insn->mnemonic, insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return &insn->detail->alpha.operands[idx];
}

static inline const char *alpha_op_as_reg(RzAsmAlphaContext *ctx, int idx) {
	const cs_alpha_op *op = alpha_op_get(ctx->insn, idx);
	if (op->type != ALPHA_OP_REG) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [reg]\n",
			idx, alpha_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return cs_reg_name(ctx->h, op->reg);
}

static inline st64 alpha_op_as_imm(RzAsmAlphaContext *ctx, int idx) {
	const cs_alpha_op *op = alpha_op_get(ctx->insn, idx);
	if (op->type != ALPHA_OP_IMM) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [imm]\n",
			idx, alpha_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}
