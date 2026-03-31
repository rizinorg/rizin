// SPDX-FileCopyrightText: 2024 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone/capstone.h>
#include <capstone/loongarch.h>
#include "loongarch.h"

#define LOONGARCH_CPUS "loongarch32,loongarch64"

static inline bool
loongarch_setup_cs_handle(RzAsmLoongArchContext *ctx, bool is_64_bits, bool big_endian) {
	cs_mode mode = big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
	if (mode != ctx->mode) {
		cs_close(&ctx->h);
		ctx->h = 0;
		ctx->mode = mode;
	}

	if (is_64_bits) {
		mode |= CS_MODE_LOONGARCH64;
	} else {
		mode |= CS_MODE_LOONGARCH32;
	}

	if (ctx->h != 0) {
		return true;
	}
	cs_err err = cs_open(CS_ARCH_LOONGARCH, mode, &ctx->h);
	if (err) {
		const char *error_str = cs_strerror(err);
		RZ_LOG_ERROR("Failed on cs_open() with error returned: %u: %s\n", err, error_str);
		return false;
	}
	err = cs_option(ctx->h, CS_OPT_DETAIL, CS_OPT_ON);
	if (err) {
		const char *error_str = cs_strerror(err);
		RZ_LOG_ERROR("Failed on cs_option(CS_OPT_DETAIL, CS_OPT_ON) with error returned: %u: %s\n", err, error_str);
		return false;
	}
	err = cs_option(ctx->h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NO_DOLLAR);
	if (err) {
		const char *error_str = cs_strerror(err);
		RZ_LOG_ERROR("Failed on cs_option(CS_OPT_SYNTAX, CS_OPT_SYNTAX_NO_DOLLAR) with error returned: %u: %s\n", err, error_str);
		return false;
	}
	return true;
}

static inline ut8 loongarch_op_count(cs_insn *insn) {
	return insn->detail->loongarch.op_count;
}

static inline cs_loongarch_op *loongarch_op_get(cs_insn *insn, int idx) {
	if (idx >= loongarch_op_count(insn)) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\"\n",
			idx, loongarch_op_count(insn), insn->mnemonic, insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return &insn->detail->loongarch.operands[idx];
}

static inline bool loongarch_op_is_reg(RzAsmLoongArchContext *ctx, int idx, loongarch_reg reg_no) {
	const cs_loongarch_op *op = loongarch_op_get(ctx->insn, idx);
	if (!op || op->type != LOONGARCH_OP_REG) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [reg]\n",
			idx, loongarch_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return op->reg == reg_no;
}

static inline const char *loongarch_op_as_reg(RzAsmLoongArchContext *ctx, int idx) {
	const cs_loongarch_op *op = loongarch_op_get(ctx->insn, idx);
	if (!op || op->type != LOONGARCH_OP_REG) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [reg]\n",
			idx, loongarch_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return cs_reg_name(ctx->h, op->reg);
}

static inline st64 loongarch_op_as_imm(RzAsmLoongArchContext *ctx, int idx) {
	const cs_loongarch_op *op = loongarch_op_get(ctx->insn, idx);
	if (!op || op->type != LOONGARCH_OP_IMM) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [imm]\n",
			idx, loongarch_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}
