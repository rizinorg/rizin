// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-FileCopyrightText: 2024 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone/capstone.h>
#include <capstone/hppa.h>
#include "hppa.h"

static inline cs_mode hppa_cpu_to_cs_mode(const char *cpu_type) {
	if (RZ_STR_ISNOTEMPTY(cpu_type)) {
		if (!strcmp(cpu_type, "hppa1.1")) {
			return CS_MODE_HPPA_11;
		}
		if (!strcmp(cpu_type, "hppa2.0")) {
			return CS_MODE_HPPA_20;
		}
		if (!strcmp(cpu_type, "hppa2.0w")) {
			return CS_MODE_HPPA_20W;
		}
	}
	return CS_MODE_HPPA_11;
}

static inline bool hppa_setup_cs_handle(RzAsmHPPAContext *ctx, const char *cpu, const char *features, bool big_endian) {
	const cs_mode mode = hppa_cpu_to_cs_mode(cpu) | (big_endian ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN);
	if (mode != ctx->mode) {
		cs_close(&ctx->h);
		ctx->h = 0;
		ctx->mode = mode;
	}

	if (ctx->h != 0) {
		return true;
	}
	cs_err err = cs_open(CS_ARCH_HPPA, mode, &ctx->h);
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

static inline ut8 hppa_op_count(cs_insn *insn) {
	return insn->detail->hppa.op_count;
}

static inline cs_hppa_op *hppa_op_get(cs_insn *insn, int idx) {
	if (idx >= hppa_op_count(insn)) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\"\n",
			idx, hppa_op_count(insn), insn->mnemonic, insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return &insn->detail->hppa.operands[idx];
}

static inline const char *hppa_op_as_reg(RzAsmHPPAContext *ctx, int idx) {
	const cs_hppa_op *op = hppa_op_get(ctx->insn, idx);
	if (op->type != HPPA_OP_REG) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [reg]\n",
			idx, hppa_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return cs_reg_name(ctx->h, op->reg);
}

static inline const char *hppa_op_as_mem(RzAsmHPPAContext *ctx, int idx) {
	const cs_hppa_op *op = hppa_op_get(ctx->insn, idx);
	if (op->type != HPPA_OP_MEM) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [reg]\n",
			idx, hppa_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return NULL;
	}
	return cs_reg_name(ctx->h, op->reg);
}

static inline st64 hppa_op_as_imm(RzAsmHPPAContext *ctx, int idx) {
	const cs_hppa_op *op = hppa_op_get(ctx->insn, idx);
	if (op->type != HPPA_OP_IMM) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [imm]\n",
			idx, hppa_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}

static inline st64 hppa_op_as_disp(RzAsmHPPAContext *ctx, int idx) {
	const cs_hppa_op *op = hppa_op_get(ctx->insn, idx);
	if (op->type != HPPA_OP_DISP) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [imm]\n",
			idx, hppa_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}

static inline st64 hppa_op_as_target(RzAsmHPPAContext *ctx, int idx) {
	const cs_hppa_op *op = hppa_op_get(ctx->insn, idx);
	if (op->type != HPPA_OP_TARGET) {
		RZ_LOG_WARN("Failed to get operand%d [%d]: \"%s %s\" [imm]\n",
			idx, hppa_op_count(ctx->insn), ctx->insn->mnemonic, ctx->insn->op_str);
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}
