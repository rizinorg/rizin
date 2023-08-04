// SPDX-FileCopyrightText: 2023 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <capstone/tricore.h>

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

static inline cs_tricore_op *tricore_get_op(cs_insn *insn, int idx) {
	if (idx >= insn->detail->tricore.op_count) {
		rz_warn_if_reached();
		return NULL;
	}
	return &insn->detail->tricore.operands[idx];
}

static inline const char *tricore_get_op_regname(csh h, cs_insn *insn, int idx) {
	cs_tricore_op *op = tricore_get_op(insn, idx);
	if (op->type != TRICORE_OP_REG) {
		rz_warn_if_reached();
		return NULL;
	}
	return cs_reg_name(h, op->reg);
}

static inline st32 tricore_get_op_imm(cs_insn *insn, int idx) {
	cs_tricore_op *op = tricore_get_op(insn, idx);
	if (op->type != TRICORE_OP_IMM) {
		rz_warn_if_reached();
		return 0;
	}
	return op->imm;
}

static inline ut8 tricore_op_count(cs_insn *insn) {
	return insn->detail->tricore.op_count;
}
