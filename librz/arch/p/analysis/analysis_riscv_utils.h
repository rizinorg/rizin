// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ANALYSIS_RISCV_UTILS_H
#define ANALYSIS_RISCV_UTILS_H

#include <rz_analysis.h>

#include <capstone/capstone.h>
#include <capstone/riscv.h>
#include <stdint.h>

// A more high-level alternative to direct indexing that can get immediates and operands without exact indices
// While also enforcing high-level constraints such as "exactly one immediate operand is present"  or "at most
// one operand is present" or "get the single register that is read/written"

static inline ut32 find_at_most_one_op(cs_riscv_op *operands, uint8_t op_count, riscv_op_type type, const char *type_str) {
	ut32 first = UT32_MAX;
	for (ut32 i = 0; i < op_count; i++) {
		if (operands[i].type == type) {
			if (first == UT32_MAX) {
				first = i;
			} else {
				RZ_LOG_DEBUG("Expected exactly one %s operand, two elements matched (the %ith and %ith elements)", type_str, first, i);
			}
		}
	}
	return first;
}

static inline ut32 find_at_most_one_imm(cs_riscv_op *operands, uint8_t op_count) {
	return find_at_most_one_op(operands, op_count, RISCV_OP_IMM, "immediate");
}

static inline ut32 find_exactly_one_op(cs_riscv_op *operands, uint8_t op_count, riscv_op_type type, const char *type_str) {
	return find_at_most_one_op(operands, op_count, type, type_str);
}

static inline ut32 find_exactly_one_imm(cs_riscv_op *operands, uint8_t op_count) {
	return find_exactly_one_op(operands, op_count, RISCV_OP_IMM, "immediate");
}

static inline int64_t get_exactly_one_immediate(cs_riscv_op *operands, uint8_t op_count) {
	ut32 idx = find_exactly_one_imm(operands, op_count);
	if (idx < op_count) {
		return operands[idx].imm;
	}
	return INT64_MAX;
}

static inline int64_t get_at_most_one_immediate(cs_riscv_op *operands, uint8_t op_count) {
	ut32 idx = find_at_most_one_imm(operands, op_count);
	if (idx < op_count) {
		return operands[idx].imm;
	}
	return INT64_MAX;
}

#define SINGLE_IMM(insn) get_exactly_one_immediate(insn->detail->riscv.operands, insn->detail->riscv.op_count);
#define MAYBE_IMM(insn)  get_at_most_one_immediate(insn->detail->riscv.operands, insn->detail->riscv.op_count);

static inline ut32 find_first_op(cs_riscv_op *operands, uint8_t op_count, riscv_op_type type) {
	for (ut32 i = 0; i < op_count; i++) {
		if (operands[i].type == type) {
			return i;
		}
	}
	return UT32_MAX;
}

static inline ut32 find_first_imm(cs_riscv_op *operands, uint8_t op_count) {
	return find_first_op(operands, op_count, RISCV_OP_IMM);
}

static inline int64_t get_first_immediate(cs_riscv_op *operands, uint8_t op_count) {
	ut32 idx = find_first_imm(operands, op_count);
	if (idx < op_count) {
		return operands[idx].imm;
	}
	return INT64_MAX;
}

#define FIRST_IMM(insn) get_first_immediate(insn->detail->riscv.operands, insn->detail->riscv.op_count);

static inline ut32 get_any_reg_accessed_as(cs_riscv_op *operands, uint8_t op_count, cs_ac_type access) {
	for (ut32 i = 0; i < op_count; i++) {
		if (operands[i].type == RISCV_OP_REG && (operands[i].access & access)) {
			return operands[i].reg;
		}
	}
	RZ_LOG_DEBUG("Expected at least one register with %s access, found none", access == CS_AC_READ ? "read" : "write");
	return 0; // dummy for type checking, never reached
}

static inline ut32 first_read_register(cs_riscv_op *operands, uint8_t op_count) {
	return get_any_reg_accessed_as(operands, op_count, CS_AC_READ);
}

static inline ut32 first_written_register(cs_riscv_op *operands, uint8_t op_count) {
	return get_any_reg_accessed_as(operands, op_count, CS_AC_WRITE);
}

#define FIRST_READ_REGID(insn)    first_read_register(insn->detail->riscv.operands, insn->detail->riscv.op_count)
#define FIRST_WRITTEN_REGID(insn) first_written_register(insn->detail->riscv.operands, insn->detail->riscv.op_count)

// check if a certain reg is ever accessed as read/write register
static inline bool is_any_reg_accessed_as(cs_riscv_op *operands, uint8_t op_count, ut32 reg, cs_ac_type access) {
	for (int i = 0; i < op_count; i++) {
		if (operands[i].type == RISCV_OP_REG && operands[i].reg == reg && (operands[i].access & access)) {
			return true;
		}
	}
	return false;
}

static inline bool is_reg_written(cs_riscv_op *operands, uint8_t op_count, ut32 reg) {
	return is_any_reg_accessed_as(operands, op_count, reg, CS_AC_WRITE);
}
static inline bool is_reg_read(cs_riscv_op *operands, uint8_t op_count, ut32 reg) {
	return is_any_reg_accessed_as(operands, op_count, reg, CS_AC_READ);
}

#define IS_REG_WRITTEN(insn, reg) is_reg_written(insn->detail->riscv.operands, insn->detail->riscv.op_count, reg)
#define IS_REG_READ(insn, reg)    is_reg_read(insn->detail->riscv.operands, insn->detail->riscv.op_count, reg)

static inline bool is_any_reg_memory_base(cs_riscv_op *operands, uint8_t op_count, unsigned int reg) {
	for (ut32 i = 0; i < op_count; i++) {
		if (operands[i].type == RISCV_OP_MEM && operands[i].mem.base == reg) {
			return true;
		}
	}
	return false;
}

#define MEM_BASE(insn, reg) is_any_reg_memory_base(insn->detail->riscv.operands, insn->detail->riscv.op_count, reg)

#endif /* ANALYSIS_RISCV_UTILS_H */
