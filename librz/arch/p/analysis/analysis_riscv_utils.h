// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_analysis.h>

#include "cs_operand.h"
#include "rz_util/rz_log.h"

#include <capstone/capstone.h>
#include <capstone/riscv.h>
#include <stdint.h>

// A more high-level alternative to direct indexing that can get immediates and operands without exact
// indices
// While also enforcing high-level constraints such as "exactly one immediate operand is present"
// or "at most one operand is present" or "get the single register that is read/written"

static inline int find_at_most_one_op(cs_riscv_op *operands, uint8_t op_count, riscv_op_type type, const char *type_str) {
	int first = -1;
	for (int i = 0; i < op_count; i++) {
		if (operands[i].type == type) {
			if (first == -1) {
				first = i;
			} else {
				RZ_LOG_FATAL("Expected exactly one %s operand, two elements matched (the %ith and %ith elements)", type_str, first, i);
				exit(-1);
			}
		}
	}
	return first;
}

static inline int find_at_most_one_imm(cs_riscv_op *operands, uint8_t op_count) {
	return find_at_most_one_op(operands, op_count, RISCV_OP_IMM, "immediate");
}

static inline int find_exactly_one_op(cs_riscv_op *operands, uint8_t op_count, riscv_op_type type, const char *type_str) {
	int first = find_at_most_one_op(operands, op_count, type, type_str);
	if (first == -1) {
		RZ_LOG_FATAL("Expected exactly one %s operand, found none", type_str);
		exit(-1);
	}
	return first;
}

static inline int find_exactly_one_imm(cs_riscv_op *operands, uint8_t op_count) {
	return find_exactly_one_op(operands, op_count, RISCV_OP_IMM, "immediate");
}

static inline int64_t get_exactly_one_immediate(cs_riscv_op *operands, uint8_t op_count) {
	return operands[find_exactly_one_imm(operands, op_count)].imm;
}

static inline int64_t get_at_most_one_immediate(cs_riscv_op *operands, uint8_t op_count) {
	int64_t idx = find_at_most_one_imm(operands, op_count);
	if (idx == -1) {
		return INT64_MAX;
	}
	return operands[idx].imm;
}

#define SINGLE_IMM(insn) get_exactly_one_immediate(insn->detail->riscv.operands, insn->detail->riscv.op_count);
#define MAYBE_IMM(insn)  get_at_most_one_immediate(insn->detail->riscv.operands, insn->detail->riscv.op_count);

static inline int find_first_op(cs_riscv_op *operands, uint8_t op_count, riscv_op_type type) {
	for (int i = 0; i < op_count; i++) {
		if (operands[i].type == type) {
			return i;
		}
	}
	return -1;
}

static inline int find_first_imm(cs_riscv_op *operands, uint8_t op_count) {
	return find_first_op(operands, op_count, RISCV_OP_IMM);
}

static inline int64_t get_first_immediate(cs_riscv_op *operands, uint8_t op_count) {
	int idx = find_first_imm(operands, op_count);
	if (idx == -1) {
		return INT64_MAX;
	}
	return operands[idx].imm;
}

#define FIRST_IMM(insn) get_first_immediate(insn->detail->riscv.operands, insn->detail->riscv.op_count);

static inline unsigned int get_any_reg_accessed_as(cs_riscv_op *operands, uint8_t op_count, cs_ac_type access) {
	for (int i = 0; i < op_count; i++) {
		if (operands[i].type == RISCV_OP_REG && (operands[i].access & access)) {
			return operands[i].reg;
		}
	}
	RZ_LOG_FATAL("Expected at least one register with %s access, found none", access == CS_AC_READ ? "read" : "write");
	exit(-1);
	return 0; // dummy for type checking, never reached
}

static inline unsigned int first_read_register(cs_riscv_op *operands, uint8_t op_count) {
	return get_any_reg_accessed_as(operands, op_count, CS_AC_READ);
}

static inline unsigned int first_written_register(cs_riscv_op *operands, uint8_t op_count) {
	return get_any_reg_accessed_as(operands, op_count, CS_AC_WRITE);
}

#define FIRST_READ_REGID(insn)    first_read_register(insn->detail->riscv.operands, insn->detail->riscv.op_count)
#define FIRST_WRITTEN_REGID(insn) first_written_register(insn->detail->riscv.operands, insn->detail->riscv.op_count)

// check if a certain reg is ever accessed as read/write register
static inline bool is_any_reg_accessed_as(cs_riscv_op *operands, uint8_t op_count, unsigned int reg, cs_ac_type access) {
	for (int i = 0; i < op_count; i++) {
		if (operands[i].type == RISCV_OP_REG && operands[i].reg == reg && (operands[i].access & access)) {
			return true;
		}
	}
	return false;
}

static inline bool is_reg_written(cs_riscv_op *operands, uint8_t op_count, unsigned int reg) {
	return is_any_reg_accessed_as(operands, op_count, reg, CS_AC_WRITE);
}
static inline bool is_reg_read(cs_riscv_op *operands, uint8_t op_count, unsigned int reg) {
	return is_any_reg_accessed_as(operands, op_count, reg, CS_AC_READ);
}

#define IS_REG_WRITTEN(insn, reg) is_reg_written(insn->detail->riscv.operands, insn->detail->riscv.op_count, reg)
#define IS_REG_READ(insn, reg)    is_reg_read(insn->detail->riscv.operands, insn->detail->riscv.op_count, reg)

static inline bool is_any_reg_memory_base(cs_riscv_op *operands, uint8_t op_count, unsigned int reg) {
	for (int i = 0; i < op_count; i++) {
		if (operands[i].type == RISCV_OP_MEM && operands[i].mem.base == reg) {
			return true;
		}
	}
	return false;
}

#define MEM_BASE(insn, reg) is_any_reg_memory_base(insn->detail->riscv.operands, insn->detail->riscv.op_count, reg)