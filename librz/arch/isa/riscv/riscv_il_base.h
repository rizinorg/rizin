// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_BASE_H
#define RISCV_IL_BASE_H

#include "riscv.h"
#include "rz_types.h"
#include <rz_analysis.h>

#include "riscv_il_integer_reg_names.h"

#include <rz_il/rz_il_opbuilder_begin.h>

static inline RzILOpBitVector *riscv_il_get_reg(ut32 bits, uint32_t reg) {
	return reg != RISCV_REG_X0 ? VARG(riscv_integer_reg_name(reg)) : UN(bits, 0);
}

static inline RzILOpEffect *riscv_il_set_reg(uint32_t reg, RZ_OWN RZ_NONNULL RzILOpBitVector *value) {
	if (reg != RISCV_REG_X0) {
		return SETG(riscv_integer_reg_name(reg), value);
	}
	// assigning to x0 is a no-op, so the value will never be referenced in the IL tree
	rz_il_op_pure_free(value);
	return NOP();
}

#define DEFINE_LIFTER(name, decoder, result) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return riscv_il_set_reg(rd, result); \
	}

// by default, a RISC-V jump both sets a destination and sets the PC (i.e., jumps)
#define DEFINE_LIFTER_FOR_JUMP(name, decoder, result, jmp_effect) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return SEQ2( \
			riscv_il_set_reg(rd, result), \
			jmp_effect); \
	}

#define DEFINE_LIFTER_WITH_EFFECT(name, decoder, effect) \
	RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return effect; \
	}

// oneway jumps are those that don't have a destination register
#define DEFINE_LIFTER_FOR_ONEWAY_JUMP DEFINE_LIFTER_WITH_EFFECT

// A more intuitive definition would be:
//   static const RiscvInstructionLifter rz_riscv_lift_##alias = ...;
// but C (unlike C++) does not treat const-qualified variables as constant expressions
// (C11 §6.6), so they cannot appear in a static array initializer. Most compilers
// accept it tolerantly, but TCC enforces the standard strictly and rejects it.
// A forced-inline wrapper is an alternative for 0-indirection aliasing.
#define DEFINE_ALIAS_LIFTER(alias, name) \
	RzILOpEffect *rz_riscv_lift_##alias(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		return rz_riscv_lift_##name(analysis, op, insn, current_addr, size); \
	}

#if RZ_CHECKS_LEVEL > 0
static inline bool riscv_il_require_op(RZ_NONNULL cs_insn *insn, ut64 current_addr, int idx, int type, const char *type_name) {
	if (insn->detail->riscv.operands[idx].type == type && insn->detail->riscv.operands[idx].type != RISCV_OP_INVALID) {
		return true;
	}
	return false;
}

static inline bool riscv_il_require_64_bit(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL cs_insn *insn) {
	if (rz_analysis_get_bits(analysis) == 64) {
		return true;
	}
	// RZ_LOG_ERROR("[%s (%d)] Expected 64-bit analysis, found %d bits\n", insn->mnemonic, insn->id, rz_analysis_get_bits(analysis));
	return false;
}

#define REQUIRE_OP(idx, t) \
	if (!riscv_il_require_op(insn, current_addr, idx, t, #t)) { \
		return NULL; \
	}

#define REQUIRE_64_BIT(analysis) \
	if (!riscv_il_require_64_bit(analysis, insn)) { \
		return NULL; \
	}

#define REQUIRE_2OPS(t0, t1) \
	REQUIRE_OP(0, t0); \
	REQUIRE_OP(1, t1)

#define REQUIRE_3OPS(t0, t1, t2) \
	REQUIRE_OP(0, t0); \
	REQUIRE_OP(1, t1); \
	REQUIRE_OP(2, t2)
#else
#define REQUIRE_OP(idx, t) \
	do { \
	} while (0)
#define REQUIRE_64_BIT(analysis) \
	do { \
	} while (0)
#define REQUIRE_2OPS(t0, t1) \
	do { \
	} while (0)
#define REQUIRE_3OPS(t0, t1, t2) \
	do { \
	} while (0)
#endif

// Decoders, every instruction defines how its own transformation of capstone operands to IL operands

#define DECODE_RD_RS_IMM(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[2].imm);

#define DECODE_RD_RS_RS(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[2].reg);

#define DECODE_RS_IMM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_IMM); \
	RzILOpBitVector *rs = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].imm);

#define DECODE_RS_RS_IMM(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	RzILOpBitVector *rs1 = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[2].imm);

#define DECODE_RD_RS(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].reg);

#define DECODE_IMM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_IMM); \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[0].imm);

#define DECODE_RD_IMM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].imm);

#define DECODE_RS_RS_IMM_MEM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_MEM); \
	RzILOpBitVector *rs1 = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].mem.disp);

#define DECODE_RD_RS_IMM_MEM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_MEM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].mem.disp);

// used for *w instructions in RV64 that truncate the operands to 32 bits then does the operation
#define DECODE_RD_RS_RS_TRUNCATE32(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = CAST(32, IL_FALSE, riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].reg)); \
	RzILOpBitVector *rs2 = CAST(32, IL_FALSE, riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[2].reg));

#define DECODE_RD_RS_IMM_TRUNCATE32(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = CAST(32, IL_FALSE, riscv_il_get_reg(rz_analysis_get_bits(analysis), insn->detail->riscv.operands[1].reg)); \
	RzILOpBitVector *imm = SN(32, insn->detail->riscv.operands[2].imm);

#define DECODE_RD_IMM_TRUNCATE32(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *imm = SN(32, insn->detail->riscv.operands[1].imm);

#define DECODE_NONE(analysis, insn) \
	(void)analysis; \
	(void)insn;

#define USE_LIFTER(name, uppername) [RISCV_INS_##uppername] = rz_riscv_lift_##name

#include <rz_il/rz_il_opbuilder_end.h>

#endif // RISCV_IL_BASE_H
