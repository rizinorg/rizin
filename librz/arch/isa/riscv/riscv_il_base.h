// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_BASE_H
#define RISCV_IL_BASE_H

#include "riscv.h"
#include "rz_types.h"
#include <rz_analysis.h>

#include "riscv_il.h"
#include "riscv_il_integer_reg_names.h"

#include <rz_il/rz_il_opbuilder_begin.h>

static inline RzILOpBitVector *riscv_il_get_reg(ut32 bits, uint32_t reg) {
	return reg != RISCV_REG_X0 ? VARG(riscv_integer_reg_name(reg)) : UN(bits, 0);
}

static inline RzILOpEffect *riscv_il_set_reg(uint32_t reg, RZ_OWN RZ_NONNULL RzILOpBitVector *value) {
	return reg != RISCV_REG_X0 ? SETG(riscv_integer_reg_name(reg), value) : ((rz_il_op_pure_free(value), NOP()));
}

#define DEFINE_LIFTER(name, decoder, result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return riscv_il_set_reg(rd, result); \
	}

// by default, a RISC-V jump both sets a destination and sets the PC (i.e., jumps)
#define DEFINE_LIFTER_FOR_JUMP(name, decoder, result, jmp_effect) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		decoder(analysis, insn); \
		return SEQ2( \
			riscv_il_set_reg(rd, result), \
			jmp_effect); \
	}

#define DEFINE_LIFTER_WITH_EFFECT(name, decoder, effect) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
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
	static inline FUNC_ATTR_ALWAYS_INLINE RzILOpEffect *rz_riscv_lift_##alias(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) { \
		return rz_riscv_lift_##name(analysis, op, insn, current_addr, size); \
	}

#define TWICE_FOR(name1, name2, def_lifter, ...) \
	def_lifter(name1, __VA_ARGS__) \
		def_lifter(name2, __VA_ARGS__)

#define THRICE_FOR(name1, name2, name3, def_lifter, ...) \
	TWICE_FOR(name1, name2, def_lifter, __VA_ARGS__) \
	def_lifter(name3, __VA_ARGS__)

#define FOR_4(name1, name2, name3, name4, def_lifter, ...) \
	TWICE_FOR(name1, name2, def_lifter, __VA_ARGS__) \
	TWICE_FOR(name3, name4, def_lifter, __VA_ARGS__)

#if RZ_CHECKS_LEVEL > 0
static inline void riscv_il_dump_operands(RZ_NONNULL cs_insn *insn) {
	RZ_LOG_ERROR("op_str: %s\n", insn->op_str);
	RZ_LOG_ERROR("need_effective_addr: %d\n", insn->detail->riscv.need_effective_addr);
	RZ_LOG_ERROR("op_count: %u\n", insn->detail->riscv.op_count);
	for (int i = 0; i < insn->detail->riscv.op_count; i++) {
		RZ_LOG_ERROR("operands[%d].type: %d\n", i, insn->detail->riscv.operands[i].type);
		if (insn->detail->riscv.operands[i].type == RISCV_OP_REG) {
			RZ_LOG_ERROR("  REG = %d\n", insn->detail->riscv.operands[i].reg);
		} else if (insn->detail->riscv.operands[i].type == RISCV_OP_IMM) {
			RZ_LOG_ERROR("  IMM = 0x%" PFMT64x "\n", (ut64)insn->detail->riscv.operands[i].imm);
		} else if (insn->detail->riscv.operands[i].type == RISCV_OP_MEM) {
			RZ_LOG_ERROR("  MEM base = %d, disp = 0x%" PFMT64x "\n", insn->detail->riscv.operands[i].mem.base, (ut64)insn->detail->riscv.operands[i].mem.disp);
		}
	}
}

static inline void riscv_il_log_operand_mismatch(RZ_NONNULL cs_insn *insn, ut64 current_addr, int idx, int type, const char *type_name) {
	RZ_LOG_ERROR("[%s (%d) @ 0x%08" PFMT64x "] Expected type %d (%s) at index %d, found type %d instead\n",
		insn->mnemonic, insn->id, current_addr, type, type_name, idx, insn->detail->riscv.operands[idx].type);
	riscv_il_dump_operands(insn);
}

static inline bool riscv_il_require_op(RZ_NONNULL cs_insn *insn, ut64 current_addr, int idx, int type, const char *type_name) {
	if (insn->detail->riscv.operands[idx].type == type && insn->detail->riscv.operands[idx].type != RISCV_OP_INVALID) {
		return true;
	}
	riscv_il_log_operand_mismatch(insn, current_addr, idx, type, type_name);
	return false;
}

static inline bool riscv_il_require_64_bit(RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL cs_insn *insn) {
	if (analysis->bits == 64) {
		return true;
	}
	RZ_LOG_ERROR("[%s (%d)] Expected 64-bit analysis, found %d bits\n", insn->mnemonic, insn->id, analysis->bits);
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
	RzILOpBitVector *rs = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[2].imm);

#define DECODE_RD_RS_RS(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[2].reg);

#define DECODE_RS_IMM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_IMM); \
	RzILOpBitVector *rs = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].imm);

#define DECODE_RS_RS_IMM(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	RzILOpBitVector *rs1 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[2].imm);

#define DECODE_RD_RS(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg);

#define DECODE_IMM(analysis, insn) \
	REQUIRE_OP(0, RISCV_OP_IMM); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[0].imm);

#define DECODE_RD_IMM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].imm);

#define DECODE_RS_RS_IMM_MEM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_MEM); \
	RzILOpBitVector *rs1 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs2 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define DECODE_RD_RS_IMM_MEM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_MEM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

// used for *w instructions in RV64 that truncate the operands to 32 bits then does the operation
#define DECODE_RD_RS_RS_TRUNCATE32(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = CAST(32, IL_FALSE, riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg)); \
	RzILOpBitVector *rs2 = CAST(32, IL_FALSE, riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[2].reg));

#define DECODE_RD_RS_IMM_TRUNCATE32(analysis, insn) \
	REQUIRE_64_BIT(analysis); \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = CAST(32, IL_FALSE, riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg)); \
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