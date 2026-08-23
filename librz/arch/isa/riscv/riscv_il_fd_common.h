// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_FD_COMMON_H
#define RISCV_IL_FD_COMMON_H

#include "riscv_il.h"

#include <rz_util/rz_float.h>

/**
 * The RzFloat format is the complete F/D specialization parameter. Field
 * widths, field offsets, exponent bias, canonical NaN, and NaN-boxing are all
 * derived from its metadata and the fixed 64-bit floating-register storage.
 */

// Decoder macros follow the RISC-V IL convention: validate Capstone operands,
// then bind the instruction's register IDs and IL operands in the lifter scope.
#define DECODE_FD_FD_MEM(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_MEM); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpBitVector *base = riscv_il_get_reg((analysis)->bits, (insn)->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *offset = SN((analysis)->bits, (insn)->detail->riscv.operands[1].mem.disp)

#define DECODE_FD_FS_MEM(format, analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_MEM); \
	RzILOpBitVector *value = fd_get_reg_bv((format), (insn)->detail->riscv.operands[0].reg); \
	RzILOpBitVector *base = riscv_il_get_reg((analysis)->bits, (insn)->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *offset = SN((analysis)->bits, (insn)->detail->riscv.operands[1].mem.disp)

#define DECODE_FD_FD_FS_FS(format, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpFloat *left = fd_get_reg((format), (insn)->detail->riscv.operands[1].reg); \
	RzILOpFloat *right = fd_get_reg((format), (insn)->detail->riscv.operands[2].reg)

#define DECODE_FD_FD_FS(format, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpFloat *source = fd_get_reg((format), (insn)->detail->riscv.operands[1].reg)

#define DECODE_FD_FD_FS_FS_FS(format, insn) \
	REQUIRE_OP(0, RISCV_OP_REG); \
	REQUIRE_OP(1, RISCV_OP_REG); \
	REQUIRE_OP(2, RISCV_OP_REG); \
	REQUIRE_OP(3, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpFloat *left = fd_get_reg((format), (insn)->detail->riscv.operands[1].reg); \
	RzILOpFloat *right = fd_get_reg((format), (insn)->detail->riscv.operands[2].reg); \
	RzILOpFloat *addend = fd_get_reg((format), (insn)->detail->riscv.operands[3].reg)

#define DECODE_FD_FD_BV_BV(format, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpBitVector *left = fd_get_reg_bv((format), (insn)->detail->riscv.operands[1].reg); \
	RzILOpBitVector *right = fd_get_reg_bv((format), (insn)->detail->riscv.operands[2].reg)

#define DECODE_FD_FD_FREGS(insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	uint32_t frs1 = (insn)->detail->riscv.operands[1].reg; \
	uint32_t frs2 = (insn)->detail->riscv.operands[2].reg

#define DECODE_FD_RD_FREGS(insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = (insn)->detail->riscv.operands[0].reg; \
	uint32_t frs1 = (insn)->detail->riscv.operands[1].reg; \
	uint32_t frs2 = (insn)->detail->riscv.operands[2].reg

#define DECODE_FD_RD_FS_BV(format, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpBitVector *value = fd_get_reg_bv((format), (insn)->detail->riscv.operands[1].reg)

#define DECODE_FD_FD_RS(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpBitVector *source = riscv_il_get_reg((analysis)->bits, (insn)->detail->riscv.operands[1].reg)

#define DECODE_FD_FD_FS_FORMAT(source_format, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t frd = (insn)->detail->riscv.operands[0].reg; \
	RzILOpFloat *source = fd_get_reg_format((source_format), (insn)->detail->riscv.operands[1].reg)

RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_load(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_store(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_add(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_sub(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_mul(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_div(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_sqrt(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmadd(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmsub(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fnmadd(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fnmsub(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnj(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnjn(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fsgnjx(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmin(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmax(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_feq(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_flt(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fle(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fclass(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_w(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_wu(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_l(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_lu(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_w(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_wu(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_l(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_from_lu(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_format(
	RzFloatFormat destination_format,
	RzFloatFormat source_format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmv_to_x(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fmv_from_x(
	RzFloatFormat format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);

#endif // RISCV_IL_FD_COMMON_H
