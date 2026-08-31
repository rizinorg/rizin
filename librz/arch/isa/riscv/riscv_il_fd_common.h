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

#define DECL_FD_LIFTER(suffix) \
	RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_ ## suffix(RzFloatFormat format, \
		RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, \
		RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size)

DECL_FD_LIFTER(load);
DECL_FD_LIFTER(store);
DECL_FD_LIFTER(add);
DECL_FD_LIFTER(sub);
DECL_FD_LIFTER(mul);
DECL_FD_LIFTER(div);
DECL_FD_LIFTER(sqrt);
DECL_FD_LIFTER(fmadd);
DECL_FD_LIFTER(fmsub);
DECL_FD_LIFTER(fnmadd);
DECL_FD_LIFTER(fnmsub);
DECL_FD_LIFTER(fsgnj);
DECL_FD_LIFTER(fsgnjn);
DECL_FD_LIFTER(fsgnjx);
DECL_FD_LIFTER(fmin);
DECL_FD_LIFTER(fmax);
DECL_FD_LIFTER(feq);
DECL_FD_LIFTER(flt);
DECL_FD_LIFTER(fle);
DECL_FD_LIFTER(fclass);
DECL_FD_LIFTER(fcvt_w);
DECL_FD_LIFTER(fcvt_wu);
DECL_FD_LIFTER(fcvt_l);
DECL_FD_LIFTER(fcvt_lu);
DECL_FD_LIFTER(fcvt_from_w);
DECL_FD_LIFTER(fcvt_from_wu);
DECL_FD_LIFTER(fcvt_from_l);
DECL_FD_LIFTER(fcvt_from_lu);
RZ_OWN RZ_IPI RzILOpEffect *riscv_il_fd_lift_fcvt_format(
	RzFloatFormat destination_format,
	RzFloatFormat source_format,
	RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op,
	RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size);
DECL_FD_LIFTER(fmv_to_x);
DECL_FD_LIFTER(fmv_from_x);

#endif // RISCV_IL_FD_COMMON_H
