// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_m.h"

#include "analysis_private.h"

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// M extension: multiply/divide/remainder (RV32M / RV64M)

static inline RzILOpBitVector *riscv_il_div_by_zero_result(ut32 bits) {
	return UN(bits, UT64_MAX);
}

static inline RzILOpBitVector *riscv_il_sdiv(ut32 bits, RZ_OWN RzILOpBitVector *rs1, RZ_OWN RzILOpBitVector *rs2) {
	return ITE(IS_ZERO(DUP(rs2)), riscv_il_div_by_zero_result(bits), SDIV(rs1, rs2));
}

static inline RzILOpBitVector *riscv_il_divu(ut32 bits, RZ_OWN RzILOpBitVector *rs1, RZ_OWN RzILOpBitVector *rs2) {
	return ITE(IS_ZERO(DUP(rs2)), riscv_il_div_by_zero_result(bits), DIV(rs1, rs2));
}

// RV32M
DEFINE_LIFTER(mul, DECODE_RD_RS_RS, MUL(rs1, rs2))
DEFINE_LIFTER(mulh, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(SIGNED(analysis->bits * 2, rs1), SIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(mulhsu, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(SIGNED(analysis->bits * 2, rs1), UNSIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(mulhu, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(UNSIGNED(analysis->bits * 2, rs1), UNSIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(div, DECODE_RD_RS_RS, riscv_il_sdiv(analysis->bits, rs1, rs2))
DEFINE_LIFTER(divu, DECODE_RD_RS_RS, riscv_il_divu(analysis->bits, rs1, rs2))
DEFINE_LIFTER(rem, DECODE_RD_RS_RS, SMOD(rs1, rs2))
DEFINE_LIFTER(remu, DECODE_RD_RS_RS, MOD(rs1, rs2))

// RV64M: *w instructions operate on lower 32 bits, result sign-extended to 64 bits
DEFINE_LIFTER(mulw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, MUL(rs1, rs2)))
DEFINE_LIFTER(divw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, riscv_il_sdiv(32, rs1, rs2)))
DEFINE_LIFTER(divuw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, riscv_il_divu(32, rs1, rs2)))
DEFINE_LIFTER(remw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SMOD(rs1, rs2)))
DEFINE_LIFTER(remuw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, MOD(rs1, rs2)))

#include <rz_il/rz_il_opbuilder_end.h>
