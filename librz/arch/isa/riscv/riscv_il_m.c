// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_m.h"

#include "analysis_private.h"

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// M extension: multiply/divide/remainder (RV32M / RV64M)

// RV32M
DEFINE_LIFTER(mul, DECODE_RD_RS_RS, MUL(rs1, rs2))
DEFINE_LIFTER(mulh, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(SIGNED(analysis->bits * 2, rs1), SIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(mulhsu, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(SIGNED(analysis->bits * 2, rs1), UNSIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(mulhu, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(UNSIGNED(analysis->bits * 2, rs1), UNSIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(div, DECODE_RD_RS_RS, SDIV(rs1, rs2))
DEFINE_LIFTER(divu, DECODE_RD_RS_RS, DIV(rs1, rs2))
DEFINE_LIFTER(rem, DECODE_RD_RS_RS, SMOD(rs1, rs2))
DEFINE_LIFTER(remu, DECODE_RD_RS_RS, MOD(rs1, rs2))

// RV64M: *w instructions operate on lower 32 bits, result sign-extended to 64 bits
DEFINE_LIFTER(mulw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, MUL(rs1, rs2)))
DEFINE_LIFTER(divw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SDIV(rs1, rs2)))
DEFINE_LIFTER(divuw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, DIV(rs1, rs2)))
DEFINE_LIFTER(remw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SMOD(rs1, rs2)))
DEFINE_LIFTER(remuw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, MOD(rs1, rs2)))

#include <rz_il/rz_il_opbuilder_end.h>
