// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_M_H
#define RISCV_IL_M_H

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// M extension: multiply/divide/remainder (RV32M / RV64M)
DEFINE_LIFTER(mul, DECODE_RD_RS_RS, MUL(rs1, rs2))
DEFINE_LIFTER(mulhu, DECODE_RD_RS_RS, CAST(analysis->bits, IL_FALSE, SHIFTR0(MUL(UNSIGNED(analysis->bits * 2, rs1), UNSIGNED(analysis->bits * 2, rs2)), UN(8, analysis->bits))))
DEFINE_LIFTER(divu, DECODE_RD_RS_RS, DIV(rs1, rs2))
DEFINE_LIFTER(remu, DECODE_RD_RS_RS, MOD(rs1, rs2))
// RV64M: unsigned remainder of 32-bit operands, result sign-extended to 64 bits
DEFINE_LIFTER(remuw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, MOD(rs1, rs2)))

#include <rz_il/rz_il_opbuilder_end.h>

#endif // RISCV_IL_M_H
