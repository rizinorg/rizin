// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RISCV_IL_COMPRESSED_H
#define RISCV_IL_COMPRESSED_H

#include "riscv/riscv_il_base.h"
#include "riscv_il_integer.h"
#include "rz_util/rz_buf.h"

#include <rz_il/rz_il_opbuilder_begin.h>

// Compressed instruction decoder variants that suppress operands not consumed by the lifter
#define DECODE_RD_RS_IMM_NO_RS(analysis, insn) \
	DECODE_RD_RS_IMM(analysis, insn) \
	(void)(rs);

#define DECODE_RD_IMM_NO_RD(analysis, insn) \
	DECODE_RD_IMM(analysis, insn) \
	(void)(rd);

#define DECODE_RS_RS_IMM_NO_RS2(analysis, insn) \
	DECODE_RS_RS_IMM(analysis, insn) \
	(void)(rs2);

DEFINE_ALIAS_LIFTER(c_addi, addi)
DEFINE_ALIAS_LIFTER(c_addi16sp, addi)
DEFINE_ALIAS_LIFTER(c_addi4spn, addi)
DEFINE_ALIAS_LIFTER(c_add, add)
DEFINE_ALIAS_LIFTER(c_slli, slli)
DEFINE_ALIAS_LIFTER(c_andi, andi)
DEFINE_ALIAS_LIFTER(c_srli, srli)
DEFINE_ALIAS_LIFTER(c_srai, srai)
DEFINE_ALIAS_LIFTER(c_or, or)
DEFINE_ALIAS_LIFTER(c_sub, sub)
DEFINE_ALIAS_LIFTER(c_and, and)
DEFINE_ALIAS_LIFTER(c_xor, xor)
DEFINE_ALIAS_LIFTER(c_addw, addw)

DEFINE_ALIAS_LIFTER(c_addiw, addiw)

DEFINE_ALIAS_LIFTER(c_subw, subw)

DEFINE_LIFTER(c_mv, DECODE_RD_RS, DUP(rs))
DEFINE_LIFTER(c_li, DECODE_RD_RS_IMM_NO_RS, DUP(imm))

DEFINE_LIFTER_FOR_ONEWAY_JUMP(c_j, DECODE_RD_IMM_NO_RD, JMP(imm))
DEFINE_ALIAS_LIFTER(c_jr, jalr)

DEFINE_ALIAS_LIFTER(c_jalr, jalr)

DEFINE_ALIAS_LIFTER(c_lui, lui)

DEFINE_ALIAS_LIFTER(c_sw, sw)
DEFINE_ALIAS_LIFTER(c_swsp, sw)

DEFINE_ALIAS_LIFTER(c_sd, sd)
DEFINE_ALIAS_LIFTER(c_sdsp, sd)

DEFINE_ALIAS_LIFTER(c_lwsp, lw)
DEFINE_ALIAS_LIFTER(c_lw, lw)

DEFINE_ALIAS_LIFTER(c_ld, ld)
DEFINE_ALIAS_LIFTER(c_ldsp, ld)

DEFINE_LIFTER_FOR_BRANCH(c_beqz, DECODE_RS_RS_IMM_NO_RS2, EQ(rs1, UN(analysis->bits, 0)))
DEFINE_LIFTER_FOR_BRANCH(c_bnez, DECODE_RS_RS_IMM_NO_RS2, NE(rs1, UN(analysis->bits, 0)))

#include <rz_il/rz_il_opbuilder_end.h>

#endif // RISCV_IL_COMPRESSED_H
