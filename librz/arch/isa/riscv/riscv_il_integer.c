// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_integer.h"

#include "analysis_private.h"
#include "capstone.h"

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

DEFINE_LIFTER(addi, DECODE_RD_RS_IMM, ADD(rs, imm))
DEFINE_LIFTER(slli, DECODE_RD_RS_IMM, SHIFTL0(rs, imm))
DEFINE_LIFTER(andi, DECODE_RD_RS_IMM, LOGAND(rs, imm))
DEFINE_LIFTER(ori, DECODE_RD_RS_IMM, LOGOR(rs, imm))
DEFINE_LIFTER(xori, DECODE_RD_RS_IMM, LOGXOR(rs, imm))
DEFINE_LIFTER(slti, DECODE_RD_RS_IMM, BOOL_TO_BV(SLT(rs, imm), analysis->bits))
DEFINE_LIFTER(sltiu, DECODE_RD_RS_IMM, BOOL_TO_BV(ULT(rs, imm), analysis->bits))
DEFINE_LIFTER(srli, DECODE_RD_RS_IMM, SHIFTR0(rs, imm))
DEFINE_LIFTER(srai, DECODE_RD_RS_IMM, SHIFTRA(rs, imm))

DEFINE_LIFTER(add, DECODE_RD_RS_RS, ADD(rs1, rs2))
DEFINE_LIFTER(sub, DECODE_RD_RS_RS, SUB(rs1, rs2))
DEFINE_LIFTER(and, DECODE_RD_RS_RS, LOGAND(rs1, rs2))
DEFINE_LIFTER(or, DECODE_RD_RS_RS, LOGOR(rs1, rs2))
DEFINE_LIFTER(xor, DECODE_RD_RS_RS, LOGXOR(rs1, rs2))
DEFINE_LIFTER(slt, DECODE_RD_RS_RS, BOOL_TO_BV(SLT(rs1, rs2), analysis->bits))
DEFINE_LIFTER(sltu, DECODE_RD_RS_RS, BOOL_TO_BV(ULT(rs1, rs2), analysis->bits))
DEFINE_LIFTER(sll, DECODE_RD_RS_RS, SHIFTL0(rs1, LOGAND(rs2, UN(analysis->bits, analysis->bits - 1))))
DEFINE_LIFTER(srl, DECODE_RD_RS_RS, SHIFTR0(rs1, LOGAND(rs2, UN(analysis->bits, analysis->bits - 1))))
DEFINE_LIFTER(sra, DECODE_RD_RS_RS, SHIFTRA(rs1, LOGAND(rs2, UN(analysis->bits, analysis->bits - 1))))

#define DEFINE_LIFTER_FOR_BRANCH(name, decoder, condition) \
	DEFINE_LIFTER_FOR_ONEWAY_JUMP(name, decoder, BRANCH(condition, JMP(imm), JMP(UN(analysis->bits, current_addr + size))))

DEFINE_LIFTER_FOR_BRANCH(beq, DECODE_RS_RS_IMM, EQ(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bne, DECODE_RS_RS_IMM, NE(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(blt, DECODE_RS_RS_IMM, SLT(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bge, DECODE_RS_RS_IMM, SGE(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bltu, DECODE_RS_RS_IMM, ULT(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bgeu, DECODE_RS_RS_IMM, UGE(rs1, rs2))

DEFINE_LIFTER_FOR_JUMP(jal, DECODE_RD_IMM,
	/*RETURN ADDR*/ UN(analysis->bits, current_addr + size),
	/*GOTO ADDR*/ JMP(imm))

DEFINE_LIFTER_FOR_JUMP(jalr, DECODE_RD_RS_IMM,
	/*RETURN ADDR*/ UN(analysis->bits, current_addr + size),
	/*GOTO ADDR*/ JMP(LOGAND(ADD(rs, imm), UN(analysis->bits, ~1ULL))))

// Intentional: on RV32 imm is already 32-bit and the result needs no sign-extension,
// so CAST(32) and SIGNED(32) would both be no-ops; on RV64 CAST(32) truncates imm and SIGNED(64)
// sign-extends the shifted 32-bit result to XLEN.
DEFINE_LIFTER(lui, DECODE_RD_IMM,
	analysis->bits == 32
		? SHIFTL0(imm, UN(32, 12))
		: SIGNED(analysis->bits, SHIFTL0(CAST(32, IL_FALSE, imm), UN(32, 12))))
DEFINE_LIFTER(auipc, DECODE_RD_IMM,
	ADD(UN(analysis->bits, current_addr),
		analysis->bits == 32
			? SHIFTL0(imm, UN(32, 12))
			: SIGNED(analysis->bits, SHIFTL0(CAST(32, IL_FALSE, imm), UN(32, 12)))))

DEFINE_LIFTER_WITH_EFFECT(sb, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), CAST(8, IL_FALSE, rs1)))
DEFINE_LIFTER_WITH_EFFECT(sh, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), CAST(16, IL_FALSE, rs1)))
// Intentional: on RV32 rs1 is already 32-bit so CAST(32) would be a redundant no-op;
// on RV64 it is needed to truncate the 64-bit register value to 32 bits before storing.
DEFINE_LIFTER_WITH_EFFECT(sw, DECODE_RS_RS_IMM_MEM,
	analysis->bits == 32
		? STOREW(ADD(rs2, imm), rs1)
		: STOREW(ADD(rs2, imm), CAST(32, IL_FALSE, rs1)))
DEFINE_LIFTER_WITH_EFFECT(sd, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), rs1))

DEFINE_LIFTER(lw, DECODE_RD_RS_IMM_MEM, analysis->bits == 32 ? LOADW(32, ADD(rs, imm)) : SIGNED(analysis->bits, LOADW(32, ADD(rs, imm))))
DEFINE_LIFTER(lb, DECODE_RD_RS_IMM_MEM, SIGNED(analysis->bits, LOADW(8, ADD(rs, imm))))
DEFINE_LIFTER(lh, DECODE_RD_RS_IMM_MEM, SIGNED(analysis->bits, LOADW(16, ADD(rs, imm))))
DEFINE_LIFTER(lbu, DECODE_RD_RS_IMM_MEM, UNSIGNED(analysis->bits, LOADW(8, ADD(rs, imm))))
DEFINE_LIFTER(lhu, DECODE_RD_RS_IMM_MEM, UNSIGNED(analysis->bits, LOADW(16, ADD(rs, imm))))
DEFINE_LIFTER(ld, DECODE_RD_RS_IMM_MEM, LOADW(64, ADD(rs, imm)))

DEFINE_LIFTER_WITH_EFFECT(fence, DECODE_NONE, NOP())
DEFINE_LIFTER_WITH_EFFECT(fence_i, DECODE_NONE, NOP())

DEFINE_LIFTER(addw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, ADD(rs1, rs2)))
DEFINE_LIFTER(subw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SUB(rs1, rs2)))
DEFINE_LIFTER(sllw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SHIFTL0(rs1, LOGAND(rs2, UN(32, 31)))))
DEFINE_LIFTER(srlw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SHIFTR0(rs1, LOGAND(rs2, UN(32, 31)))))
DEFINE_LIFTER(sraw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(analysis->bits, SHIFTRA(rs1, LOGAND(rs2, UN(32, 31)))))
DEFINE_LIFTER(addiw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(analysis->bits, ADD(rs, imm)))
DEFINE_LIFTER(slliw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(analysis->bits, SHIFTL0(rs, imm)))
DEFINE_LIFTER(srliw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(analysis->bits, SHIFTR0(rs, imm)))
DEFINE_LIFTER(sraiw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(analysis->bits, SHIFTRA(rs, imm)))

// RV64I: load word unsigned (zero-extend 32-bit load to XLEN)
DEFINE_LIFTER(lwu, DECODE_RD_RS_IMM_MEM, UNSIGNED(analysis->bits, LOADW(32, ADD(rs, imm))))

// System: environment call / breakpoint (trap to OS / debugger)
DEFINE_LIFTER_WITH_EFFECT(ecall, DECODE_NONE, GOTO("ecall"))
DEFINE_LIFTER_WITH_EFFECT(ebreak, DECODE_NONE, GOTO("ebreak"))

#include <rz_il/rz_il_opbuilder_end.h>
