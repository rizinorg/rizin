// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_integer.h"

#include "capstone.h"

#include "riscv_il_base.h"

#include <rz_il/rz_il_opbuilder_begin.h>

DEFINE_LIFTER(addi, DECODE_RD_RS_IMM, ADD(rs, imm))
DEFINE_LIFTER(slli, DECODE_RD_RS_IMM, SHIFTL0(rs, imm))
DEFINE_LIFTER(andi, DECODE_RD_RS_IMM, LOGAND(rs, imm))
DEFINE_LIFTER(ori, DECODE_RD_RS_IMM, LOGOR(rs, imm))
DEFINE_LIFTER(xori, DECODE_RD_RS_IMM, LOGXOR(rs, imm))
DEFINE_LIFTER(slti, DECODE_RD_RS_IMM, BOOL_TO_BV(SLT(rs, imm), rz_analysis_get_bits(analysis)))
DEFINE_LIFTER(sltiu, DECODE_RD_RS_IMM, BOOL_TO_BV(ULT(rs, imm), rz_analysis_get_bits(analysis)))
DEFINE_LIFTER(srli, DECODE_RD_RS_IMM, SHIFTR0(rs, imm))
DEFINE_LIFTER(srai, DECODE_RD_RS_IMM, SHIFTRA(rs, imm))

DEFINE_LIFTER(add, DECODE_RD_RS_RS, ADD(rs1, rs2))
DEFINE_LIFTER(sub, DECODE_RD_RS_RS, SUB(rs1, rs2))
DEFINE_LIFTER(and, DECODE_RD_RS_RS, LOGAND(rs1, rs2))
DEFINE_LIFTER(or, DECODE_RD_RS_RS, LOGOR(rs1, rs2))
DEFINE_LIFTER(xor, DECODE_RD_RS_RS, LOGXOR(rs1, rs2))
DEFINE_LIFTER(slt, DECODE_RD_RS_RS, BOOL_TO_BV(SLT(rs1, rs2), rz_analysis_get_bits(analysis)))
DEFINE_LIFTER(sltu, DECODE_RD_RS_RS, BOOL_TO_BV(ULT(rs1, rs2), rz_analysis_get_bits(analysis)))
DEFINE_LIFTER(sll, DECODE_RD_RS_RS, SHIFTL0(rs1, LOGAND(rs2, UN(rz_analysis_get_bits(analysis), rz_analysis_get_bits(analysis) - 1))))
DEFINE_LIFTER(srl, DECODE_RD_RS_RS, SHIFTR0(rs1, LOGAND(rs2, UN(rz_analysis_get_bits(analysis), rz_analysis_get_bits(analysis) - 1))))
DEFINE_LIFTER(sra, DECODE_RD_RS_RS, SHIFTRA(rs1, LOGAND(rs2, UN(rz_analysis_get_bits(analysis), rz_analysis_get_bits(analysis) - 1))))

#define DEFINE_LIFTER_FOR_BRANCH(name, decoder, condition) \
	DEFINE_LIFTER_FOR_ONEWAY_JUMP(name, decoder, BRANCH(condition, JMP(imm), JMP(UN(rz_analysis_get_bits(analysis), current_addr + size))))

DEFINE_LIFTER_FOR_BRANCH(beq, DECODE_RS_RS_IMM, EQ(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bne, DECODE_RS_RS_IMM, NE(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(blt, DECODE_RS_RS_IMM, SLT(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bge, DECODE_RS_RS_IMM, SGE(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bltu, DECODE_RS_RS_IMM, ULT(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bgeu, DECODE_RS_RS_IMM, UGE(rs1, rs2))

DEFINE_LIFTER_FOR_JUMP(jal, DECODE_RD_IMM,
	/*RETURN ADDR*/ UN(rz_analysis_get_bits(analysis), current_addr + size),
	/*GOTO ADDR*/ JMP(imm))

RzILOpEffect *rz_riscv_lift_jalr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis,
	RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	DECODE_RD_RS_IMM(analysis, insn);
	(void)op;

	return SEQ3(
		SETL("jalr_target", LOGAND(ADD(rs, imm), UN(rz_analysis_get_bits(analysis), ~1ULL))),
		riscv_il_set_reg(rd, UN(rz_analysis_get_bits(analysis), current_addr + size)),
		JMP(VARL("jalr_target")));
}

// Intentional: on RV32 imm is already 32-bit and the result needs no sign-extension,
// so CAST(32) and SIGNED(32) would both be no-ops; on RV64 CAST(32) truncates imm and SIGNED(64)
// sign-extends the shifted 32-bit result to XLEN.
DEFINE_LIFTER(lui, DECODE_RD_IMM,
	rz_analysis_get_bits(analysis) == 32
		? SHIFTL0(imm, UN(32, 12))
		: SIGNED(rz_analysis_get_bits(analysis), SHIFTL0(CAST(32, IL_FALSE, imm), UN(32, 12))))
DEFINE_LIFTER(auipc, DECODE_RD_IMM,
	ADD(UN(rz_analysis_get_bits(analysis), current_addr),
		rz_analysis_get_bits(analysis) == 32
			? SHIFTL0(imm, UN(32, 12))
			: SIGNED(rz_analysis_get_bits(analysis), SHIFTL0(CAST(32, IL_FALSE, imm), UN(32, 12)))))

DEFINE_LIFTER_WITH_EFFECT(sb, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), CAST(8, IL_FALSE, rs1)))
DEFINE_LIFTER_WITH_EFFECT(sh, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), CAST(16, IL_FALSE, rs1)))
// Intentional: on RV32 rs1 is already 32-bit so CAST(32) would be a redundant no-op;
// on RV64 it is needed to truncate the 64-bit register value to 32 bits before storing.
DEFINE_LIFTER_WITH_EFFECT(sw, DECODE_RS_RS_IMM_MEM,
	rz_analysis_get_bits(analysis) == 32
		? STOREW(ADD(rs2, imm), rs1)
		: STOREW(ADD(rs2, imm), CAST(32, IL_FALSE, rs1)))
DEFINE_LIFTER_WITH_EFFECT(sd, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), rs1))

DEFINE_LIFTER(lw, DECODE_RD_RS_IMM_MEM, rz_analysis_get_bits(analysis) == 32 ? LOADW(32, ADD(rs, imm)) : SIGNED(rz_analysis_get_bits(analysis), LOADW(32, ADD(rs, imm))))
DEFINE_LIFTER(lb, DECODE_RD_RS_IMM_MEM, SIGNED(rz_analysis_get_bits(analysis), LOADW(8, ADD(rs, imm))))
DEFINE_LIFTER(lh, DECODE_RD_RS_IMM_MEM, SIGNED(rz_analysis_get_bits(analysis), LOADW(16, ADD(rs, imm))))
DEFINE_LIFTER(lbu, DECODE_RD_RS_IMM_MEM, UNSIGNED(rz_analysis_get_bits(analysis), LOADW(8, ADD(rs, imm))))
DEFINE_LIFTER(lhu, DECODE_RD_RS_IMM_MEM, UNSIGNED(rz_analysis_get_bits(analysis), LOADW(16, ADD(rs, imm))))
DEFINE_LIFTER(ld, DECODE_RD_RS_IMM_MEM, LOADW(64, ADD(rs, imm)))

DEFINE_LIFTER_WITH_EFFECT(fence, DECODE_NONE, NOP())
DEFINE_LIFTER_WITH_EFFECT(fence_i, DECODE_NONE, NOP())

DEFINE_LIFTER(addw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), ADD(rs1, rs2)))
DEFINE_LIFTER(subw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SUB(rs1, rs2)))
DEFINE_LIFTER(sllw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SHIFTL0(rs1, LOGAND(rs2, UN(32, 31)))))
DEFINE_LIFTER(srlw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SHIFTR0(rs1, LOGAND(rs2, UN(32, 31)))))
DEFINE_LIFTER(sraw, DECODE_RD_RS_RS_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SHIFTRA(rs1, LOGAND(rs2, UN(32, 31)))))
DEFINE_LIFTER(addiw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), ADD(rs, imm)))
DEFINE_LIFTER(slliw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SHIFTL0(rs, imm)))
DEFINE_LIFTER(srliw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SHIFTR0(rs, imm)))
DEFINE_LIFTER(sraiw, DECODE_RD_RS_IMM_TRUNCATE32, SIGNED(rz_analysis_get_bits(analysis), SHIFTRA(rs, imm)))

// RV64I: load word unsigned (zero-extend 32-bit load to XLEN)
DEFINE_LIFTER(lwu, DECODE_RD_RS_IMM_MEM, UNSIGNED(rz_analysis_get_bits(analysis), LOADW(32, ADD(rs, imm))))

// System: environment call / breakpoint (trap to OS / debugger)
DEFINE_LIFTER_WITH_EFFECT(ecall, DECODE_NONE, GOTO("ecall"))
DEFINE_LIFTER_WITH_EFFECT(ebreak, DECODE_NONE, GOTO("ebreak"))

#include <rz_il/rz_il_opbuilder_end.h>
