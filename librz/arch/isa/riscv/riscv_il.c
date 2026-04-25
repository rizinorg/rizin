// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause
#include "analysis_private.h"
#include "riscv.h"
#include "rz_il/rz_il_opcodes.h"
#include "rz_types.h"
#include "rz_util/rz_assert.h"
#include <rz_analysis.h>
#include "riscv_il.h"

#include <rz_il/rz_il_opbuilder_begin.h>
static const char *riscv_register_names[] = {
	[RISCV_REG_X1] = "ra",
	[RISCV_REG_X2] = "sp",
	[RISCV_REG_X3] = "gp",
	[RISCV_REG_X4] = "tp",
	[RISCV_REG_X5] = "t0",
	[RISCV_REG_X6] = "t1",
	[RISCV_REG_X7] = "t2",
	[RISCV_REG_X8] = "s0",
	[RISCV_REG_X9] = "s1",
	[RISCV_REG_X10] = "a0",
	[RISCV_REG_X11] = "a1",
	[RISCV_REG_X12] = "a2",
	[RISCV_REG_X13] = "a3",
	[RISCV_REG_X14] = "a4",
	[RISCV_REG_X15] = "a5",
	[RISCV_REG_X16] = "a6",
	[RISCV_REG_X17] = "a7",
	[RISCV_REG_X18] = "s2",
	[RISCV_REG_X19] = "s3",
	[RISCV_REG_X20] = "s4",
	[RISCV_REG_X21] = "s5",
	[RISCV_REG_X22] = "s6",
	[RISCV_REG_X23] = "s7",
	[RISCV_REG_X24] = "s8",
	[RISCV_REG_X25] = "s9",
	[RISCV_REG_X26] = "s10",
	[RISCV_REG_X27] = "s11",
	[RISCV_REG_X28] = "t3",
	[RISCV_REG_X29] = "t4",
	[RISCV_REG_X30] = "t5",
	[RISCV_REG_X31] = "t6",
};

#define RISCV_GET_REG(reg)    (((reg) != RISCV_REG_X0) ? (VARG(riscv_register_names[reg])) : UN(analysis->bits, 0))
#define RISCV_SET_REG(reg, r) (((reg) != RISCV_REG_X0) ? (SETG(riscv_register_names[reg], r)) : ((rz_il_op_pure_free(r), NOP())))

#define DEFINE_LIFTER(name, decoder, result) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, int size) { \
		decoder(analysis, insn); \
		return RISCV_SET_REG(rd, result); \
	}

// by default, a RISC-V jump both sets a destination and sets the PC (i.e., jumps)
#define DEFINE_LIFTER_FOR_JUMP(name, decoder, result, jmp_effect) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, int size) { \
		decoder(analysis, insn); \
		return SEQ2( \
			RISCV_SET_REG(rd, result), \
			jmp_effect); \
	}

#define DEFINE_LIFTER_WITH_EFFECT(name, decoder, effect) \
	static RzILOpEffect *rz_riscv_lift_##name(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, \
		RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, int size) { \
		decoder(analysis, insn); \
		return effect; \
	}

// oneway jumps are those that don't have a destination register
#define DEFINE_LIFTER_FOR_ONEWAY_JUMP DEFINE_LIFTER_WITH_EFFECT

#define TWICE_FOR(name1, name2, lifter, ...) \
	lifter(name1, __VA_ARGS__) \
		lifter(name2, __VA_ARGS__)

#define THRICE_FOR(name1, name2, name3, lifter, ...) \
	TWICE_FOR(name1, name2, lifter, __VA_ARGS__) \
	lifter(name3, __VA_ARGS__)

#define FOR_4(name1, name2, name3, name4, lifter, ...) \
	TWICE_FOR(name1, name2, lifter, __VA_ARGS__) \
	TWICE_FOR(name3, name4, lifter, __VA_ARGS__)

#define DECODE_RD_RS_IMM(analysis, insn) \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[2].imm);

#define DECODE_RD_RS_RS(analysis, insn) \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs1 = RISCV_GET_REG(insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *rs2 = RISCV_GET_REG(insn->detail->riscv.operands[2].reg);

#define DECODE_RS_IMM(analysis, insn) \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].imm);

#define DECODE_RS_RS_IMM(analysis, insn) \
	RzILOpBitVector *rs1 = RISCV_GET_REG(insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs2 = RISCV_GET_REG(insn->detail->riscv.operands[1].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[2].imm);

#define DECODE_RD_RS(analysis, insn) \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].reg);

#define DECODE_IMM(analysis, insn) \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[0].imm);

#define DECODE_RD_IMM(analysis, insn) \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].imm);

#define DECODE_RS_RS_IMM_MEM(analysis, insn) \
	RzILOpBitVector *rs1 = RISCV_GET_REG(insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *rs2 = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define DECODE_RD_RS_IMM_MEM(analysis, insn) \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = RISCV_GET_REG(insn->detail->riscv.operands[1].mem.base); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[1].mem.disp);

#define USE_LIFTER(name, uppername) [RISCV_INS_##uppername] = rz_riscv_lift_##name

FOR_4(addi, c_addi, c_addi16sp, c_addi4spn,
	DEFINE_LIFTER, DECODE_RD_RS_IMM, ADD(rs, imm))
TWICE_FOR(slli, c_slli,
	DEFINE_LIFTER, DECODE_RD_RS_IMM, SHIFTL0(rs, imm))
TWICE_FOR(andi, c_andi,
	DEFINE_LIFTER, DECODE_RD_RS_IMM, LOGAND(rs, imm))
DEFINE_LIFTER(ori, DECODE_RD_RS_IMM, LOGOR(rs, imm))
DEFINE_LIFTER(xori, DECODE_RD_RS_IMM, LOGXOR(rs, imm))
DEFINE_LIFTER(slti, DECODE_RD_RS_IMM, BOOL_TO_BV(SLT(rs, imm), analysis->bits))
DEFINE_LIFTER(sltiu, DECODE_RD_RS_IMM, BOOL_TO_BV(ULT(rs, imm), analysis->bits))
TWICE_FOR(srli, c_srli,
	DEFINE_LIFTER, DECODE_RD_RS_IMM, SHIFTR0(rs, imm))
TWICE_FOR(srai, c_srai,
	DEFINE_LIFTER, DECODE_RD_RS_IMM, SHIFTRA(rs, imm))

DEFINE_LIFTER(add, DECODE_RD_RS_RS, ADD(rs1, rs2))
DEFINE_LIFTER(sub, DECODE_RD_RS_RS, SUB(rs1, rs2))
DEFINE_LIFTER(and, DECODE_RD_RS_RS, LOGAND(rs1, rs2))
DEFINE_LIFTER(or, DECODE_RD_RS_RS, LOGOR(rs1, rs2))
DEFINE_LIFTER(xor, DECODE_RD_RS_RS, LOGXOR(rs1, rs2))
DEFINE_LIFTER(slt, DECODE_RD_RS_RS, BOOL_TO_BV(SLT(rs1, rs2), analysis->bits))
DEFINE_LIFTER(sltu, DECODE_RD_RS_RS, BOOL_TO_BV(ULT(rs1, rs2), analysis->bits))
DEFINE_LIFTER(sll, DECODE_RD_RS_RS, SHIFTL0(rs1, rs2))
DEFINE_LIFTER(srl, DECODE_RD_RS_RS, SHIFTR0(rs1, rs2))
DEFINE_LIFTER(sra, DECODE_RD_RS_RS, SHIFTRA(rs1, rs2))

#define DEFINE_LIFTER_FOR_BRANCH(name, decoder, condition) \
	DEFINE_LIFTER_FOR_ONEWAY_JUMP(name, decoder, BRANCH(condition, JMP(imm), JMP(UN(analysis->bits, current_addr + size))))

DEFINE_LIFTER_FOR_BRANCH(beq, DECODE_RS_RS_IMM, EQ(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bne, DECODE_RS_RS_IMM, NE(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(blt, DECODE_RS_RS_IMM, SLT(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bge, DECODE_RS_RS_IMM, SGE(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bltu, DECODE_RS_RS_IMM, ULT(rs1, rs2))
DEFINE_LIFTER_FOR_BRANCH(bgeu, DECODE_RS_RS_IMM, UGE(rs1, rs2))

DEFINE_LIFTER_FOR_BRANCH(c_beqz, DECODE_RS_IMM, EQ(rs, UN(analysis->bits, 0)))
DEFINE_LIFTER_FOR_BRANCH(c_bnez, DECODE_RS_IMM, NE(rs, UN(analysis->bits, 0)))

DEFINE_LIFTER(c_mv, DECODE_RD_RS, DUP(rs))

DEFINE_LIFTER_FOR_ONEWAY_JUMP(c_j, DECODE_IMM, JMP(imm))

DEFINE_LIFTER_FOR_JUMP(jal, DECODE_RD_IMM,
	/*RETURN ADDR*/ UN(analysis->bits, current_addr + size),
	/*GOTO ADDR*/ JMP(imm))

TWICE_FOR(jalr, c_jr,
	DEFINE_LIFTER_FOR_JUMP, DECODE_RD_RS_IMM,
	/*RETURN ADDR*/ UN(analysis->bits, current_addr + size),
	/*GOTO ADDR*/ JMP(LOGAND(ADD(rs, imm), UN(analysis->bits, ~1ULL))))

TWICE_FOR(lui, c_lui,
	DEFINE_LIFTER, DECODE_RD_IMM, SHIFTL0(imm, UN(analysis->bits, 12)))
DEFINE_LIFTER(c_li, DECODE_RD_IMM, DUP(imm))
DEFINE_LIFTER(auipc, DECODE_RD_IMM, ADD(UN(analysis->bits, current_addr), SHIFTL0(imm, UN(analysis->bits, 12))))

DEFINE_LIFTER_WITH_EFFECT(sb, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), CAST(8, IL_FALSE, rs1)))
DEFINE_LIFTER_WITH_EFFECT(sh, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), CAST(16, IL_FALSE, rs1)))

THRICE_FOR(sw, c_sw, c_swsp,
	DEFINE_LIFTER_WITH_EFFECT, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), analysis->bits == 32 ? rs1 : CAST(64, IL_FALSE, rs1)))

TWICE_FOR(sd, c_sd,
	DEFINE_LIFTER_WITH_EFFECT, DECODE_RS_RS_IMM_MEM, STOREW(ADD(rs2, imm), rs1))

THRICE_FOR(lw, c_lwsp, c_lw,
	DEFINE_LIFTER, DECODE_RD_RS_IMM_MEM, analysis->bits == 32 ? LOADW(32, ADD(rs, imm)) : SIGNED(analysis->bits, LOADW(32, ADD(rs, imm))))
DEFINE_LIFTER(lb, DECODE_RD_RS_IMM_MEM, SIGNED(analysis->bits, LOADW(8, ADD(rs, imm))))
DEFINE_LIFTER(lh, DECODE_RD_RS_IMM_MEM, SIGNED(analysis->bits, LOADW(16, ADD(rs, imm))))
DEFINE_LIFTER(lbu, DECODE_RD_RS_IMM_MEM, UNSIGNED(analysis->bits, LOADW(8, ADD(rs, imm))))
DEFINE_LIFTER(lhu, DECODE_RD_RS_IMM_MEM, UNSIGNED(analysis->bits, LOADW(16, ADD(rs, imm))))

TWICE_FOR(ld, c_ld,
	DEFINE_LIFTER, DECODE_RD_RS_IMM_MEM, LOADW(64, ADD(rs, imm)))

#include <rz_il/rz_il_opbuilder_end.h>

static const RiscvInstructionLifter riscv_lifters[] = {
	USE_LIFTER(addi, ADDI),
	USE_LIFTER(c_addi, C_ADDI),
	USE_LIFTER(c_addi16sp, C_ADDI16SP),
	USE_LIFTER(c_addi4spn, C_ADDI4SPN),
	USE_LIFTER(andi, ANDI),
	USE_LIFTER(c_andi, C_ANDI),
	USE_LIFTER(ori, ORI),
	USE_LIFTER(xori, XORI),
	USE_LIFTER(slti, SLTI),
	USE_LIFTER(sltiu, SLTIU),
	USE_LIFTER(slli, SLLI),
	USE_LIFTER(srli, SRLI),
	USE_LIFTER(srai, SRAI),
	USE_LIFTER(c_slli, C_SLLI),
	USE_LIFTER(c_srli, C_SRLI),
	USE_LIFTER(c_srai, C_SRAI),
	USE_LIFTER(jalr, JALR),
	USE_LIFTER(c_jr, C_JR),
	USE_LIFTER(lb, LB),
	USE_LIFTER(lh, LH),
	USE_LIFTER(lw, LW),
	USE_LIFTER(lbu, LBU),
	USE_LIFTER(lhu, LHU),
	USE_LIFTER(c_lwsp, C_LWSP),
	USE_LIFTER(c_lw, C_LW),
	USE_LIFTER(ld, LD),
	USE_LIFTER(c_ld, C_LD),
	USE_LIFTER(lui, LUI),
	USE_LIFTER(c_lui, C_LUI),
	USE_LIFTER(c_li, C_LI),
	USE_LIFTER(auipc, AUIPC),
	USE_LIFTER(beq, BEQ),
	USE_LIFTER(bne, BNE),
	USE_LIFTER(blt, BLT),
	USE_LIFTER(bge, BGE),
	USE_LIFTER(bltu, BLTU),
	USE_LIFTER(bgeu, BGEU),
	USE_LIFTER(c_beqz, C_BEQZ),
	USE_LIFTER(c_bnez, C_BNEZ),
	USE_LIFTER(sb, SB),
	USE_LIFTER(sh, SH),
	USE_LIFTER(sw, SW),
	USE_LIFTER(c_sw, C_SW),
	USE_LIFTER(c_swsp, C_SWSP),
	USE_LIFTER(sd, SD),
	USE_LIFTER(c_sd, C_SD),
	USE_LIFTER(add, ADD),
	USE_LIFTER(sub, SUB),
	USE_LIFTER(and, AND),
	USE_LIFTER(or, OR),
	USE_LIFTER(xor, XOR),
	USE_LIFTER(slt, SLT),
	USE_LIFTER(sltu, SLTU),
	USE_LIFTER(sll, SLL),
	USE_LIFTER(srl, SRL),
	USE_LIFTER(sra, SRA),
	USE_LIFTER(jal, JAL),
	USE_LIFTER(c_mv, C_MV),
	USE_LIFTER(c_j, C_J),
};

RZ_OWN RZ_IPI RzILOpEffect *
rz_riscv_lift_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, int size) {
	rz_return_val_if_fail(analysis && op && insn, NULL);

	if (insn->id > 0 && insn->id < RZ_ARRAY_SIZE(riscv_lifters)) {
		RiscvInstructionLifter lifter = riscv_lifters[insn->id];
		if (lifter) {
			return lifter(analysis, op, insn, current_addr, size);
		} else {
			RZ_LOG_ERROR("No lifter found for instruction %s (id: %d) (0x%08x)", insn->mnemonic, insn->id, rz_read_le32(insn->bytes));
		}
	}
	rz_warn_if_reached();
	return NULL;
}

RZ_IPI RzAnalysisILConfig *rz_riscv_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *conf = rz_analysis_il_config_new(analysis->bits, analysis->big_endian, analysis->bits);

	return conf;
}