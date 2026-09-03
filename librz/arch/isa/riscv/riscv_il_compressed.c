// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il_compressed.h"

#include "analysis_private.h"
#include "riscv/riscv_il_base.h"
#include "riscv_il_integer.h"
#include "rz_util/rz_buf.h"

#include <rz_il/rz_il_opbuilder_begin.h>

#define DECODE_C_MV(analysis, insn) \
	REQUIRE_2OPS(RISCV_OP_REG, RISCV_OP_REG); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *rs = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[1].reg);

#define DECODE_C_LI(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	uint32_t rd = insn->detail->riscv.operands[0].reg; \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[2].imm);

#define DECODE_C_BRANCH_ZERO(analysis, insn) \
	REQUIRE_3OPS(RISCV_OP_REG, RISCV_OP_REG, RISCV_OP_IMM); \
	RzILOpBitVector *rs1 = riscv_il_get_reg(analysis->bits, insn->detail->riscv.operands[0].reg); \
	RzILOpBitVector *imm = SN(analysis->bits, insn->detail->riscv.operands[2].imm);

DEFINE_LIFTER_WITH_EFFECT(c_nop, DECODE_NONE, NOP())
DEFINE_ALIAS_LIFTER(c_addi, addi)
DEFINE_ALIAS_LIFTER(c_addi16sp, addi)
DEFINE_ALIAS_LIFTER(c_addi4spn, addi)
DEFINE_ALIAS_LIFTER(c_add, add)

RzILOpEffect *rz_riscv_lift_c_slli(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	if (insn->detail->riscv.op_count == 2 &&
		insn->detail->riscv.operands[0].type == RISCV_OP_REG &&
		insn->detail->riscv.operands[0].reg == RISCV_REG_X0 &&
		insn->detail->riscv.operands[1].type == RISCV_OP_IMM) {
		// Capstone exposes the c.slli hint form as the same public ID as c.slli.
		// It should later fix this by having a different public ID for the hint form.
		return NOP();
	}
	return rz_riscv_lift_slli(analysis, op, insn, current_addr, size);
}

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

DEFINE_LIFTER(c_mv, DECODE_C_MV, rs)
DEFINE_LIFTER(c_li, DECODE_C_LI, imm)

DEFINE_ALIAS_LIFTER(c_j, jal)
DEFINE_ALIAS_LIFTER(c_jal, jal)
DEFINE_ALIAS_LIFTER(c_jr, jalr)

DEFINE_ALIAS_LIFTER(c_jalr, jalr)
DEFINE_ALIAS_LIFTER(c_ebreak, ebreak)

DEFINE_ALIAS_LIFTER(c_lui, lui)

DEFINE_ALIAS_LIFTER(c_sw, sw)
DEFINE_ALIAS_LIFTER(c_swsp, sw)

DEFINE_ALIAS_LIFTER(c_sd, sd)
DEFINE_ALIAS_LIFTER(c_sdsp, sd)

DEFINE_ALIAS_LIFTER(c_lwsp, lw)
DEFINE_ALIAS_LIFTER(c_lw, lw)

DEFINE_ALIAS_LIFTER(c_ld, ld)
DEFINE_ALIAS_LIFTER(c_ldsp, ld)

DEFINE_LIFTER_FOR_ONEWAY_JUMP(c_beqz, DECODE_C_BRANCH_ZERO, BRANCH(EQ(rs1, UN(analysis->bits, 0)), JMP(imm), JMP(UN(analysis->bits, current_addr + size))))
DEFINE_LIFTER_FOR_ONEWAY_JUMP(c_bnez, DECODE_C_BRANCH_ZERO, BRANCH(NE(rs1, UN(analysis->bits, 0)), JMP(imm), JMP(UN(analysis->bits, current_addr + size))))

#include <rz_il/rz_il_opbuilder_end.h>
