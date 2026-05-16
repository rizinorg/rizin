// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il.h"
#include "riscv_il_integer.h"
#include "riscv_il_m.h"
#include "riscv_il_compressed.h"

static void label_ecall(RzILVM *vm, RzILOpEffect *op) {
	// stub: ecall is handled at the analysis layer
}

static const RiscvInstructionLifter riscv_lifters[] = {
	/* ---------------------------------- Integer ---------------------------------*/
	// arithmetic, immediate
	USE_LIFTER(addi, ADDI),
	USE_LIFTER(andi, ANDI),
	USE_LIFTER(ori, ORI),
	USE_LIFTER(xori, XORI),
	USE_LIFTER(slti, SLTI),
	USE_LIFTER(sltiu, SLTIU),
	USE_LIFTER(slli, SLLI),
	USE_LIFTER(srli, SRLI),
	USE_LIFTER(srai, SRAI),
	// immediate constants
	USE_LIFTER(lui, LUI),
	USE_LIFTER(auipc, AUIPC),
	// arithmetic
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
	// arithmetic, 32-bit operations in 64-bit mode
	USE_LIFTER(addw, ADDW),
	USE_LIFTER(subw, SUBW),
	USE_LIFTER(sllw, SLLW),
	USE_LIFTER(srlw, SRLW),
	USE_LIFTER(sraw, SRAW),
	USE_LIFTER(addiw, ADDIW),
	USE_LIFTER(slliw, SLLIW),
	USE_LIFTER(srliw, SRLIW),
	USE_LIFTER(sraiw, SRAIW),
	// memory
	USE_LIFTER(lb, LB),
	USE_LIFTER(lh, LH),
	USE_LIFTER(lw, LW),
	USE_LIFTER(lbu, LBU),
	USE_LIFTER(lhu, LHU),
	USE_LIFTER(ld, LD),
	USE_LIFTER(sb, SB),
	USE_LIFTER(sh, SH),
	USE_LIFTER(sw, SW),
	USE_LIFTER(sd, SD),
	// branches
	USE_LIFTER(beq, BEQ),
	USE_LIFTER(bne, BNE),
	USE_LIFTER(blt, BLT),
	USE_LIFTER(bge, BGE),
	USE_LIFTER(bltu, BLTU),
	USE_LIFTER(bgeu, BGEU),
	USE_LIFTER(jalr, JALR),
	USE_LIFTER(jal, JAL),
	// concurrency, no-ops in RzIL
	USE_LIFTER(fence, FENCE),
	USE_LIFTER(fence_i, FENCE_I),
	// system
	USE_LIFTER(ecall, ECALL),
	// RV64I extra loads
	USE_LIFTER(lwu, LWU),
	// M extension
	USE_LIFTER(mul, MUL),
	USE_LIFTER(mulh, MULH),
	USE_LIFTER(mulhsu, MULHSU),
	USE_LIFTER(mulhu, MULHU),
	USE_LIFTER(div, DIV),
	USE_LIFTER(divu, DIVU),
	USE_LIFTER(rem, REM),
	USE_LIFTER(remu, REMU),
	USE_LIFTER(mulw, MULW),
	USE_LIFTER(divw, DIVW),
	USE_LIFTER(divuw, DIVUW),
	USE_LIFTER(remw, REMW),
	USE_LIFTER(remuw, REMUW),
	/* ---------------------------------- Compressed ---------------------------------*/
	USE_LIFTER(c_addi, C_ADDI),
	USE_LIFTER(c_addi16sp, C_ADDI16SP),
	USE_LIFTER(c_addi4spn, C_ADDI4SPN),
	USE_LIFTER(c_add, C_ADD),
	USE_LIFTER(c_andi, C_ANDI),
	USE_LIFTER(c_slli, C_SLLI),
	USE_LIFTER(c_srli, C_SRLI),
	USE_LIFTER(c_srai, C_SRAI),
	USE_LIFTER(c_jr, C_JR),
	USE_LIFTER(c_jalr, C_JALR),
	USE_LIFTER(c_lwsp, C_LWSP),
	USE_LIFTER(c_lw, C_LW),
	USE_LIFTER(c_ld, C_LD),
	USE_LIFTER(c_lui, C_LUI),
	USE_LIFTER(c_li, C_LI),
	USE_LIFTER(c_beqz, C_BEQZ),
	USE_LIFTER(c_bnez, C_BNEZ),
	USE_LIFTER(c_sw, C_SW),
	USE_LIFTER(c_swsp, C_SWSP),
	USE_LIFTER(c_sd, C_SD),
	USE_LIFTER(c_mv, C_MV),
	USE_LIFTER(c_j, C_J),
	USE_LIFTER(c_or, C_OR),
	USE_LIFTER(c_ldsp, C_LDSP),
	USE_LIFTER(c_sdsp, C_SDSP),
	USE_LIFTER(c_sub, C_SUB),
	USE_LIFTER(c_and, C_AND),
	USE_LIFTER(c_xor, C_XOR),
	USE_LIFTER(c_addw, C_ADDW),
	USE_LIFTER(c_addiw, C_ADDIW),
	USE_LIFTER(c_subw, C_SUBW),
};

RZ_OWN RZ_IPI RzILOpEffect *
rz_riscv_lift_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
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

	RzILEffectLabel *ecall_label = rz_il_effect_label_new("ecall", EFFECT_LABEL_SYSCALL);
	ecall_label->hook = label_ecall;
	rz_analysis_il_config_add_label(conf, ecall_label);

	return conf;
}