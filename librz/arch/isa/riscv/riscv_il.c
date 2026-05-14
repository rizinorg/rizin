// SPDX-FileCopyrightText: 2026 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "riscv_il.h"
#include "analysis_private.h"
#include "riscv_il_base.h"
#include "riscv_il_integer.h"
#include "riscv_il_m.h"
#include "riscv_il_a.h"
#include "riscv_il_f.h"
#include "riscv_il_d.h"
#include "riscv_il_compressed.h"
#include "riscv_il_fd_compressed.h"
#include "riscv_il_priv.h"

static void label_ecall(RzILVM *vm, RzILOpEffect *op) {
	// stub: ecall is handled at the analysis layer
}

static void label_ebreak(RzILVM *vm, RzILOpEffect *op) {
	// stub: ebreak is handled at the analysis layer
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
	USE_LIFTER(ebreak, EBREAK),
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
	/* ---------------------------------- A extension ---------------------------------*/
	// Load-Reserved / Store-Conditional
	USE_LIFTER(lr_w, LR_W),
	USE_LIFTER(lr_w_aq, LR_W_AQ),
	USE_LIFTER(lr_w_rl, LR_W_RL),
	USE_LIFTER(lr_w_aqrl, LR_W_AQRL),
	USE_LIFTER(lr_d, LR_D),
	USE_LIFTER(lr_d_aq, LR_D_AQ),
	USE_LIFTER(lr_d_rl, LR_D_RL),
	USE_LIFTER(lr_d_aqrl, LR_D_AQRL),
	USE_LIFTER(sc_w, SC_W),
	USE_LIFTER(sc_w_aq, SC_W_AQ),
	USE_LIFTER(sc_w_rl, SC_W_RL),
	USE_LIFTER(sc_w_aqrl, SC_W_AQRL),
	USE_LIFTER(sc_d, SC_D),
	USE_LIFTER(sc_d_aq, SC_D_AQ),
	USE_LIFTER(sc_d_rl, SC_D_RL),
	USE_LIFTER(sc_d_aqrl, SC_D_AQRL),
	// AMO swap
	USE_LIFTER(amoswap_w, AMOSWAP_W),
	USE_LIFTER(amoswap_w_aq, AMOSWAP_W_AQ),
	USE_LIFTER(amoswap_w_rl, AMOSWAP_W_RL),
	USE_LIFTER(amoswap_w_aqrl, AMOSWAP_W_AQRL),
	USE_LIFTER(amoswap_d, AMOSWAP_D),
	USE_LIFTER(amoswap_d_aq, AMOSWAP_D_AQ),
	USE_LIFTER(amoswap_d_rl, AMOSWAP_D_RL),
	USE_LIFTER(amoswap_d_aqrl, AMOSWAP_D_AQRL),
	// AMO add
	USE_LIFTER(amoadd_w, AMOADD_W),
	USE_LIFTER(amoadd_w_aq, AMOADD_W_AQ),
	USE_LIFTER(amoadd_w_rl, AMOADD_W_RL),
	USE_LIFTER(amoadd_w_aqrl, AMOADD_W_AQRL),
	USE_LIFTER(amoadd_d, AMOADD_D),
	USE_LIFTER(amoadd_d_aq, AMOADD_D_AQ),
	USE_LIFTER(amoadd_d_rl, AMOADD_D_RL),
	USE_LIFTER(amoadd_d_aqrl, AMOADD_D_AQRL),
	// AMO xor
	USE_LIFTER(amoxor_w, AMOXOR_W),
	USE_LIFTER(amoxor_w_aq, AMOXOR_W_AQ),
	USE_LIFTER(amoxor_w_rl, AMOXOR_W_RL),
	USE_LIFTER(amoxor_w_aqrl, AMOXOR_W_AQRL),
	USE_LIFTER(amoxor_d, AMOXOR_D),
	USE_LIFTER(amoxor_d_aq, AMOXOR_D_AQ),
	USE_LIFTER(amoxor_d_rl, AMOXOR_D_RL),
	USE_LIFTER(amoxor_d_aqrl, AMOXOR_D_AQRL),
	// AMO and
	USE_LIFTER(amoand_w, AMOAND_W),
	USE_LIFTER(amoand_w_aq, AMOAND_W_AQ),
	USE_LIFTER(amoand_w_rl, AMOAND_W_RL),
	USE_LIFTER(amoand_w_aqrl, AMOAND_W_AQRL),
	USE_LIFTER(amoand_d, AMOAND_D),
	USE_LIFTER(amoand_d_aq, AMOAND_D_AQ),
	USE_LIFTER(amoand_d_rl, AMOAND_D_RL),
	USE_LIFTER(amoand_d_aqrl, AMOAND_D_AQRL),
	// AMO or
	USE_LIFTER(amoor_w, AMOOR_W),
	USE_LIFTER(amoor_w_aq, AMOOR_W_AQ),
	USE_LIFTER(amoor_w_rl, AMOOR_W_RL),
	USE_LIFTER(amoor_w_aqrl, AMOOR_W_AQRL),
	USE_LIFTER(amoor_d, AMOOR_D),
	USE_LIFTER(amoor_d_aq, AMOOR_D_AQ),
	USE_LIFTER(amoor_d_rl, AMOOR_D_RL),
	USE_LIFTER(amoor_d_aqrl, AMOOR_D_AQRL),
	// AMO signed min
	USE_LIFTER(amomin_w, AMOMIN_W),
	USE_LIFTER(amomin_w_aq, AMOMIN_W_AQ),
	USE_LIFTER(amomin_w_rl, AMOMIN_W_RL),
	USE_LIFTER(amomin_w_aqrl, AMOMIN_W_AQRL),
	USE_LIFTER(amomin_d, AMOMIN_D),
	USE_LIFTER(amomin_d_aq, AMOMIN_D_AQ),
	USE_LIFTER(amomin_d_rl, AMOMIN_D_RL),
	USE_LIFTER(amomin_d_aqrl, AMOMIN_D_AQRL),
	// AMO signed max
	USE_LIFTER(amomax_w, AMOMAX_W),
	USE_LIFTER(amomax_w_aq, AMOMAX_W_AQ),
	USE_LIFTER(amomax_w_rl, AMOMAX_W_RL),
	USE_LIFTER(amomax_w_aqrl, AMOMAX_W_AQRL),
	USE_LIFTER(amomax_d, AMOMAX_D),
	USE_LIFTER(amomax_d_aq, AMOMAX_D_AQ),
	USE_LIFTER(amomax_d_rl, AMOMAX_D_RL),
	USE_LIFTER(amomax_d_aqrl, AMOMAX_D_AQRL),
	// AMO unsigned min
	USE_LIFTER(amominu_w, AMOMINU_W),
	USE_LIFTER(amominu_w_aq, AMOMINU_W_AQ),
	USE_LIFTER(amominu_w_rl, AMOMINU_W_RL),
	USE_LIFTER(amominu_w_aqrl, AMOMINU_W_AQRL),
	USE_LIFTER(amominu_d, AMOMINU_D),
	USE_LIFTER(amominu_d_aq, AMOMINU_D_AQ),
	USE_LIFTER(amominu_d_rl, AMOMINU_D_RL),
	USE_LIFTER(amominu_d_aqrl, AMOMINU_D_AQRL),
	// AMO unsigned max
	USE_LIFTER(amomaxu_w, AMOMAXU_W),
	USE_LIFTER(amomaxu_w_aq, AMOMAXU_W_AQ),
	USE_LIFTER(amomaxu_w_rl, AMOMAXU_W_RL),
	USE_LIFTER(amomaxu_w_aqrl, AMOMAXU_W_AQRL),
	USE_LIFTER(amomaxu_d, AMOMAXU_D),
	USE_LIFTER(amomaxu_d_aq, AMOMAXU_D_AQ),
	USE_LIFTER(amomaxu_d_rl, AMOMAXU_D_RL),
	USE_LIFTER(amomaxu_d_aqrl, AMOMAXU_D_AQRL),
	/* ---------------------------------- F extension ---------------------------------*/
	// Memory
	USE_LIFTER(flw, FLW),
	USE_LIFTER(fsw, FSW),
	// Arithmetic
	USE_LIFTER(fadd_s, FADD_S),
	USE_LIFTER(fsub_s, FSUB_S),
	USE_LIFTER(fmul_s, FMUL_S),
	USE_LIFTER(fdiv_s, FDIV_S),
	USE_LIFTER(fsqrt_s, FSQRT_S),
	// Fused multiply-add
	USE_LIFTER(fmadd_s, FMADD_S),
	USE_LIFTER(fmsub_s, FMSUB_S),
	USE_LIFTER(fnmadd_s, FNMADD_S),
	USE_LIFTER(fnmsub_s, FNMSUB_S),
	// Sign injection
	USE_LIFTER(fsgnj_s, FSGNJ_S),
	USE_LIFTER(fsgnjn_s, FSGNJN_S),
	USE_LIFTER(fsgnjx_s, FSGNJX_S),
	// Min / max
	USE_LIFTER(fmin_s, FMIN_S),
	USE_LIFTER(fmax_s, FMAX_S),
	// Comparison
	USE_LIFTER(feq_s, FEQ_S),
	USE_LIFTER(flt_s, FLT_S),
	USE_LIFTER(fle_s, FLE_S),
	// Classification
	USE_LIFTER(fclass_s, FCLASS_S),
	// Conversions float32 → int
	USE_LIFTER(fcvt_w_s, FCVT_W_S),
	USE_LIFTER(fcvt_wu_s, FCVT_WU_S),
	USE_LIFTER(fcvt_l_s, FCVT_L_S),
	USE_LIFTER(fcvt_lu_s, FCVT_LU_S),
	// Conversions int → float32
	USE_LIFTER(fcvt_s_w, FCVT_S_W),
	USE_LIFTER(fcvt_s_wu, FCVT_S_WU),
	USE_LIFTER(fcvt_s_l, FCVT_S_L),
	USE_LIFTER(fcvt_s_lu, FCVT_S_LU),
	// Bit-level move
	USE_LIFTER(fmv_x_w, FMV_X_W),
	USE_LIFTER(fmv_w_x, FMV_W_X),
	/* ---------------------------------- D extension ---------------------------------*/
	// Memory
	USE_LIFTER(fld, FLD),
	USE_LIFTER(fsd, FSD),
	// Arithmetic
	USE_LIFTER(fadd_d, FADD_D),
	USE_LIFTER(fsub_d, FSUB_D),
	USE_LIFTER(fmul_d, FMUL_D),
	USE_LIFTER(fdiv_d, FDIV_D),
	USE_LIFTER(fsqrt_d, FSQRT_D),
	// Fused multiply-add
	USE_LIFTER(fmadd_d, FMADD_D),
	USE_LIFTER(fmsub_d, FMSUB_D),
	USE_LIFTER(fnmadd_d, FNMADD_D),
	USE_LIFTER(fnmsub_d, FNMSUB_D),
	// Sign injection
	USE_LIFTER(fsgnj_d, FSGNJ_D),
	USE_LIFTER(fsgnjn_d, FSGNJN_D),
	USE_LIFTER(fsgnjx_d, FSGNJX_D),
	// Min / max
	USE_LIFTER(fmin_d, FMIN_D),
	USE_LIFTER(fmax_d, FMAX_D),
	// Comparison
	USE_LIFTER(feq_d, FEQ_D),
	USE_LIFTER(flt_d, FLT_D),
	USE_LIFTER(fle_d, FLE_D),
	// Classification
	USE_LIFTER(fclass_d, FCLASS_D),
	// Conversions float64 → int
	USE_LIFTER(fcvt_w_d, FCVT_W_D),
	USE_LIFTER(fcvt_wu_d, FCVT_WU_D),
	USE_LIFTER(fcvt_l_d, FCVT_L_D),
	USE_LIFTER(fcvt_lu_d, FCVT_LU_D),
	// Conversions int → float64
	USE_LIFTER(fcvt_d_w, FCVT_D_W),
	USE_LIFTER(fcvt_d_wu, FCVT_D_WU),
	USE_LIFTER(fcvt_d_l, FCVT_D_L),
	USE_LIFTER(fcvt_d_lu, FCVT_D_LU),
	// Precision conversions
	USE_LIFTER(fcvt_d_s, FCVT_D_S),
	USE_LIFTER(fcvt_s_d, FCVT_S_D),
	// Bit-level move (RV64D only)
	USE_LIFTER(fmv_x_d, FMV_X_D),
	USE_LIFTER(fmv_d_x, FMV_D_X),
	// ---------------------------------- Compressed F/D ---------------------------------
	USE_LIFTER(c_fld, C_FLD),
	USE_LIFTER(c_fsd, C_FSD),
	USE_LIFTER(c_fldsp, C_FLDSP),
	USE_LIFTER(c_fsdsp, C_FSDSP),
	/* ---------------------------------- Compressed ---------------------------------*/
	USE_LIFTER(c_nop, C_NOP),
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
	USE_LIFTER(c_ebreak, C_EBREAK),
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
	USE_LIFTER(c_jal, C_JAL),
	USE_LIFTER(c_or, C_OR),
	USE_LIFTER(c_ldsp, C_LDSP),
	USE_LIFTER(c_sdsp, C_SDSP),
	USE_LIFTER(c_sub, C_SUB),
	USE_LIFTER(c_and, C_AND),
	USE_LIFTER(c_xor, C_XOR),
	USE_LIFTER(c_addw, C_ADDW),
	USE_LIFTER(c_addiw, C_ADDIW),
	USE_LIFTER(c_subw, C_SUBW),
	// ---------------------------------- Privileged instructions ---------------------------------
	USE_LIFTER(csrrw, CSRRW),
	USE_LIFTER(csrrs, CSRRS),
	USE_LIFTER(csrrc, CSRRC),
	USE_LIFTER(csrrwi, CSRRWI),
	USE_LIFTER(csrrsi, CSRRSI),
	USE_LIFTER(csrrci, CSRRCI),
};

RZ_OWN RZ_IPI RzILOpEffect *
rz_riscv_lift_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL cs_insn *insn, ut64 current_addr, size_t size) {
	rz_return_val_if_fail(analysis && op && insn, NULL);

	if (insn->id == RISCV_INS_INVALID) {
		return NULL;
	}
	if (insn->id >= RISCV_INS_ENDING) {
		RZ_LOG_ERROR("Invalid RISC-V instruction id %u (0x%08x)\n", insn->id, rz_read_le32(insn->bytes));
		return NULL;
	}
	if (insn->id >= RZ_ARRAY_SIZE(riscv_lifters)) {
		return NULL;
	}
	RiscvInstructionLifter lifter = riscv_lifters[insn->id];
	if (!lifter) {
		return NULL;
	}
	return lifter(analysis, op, insn, current_addr, size);
}

RZ_IPI RzAnalysisILConfig *rz_riscv_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *conf = rz_analysis_il_config_new(analysis->bits, analysis->big_endian, analysis->bits);

	RzILEffectLabel *ecall_label = rz_il_effect_label_new("ecall", EFFECT_LABEL_SYSCALL);
	ecall_label->hook = label_ecall;
	rz_analysis_il_config_add_label(conf, ecall_label);

	RzILEffectLabel *ebreak_label = rz_il_effect_label_new("ebreak", EFFECT_LABEL_SYSCALL);
	ebreak_label->hook = label_ebreak;
	rz_analysis_il_config_add_label(conf, ebreak_label);

	return conf;
}