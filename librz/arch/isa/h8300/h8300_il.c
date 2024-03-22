//
// Created by Ashis Kumar Naik on 21/03/24.
//

#include "h8300_il.h"
#include "h8300_disas.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \file h8300_il.c
 *
 * Converts H8300 instructions to RzIL statements
 * References:
 *  - https://www.classes.cs.uchicago.edu/archive/2006/winter/23000-1/docs/h8300.pdf
 */

#define H8300_ADDR_SIZE 16
#define H8300_REG_SIZE  8


#define H8300_SREG    "sreg"
#define H8300_SP      "sp"
#define H8300_LET_RES "RES"

// Below is described the status register
// SREG = I|U|H|U|N|Z|V|C
// bits   7|6|5|4|3|2|1|0
#define H8300_SREG_I_BIT ((ut8)(1u << 7))
#define H8300_SREG_I     "if"
#define H8300_SREG_U_BIT ((ut8)(1u << 6))
#define H8300_SREG_U     "uf"
#define H8300_SREG_H_BIT ((ut8)(1u << 5))
#define H8300_SREG_H     "hf"
#define H8300_SREG_U_BIT ((ut8)(1u << 4))
#define H8300_SREG_U     "uf"
#define H8300_SREG_N_BIT ((ut8)(1u << 3))
#define H8300_SREG_N     "nf"
#define H8300_SREG_Z_BIT ((ut8)(1u << 2))
#define H8300_SREG_Z     "zf"
#define H8300_SREG_V_BIT ((ut8)(1u << 1))
#define H8300_SREG_V     "vf"
#define H8300_SREG_C_BIT ((ut8)(1u << 0))
#define H8300_SREG_C     "cf"

#define H8300_REG(reg)         VARG(h8300_registers[reg])
#define H8300_REG_SET(reg, x)  SETG(h8300_registers[reg], x)
#define H8300_IMM(imm)         UN(H8300_REG_SIZE, (imm))

#define H8300_SREG_V_SET(x) h8300_il_assign_bool(H8300_SREG_V, x)
#define H8300_SREG_N_SET(x) h8300_il_assign_bool(H8300_SREG_N, x)

#define h8300_return_val_if_invalid_gpr(x, v) \
	if (x >= 24) { \
		RZ_LOG_ERROR("RzIL: H8300: invalid register R%u\n", x); \
		return v; \
	}

const char *h8300_registers[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",  // used as stack pointer
	"r0l",
	"r0h",
	"r1l",
	"r1h",
	"r2l",
	"r2h",
	"r3l",
	"r3h",
	"r4l",
	"r4h",
	"r5l",
	"r5h",
	"r6l",
	"r6h",
	"r7l",
	"r7h",
};

/**
 * All registers available as global IL variables
 */
static const char *h8300_global_registers[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",  // used as stack pointer
	"r0l",
	"r0h",
	"r1l",
	"r1h",
	"r2l",
	"r2h",
	"r3l",
	"r3h",
	"r4l",
	"r4h",
	"r5l",
	"r5h",
	"r6l",
	"r6h",
	"r7l",
	"r7h",
	H8300_SREG,
	H8300_SP,
};

static inline RzILOpEffect *h8300_il_assign_bool(const char *reg, ut16 value) {
	return SETG(reg, value ? IL_TRUE : IL_FALSE);
}

static RzILOpEffect *h8300_il_check_negative_flag_reg(ut16 reg) {
	// N: Res7 is set, AKA MSB
	// extract bit 7 from Res
	RzILOpPure *x = H8300_REG(reg);
	x = MSB(x);
	return SETG(H8300_SREG_N, x);
}

static RzILOpEffect *h8300_il_check_zero_flag_reg(ut16 reg) {
	RzILOpPure *x = H8300_REG(reg);
	x = IS_ZERO(x);
	return SETG(H8300_SREG_Z, x);
}

static RzILOpEffect *h8300_il_check_zero_flag_local(const char *local, bool and_zero) {
	// set Z to 1 if !(x - y) or !(x - y - C)
	RzILOpPure *_alu = VARL(local);
	RzILOpBool *_is_zero = IS_ZERO(_alu);
	if (and_zero) {
		RzILOpBool *Z = VARG(H8300_SREG_Z);
		_is_zero = AND(_is_zero, Z);
	}
	return SETG(H8300_SREG_Z, _is_zero);
}

static RzILOpEffect *h8300_il_check_half_carry_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rs, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rs = Y, Res = Rd - Rs or Res = Rd - Rs - C
	// H: (!Rd3 & Rs3) | (Rs3 & Res3) | (Res3 & !Rd3)
	// Set if there was a carry from bit 3; cleared otherwise

	Rs = DUP(y);
	// and0 = (!Rd3 & Rs3)
	Rd = DUP(x);
	not0 = LOGNOT(Rd); // !Rd
	and0 = LOGAND(not0, Rs);

	// and1 = (Rs3 & Res3)
	Res = VARL(local);
	and1 = LOGAND(y, Res);

	// and2 = (Res3 & !Rd3)
	Res = VARL(local);
	not0 = LOGNOT(x);
	and2 = LOGAND(Res, not0);

	// or = (and0 | and1)
	or0 = LOGOR(and0, and1);

	// or |= and2
	or0 = LOGOR(or0, and2);

	// extract bit 3 from or
	bit = H8300_IMM(1u << 3);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(H8300_SREG_H, and0);
}

static RzILOpEffect *h8300_il_check_two_complement_overflow_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rs, *not0, *not1, *Res, *and0, *and1, *or0;
	// Rd = X, Rs = Y, Res = Rd - Rs or Res = Rd - Rs - C
	// V: (Rd7 & !Rs7 & !Res7) | (!Rd7 & Rs7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// and0 = Rd7 & !Rs7 & !Res7
	Res = VARL(local);
	Rs = DUP(y);
	not0 = LOGNOT(Rs); // !Rs
	not1 = LOGNOT(Res); // !Res
	Rd = DUP(x);
	and0 = LOGAND(Rd, not0); // Rd & !Rs
	and0 = LOGAND(and0, not1); // Rd & !Rs & !Res

	// and1 = !Rd7 & Rs7 & Res7
	Res = VARL(local);
	not0 = LOGNOT(x); // !Rd
	and1 = LOGAND(not0, y); // !Rd & Rs
	and1 = LOGAND(and1, Res); // !Rd & Rs & Res

	// or = and0 | and1
	or0 = LOGOR(and0, and1);

	return SETG(H8300_SREG_V, MSB(or0));
}

static RzILOpEffect *h8300_il_check_negative_flag_local(const char *local) {
	// N: Res7 is set, AKA MSB
	// extract bit 7 from Res
	RzILOpPure *x = VARL(local);
	x = MSB(x);
	return SETG(H8300_SREG_N, x);
}

static RzILOpEffect *h8300_il_check_carry_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if there was a carry from bit 7; cleared otherwise

	Rr = DUP(y);
	// and0 = (!Rd7 & Rr7)
	Rd = DUP(x);
	not0 = LOGNOT(Rd); // !Rd
	and0 = LOGAND(not0, Rr);

	// and1 = (Rr7 & Res7)
	Res = VARL(local);
	and1 = LOGAND(y, Res);

	// and2 = (Res7 & !Rd7)
	Res = VARL(local);
	not0 = LOGNOT(x);
	and2 = LOGAND(Res, not0);

	// or = (and0 | and1)
	or0 = LOGOR(and0, and1);

	// or |= and2
	or0 = LOGOR(or0, and2);

	// extract bit 7 from or
	bit = H8300_IMM(1u << 7);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(H8300_SREG_C, and0);
}


static inline RzILOpEffect *h8300_il_assign_reg(const char *dst, const char *src) {
	RzILOpPure *_var = VARG(src);
	return SETG(dst, _var);
}

// Unkonw instruction
static int *h8300_il_nop(H8300Op *aop, H8300Op *next_op,  ut64 pc, RzAnalysis *analysis) {
	return NOP();
}

static RzILOpEffect *h8300_il_mov1(H8300Op *aop, H8300Op *next_op,  ut64 pc, RzAnalysis *analysis) {
	// Rd = Rs
	ut16 Rd = aop->param[0];
	ut16 Rs = aop->param[1];
	h8300_return_val_if_invalid_gpr(Rd, NULL);
	h8300_return_val_if_invalid_gpr(Rs, NULL);

	return h8300_il_assign_reg(h8300_registers[Rd], h8300_registers[Rs]);
}

static RzILOpEffect *h8300_il_or(H8300Op *aop, H8300Op *next_op,  ut64 pc, RzAnalysis *analysis) {
	// Rd -> Rd | Rs
	// changes N|Z|V
	RzILOpPure *x, *y;
	RzILOpEffect * or, *N, *Z, *V;

	ut16 Rd = aop->param[0];
	ut16 Rs = aop->param[1];

	// Rd |= Rs
	x = H8300_REG(Rd);
	y = H8300_REG(Rs);
	x = LOGOR(x, y);
	or = H8300_REG_SET(Rd, x);

	// Set flags
	// V: 0
	V = H8300_SREG_V_SET(false);

	// N: Res7
	N = h8300_il_check_negative_flag_reg(Rd);

	// Z: Res == 0x00
	x = H8300_REG(Rd); // Rd is now Res
	x = IS_ZERO(x); // Rd == 0x00
	Z = SETG(H8300_SREG_Z, x);

	return SEQ4(or, V, N, Z);
}

static RzILOpEffect *h8300_il_and(H8300Op *aop, H8300Op *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *and0, *N, *Z, *V;
	// Rd = Rd & Rs
	// changes N|Z|V
	ut16 Rd = aop->param[0];
	ut16 Rs = aop->param[1];
	h8300_return_val_if_invalid_gpr(Rd, NULL);
	h8300_return_val_if_invalid_gpr(Rs, NULL);

	// Rd = Rd & Rs
	x = H8300_REG(Rd);
	y = H8300_REG(Rs);
	x = LOGAND(x, y);
	and0 = H8300_REG_SET(Rd, x);

	// V: 0 (Cleared)
	V = H8300_SREG_V_SET(false);

	// N: Res7
	N = h8300_il_check_negative_flag_reg(Rd);

	// Z: !Res
	Z = h8300_il_check_zero_flag_reg(Rd);


	return SEQ4(and0, V, N, Z);
}

static RzILOpEffect *h8300_il_sub1(H8300Op *aop, H8300Op *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd - Rs
	// changes H|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rs = aop->param[1];
	h8300_return_val_if_invalid_gpr(Rd, NULL);
	h8300_return_val_if_invalid_gpr(Rs, NULL);

	RzILOpPure *x, *y;
	RzILOpEffect *let, *subt, *Z, *H, *V, *N, *C;
	RzILOpBitVector *sub;

	// TMP = Rd - Rs
	x = H8300_REG(Rd);
	y = H8300_REG(Rs);
	sub = SUB(x, y);
	let = SETL(H8300_LET_RES, sub);

	// Rd = TMP
	x = VARL(H8300_LET_RES);
	subt = H8300_REG_SET(Rd, x);

	// set Z to 1 if !(x -y)
	Z = h8300_il_check_zero_flag_local(H8300_LET_RES, false);

	// Set if there was a borrow from bit 3; cleared otherwise
	x = H8300_REG(Rd);
	y = H8300_REG(Rs);
	H = h8300_il_check_half_carry_flag_subtraction(H8300_LET_RES, x, y);

	// V: (Rd7 & !Rs7 & !Res7) | (!Rd7 & Rs7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = H8300_REG(Rd);
	y = H8300_REG(Rs);
	V = h8300_il_check_two_complement_overflow_flag_subtraction(H8300_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = h8300_il_check_negative_flag_local(H8300_LET_RES);

	// C: (!Rd7 & Rs7) | (Rs7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rs is larger than the absolute value of Rd; cleared otherwise
	x = H8300_REG(Rd);
	y = H8300_REG(Rs);
	C = h8300_il_check_carry_flag_subtraction(H8300_LET_RES, x, y);

	return SEQ7(let, Z, H, V, N, C, subt);
}

typedef RzILOpEffect *(*h8300_il_op)(H8300Op *aop, H8300Op *next_op, ut64 pc, RzAnalysis *analysis);

// Lookup table for the IL lifting handlers for the various instruction
static const h8300_il_op h8300_ops[H8300_OP_SIZE] = {
	[H8300_OP_NOP] = h8300_il_nop,
	[H8300_OP_SLEEP] = h8300_il_sleep,
	[H8300_OP_STC] = h8300_il_stc,
	[H8300_OP_LDC] = h8300_il_ldc,
	[H8300_OP_ORC] = h8300_il_orc,
	[H8300_OP_XORC] = h8300_il_xorc,
	[H8300_OP_ANDC] = h8300_il_andc,
	[H8300_OP_LDC_2] = h8300_il_ldc_2,
	[H8300_OP_RTE] = h8300_il_rte,
	[H8300_OP_ADDB_DIRECT] = h8300_il_addb_direct,
	[H8300_OP_ADDW_DIRECT] = h8300_il_addw_direct,
	[H8300_OP_INC] = h8300_il_inc,
	[H8300_OP_ADDS] = h8300_il_adds,
	[H8300_OP_MOV_1] = h8300_il_mov1,
	[H8300_OP_MOV_2] = h8300_il_mov2,
	[H8300_OP_ADDX] = h8300_il_addx,
	[H8300_OP_DAA] = h8300_il_daa,
	[H8300_OP_SHL] = h8300_il_shl,
	[H8300_OP_SHR] = h8300_il_shr,
	[H8300_OP_ROTL] = h8300_il_rotl,
	[H8300_OP_ROTR] = h8300_il_rotr,
	[H8300_OP_OR] = h8300_il_or, // done
	[H8300_OP_XOR] = h8300_il_xor,
	[H8300_OP_AND] = h8300_il_and,
	[H8300_OP_NOT_NEG] = h8300_il_not_neg,
	[H8300_OP_SUB_1] = h8300_il_sub1,
	[H8300_OP_SUBW] = h8300_il_subw,
	[H8300_OP_DEC] = h8300_il_dec,
	[H8300_OP_SUBS] = h8300_il_subs,
	[H8300_OP_CMP_1] = h8300_il_cmp1,
	[H8300_OP_CMP_2] = h8300_il_cmp2,
	[H8300_OP_SUBX] = h8300_il_subx,
	[H8300_OP_DAS] = h8300_il_das,
	[H8300_OP_BRA] = h8300_il_bra,
	[H8300_OP_BRN] = h8300_il_brn,
	[H8300_OP_BHI] = h8300_il_bhi,
	[H8300_OP_BLS] = h8300_il_bls,
	[H8300_OP_BCC] = h8300_il_bcc,
	[H8300_OP_BCS] = h8300_il_bcs,
	[H8300_OP_BNE] = h8300_il_bne,
	[H8300_OP_BEQ] = h8300_il_beq,
	[H8300_OP_BVC] = h8300_il_bvc,
	[H8300_OP_BVS] = h8300_il_bvs,
	[H8300_OP_BPL] = h8300_il_bpl,
	[H8300_OP_BMI] = h8300_il_bmi,
	[H8300_OP_BGE] = h8300_il_bge,
	[H8300_OP_BLT] = h8300_il_blt,
	[H8300_OP_BGT] = h8300_il_bgt,
	[H8300_OP_BLE] = h8300_il_ble,
	[H8300_OP_MULXU] = h8300_il_mulxu,
	[H8300_OP_DIVXU] = h8300_il_divxu,
	[H8300_OP_RTS] = h8300_il_rts,
	[H8300_OP_BSR] = h8300_il_bsr,

	[H8300_OP_JMP_1] = h8300_il_jmp1,
	[H8300_OP_JMP_2] = h8300_il_jmp2,
	[H8300_OP_JMP_3] = h8300_il_jmp3,
	[H8300_OP_JSR_1] = h8300_il_jsr1,
	[H8300_OP_JSR_2] = h8300_il_jsr2,
	[H8300_OP_JSR_3] = h8300_il_jsr3,
	[H8300_OP_BSET_1] = h8300_il_bset1,
	[H8300_OP_BNOT_1] = h8300_il_bnot1,
	[H8300_OP_BCLR_R2R8] = h8300_il_bclr_r2r8,
	[H8300_OP_BTST_R2R8] = h8300_il_btst_r2r8,
	[H8300_OP_BST_BIST] = h8300_il_bst_bist,
	[H8300_OP_MOV_R82IND16] = h8300_il_mov_r82ind16,
	[H8300_OP_MOV_IND162R16] = h8300_il_mov_ind162r16,
	[H8300_OP_MOV_R82ABS16] = h8300_il_mov_r82abs16,
	[H8300_OP_MOV_ABS162R16] = h8300_il_mov_abs162r16,
	[H8300_OP_MOV_R82RDEC16] = h8300_il_mov_r82rdec16,
	[H8300_OP_MOV_INDINC162R16] = h8300_il_mov_indinc162r16,
	[H8300_OP_MOV_R82DISPR16] = h8300_il_mov_r82dispr16,
	[H8300_OP_MOV_DISP162R16] = h8300_il_mov_disp162r16,
	[H8300_OP_BSET_2] = h8300_il_bset2,
	[H8300_OP_BNOT_2] = h8300_il_bnot2,
	[H8300_OP_BCLR_IMM2R8] = h8300_il_bclr_imm2r8,
	[H8300_OP_BTST] = h8300_il_btst,
	[H8300_OP_BOR_BIOR] = h8300_il_bor_bior,
	[H8300_OP_BXOR_BIXOR] = h8300_il_bxor_bixor,
	[H8300_OP_BAND_BIAND] = h8300_il_band_biand,
	[H8300_OP_BILD_IMM2R8] = h8300_il_bild_imm2r8,
	[H8300_OP_MOV_IMM162R16] = h8300_il_mov_imm162r16,
	[H8300_OP_EEPMOV] = h8300_il_eepmov,
	[H8300_OP_BIAND_IMM2IND16] = h8300_il_biand_imm2ind16,
	[H8300_OP_BCLR_R2IND16] = h8300_il_bclr_r2ind16,
	[H8300_OP_BIAND_IMM2ABS8] = h8300_il_biand_imm2abs8,
	[H8300_OP_BCLR_R2ABS8] = h8300_il_bclr_r2abs8,
};


RZ_IPI bool rz_h8300_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, H8300Op *aop, H8300Op *next_op) {
	rz_return_val_if_fail(analysis && op && aop && next_op, false);
	if (aop->mnemonic >= H8300_OP_SIZE) {
		RZ_LOG_ERROR("RzIL: H8300: out of bounds op\n");
		return false;
	}

	h8300_il_op create_op = h8300_ops[aop->mnemonic];

	RzILOpEffect *lifted = create_op(aop, next_op, pc, analysis);
	op->il_op = lifted;
	return true;
}

// Initialize new config for h8300
RZ_IPI RzAnalysisILConfig *rz_h8300_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	return rz_analysis_il_config_new(H8300_ADDR_SIZE, analysis->big_endian, H8300_ADDR_SIZE);
}