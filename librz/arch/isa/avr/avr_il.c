// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "avr_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/** \file avr_il.c
 * Converts AVR instructions into RzIL statements
 * references:
 * - https://www.da.isy.liu.se/vanheden/pdf/avr_instr_set.pdf (no errors but old and missing some instructions)
 * - https://ww1.microchip.com/downloads/en/devicedoc/atmel-0856-avr-instruction-set-manual.pdf (contains many errors but complete)
 */

#define AVR_REG_SIZE  8
#define AVR_SREG_SIZE 8
#define AVR_MMIO_SIZE 8
#define AVR_SP_SIZE   16
#define AVR_IND_SIZE  16
#define AVR_ADDR_SIZE 32 // should be 22 bits max, but we can ignore this

#define AVR_SREG    "sreg"
#define AVR_SP      "sp"
#define AVR_SPH     "spl"
#define AVR_SPL     "sph"
#define AVR_RAMPX   "rampx"
#define AVR_RAMPY   "rampy"
#define AVR_RAMPZ   "rampz"
#define AVR_RAMPD   "rampd"
#define AVR_EIND    "eind"
#define AVR_SPMCSR  "spmcsr"
#define AVR_LET_RES "RES"
#define AVR_LET_IND "IND"

// Below is described the status register
// SREG = I|T|H|S|V|N|Z|C
// bits   7|6|5|4|3|2|1|0
#define AVR_SREG_I_BIT ((ut8)(1u << 7))
#define AVR_SREG_I     "if"
#define AVR_SREG_T_BIT ((ut8)(1u << 6))
#define AVR_SREG_T     "tf"
#define AVR_SREG_H_BIT ((ut8)(1u << 5))
#define AVR_SREG_H     "hf"
#define AVR_SREG_S_BIT ((ut8)(1u << 4))
#define AVR_SREG_S     "sf"
#define AVR_SREG_V_BIT ((ut8)(1u << 3))
#define AVR_SREG_V     "vf"
#define AVR_SREG_N_BIT ((ut8)(1u << 2))
#define AVR_SREG_N     "nf"
#define AVR_SREG_Z_BIT ((ut8)(1u << 1))
#define AVR_SREG_Z     "zf"
#define AVR_SREG_C_BIT ((ut8)(1u << 0))
#define AVR_SREG_C     "cf"

#define AVR_ADDR(x)          UNSIGNED(AVR_ADDR_SIZE, x)
#define AVR_PC(x)            UN(AVR_ADDR_SIZE, x)
#define AVR_SH(sh)           U32((sh))
#define AVR_IMM(imm)         UN(AVR_REG_SIZE, (imm))
#define AVR_IMM16(imm)       U16((imm))
#define AVR_REG(reg)         VARG(avr_registers[reg])
#define AVR_REG_SET(reg, x)  SETG(avr_registers[reg], x)
#define AVR_ONE()            UN(AVR_REG_SIZE, 1)
#define AVR_ZERO()           UN(AVR_REG_SIZE, 0)
#define AVR_X()              avr_il_get_indirect_address_reg(27, 26)
#define AVR_Y()              avr_il_get_indirect_address_reg(29, 28)
#define AVR_Z()              avr_il_get_indirect_address_reg(31, 30)
#define AVR_SET_X(l, n, add) avr_il_update_indirect_address_reg(l, 27, 26, n, add)
#define AVR_SET_Y(l, n, add) avr_il_update_indirect_address_reg(l, 29, 28, n, add)
#define AVR_SET_Z(l, n, add) avr_il_update_indirect_address_reg(l, 31, 30, n, add)

#define AVR_SREG_I_SET(x) avr_il_assign_bool(AVR_SREG_I, x)
#define AVR_SREG_T_SET(x) avr_il_assign_bool(AVR_SREG_T, x)
#define AVR_SREG_H_SET(x) avr_il_assign_bool(AVR_SREG_H, x)
#define AVR_SREG_S_SET(x) avr_il_assign_bool(AVR_SREG_S, x)
#define AVR_SREG_V_SET(x) avr_il_assign_bool(AVR_SREG_V, x)
#define AVR_SREG_N_SET(x) avr_il_assign_bool(AVR_SREG_N, x)
#define AVR_SREG_Z_SET(x) avr_il_assign_bool(AVR_SREG_Z, x)
#define AVR_SREG_C_SET(x) avr_il_assign_bool(AVR_SREG_C, x)

#define avr_return_val_if_invalid_gpr(x, v) \
	if (x >= 32) { \
		RZ_LOG_ERROR("RzIL: AVR: invalid register R%u\n", x); \
		return v; \
	}

#define avr_return_val_if_invalid_indirect_address(x, v) \
	if (x != 'X' && x != 'Y' && x != 'Z') { \
		RZ_LOG_ERROR("RzIL: AVR: invalid indirect address register %c\n", x); \
		return v; \
	}

/**
 * All registers
 */
const char *avr_registers[32] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
	"r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18",
	"r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",
	"r28", "r29", "r30", "r31"
};

/**
 * All registers available as global IL variables
 */
static const char *avr_global_registers[] = {
	"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
	"r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18",
	"r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",
	"r28", "r29", "r30", "r31", AVR_SREG_I, AVR_SREG_T, AVR_SREG_H,
	AVR_SREG_S, AVR_SREG_V, AVR_SREG_N, AVR_SREG_Z, AVR_SREG_C,
	AVR_SP, AVR_RAMPX, AVR_RAMPY, AVR_RAMPZ, AVR_RAMPD,
	AVR_EIND, AVR_SPMCSR, NULL
};

static RzILOpBitVector *avr_il_get_indirect_address_reg(ut16 reg_high, ut16 reg_low) {
	RzILOpPure *high = AVR_REG(reg_high); // rH
	RzILOpPure *low = AVR_REG(reg_low); // rL
	return rz_il_op_new_append(high, low); // addr
}

static RzILOpEffect *avr_il_update_indirect_address_reg(const char *local, ut16 reg_high, ut16 reg_low, ut64 n, bool add) {
	RzILOpBitVector *_iar, *_num;
	RzILOpEffect *_high, *_low;
	const char *Rh = avr_registers[reg_high]; // register high
	const char *Rl = avr_registers[reg_low]; // register low

	_iar = VARL(local);
	if (n > 0) {
		_num = UN(AVR_IND_SIZE, n);
		if (add) {
			_iar = ADD(_iar, _num);
		} else {
			_iar = SUB(_iar, _num);
		}
	}
	_num = AVR_SH(8);
	_iar = SHIFTR0(_iar, _num);
	_iar = UNSIGNED(AVR_REG_SIZE, _iar);
	_high = SETG(Rh, _iar);

	_iar = VARL(local);
	if (n > 0) {
		_num = UN(AVR_IND_SIZE, n);
		if (add) {
			_iar = ADD(_iar, _num);
		} else {
			_iar = SUB(_iar, _num);
		}
	}
	_iar = UNSIGNED(AVR_REG_SIZE, _iar);
	_low = SETG(Rl, _iar);
	return SEQ2(_high, _low);
}

static inline RzILOpEffect *avr_il_jump_relative(AVROp *aop, RzAnalysis *analysis, ut64 where) {
	RzILOpBitVector *_loc = UN(AVR_ADDR_SIZE, where);
	return JMP(_loc);
}

static inline RzILOpEffect *avr_il_branch_when(AVROp *aop, RzAnalysis *analysis, ut64 where, RzILOpBool *when, bool cond) {
	RzILOpEffect *_jmp = avr_il_jump_relative(aop, analysis, where);
	if (cond) {
		return BRANCH(when, _jmp, NULL);
	}
	return BRANCH(when, NULL, _jmp);
}

static inline RzILOpEffect *avr_il_assign_imm(const char *reg, ut16 imm) {
	RzILOpBitVector *_bv = UN(AVR_REG_SIZE, imm);
	return SETG(reg, _bv);
}

static inline RzILOpEffect *avr_il_assign_bool(const char *reg, ut16 value) {
	return SETG(reg, value ? IL_TRUE : IL_FALSE);
}

static inline RzILOpEffect *avr_il_assign_reg(const char *dst, const char *src) {
	RzILOpPure *_var = VARG(src);
	return SETG(dst, _var);
}

static inline RzILOpEffect *avr_il_store_pure(ut64 addr, RzILOpPure *var) {
	RzILOpBitVector *_loc = UN(AVR_ADDR_SIZE, addr);
	return STOREW(_loc, var);
}

static inline RzILOpEffect *avr_il_store_reg(ut64 addr, const char *reg) {
	RzILOpPure *_var = VARG(reg);
	return avr_il_store_pure(addr, _var);
}

static inline RzILOpEffect *avr_il_load_reg(ut64 addr, const char *reg, ut16 size) {
	RzILOpBitVector *_loc = UN(AVR_ADDR_SIZE, addr);
	RzILOpBitVector *_val = LOADW(size, _loc);
	return SETG(reg, _val);
}

static inline RzILOpEffect *avr_il_set16_from_reg(const char *dst, const char *src, ut16 mask, ut16 sh) {
	RzILOpPure *_dst = VARG(dst);
	RzILOpBitVector *_mask = UN(16, mask);
	RzILOpBitVector *_and = LOGAND(_dst, _mask);
	RzILOpPure *_src = VARG(src);
	RzILOpBitVector *_extz = UNSIGNED(16, _src);
	if (sh) {
		RzILOpBitVector *_sh = AVR_SH(sh);
		_extz = SHIFTL0(_extz, _sh);
	}
	RzILOpBitVector *_or = LOGOR(_extz, _and);
	return SETG(dst, _or);
}

static inline RzILOpEffect *avr_il_set_sreg_bit_from_reg(const char *src, ut8 bit_val, const char *bit_reg) {
	RzILOpPure *reg = VARG(src);
	RzILOpBitVector *bit = UN(AVR_REG_SIZE, bit_val);
	RzILOpBitVector *and = LOGAND(reg, bit);
	return SETG(bit_reg, and);
}

static inline RzILOpBitVector *avr_il_sreg_bit_as_imm(const char *sreg_bit, ut8 bit) {
	RzILOpPure *_bit = VARG(sreg_bit);
	RzILOpPure *_true = AVR_IMM(bit);
	RzILOpPure *_false = AVR_ZERO();
	return rz_il_op_new_ite(_bit, _true, _false);
}

static inline const char *resolve_mmio(RzAnalysis *analysis, ut16 address) {
	RzPlatformProfile *profile = analysis->arch_target ? analysis->arch_target->profile : NULL;
	if (!profile) {
		return NULL;
	}
	return rz_platform_profile_resolve_mmio(profile, address);
}

static RzILOpEffect *avr_il_check_zero_flag_local(const char *local, bool and_zero) {
	// set Z to 1 if !(x - y) or !(x - y - C)
	RzILOpPure *_alu = VARL(local);
	RzILOpBool *_is_zero = IS_ZERO(_alu);
	if (and_zero) {
		RzILOpBool *Z = VARG(AVR_SREG_Z);
		_is_zero = AND(_is_zero, Z);
	}
	return SETG(AVR_SREG_Z, _is_zero);
}

static RzILOpEffect *avr_il_check_zero_flag_reg(ut16 reg) {
	RzILOpPure *x = AVR_REG(reg);
	x = IS_ZERO(x);
	return SETG(AVR_SREG_Z, x);
}

static RzILOpEffect *avr_il_check_half_carry_flag_addition(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd + Rr or Res = Rd + Rr + C
	// H: (Rd3 & Rr3) | (Rr3 & !Res3) | (!Res3 & Rd3)
	// Set if there was a carry from bit 3; cleared otherwise

	// and0 = (Rd3 & Rr3)
	Rd = DUP(x);
	Rr = DUP(y);
	and0 = LOGAND(Rd, Rr);

	// and1 = (Rr3 & !Res3)
	Res = VARL(local);
	not0 = LOGNOT(Res);
	and1 = LOGAND(y, not0);

	// and2 = (!Res3 & Rd3)
	Res = VARL(local);
	not0 = LOGNOT(Res);
	and2 = LOGAND(not0, x);

	// or = (and0 | and1)
	or0 = LOGOR(and0, and1);

	// or |= and2
	or0 = LOGOR(or0, and2);

	// extract bit 3 from or
	bit = AVR_IMM(1u << 3);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(AVR_SREG_H, and0);
}

static RzILOpEffect *avr_il_check_half_carry_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a carry from bit 3; cleared otherwise

	Rr = DUP(y);
	// and0 = (!Rd3 & Rr3)
	Rd = DUP(x);
	not0 = LOGNOT(Rd); // !Rd
	and0 = LOGAND(not0, Rr);

	// and1 = (Rr3 & Res3)
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
	bit = AVR_IMM(1u << 3);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(AVR_SREG_H, and0);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_addition(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *not0, *not1, *Res, *and0, *and1, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// V: (Rd7 & Rr7 & !Res7) | (!Rd7 & !Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// and0 = Rd7 & Rr7 & !Res7
	Res = VARL(local);
	Rd = DUP(x);
	Rr = DUP(y);
	not0 = LOGNOT(Res); // !Res
	and0 = LOGAND(Rd, Rr); // Rd & Rr
	and0 = LOGAND(and0, not0); // Rd & Rr & !Res

	// and1 = !Rd7 & !Rr7 & Res7
	Res = VARL(local);
	not0 = LOGNOT(x); // !Rd
	not1 = LOGNOT(y); // !Rr
	and1 = LOGAND(not0, not1); // !Rd & !Rr
	and1 = LOGAND(and1, Res); // !Rd & Rr & Res

	// or = and0 | and1
	or0 = LOGOR(and0, and1);

	// extract bit 7 from or
	return SETG(AVR_SREG_V, MSB(or0));
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_addition_wide(const char *local, ut16 reg) {
	RzILOpPure *ovf, *Rdh, *Res;
	// Rdh = X, Res = Rd+1:Rd
	// V: !Rdh7 & Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	Rdh = AVR_REG(reg);
	Rdh = MSB(Rdh); // Rdh7
	Rdh = INV(Rdh); // !Rdh7

	Res = VARL(local);
	Res = MSB(Res); // Res15

	ovf = AND(Rdh, Res); // !Rdh7 & Res15
	return SETG(AVR_SREG_V, ovf);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *not0, *not1, *Res, *and0, *and1, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// and0 = Rd7 & !Rr7 & !Res7
	Res = VARL(local);
	Rr = DUP(y);
	not0 = LOGNOT(Rr); // !Rr
	not1 = LOGNOT(Res); // !Res
	Rd = DUP(x);
	and0 = LOGAND(Rd, not0); // Rd & !Rr
	and0 = LOGAND(and0, not1); // Rd & !Rr & !Res

	// and1 = !Rd7 & Rr7 & Res7
	Res = VARL(local);
	not0 = LOGNOT(x); // !Rd
	and1 = LOGAND(not0, y); // !Rd & Rr
	and1 = LOGAND(and1, Res); // !Rd & Rr & Res

	// or = and0 | and1
	or0 = LOGOR(and0, and1);

	return SETG(AVR_SREG_V, MSB(or0));
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_subtraction_wide(const char *local, ut16 reg) {
	RzILOpPure *ovf, *Rdh, *Res;
	// Rdh = X, Res = Rd+1:Rd
	// V: Rdh7 & !Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// extract bit 7 from Rdh
	Rdh = AVR_REG(reg); // Rdh
	Rdh = MSB(Rdh); // Rdh7

	// extract bit 15 from Res
	Res = VARL(local);
	Res = MSB(Res); // Res15
	Res = INV(Res); // !Res15

	ovf = AND(Rdh, Res); // Rdh7 & !Res15
	return SETG(AVR_SREG_V, ovf);
}

static RzILOpEffect *avr_il_check_negative_flag_local(const char *local) {
	// N: Res7 is set, AKA MSB
	// extract bit 7 from Res
	RzILOpPure *x = VARL(local);
	x = MSB(x);
	return SETG(AVR_SREG_N, x);
}

static RzILOpEffect *avr_il_check_negative_flag_reg(ut16 reg) {
	// N: Res7 is set, AKA MSB
	// extract bit 7 from Res
	RzILOpPure *x = AVR_REG(reg);
	x = MSB(x);
	return SETG(AVR_SREG_N, x);
}

static RzILOpEffect *avr_il_check_carry_flag_addition(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd + Rr or Res = Rd + Rr + C
	// H: (Rd7 & Rr7) | (Rr7 & !Res7) | (!Res7 & Rd7)
	// Set if there was a carry from bit 7; cleared otherwise

	// and0 = (Rd7 & Rr7)
	Rd = DUP(x);
	Rr = DUP(y);
	and0 = LOGAND(Rd, Rr);

	// and1 = (Rr7 & !Res7)
	Res = VARL(local);
	not0 = LOGNOT(Res);
	and1 = LOGAND(y, not0);

	// and2 = (!Res7 & Rd7)
	Res = VARL(local);
	not0 = LOGNOT(Res);
	and2 = LOGAND(not0, x);

	// or = (and0 | and1)
	or0 = LOGOR(and0, and1);

	// or |= and2
	or0 = LOGOR(or0, and2);

	return SETG(AVR_SREG_C, MSB(or0));
}

static RzILOpEffect *avr_il_check_carry_flag_addition_wide(const char *local, ut16 reg) {
	RzILOpBitVector *carry, *Rdh, *Res;
	// Res = Rd+1:Rd
	// !Res15 & Rdh7
	// Set if the absolute value of K is larger than the absolute value of Rd; cleared otherwise

	// extract bit 7 from Rdh
	Rdh = AVR_REG(reg); // Rdh
	Rdh = MSB(Rdh); // Rdh7

	// extract bit 15 from Res
	Res = VARL(local);
	Res = MSB(Res); // Res15
	Res = INV(Res); // !Res15

	carry = AND(Res, Rdh); // !Res15 & Rdh7
	return SETG(AVR_SREG_C, carry);
}

static RzILOpEffect *avr_il_check_carry_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
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
	bit = AVR_IMM(1u << 7);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(AVR_SREG_C, and0);
}

static RzILOpEffect *avr_il_check_carry_flag_subtraction_wide(const char *local, ut16 reg) {
	RzILOpBitVector *carry, *Rdh, *Res;
	// Res = Rd+1:Rd
	// Res15 & !Rdh7
	// Set if the absolute value of K is larger than the absolute value of Rd; cleared otherwise

	// extract bit 7 from Rdh
	Rdh = AVR_REG(reg); // Rdh
	Rdh = MSB(Rdh); // Rdh7
	Rdh = INV(Rdh); // !Rdh7

	// extract bit 15 from Res
	Res = VARL(local);
	Res = MSB(Res); // Res15

	carry = AND(Res, Rdh); // Res15 & !Rdh7
	return SETG(AVR_SREG_C, carry);
}

static RzILOpEffect *avr_il_check_signess_flag() {
	// S: N ^ V, For signed tests.
	RzILOpPure *N = VARG(AVR_SREG_N);
	RzILOpPure *V = VARG(AVR_SREG_V);
	RzILOpBool *_xor = XOR(N, V);
	return SETG(AVR_SREG_S, _xor);
}

static RzILOpEffect *avr_il_check_nc_overflow_flag() {
	// V: N ^ C, Overflow with negative xor carry
	RzILOpPure *N = VARG(AVR_SREG_N);
	RzILOpPure *C = VARG(AVR_SREG_C);
	RzILOpBool *_xor = XOR(N, C);
	return SETG(AVR_SREG_V, _xor);
}

static RzILOpPure *avr_subtract_if(ut32 bitsize, ut64 limit, RzILOpPure *minuend, ut64 subtrahend, bool invert) {
	RzILOpPure *x, *y, *cmp;

	// cmp = minuend > limit
	x = UN(bitsize, limit);
	y = DUP(minuend);
	cmp = UGT(y, x);

	x = DUP(minuend);
	y = UN(bitsize, subtrahend);
	if (invert) {
		// x = subtrahend - minuend
		x = SUB(y, x);
	} else {
		// x = minuend - subtrahend
		x = SUB(x, y);
	}

	return ITE(cmp, x, minuend);
}

/* ops */

static RzILOpEffect *avr_il_unk(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	return NULL; // rz_il_op_new_nop();
}

static RzILOpEffect *avr_il_nop(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	return NOP();
}

static RzILOpEffect *avr_il_adc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *adc, *let, *H, *S, *V, *N, *Z, *C;
	// Rd = Rd + Rr + C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// TMP = Rd + Rr + C
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = ADD(x, y);
	y = avr_il_sreg_bit_as_imm(AVR_SREG_C, 1);
	x = ADD(x, y);
	let = SETL(AVR_LET_RES, x);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	adc = AVR_REG_SET(Rd, x);

	// V: (Rd7 & Rr7 & !Res7) | (!Rd7 & !Rr7 & Res7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_addition(AVR_LET_RES, x, y);

	// H: (Rd3 & Rr3) | (Rr3 & !R3) | (!R3 & Rd3)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_addition(AVR_LET_RES, x, y);

	// N: Res7
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// Z: !Res
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, false);

	// C: (Rd7 & Rr7) | (Rr7 & !R7) | (!R7 & Rd7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_addition(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, H, V, N, Z, C, S, adc);
}

static RzILOpEffect *avr_il_add(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *adc, *let, *H, *S, *V, *N, *Z, *C;
	// Rd = Rd + Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// TMP = Rd + Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = ADD(x, y);
	let = SETL(AVR_LET_RES, x);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	adc = AVR_REG_SET(Rd, x);

	// V: (Rd7 & Rr7 & !Res7) | (!Rd7 & !Rr7 & Res7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_addition(AVR_LET_RES, x, y);

	// H: (Rd3 & Rr3) | (Rr3 & !R3) | (!R3 & Rd3)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_addition(AVR_LET_RES, x, y);

	// N: Res7
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// Z: !Res
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, false);

	// C: (Rd7 & Rr7) | (Rr7 & !R7) | (!R7 & Rd7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_addition(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, H, V, N, Z, C, S, adc);
}

static RzILOpEffect *avr_il_adiw(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *imm;
	RzILOpEffect *let, *adiw, *Z, *S, *V, *N, *C;
	// Rd+1:Rd = Rd+1:Rd + K
	// Rd can be only 24,26,28,30
	ut16 Rdh = aop->param[0];
	ut16 Rdl = aop->param[1];
	ut16 K = aop->param[2];
	avr_return_val_if_invalid_gpr(Rdh, NULL);
	avr_return_val_if_invalid_gpr(Rdl, NULL);

	// IND = Rd+1:Rd + K
	imm = UN(AVR_IND_SIZE, K);
	x = avr_il_get_indirect_address_reg(Rdh, Rdl);
	x = ADD(x, imm);
	let = SETL(AVR_LET_IND, x);

	// Rd+1:Rd = IND
	adiw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rdh, Rdl, 0, false);

	// set Z to 1 if !IND
	Z = avr_il_check_zero_flag_local(AVR_LET_IND, false);

	// Res = IND
	// V: !Rdh7 & Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	V = avr_il_check_two_complement_overflow_flag_addition_wide(AVR_LET_IND, Rdh);

	// Res = IND
	// N: Res15
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_IND);

	// Res = IND
	// C: !Res15 & Rdh7
	C = avr_il_check_carry_flag_addition_wide(AVR_LET_IND, Rdh);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, adiw, Z, V, N, C, S);
}

static RzILOpEffect *avr_il_and(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *and0, *S, *V, *N, *Z;
	// Rd = Rd & Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// Rd = Rd & Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = LOGAND(x, y);
	and0 = AVR_REG_SET(Rd, x);

	// V: 0 (Cleared)
	V = AVR_SREG_V_SET(false);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	Z = avr_il_check_zero_flag_reg(Rd);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(and0, V, N, Z, S);
}

static RzILOpEffect *avr_il_andi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *andi, *S, *V, *N, *Z;
	// Rd = Rd & K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// Rd = Rd & K
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	x = LOGAND(x, y);
	andi = AVR_REG_SET(Rd, x);

	// V: 0 (Cleared)
	V = AVR_SREG_V_SET(false);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	Z = avr_il_check_zero_flag_reg(Rd);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(andi, V, N, Z, S);
}

static RzILOpEffect *avr_il_asr(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Arithmetic Signed Shift Right
	RzILOpPure *x, *y, *z;
	RzILOpEffect *asr, *S, *V, *N, *Z, *C;
	// Rd >>= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// simplified by adding itself
	x = AVR_REG(Rd);
	z = MSB(x);
	x = AVR_REG(Rd);
	y = AVR_SH(1);
	x = SHIFTR(z, x, y);
	asr = AVR_REG_SET(Rd, x);

	// C: Rd0
	x = AVR_REG(Rd);
	x = LSB(x);
	C = SETG(AVR_SREG_C, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	Z = avr_il_check_zero_flag_reg(Rd);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	V = avr_il_check_nc_overflow_flag();

	return SEQ6(C, asr, N, Z, S, V);
}

static RzILOpEffect *avr_il_bld(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Copies the T Flag in the SREG (Status Register) to bit b in register Rd
	// all the other bits are unchanged
	ut16 Rd = aop->param[0];
	ut16 b = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpPure *reg, *add_bit, *remove_bit, *bit, *res;

	reg = AVR_REG(Rd);
	bit = AVR_IMM(1u << b);
	add_bit = LOGOR(reg, bit);

	bit = AVR_IMM(~(1u << b));
	reg = AVR_REG(Rd);
	remove_bit = LOGAND(reg, bit);

	res = ITE(VARG(AVR_SREG_T), add_bit, remove_bit);
	return AVR_REG_SET(Rd, res);
}

static RzILOpEffect *avr_il_brcc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if C = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_C);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brcs(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if C = 1
	ut16 k = aop->param[0];

	RzILOpPure *when = VARG(AVR_SREG_C);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_breq(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if Z = 1
	ut16 k = aop->param[0];

	RzILOpPure *when = VARG(AVR_SREG_Z);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brge(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if N ^ V = 0
	ut16 k = aop->param[0];

	RzILOpBool *N = VARG(AVR_SREG_N);
	RzILOpBool *V = VARG(AVR_SREG_V);
	RzILOpPure *when = XOR(N, V);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brhc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if H = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_H);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brhs(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if H = 1
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_H);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brid(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if I = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_I);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brie(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if I = 1
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_I);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brlt(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if N ^ V = 1
	ut16 k = aop->param[0];

	RzILOpBool *N = VARG(AVR_SREG_N);
	RzILOpBool *V = VARG(AVR_SREG_V);
	RzILOpPure *when = XOR(N, V);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brmi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if N = 1
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_N);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brne(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if Z = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_Z);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brpl(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if N = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_N);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brtc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if T = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_T);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brts(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if T = 1
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_T);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brvc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if V = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_V);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brvs(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if V = 1
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_V);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_bst(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Stores bit b from Rd to the T Flag in SREG (Status Register)
	ut16 Rd = aop->param[0];
	ut16 b = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpPure *reg, *bit;

	reg = AVR_REG(Rd);
	bit = AVR_IMM(1u << b);
	bit = LOGAND(reg, bit);
	bit = NON_ZERO(bit);
	return SETG(AVR_SREG_T, bit);
}

static RzILOpEffect *avr_il_call(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// PC = k
	ut32 k = aop->param[0];
	k <<= 16;
	k |= aop->param[1];

	RzILOpPure *val, *num;
	RzILOpEffect *jmp, *push, *sub;

	jmp = avr_il_jump_relative(aop, analysis, k);

	val = VARG(AVR_SP);
	val = AVR_ADDR(val);
	num = AVR_PC((AVR_ADDR_SIZE / 8) - 1);
	val = SUB(val, num);
	num = AVR_PC(pc + aop->size);
	push = STOREW(val, num);

	num = AVR_IMM16(AVR_ADDR_SIZE / 8);
	val = VARG(AVR_SP);
	val = SUB(val, num);
	sub = SETG(AVR_SP, val);

	return SEQ3(push, sub, jmp);
}

static RzILOpEffect *avr_il_cbi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Clears a specified bit in an I/O Register.
	ut16 A = aop->param[0];
	ut16 b = aop->param[1];

	RzILOpPure *clearb, *target, *result;
	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		reg = avr_registers[A];
	}

	clearb = AVR_IMM(~(1u << b));
	target = VARG(reg);
	result = LOGAND(clearb, target);
	return SETG(reg, result);
}

static RzILOpEffect *avr_il_clc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// C = 0
	return AVR_SREG_C_SET(false);
}

static RzILOpEffect *avr_il_clh(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// H = 0
	return AVR_SREG_H_SET(false);
}

static RzILOpEffect *avr_il_cli(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// I = 0
	return AVR_SREG_I_SET(false);
}

static RzILOpEffect *avr_il_cln(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// N = 0
	return AVR_SREG_N_SET(false);
}

static RzILOpEffect *avr_il_clr(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd ^ Rd -> S=0, V=0, N=0, Z=1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpEffect *clr, *S, *V, *N, *Z;
	clr = avr_il_assign_imm(avr_registers[Rd], 0);
	S = AVR_SREG_S_SET(false);
	V = AVR_SREG_V_SET(false);
	N = AVR_SREG_N_SET(false);
	Z = AVR_SREG_Z_SET(true);

	return SEQ5(clr, S, V, N, Z);
}

static RzILOpEffect *avr_il_cls(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// S = 0
	return AVR_SREG_S_SET(false);
}

static RzILOpEffect *avr_il_clt(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// T = 0
	return AVR_SREG_T_SET(false);
}

static RzILOpEffect *avr_il_clv(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// V = 0
	return AVR_SREG_V_SET(false);
}

static RzILOpEffect *avr_il_clz(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Z = 0
	return AVR_SREG_Z_SET(false);
}

static RzILOpEffect *avr_il_com(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = 0xFF - Rd
	// changes S|V|N|Z|C with V = 0 and C = 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpPure *x, *y, *sub;
	RzILOpEffect *set, *S, *V, *N, *Z, *C;

	x = AVR_REG(Rd);
	y = AVR_IMM(0xFF);
	sub = SUB(y, x);
	set = AVR_REG_SET(Rd, sub);

	// C = 1
	C = AVR_SREG_C_SET(true);

	// V = 0
	V = AVR_SREG_V_SET(false);

	// set Z to 1 if !(0xFF - Rd)
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// N = Res7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ6(set, C, V, Z, N, S);
}

static RzILOpEffect *avr_il_cp(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// compare Rd with Rr and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// result local variable
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	sub = SUB(x, y);
	let = SETL(AVR_LET_RES, sub);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, false);

	// Res = Rd - Rr
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// Res = Rd - Rr
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// Res = Rd - Rr
	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// Res = Rd - Rr
	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, Z, H, V, N, C, S);
}

static RzILOpEffect *avr_il_cpi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// compare Rd with Imm and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// result local variable
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	sub = SUB(x, y);
	let = SETL(AVR_LET_RES, sub);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, false);

	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, Z, H, V, N, C, S);
}

static RzILOpEffect *avr_il_cpc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// compare Rd with Rr with Carry and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);
	RzILOpPure *x, *y, *carry;
	RzILOpEffect *let, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// result local variable
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	carry = VARG(AVR_SREG_C);
	carry = rz_il_op_new_ite(carry, AVR_ONE(), AVR_ZERO());
	sub = SUB(x, y);
	sub = SUB(sub, carry);
	let = SETL(AVR_LET_RES, sub);

	// set Z to 1 if !(x - y - C)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, true);

	// Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// Res = Rd - Rr - C
	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// Res = Rd - Rr - C
	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, Z, H, V, N, C, S);
}

static RzILOpEffect *avr_il_cpse(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// branch if If Rd == Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	RzILOpBool *when = EQ(AVR_REG(Rd), AVR_REG(Rr));
	return avr_il_branch_when(aop, analysis, pc + next_op->size, when, true);
}

static RzILOpEffect *avr_il_dec(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *dec, *S, *V, *N, *Z;
	// Rd -= 1
	// changes S|V|N|Z
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// V: Rd == 0x80
	x = AVR_REG(Rd);
	y = AVR_IMM(0x80);
	x = EQ(x, y);
	V = SETG(AVR_SREG_V, x);

	// Rd -= 1
	x = AVR_REG(Rd);
	y = AVR_ONE();
	x = SUB(x, y);
	dec = AVR_REG_SET(Rd, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(V, dec, N, Z, S);
}

static RzILOpEffect *avr_il_eicall(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// *(SP--) = PC
	// PC = (EIND << 16) | Z
	RzILOpPure *x, *y;
	RzILOpEffect *jmp, *push, *sub;

	x = VARG(AVR_EIND);
	y = AVR_Z();
	x = APPEND(x, y);
	// extend to max PC address size
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	y = AVR_PC(1);
	x = SHIFTL0(x, y);
	jmp = JMP(x);

	x = VARG(AVR_SP);
	x = AVR_ADDR(x);
	y = AVR_PC((AVR_ADDR_SIZE / 8) - 1);
	x = SUB(x, y);
	y = AVR_PC(pc + aop->size);
	push = STOREW(x, y);

	x = AVR_IMM16(AVR_ADDR_SIZE / 8);
	y = VARG(AVR_SP);
	y = SUB(y, x);
	sub = SETG(AVR_SP, y);

	return SEQ3(push, sub, jmp);
}

static RzILOpEffect *avr_il_eijmp(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// PC = (EIND << 16) | Z
	RzILOpPure *x, *y;

	x = VARG(AVR_EIND);
	y = AVR_Z();
	x = APPEND(x, y);
	// extend to max PC address size
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	y = AVR_PC(1);
	x = SHIFTL0(x, y);
	return JMP(x);
}

static RzILOpEffect *avr_il_elpm(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = *(RAMPZ:Z)   # RAMPZ:Z: Unchanged
	// Rd = *(RAMPZ:Z++) # RAMPZ:Z: Post incremented
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *load, *rampz, *reg30, *reg31, *local;

	// RAMPZ:Z
	x = VARG(AVR_RAMPZ);
	y = AVR_Z();
	x = APPEND(x, y);
	// extend to max PC address size
	x = UNSIGNED(AVR_ADDR_SIZE, x);

	// Rd = *(RAMPZ:Z)
	y = LOADW(AVR_REG_SIZE, x);
	load = AVR_REG_SET(Rd, y);

	if (aop->param[2] != '+') {
		// do not need to post increment
		return load;
	}

	// RES = (RAMPZ:Z) + 1
	x = DUP(x);
	y = AVR_PC(1);
	x = ADD(x, y);
	local = SETL(AVR_LET_RES, x);

	// RAMPZ = (ut8)(RES >> 16)
	x = VARL(AVR_LET_RES);
	y = AVR_SH(AVR_IND_SIZE);
	x = SHIFTR0(x, y);
	x = UNSIGNED(AVR_REG_SIZE, x);
	rampz = SETG(AVR_RAMPZ, x);

	// R31 = (ut8)(RES >> 8)
	x = VARL(AVR_LET_RES);
	y = AVR_SH(AVR_REG_SIZE);
	x = SHIFTR0(x, y);
	x = UNSIGNED(AVR_REG_SIZE, x);
	reg31 = AVR_REG_SET(31, x);

	// R30 = (ut8)(RES)
	x = VARL(AVR_LET_RES);
	x = UNSIGNED(AVR_REG_SIZE, x);
	reg30 = AVR_REG_SET(30, x);

	return SEQ5(load, local, rampz, reg31, reg30);
}

static RzILOpEffect *avr_il_eor(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *eor, *S, *V, *N, *Z;
	// Rd = Rd ^ Rr
	// changes S|V|N|Z
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// Rd = Rd + Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = LOGXOR(x, y);
	eor = AVR_REG_SET(Rd, x);

	// V: cleared (0)
	V = AVR_SREG_V_SET(false);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(eor, V, N, Z, S);
}

static RzILOpEffect *avr_il_fmul(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *ind, *res, *mul, *Z, *C;
	// Rd and Rr are floating points that are in 1.7 format that
	// has values between [0, 2) and results in 1.15 format in R1:R0
	// bits 7      0
	// Rd = xxxxxxxx
	//      |||||||`-- 2^-7 = 0.0078125
	//      ||||||`--- 2^-6 = 0.015625
	//      |||||`---- 2^-5 = 0.03125
	//      ||||`----- 2^-4 = 0.0625
	//      |||`------ 2^-3 = 0.125
	//      ||`------- 2^-2 = 0.25
	//      |`-------- 2^-1 = 0.5
	//      `--------- 2^0  = 1
	//      01001100 = 0.5 + 0.0625 + 0.03125 = 0.59375
	// R1:R0 = ((unsigned)Rd * (unsigned)Rr)
	// changes Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// IND = Rd * Rr
	x = AVR_REG(Rd);
	x = UNSIGNED(AVR_IND_SIZE, x);
	y = AVR_REG(Rr);
	y = UNSIGNED(AVR_IND_SIZE, y);
	x = MUL(x, y);
	ind = SETL(AVR_LET_IND, x);

	// RES = ((IND > 0x7FFF) ? (IND - 0x8000) : IND) << 1
	x = VARL(AVR_LET_IND);
	x = avr_subtract_if(16, 0x7FFF, x, 0x8000, false);
	y = AVR_ONE();
	x = SHIFTL0(x, y);
	res = SETL(AVR_LET_RES, x);

	// R1:R0 = RES
	mul = avr_il_update_indirect_address_reg(AVR_LET_RES, 1, 0, 0, false);

	// set Z to 1 if !(RES)
	x = VARL(AVR_LET_RES);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// C = Res16
	x = VARL(AVR_LET_RES);
	x = MSB(x); // most significant bit
	C = SETG(AVR_SREG_C, x);

	return SEQ5(ind, res, mul, Z, C);
}

static RzILOpEffect *avr_il_fmuls(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y, *z;
	RzILOpEffect *ind, *res, *high, *low, *Z, *C;
	// Rd and Rr are floating points that are in 1.7 format
	// R1:R0 = ((signed)Rd * (signed)Rr)
	// changes Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// IND = (Rd > 0x7F ? 0 - Rd : Rd) * (Rr > 0x7F ? 0 - Rr : Rr)
	x = AVR_REG(Rd);
	x = avr_subtract_if(AVR_REG_SIZE, 0x7F, x, 0, true);
	x = UNSIGNED(AVR_IND_SIZE, x);

	y = AVR_REG(Rr);
	y = avr_subtract_if(AVR_REG_SIZE, 0x7F, y, 0, true);
	y = UNSIGNED(AVR_IND_SIZE, y);

	x = MUL(x, y);
	ind = SETL(AVR_LET_IND, x);

	// checking if one of the original values are negative
	x = AVR_REG(Rd);
	x = MSB(x);
	y = AVR_REG(Rr);
	y = MSB(y);
	z = XOR(x, y);

	// RES = ((IND > 0x3FFF) ? (IND - 0x4000) : IND) << 1
	x = VARL(AVR_LET_IND);
	x = avr_subtract_if(16, 0x3FFF, x, 0x4000, false);
	y = AVR_ONE();
	x = SHIFTL0(x, y);
	res = SETL(AVR_LET_RES, x);

	// R1 = (ut8)((z ? (0 - RES) : RES) >> 8)
	x = AVR_IMM16(0);
	y = VARL(AVR_LET_RES);
	x = SUB(x, y);
	y = VARL(AVR_LET_RES);
	x = ITE(z, x, y);
	y = AVR_SH(AVR_REG_SIZE);
	x = SHIFTR0(x, y);
	x = UNSIGNED(AVR_REG_SIZE, x);
	high = SETG("r1", x);

	// R0 = (ut8)(z ? (0 - RES) : RES)
	x = AVR_IMM16(0);
	y = VARL(AVR_LET_RES);
	x = SUB(x, y);
	y = VARL(AVR_LET_RES);
	z = DUP(z);
	x = ITE(z, x, y);
	x = UNSIGNED(AVR_REG_SIZE, x);
	low = SETG("r0", x);

	// set Z to 1 if !(r0:r1)
	x = VARG("r0");
	x = IS_ZERO(x);
	y = VARG("r1");
	y = IS_ZERO(y);
	x = AND(x, y);
	Z = SETG(AVR_SREG_Z, x);

	// C = Res16 = r1
	x = VARG("r1");
	x = MSB(x); // most significant bit
	C = SETG(AVR_SREG_C, x);

	return SEQ6(ind, res, high, low, Z, C);
}

static RzILOpEffect *avr_il_fmulsu(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y, *z;
	RzILOpEffect *ind, *res, *high, *low, *Z, *C;
	// Rd and Rr are floating points that are in 1.7 format
	// R1:R0 = ((signed)Rd * (unsigned)Rr)
	// changes Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// IND = (Rd > 0x7F ? Rd - 0x80 : Rd) * Rr
	x = AVR_REG(Rd);
	x = UNSIGNED(AVR_IND_SIZE, x);
	x = avr_subtract_if(AVR_IND_SIZE, 0x7F, x, 0x80, false);
	y = AVR_REG(Rr);
	y = UNSIGNED(AVR_IND_SIZE, y);
	x = MUL(x, y);
	ind = SETL(AVR_LET_IND, x);

	// checking if Rd is negative
	x = AVR_REG(Rd);
	z = MSB(x);

	// RES = ((IND > 0x3FFF) ? (IND - 0x4000) : IND) << 1
	x = VARL(AVR_LET_IND);
	x = avr_subtract_if(16, 0x3FFF, x, 0x4000, false);
	y = AVR_ONE();
	x = SHIFTL0(x, y);
	res = SETL(AVR_LET_RES, x);

	// R1 = (ut8)((z ? (0 - RES) : RES) >> 8)
	x = AVR_IMM16(0);
	y = VARL(AVR_LET_RES);
	x = SUB(x, y);
	y = VARL(AVR_LET_RES);
	x = ITE(z, x, y);
	y = AVR_SH(AVR_REG_SIZE);
	x = SHIFTR0(x, y);
	x = UNSIGNED(AVR_REG_SIZE, x);
	high = SETG("r1", x);

	// R0 = (ut8)(z ? (0 - RES) : RES)
	x = AVR_IMM16(0);
	y = VARL(AVR_LET_RES);
	x = SUB(x, y);
	y = VARL(AVR_LET_RES);
	z = DUP(z);
	x = ITE(z, x, y);
	x = UNSIGNED(AVR_REG_SIZE, x);
	low = SETG("r0", x);

	// set Z to 1 if !(r0:r1)
	x = VARG("r0");
	x = IS_ZERO(x);
	y = VARG("r1");
	y = IS_ZERO(y);
	x = AND(x, y);
	Z = SETG(AVR_SREG_Z, x);

	// C = Res16 = r1
	x = VARG("r1");
	x = MSB(x); // most significant bit
	C = SETG(AVR_SREG_C, x);

	return SEQ6(ind, res, high, low, Z, C);
}

static RzILOpEffect *avr_il_icall(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// *(SP--) = PC
	// PC = Z << 1
	RzILOpPure *x, *y;
	RzILOpEffect *jmp, *push, *sub;

	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	y = AVR_SH(1);
	x = SHIFTL0(x, y);
	jmp = JMP(x);

	x = VARG(AVR_SP);
	x = AVR_ADDR(x);
	y = AVR_PC((AVR_ADDR_SIZE / 8) - 1);
	x = SUB(x, y);
	y = AVR_PC(pc + aop->size);
	push = STOREW(x, y);

	x = AVR_IMM16(AVR_ADDR_SIZE / 8);
	y = VARG(AVR_SP);
	y = SUB(y, x);
	sub = SETG(AVR_SP, y);

	return SEQ3(push, sub, jmp);
}

static RzILOpEffect *avr_il_ijmp(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *loc, *one;
	// PC = Z << 1
	loc = AVR_Z();
	loc = UNSIGNED(AVR_ADDR_SIZE, loc);
	one = AVR_SH(1);
	loc = SHIFTL0(loc, one);
	return JMP(loc);
}

static RzILOpEffect *avr_il_in(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = I/O(A)
	ut16 Rd = aop->param[0];
	ut16 A = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		return avr_il_assign_reg(avr_registers[Rd], avr_registers[A]);
	} else if (!reg) {
		// memory read
		return avr_il_load_reg(A, avr_registers[Rd], AVR_REG_SIZE);
	} else if (!rz_str_ncasecmp(reg, AVR_SPL, strlen(AVR_SPL))) {
		// zeros low 8 bits and OR new value
		RzILOpPure *x = VARG(AVR_SP);
		x = UNSIGNED(AVR_REG_SIZE, x);
		return AVR_REG_SET(Rd, x);
	} else if (!rz_str_ncasecmp(reg, AVR_SPH, strlen(AVR_SPH))) {
		// zeros high 8 bits and OR new value
		RzILOpPure *x = VARG(AVR_SP);
		RzILOpPure *y = AVR_SH(AVR_REG_SIZE);
		x = SHIFTR0(x, y);
		x = UNSIGNED(AVR_REG_SIZE, x);
		return AVR_REG_SET(Rd, x);
	} else if (!rz_str_ncasecmp(reg, AVR_SREG, strlen(AVR_SREG))) {
		// this could be optimized to just be Rd = SREG
		RzILOpBitVector *x, *I, *T, *H, *S, *V, *N, *Z, *C;
		I = avr_il_sreg_bit_as_imm(AVR_SREG_I, AVR_SREG_I_BIT);
		T = avr_il_sreg_bit_as_imm(AVR_SREG_T, AVR_SREG_T_BIT);
		H = avr_il_sreg_bit_as_imm(AVR_SREG_H, AVR_SREG_H_BIT);
		S = avr_il_sreg_bit_as_imm(AVR_SREG_S, AVR_SREG_S_BIT);
		V = avr_il_sreg_bit_as_imm(AVR_SREG_V, AVR_SREG_V_BIT);
		N = avr_il_sreg_bit_as_imm(AVR_SREG_N, AVR_SREG_N_BIT);
		Z = avr_il_sreg_bit_as_imm(AVR_SREG_Z, AVR_SREG_Z_BIT);
		C = avr_il_sreg_bit_as_imm(AVR_SREG_C, AVR_SREG_C_BIT);
		x = LOGOR(I, T);
		x = LOGOR(x, H);
		x = LOGOR(x, S);
		x = LOGOR(x, V);
		x = LOGOR(x, N);
		x = LOGOR(x, Z);
		x = LOGOR(x, C);
		return AVR_REG_SET(Rd, x);
	}
	// assign the register value.
	return avr_il_assign_reg(avr_registers[Rd], reg);
}

static RzILOpEffect *avr_il_inc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *inc, *S, *V, *N, *Z;
	// Rd += 1
	// changes S|V|N|Z
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// V: Rd == 0x7F
	x = AVR_REG(Rd);
	y = AVR_IMM(0x7F);
	x = EQ(x, y);
	V = SETG(AVR_SREG_V, x);

	// Rd += 1
	x = AVR_REG(Rd);
	y = AVR_ONE();
	x = ADD(x, y);
	inc = AVR_REG_SET(Rd, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(V, inc, N, Z, S);
}

static RzILOpEffect *avr_il_jmp(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// PC = PC + k + 1
	st32 k = aop->param[0];
	k <<= 16;
	k |= aop->param[1];

	return avr_il_jump_relative(aop, analysis, k);
}

static RzILOpEffect *avr_il_lac(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// it's swap like op but clears the bits
	// *(Z) = 0xFF – Rd and Rd = *(Z)
	st32 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *local, *load, *store;

	// RES = 0xFF – Rd
	x = AVR_IMM(0xFF);
	y = AVR_REG(Rd);
	x = SUB(x, y);
	local = SETL(AVR_LET_RES, x);

	// Rd = *(Z)
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	x = LOADW(AVR_REG_SIZE, x);
	load = AVR_REG_SET(Rd, x);

	// *(Z) = RES
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	y = VARL(AVR_LET_RES);
	store = STOREW(x, y);

	return SEQ3(local, load, store);
}

static RzILOpEffect *avr_il_las(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// it's swap like op
	// *(Z) = Rd and Rd = *(Z)
	st32 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *local, *load, *store;

	// RES = 0xFF – Rd
	x = AVR_REG(Rd);
	local = SETL(AVR_LET_RES, x);

	// Rd = *(Z)
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	x = LOADW(AVR_REG_SIZE, x);
	load = AVR_REG_SET(Rd, x);

	// *(Z) = RES
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	y = VARL(AVR_LET_RES);
	store = STOREW(x, y);

	return SEQ3(local, load, store);
}

static RzILOpEffect *avr_il_lat(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// it's swap like op but xor the memory value
	// *(Z) ^= Rd and Rd = *(Z)
	st32 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *local, *load, *store;

	// RES = *(Z)
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	x = LOADW(AVR_REG_SIZE, x);
	local = SETL(AVR_LET_RES, x);

	// *(Z) = RES ^ Rd
	x = VARL(AVR_LET_RES);
	y = AVR_REG(Rd);
	y = LOGXOR(x, y);
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	store = STOREW(x, y);

	// Rd = RES
	x = VARL(AVR_LET_RES);
	load = AVR_REG_SET(Rd, x);

	return SEQ3(local, store, load);
}

static RzILOpEffect *avr_il_ld(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *src;
	RzILOpEffect *ld, *post_op, *let;
	// Rd = *((ut8*)X) where X = (r27 << 8) | r26;
	// Rd = *((ut8*)Y) where Y = (r29 << 8) | r28;
	// Rd = *((ut8*)Z) where Z = (r31 << 8) | r30;
	// When Z+ , Z is incremented by 1 after the execution (applies also to X and Y).
	// When -X , X is decremented by 1 after the execution (applies also to Z and Y).
	// When Y+q, Y is incremented by q after the execution (applies also to X and Z).

	// undefined behaviour per ISA below
	// ld r26, X+
	// ld r27, X+
	// ld r26, -X
	// ld r27, -X

	ut16 Rd = aop->param[0];
	char Rr = (char)aop->param[1]; // 'X' or 'Y' or 'Z'
	char Op = (char)aop->param[2]; //  0  or '+' or '-'
	ut16 q = aop->param[3];

	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_indirect_address(Rr, NULL);

	switch (Rr) {
	case 'X':
		src = AVR_X();
		break;
	case 'Y':
		src = AVR_Y();
		break;
	default: // 'Z'
		src = AVR_Z();
		break;
	}

	src = AVR_ADDR(src);
	src = LOADW(AVR_REG_SIZE, src);
	ld = AVR_REG_SET(Rd, src);

	if (Op != '+' && Op != '-') {
		return ld;
	}

	switch (Rr) {
	case 'X':
		src = AVR_X();
		post_op = AVR_SET_X(AVR_LET_IND, q, Op == '+');
		break;
	case 'Y':
		src = AVR_Y();
		post_op = AVR_SET_Y(AVR_LET_IND, q, Op == '+');
		break;
	default: // 'Z'
		src = AVR_Z();
		post_op = AVR_SET_Z(AVR_LET_IND, q, Op == '+');
		break;
	}

	let = SETL(AVR_LET_IND, src);
	return SEQ3(ld, let, post_op);
}

static RzILOpEffect *avr_il_ldi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_assign_imm(avr_registers[Rd], K);
}

static RzILOpEffect *avr_il_lds(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = *(k)
	ut16 Rd = aop->param[0];
	ut16 k = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_load_reg(k, avr_registers[Rd], AVR_REG_SIZE);
}

static RzILOpEffect *avr_il_lpm(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// R0 = *((ut8*)Z) where Z = (r31 << 8) | r30;
	// when Z+, Z is incremented after the execution.
	// LPM r30, Z+ and LPM r31, Z+ have an undefined behaviour per ISA
	// Z is always implied with lpm so we need to check only for post increment

	ut16 Rd = aop->param[0];
	bool post_inc = aop->param[2] == '+';
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpBitVector *z, *load;
	RzILOpEffect *lpm, *let, *zpp;

	z = AVR_Z();
	z = AVR_ADDR(z);
	load = rz_il_op_new_loadw(0, z, AVR_REG_SIZE);
	lpm = AVR_REG_SET(Rd, load);

	if (!post_inc) {
		return lpm;
	}
	z = AVR_Z();
	let = SETL(AVR_LET_IND, z);
	zpp = AVR_SET_Z(AVR_LET_IND, 1, true); // Z++
	return SEQ3(lpm, let, zpp);
}

static RzILOpEffect *avr_il_lsl(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *lsl, *H, *S, *V, *N, *Z, *C;
	// Rd <<= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// simplified by adding itself
	x = AVR_REG(Rd);
	y = AVR_REG(Rd);
	x = ADD(x, y);
	lsl = AVR_REG_SET(Rd, x);

	// H: Rd3
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 3);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	H = SETG(AVR_SREG_H, x);

	// C: Rd7
	x = AVR_REG(Rd);
	x = MSB(x);
	C = SETG(AVR_SREG_C, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	V = avr_il_check_nc_overflow_flag();

	return SEQ7(H, C, lsl, N, Z, S, V);
}

static RzILOpEffect *avr_il_lsr(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *lsr, *S, *V, *N, *Z, *C;
	// Rd >>= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	x = AVR_REG(Rd);
	y = AVR_SH(1);
	x = SHIFTR0(x, y);
	lsr = AVR_REG_SET(Rd, x);

	// C: Rd0
	x = AVR_REG(Rd);
	x = LSB(x);
	C = SETG(AVR_SREG_C, x);

	// perform shift since we need the result for the SREG flags.
	// N: 0
	N = AVR_SREG_N_SET(false);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	V = avr_il_check_nc_overflow_flag();

	return SEQ6(C, N, lsr, Z, S, V);
}

static RzILOpEffect *avr_il_mov(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	return avr_il_assign_reg(avr_registers[Rd], avr_registers[Rr]);
}

static RzILOpEffect *avr_il_movw(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x;

	RzILOpEffect *let, *movw;
	// Rd+1:Rd = Rr+1:Rr
	ut32 Rd = aop->param[0];
	ut32 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	x = avr_il_get_indirect_address_reg(Rr + 1, Rr);
	let = SETL(AVR_LET_IND, x);

	movw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rd + 1, Rd, 0, false);
	return SEQ2(let, movw);
}

static RzILOpEffect *avr_il_mul(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *let, *mul, *Z, *C;
	// R1:R0 = (signed)Rd * (signed)Rr
	// changes Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// RES = (signed)Rd * (signed)Rr
	x = AVR_REG(Rd);
	x = UNSIGNED(AVR_IND_SIZE, x); // (unsigned)Rd
	y = AVR_REG(Rr);
	y = UNSIGNED(AVR_IND_SIZE, y); // (unsigned)Rr
	x = MUL(x, y);
	let = SETL(AVR_LET_RES, x);

	// R1:R0 = RES
	mul = avr_il_update_indirect_address_reg(AVR_LET_RES, 1, 0, 0, false);

	// set Z to 1 if !(RES)
	x = VARL(AVR_LET_RES);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// C = Res16
	x = VARL(AVR_LET_RES);
	x = MSB(x); // most significant bit
	C = SETG(AVR_SREG_C, x);

	return SEQ4(let, mul, Z, C);
}

static RzILOpEffect *avr_il_muls(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *let, *mul, *Z, *C;
	// R1:R0 = (signed)Rd * (signed)Rr
	// changes Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// RES = (signed)Rd * (signed)Rr
	x = AVR_REG(Rd);
	x = SIGNED(AVR_IND_SIZE, x); // (signed)Rd
	y = AVR_REG(Rr);
	y = SIGNED(AVR_IND_SIZE, y); // (signed)Rr
	x = MUL(x, y);
	let = SETL(AVR_LET_RES, x);

	// R1:R0 = RES
	mul = avr_il_update_indirect_address_reg(AVR_LET_RES, 1, 0, 0, false);

	// set Z to 1 if !(RES)
	x = VARL(AVR_LET_RES);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// C = Res16
	x = VARL(AVR_LET_RES);
	x = MSB(x); // most significant bit
	C = SETG(AVR_SREG_C, x);

	return SEQ4(let, mul, Z, C);
}

static RzILOpEffect *avr_il_mulsu(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *let, *mul, *Z, *C;
	// R1:R0 = (signed)Rd * (unsigned)Rr
	// changes Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// RES = (signed)Rd * (unsigned)Rr
	x = AVR_REG(Rd);
	x = SIGNED(AVR_IND_SIZE, x); // (signed)Rd
	y = AVR_REG(Rr);
	y = UNSIGNED(AVR_IND_SIZE, y); // (unsigned)Rr
	x = MUL(x, y);
	let = SETL(AVR_LET_RES, x);

	// R1:R0 = RES
	mul = avr_il_update_indirect_address_reg(AVR_LET_RES, 1, 0, 0, false);

	// set Z to 1 if !(RES)
	x = VARL(AVR_LET_RES);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// C = Res16
	x = VARL(AVR_LET_RES);
	x = MSB(x); // most significant bit
	C = SETG(AVR_SREG_C, x);

	return SEQ4(let, mul, Z, C);
}

static RzILOpEffect *avr_il_neg(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y, *cmp;
	RzILOpEffect *let, *neg, *H, *S, *V, *N, *Z, *C;
	// Rd = 0x00 - Rd (when Rd == 0x80 it stays 0x80)
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// IND = Rd
	let = SETL(AVR_LET_IND, AVR_REG(Rd));

	// Rd = (Rd == 0x80) ? Rd : (0x00 - Rd)
	x = AVR_REG(Rd);
	y = AVR_IMM(0x80);
	cmp = EQ(x, y); // Rd == 0x80

	x = AVR_ZERO();
	y = AVR_REG(Rd);
	x = SUB(x, y); // 0x00 - Rd

	y = AVR_REG(Rd); // Rd
	x = ITE(cmp, y, x); // (Rd == 0x80) ? Rd : (0x00 - Rd)
	neg = AVR_REG_SET(Rd, x); // Rd = (Rd == 0x80) ? Rd : (0x00 - Rd)

	// H: Res3 | Rd3
	x = AVR_REG(Rd); // Rd is now Res
	y = VARL(AVR_LET_IND); // IND is the old Rd
	x = LOGOR(x, y); // Rd | IND
	y = AVR_IMM(1u << 3);
	x = LOGAND(x, y); // extract bit 3
	x = NON_ZERO(x); // cast to bool
	H = SETG(AVR_SREG_H, x);

	// V: Res == 0x80 (after operation)
	x = AVR_REG(Rd); // Rd is now Res
	y = AVR_IMM(0x80);
	x = EQ(x, y); // Rd == 0x80
	V = SETG(AVR_SREG_V, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// C: Res != 0x00
	x = AVR_REG(Rd); // Rd is now Res
	x = NON_ZERO(x); // Rd != 0x00
	C = SETG(AVR_SREG_C, x);

	// Z: Res == 0x00
	x = AVR_REG(Rd); // Rd is now Res
	x = IS_ZERO(x); // Rd == 0x00
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V
	S = avr_il_check_signess_flag();

	return SEQ8(let, neg, H, V, N, C, Z, S);
}

static RzILOpEffect *avr_il_or(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *or, *S, *V, *N, *Z;
	// Rd = Rd | Rr
	// changes S|V|N|Z
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);

	// Rd |= Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = LOGOR(x, y);
	or = AVR_REG_SET(Rd, x);

	// V: 0
	V = AVR_SREG_V_SET(false);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: Res == 0x00
	x = AVR_REG(Rd); // Rd is now Res
	x = IS_ZERO(x); // Rd == 0x00
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V
	S = avr_il_check_signess_flag();

	return SEQ5(or, V, N, Z, S);
}

static RzILOpEffect *avr_il_ori(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *or, *S, *V, *N, *Z;
	// Rd = Rd | K
	// changes S|V|N|Z
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// Rd |= K
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	x = LOGOR(x, y);
	or = AVR_REG_SET(Rd, x);

	// V: 0
	V = AVR_SREG_V_SET(false);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: Res == 0x00
	x = AVR_REG(Rd); // Rd is now Res
	x = IS_ZERO(x); // Rd == 0x00
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V
	S = avr_il_check_signess_flag();

	return SEQ5(or, V, N, Z, S);
}

static RzILOpEffect *avr_il_out(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// I/O(A) = Rr -> None
	ut16 A = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rr, NULL);

	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		return avr_il_assign_reg(avr_registers[A], avr_registers[Rr]);
	} else if (!reg) {
		// memory write
		return avr_il_store_reg(A, avr_registers[Rr]);
	} else if (!rz_str_ncasecmp(reg, AVR_SPL, strlen(AVR_SPL))) {
		// zeros low 8 bits and OR new value
		return avr_il_set16_from_reg(AVR_SP, avr_registers[Rr], 0xFF00, 0);
	} else if (!rz_str_ncasecmp(reg, AVR_SPH, strlen(AVR_SPH))) {
		// zeros high 8 bits and OR new value
		return avr_il_set16_from_reg(AVR_SP, avr_registers[Rr], 0x00FF, 8);
	} else if (!rz_str_ncasecmp(reg, AVR_SREG, strlen(AVR_SREG))) {
		RzILOpEffect *I = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_I_BIT, AVR_SREG_I);
		RzILOpEffect *T = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_T_BIT, AVR_SREG_T);
		RzILOpEffect *H = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_H_BIT, AVR_SREG_H);
		RzILOpEffect *S = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_S_BIT, AVR_SREG_S);
		RzILOpEffect *V = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_V_BIT, AVR_SREG_V);
		RzILOpEffect *N = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_N_BIT, AVR_SREG_N);
		RzILOpEffect *Z = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_Z_BIT, AVR_SREG_Z);
		RzILOpEffect *C = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_C_BIT, AVR_SREG_C);
		RzILOpEffect *SREG = avr_il_assign_reg(reg, avr_registers[Rr]);
		return SEQ9(I, T, H, S, V, N, Z, C, SREG);
	}
	// assign the register value.
	return avr_il_assign_reg(reg, avr_registers[Rr]);
}

static RzILOpEffect *avr_il_pop(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// SP++
	// Rd = *(SP)
	st32 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *pop, *inc;

	// SP++
	x = VARG(AVR_SP);
	y = AVR_IMM16(1);
	x = ADD(x, y);
	inc = SETG(AVR_SP, x);

	// Rd = *(SP)
	y = VARG(AVR_SP);
	y = UNSIGNED(AVR_ADDR_SIZE, y);
	x = LOADW(AVR_REG_SIZE, y);
	pop = AVR_REG_SET(Rd, x);

	return SEQ2(inc, pop);
}

static RzILOpEffect *avr_il_push(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// *(SP) = Rd
	// SP--
	st32 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *push, *dec;

	// *(SP) = Rd
	y = VARG(AVR_SP);
	y = UNSIGNED(AVR_ADDR_SIZE, y);
	x = AVR_REG(Rd);
	push = STOREW(y, x);

	// SP--
	x = VARG(AVR_SP);
	y = AVR_IMM16(1);
	x = SUB(x, y);
	dec = SETG(AVR_SP, x);

	return SEQ2(push, dec);
}

static RzILOpEffect *avr_il_rcall(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// PC = PC + k + 1
	st16 k = (st16)aop->param[0];

	RzILOpPure *val, *num;
	RzILOpEffect *jmp, *push, *sub;

	jmp = avr_il_jump_relative(aop, analysis, pc + k);

	val = VARG(AVR_SP);
	val = AVR_ADDR(val);
	num = AVR_PC((AVR_ADDR_SIZE / 8) - 1);
	val = SUB(val, num);
	num = AVR_PC(pc + aop->size);
	push = STOREW(val, num);

	num = AVR_IMM16(AVR_ADDR_SIZE / 8);
	val = VARG(AVR_SP);
	val = SUB(val, num);
	sub = SETG(AVR_SP, val);

	return SEQ3(push, sub, jmp);
}

static RzILOpEffect *avr_il_ret(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// SP += PC_SIZE
	// PC = *(SP - PC_SIZE + 1)
	RzILOpPure *x, *y;
	RzILOpEffect *jmp, *inc;

	// PC = *(SP - PC_SIZE + 1)
	y = VARG(AVR_SP);
	y = UNSIGNED(AVR_ADDR_SIZE, y);
	x = AVR_PC((AVR_ADDR_SIZE / 8) - 1);
	y = SUB(y, x);
	x = LOADW(AVR_ADDR_SIZE, y);
	jmp = JMP(x);

	// SP += PC_SIZE
	x = VARG(AVR_SP);
	y = AVR_IMM16(AVR_ADDR_SIZE / 8);
	x = ADD(x, y);
	inc = SETG(AVR_SP, x);

	return SEQ2(inc, jmp);
}

static RzILOpEffect *avr_il_rjmp(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// PC = PC + k + 1
	st16 k = (st16)aop->param[0];

	return avr_il_jump_relative(aop, analysis, pc + k);
}

static RzILOpEffect *avr_il_rol(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y, *carry;
	RzILOpEffect *let, *rol, *H, *S, *V, *N, *Z, *C;
	// Rd = rot_left(Rd, 1)
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// copy C into RES
	carry = VARG(AVR_SREG_C);
	let = SETL(AVR_LET_RES, carry);

	x = AVR_REG(Rd);
	y = AVR_SH(1);
	// Use carry as bit filler
	carry = VARL(AVR_LET_RES);
	x = SHIFTL(carry, x, y);
	rol = AVR_REG_SET(Rd, x);

	// H: Rd3
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 3);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	H = SETG(AVR_SREG_H, x);

	// C: Rd7
	x = AVR_REG(Rd);
	x = MSB(x);
	C = SETG(AVR_SREG_C, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	V = avr_il_check_nc_overflow_flag();

	return SEQ8(let, H, C, rol, N, Z, S, V);
}

static RzILOpEffect *avr_il_ror(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y, *carry;
	RzILOpEffect *let, *ror, *S, *V, *N, *Z, *C;
	// Rd = rot_right(Rd, 1)
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// copy C into RES
	carry = VARG(AVR_SREG_C);
	let = SETL(AVR_LET_RES, carry);

	x = AVR_REG(Rd);
	y = AVR_SH(1);
	// Use carry as bit filler
	carry = VARL(AVR_LET_RES);
	x = SHIFTR(carry, x, y);
	ror = AVR_REG_SET(Rd, x);

	// C: Rd0
	x = AVR_REG(Rd);
	x = LSB(x);
	C = SETG(AVR_SREG_C, x);

	// N: Res7
	N = avr_il_check_negative_flag_reg(Rd);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	V = avr_il_check_nc_overflow_flag();

	return SEQ7(let, C, ror, N, Z, S, V);
}

static RzILOpEffect *avr_il_sbc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd - Rr - C
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *subt, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// TMP = Rd - Rr - C
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = SUB(x, y);
	y = avr_il_sreg_bit_as_imm(AVR_SREG_C, 1);
	sub = SUB(x, y);
	let = SETL(AVR_LET_RES, sub);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	subt = AVR_REG_SET(Rd, x);

	// set Z to 1 if !(x - y - C)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, true);

	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, Z, H, V, N, C, S, subt);
}

static RzILOpEffect *avr_il_sbci(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd - K - C
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *subt, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// TMP = Rd - K - C
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	x = SUB(x, y);
	y = avr_il_sreg_bit_as_imm(AVR_SREG_C, 1);
	sub = SUB(x, y);
	let = SETL(AVR_LET_RES, sub);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	subt = AVR_REG_SET(Rd, x);

	// set Z to 1 if !(x - y - C)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, true);

	// H: (!Rd3 & K3) | (K3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// V: (Rd7 & !K7 & !Res7) | (!Rd7 & K7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// C: (!Rd7 & K7) | (K7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of K is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, Z, H, V, N, C, S, subt);
}

static RzILOpEffect *avr_il_sbi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Sets a specified bit in an I/O Register.
	ut16 A = aop->param[0];
	ut16 b = aop->param[1];

	RzILOpPure *setb, *target, *result;
	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		reg = avr_registers[A];
	}

	setb = AVR_IMM(1u << b);
	target = VARG(reg);
	result = LOGOR(setb, target);
	return SETG(reg, result);
}

static RzILOpEffect *avr_il_sbic(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Skip if Bit in I/O Register is Cleared.
	ut16 A = aop->param[0];
	ut16 b = aop->param[1];

	RzILOpPure *clearb, *target, *result;
	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		reg = avr_registers[A];
	}

	clearb = AVR_IMM(~(1u << b));
	target = VARG(reg);
	result = LOGAND(clearb, target);
	result = IS_ZERO(result);
	return avr_il_branch_when(aop, analysis, pc + next_op->size, result, true);
}

static RzILOpEffect *avr_il_sbis(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Skip if Bit in I/O Register is Set.
	ut16 A = aop->param[0];
	ut16 b = aop->param[1];

	RzILOpPure *clearb, *target, *result;
	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		reg = avr_registers[A];
	}

	clearb = AVR_IMM(~(1u << b));
	target = VARG(reg);
	result = LOGAND(clearb, target);
	result = IS_ZERO(result);
	return avr_il_branch_when(aop, analysis, pc + next_op->size, result, false);
}

static RzILOpEffect *avr_il_sbiw(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *imm;
	RzILOpEffect *let, *sbiw, *Z, *S, *V, *N, *C;
	// Rd+1:Rd = Rd+1:Rd - K
	// Rd can be only 24,26,28,30
	ut16 Rdh = aop->param[0];
	ut16 Rdl = aop->param[1];
	ut16 K = aop->param[2];
	avr_return_val_if_invalid_gpr(Rdh, NULL);
	avr_return_val_if_invalid_gpr(Rdl, NULL);

	// IND = Rd+1:Rd - K
	imm = UN(AVR_IND_SIZE, K);
	x = avr_il_get_indirect_address_reg(Rdh, Rdl);
	x = SUB(x, imm);
	let = SETL(AVR_LET_IND, x);

	// Rd+1:Rd = IND
	sbiw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rdh, Rdl, 0, false);

	// set Z to 1 if !IND
	Z = avr_il_check_zero_flag_local(AVR_LET_IND, false);

	// Res = IND
	// V: Rdh7 & !Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	V = avr_il_check_two_complement_overflow_flag_subtraction_wide(AVR_LET_IND, Rdh);

	// Res = IND
	// N: Res15
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_IND);

	// Res = IND
	// C: !Rdh7 & Res15
	C = avr_il_check_carry_flag_subtraction_wide(AVR_LET_IND, Rdh);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, sbiw, Z, V, N, C, S);
}

static RzILOpEffect *avr_il_sbrc(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Skip if Bit in Register is Cleared.
	ut16 Rd = aop->param[0];
	ut16 b = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpPure *clearb, *target, *result;

	clearb = AVR_IMM(~(1u << b));
	target = AVR_REG(Rd);
	result = LOGAND(clearb, target);
	result = IS_ZERO(result);
	return avr_il_branch_when(aop, analysis, pc + next_op->size, result, true);
}

static RzILOpEffect *avr_il_sbrs(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Skip if Bit in Register is Set.
	ut16 Rd = aop->param[0];
	ut16 b = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpPure *clearb, *target, *result;

	clearb = AVR_IMM(~(1u << b));
	target = AVR_REG(Rd);
	result = LOGAND(clearb, target);
	result = IS_ZERO(result);
	return avr_il_branch_when(aop, analysis, pc + next_op->size, result, false);
}

static RzILOpEffect *avr_il_sec(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// C = 1
	return AVR_SREG_C_SET(true);
}

static RzILOpEffect *avr_il_seh(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// H = 1
	return AVR_SREG_H_SET(true);
}

static RzILOpEffect *avr_il_sei(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// I = 1
	return AVR_SREG_I_SET(true);
}

static RzILOpEffect *avr_il_sen(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// N = 1
	return AVR_SREG_N_SET(true);
}

static RzILOpEffect *avr_il_ser(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_assign_imm(avr_registers[Rd], 0xFF);
}

static RzILOpEffect *avr_il_ses(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// S = 1
	return AVR_SREG_S_SET(true);
}

static RzILOpEffect *avr_il_set(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// T = 1
	return AVR_SREG_T_SET(true);
}

static RzILOpEffect *avr_il_sev(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// V = 1
	return AVR_SREG_V_SET(true);
}

static RzILOpEffect *avr_il_sez(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Z = 1
	return AVR_SREG_Z_SET(true);
}

static RzILOpEffect *avr_il_st(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	RzILOpBitVector *addr;
	RzILOpPure *src;
	RzILOpEffect *st, *post_op, *let;
	// *((ut8*)X) = Rd where X = (r27 << 8) | r26;
	// *((ut8*)Y) = Rd where Y = (r29 << 8) | r28;
	// *((ut8*)Z) = Rd where Z = (r31 << 8) | r30;
	// When Z+ , Z is incremented by 1 after the execution (applies also to X and Y).
	// When -X , X is decremented by 1 after the execution (applies also to Z and Y).
	// When Y+q, Y is incremented by q after the execution (applies also to X and Z).

	// undefined behaviour per ISA below
	// st X+, r26 ; st X+, r27 ; st -X, r26 ; st -X, r27
	// st Y+, r28 ; st Y+, r29 ; st -Y, r28 ; st -Y, r29
	// st Z+, r30 ; st Z+, r31 ; st -Z, r30 ; st -Z, r31

	ut16 Rd = aop->param[0];
	char Rr = (char)aop->param[1]; // 'X' or 'Y' or 'Z'
	char Op = (char)aop->param[2]; //  0  or '+' or '-'
	ut16 q = aop->param[3];

	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_indirect_address(Rr, NULL);

	switch (Rr) {
	case 'X':
		addr = AVR_X();
		break;
	case 'Y':
		addr = AVR_Y();
		break;
	default: // 'Z'
		addr = AVR_Z();
		break;
	}

	addr = AVR_ADDR(addr);
	src = AVR_REG(Rd);
	st = STOREW(addr, src);

	if (Op != '+' && Op != '-') {
		return st;
	}

	switch (Rr) {
	case 'X':
		addr = AVR_X();
		post_op = AVR_SET_X(AVR_LET_IND, q, Op == '+');
		break;
	case 'Y':
		addr = AVR_Y();
		post_op = AVR_SET_Y(AVR_LET_IND, q, Op == '+');
		break;
	default: // 'Z'
		addr = AVR_Z();
		post_op = AVR_SET_Z(AVR_LET_IND, q, Op == '+');
		break;
	}

	let = SETL(AVR_LET_IND, addr);
	return SEQ3(st, let, post_op);
}

static RzILOpEffect *avr_il_sts(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = *(k)
	ut16 k = aop->param[0];
	ut16 Rd = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_store_reg(k, avr_registers[Rd]);
}

static RzILOpEffect *avr_il_sub(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd - Rr
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	avr_return_val_if_invalid_gpr(Rr, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *subt, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// TMP = Rd - Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	sub = SUB(x, y);
	let = SETL(AVR_LET_RES, sub);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	subt = AVR_REG_SET(Rd, x);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, false);

	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, Z, H, V, N, C, S, subt);
}

static RzILOpEffect *avr_il_subi(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd - K
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *subt, *Z, *H, *S, *V, *N, *C;
	RzILOpBitVector *sub;

	// TMP = Rd - K
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	sub = SUB(x, y);
	let = SETL(AVR_LET_RES, sub);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	subt = AVR_REG_SET(Rd, x);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag_local(AVR_LET_RES, false);

	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	H = avr_il_check_half_carry_flag_subtraction(AVR_LET_RES, x, y);

	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	V = avr_il_check_two_complement_overflow_flag_subtraction(AVR_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_local(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, Z, H, V, N, C, S, subt);
}

static RzILOpEffect *avr_il_swap(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Swaps high and low nibbles in a register.
	// R(7:4) = Rd(3:0), R(3:0) = Rd(7:4)
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y, *z;
	RzILOpEffect *let, *swap;

	// copy Rd
	x = AVR_REG(Rd);
	let = SETL(AVR_LET_RES, x);

	// Rd <<= 4
	x = AVR_REG(Rd);
	y = AVR_SH(4);
	x = SHIFTL0(x, y);

	// Rd |= RES >> 4
	z = VARL(AVR_LET_RES);
	y = AVR_SH(4);
	z = SHIFTR0(z, y);

	// Rd = (Rd << 4) | (RES >> 4)
	x = LOGOR(x, z);
	swap = AVR_REG_SET(Rd, x);

	return SEQ2(let, swap);
}

static RzILOpEffect *avr_il_xch(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis) {
	// Swaps the register content with the contents pointed by Z.
	// *(Z) = Rd and Rd = *(Z)
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *set, *store;

	// copy Rd
	x = AVR_REG(Rd);
	let = SETL(AVR_LET_RES, x);

	// Rd = *(Z)
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	x = LOADW(AVR_REG_SIZE, x);
	set = AVR_REG_SET(Rd, x);

	// *(Z) = RES
	x = AVR_Z();
	x = UNSIGNED(AVR_ADDR_SIZE, x);
	y = VARL(AVR_LET_RES);
	store = STOREW(x, y);

	return SEQ3(let, set, store);
}

#include <rz_il/rz_il_opbuilder_end.h>

typedef RzILOpEffect *(*avr_il_op)(AVROp *aop, AVROp *next_op, ut64 pc, RzAnalysis *analysis);

static avr_il_op avr_ops[AVR_OP_SIZE] = {
	avr_il_unk, /* AVR_OP_INVALID */
	avr_il_adc,
	avr_il_add,
	avr_il_adiw,
	avr_il_and,
	avr_il_andi,
	avr_il_asr,
	avr_il_bld,
	avr_il_brcc,
	avr_il_brcs,
	avr_il_nop, /* AVR_OP_BREAK - the CPU treats the BREAK instruction as a NOP when not in JTAG mode */
	avr_il_breq,
	avr_il_brge,
	avr_il_brhc,
	avr_il_brhs,
	avr_il_brid,
	avr_il_brie,
	avr_il_brcs, /* AVR_OP_BRLO - alias of brcs */
	avr_il_brlt,
	avr_il_brmi,
	avr_il_brne,
	avr_il_brpl,
	avr_il_brcc, /* AVR_OP_BRSH - alias of brcc */
	avr_il_brtc,
	avr_il_brts,
	avr_il_brvc,
	avr_il_brvs,
	avr_il_bst,
	avr_il_call,
	avr_il_cbi,
	avr_il_clc,
	avr_il_clh,
	avr_il_cli,
	avr_il_cln,
	avr_il_clr,
	avr_il_cls,
	avr_il_clt,
	avr_il_clv,
	avr_il_clz,
	avr_il_com,
	avr_il_cp,
	avr_il_cpc,
	avr_il_cpi,
	avr_il_cpse,
	avr_il_dec,
	avr_il_unk, /* AVR_OP_DES */
	avr_il_eicall,
	avr_il_eijmp,
	avr_il_elpm,
	avr_il_eor,
	avr_il_fmul,
	avr_il_fmuls,
	avr_il_fmulsu,
	avr_il_icall,
	avr_il_ijmp,
	avr_il_in,
	avr_il_inc,
	avr_il_jmp,
	avr_il_lac,
	avr_il_las,
	avr_il_lat,
	avr_il_ld,
	avr_il_ld, /* AVR_OP_LDD - like ld */
	avr_il_ldi,
	avr_il_lds,
	avr_il_lpm,
	avr_il_lsl,
	avr_il_lsr,
	avr_il_mov,
	avr_il_movw,
	avr_il_mul,
	avr_il_muls,
	avr_il_mulsu,
	avr_il_neg,
	avr_il_nop,
	avr_il_or,
	avr_il_ori,
	avr_il_out,
	avr_il_pop,
	avr_il_push,
	avr_il_rcall,
	avr_il_ret,
	avr_il_ret, /* AVR_OP_RETI - works same way as ret */
	avr_il_rjmp,
	avr_il_rol,
	avr_il_ror,
	avr_il_sbc,
	avr_il_sbci,
	avr_il_sbi,
	avr_il_sbic,
	avr_il_sbis,
	avr_il_sbiw,
	avr_il_sbrc,
	avr_il_sbrs,
	avr_il_sec,
	avr_il_seh,
	avr_il_sei,
	avr_il_sen,
	avr_il_ser,
	avr_il_ses,
	avr_il_set,
	avr_il_sev,
	avr_il_sez,
	avr_il_nop, /* AVR_OP_SLEEP - is a NOP for RzIL */
	avr_il_unk, /* AVR_OP_SPM - this cannot be implemented. */
	avr_il_st,
	avr_il_st, /* AVR_OP_STD - same as ST */
	avr_il_sts,
	avr_il_sub,
	avr_il_subi,
	avr_il_swap,
	avr_il_and, /* AVR_OP_TST - same as and */
	avr_il_nop, /* AVR_OP_WDR - is a NOP for RzIL */
	avr_il_xch,
};

RZ_IPI bool rz_avr_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop, AVROp *next_op) {
	rz_return_val_if_fail(analysis && op && aop && next_op, false);
	if (aop->mnemonic >= AVR_OP_SIZE) {
		RZ_LOG_ERROR("RzIL: AVR: out of bounds op\n");
		return false;
	}

	avr_il_op create_op = avr_ops[aop->mnemonic];
	op->il_op = create_op(aop, next_op, pc, analysis);

	return true;
}

RZ_IPI RzAnalysisILConfig *rz_avr_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *r = rz_analysis_il_config_new(AVR_ADDR_SIZE, analysis->big_endian, AVR_ADDR_SIZE);
	r->reg_bindings = avr_global_registers;
	return r;
}
