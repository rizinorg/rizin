// SPDX-FileCopyrightText: 2021-2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "avr_il.h"
#include <rz_il/rz_il_opbuilder_begin.h>

#define AVR_REG_SIZE  8
#define AVR_SREG_SIZE 8
#define AVR_MMIO_SIZE 8
#define AVR_SP_SIZE   16
#define AVR_IND_SIZE  16
#define AVR_ADDR_SIZE 32 // should be 22 bits max, but we can ignore this
#define AVR_SREG      "sreg"
#define AVR_SP        "sp"
#define AVR_SPH       "spl"
#define AVR_SPL       "sph"
#define AVR_RAMPX     "rampx"
#define AVR_RAMPY     "rampy"
#define AVR_RAMPZ     "rampz"
#define AVR_RAMPD     "rampd"
#define AVR_EIND      "eind"
#define AVR_SPMCSR    "spmcsr"
#define AVR_LET_RES   "RES"
#define AVR_LET_IND   "IND"

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
#define AVR_REG(reg)         VARG(avr_registers[(reg)])
#define AVR_ONE()            UN(AVR_REG_SIZE, 1)
#define AVR_ZERO()           UN(AVR_REG_SIZE, 0)
#define AVR_X()              avr_il_get_indirect_address_reg(27, 26)
#define AVR_Y()              avr_il_get_indirect_address_reg(29, 28)
#define AVR_Z()              avr_il_get_indirect_address_reg(31, 30)
#define AVR_SET_X(l, n, add) avr_il_update_indirect_address_reg(l, 27, 26, n, add)
#define AVR_SET_Y(l, n, add) avr_il_update_indirect_address_reg(l, 29, 28, n, add)
#define AVR_SET_Z(l, n, add) avr_il_update_indirect_address_reg(l, 31, 30, n, add)

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

static inline RzILOpEffect *avr_il_jump_relative(AVROp *aop, RzAnalysis *analysis, ut32 where) {
	RzILOpBitVector *_loc = UN(AVR_ADDR_SIZE, where - aop->size);
	return JMP(_loc);
}

static inline RzILOpEffect *avr_il_branch_when(AVROp *aop, RzAnalysis *analysis, ut16 where, RzILOpBool *when, bool cond) {
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

static inline RzILOpEffect *avr_il_store_reg(ut64 addr, const char *reg) {
	RzILOpBitVector *_loc = UN(AVR_ADDR_SIZE, addr);
	RzILOpPure *_var = VARG(reg);
	return STOREW(_loc, _var);
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
	RzArchProfile *profile = analysis->arch_target ? analysis->arch_target->profile : NULL;
	if (!profile) {
		return NULL;
	}
	return rz_arch_profile_resolve_mmio(profile, address);
}

static RzILOpEffect *avr_il_check_zero_flag(const char *local, bool and_zero) {
	// set Z to 1 if !(x - y) or !(x - y - C)
	RzILOpPure *_alu = VARL(local);
	RzILOpBool *_is_zero = IS_ZERO(_alu);
	if (and_zero) {
		RzILOpBool *Z = VARG(AVR_SREG_Z);
		_is_zero = AND(_is_zero, Z);
	}
	return SETG(AVR_SREG_Z, _is_zero);
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
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *not1, *Res, *and0, *and1, *or0;
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
	bit = AVR_IMM(1u << 7);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(AVR_SREG_V, and0);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_addition_wide(const char *local, RzILOpPure *Rdh) {
	RzILOpBool *ovf;
	RzILOpBitVector *bit, *Res;
	// Rdh = X, Res = Rd+1:Rd
	// V: !Rdh7 & Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// extract bit 7 from Rdh
	bit = AVR_IMM(1u << 7);
	Rdh = LOGNOT(Rdh); // !Rdh
	Rdh = LOGAND(Rdh, bit); // !Rdh7

	// extract bit 15 from Res
	Res = VARL(local);
	bit = UN(AVR_IND_SIZE, 1u << 15);
	Res = LOGAND(Res, bit); // !Res15

	// boolean and (not logical)
	Rdh = NON_ZERO(Rdh); // cast to bool
	Res = NON_ZERO(Res); // cast to bool
	ovf = AND(Rdh, Res); // !Rdh7 & Res15
	return SETG(AVR_SREG_V, ovf);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_subtraction(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *not1, *Res, *and0, *and1, *or0;
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

	// extract bit 7 from or
	bit = AVR_IMM(1u << 7);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(AVR_SREG_V, and0);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_subtraction_wide(const char *local, RzILOpPure *Rdh) {
	RzILOpBool *ovf;
	RzILOpBitVector *bit, *Res;
	// Rdh = X, Res = Rd+1:Rd
	// V: Rdh7 & !Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// extract bit 7 from Rdh
	bit = AVR_IMM(1u << 7);
	Rdh = LOGAND(Rdh, bit);

	// extract bit 15 from Res
	Res = VARL(local);
	Res = LOGNOT(Res); // !Res
	bit = UN(AVR_IND_SIZE, 1u << 15);
	Res = LOGAND(Res, bit); // !Res15

	// boolean and (not logical)
	Rdh = NON_ZERO(Rdh); // cast to bool
	Res = NON_ZERO(Res); // cast to bool
	ovf = AND(Rdh, Res); // Rdh7 & !Res15
	return SETG(AVR_SREG_V, ovf);
}

static RzILOpEffect *avr_il_check_negative_flag(const char *local) {
	// Res = Rd - Rr
	// N: Res7 is set
	// Set if MSB of the result is set; cleared otherwise.

	// extract bit 7 from Res
	RzILOpPure *Res = VARL(local);
	RzILOpBitVector *bit = AVR_IMM(1u << 7);
	RzILOpBitVector *and = LOGAND(Res, bit);
	and = NON_ZERO(and); // cast to bool
	return SETG(AVR_SREG_N, and);
}

static RzILOpEffect *avr_il_check_negative_flag_wide(const char *local) {
	// Res = Rd+1:Rd
	// N: Res15 is set
	// Set if MSB of the result is set; cleared otherwise.

	// extract bit 15 from Res
	RzILOpBitVector *Res = VARL(local);
	RzILOpBitVector *bit = UN(AVR_IND_SIZE, 1u << 15);
	RzILOpBitVector *and = LOGAND(Res, bit);
	and = NON_ZERO(and); // cast to bool
	return SETG(AVR_SREG_N, and);
}

static RzILOpEffect *avr_il_check_carry_flag_addition(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
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

	// extract bit 7 from or
	bit = AVR_IMM(1u << 7);
	and0 = LOGAND(or0, bit);
	and0 = NON_ZERO(and0); // cast to bool
	return SETG(AVR_SREG_H, and0);
}

static RzILOpEffect *avr_il_check_carry_flag_addition_wide(const char *local, RzILOpPure *Rdh) {
	RzILOpBitVector *crr, *bit, *Res;
	// Res = Rd+1:Rd
	// !Res15 & Rdh7
	// Set if the absolute value of K is larger than the absolute value of Rd; cleared otherwise

	// extract bit 7 from Rdh
	bit = AVR_IMM(1u << 7);
	Rdh = LOGAND(Rdh, bit);

	// extract bit 15 from Res
	Res = VARL(local);
	Res = LOGNOT(Res); // !Res
	bit = UN(AVR_IND_SIZE, 1u << 15);
	Res = LOGAND(Res, bit); // !Res15

	// boolean and (not logical)
	Res = NON_ZERO(Res); // cast to bool
	Rdh = NON_ZERO(Rdh); // cast to bool
	crr = AND(Res, Rdh); // !Res15 & Rdh7
	return SETG(AVR_SREG_C, crr);
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

static RzILOpEffect *avr_il_check_carry_flag_subtraction_wide(const char *local, RzILOpPure *Rdh) {
	RzILOpBitVector *crr, *bit, *Res;
	// Res = Rd+1:Rd
	// Res15 & !Rdh7
	// Set if the absolute value of K is larger than the absolute value of Rd; cleared otherwise

	// extract bit 7 from Rdh
	bit = AVR_IMM(1u << 7);
	Rdh = LOGNOT(Rdh); // !Rdh
	Rdh = LOGAND(Rdh, bit); // !Rdh7

	// extract bit 15 from Res
	Res = VARL(local);
	bit = UN(AVR_IND_SIZE, 1u << 15);
	Res = LOGAND(Res, bit); // Res15

	// boolean and (not logical)
	Res = NON_ZERO(Res); // cast to bool
	Rdh = NON_ZERO(Rdh); // cast to bool
	crr = AND(Res, Rdh); // Res15 & !Rdh7
	return SETG(AVR_SREG_C, crr);
}

static RzILOpEffect *avr_il_check_signess_flag() {
	// S: N ^ V, For signed tests.
	RzILOpPure *N = VARG(AVR_SREG_N);
	RzILOpPure *V = VARG(AVR_SREG_V);
	RzILOpBool *_xor = XOR(N, V);
	return SETG(AVR_SREG_S, _xor);
}

/* ops */

static RzILOpEffect *avr_il_unk(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	return NULL; // rz_il_op_new_nop();
}

static RzILOpEffect *avr_il_nop(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	return NOP;
}

static RzILOpEffect *avr_il_adc(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *adc, *let, *H, *S, *V, *N, *Z, *C;
	// Rd = Rd + Rr + C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	// TMP = Rd + Rr + C
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = ADD(x, y);
	y = avr_il_sreg_bit_as_imm(AVR_SREG_C, 1);
	x = ADD(x, y);
	let = SETL(AVR_LET_RES, x);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	adc = SETG(avr_registers[Rd], x);

	// H: (Rd3 & Rr3) | (Rr3 & !R3) | (!R3 & Rd3)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_addition(AVR_LET_RES, x, y);

	// V: (Rd7 & Rr7 & !Res7) | (!Rd7 & !Rr7 & Res7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_addition(AVR_LET_RES, x, y);

	// H: (Rd3 & Rr3) | (Rr3 & !R3) | (!R3 & Rd3)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_addition(AVR_LET_RES, x, y);

	// N: Res7
	x = VARL(AVR_LET_RES);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = VARL(AVR_LET_RES);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// C: (Rd7 & Rr7) | (Rr7 & !R7) | (!R7 & Rd7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_addition(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, H, V, N, Z, C, S, adc);
}

static RzILOpEffect *avr_il_add(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *adc, *let, *H, *S, *V, *N, *Z, *C;
	// Rd = Rd + Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	// TMP = Rd + Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = ADD(x, y);
	let = SETL(AVR_LET_RES, x);

	// Rd = TMP
	x = VARL(AVR_LET_RES);
	adc = SETG(avr_registers[Rd], x);

	// H: (Rd3 & Rr3) | (Rr3 & !R3) | (!R3 & Rd3)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_addition(AVR_LET_RES, x, y);

	// V: (Rd7 & Rr7 & !Res7) | (!Rd7 & !Rr7 & Res7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	V = avr_il_check_two_complement_overflow_flag_addition(AVR_LET_RES, x, y);

	// H: (Rd3 & Rr3) | (Rr3 & !R3) | (!R3 & Rd3)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	H = avr_il_check_half_carry_flag_addition(AVR_LET_RES, x, y);

	// N: Res7
	x = VARL(AVR_LET_RES);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = VARL(AVR_LET_RES);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// C: // C: (Rd7 & Rr7) | (Rr7 & !R7) | (!R7 & Rd7)
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_addition(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// update SREG based on flags

	return SEQ8(let, H, V, N, Z, C, S, adc);
}

static RzILOpEffect *avr_il_adiw(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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
	Z = avr_il_check_zero_flag(AVR_LET_IND, false);

	// Res = IND
	// V: !Rdh7 & Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rdh);
	V = avr_il_check_two_complement_overflow_flag_addition_wide(AVR_LET_IND, x);

	// Res = IND
	// N: Res15
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_wide(AVR_LET_IND);

	// Res = IND
	// C: !Res15 & Rdh7
	x = AVR_REG(Rdh);
	C = avr_il_check_carry_flag_addition_wide(AVR_LET_IND, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, adiw, Z, V, N, C, S);
}

static RzILOpEffect *avr_il_and(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *and0, *S, *V, *N, *Z;
	// Rd = Rd & Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	// Rd = Rd & Rr
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	x = LOGAND(x, y);
	and0 = SETG(avr_registers[Rd], x);

	// V: 0 (Cleared)
	x = rz_il_op_new_b0();
	V = SETG(AVR_SREG_V, x);

	// N: Res7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(and0, V, N, Z, S);
}

static RzILOpEffect *avr_il_andi(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *andi, *S, *V, *N, *Z;
	// Rd = Rd & K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];

	// Rd = Rd & K
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	x = LOGAND(x, y);
	andi = SETG(avr_registers[Rd], x);

	// V: 0 (Cleared)
	x = rz_il_op_new_b0();
	V = SETG(AVR_SREG_V, x);

	// N: Res7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ5(andi, V, N, Z, S);
}

static RzILOpEffect *avr_il_asr(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *asr, *S, *V, *N, *Z, *C;
	// Rd >>= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// simplified by adding itself
	x = AVR_REG(Rd);
	y = AVR_SH(1);
	x = SHIFTR0(x, y);
	asr = SETG(avr_registers[Rd], x);

	// C: Rd0
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 0);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	C = SETG(AVR_SREG_C, x);

	// perform shift since we need the result for the SREG flags.
	// N: Res7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = VARG(AVR_SREG_N);
	y = VARG(AVR_SREG_C);
	x = XOR(x, y);
	V = SETG(AVR_SREG_V, x);

	return SEQ6(C, asr, N, Z, S, V);
}

static RzILOpEffect *avr_il_bld(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Copies the T Flag in the SREG (Status Register) to bit b in register Rd
	// all the other bits are unchanged
	ut16 Rd = aop->param[0];
	ut16 b = aop->param[1];

	RzILOpPure *reg, *add_bit, *remove_bit, *bit, *res;

	reg = AVR_REG(Rd);
	bit = AVR_IMM(1u << b);
	add_bit = LOGOR(reg, bit);

	bit = AVR_IMM(~(1u << b));
	reg = AVR_REG(Rd);
	remove_bit = LOGAND(reg, bit);

	res = ITE(VARG(AVR_SREG_T), add_bit, remove_bit);
	return SETG(avr_registers[Rd], res);
}

static RzILOpEffect *avr_il_brcc(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// branch if C = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_C);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brcs(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// branch if C = 1
	ut16 k = aop->param[0];

	RzILOpPure *when = VARG(AVR_SREG_C);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_breq(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// branch if Z = 1
	ut16 k = aop->param[0];

	RzILOpPure *when = VARG(AVR_SREG_Z);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brne(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// branch if Z = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = VARG(AVR_SREG_Z);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_call(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// PC = k
	ut32 k = aop->param[0];
	k <<= 16;
	k |= aop->param[1];

	RzILOpPure *val, *num;
	RzILOpEffect *jmp, *push, *sub;

	jmp = avr_il_jump_relative(aop, analysis, k);

	num = AVR_PC(pc);
	val = VARG(AVR_SP);
	val = AVR_ADDR(val);
	push = STOREW(val, num);

	num = AVR_IMM16(2);
	val = VARG(AVR_SP);
	val = SUB(val, num);
	sub = SETG(AVR_SP, val);

	return SEQ3(push, sub, jmp);
}

static RzILOpEffect *avr_il_clc(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// C = 0
	return avr_il_assign_bool(AVR_SREG_C, false);
}

static RzILOpEffect *avr_il_clh(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// H = 0
	return avr_il_assign_bool(AVR_SREG_H, false);
}

static RzILOpEffect *avr_il_cli(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// I = 0
	return avr_il_assign_bool(AVR_SREG_I, false);
}

static RzILOpEffect *avr_il_cln(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// N = 0
	return avr_il_assign_bool(AVR_SREG_N, false);
}

static RzILOpEffect *avr_il_clr(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd ^ Rd -> S=0, V=0, N=0, Z=1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpEffect *clr, *S, *V, *N, *Z;
	clr = avr_il_assign_imm(avr_registers[Rd], 0);
	S = avr_il_assign_bool(AVR_SREG_S, false);
	V = avr_il_assign_bool(AVR_SREG_V, false);
	N = avr_il_assign_bool(AVR_SREG_N, false);
	Z = avr_il_assign_bool(AVR_SREG_Z, true);

	return SEQ5(clr, S, V, N, Z);
}

static RzILOpEffect *avr_il_cls(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// S = 0
	return avr_il_assign_bool(AVR_SREG_S, false);
}

static RzILOpEffect *avr_il_clt(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// T = 0
	return avr_il_assign_bool(AVR_SREG_T, false);
}

static RzILOpEffect *avr_il_clv(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// V = 0
	return avr_il_assign_bool(AVR_SREG_V, false);
}

static RzILOpEffect *avr_il_clz(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Z = 0
	return avr_il_assign_bool(AVR_SREG_Z, false);
}

static RzILOpEffect *avr_il_cpi(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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
	Z = avr_il_check_zero_flag(AVR_LET_RES, false);

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
	N = avr_il_check_negative_flag(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, Z, H, V, N, C, S);
}

static RzILOpEffect *avr_il_cpc(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// compare Rd with Rr with Carry and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
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
	Z = avr_il_check_zero_flag(AVR_LET_RES, true);

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
	N = avr_il_check_negative_flag(AVR_LET_RES);

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

static RzILOpEffect *avr_il_ijmp(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *loc, *one;
	// PC = Z << 1
	loc = AVR_Z();
	loc = EXTZERO(AVR_ADDR_SIZE, loc);
	one = AVR_SH(1);
	loc = SHIFTL0(loc, one);
	return JMP(loc);
}

static RzILOpEffect *avr_il_jmp(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// PC = PC + k + 1
	ut16 k = aop->param[0];

	return avr_il_jump_relative(aop, analysis, k);
}

static RzILOpEffect *avr_il_ldi(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Rd = K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_assign_imm(avr_registers[Rd], K);
}

static RzILOpEffect *avr_il_lpm(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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
	lpm = SETG(avr_registers[Rd], load);

	if (!post_inc) {
		return lpm;
	}
	z = AVR_Z();
	let = SETL(AVR_LET_IND, z);
	zpp = AVR_SET_Z(AVR_LET_IND, 1, true); // Z++
	return SEQ3(lpm, let, zpp);
}

static RzILOpEffect *avr_il_lsl(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *lsl, *H, *S, *V, *N, *Z, *C;
	// Rd <<= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// simplified by adding itself
	x = AVR_REG(Rd);
	y = AVR_REG(Rd);
	x = ADD(x, y);
	lsl = SETG(avr_registers[Rd], x);

	// H: Rd3
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 3);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	H = SETG(AVR_SREG_H, x);

	// C: Rd7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	C = SETG(AVR_SREG_C, x);

	// perform shift since we need the result for the SREG flags.
	// N: Res7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = VARG(AVR_SREG_N);
	y = VARG(AVR_SREG_C);
	x = XOR(x, y);
	V = SETG(AVR_SREG_V, x);

	return SEQ7(H, C, lsl, N, Z, S, V);
}

static RzILOpEffect *avr_il_mov(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	return avr_il_assign_reg(avr_registers[Rd], avr_registers[Rr]);
}

static RzILOpEffect *avr_il_movw(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x;

	RzILOpEffect *let, *movw;
	// Rd+1:Rd = Rr+1:Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	x = avr_il_get_indirect_address_reg(Rr + 1, Rr);
	let = SETL(AVR_LET_IND, x);

	movw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rd + 1, Rd, 0, false);
	return SEQ2(let, movw);
}

static RzILOpEffect *avr_il_out(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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

static RzILOpEffect *avr_il_rol(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *rol, *H, *S, *V, *N, *Z, *C;
	// Rd = rot_left(Rd, 1)
	ut16 Rd = aop->param[0];

	// simplified by adding itself with Carry
	x = AVR_REG(Rd);
	y = AVR_REG(Rd);
	x = ADD(x, y);
	y = avr_il_sreg_bit_as_imm(AVR_SREG_C, 1);
	x = ADD(x, y);
	rol = SETG(avr_registers[Rd], x);

	// H: Rd3
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 3);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	H = SETG(AVR_SREG_H, x);

	// C: Rd7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	C = SETG(AVR_SREG_C, x);

	// perform rotation since we need the result for the SREG flags.
	// N: Res7
	x = AVR_REG(Rd);
	y = AVR_IMM(1u << 7);
	x = LOGAND(x, y);
	x = NON_ZERO(x); // cast to bool
	N = SETG(AVR_SREG_N, x);

	// Z: !Res
	x = AVR_REG(Rd);
	x = IS_ZERO(x);
	Z = SETG(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = VARG(AVR_SREG_N);
	y = VARG(AVR_SREG_C);
	x = XOR(x, y);
	V = SETG(AVR_SREG_V, x);

	return SEQ7(H, C, rol, N, Z, S, V);
}

static RzILOpEffect *avr_il_sbiw(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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
	Z = avr_il_check_zero_flag(AVR_LET_IND, false);

	// Res = IND
	// V: Rdh7 & !Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = AVR_REG(Rdh);
	V = avr_il_check_two_complement_overflow_flag_subtraction_wide(AVR_LET_IND, x);

	// Res = IND
	// N: Res15
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_wide(AVR_LET_IND);

	// Res = IND
	// C: !Rdh7 & Res15
	x = AVR_REG(Rdh);
	C = avr_il_check_carry_flag_subtraction_wide(AVR_LET_IND, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ7(let, sbiw, Z, V, N, C, S);
}

static RzILOpEffect *avr_il_sec(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// C = 0
	return avr_il_assign_bool(AVR_SREG_C, true);
}

static RzILOpEffect *avr_il_seh(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// H = 0
	return avr_il_assign_bool(AVR_SREG_H, true);
}

static RzILOpEffect *avr_il_sei(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// I = 0
	return avr_il_assign_bool(AVR_SREG_I, true);
}

static RzILOpEffect *avr_il_sen(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// N = 0
	return avr_il_assign_bool(AVR_SREG_N, true);
}

static RzILOpEffect *avr_il_ser(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_assign_imm(avr_registers[Rd], 0xFF);
}

static RzILOpEffect *avr_il_ses(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// S = 0
	return avr_il_assign_bool(AVR_SREG_S, true);
}

static RzILOpEffect *avr_il_set(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// T = 0
	return avr_il_assign_bool(AVR_SREG_T, true);
}

static RzILOpEffect *avr_il_sev(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// V = 0
	return avr_il_assign_bool(AVR_SREG_V, true);
}

static RzILOpEffect *avr_il_sez(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Z = 0
	return avr_il_assign_bool(AVR_SREG_Z, true);
}

static RzILOpEffect *avr_il_st(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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

static RzILOpEffect *avr_il_sub(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
	// Rd = Rd - Rr
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
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
	subt = SETG(avr_registers[Rd], x);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag(AVR_LET_RES, false);

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
	N = avr_il_check_negative_flag(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_REG(Rr);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, Z, H, V, N, C, S, subt);
}

static RzILOpEffect *avr_il_subi(AVROp *aop, ut64 pc, RzAnalysis *analysis) {
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
	subt = SETG(avr_registers[Rd], x);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag(AVR_LET_RES, false);

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
	N = avr_il_check_negative_flag(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = AVR_REG(Rd);
	y = AVR_IMM(K);
	C = avr_il_check_carry_flag_subtraction(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return SEQ8(let, Z, H, V, N, C, S, subt);
}

typedef RzILOpEffect *(*avr_il_op)(AVROp *aop, ut64 pc, RzAnalysis *analysis);

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
	avr_il_unk, /* AVR_OP_BRGE */
	avr_il_unk, /* AVR_OP_BRHC */
	avr_il_unk, /* AVR_OP_BRHS */
	avr_il_unk, /* AVR_OP_BRID */
	avr_il_unk, /* AVR_OP_BRIE */
	avr_il_unk, /* AVR_OP_BRLO */
	avr_il_unk, /* AVR_OP_BRLT */
	avr_il_unk, /* AVR_OP_BRMI */
	avr_il_brne,
	avr_il_unk, /* AVR_OP_BRPL */
	avr_il_unk, /* AVR_OP_BRSH */
	avr_il_unk, /* AVR_OP_BRTC */
	avr_il_unk, /* AVR_OP_BRTS */
	avr_il_unk, /* AVR_OP_BRVC */
	avr_il_unk, /* AVR_OP_BRVS */
	avr_il_unk, /* AVR_OP_BST */
	avr_il_call,
	avr_il_unk, /* AVR_OP_CBI */
	avr_il_clc,
	avr_il_clh,
	avr_il_cli,
	avr_il_cln,
	avr_il_clr,
	avr_il_cls,
	avr_il_clt,
	avr_il_clv,
	avr_il_clz,
	avr_il_unk, /* AVR_OP_COM */
	avr_il_unk, /* AVR_OP_CP */
	avr_il_cpc,
	avr_il_cpi,
	avr_il_unk, /* AVR_OP_CPSE */
	avr_il_unk, /* AVR_OP_DEC */
	avr_il_unk, /* AVR_OP_DES */
	avr_il_unk, /* AVR_OP_EICALL */
	avr_il_unk, /* AVR_OP_EIJMP */
	avr_il_unk, /* AVR_OP_ELPM */
	avr_il_unk, /* AVR_OP_EOR */
	avr_il_unk, /* AVR_OP_FMUL */
	avr_il_unk, /* AVR_OP_FMULS */
	avr_il_unk, /* AVR_OP_FMULSU */
	avr_il_unk, /* AVR_OP_ICALL */
	avr_il_ijmp,
	avr_il_unk, /* AVR_OP_IN */
	avr_il_unk, /* AVR_OP_INC */
	avr_il_jmp, /* AVR_OP_JMP - same as rjmp */
	avr_il_unk, /* AVR_OP_LAC */
	avr_il_unk, /* AVR_OP_LAS */
	avr_il_unk, /* AVR_OP_LAT */
	avr_il_unk, /* AVR_OP_LD */
	avr_il_unk, /* AVR_OP_LDD */
	avr_il_ldi,
	avr_il_unk, /* AVR_OP_LDS */
	avr_il_lpm,
	avr_il_lsl,
	avr_il_unk, /* AVR_OP_LSR */
	avr_il_mov,
	avr_il_movw,
	avr_il_unk, /* AVR_OP_MUL */
	avr_il_unk, /* AVR_OP_MULS */
	avr_il_unk, /* AVR_OP_MULSU */
	avr_il_unk, /* AVR_OP_NEG */
	avr_il_nop,
	avr_il_unk, /* AVR_OP_OR */
	avr_il_unk, /* AVR_OP_ORI */
	avr_il_out,
	avr_il_unk, /* AVR_OP_POP */
	avr_il_unk, /* AVR_OP_PUSH */
	avr_il_unk, /* AVR_OP_RCALL */
	avr_il_unk, /* AVR_OP_RET */
	avr_il_unk, /* AVR_OP_RETI */
	avr_il_jmp, /* AVR_OP_RJMP - same as jmp */
	avr_il_rol,
	avr_il_unk, /* AVR_OP_ROR */
	avr_il_unk, /* AVR_OP_SBC */
	avr_il_unk, /* AVR_OP_SBCI */
	avr_il_unk, /* AVR_OP_SBI */
	avr_il_unk, /* AVR_OP_SBIC */
	avr_il_unk, /* AVR_OP_SBIS */
	avr_il_sbiw,
	avr_il_unk, /* AVR_OP_SBRC */
	avr_il_unk, /* AVR_OP_SBRS */
	avr_il_sec,
	avr_il_seh,
	avr_il_sei,
	avr_il_sen,
	avr_il_ser,
	avr_il_ses,
	avr_il_set,
	avr_il_sev,
	avr_il_sez,
	avr_il_unk, /* AVR_OP_SLEEP */
	avr_il_unk, /* AVR_OP_SPM */
	avr_il_st,
	avr_il_unk, /* AVR_OP_STD */
	avr_il_unk, /* AVR_OP_STS */
	avr_il_sub,
	avr_il_subi,
	avr_il_unk, /* AVR_OP_SWAP */
	avr_il_and, /* AVR_OP_TST - same as and */
	avr_il_unk, /* AVR_OP_WDR */
	avr_il_unk, /* AVR_OP_XCH */
};

RZ_IPI bool rz_avr_il_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop) {
	rz_return_val_if_fail(analysis, false);
	if (aop->mnemonic >= AVR_OP_SIZE) {
		RZ_LOG_ERROR("RzIL: AVR: out of bounds op\n");
		return false;
	}

	avr_il_op create_op = avr_ops[aop->mnemonic];
	op->il_op = create_op(aop, pc, analysis);

	return true;
}

#include <rz_il/rz_il_opbuilder_end.h>

RZ_IPI RzAnalysisILConfig *rz_avr_il_config(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	RzAnalysisILConfig *r = rz_analysis_il_config_new(AVR_ADDR_SIZE, analysis->big_endian, AVR_ADDR_SIZE);
	r->reg_bindings = avr_global_registers;
	return r;
}
