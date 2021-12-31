// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "il_avr.h"

#define AVR_REG_SIZE  8
#define AVR_SREG_SIZE 8
#define AVR_MMIO_SIZE 8
#define AVR_SP_SIZE   16
#define AVR_IND_SIZE  16
#define AVR_ADDR_SIZE 32 // should be 22 bits max, but we can ignore this
#define AVR_SREG      "SREG"
#define AVR_SP        "SP"
#define AVR_SPH       "SPH"
#define AVR_SPL       "SPL"
#define AVR_RAMPX     "RAMPX"
#define AVR_RAMPY     "RAMPY"
#define AVR_RAMPZ     "RAMPZ"
#define AVR_RAMPD     "RAMPD"
#define AVR_EIND      "EIND"
#define AVR_LET_RES   "RES"
#define AVR_LET_IND   "IND"

// SREG = I|T|H|S|V|N|Z|C
// bits   7|6|5|4|3|2|1|0
#define AVR_SREG_I_BIT ((ut8)(1u << 7))
#define AVR_SREG_I     "I"
#define AVR_SREG_T_BIT ((ut8)(1u << 6))
#define AVR_SREG_T     "T"
#define AVR_SREG_H_BIT ((ut8)(1u << 5))
#define AVR_SREG_H     "H"
#define AVR_SREG_S_BIT ((ut8)(1u << 4))
#define AVR_SREG_S     "S"
#define AVR_SREG_V_BIT ((ut8)(1u << 3))
#define AVR_SREG_V     "V"
#define AVR_SREG_N_BIT ((ut8)(1u << 2))
#define AVR_SREG_N     "N"
#define AVR_SREG_Z_BIT ((ut8)(1u << 1))
#define AVR_SREG_Z     "Z"
#define AVR_SREG_C_BIT ((ut8)(1u << 0))
#define AVR_SREG_C     "C"

#define avr_il_true  rz_il_op_new_b1()
#define avr_il_false rz_il_op_new_b0()

#define avr_il_to_address(x)                        rz_il_op_new_unsigned(AVR_ADDR_SIZE, x)
#define avr_il_pc(a)                                rz_il_op_new_bitv_from_ut64(AVR_ADDR_SIZE, rz_bv_to_ut64((a)->rzil->vm->pc))
#define avr_il_new_sh(sh)                           rz_il_op_new_bitv_from_ut64(32, (sh))
#define avr_il_new_imm(imm)                         rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, (imm))
#define avr_il_new_imm16(imm)                       rz_il_op_new_bitv_from_ut64(16, (imm))
#define avr_il_new_reg(reg)                         rz_il_op_new_var(avr_registers[(reg)])
#define avr_il_new_one()                            rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, 1)
#define avr_il_new_zero()                           rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, 0)
#define avr_il_get_indirect_address_x()             avr_il_get_indirect_address_reg(27, 26)
#define avr_il_get_indirect_address_y()             avr_il_get_indirect_address_reg(29, 28)
#define avr_il_get_indirect_address_z()             avr_il_get_indirect_address_reg(31, 30)
#define avr_il_update_indirect_address_x(l, n, add) avr_il_update_indirect_address_reg(l, 27, 26, n, add)
#define avr_il_update_indirect_address_y(l, n, add) avr_il_update_indirect_address_reg(l, 29, 28, n, add)
#define avr_il_update_indirect_address_z(l, n, add) avr_il_update_indirect_address_reg(l, 31, 30, n, add)

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

const char *avr_registers[32] = {
	"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
	"R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18",
	"R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27",
	"R28", "R29", "R30", "R31"
};

static RzILOpBitVector *avr_il_get_indirect_address_reg(ut16 reg_high, ut16 reg_low) {
	RzILOpPure *high = avr_il_new_reg(reg_high); // rH
	RzILOpPure *low = avr_il_new_reg(reg_low); // rL
	return rz_il_op_new_append(high, low); // addr
}

static RzILOpEffect *avr_il_update_indirect_address_reg(const char *local, ut16 reg_high, ut16 reg_low, ut64 n, bool add) {
	RzILOpBitVector *_iar, *_num;
	RzILOpEffect *_high, *_low;
	const char *Rh = avr_registers[reg_high]; // register high
	const char *Rl = avr_registers[reg_low]; // register low

	_iar = rz_il_op_new_var(local);
	if (n > 0) {
		_num = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, n);
		if (add) {
			_iar = rz_il_op_new_add(_iar, _num);
		} else {
			_iar = rz_il_op_new_sub(_iar, _num);
		}
	}
	_num = avr_il_new_sh(8);
	_iar = rz_il_op_new_shiftr(avr_il_false, _iar, _num);
	_iar = rz_il_op_new_unsigned(AVR_REG_SIZE, _iar);
	_high = rz_il_op_new_set(Rh, _iar);

	_iar = rz_il_op_new_var(local);
	if (n > 0) {
		_num = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, n);
		if (add) {
			_iar = rz_il_op_new_add(_iar, _num);
		} else {
			_iar = rz_il_op_new_sub(_iar, _num);
		}
	}
	_iar = rz_il_op_new_unsigned(AVR_REG_SIZE, _iar);
	_low = rz_il_op_new_set(Rl, _iar);
	return rz_il_op_new_seq(_high, _low);
}

static inline RzILOpEffect *avr_il_jump_relative(AVROp *aop, RzAnalysis *analysis, ut32 where) {
	ut32 pc_size = analysis->rzil->vm->addr_size;
	RzILOpBitVector *_loc = rz_il_op_new_bitv_from_ut64(pc_size, where - aop->size);
	return rz_il_op_new_jmp(_loc);
}

static inline RzILOpEffect *avr_il_branch_when(AVROp *aop, RzAnalysis *analysis, ut16 where, RzILOpBool *when, bool cond) {
	RzILOpEffect *_jmp = avr_il_jump_relative(aop, analysis, where);
	if (cond) {
		return rz_il_op_new_branch(when, _jmp, NULL);
	}
	return rz_il_op_new_branch(when, NULL, _jmp);
}

static inline RzILOpEffect *avr_il_assign_imm(const char *reg, ut16 imm) {
	RzILOpBitVector *_bv = rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, imm);
	return rz_il_op_new_set(reg, _bv);
}

static inline RzILOpEffect *avr_il_assign_bool(const char *reg, ut16 value) {
	return rz_il_op_new_set(reg, value ? avr_il_true : avr_il_false);
}

static inline RzILOpEffect *avr_il_assign_reg(const char *dst, const char *src) {
	RzILOpPure *_var = rz_il_op_new_var(src);
	return rz_il_op_new_set(dst, _var);
}

static inline RzILOpEffect *avr_il_store_reg(ut64 addr, const char *reg) {
	RzILOpBitVector *_loc = rz_il_op_new_bitv_from_ut64(AVR_ADDR_SIZE, addr);
	RzILOpPure *_var = rz_il_op_new_var(reg);
	return rz_il_op_new_storew(0, _loc, _var);
}

static inline RzILOpEffect *avr_il_set16_from_reg(const char *dst, const char *src, ut16 mask, ut16 sh) {
	RzILOpPure *_dst = rz_il_op_new_var(dst);
	RzILOpBitVector *_mask = rz_il_op_new_bitv_from_ut64(16, mask);
	RzILOpBitVector *_and = rz_il_op_new_log_and(_dst, _mask);
	RzILOpPure *_src = rz_il_op_new_var(src);
	RzILOpBitVector *_extz = rz_il_op_new_unsigned(16, _src);
	if (sh) {
		RzILOpBitVector *_sh = avr_il_new_sh(sh);
		_extz = rz_il_op_new_shiftl(avr_il_false, _extz, _sh);
	}
	RzILOpBitVector *_or = rz_il_op_new_log_or(_extz, _and);
	return rz_il_op_new_set(dst, _or);
}

static inline RzILOpEffect *avr_il_set_sreg_bit_from_reg(const char *src, ut8 bit_val, const char *bit_reg) {
	RzILOpPure *reg = rz_il_op_new_var(src);
	RzILOpBitVector *bit = rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, bit_val);
	RzILOpBitVector *and = rz_il_op_new_log_and(reg, bit);
	return rz_il_op_new_set(bit_reg, and);
}

static inline RzILOpBitVector *avr_il_sreg_bit_as_imm(const char *sreg_bit, ut8 bit) {
	RzILOpPure *_bit = rz_il_op_new_var(sreg_bit);
	RzILOpPure *_true = avr_il_new_imm(bit);
	RzILOpPure *_false = avr_il_new_zero();
	return rz_il_op_new_ite(_bit, _true, _false);
}

static inline RzILOpEffect *avr_il_update_sreg() {
	RzILOpBitVector *_or, *I, *T, *H, *S, *V, *N, *Z, *C;
	I = avr_il_sreg_bit_as_imm(AVR_SREG_I, AVR_SREG_I_BIT);
	T = avr_il_sreg_bit_as_imm(AVR_SREG_T, AVR_SREG_T_BIT);
	H = avr_il_sreg_bit_as_imm(AVR_SREG_H, AVR_SREG_H_BIT);
	S = avr_il_sreg_bit_as_imm(AVR_SREG_S, AVR_SREG_S_BIT);
	V = avr_il_sreg_bit_as_imm(AVR_SREG_V, AVR_SREG_V_BIT);
	N = avr_il_sreg_bit_as_imm(AVR_SREG_N, AVR_SREG_N_BIT);
	Z = avr_il_sreg_bit_as_imm(AVR_SREG_Z, AVR_SREG_Z_BIT);
	C = avr_il_sreg_bit_as_imm(AVR_SREG_C, AVR_SREG_C_BIT);
	_or = rz_il_op_new_log_or(I, T);
	_or = rz_il_op_new_log_or(_or, H);
	_or = rz_il_op_new_log_or(_or, S);
	_or = rz_il_op_new_log_or(_or, V);
	_or = rz_il_op_new_log_or(_or, N);
	_or = rz_il_op_new_log_or(_or, Z);
	_or = rz_il_op_new_log_or(_or, C);
	return rz_il_op_new_set(AVR_SREG, _or);
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
	RzILOpPure *_alu = rz_il_op_new_var(local);
	RzILOpBool *_is_zero = rz_il_op_new_is_zero(_alu);
	if (and_zero) {
		RzILOpBool *Z = rz_il_op_new_var(AVR_SREG_Z);
		_is_zero = rz_il_op_new_bool_and(_is_zero, Z);
	}
	return rz_il_op_new_set(AVR_SREG_Z, _is_zero);
}

static RzILOpEffect *avr_il_check_half_carry_flag(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a carry from bit 3; cleared otherwise

	Rr = rz_il_op_pure_dup(y);
	// and0 = (!Rd3 & Rr3)
	Rd = rz_il_op_pure_dup(x);
	not0 = rz_il_op_new_log_not(Rd); // !Rd
	and0 = rz_il_op_new_log_and(not0, Rr);

	// and1 = (Rr3 & Res3)
	Res = rz_il_op_new_var(local);
	and1 = rz_il_op_new_log_and(y, Res);

	// and2 = (Res3 & !Rd3)
	Res = rz_il_op_new_var(local);
	not0 = rz_il_op_new_log_not(x);
	and2 = rz_il_op_new_log_and(Res, not0);

	// or = (and0 | and1)
	or0 = rz_il_op_new_log_or(and0, and1);

	// or |= and2
	or0 = rz_il_op_new_log_or(or0, and2);

	// extract bit 3 from or
	bit = avr_il_new_imm(1u << 3);
	and0 = rz_il_op_new_log_and(or0, bit);
	and0 = rz_il_op_new_non_zero(and0); // cast to bool
	return rz_il_op_new_set(AVR_SREG_H, and0);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *not1, *Res, *and0, *and1, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// and0 = Rd7 & !Rr7 & !Res7
	Res = rz_il_op_new_var(local);
	Rr = rz_il_op_pure_dup(y);
	not0 = rz_il_op_new_log_not(Rr); // !Rr
	not1 = rz_il_op_new_log_not(Res); // !Res
	Rd = rz_il_op_pure_dup(x);
	and0 = rz_il_op_new_log_and(Rd, not0); // Rd & !Rr
	and0 = rz_il_op_new_log_and(and0, not1); // Rd & !Rr & !Res

	// and1 = !Rd7 & Rr7 & Res7
	Res = rz_il_op_new_var(local);
	not0 = rz_il_op_new_log_not(x); // !Rd
	and1 = rz_il_op_new_log_and(not0, y); // !Rd & Rr
	and1 = rz_il_op_new_log_and(and1, Res); // !Rd & Rr & Res

	// or = and0 | and1
	or0 = rz_il_op_new_log_or(and0, and1);

	// extract bit 7 from or
	bit = avr_il_new_imm(1u << 7);
	and0 = rz_il_op_new_log_and(or0, bit);
	and0 = rz_il_op_new_non_zero(and0); // cast to bool
	return rz_il_op_new_set(AVR_SREG_V, and0);
}

static RzILOpEffect *avr_il_check_two_complement_overflow_flag_wide(const char *local, RzILOpPure *Rdh) {
	RzILOpBool *ovf;
	RzILOpBitVector *bit, *Res;
	// Rdh = X, Res = Rd+1:Rd
	// V: Rdh7 & !Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// extract bit 7 from Rdh
	bit = avr_il_new_imm(1u << 7);
	Rdh = rz_il_op_new_log_and(Rdh, bit);

	// extract bit 15 from Res
	Res = rz_il_op_new_var(local);
	Res = rz_il_op_new_log_not(Res); // !Res
	bit = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, 1u << 15);
	Res = rz_il_op_new_log_and(Res, bit); // !Res15

	// boolean and (not logical)
	Rdh = rz_il_op_new_non_zero(Rdh); // cast to bool
	Res = rz_il_op_new_non_zero(Res); // cast to bool
	ovf = rz_il_op_new_bool_and(Rdh, Res); // Rdh7 & !Res15
	return rz_il_op_new_set(AVR_SREG_V, ovf);
}

static RzILOpEffect *avr_il_check_negative_flag(const char *local) {
	// Res = Rd - Rr
	// N: Res7 is set
	// Set if MSB of the result is set; cleared otherwise.

	// extract bit 7 from Res
	RzILOpPure *Res = rz_il_op_new_var(local);
	RzILOpBitVector *bit = avr_il_new_imm(1u << 7);
	RzILOpBitVector *and = rz_il_op_new_log_and(Res, bit);
	and = rz_il_op_new_non_zero(and); // cast to bool
	return rz_il_op_new_set(AVR_SREG_N, and);
}

static RzILOpEffect *avr_il_check_negative_flag_wide(const char *local) {
	// Res = Rd+1:Rd
	// N: Res15 is set
	// Set if MSB of the result is set; cleared otherwise.

	// extract bit 15 from Res
	RzILOpBitVector *Res = rz_il_op_new_var(local);
	RzILOpBitVector *bit = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, 1u << 15);
	RzILOpBitVector *and = rz_il_op_new_log_and(Res, bit);
	and = rz_il_op_new_non_zero(and); // cast to bool
	return rz_il_op_new_set(AVR_SREG_N, and);
}

static RzILOpEffect *avr_il_check_carry_flag(const char *local, RzILOpPure *x, RzILOpPure *y) {
	RzILOpBitVector *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if there was a carry from bit 7; cleared otherwise

	Rr = rz_il_op_pure_dup(y);
	// and0 = (!Rd7 & Rr7)
	Rd = rz_il_op_pure_dup(x);
	not0 = rz_il_op_new_log_not(Rd); // !Rd
	and0 = rz_il_op_new_log_and(not0, Rr);

	// and1 = (Rr7 & Res7)
	Res = rz_il_op_new_var(local);
	and1 = rz_il_op_new_log_and(y, Res);

	// and2 = (Res7 & !Rd7)
	Res = rz_il_op_new_var(local);
	not0 = rz_il_op_new_log_not(x);
	and2 = rz_il_op_new_log_and(Res, not0);

	// or = (and0 | and1)
	or0 = rz_il_op_new_log_or(and0, and1);

	// or |= and2
	or0 = rz_il_op_new_log_or(or0, and2);

	// extract bit 7 from or
	bit = avr_il_new_imm(1u << 7);
	and0 = rz_il_op_new_log_and(or0, bit);
	and0 = rz_il_op_new_non_zero(and0); // cast to bool
	return rz_il_op_new_set(AVR_SREG_C, and0);
}

static RzILOpEffect *avr_il_check_carry_flag_wide(const char *local, RzILOpPure *Rdh) {
	RzILOpBitVector *crr, *bit, *Res;
	// Res = Rd+1:Rd
	// Res15 & !Rdh7
	// Set if the absolute value of K is larger than the absolute value of Rd; cleared otherwise

	// extract bit 7 from Rdh
	bit = avr_il_new_imm(1u << 7);
	Rdh = rz_il_op_new_log_and(Rdh, bit);
	Rdh = rz_il_op_new_log_not(Rdh); // !Rdh

	// extract bit 15 from Res
	Res = rz_il_op_new_var(local);
	bit = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, 1u << 15);
	Res = rz_il_op_new_log_and(Res, bit); // Res15

	// boolean and (not logical)
	Res = rz_il_op_new_non_zero(Res); // cast to bool
	Rdh = rz_il_op_new_non_zero(Rdh); // cast to bool
	crr = rz_il_op_new_bool_and(Res, Rdh); // Res15 & Rdh7
	return rz_il_op_new_set(AVR_SREG_C, crr);
}

static RzILOpEffect *avr_il_check_signess_flag() {
	// S: N ^ V, For signed tests.
	RzILOpPure *N = rz_il_op_new_var(AVR_SREG_N);
	RzILOpPure *V = rz_il_op_new_var(AVR_SREG_V);
	RzILOpBool *_xor = rz_il_op_new_bool_xor(N, V);
	return rz_il_op_new_set(AVR_SREG_S, _xor);
}

/* ops */

static RzILOpEffect *avr_il_nop(AVROp *aop, RzAnalysis *analysis) {
	return NULL; // rz_il_op_new_nop();
}

static RzILOpEffect *avr_il_brcc(AVROp *aop, RzAnalysis *analysis) {
	// branch if C = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = rz_il_op_new_var(AVR_SREG_C);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_brcs(AVROp *aop, RzAnalysis *analysis) {
	// branch if C = 1
	ut16 k = aop->param[0];

	RzILOpPure *when = rz_il_op_new_var(AVR_SREG_C);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_breq(AVROp *aop, RzAnalysis *analysis) {
	// branch if Z = 1
	ut16 k = aop->param[0];

	RzILOpPure *when = rz_il_op_new_var(AVR_SREG_Z);
	return avr_il_branch_when(aop, analysis, k, when, true);
}

static RzILOpEffect *avr_il_brne(AVROp *aop, RzAnalysis *analysis) {
	// branch if Z = 0
	ut16 k = aop->param[0];

	RzILOpBool *when = rz_il_op_new_var(AVR_SREG_Z);
	return avr_il_branch_when(aop, analysis, k, when, false);
}

static RzILOpEffect *avr_il_call(AVROp *aop, RzAnalysis *analysis) {
	// PC = k
	ut32 k = aop->param[0];
	k <<= 16;
	k |= aop->param[1];

	RzILOpPure *val, *num;
	RzILOpEffect *jmp, *push, *sub;

	jmp = avr_il_jump_relative(aop, analysis, k);

	num = avr_il_pc(analysis);
	val = rz_il_op_new_var(AVR_SP);
	val = avr_il_to_address(val);
	push = rz_il_op_new_storew(0, val, num);

	num = avr_il_new_imm16(2);
	val = rz_il_op_new_var(AVR_SP);
	val = rz_il_op_new_sub(val, num);
	sub = rz_il_op_new_set(AVR_SP, val);

	return rz_il_op_new_seqn(3, jmp, push, sub);
}

static RzILOpEffect *avr_il_clr(AVROp *aop, RzAnalysis *analysis) {
	// Rd = Rd ^ Rd -> S=0, V=0, N=0, Z=1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpEffect *clr, *S, *V, *N, *Z, *SREG;
	clr = avr_il_assign_imm(avr_registers[Rd], 0);
	S = avr_il_assign_bool(AVR_SREG_S, false);
	V = avr_il_assign_bool(AVR_SREG_V, false);
	N = avr_il_assign_bool(AVR_SREG_N, false);
	Z = avr_il_assign_bool(AVR_SREG_Z, true);
	SREG = avr_il_update_sreg();

	return rz_il_op_new_seqn(6, clr, S, V, N, Z, SREG);
}

static RzILOpEffect *avr_il_cpi(AVROp *aop, RzAnalysis *analysis) {
	// compare Rd with Imm and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y;
	RzILOpEffect *let, *Z, *H, *S, *V, *N, *C, *SREG;
	RzILOpBitVector *sub;

	// result local variable
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	sub = rz_il_op_new_sub(x, y);
	let = rz_il_op_new_let(AVR_LET_RES, sub, true);

	// set Z to 1 if !(x - y)
	Z = avr_il_check_zero_flag(AVR_LET_RES, false);

	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	H = avr_il_check_half_carry_flag(AVR_LET_RES, x, y);

	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	V = avr_il_check_two_complement_overflow_flag(AVR_LET_RES, x, y);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag(AVR_LET_RES);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	C = avr_il_check_carry_flag(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();
	SREG = avr_il_update_sreg();

	return rz_il_op_new_seqn(8, let, Z, H, V, N, C, S, SREG);
}

static RzILOpEffect *avr_il_cpc(AVROp *aop, RzAnalysis *analysis) {
	// compare Rd with Rr with Carry and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOpPure *x, *y, *carry;
	RzILOpEffect *let, *Z, *H, *S, *V, *N, *C, *SREG;
	RzILOpBitVector *sub;

	// result local variable
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	carry = rz_il_op_new_var(AVR_SREG_C);
	carry = rz_il_op_new_ite(carry, avr_il_new_one(), avr_il_new_zero());
	sub = rz_il_op_new_sub(x, y);
	sub = rz_il_op_new_sub(sub, carry);
	let = rz_il_op_new_let(AVR_LET_RES, sub, true);

	// set Z to 1 if !(x - y - C)
	Z = avr_il_check_zero_flag(AVR_LET_RES, true);

	// Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	H = avr_il_check_half_carry_flag(AVR_LET_RES, x, y);

	// Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	V = avr_il_check_two_complement_overflow_flag(AVR_LET_RES, x, y);

	// Res = Rd - Rr - C
	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag(AVR_LET_RES);

	// Res = Rd - Rr - C
	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	C = avr_il_check_carry_flag(AVR_LET_RES, x, y);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();
	SREG = avr_il_update_sreg();

	return rz_il_op_new_seqn(8, let, Z, H, V, N, C, S, SREG);
}

static RzILOpEffect *avr_il_ijmp(AVROp *aop, RzAnalysis *analysis) {
	RzILOpPure *loc, *one;
	// PC = Z << 1
	ut32 pc_size = analysis->rzil->vm->addr_size;
	loc = avr_il_get_indirect_address_z();
	loc = rz_il_op_new_cast(pc_size, avr_il_false, loc);
	one = avr_il_new_sh(1);
	loc = rz_il_op_new_shiftl(avr_il_false, loc, one);
	return rz_il_op_new_jmp(loc);
}

static RzILOpEffect *avr_il_jmp(AVROp *aop, RzAnalysis *analysis) {
	// PC = PC + k + 1
	ut16 k = aop->param[0];

	return avr_il_jump_relative(aop, analysis, k);
}

static RzILOpEffect *avr_il_ldi(AVROp *aop, RzAnalysis *analysis) {
	// Rd = K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_assign_imm(avr_registers[Rd], K);
}

static RzILOpEffect *avr_il_lpm(AVROp *aop, RzAnalysis *analysis) {
	// R0 = *((ut8*)Z) where Z = (r31 << 8) | r30;
	// when Z+, Z is incremented after the execution.
	// LPM r30, Z+ and LPM r31, Z+ have an undefined behaviour per ISA
	// Z is always implied with lpm so we need to check only for post increment

	ut16 Rd = aop->param[0];
	bool post_inc = aop->param[2] == '+';
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOpBitVector *z, *load;
	RzILOpEffect *lpm, *let, *zpp;

	z = avr_il_get_indirect_address_z();
	z = avr_il_to_address(z);
	load = rz_il_op_new_loadw(0, z, AVR_REG_SIZE);
	lpm = rz_il_op_new_set(avr_registers[Rd], load);

	if (!post_inc) {
		return lpm;
	}
	z = avr_il_get_indirect_address_z();
	let = rz_il_op_new_let(AVR_LET_IND, z, true);
	zpp = avr_il_update_indirect_address_z(AVR_LET_IND, 1, true); // Z++
	return rz_il_op_new_seqn(3, lpm, let, zpp);
}

static RzILOpEffect *avr_il_lsl(AVROp *aop, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *lsl, *H, *S, *V, *N, *Z, *C, *SREG;
	// Rd <<= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// simplified by adding itself
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rd);
	x = rz_il_op_new_add(x, y);
	lsl = rz_il_op_new_set(avr_registers[Rd], x);

	// H: Rd3
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 3);
	x = rz_il_op_new_log_and(x, y);
	x = rz_il_op_new_non_zero(x); // cast to bool
	H = rz_il_op_new_set(AVR_SREG_H, x);

	// C: Rd7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	x = rz_il_op_new_log_and(x, y);
	x = rz_il_op_new_non_zero(x); // cast to bool
	C = rz_il_op_new_set(AVR_SREG_C, x);

	// perform shift since we need the result for the SREG flags.
	// N: Res7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	x = rz_il_op_new_log_and(x, y);
	x = rz_il_op_new_non_zero(x); // cast to bool
	N = rz_il_op_new_set(AVR_SREG_N, x);

	// Z: !Res
	x = avr_il_new_reg(Rd);
	x = rz_il_op_new_is_zero(x);
	Z = rz_il_op_new_set(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = rz_il_op_new_var(AVR_SREG_N);
	y = rz_il_op_new_var(AVR_SREG_C);
	x = rz_il_op_new_bool_xor(x, y);
	V = rz_il_op_new_set(AVR_SREG_V, x);

	// update SREG based on flags
	SREG = avr_il_update_sreg();

	return rz_il_op_new_seqn(8, H, C, lsl, N, Z, S, V, SREG);
}

static RzILOpEffect *avr_il_mov(AVROp *aop, RzAnalysis *analysis) {
	// Rd = Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	return avr_il_assign_reg(avr_registers[Rd], avr_registers[Rr]);
}

static RzILOpEffect *avr_il_movw(AVROp *aop, RzAnalysis *analysis) {
	RzILOpPure *x;

	RzILOpEffect *let, *movw;
	// Rd+1:Rd = Rr+1:Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	x = avr_il_get_indirect_address_reg(Rr + 1, Rr);
	let = rz_il_op_new_let(AVR_LET_IND, x, true);

	movw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rd + 1, Rd, 0, false);
	return rz_il_op_new_seqn(2, let, movw);
}

static RzILOpEffect *avr_il_out(AVROp *aop, RzAnalysis *analysis) {
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
	} else if (!strcmp(AVR_SPL, reg)) {
		// zeros low 8 bits and OR new value
		return avr_il_set16_from_reg("SP", avr_registers[Rr], 0xFF00, 0);
	} else if (!strcmp(AVR_SPH, reg)) {
		// zeros high 8 bits and OR new value
		return avr_il_set16_from_reg("SP", avr_registers[Rr], 0x00FF, 8);
	} else if (!strcmp(AVR_SREG, reg)) {
		RzILOpEffect *I = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_I_BIT, AVR_SREG_I);
		RzILOpEffect *T = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_T_BIT, AVR_SREG_T);
		RzILOpEffect *H = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_H_BIT, AVR_SREG_H);
		RzILOpEffect *S = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_S_BIT, AVR_SREG_S);
		RzILOpEffect *V = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_V_BIT, AVR_SREG_V);
		RzILOpEffect *N = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_N_BIT, AVR_SREG_N);
		RzILOpEffect *Z = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_Z_BIT, AVR_SREG_Z);
		RzILOpEffect *C = avr_il_set_sreg_bit_from_reg(avr_registers[Rr], AVR_SREG_C_BIT, AVR_SREG_C);
		RzILOpEffect *SREG = avr_il_assign_reg(reg, avr_registers[Rr]);
		return rz_il_op_new_seqn(9, I, T, H, S, V, N, Z, C, SREG);
	}
	// assign the register value.
	return avr_il_assign_reg(reg, avr_registers[Rr]);
}

static RzILOpEffect *avr_il_rol(AVROp *aop, RzAnalysis *analysis) {
	RzILOpPure *x, *y;
	RzILOpEffect *SREG, *rol, *H, *S, *V, *N, *Z, *C;
	// Rd = rot_left(Rd, 1)
	ut16 Rd = aop->param[0];

	// simplified by adding itself with Carry
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rd);
	x = rz_il_op_new_add(x, y);
	y = avr_il_sreg_bit_as_imm(AVR_SREG_C, 1);
	x = rz_il_op_new_add(x, y);
	rol = rz_il_op_new_set(avr_registers[Rd], x);

	// H: Rd3
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 3);
	x = rz_il_op_new_log_and(x, y);
	x = rz_il_op_new_non_zero(x); // cast to bool
	H = rz_il_op_new_set(AVR_SREG_H, x);

	// C: Rd7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	x = rz_il_op_new_log_and(x, y);
	x = rz_il_op_new_non_zero(x); // cast to bool
	C = rz_il_op_new_set(AVR_SREG_C, x);

	// perform rotation since we need the result for the SREG flags.
	// N: Res7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	x = rz_il_op_new_log_and(x, y);
	x = rz_il_op_new_non_zero(x); // cast to bool
	N = rz_il_op_new_set(AVR_SREG_N, x);

	// Z: !Res
	x = avr_il_new_reg(Rd);
	x = rz_il_op_new_is_zero(x);
	Z = rz_il_op_new_set(AVR_SREG_Z, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = rz_il_op_new_var(AVR_SREG_N);
	y = rz_il_op_new_var(AVR_SREG_C);
	x = rz_il_op_new_bool_xor(x, y);
	V = rz_il_op_new_set(AVR_SREG_V, x);

	// update SREG based on flags
	SREG = avr_il_update_sreg();

	return rz_il_op_new_seqn(8, H, C, rol, N, Z, S, V, SREG);
}

static RzILOpEffect *avr_il_sbiw(AVROp *aop, RzAnalysis *analysis) {
	RzILOpPure *x, *imm;
	RzILOpEffect *let, *sbiw, *Z, *S, *V, *N, *C, *SREG;
	// Rd+1:Rd = Rd+1:Rd - K
	// Rd can be only 24,26,28,30
	ut16 Rdh = aop->param[0];
	ut16 Rdl = aop->param[1];
	ut16 K = aop->param[2];
	avr_return_val_if_invalid_gpr(Rdh, NULL);
	avr_return_val_if_invalid_gpr(Rdl, NULL);

	// IND = Rd+1:Rd - K
	imm = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, K);
	x = avr_il_get_indirect_address_reg(Rdh, Rdl);
	x = rz_il_op_new_sub(x, imm);
	let = rz_il_op_new_let(AVR_LET_IND, x, true);

	// Rd+1:Rd = IND
	sbiw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rdh, Rdl, 0, false);

	// set Z to 1 if !IND
	Z = avr_il_check_zero_flag(AVR_LET_IND, false);

	// Res = IND
	// V: Rdh7 & !Res15
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = avr_il_new_reg(Rdh);
	V = avr_il_check_two_complement_overflow_flag_wide(AVR_LET_IND, x);

	// Res = IND
	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	N = avr_il_check_negative_flag_wide(AVR_LET_IND);

	// Res = IND
	// C: !Rdh7 & Res15
	x = avr_il_new_reg(Rdh);
	C = avr_il_check_carry_flag_wide(AVR_LET_IND, x);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// Update SREG with the new flags
	SREG = avr_il_update_sreg();
	return rz_il_op_new_seqn(8, let, sbiw, Z, V, N, C, S, SREG);
}

static RzILOpEffect *avr_il_ser(AVROp *aop, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	return avr_il_assign_imm(avr_registers[Rd], 0xFF);
}

static RzILOpEffect *avr_il_st(AVROp *aop, RzAnalysis *analysis) {
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
		addr = avr_il_get_indirect_address_x();
		break;
	case 'Y':
		addr = avr_il_get_indirect_address_y();
		break;
	default: // 'Z'
		addr = avr_il_get_indirect_address_z();
		break;
	}

	addr = avr_il_to_address(addr);
	src = avr_il_new_reg(Rd);
	st = rz_il_op_new_storew(0, addr, src);

	if (Op != '+' && Op != '-') {
		return st;
	}

	switch (Rr) {
	case 'X':
		addr = avr_il_get_indirect_address_x();
		post_op = avr_il_update_indirect_address_x(AVR_LET_IND, q, Op == '+');
		break;
	case 'Y':
		addr = avr_il_get_indirect_address_y();
		post_op = avr_il_update_indirect_address_y(AVR_LET_IND, q, Op == '+');
		break;
	default: // 'Z'
		addr = avr_il_get_indirect_address_z();
		post_op = avr_il_update_indirect_address_z(AVR_LET_IND, q, Op == '+');
		break;
	}

	let = rz_il_op_new_let(AVR_LET_IND, addr, true);
	return rz_il_op_new_seqn(3, st, let, post_op);
}

typedef RzILOpEffect *(*avr_rzil_op)(AVROp *aop, RzAnalysis *analysis);

static avr_rzil_op avr_ops[AVR_OP_SIZE] = {
	avr_il_nop, /* AVR_OP_INVALID */
	avr_il_nop, /* AVR_OP_ADC */
	avr_il_nop, /* AVR_OP_ADD */
	avr_il_nop, /* AVR_OP_ADIW */
	avr_il_nop, /* AVR_OP_AND */
	avr_il_nop, /* AVR_OP_ANDI */
	avr_il_nop, /* AVR_OP_ASR */
	avr_il_nop, /* AVR_OP_BLD */
	avr_il_brcc,
	avr_il_brcs,
	avr_il_nop, /* AVR_OP_BREAK */
	avr_il_breq,
	avr_il_nop, /* AVR_OP_BRGE */
	avr_il_nop, /* AVR_OP_BRHC */
	avr_il_nop, /* AVR_OP_BRHS */
	avr_il_nop, /* AVR_OP_BRID */
	avr_il_nop, /* AVR_OP_BRIE */
	avr_il_nop, /* AVR_OP_BRLO */
	avr_il_nop, /* AVR_OP_BRLT */
	avr_il_nop, /* AVR_OP_BRMI */
	avr_il_brne,
	avr_il_nop, /* AVR_OP_BRPL */
	avr_il_nop, /* AVR_OP_BRSH */
	avr_il_nop, /* AVR_OP_BRTC */
	avr_il_nop, /* AVR_OP_BRTS */
	avr_il_nop, /* AVR_OP_BRVC */
	avr_il_nop, /* AVR_OP_BRVS */
	avr_il_nop, /* AVR_OP_BST */
	avr_il_call,
	avr_il_nop, /* AVR_OP_CBI */
	avr_il_nop, /* AVR_OP_CLC */
	avr_il_nop, /* AVR_OP_CLH */
	avr_il_nop, /* AVR_OP_CLI */
	avr_il_nop, /* AVR_OP_CLN */
	avr_il_clr,
	avr_il_nop, /* AVR_OP_CLS */
	avr_il_nop, /* AVR_OP_CLT */
	avr_il_nop, /* AVR_OP_CLV */
	avr_il_nop, /* AVR_OP_CLZ */
	avr_il_nop, /* AVR_OP_COM */
	avr_il_nop, /* AVR_OP_CP */
	avr_il_cpc,
	avr_il_cpi,
	avr_il_nop, /* AVR_OP_CPSE */
	avr_il_nop, /* AVR_OP_DEC */
	avr_il_nop, /* AVR_OP_DES */
	avr_il_nop, /* AVR_OP_EICALL */
	avr_il_nop, /* AVR_OP_EIJMP */
	avr_il_nop, /* AVR_OP_ELPM */
	avr_il_nop, /* AVR_OP_EOR */
	avr_il_nop, /* AVR_OP_FMUL */
	avr_il_nop, /* AVR_OP_FMULS */
	avr_il_nop, /* AVR_OP_FMULSU */
	avr_il_nop, /* AVR_OP_ICALL */
	avr_il_ijmp,
	avr_il_nop, /* AVR_OP_IN */
	avr_il_nop, /* AVR_OP_INC */
	avr_il_jmp, /* AVR_OP_JMP - same as rjmp */
	avr_il_nop, /* AVR_OP_LAC */
	avr_il_nop, /* AVR_OP_LAS */
	avr_il_nop, /* AVR_OP_LAT */
	avr_il_nop, /* AVR_OP_LD */
	avr_il_nop, /* AVR_OP_LDD */
	avr_il_ldi,
	avr_il_nop, /* AVR_OP_LDS */
	avr_il_lpm,
	avr_il_lsl,
	avr_il_nop, /* AVR_OP_LSR */
	avr_il_mov,
	avr_il_movw,
	avr_il_nop, /* AVR_OP_MUL */
	avr_il_nop, /* AVR_OP_MULS */
	avr_il_nop, /* AVR_OP_MULSU */
	avr_il_nop, /* AVR_OP_NEG */
	avr_il_nop, /* AVR_OP_NOP */
	avr_il_nop, /* AVR_OP_OR */
	avr_il_nop, /* AVR_OP_ORI */
	avr_il_out,
	avr_il_nop, /* AVR_OP_POP */
	avr_il_nop, /* AVR_OP_PUSH */
	avr_il_nop, /* AVR_OP_RCALL */
	avr_il_nop, /* AVR_OP_RET */
	avr_il_nop, /* AVR_OP_RETI */
	avr_il_jmp, /* AVR_OP_RJMP - same as jmp */
	avr_il_rol,
	avr_il_nop, /* AVR_OP_ROR */
	avr_il_nop, /* AVR_OP_SBC */
	avr_il_nop, /* AVR_OP_SBCI */
	avr_il_nop, /* AVR_OP_SBI */
	avr_il_nop, /* AVR_OP_SBIC */
	avr_il_nop, /* AVR_OP_SBIS */
	avr_il_sbiw,
	avr_il_nop, /* AVR_OP_SBRC */
	avr_il_nop, /* AVR_OP_SBRS */
	avr_il_nop, /* AVR_OP_SEC */
	avr_il_nop, /* AVR_OP_SEH */
	avr_il_nop, /* AVR_OP_SEI */
	avr_il_nop, /* AVR_OP_SEN */
	avr_il_ser,
	avr_il_nop, /* AVR_OP_SES */
	avr_il_nop, /* AVR_OP_SET */
	avr_il_nop, /* AVR_OP_SEV */
	avr_il_nop, /* AVR_OP_SEZ */
	avr_il_nop, /* AVR_OP_SLEEP */
	avr_il_nop, /* AVR_OP_SPM */
	avr_il_st,
	avr_il_nop, /* AVR_OP_STD */
	avr_il_nop, /* AVR_OP_STS */
	avr_il_nop, /* AVR_OP_SUB */
	avr_il_nop, /* AVR_OP_SUBI */
	avr_il_nop, /* AVR_OP_SWAP */
	avr_il_nop, /* AVR_OP_TST */
	avr_il_nop, /* AVR_OP_WDR */
	avr_il_nop, /* AVR_OP_XCH */
};

RZ_IPI bool avr_rzil_opcode(RzAnalysis *analysis, RzAnalysisOp *op, ut64 pc, AVROp *aop) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	op->rzil_op = RZ_NEW0(RzAnalysisRzilOp);
	if (!op->rzil_op) {
		RZ_LOG_ERROR("RzIL: AVR: cannot allocate RzAnalysisRzilOp\n");
		return false;
	}

	if (aop->mnemonic >= AVR_OP_SIZE) {
		RZ_LOG_ERROR("RzIL: AVR: out of bounds op\n");
		return false;
	}

	avr_rzil_op create_op = avr_ops[aop->mnemonic];
	op->rzil_op->op = create_op(aop, analysis);

	return true;
}

RZ_IPI bool avr_rzil_fini(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);

	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->vm) {
		rz_il_vm_fini(rzil->vm);
		rzil->vm = NULL;
	}

	rzil->inited = false;
	return true;
}

static bool avr_add_mmio_register(void *user, const ut64 k, const void *v) {
	RzILVM *vm = (RzILVM *)user;
	const char *name = (const char *)v;
	if (!strcmp(name, AVR_SPL) || !strcmp(name, AVR_SPH) || !strcmp(name, AVR_SREG)) {
		return true;
	}
	rz_il_vm_add_reg(vm, name, AVR_MMIO_SIZE);
	return true;
}

RZ_IPI bool avr_rzil_init(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis && analysis->rzil, false);
	RzAnalysisRzil *rzil = analysis->rzil;

	if (rzil->inited) {
		RZ_LOG_ERROR("RzIL: AVR: VM is already configured\n");
		return true;
	}

	RzArchProfile *profile = analysis->arch_target ? analysis->arch_target->profile : NULL;

	if (!rz_il_vm_init(rzil->vm, 0, AVR_ADDR_SIZE, analysis->big_endian)) {
		RZ_LOG_ERROR("RzIL: AVR: failed to initialize VM\n");
		return false;
	}

	// SREG = I|T|H|S|V|N|Z|C
	// bits   7|6|5|4|3|2|1|0
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_I, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_T, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_H, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_S, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_V, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_N, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_Z, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_C, false);
	rz_il_vm_add_reg(rzil->vm, AVR_SREG, AVR_REG_SIZE);

	ht_up_foreach(profile->registers_mmio, avr_add_mmio_register, rzil->vm);
	rz_il_vm_add_reg(rzil->vm, AVR_SP, AVR_SP_SIZE);

	char reg[8] = { 0 };

	for (ut32 i = 0; i < 32; ++i) {
		rz_strf(reg, "R%d", i);
		rz_il_vm_add_reg(rzil->vm, reg, AVR_REG_SIZE);
	}

	RzBuffer *buf = rz_buf_new_sparse_overlay(rzil->io_buf, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!buf) {
		rz_il_vm_fini(rzil->vm);
		return false;
	}
	RzILMem *mem = rz_il_mem_new(buf, AVR_ADDR_SIZE);
	if (!mem) {
		rz_buf_free(buf);
		rz_il_vm_fini(rzil->vm);
		return false;
	}
	rz_il_vm_add_mem(rzil->vm, 0, mem);

	rzil->inited = true;
	return true;
}
