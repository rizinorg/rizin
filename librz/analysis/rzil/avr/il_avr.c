// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "il_avr.h"

#define AVR_REG_SIZE  8
#define AVR_SREG_SIZE 8
#define AVR_MMIO_SIZE 8
#define AVR_SP_SIZE   16
#define AVR_IND_SIZE  16
#define AVR_SREG      "SREG"
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
// bits   0|1|2|3|4|5|6|7
#define AVR_SREG_I_BIT ((ut8)(1u << 0))
#define AVR_SREG_I     "I"
#define AVR_SREG_T_BIT ((ut8)(1u << 1))
#define AVR_SREG_T     "T"
#define AVR_SREG_H_BIT ((ut8)(1u << 2))
#define AVR_SREG_H     "H"
#define AVR_SREG_S_BIT ((ut8)(1u << 3))
#define AVR_SREG_S     "S"
#define AVR_SREG_V_BIT ((ut8)(1u << 4))
#define AVR_SREG_V     "V"
#define AVR_SREG_N_BIT ((ut8)(1u << 5))
#define AVR_SREG_N     "N"
#define AVR_SREG_Z_BIT ((ut8)(1u << 6))
#define AVR_SREG_Z     "Z"
#define AVR_SREG_C_BIT ((ut8)(1u << 7))
#define AVR_SREG_C     "C"

#define AVR_RAMPD_ADDR 0x38
#define AVR_RAMPX_ADDR 0x39
#define AVR_RAMPY_ADDR 0x3a
#define AVR_RAMPZ_ADDR 0x3b
#define AVR_EIND_ADDR  0x3c
#define AVR_SPL_ADDR   0x3d
#define AVR_SPH_ADDR   0x3e
#define AVR_SREG_ADDR  0x3f

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

#define avr_il_new_imm(imm) rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, (imm))
#define avr_il_new_reg(reg) rz_il_op_new_var(avr_registers[reg])

#define avr_il_cast_reg(name, dst, len, sh, src) \
	do { \
		RzILOp *_var = rz_il_op_new_var((src)); \
		RzILOp *_cast = rz_il_op_new_cast((len), (sh), _var); \
		RzILOp *_set = rz_il_op_new_set((dst), _cast); \
		(name) = rz_il_op_new_perform(_set); \
	} while (0)

#define avr_il_branch_when(name, addr, when) \
	do { \
		ut32 _pc_size = analysis->rzil->vm->addr_size; \
		RzILOp *_bv = rz_il_op_new_bitv_from_ut64(_pc_size, (addr)); \
		RzILOp *_jmp = rz_il_op_new_jmp(_bv); \
		RzILOp *_branch = rz_il_op_new_branch((when), _jmp, NULL); \
		(name) = rz_il_op_new_perform(_branch); \
	} while (0)

#define avr_il_assign_reg(name, dst, src) \
	do { \
		RzILOp *_var = rz_il_op_new_var((src)); \
		RzILOp *_set = rz_il_op_new_set((dst), _var); \
		(name) = rz_il_op_new_perform(_set); \
	} while (0)

#define avr_il_assign_not_reg(name, dst, src) \
	do { \
		RzILOp *_var = rz_il_op_new_var((src)); \
		RzILOp *_not = rz_il_op_new_log_not(_var); \
		RzILOp *_set = rz_il_op_new_set((dst), _var); \
		(name) = rz_il_op_new_perform(_set); \
	} while (0)

#define avr_il_assign_imm(name, reg, imm) \
	do { \
		RzILOp *_bv = rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, (imm)); \
		RzILOp *_set = rz_il_op_new_set((reg), _bv); \
		(name) = rz_il_op_new_perform(_set); \
	} while (0)

#define avr_il_assign_bool(name, reg, b) \
	do { \
		RzILOp *_bv = rz_il_op_new_bitv_from_ut64(1, (b)); \
		RzILOp *_set = rz_il_op_new_set((reg), _bv); \
		(name) = rz_il_op_new_perform(_set); \
	} while (0)

#define avr_il_store_reg(name, addr, reg) \
	do { \
		RzILOp *_bv = rz_il_op_new_bitv_from_ut64(32, addr); \
		RzILOp *_var = rz_il_op_new_var((reg)); \
		(name) = rz_il_op_new_store(0, _bv, _var); \
	} while (0)

#define avr_il_set16_from_reg(name, dst, and_mask, sh, src) \
	do { \
		RzILOp *_dst = rz_il_op_new_var((dst)); \
		RzILOp *_bv_and = rz_il_op_new_bitv_from_ut64(16, and_mask); \
		RzILOp *_and = rz_il_op_new_log_and(_dst, _bv_and); \
		RzILOp *_src = rz_il_op_new_var((src)); \
		RzILOp *_cast = rz_il_op_new_cast(16, (sh), _src); \
		RzILOp *_or = rz_il_op_new_log_or(_cast, _and); \
		RzILOp *_set = rz_il_op_new_set((dst), _or); \
		(name) = rz_il_op_new_perform(_set); \
	} while (0)

#define avr_il_hook(name, hook) \
	do { \
		RzILOp *_hook = rz_il_op_new_goto((hook)); \
		(name) = rz_il_op_new_perform(_hook); \
	} while (0)

#define avr_il_get_indirect_address_x()             avr_il_get_indirect_address_reg(27, 26)
#define avr_il_get_indirect_address_y()             avr_il_get_indirect_address_reg(29, 28)
#define avr_il_get_indirect_address_z()             avr_il_get_indirect_address_reg(31, 30)
#define avr_il_update_indirect_address_x(l, n, add) avr_il_update_indirect_address_reg(l, 27, 26, n, add)
#define avr_il_update_indirect_address_y(l, n, add) avr_il_update_indirect_address_reg(l, 29, 28, n, add)
#define avr_il_update_indirect_address_z(l, n, add) avr_il_update_indirect_address_reg(l, 31, 30, n, add)

typedef RzPVector *(*avr_rzil_op)(AVROp *aop, RzAnalysis *analysis);

const char *avr_registers[32] = {
	"R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9",
	"R10", "R11", "R12", "R13", "R14", "R15", "R16", "R17", "R18",
	"R19", "R20", "R21", "R22", "R23", "R24", "R25", "R26", "R27",
	"R28", "R29", "R30", "R31"
};

static RzILOp *avr_il_get_indirect_address_reg(ut16 reg_high, ut16 reg_low) {
	RzILOp *high = avr_il_new_reg(reg_high); // rH
	RzILOp *low = avr_il_new_reg(reg_low); // rL
	return rz_il_op_new_append(high, low); // addr
}

static RzILOp *avr_il_update_indirect_address_reg(const char *local, ut16 reg_high, ut16 reg_low, ut64 n, bool add) {
	RzILOp *iar, *num, *seq, *set_h, *set_l;
	const char *Rh = avr_registers[reg_high]; // register high
	const char *Rl = avr_registers[reg_low]; // register low

	iar = rz_il_op_new_var(local);
	if (n > 0) {
		num = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, n);
		if (add) {
			iar = rz_il_op_new_add(iar, num);
		} else {
			iar = rz_il_op_new_sub(iar, num);
		}
	}
	set_h = rz_il_op_new_cast(AVR_REG_SIZE, -8, iar);
	set_h = rz_il_op_new_set(Rh, set_h);

	iar = rz_il_op_new_var(local);
	if (n > 0) {
		num = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, n);
		if (add) {
			iar = rz_il_op_new_add(iar, num);
		} else {
			iar = rz_il_op_new_sub(iar, num);
		}
	}
	set_l = rz_il_op_new_cast(AVR_REG_SIZE, 0, iar);
	set_l = rz_il_op_new_set(Rl, set_l);

	seq = rz_il_op_new_seq(set_h, set_l);
	return rz_il_op_new_perform(seq);
}

static RzILOp *avr_il_dup_value(RzILOp *op) {
	RzBitVector *bv = NULL;
	switch (op->code) {
	case RZIL_OP_VAR:
		return rz_il_op_new_var(op->op.var->v);
	case RZIL_OP_BITV:
		bv = rz_bv_dup(op->op.bitv->value);
		return bv ? rz_il_op_new_bitv(bv) : NULL;
	default:
		return NULL;
	}
}

static RzILOp *avr_il_sreg_as_imm(const char *sreg_bit) {
	RzILOp *bit = rz_il_op_new_var(sreg_bit);
	return rz_il_op_new_cast(AVR_REG_SIZE, 0, bit);
}

static RzILOp *avr_il_check_zero_flag(const char *local, bool and_zero) {
	// set Z to 1 if !(x - y) or !(x - y - C)
	RzILOp *_alu = rz_il_op_new_var(local);
	RzILOp *_inv = rz_il_op_new_bool_inv(_alu);
	if (and_zero) {
		RzILOp *Z = avr_il_sreg_as_imm(AVR_SREG_Z);
		_inv = rz_il_op_new_bool_and(_inv, Z);
	}
	RzILOp *_set = rz_il_op_new_set(AVR_SREG_Z, _inv);
	return rz_il_op_new_perform(_set);
}

static RzILOp *avr_il_check_half_carry_flag(const char *local, RzILOp *x, RzILOp *y) {
	RzILOp *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a carry from bit 3; cleared otherwise

	Rr = avr_il_dup_value(y);
	// and0 = (!Rd3 & Rr3)
	Rd = avr_il_dup_value(x);
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
	RzILOp *set = rz_il_op_new_set(AVR_SREG_H, and0);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_two_complement_overflow_flag(const char *local, RzILOp *x, RzILOp *y) {
	RzILOp *Rd, *Rr, *bit, *not0, *not1, *Res, *and0, *and1, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	// and0 = Rd7 & !Rr7 & !Res7
	Res = rz_il_op_new_var(local);
	Rr = avr_il_dup_value(y);
	not0 = rz_il_op_new_log_not(Rr); // !Rr
	not1 = rz_il_op_new_log_not(Res); // !Res
	Rd = avr_il_dup_value(x);
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
	RzILOp *set = rz_il_op_new_set(AVR_SREG_V, and0);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_two_complement_overflow_flag_wide(const char *local, RzILOp *Rdh) {
	RzILOp *ovf, *bit, *Res;
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
	ovf = rz_il_op_new_bool_and(Rdh, Res); // Rdh7 & !Res15
	ovf = rz_il_op_new_set(AVR_SREG_V, ovf);
	return rz_il_op_new_perform(ovf);
}

static RzILOp *avr_il_check_negative_flag(const char *local) {
	// Res = Rd - Rr
	// N: Res7 is set
	// Set if MSB of the result is set; cleared otherwise.

	// extract bit 7 from Res
	RzILOp *Res = rz_il_op_new_var(local);
	RzILOp *bit = avr_il_new_imm(1u << 7);
	RzILOp *and = rz_il_op_new_log_and(Res, bit);
	RzILOp *set = rz_il_op_new_set(AVR_SREG_N, and);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_negative_flag_wide(const char *local) {
	// Res = Rd+1:Rd
	// N: Res15 is set
	// Set if MSB of the result is set; cleared otherwise.

	// extract bit 15 from Res
	RzILOp *Res = rz_il_op_new_var(local);
	RzILOp *bit = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, 1u << 15);
	RzILOp *and = rz_il_op_new_log_and(Res, bit);
	RzILOp *set = rz_il_op_new_set(AVR_SREG_N, and);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_carry_flag(const char *local, RzILOp *x, RzILOp *y) {
	RzILOp *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if there was a carry from bit 7; cleared otherwise

	Rr = avr_il_dup_value(y);
	// and0 = (!Rd7 & Rr7)
	Rd = avr_il_dup_value(x);
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
	RzILOp *set = rz_il_op_new_set(AVR_SREG_C, and0);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_carry_flag_wide(const char *local, RzILOp *Rdh) {
	RzILOp *crr, *bit, *Res;
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
	crr = rz_il_op_new_bool_and(Res, Rdh); // Res15 & Rdh7
	crr = rz_il_op_new_set(AVR_SREG_C, crr);
	return rz_il_op_new_perform(crr);
}

static RzILOp *avr_il_check_signess_flag() {
	// S: N ^ V, For signed tests.
	RzILOp *N = rz_il_op_new_var(AVR_SREG_N);
	RzILOp *V = rz_il_op_new_var(AVR_SREG_V);
	RzILOp *_xor = rz_il_op_new_bool_xor(N, V);
	RzILOp *set = rz_il_op_new_set(AVR_SREG_S, _xor);
	return rz_il_op_new_perform(set);
}

static inline RzILOp *avr_il_set_sreg_bit_from_reg(ut16 Rr, ut8 bit_val, const char *bit_reg) {
	RzILOp *reg = rz_il_op_new_var(avr_registers[Rr]);
	RzILOp *bit = rz_il_op_new_bitv_from_ut64(AVR_REG_SIZE, bit_val);
	RzILOp *and = rz_il_op_new_log_and(reg, bit);
	RzILOp *set = rz_il_op_new_set(bit_reg, and);
	return rz_il_op_new_perform(set);
}

static const char *resolve_mmio(RzAnalysis *analysis, ut16 address) {
	RzArchProfile *profile = analysis->arch_target ? analysis->arch_target->profile : NULL;
	if (!profile) {
		return NULL;
	}
	return rz_arch_profile_resolve_mmio(profile, address);
}

static RzPVector *avr_il_nop(AVROp *aop, RzAnalysis *analysis) {
	return NULL; // rz_il_make_nop_list();
}

static RzPVector *avr_il_brcc(AVROp *aop, RzAnalysis *analysis) {
	// branch if C = 0
	ut16 k = aop->param[0];

	RzILOp *brop = NULL;
	RzILOp *bit = rz_il_op_new_var(AVR_SREG_C);
	RzILOp *inv = rz_il_op_new_bool_inv(bit);

	avr_il_branch_when(brop, k - aop->size, inv);
	return rz_il_make_oplist(1, brop);
}

static RzPVector *avr_il_brcs(AVROp *aop, RzAnalysis *analysis) {
	// branch if C = 1
	ut16 k = aop->param[0];

	RzILOp *brop = NULL;
	RzILOp *bit = rz_il_op_new_var(AVR_SREG_C);

	avr_il_branch_when(brop, k - aop->size, bit);
	return rz_il_make_oplist(1, brop);
}

static RzPVector *avr_il_breq(AVROp *aop, RzAnalysis *analysis) {
	// branch if Z = 1
	ut16 k = aop->param[0];

	RzILOp *brop = NULL;
	RzILOp *bit = rz_il_op_new_var(AVR_SREG_Z);

	avr_il_branch_when(brop, k - aop->size, bit);
	return rz_il_make_oplist(1, brop);
}

static RzPVector *avr_il_brne(AVROp *aop, RzAnalysis *analysis) {
	// branch if Z = 0
	ut16 k = aop->param[0];

	RzILOp *brop = NULL;
	RzILOp *bit = rz_il_op_new_var(AVR_SREG_Z);
	RzILOp *inv = rz_il_op_new_bool_inv(bit);

	avr_il_branch_when(brop, k - aop->size, inv);
	return rz_il_make_oplist(1, brop);
}

static RzPVector *avr_il_call(AVROp *aop, RzAnalysis *analysis) {
	// PC = k
	ut16 k = aop->param[0];

	ut32 pc_size = analysis->rzil->vm->addr_size;
	RzILOp *loc = rz_il_op_new_bitv_from_ut64(pc_size, k - aop->size);
	RzILOp *jmp = rz_il_op_new_jmp(loc);
	RzILOp *perform = rz_il_op_new_perform(jmp);
	return rz_il_make_oplist(1, perform);
}

static RzPVector *avr_il_clr(AVROp *aop, RzAnalysis *analysis) {
	// Rd = Rd ^ Rd -> S=0, V=0, N=0, Z=1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *clr = NULL;
	RzILOp *sreg_s = NULL;
	RzILOp *sreg_v = NULL;
	RzILOp *sreg_n = NULL;
	RzILOp *sreg_z = NULL;
	avr_il_assign_imm(clr, avr_registers[Rd], 0);
	avr_il_assign_bool(sreg_s, AVR_SREG_S, 0);
	avr_il_assign_bool(sreg_v, AVR_SREG_V, 0);
	avr_il_assign_bool(sreg_n, AVR_SREG_N, 0);
	avr_il_assign_bool(sreg_z, AVR_SREG_Z, 1);

	return rz_il_make_oplist(5, clr, sreg_s, sreg_v, sreg_n, sreg_z);
}

static RzPVector *avr_il_cpi(AVROp *aop, RzAnalysis *analysis) {
	// compare Rd with Imm and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOp *x, *y, *let, *Z, *H, *S, *V, *N, *C;

	// result local variable
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	let = rz_il_op_new_sub(x, y);
	let = rz_il_op_new_let(AVR_LET_RES, let, false);
	let = rz_il_op_new_perform(let);

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

	return rz_il_make_oplist(7, let, Z, H, V, N, C, S);
}

static RzPVector *avr_il_cpc(AVROp *aop, RzAnalysis *analysis) {
	// compare Rd with Rr with Carry and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOp *x, *y, *let, *Z, *H, *S, *V, *N, *C;

	// result local variable
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	C = avr_il_sreg_as_imm(AVR_SREG_C);
	let = rz_il_op_new_sub(x, y);
	let = rz_il_op_new_sub(let, C);
	let = rz_il_op_new_let(AVR_LET_RES, let, false);
	let = rz_il_op_new_perform(let);

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

	return rz_il_make_oplist(7, let, Z, H, V, N, C, S);
}

static RzPVector *avr_il_ijmp(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *addr, *ijmp;
	// PC = Z << 1
	ut32 pc_size = analysis->rzil->vm->addr_size;
	addr = avr_il_get_indirect_address_z();
	addr = rz_il_op_new_cast(pc_size, 1, addr);
	ijmp = rz_il_op_new_jmp(addr);
	ijmp = rz_il_op_new_perform(ijmp);
	return rz_il_make_oplist(1, ijmp);
}

static RzPVector *avr_il_jmp(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *loc, *jmp;
	// PC = PC + k + 1
	ut16 k = aop->param[0];

	ut32 pc_size = analysis->rzil->vm->addr_size;
	loc = rz_il_op_new_bitv_from_ut64(pc_size, k - aop->size);
	jmp = rz_il_op_new_jmp(loc);
	jmp = rz_il_op_new_perform(jmp);
	return rz_il_make_oplist(1, jmp);
}

static RzPVector *avr_il_ldi(AVROp *aop, RzAnalysis *analysis) {
	// Rd = K
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ldi = NULL;
	avr_il_assign_imm(ldi, avr_registers[Rd], K);
	return rz_il_make_oplist(1, ldi);
}

static RzPVector *avr_il_lpm(AVROp *aop, RzAnalysis *analysis) {
	// R0 = *((ut8*)Z) where Z = (r31 << 8) | r30;
	// when Z+, Z is incremented after the execution.
	// LPM r30, Z+ and LPM r31, Z+ have an undefined behaviour per ISA
	// Z is always implied with lpm so we need to check only for post increment

	ut16 Rd = aop->param[0];
	bool post_inc = aop->param[2] == '+';
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *z = avr_il_get_indirect_address_z();
	RzILOp *load = rz_il_op_new_load(0, z);
	RzILOp *set = rz_il_op_new_set(avr_registers[Rd], load);
	RzILOp *lpm = rz_il_op_new_perform(set);

	if (!post_inc) {
		return rz_il_make_oplist(1, lpm);
	}
	z = avr_il_get_indirect_address_z();
	RzILOp *let = rz_il_op_new_let(AVR_LET_IND, z, false);
	let = rz_il_op_new_perform(let);
	RzILOp *zpp = avr_il_update_indirect_address_z(AVR_LET_IND, 1, true); // Z++
	return rz_il_make_oplist(3, lpm, let, zpp);
}

static RzPVector *avr_il_lsl(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *x, *y, *lsl, *H, *S, *V, *N, *Z, *C;
	// Rd <<= 1
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	// simplified by adding itself
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rd);
	lsl = rz_il_op_new_add(x, y);
	lsl = rz_il_op_new_set(avr_registers[Rd], lsl);
	lsl = rz_il_op_new_perform(lsl);

	// H: Rd3
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 3);
	H = rz_il_op_new_log_and(x, y);
	H = rz_il_op_new_set(AVR_SREG_H, H);
	H = rz_il_op_new_perform(H);

	// C: Rd7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	C = rz_il_op_new_log_and(x, y);
	C = rz_il_op_new_set(AVR_SREG_C, C);
	C = rz_il_op_new_perform(C);

	// perform shift since we need the result for the SREG flags.
	// N: Res7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	N = rz_il_op_new_log_and(x, y);
	N = rz_il_op_new_set(AVR_SREG_N, N);
	N = rz_il_op_new_perform(N);

	// Z: !Res
	x = avr_il_new_reg(Rd);
	Z = rz_il_op_new_bool_inv(x);
	Z = rz_il_op_new_set(AVR_SREG_Z, Z);
	Z = rz_il_op_new_perform(Z);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = rz_il_op_new_var(AVR_SREG_N);
	y = rz_il_op_new_var(AVR_SREG_C);
	V = rz_il_op_new_bool_xor(x, y);
	V = rz_il_op_new_set(AVR_SREG_V, V);
	V = rz_il_op_new_perform(V);

	return rz_il_make_oplist(7, H, C, lsl, N, Z, S, V);
}

static RzPVector *avr_il_mov(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *mov;
	// Rd = Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	avr_il_assign_reg(mov, avr_registers[Rd], avr_registers[Rr]);
	return rz_il_make_oplist(1, mov);
}

static RzPVector *avr_il_movw(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *let, *movw;
	// Rd+1:Rd = Rr+1:Rr
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];

	let = avr_il_get_indirect_address_reg(Rr + 1, Rr);
	let = rz_il_op_new_let(AVR_LET_IND, let, false);
	let = rz_il_op_new_perform(let);

	movw = avr_il_update_indirect_address_reg(AVR_LET_IND, Rd + 1, Rd, 0, false);
	return rz_il_make_oplist(2, let, movw);
}

static RzPVector *avr_il_out(AVROp *aop, RzAnalysis *analysis) {
	// I/O(A) = Rr -> None
	ut16 A = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rr, NULL);

	RzILOp *out = NULL;
	const char *reg = resolve_mmio(analysis, A);
	if (!reg && A < 32) {
		// profiles that does not map registers between 0 and 31 have MMIO regs at this range
		avr_il_assign_reg(out, avr_registers[A], avr_registers[Rr]);
	} else if (!reg) {
		// memory write
		avr_il_store_reg(out, A, avr_registers[Rr]);
	} else if (!strcmp(AVR_SPL, reg)) {
		// zeros low 8 bits and OR new value
		avr_il_set16_from_reg(out, "SP", 0xFF00, 0, avr_registers[Rr]);
	} else if (!strcmp(AVR_SPH, reg)) {
		// zeros high 8 bits and OR new value
		avr_il_set16_from_reg(out, "SP", 0x00FF, 8, avr_registers[Rr]);
	} else if (!strcmp(AVR_SREG, reg)) {
		RzILOp *I = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_I_BIT, AVR_SREG_I);
		RzILOp *T = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_T_BIT, AVR_SREG_T);
		RzILOp *H = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_H_BIT, AVR_SREG_H);
		RzILOp *S = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_S_BIT, AVR_SREG_S);
		RzILOp *V = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_V_BIT, AVR_SREG_V);
		RzILOp *N = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_N_BIT, AVR_SREG_N);
		RzILOp *Z = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_Z_BIT, AVR_SREG_Z);
		RzILOp *C = avr_il_set_sreg_bit_from_reg(Rr, AVR_SREG_C_BIT, AVR_SREG_C);
		return rz_il_make_oplist(8, I, T, H, S, V, N, Z, C);
	} else {
		// any other MMIO registers
		avr_il_assign_reg(out, reg, avr_registers[Rr]);
	}
	return rz_il_make_oplist(1, out);
}

static RzPVector *avr_il_rjmp(AVROp *aop, RzAnalysis *analysis) {
	// PC = PC + k + 1
	ut16 k = aop->param[0];

	ut32 pc_size = analysis->rzil->vm->addr_size;
	RzILOp *loc = rz_il_op_new_bitv_from_ut64(pc_size, k - aop->size);
	RzILOp *rjmp = rz_il_op_new_jmp(loc);

	RzILOp *perform = rz_il_op_new_perform(rjmp);
	return rz_il_make_oplist(1, perform);
}

static RzPVector *avr_il_rol(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *x, *y, *rol, *H, *S, *V, *N, *Z, *C;
	// Rd = rot_left(Rd, 1)
	ut16 Rd = aop->param[0];

	// simplified by adding itself with Carry
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rd);
	rol = rz_il_op_new_add(x, y);
	y = avr_il_sreg_as_imm(AVR_SREG_C);
	rol = rz_il_op_new_add(rol, y);
	rol = rz_il_op_new_set(avr_registers[Rd], rol);
	rol = rz_il_op_new_perform(rol);

	// H: Rd3
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 3);
	H = rz_il_op_new_log_and(x, y);
	H = rz_il_op_new_set(AVR_SREG_H, H);
	H = rz_il_op_new_perform(H);

	// C: Rd7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	C = rz_il_op_new_log_and(x, y);
	C = rz_il_op_new_set(AVR_SREG_C, C);
	C = rz_il_op_new_perform(C);

	// perform rotation since we need the result for the SREG flags.
	// N: Res7
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(1u << 7);
	N = rz_il_op_new_log_and(x, y);
	N = rz_il_op_new_set(AVR_SREG_N, N);
	N = rz_il_op_new_perform(N);

	// Z: !Res
	x = avr_il_new_reg(Rd);
	Z = rz_il_op_new_bool_inv(x);
	Z = rz_il_op_new_set(AVR_SREG_Z, Z);
	Z = rz_il_op_new_perform(Z);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	// V: N ^ C, For N and C after the shift
	x = rz_il_op_new_var(AVR_SREG_N);
	y = rz_il_op_new_var(AVR_SREG_C);
	V = rz_il_op_new_bool_xor(x, y);
	V = rz_il_op_new_set(AVR_SREG_V, V);
	V = rz_il_op_new_perform(V);

	return rz_il_make_oplist(7, H, C, rol, N, Z, S, V);
}

static RzPVector *avr_il_sbiw(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *x, *let, *sbiw, *imm, *Z, *S, *V, *N, *C;
	// Rd+1:Rd = Rd+1:Rd - K
	// Rd can be only 24,26,28,30
	ut16 Rdh = aop->param[0];
	ut16 Rdl = aop->param[1];
	ut16 K = aop->param[2];
	avr_return_val_if_invalid_gpr(Rdh, NULL);
	avr_return_val_if_invalid_gpr(Rdl, NULL);

	// IND = Rd+1:Rd - K
	imm = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, K);
	let = avr_il_get_indirect_address_reg(Rdh, Rdl);
	let = rz_il_op_new_sub(let, imm);
	let = rz_il_op_new_let(AVR_LET_IND, let, false);
	let = rz_il_op_new_perform(let);

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

	return rz_il_make_oplist(7, let, sbiw, Z, V, N, C, S);
}

static RzPVector *avr_il_ser(AVROp *aop, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ser = NULL;
	avr_il_assign_imm(ser, avr_registers[Rd], 0xFF);
	return rz_il_make_oplist(1, ser);
}

static RzPVector *avr_il_st(AVROp *aop, RzAnalysis *analysis) {
	RzILOp *st, *src, *addr, *post_op, *let;
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

	src = avr_il_new_reg(Rd);
	st = rz_il_op_new_store(0, addr, src);

	if (Op != '+' && Op != '-') {
		return rz_il_make_oplist(1, st);
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

	let = rz_il_op_new_let(AVR_LET_IND, addr, false);
	let = rz_il_op_new_perform(let);
	return rz_il_make_oplist(3, st, let, post_op);
}

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
	avr_il_jmp,
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
	avr_il_rjmp,
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
	avr_il_st, /* AVR_OP_ST */
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
	op->rzil_op->ops = create_op(aop, analysis);

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
	if (!strcmp(name, AVR_SPL) || !strcmp(name, AVR_SPH)) {
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

	ut32 addr_space = 22; // 22 bits address space
	ut64 pc_address = 0;

	if (!rz_il_vm_init(rzil->vm, pc_address, addr_space, addr_space)) {
		RZ_LOG_ERROR("RzIL: AVR: failed to initialize VM\n");
		return false;
	}

	// SREG = I|T|H|S|V|N|Z|C
	// bits   0|1|2|3|4|5|6|7
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_I, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_T, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_H, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_S, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_V, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_N, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_Z, false);
	rz_il_vm_add_bit_reg(rzil->vm, AVR_SREG_C, false);

	ht_up_foreach(profile->registers_mmio, avr_add_mmio_register, rzil->vm);

	rz_il_vm_add_reg(rzil->vm, "SP", AVR_SP_SIZE);

	char reg[8] = { 0 };

	for (ut32 i = 0; i < 32; ++i) {
		rz_strf(reg, "R%d", i);
		rz_il_vm_add_reg(rzil->vm, reg, AVR_REG_SIZE);
	}

	rz_il_vm_add_mem(rzil->vm, 8);

	rzil->inited = true;
	return true;
}
