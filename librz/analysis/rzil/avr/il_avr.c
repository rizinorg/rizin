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

#define avr_il_get_indirect_address_x() avr_il_get_indirect_address_reg(27, 26)
#define avr_il_get_indirect_address_y() avr_il_get_indirect_address_reg(29, 28)
#define avr_il_get_indirect_address_z() avr_il_get_indirect_address_reg(31, 30)
#define avr_il_inc_indirect_address_x() avr_il_inc_indirect_address_reg(27, 26)
#define avr_il_inc_indirect_address_y() avr_il_inc_indirect_address_reg(29, 28)
#define avr_il_inc_indirect_address_z() avr_il_inc_indirect_address_reg(31, 30)

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

static RzILOp *avr_il_inc_indirect_address_reg(ut16 reg_high, ut16 reg_low) {
	RzILOp *iar, *one, *let;
	const char *high = avr_registers[reg_high]; // rH
	const char *low = avr_registers[reg_low]; // rL

	iar = avr_il_get_indirect_address_reg(reg_high, reg_low);
	one = rz_il_op_new_bitv_from_ut64(AVR_IND_SIZE, 1);
	iar = rz_il_op_new_add(iar, one);
	let = rz_il_op_new_let(high, low, iar);
	return rz_il_op_new_perform(let);
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

static RzILOp *avr_il_check_zero_flag(RzILOp *x, RzILOp *y, bool add_carry) {
	// set Z to 1 if !(x - y) or !(x - y - C)
	RzILOp *_sub = rz_il_op_new_sub(x, y);
	if (add_carry) {
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		_sub = rz_il_op_new_sub(_sub, C);
	}
	RzILOp *_inv = rz_il_op_new_bool_inv(_sub);
	if (add_carry) {
		RzILOp *Z = avr_il_sreg_as_imm(AVR_SREG_Z);
		_inv = rz_il_op_new_bool_and(_inv, Z);
	}
	RzILOp *_set = rz_il_op_new_set(AVR_SREG_Z, _inv);
	return rz_il_op_new_perform(_set);
}

static RzILOp *avr_il_check_half_carry_flag(RzILOp *x, RzILOp *y, bool add_carry) {
	RzILOp *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a carry from bit 3; cleared otherwise

	Rd = avr_il_dup_value(x);
	Rr = avr_il_dup_value(y);
	// and0 = (!Rd3 & Rr3)
	not0 = rz_il_op_new_log_not(Rd);
	and0 = rz_il_op_new_log_and(not0, Rr);

	Rd = avr_il_dup_value(x);
	Rr = avr_il_dup_value(y);
	// and1 = (Rr3 & Res3)
	Res = rz_il_op_new_sub(Rd, Rr);
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}
	Rr = avr_il_dup_value(y);
	and1 = rz_il_op_new_log_and(Rr, Res);

	// and2 = (Res3 & !Rd3)
	Rd = avr_il_dup_value(x);
	Res = rz_il_op_new_sub(x, y);
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}
	not0 = rz_il_op_new_log_not(Rd);
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

static RzILOp *avr_il_check_two_complement_overflow_flag(RzILOp *x, RzILOp *y, bool add_carry) {
	RzILOp *Rd, *Rr, *bit, *not0, *not1, *Res, *and0, *and1, *and, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr or Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.

	Rd = avr_il_dup_value(x);
	Rr = avr_il_dup_value(y);
	// and0 = Rd7 & !Rr7 & !Res7
	Res = rz_il_op_new_sub(Rd, Rr); // Res = Rd - Rr
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}
	Rr = avr_il_dup_value(y);
	not0 = rz_il_op_new_log_not(Rr); // !Rr
	not1 = rz_il_op_new_log_not(Res); // !Res
	Rd = avr_il_dup_value(x);
	and = rz_il_op_new_log_and(Rd, not0); // Rd & !Rr
	and0 = rz_il_op_new_log_and(and, not1); // Rd & !Rr & !Res

	Rd = avr_il_dup_value(x);
	Rr = avr_il_dup_value(y);
	// and1 = Rd7 & !Rr7 & !Res7
	Res = rz_il_op_new_sub(Rd, Rr); // Res = Rd - Rr
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}
	not0 = rz_il_op_new_log_not(y); // !Rr
	not1 = rz_il_op_new_log_not(Res); // !Res
	and = rz_il_op_new_log_and(x, not0); // Rd & !Rr
	and1 = rz_il_op_new_log_and(and, not1); // Rd & !Rr & !Res

	// or = and0 | and1
	or0 = rz_il_op_new_log_or(and0, and1);

	// extract bit 7 from or
	bit = avr_il_new_imm(1u << 7);
	and = rz_il_op_new_log_and(or0, bit);
	RzILOp *set = rz_il_op_new_set(AVR_SREG_V, and);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_negative_flag(RzILOp *x, RzILOp *y, bool add_carry) {
	// Res = Rd - Rr
	// N: Res7 is set
	// Set if MSB of the result is set; cleared otherwise.
	RzILOp *Res = rz_il_op_new_sub(x, y);
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}

	// extract bit 7 from Res
	RzILOp *bit = avr_il_new_imm(1u << 7);
	RzILOp *and = rz_il_op_new_log_and(Res, bit);
	RzILOp *set = rz_il_op_new_set(AVR_SREG_N, and);
	return rz_il_op_new_perform(set);
}

static RzILOp *avr_il_check_carry_flag(RzILOp *x, RzILOp *y, bool add_carry) {
	RzILOp *Rd, *Rr, *bit, *not0, *Res, *and0, *and1, *and2, *or0;
	// Rd = X, Rr = Y, Res = Rd - Rr
	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise

	Rd = avr_il_dup_value(x);
	Rr = avr_il_dup_value(y);
	// and0 = (!Rd7 & Rr7)
	not0 = rz_il_op_new_log_not(Rd);
	and0 = rz_il_op_new_log_and(not0, Rr);

	Rd = avr_il_dup_value(x);
	Rr = avr_il_dup_value(y);
	// and1 = (Rr7 & Res7)
	Res = rz_il_op_new_sub(Rd, Rr);
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}
	Rr = avr_il_dup_value(y);
	and1 = rz_il_op_new_log_and(Rr, Res);

	// and2 = (Res7 & !Rd7)
	Rd = avr_il_dup_value(x);
	Res = rz_il_op_new_sub(x, y);
	if (add_carry) {
		// Res = Rd - Rr - C
		RzILOp *C = avr_il_sreg_as_imm(AVR_SREG_C);
		Res = rz_il_op_new_sub(Res, C);
	}
	not0 = rz_il_op_new_log_not(Rd);
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

static RzILOp *avr_il_check_signess_flag() {
	// S: N ^ V, For signed tests.
	RzILOp *N = rz_il_op_new_var(AVR_SREG_N);
	RzILOp *V = rz_il_op_new_var(AVR_SREG_V);
	RzILOp * xor = rz_il_op_new_bool_xor(N, V);
	RzILOp *set = rz_il_op_new_set(AVR_SREG_S, xor);
	return rz_il_op_new_perform(set);
}

static RzPVector *avr_il_cpi(AVROp *aop, RzAnalysis *analysis) {
	// compare Rd with Imm and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 K = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOp *x, *y, *Z, *H, *S, *V, *N, *C;

	// set Z to 1 if !(x - y)
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	Z = avr_il_check_zero_flag(x, y, false);

	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	H = avr_il_check_half_carry_flag(x, y, false);

	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	V = avr_il_check_two_complement_overflow_flag(x, y, false);

	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	N = avr_il_check_negative_flag(x, y, false);

	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_imm(K);
	C = avr_il_check_carry_flag(x, y, false);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return rz_il_make_oplist(6, Z, H, V, N, C, S);
}

static RzPVector *avr_il_cpc(AVROp *aop, RzAnalysis *analysis) {
	// compare Rd with Rr with Carry and sets the SREG flags
	// changes H|S|V|N|Z|C
	ut16 Rd = aop->param[0];
	ut16 Rr = aop->param[1];
	avr_return_val_if_invalid_gpr(Rd, NULL);
	RzILOp *x, *y, *Z, *H, *S, *V, *N, *C;

	// set Z to 1 if !(x - y - C)
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	Z = avr_il_check_zero_flag(x, y, true);

	// Res = Rd - Rr - C
	// H: (!Rd3 & Rr3) | (Rr3 & Res3) | (Res3 & !Rd3)
	// Set if there was a borrow from bit 3; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	H = avr_il_check_half_carry_flag(x, y, true);

	// Res = Rd - Rr - C
	// V: (Rd7 & !Rr7 & !Res7) | (!Rd7 & Rr7 & Res7)
	// Set if two’s complement overflow resulted from the operation; cleared otherwise.
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	V = avr_il_check_two_complement_overflow_flag(x, y, true);

	// Res = Rd - Rr - C
	// N: Res7
	// Set if MSB of the result is set; cleared otherwise.
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	N = avr_il_check_negative_flag(x, y, true);

	// Res = Rd - Rr - C
	// C: (!Rd7 & Rr7) | (Rr7 & Res7) | (Res7 & !Rd7)
	// Set if the absolute value of Rr is larger than the absolute value of Rd; cleared otherwise
	x = avr_il_new_reg(Rd);
	y = avr_il_new_reg(Rr);
	C = avr_il_check_carry_flag(x, y, true);

	// S: N ^ V, For signed tests.
	S = avr_il_check_signess_flag();

	return rz_il_make_oplist(6, Z, H, V, N, C, S);
}

static RzPVector *avr_il_jmp(AVROp *aop, RzAnalysis *analysis) {
	// PC = PC + k + 1
	ut16 k = aop->param[0];

	ut32 pc_size = analysis->rzil->vm->addr_size;
	RzILOp *loc = rz_il_op_new_bitv_from_ut64(pc_size, k - aop->size);
	RzILOp *jmp = rz_il_op_new_jmp(loc);

	RzILOp *perform = rz_il_op_new_perform(jmp);
	return rz_il_make_oplist(1, perform);
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
	RzILOp *zplus = avr_il_inc_indirect_address_z();
	return rz_il_make_oplist(2, lpm, zplus);
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

static RzPVector *avr_il_ser(AVROp *aop, RzAnalysis *analysis) {
	// Rd = $FF
	ut16 Rd = aop->param[0];
	avr_return_val_if_invalid_gpr(Rd, NULL);

	RzILOp *ser = NULL;
	avr_il_assign_imm(ser, avr_registers[Rd], 0xFF);
	return rz_il_make_oplist(1, ser);
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
	avr_il_nop, /* AVR_OP_CALL */
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
	avr_il_nop, /* AVR_OP_IJMP */
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
	avr_il_nop, /* AVR_OP_LSL */
	avr_il_nop, /* AVR_OP_LSR */
	avr_il_nop, /* AVR_OP_MOV */
	avr_il_nop, /* AVR_OP_MOVW */
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
	avr_il_nop, /* AVR_OP_ROL */
	avr_il_nop, /* AVR_OP_ROR */
	avr_il_nop, /* AVR_OP_SBC */
	avr_il_nop, /* AVR_OP_SBCI */
	avr_il_nop, /* AVR_OP_SBI */
	avr_il_nop, /* AVR_OP_SBIC */
	avr_il_nop, /* AVR_OP_SBIS */
	avr_il_nop, /* AVR_OP_SBIW */
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
	avr_il_nop, /* AVR_OP_ST */
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
