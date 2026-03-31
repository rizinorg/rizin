// SPDX-FileCopyrightText: 2024 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <msp430/msp430_disas.h>
#include <rz_il/rz_il_opbuilder_begin.h>

RZ_OWN RzILOpBitVector *update_sr_clear_vcnz(RZ_OWN RzILOpBitVector *old_sr_value) {
	// the general idea is
	//		1- Zero out the N,Z,C,V bits in the old SR value
	// 		   By ANDing with a mask of all 1s everywhere and 0s in those flags' positions
	// 		2- Code can later set those flags by ORing the resulting sr value with a mask
	// 		   having 1s in the relevant positions and all 0s everywhere else
	int cnz_zero_mask = 0xFFF8;
	int vcnz_zero_mask = cnz_zero_mask & (~(1 << 8));
	return LOGAND(old_sr_value, U16(vcnz_zero_mask));
}

RZ_OWN RzILOpBitVector *update_sr_z_flag(RZ_OWN RzILOpBool *new_value, RZ_OWN RzILOpBitVector *old_sr_value) {
	return LOGOR(old_sr_value, SHIFTL0(BOOL_TO_BV(new_value, 16), U8(1)));
}

RZ_OWN RzILOpBitVector *update_sr_n_flag(RZ_OWN RzILOpBool *new_value, RZ_OWN RzILOpBitVector *old_sr_value) {
	return LOGOR(old_sr_value, SHIFTL0(BOOL_TO_BV(new_value, 16), U8(2)));
}

RZ_OWN RzILOpBitVector *update_sr_nz_flags(RZ_OWN RzILOpBitVector *new_value, RZ_OWN RzILOpBitVector *old_sr_value) {
	RzILOpBool *n_flag_value = MSB(new_value);
	RzILOpBool *z_flag_value = IS_ZERO(DUP(new_value));

	return update_sr_n_flag(n_flag_value, update_sr_z_flag(z_flag_value, old_sr_value));
}

RZ_OWN RzILOpBitVector *update_sr_v_flag(RZ_OWN RzILOpBool *new_overflow, RZ_OWN RzILOpBitVector *old_sr_value) {
	return LOGOR(old_sr_value, SHIFTL0(BOOL_TO_BV(new_overflow, 16), U8(8)));
}

RZ_OWN RzILOpBitVector *update_sr_v_flag_rcc(RZ_OWN RzILOpBitVector *old_value, RZ_OWN RzILOpBool *old_carry, RZ_OWN RzILOpBitVector *old_sr_value) {
	// the idea is the same as update_sr_nz_flags: we AND with a mask that zeroes out the bit we care about
	// then we OR with a mask that have the bit we care about in the same position that we zeroed
	RzILOpBool *v_flag_value = AND(
		INV(MSB(old_value)),
		old_carry);

	return update_sr_v_flag(v_flag_value, old_sr_value);
}

RZ_OWN RzILOpBitVector *update_sr_c_flag(RzILOpBool *new_carry, RZ_OWN RzILOpBitVector *old_sr_value) {
	return LOGOR(old_sr_value, BOOL_TO_BV(new_carry, 16));
}

RZ_OWN RzILOpBitVector *update_sr_c_flag_add(RZ_OWN RzILOpBitVector *op1, RZ_OWN RzILOpBitVector *op2,
	RZ_OWN RzILOpBitVector *result, RZ_OWN RzILOpBitVector *old_sr_value) {
	// Review any truth table for a 3-input full adder, and observe that the carry out is 1 if and only if
	//			1- Both of the inputs are 1
	//			2- One of the inputs is 1 while the result is 0
	// In this context, the "inputs" are the most significant bits of the full 16-bit operands
	RzILOpBool *op1_msb = MSB(op1);
	RzILOpBool *op2_msb = MSB(op2);

	RzILOpBool *is_carry1 = AND(op1_msb, op2_msb);
	RzILOpBool *not_result_msb = INV(MSB(result));

	RzILOpBool *is_carry2 = AND(not_result_msb, DUP(op1_msb));
	RzILOpBool *is_carry3 = AND(DUP(op2_msb), DUP(not_result_msb));

	RzILOpBool *is_carry = OR(OR(is_carry1, is_carry2), is_carry3);
	return update_sr_c_flag(is_carry, old_sr_value);
}

RZ_OWN RzILOpBitVector *update_sr_v_flag_add(RZ_OWN RzILOpBitVector *op1, RZ_OWN RzILOpBitVector *op2,
	RZ_OWN RzILOpBitVector *result, RZ_OWN RzILOpBitVector *old_sr_value) {
	// Overflow happens if and only if:
	//			Positive + Positive = Negative
	//			Negative + Negative = Positive
	RzILOpBool *op1_sign = MSB(op1);
	RzILOpBool *op2_sign = MSB(op2);

	// XNOR is the binary equality operator
	RzILOpBool *op1_op2_have_same_sign = INV(XOR(op1_sign, op2_sign));

	RzILOpBool *result_sign = MSB(result);
	RzILOpBool *result_has_different_sign = XOR(result_sign, DUP(op1_sign));

	RzILOpBool *is_overflow = AND(op1_op2_have_same_sign, result_has_different_sign);
	return update_sr_v_flag(is_overflow, old_sr_value);
}

RZ_OWN RzILOpEffect *set_rcc_flags(const char *operand_name, const char *result_name, const char *old_carry_name, const char *old_sr_name) {
	// n z as usual
	RzILOpBitVector *nz = update_sr_nz_flags(VARL(result_name), update_sr_clear_vcnz(VARL(old_sr_name)));
	// v especially for RCC
	RzILOpBitVector *vnz = update_sr_v_flag_rcc(VARL(operand_name), VARL(old_carry_name), nz);
	// and c from the discarded LSB
	RzILOpBitVector *cvnz = update_sr_c_flag(LSB(VARL(operand_name)), vnz);

	return MSP430_SETR(MSP430_SR, cvnz);
}

RZ_OWN RzILOpEffect *set_sxt_flags(const char *result_name) {
	// n z as usual
	RzILOpBitVector *nz = update_sr_nz_flags(VARL(result_name), update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)));
	// c as not if result is zero
	RzILOpBitVector *cnz = update_sr_c_flag(INV(IS_ZERO(VARL(result_name))), nz);

	// v as zero
	// no need to actually do this, v is already cleared from update_sr_clear_vcnz

	return MSP430_SETR(MSP430_SR, cnz);
}

RZ_OWN RzILOpEffect *set_and_flags(const char *result_name) {
	return set_sxt_flags(result_name);
}

RZ_OWN RzILOpEffect *set_xor_flags(const char *source_name, const char *destination_name, const char *result_name) {
	// n z as usual
	RzILOpBitVector *nz = update_sr_nz_flags(VARL(result_name), update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)));
	// c as not if result is zero
	RzILOpBitVector *cnz = update_sr_c_flag(INV(IS_ZERO(VARL(result_name))), nz);
	// v as if both operands are negative
	RzILOpBitVector *vcnz = update_sr_v_flag(AND(MSB(VARL(source_name)), MSB(VARL(destination_name))), cnz);

	return MSP430_SETR(MSP430_SR, vcnz);
}

RZ_OWN RzILOpEffect *set_add_flags(const char *source_name, const char *destination_name, const char *result_name) {
	// n z as usual
	RzILOpBitVector *nz = update_sr_nz_flags(VARL(result_name), update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)));
	// c especially for the add
	RzILOpBitVector *cnz = update_sr_c_flag_add(VARL(source_name), VARL(destination_name), VARL(result_name), nz);
	// v especially for the add
	RzILOpBitVector *vcnz = update_sr_v_flag_add(VARL(source_name), VARL(destination_name), VARL(result_name), cnz);

	return MSP430_SETR(MSP430_SR, vcnz);
}

RZ_OWN RzILOpEffect *do_set_inc_flags(const char *result_name, const char *old_destination_name,
	RZ_OWN RzILOpBitVector *zero_carry_const, RZ_OWN RzILOpBitVector *overflow_const) {
	// n as usual
	RzILOpBool *is_negative = MSB(VARL(result_name));
	RzILOpBitVector *n = update_sr_n_flag(is_negative, update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)));

	// z c v by comparison to known constants
	RzILOpBool *is_zero_and_carry = EQ(VARL(old_destination_name), zero_carry_const);
	RzILOpBool *is_overflow = EQ(VARL(old_destination_name), overflow_const);

	RzILOpBitVector *nzc = LOGOR(ITE(is_zero_and_carry, U16(0x0003), U16(0)), n);
	RzILOpBitVector *vnzc = update_sr_v_flag(is_overflow, nzc);

	return MSP430_SETR(MSP430_SR, vnzc);
}

RZ_OWN RzILOpEffect *set_incb_flags(const char *result_name, const char *old_destination_name) {
	return do_set_inc_flags(result_name, old_destination_name, U8(0xFF), U8(0x7F));
}

RZ_OWN RzILOpEffect *set_inc_flags(const char *result_name, const char *old_destination_name) {
	return do_set_inc_flags(result_name, old_destination_name, U16(0xFFFF), U16(0x7FFF));
}

RZ_OWN RzILOpEffect *do_set_dec_flags(const char *result_name, const char *old_destination_name,
	RZ_OWN RzILOpBitVector *zero_const, RZ_OWN RzILOpBitVector *carry_const, RZ_OWN RzILOpBitVector *overflow_const) {
	// n as usual
	RzILOpBool *is_negative = MSB(VARL(result_name));
	RzILOpBitVector *n = LOGOR(
		SHIFTL0(BOOL_TO_BV(is_negative, 16), U8(2)),
		update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)));

	// z c v by comparison to known constants
	RzILOpBool *is_zero = EQ(VARL(old_destination_name), zero_const);
	RzILOpBool *is_carry = INV(EQ(VARL(old_destination_name), carry_const));
	RzILOpBool *is_overflow = EQ(VARL(old_destination_name), overflow_const);

	RzILOpBitVector *nzc = update_sr_z_flag(is_zero, update_sr_c_flag(is_carry, n));
	RzILOpBitVector *vnzc = update_sr_v_flag(is_overflow, nzc);

	return MSP430_SETR(MSP430_SR, vnzc);
}

RZ_OWN RzILOpEffect *set_decb_flags(const char *result_name, const char *old_destination_name) {
	return do_set_dec_flags(result_name, old_destination_name, U8(1), U8(0), U8(0x80));
}

RZ_OWN RzILOpEffect *set_dec_flags(const char *result_name, const char *old_destination_name) {
	return do_set_dec_flags(result_name, old_destination_name, U16(1), U16(0), U16(0x8000));
}

RZ_OWN RzILOpEffect *set_tst_flags(RZ_OWN RzILOpBitVector *operand) {
	// no need to do anything to v, it's already cleared
	RzILOpBitVector *cv = LOGOR(update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)), U16(1)); // set c flag efficiently (no branching with ite, like bool2bv does)

	RzILOpBitVector *nzcv = update_sr_nz_flags(VARL("operand"), cv);

	return SEQ2(SETL("operand", operand), MSP430_SETR(MSP430_SR, nzcv));
}

RZ_OWN RzILOpEffect *set_inv_flags(const char *result_name, const char *old_destination_name) {
	RzILOpBool *is_negative = MSB(VARL(result_name));
	RzILOpBool *is_zero = IS_ZERO(VARL(result_name));
	RzILOpBool *is_carry = INV(IS_ZERO(VARL(result_name)));
	RzILOpBool *is_overflow = MSB(VARL(old_destination_name));

	return MSP430_SETR(MSP430_SR,
		update_sr_n_flag(is_negative,
			update_sr_z_flag(is_zero,
				update_sr_c_flag(is_carry,
					update_sr_v_flag(is_overflow, update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)))))));
}

RZ_OWN RzILOpEffect *set_sub_flags(const char *source_name, const char *neginc_source_name, const char *dst_name, const char *result_name,
	RZ_OWN RzILOpBitVector *carry_const, RZ_OWN RzILOpBitVector *overflow_const) {
	// n z as usual
	RzILOpBitVector *nz = update_sr_nz_flags(VARL(result_name), update_sr_clear_vcnz(MSP430_GETR(MSP430_SR)));
	// c especially for the sub
	RzILOpBitVector *_cnz = update_sr_c_flag_add(VARL(neginc_source_name), VARL(dst_name), VARL(result_name), nz);
	RzILOpBitVector *cnz = update_sr_c_flag(EQ(VARL(source_name), carry_const), _cnz);
	// v especially for the sub
	RzILOpBitVector *_vcnz = update_sr_v_flag_add(VARL(neginc_source_name), VARL(dst_name), VARL(result_name), cnz);
	RzILOpBitVector *vcnz = update_sr_v_flag(EQ(VARL(source_name), overflow_const), _vcnz);

	return MSP430_SETR(MSP430_SR, vcnz);
}

RzILOpEffect *set_setc_flags() {
	return MSP430_SETR(MSP430_SR, LOGOR(MSP430_GETR(MSP430_SR), U16(1)));
}
RzILOpEffect *set_setn_flags() {
	return MSP430_SETR(MSP430_SR, LOGOR(MSP430_GETR(MSP430_SR), U16(1 << 2)));
}

RzILOpEffect *set_setz_flags() {
	return MSP430_SETR(MSP430_SR, LOGOR(MSP430_GETR(MSP430_SR), U16(1 << 1)));
}

RzILOpEffect *set_clrc_flags() {
	return MSP430_SETR(MSP430_SR, LOGAND(MSP430_GETR(MSP430_SR), U16(~1)));
	;
}

RzILOpEffect *set_clrn_flags() {
	return MSP430_SETR(MSP430_SR, LOGAND(MSP430_GETR(MSP430_SR), U16(~(1 << 2))));
}

RzILOpEffect *set_clrz_flags() {
	return MSP430_SETR(MSP430_SR, LOGAND(MSP430_GETR(MSP430_SR), U16(~(1 << 1))));
}

RzILOpBool *check_if_zero_carry() {
	return IS_ZERO(LOGAND(MSP430_GETR(MSP430_SP), U16(1)));
}

#include <rz_il/rz_il_opbuilder_end.h>
