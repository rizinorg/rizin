// SPDX-FileCopyrightText: 2024 Mostafa Mahmoud <ubermenchun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <msp430/msp430_il.h>

/* \brief TI user guide:
 *	The 16-bit program counter (PC/R0) points to the next instruction to be executed.
 */
#define PC_SIZE 16
/* \brief TI user guide:
 *   The Low byte of a word is always an even address. The high byte is at the next odd address.
 *   For example, if a data word is located at address xxx4h, then the low byte of that data word
 *   is located at address xxx4h, and the high byte of that word is located at address xxx5h.
 */
#define IS_BIG_ENDIAN false
/* \brief implied by the size of the address space for ordinary MSP430, also the width of the PC
 * (MSP430-X has a 1 Mega address space addressed by 20 bits, but that is not supported by the lifter)
 */
#define MEM_ADDR_SIZE 16U

#include <msp430/msp430_register_names.h>
#include <msp430/msp430_il_getset.h>
#include <msp430/msp430_il_flags.h>
#include <msp430/msp430_il_jmp_utils.h>

#include <rz_il/rz_il_opbuilder_begin.h>

#define BRANCH_UNLESS(c, t, f) BRANCH(c, f, t)

// ************************************* One-Operand Lifters ********************************* //
/**
 * \defgroup One_Op_Lifters lifter functions that lift one-operand non-emulated MSP430 instructions
 * @{
 */
RZ_OWN RzILOpEffect *rz_msp430_lift_call_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ3(
		MSP430_SETR(MSP430_SP, SUB(MSP430_GETR(MSP430_SP), U16(2))),
		STOREW(MSP430_GETR(MSP430_SP), ADD(U16(current_addr), U16(instr_size))),
		JMP(get_destination(op, current_addr)));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_rrc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	// rotation is just a shift with filling
	return SEQ6(
		/* 1- get the carry (to use later as the filling for the MSB of the operand) */
		SETL("old_sr", MSP430_GETR(MSP430_SR)),
		SETL("old_carry", LSB(VARL("old_sr"))),
		/* 2- get the operand (whether register, memory location, ...) */
		SETL("operand", get_destination(op, current_addr)),
		/* 3- Perform the actual Rotate Right through Carry operation. Do:
				a- Shift the operand by 1 to the right and fill with carry */
		SETL("result", SHIFTR(VARL("old_carry"), VARL("operand"), U8(1))),
		/* ...      b- Set the operand to the value of the previous computation */
		set_destination(op, VARL("result"), current_addr),
		/* ...      c- Finally set the flags */
		set_rcc_flags("operand", "result", "old_carry", "old_sr"));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_sxt_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ3(
		SETL("result", SIGNED(16, get_destination(op, current_addr))),
		set_destination(op, VARL("result"), current_addr),
		set_sxt_flags("result"));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_swpb_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	// 1- get lower byte and upper byte of the operand
	BVPair low_high = get_destination_destructured(op, current_addr);
	RzILOpBitVector *low_byte = low_high.first;
	RzILOpBitVector *high_byte = low_high.second;

	// 2- append them in reverse order
	RzILOpBitVector *result = APPEND(low_byte, high_byte);

	// 3- set them (flags aren't affected)
	return set_destination(op, result, current_addr);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_push_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ2(
		MSP430_SETR(MSP430_SP, SUB(MSP430_GETR(MSP430_SP), U16(2))),
		(op->is_byte) ? STORE(MSP430_GETR(MSP430_SP), get_destination(op, current_addr)) : STOREW(MSP430_GETR(MSP430_SP), get_destination(op, current_addr))

	);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_pop_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ2(
		(op->is_byte) ? set_destination(op, LOAD(MSP430_GETR(MSP430_SP)), current_addr) : set_destination(op, LOADW(16, MSP430_GETR(MSP430_SP)), current_addr),
		MSP430_SETR(MSP430_SP, ADD(MSP430_GETR(MSP430_SP), U16(2))));
}
/** @} */

// ************************************* Two-Operand Lifters ********************************  //
/* \defgroup Two_Op_Lifters lifter functions that lift two-operand non-emulated MSP430 instructions
 * @{
 */
RZ_OWN RzILOpEffect *rz_msp430_lift_add_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ5(
		SETL("old_destination", get_destination(op, current_addr)),
		SETL("source", get_source(op, current_addr)),
		SETL("result", ADD(VARL("source"), VARL("old_destination"))),

		set_destination(op, VARL("result"), current_addr),
		set_add_flags("source", "old_destination", "result"));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_and_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ5(
		SETL("old_destination", get_destination(op, current_addr)),
		SETL("source", get_source(op, current_addr)),
		SETL("result", LOGAND(VARL("source"), VARL("old_destination"))),

		set_destination(op, VARL("result"), current_addr),
		set_and_flags("result"));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_bit_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ2(
		SETL("result", LOGAND(get_source(op, current_addr), get_destination(op, current_addr))),
		set_and_flags("result"));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_xor_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ5(
		SETL("old_destination", get_destination(op, current_addr)),
		SETL("source", get_source(op, current_addr)),
		SETL("result", LOGXOR(VARL("source"), VARL("old_destination"))),

		set_destination(op, VARL("result"), current_addr),
		set_xor_flags("source", "old_destination", "result"));
}

RZ_OWN RzILOpEffect *rz_msp430_lift_mov_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_destination(op, get_source(op, current_addr), current_addr);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_sub_or_cmp_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, bool write_dst, ut64 current_addr, int instr_size) {
	RzILOpBitVector *increment_by;
	RzILOpBitVector *carry_const;
	RzILOpBitVector *overflow_const;
	if (op->is_byte) {
		increment_by = U8(1);
		carry_const = U8(0);
		overflow_const = U8(~0x7F);
	} else {
		increment_by = U16(1);
		carry_const = U16(0);
		overflow_const = U16(~0x7FFF);
	}

	RzILOpEffect *get_src = SETL("op0", get_source(op, current_addr));
	RzILOpEffect *neg_src_add1 = SETL("op1", ADD(increment_by, LOGNOT(VARL("op0"))));
	RzILOpEffect *get_dst = SETL("op2", get_destination(op, current_addr));
	RzILOpEffect *compute_result = SETL("result", ADD(VARL("op1"), VARL("op2")));
	RzILOpEffect *set_flags = set_sub_flags("op0", "op1", "op2", "result", carry_const, overflow_const);

	return (write_dst) ? SEQ6( // sub
				     get_src,
				     neg_src_add1,
				     get_dst,
				     compute_result,
				     set_destination(op, VARL("result"), current_addr),
				     set_flags)
			   : SEQ5( // cmp
				     get_src,
				     neg_src_add1,
				     get_dst,
				     compute_result,
				     set_flags);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_sub_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return rz_msp430_lift_sub_or_cmp_instr(analysis, op, true, current_addr, instr_size);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_cmp_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return rz_msp430_lift_sub_or_cmp_instr(analysis, op, false, current_addr, instr_size);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_bis_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	RzILOpBitVector *result = LOGOR(get_source(op, current_addr), get_destination(op, current_addr));
	return set_destination(op, result, current_addr);
}

RZ_OWN RzILOpEffect *rz_msp430_lift_bic_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	RzILOpBitVector *result = LOGAND(LOGNOT(get_source(op, current_addr)), get_destination(op, current_addr));
	return set_destination(op, result, current_addr);
}
/* @} */

// ************************************* Emulated Instruction Lifters ******************************** //
/* \defgroup Emulated_Op_Lifters lifter functions that lift emulated MSP430 instructions
 * @{
 */
RzILOpEffect *rz_msp430_lift_ret_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ3(
		SETL("return_address", LOADW(16, MSP430_GETR(MSP430_SP))),
		MSP430_SETR(MSP430_SP, ADD(MSP430_GETR(MSP430_SP), U16(2))),
		JMP(VARL("return_address")));
}

RzILOpEffect *rz_msp430_lift_br_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return JMP(get_source(op, current_addr));
}

RzILOpEffect *rz_msp430_lift_inc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	RzILOpBitVector *increment_by;
	RzILOpEffect *(*flags_setter)(const char *, const char *);
	if (op->is_byte) {
		increment_by = U8(1);
		flags_setter = set_incb_flags;
	} else {
		increment_by = U16(1);
		flags_setter = set_inc_flags;
	}

	return SEQ4(
		SETL("old_destination", get_destination(op, current_addr)),
		SETL("result", ADD(increment_by, VARL("old_destination"))),
		set_destination(op, VARL("result"), current_addr),
		flags_setter("result", "old_destination"));
}

RzILOpEffect *rz_msp430_lift_dec_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	RzILOpBitVector *decrement_by;
	RzILOpEffect *(*flags_setter)(const char *, const char *);
	if (op->is_byte) {
		decrement_by = U8(1);
		flags_setter = set_decb_flags;
	} else {
		decrement_by = U16(1);
		flags_setter = set_dec_flags;
	}

	return SEQ4(
		SETL("old_destination", get_destination(op, current_addr)),
		SETL("result", SUB(decrement_by, VARL("old_destination"))),
		set_destination(op, VARL("result"), current_addr),
		flags_setter("result", "old_destination"));
}

RzILOpEffect *rz_msp430_lift_clr_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_destination(op, (op->is_byte) ? U8(0) : U16(0), current_addr);
}

RzILOpEffect *rz_msp430_lift_tst_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_tst_flags(get_destination(op, current_addr));
}

RzILOpEffect *rz_msp430_lift_setc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_setc_flags();
}
RzILOpEffect *rz_msp430_lift_setn_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_setn_flags();
}

RzILOpEffect *rz_msp430_lift_setz_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_setz_flags();
}

RzILOpEffect *rz_msp430_lift_clrc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_clrc_flags();
}

RzILOpEffect *rz_msp430_lift_clrn_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_clrn_flags();
}

RzILOpEffect *rz_msp430_lift_clrz_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return set_clrz_flags();
}

RzILOpEffect *rz_msp430_lift_nop_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	// so easy xD
	return NOP();
}

RzILOpEffect *rz_msp430_lift_inv_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return SEQ4(
		SETL("old_destination", get_destination(op, current_addr)),
		SETL("result", LOGNOT(VARL("old_destination"))),
		set_destination(op, VARL("result"), current_addr),
		set_inv_flags("result", "old_destination"));
}

RzILOpEffect *rz_msp430_lift_adc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return BRANCH(
		check_if_zero_carry(),
		NOP(),
		rz_msp430_lift_inc_instr(analysis, op, current_addr, instr_size));
}

RzILOpEffect *rz_msp430_lift_sbc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return BRANCH(
		check_if_zero_carry(),
		rz_msp430_lift_dec_instr(analysis, op, current_addr, instr_size),
		NOP());
}

typedef enum digit_position {
	DIGIT_0,
	DIGIT_1,
	DIGIT_2,
	DIGIT_3
} DigitPos;

RzILOpBool *check_if_digit_eq_9(const char *operand_name, DigitPos dp, bool is_byte);
RzILOpBitVector *increment_digit_clear_lesser_digits(const char *operand_name, DigitPos dp, bool is_byte);
RzILOpEffect *continue_rz_msp430_lift_dadc_instr();

RZ_OWN RzILOpEffect *rz_msp430_lift_dadc_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	// Since the msp430 manual says the result is not defined if the operand is not a valid BCD number
	// therefore we're allowed to assume that any digit in the operand is either equal to 9 or less than 9
	// Say the operand's digits are d3 d2 d1 d0, where each digit is between 0 and 9 inclusive
	return BRANCH(
		check_if_zero_carry(),
		NOP(), // nothing to do
		SEQ2(
			SETL("operand", get_destination(op, current_addr)),
			/* see if d0 is 9 */
			BRANCH_UNLESS(check_if_digit_eq_9("operand", DIGIT_0, op->is_byte),
				/* if not, then increment it. Result is d3 d2 d1 (d0 + 1) */
				SETL("result", increment_digit_clear_lesser_digits("operand", DIGIT_0, op->is_byte)),
				/* else, see if d1 is 9 */
				BRANCH_UNLESS(check_if_digit_eq_9("operand", DIGIT_1, op->is_byte),
					/* if not, then increment it. Result is d3 d2 (d1 + 1) 0 */
					SETL("result", increment_digit_clear_lesser_digits("operand", DIGIT_1, op->is_byte)),
					/* else, first see if it's a byte instruction */
					(op->is_byte) ? SETL("result", U8(0)) : // if so, overflow to 8-bit 0
						/* otherwise, continue the chain to the 4th digit */
						continue_rz_msp430_lift_dadc_instr()))));
}

RzILOpEffect *continue_rz_msp430_lift_dadc_instr() {
	const bool is_byte = false;
	return
		/* see if d2 is 9 */
		BRANCH_UNLESS(check_if_digit_eq_9("operand", DIGIT_2, is_byte),
			/* if not, then increment it. Result is d3 (d2 + 1) 0 0 */
			SETL("result", increment_digit_clear_lesser_digits("operand", DIGIT_2, is_byte)),
			/* else, see if d3 is 9 */
			BRANCH_UNLESS(check_if_digit_eq_9("operand", DIGIT_3, is_byte),
				/* if not, then increment it. Result is (d3 + 1) 0 0 0*/
				SETL("result", increment_digit_clear_lesser_digits("operand", DIGIT_3, is_byte)),
				/* else overflow to 16-bit 0 */
				SETL("result", U16(0))));
}

RzILOpBool *check_if_digit_eq_9(const char *operand_name, DigitPos dp, bool is_byte) {
	int mask = 9 << ((int)dp * 4);
	RzILOpBitVector *m1, *m2;
	if (is_byte) {
		m1 = U8(mask);
		m2 = U8(mask);
	} else {
		m1 = U16(mask);
		m2 = U16(mask);
	}
	return EQ(LOGAND(VARL(operand_name), m1), m2);
}

RzILOpBitVector *increment_digit_clear_lesser_digits(const char *operand_name, DigitPos dp, bool is_byte) {
	int clear_mask = 0xFFFF << ((int)dp * 4);
	int increment_by = 1 << ((int)dp * 4);
	RzILOpBitVector *result = ADD(VARL(operand_name), (is_byte) ? U8(increment_by) : U16(increment_by));
	return (dp == DIGIT_0) ? result : LOGAND(result, (is_byte) ? U8(clear_mask) : U16(clear_mask));
}
/* @} */

// ************************************* Jump Instructions Lifter ******************************** //
/* \defgroup Jump_Op_Lifter lifter functions that lift jump MSP430 instructions (CALL is not a jump instructino, and BR is also not counted)
 * @{
 */
RZ_OWN RzILOpEffect *rz_msp430_lift_jump_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	RzILOpBitVector *abs_addr = abs_addr_from_rel_addr(U16(current_addr), op->jmp_addr);
	RzILOpEffect *jmp = JMP(abs_addr);

	// unconditional jump
	if (op->jmp_cond == MSP430_JMP) {
		return jmp;
	}
	// otherwise, construct the condition to make a guarded branch
	RzILOpBool *jmp_cond = jmp_condition_constructors[op->jmp_cond](MSP430_GETR(MSP430_SR));

	// if applicable, invert the condition efficiently by swapping THEN and ELSE in the RzIL branch
	if (jmp_condition_triggers[op->jmp_cond] == JMP_THEN) {
		return BRANCH(jmp_cond, jmp, NOP());
	} else {
		return BRANCH(jmp_cond, NOP(), jmp);
	}
}
/* @} */

// ************************************* End of Lifters ******************************** //

RZ_OWN RzILOpEffect *rz_msp430_dummy() {
	RZ_LOG_ERROR("UNREACHABLE CONTROL FLOW");
	return NOP();
}

RzILOpEffect *rz_msp430_lift_todo(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	NOT_IMPLEMENTED;
}

#include <rz_il/rz_il_opbuilder_end.h>
#undef BRANCH_UNLESS

static const MSP430InstructionLifter one_op_lifters[] = {
	[MSP430_RRC] = rz_msp430_lift_rrc_instr,
	[MSP430_SWPB] = rz_msp430_lift_swpb_instr,
	[MSP430_RRA] = rz_msp430_lift_todo,
	[MSP430_SXT] = rz_msp430_lift_sxt_instr,
	[MSP430_PUSH] = rz_msp430_lift_push_instr,
	[MSP430_CALL] = rz_msp430_lift_call_instr,
	[MSP430_RETI] = rz_msp430_lift_todo,
	[MSP430_UNUSED] = NULL
};

RZ_OWN RzILOpEffect *rz_msp430_lift_single_operand_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	rz_return_val_if_fail(
		op->opcode == MSP430_RRC || op->opcode == MSP430_SWPB || op->opcode == MSP430_RRA ||
			op->opcode == MSP430_SXT || op->opcode == MSP430_PUSH || op->opcode == MSP430_CALL ||
			op->opcode == MSP430_RETI,
		NULL);
	return one_op_lifters[op->opcode](analysis, op, current_addr, instr_size);
}

static const MSP430InstructionLifter two_op_lifters[] = {
	[MSP430_MOV] = rz_msp430_lift_mov_instr,
	[MSP430_ADD] = rz_msp430_lift_add_instr,
	[MSP430_ADDC] = rz_msp430_lift_todo,
	[MSP430_SUBC] = rz_msp430_lift_todo,
	[MSP430_SUB] = rz_msp430_lift_sub_instr,
	[MSP430_CMP] = rz_msp430_lift_cmp_instr,
	[MSP430_DADD] = rz_msp430_lift_todo,
	[MSP430_BIT] = rz_msp430_lift_bit_instr,
	[MSP430_BIC] = rz_msp430_lift_bic_instr,
	[MSP430_BIS] = rz_msp430_lift_bis_instr,
	[MSP430_XOR] = rz_msp430_lift_xor_instr,
	[MSP430_AND] = rz_msp430_lift_and_instr
};

RZ_OWN RzILOpEffect *rz_msp430_lift_double_operand_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return two_op_lifters[op->opcode](analysis, op, current_addr, instr_size);
}

static const MSP430InstructionLifter emulated_instructions_lifter[] = {
	[MSP430_ADC] = rz_msp430_lift_adc_instr,
	[MSP430_BR] = rz_msp430_lift_br_instr,
	[MSP430_CLR] = rz_msp430_lift_clr_instr,
	[MSP430_CLRC] = rz_msp430_lift_clrc_instr,
	[MSP430_CLRN] = rz_msp430_lift_clrn_instr,
	[MSP430_CLRZ] = rz_msp430_lift_clrz_instr,
	[MSP430_DADC] = rz_msp430_lift_dadc_instr,
	[MSP430_DEC] = rz_msp430_lift_dec_instr,
	[MSP430_DECD] = rz_msp430_lift_todo,
	[MSP430_DINT] = rz_msp430_lift_todo,
	[MSP430_EINT] = rz_msp430_lift_todo,
	[MSP430_INC] = rz_msp430_lift_inc_instr,
	[MSP430_INCD] = rz_msp430_lift_todo,
	[MSP430_INV] = rz_msp430_lift_inv_instr,
	[MSP430_NOP] = rz_msp430_lift_nop_instr,
	[MSP430_POP] = rz_msp430_lift_pop_instr,
	[MSP430_RET] = rz_msp430_lift_ret_instr,
	[MSP430_RLA] = rz_msp430_lift_todo,
	[MSP430_RLC] = rz_msp430_lift_todo,
	[MSP430_SBC] = rz_msp430_lift_sbc_instr,
	[MSP430_SETC] = rz_msp430_lift_setc_instr,
	[MSP430_SETN] = rz_msp430_lift_setn_instr,
	[MSP430_SETZ] = rz_msp430_lift_setz_instr,
	[MSP430_TST] = rz_msp430_lift_tst_instr
};

RZ_OWN RzILOpEffect *rz_msp430_lift_emulated_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	return emulated_instructions_lifter[op->opcode](analysis, op, current_addr, instr_size);
}

RZ_OWN RZ_IPI RzILOpEffect *rz_msp430_lift_instr(RZ_BORROW RZ_NONNULL RzAnalysis *analysis, RZ_NONNULL const Msp430Instruction *op, ut64 current_addr, int instr_size) {
	rz_return_val_if_fail(analysis && op, NULL);

	switch (op->type) {
	case MSP430_ONEOP: {
		return rz_msp430_lift_single_operand_instr(analysis, op, current_addr, instr_size);
	}
	case MSP430_TWOOP: {
		return rz_msp430_lift_double_operand_instr(analysis, op, current_addr, instr_size);
	}
	case MSP430_JUMP: {
		return rz_msp430_lift_jump_instr(analysis, op, current_addr, instr_size);
	}
	case MSP430_EMULATE: {
		return rz_msp430_lift_emulated_instr(analysis, op, current_addr, instr_size);
	}

	// should never happen, op can't be an invalid instruction
	default:
		rz_warn_if_reached();
		return rz_msp430_dummy();
	}
}

RZ_OWN RZ_IPI RzAnalysisILConfig *rz_msp430_il_config(RZ_BORROW RZ_NONNULL RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);

	return rz_analysis_il_config_new(PC_SIZE, IS_BIG_ENDIAN, MEM_ADDR_SIZE);
}