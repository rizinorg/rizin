// SPDX-FileCopyrightText: 2023 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file il_fp_ops.c
 *
 * Contains the IL implementations for x86 floating point instructions.
 *
 * References:
 *  - https://docs.oracle.com/cd/E18752_01/html/817-5477/eoizy.html
 *  - https://eng.libretexts.org/Bookshelves/Computer_Science/Programming_Languages/x86-64_Assembly_Language_Programming_with_Ubuntu_(Jorgensen)/18%3A_Floating-Point_Instructions
 *  - https://en.wikibooks.org/wiki/X86_Assembly/Floating_Point#Floating-Point_Instruction_Set
 *  - https://github.com/avast/retdec/wiki/x86-FPU-semantic-model
 *	- https://redirect.cs.umbc.edu/courses/undergraduate/CMSC313/fall04/burt_katz/lectures/Lect12/floatingpoint.html
 */

#include "common.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * FINIT/FNINIT
 * Initialize x87 FPU
 */
IL_LIFTER(fninit) {
	RzILOpEffect *set_cw = SETG(X86_REG_FPU_CW, UN(16, 0x37f));
	/* No need to set C0-C3 flags to zero, since we are setting the FPSW to 0,
	 * so all the flag bits will also be set to 0. */
	RzILOpEffect *set_sw = x86_il_set_reg(X86_REG_FPSW, UN(16, 0x0));
	RzILOpEffect *set_tw = SETG(X86_REG_FPU_TW, UN(16, 0xffff));
	RzILOpEffect *set_ip = SETG(X86_REG_FPU_IP, UN(32, 0x0));
	RzILOpEffect *set_dp = SETG(X86_REG_FPU_DP, UN(32, 0x0));

	return SEQ5(set_cw, set_sw, set_tw, set_ip, set_dp);
}

/**
 * FLDCW m16
 * Load x87 FPU Control Word
 */
IL_LIFTER(fldcw) {
	return SETG(X86_REG_FPU_CW, x86_il_get_op(0));
}

/**
 * FSTCW/FNSTCW m2byte
 * Store x87 FPU Control Word
 */
IL_LIFTER(fnstcw) {
	return x86_il_set_op(0, VARG(X86_REG_FPU_CW));
}

/**
 * FSTSW/FNSTSW {m2byte | AX}
 * Store x87 FPU Status Word
 */
IL_LIFTER(fnstsw) {
	return x86_il_set_op(0, x86_il_get_reg(X86_REG_FPSW));
}

/**
 * FCLEX/FNCLEX
 * Clear exceptions
 */
IL_LIFTER(fnclex) {
	/* Zero out the 15th bit and 0-7 bits. */
	RzILOpPure *new_sw = LOGAND(x86_il_get_reg(X86_REG_FPSW), UN(16, 0x7f00));
	return SEQ2(x86_il_set_reg(X86_REG_FPSW, new_sw), x86_il_clear_fpsw_flags());
}

/* Arithmetic instructions */

/**
 * FABS
 * Clears the sign bit of st(0) to create absolute value
 */
IL_LIFTER(fabs) {
	RzILOpFloat *abs_value = FABS(x86_il_get_st_reg(X86_REG_ST0));
	return SEQ2(x86_il_set_st_reg(X86_REG_ST0, abs_value, 64), x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE));
}

static RzILOpEffect *fpu_stack_push_val(RzILOpFloat *val, int val_size) {
	RzILOpEffect *push_eff = x86_il_st_push(val, val_size);

	/* Set C1 if stack overflow. If stack overflow occurred, then the value of
	 * stack TOP must be 0x7. */
	RzILOpEffect *set_oveflow = x86_il_set_fpu_flag(X86_FPU_C1, EQ(x86_il_get_fpu_stack_top(), UN(3, 7)));

	return SEQ2(push_eff, set_oveflow);
}

/**
 * FLD
 * Loads a floating point value and pushes it onto the FPU stack in ST(0)
 */
IL_LIFTER(fld) {
	return fpu_stack_push_val(x86_il_get_floating_op(0),
		ins->structure->operands[0].size * BITS_PER_BYTE);
}

/**
 * FST
 * Stores the floating point value stored at the top of the FPU stack in ST(0)
 */
IL_LIFTER(fst) {
	return x86_il_set_floating_op(0, x86_il_get_st_reg(X86_REG_ST0), 64);
}

/**
 * FSTP
 * Stores the floating point value stored at the top of the FPU stack in ST(0)
 * and pops the value off the stack
 */
IL_LIFTER(fstp) {
	RzILOpEffect *pop_eff;
	RzILOpPure *pop_val;
	X86_IL_ST_POP(pop_val, pop_eff);

	return SEQ3(
		x86_il_set_floating_op(0, pop_val, 64),
		pop_eff,
		x86_il_set_fpu_flag(X86_FPU_C1, EQ(x86_il_get_fpu_stack_top(), UN(3, 0))));
}

/**
 * FLD1
 * Load +1.0
 */
IL_LIFTER(fld1) {
	return fpu_stack_push_val(F64(1.0), 64);
}

/**
 * FLDZ
 * Load +0.0
 */
IL_LIFTER(fldz) {
	return fpu_stack_push_val(F64(0.0), 64);
}

/*
 * 128-bit representation of h for value v, where
 *
 * v = (h - 1) * 2^x
 *
 * Here x is the exponent. The reason why we are computing h is because the
 * first 66 bits of the mantissa of h are stored as the internal constants in
 * the FPU and should be used for rounding. In our case, we will directly use
 *
 * log2(10)	=	3fffd49a784bcd1b8afe492bf6ff1e13
 * log2(e)	=	3fffb8aa3b295c17f0bbbe87fed055ed
 * pi 		=	4000c90fdaa22168c234c4c6628b8361
 * log10(2)	=	3fff9a209a84fbcff7988f8959ac200d
 * ln(2)	=	3ffeb17217f7d1cf79abc9e3b39828ef
 */

#define FPU_L2T 0x3fffd49a784bcd1bULL, 0x8afe492bf6ff1e13ULL
#define FPU_L2E 0x3fffb8aa3b295c17ULL, 0xf0bbbe87fed055edULL
#define FPU_PI  0x4000c90fdaa22168ULL, 0xc234c4c6628b8361ULL
#define FPU_LG2 0x3fff9a209a84fbcfULL, 0xf7988f8959ac200dULL
#define FPU_LN2 0x3ffeb17217f7d1cfULL, 0x79abc9e3b39828efULL

RzILOpFloat *math_const_to_float(uint64_t upper, uint64_t lower) {
	RzILOpPure *upper_unshifted = UN(128, upper);
	RzILOpPure *upper_shifted = SHIFTL0(upper_unshifted, UN(8, 64));

	uint64_t stripped_lower = lower & ~(0x3fffffffffffULL);
	RzILOpPure *final_bits = LOGOR(upper_shifted, UN(128, stripped_lower));

	return x86_il_resize_floating(BV2F(RZ_FLOAT_IEEE754_BIN_128, final_bits), 64);
}

/**
 * FLDL2T
 * Load log2(10)
 */
IL_LIFTER(fldl2t) {
	return SEQ2(INIT_RMODE("rmode"), fpu_stack_push_val(math_const_to_float(FPU_L2T), 64));
}

/**
 * FLDL2E
 * Load log2(e)
 */
IL_LIFTER(fldl2e) {
	return SEQ2(INIT_RMODE("rmode"), fpu_stack_push_val(math_const_to_float(FPU_L2E), 64));
}

/**
 * FLDPI
 * Load pi
 */
IL_LIFTER(fldpi) {
	return SEQ2(INIT_RMODE("rmode"), fpu_stack_push_val(math_const_to_float(FPU_PI), 64));
}

/**
 * FLDLG2
 * Load log10(2)
 */
IL_LIFTER(fldlg2) {
	return SEQ2(INIT_RMODE("rmode"), fpu_stack_push_val(math_const_to_float(FPU_LG2), 64));
}

/**
 * FLDLN2
 * Load ln(2)
 */
IL_LIFTER(fldln2) {
	return SEQ2(INIT_RMODE("rmode"), fpu_stack_push_val(math_const_to_float(FPU_LN2), 64));
}

/**
 * FXCH
 * Exchange the contents of FPU stack register with ST(0)
 */
IL_LIFTER(fxch) {
	X86Reg reg;

	if (ins->structure->op_count == 0) {
		/* Use ST1 as the default reg in case no operand is provided. */
		reg = X86_REG_ST1;
	} else {
		reg = ins->structure->operands[0].reg;
	}

	/* TODO: The IL generated from the following code is too verbose because of
	many rounding checks, there are ways to remove this sort of rounding checks,
	but it doesn't matter for now so I'm not bothering with it. */
	return SEQ4(
		SETL("tmp", x86_il_get_st_reg(X86_REG_ST0)),
		x86_il_set_st_reg(X86_REG_ST0, x86_il_get_st_reg(reg), 64),
		x86_il_set_st_reg(reg, VARL("tmp"), 64),
		x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE));
}
