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
 *	- https://www.plantation-productions.com/Webster/www.artofasm.com/Windows/HTML/RealArithmetica2.html
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

/**
 * FLD
 * Loads a floating point value and pushes it onto the FPU stack in ST(0)
 */
IL_LIFTER(fld) {
	return x86_il_st_push(x86_il_get_floating_op(0),
		x86_width_to_format(ins->structure->operands[0].size * BITS_PER_BYTE));
}

/**
 * FST
 * Stores the floating point value stored at the top of the FPU stack in ST(0)
 */
IL_LIFTER(fst) {
	// TODO: Set the C1 bit depending on floating-point inexact exception (#P).
	return x86_il_set_floating_op(0, x86_il_get_st_reg(X86_REG_ST0), RZ_FLOAT_IEEE754_BIN_80);
}

// TODO: Implement undocumented instructions, have a look at #4045 for more.

/**
 * FSTP
 * Stores the floating point value stored at the top of the FPU stack in ST(0)
 * and pops the value off the stack
 */
IL_LIFTER(fstp) {
	ILPureEffectPair pop = x86_il_st_pop_with_val();
	return SEQ2(x86_il_set_floating_op(0, pop.val, RZ_FLOAT_IEEE754_BIN_80), pop.eff);
}

/**
 * FLD1
 * Load +1.0
 */
IL_LIFTER(fld1) {
	return x86_il_st_push(F80(1.0), RZ_FLOAT_IEEE754_BIN_80);
}

/**
 * FLDZ
 * Load +0.0
 */
IL_LIFTER(fldz) {
	return x86_il_st_push(F80(0.0), RZ_FLOAT_IEEE754_BIN_80);
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

ILPureEffectPair math_const_to_float_ctx(uint64_t upper, uint64_t lower, X86ILContext *ctx) {
	RzILOpPure *upper_unshifted = UN(128, upper);
	RzILOpPure *upper_shifted = SHIFTL0(upper_unshifted, UN(8, 8));

	uint64_t stripped_lower = lower & (0x3ULL << 62);
	RzILOpPure *final_bits = LOGOR(upper_shifted, UN(128, stripped_lower));

	/* We recast the 128-bit value (having only 66 non-zero bits) to an 80-bit
	 * value to emulate the rounding effect of rounding a 66-bit value. */
	return x86_il_resize_floating(BV2F(RZ_FLOAT_IEEE754_BIN_128, final_bits), RZ_FLOAT_IEEE754_BIN_80);
}

#define math_const_to_float(upper_lower) math_const_to_float_ctx(upper_lower, ctx)

/**
 * FLDL2T
 * Load log2(10)
 */
IL_LIFTER(fldl2t) {
	ILPureEffectPair math_const = math_const_to_float(FPU_L2T);
	return SEQ2(math_const.eff, x86_il_st_push(math_const.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FLDL2E
 * Load log2(e)
 */
IL_LIFTER(fldl2e) {
	ILPureEffectPair math_const = math_const_to_float(FPU_L2E);
	return SEQ2(math_const.eff, x86_il_st_push(math_const.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FLDPI
 * Load pi
 */
IL_LIFTER(fldpi) {
	ILPureEffectPair math_const = math_const_to_float(FPU_PI);
	return SEQ2(math_const.eff, x86_il_st_push(math_const.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FLDLG2
 * Load log10(2)
 */
IL_LIFTER(fldlg2) {
	ILPureEffectPair math_const = math_const_to_float(FPU_LG2);
	return SEQ2(math_const.eff, x86_il_st_push(math_const.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FLDLN2
 * Load ln(2)
 */
IL_LIFTER(fldln2) {
	ILPureEffectPair math_const = math_const_to_float(FPU_LN2);
	return SEQ2(math_const.eff, x86_il_st_push(math_const.val, RZ_FLOAT_IEEE754_BIN_80));
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
		reg = ins->structure->operands[1].reg;
	}

	/* TODO: The IL generated from the following code is too verbose because of
	many rounding checks, there are ways to remove this sort of rounding checks,
	but it doesn't matter for now so I'm not bothering with it. */
	return SEQ4(
		SETL("tmp", x86_il_get_st_reg(X86_REG_ST0)),
		x86_il_set_st_reg(X86_REG_ST0, x86_il_get_st_reg(reg), RZ_FLOAT_IEEE754_BIN_80),
		x86_il_set_st_reg(reg, VARL("tmp"), RZ_FLOAT_IEEE754_BIN_80),
		x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE));
}

/**
 * FILD
 * Load integer onto the FPU register stack
 */
IL_LIFTER(fild) {
	RzILOpPure *int_val = x86_il_get_op(0);
	ILPureEffectPair float_val = x86_il_floating_from_int(int_val, RZ_FLOAT_IEEE754_BIN_80);

	return SEQ2(float_val.eff, x86_il_st_push(float_val.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FIST
 * Store float in ST(0) after rounding to integer
 */
IL_LIFTER(fist) {
	ILPureEffectPair int_val = x86_il_int_from_floating(x86_il_get_st_reg(X86_REG_ST0), ins->structure->operands[0].size * BITS_PER_BYTE);
	return SEQ2(int_val.eff, x86_il_set_op(0, int_val.val));
}

/**
 * FISTP
 * Store float in ST(0) after rounding to integer, pop the FPU register stack
 */
IL_LIFTER(fistp) {
	ILPureEffectPair pop = x86_il_st_pop_with_val();
	ILPureEffectPair int_val = x86_il_int_from_floating(pop.val, ins->structure->operands[0].size * BITS_PER_BYTE);
	return SEQ3(int_val.eff, x86_il_set_op(0, int_val.val), pop.eff);
}

/**
 * FBLD
 * Load binary coded decimal in ST(0)
 * 80-bit BCD (18-digits) := [sign-byte] + 9 * [data-bytes]
 */
IL_LIFTER(fbld) {
	ut8 mem_size = analysis->bits;

	RzILOpEffect *mem_init = SETL("mem", x86_il_get_memaddr(ins->structure->operands[0].mem));
	RzILOpEffect *i_init = SETL("i", UN(mem_size, 8));
	RzILOpEffect *val_init = SETL("val", UN(64, 0));

	RzILOpPure *byte_mem = ADD(VARL("mem"), VARL("i"));
	RzILOpEffect *set_byte = SETL("byte", LOADW(8, byte_mem));

	RzILOpPure *new_val = ADD(
		MUL(VARL("val"), UN(64, 100)), // hundredths position (old val)
		UNSIGNED(64, ADD(MUL(SHIFTR0(VARL("byte"), UN(8, 4)), UN(8, 10)), // tenths position (upper nibble)
				     LOGAND(VARL("byte"), UN(8, 0xf)) // ones position (lower nibble)
				     )));

	RzILOpEffect *bcd_decode_loop = REPEAT( // while
		UGE(VARL("i"), UN(mem_size, 0)), // i >= 0
		SEQ3(
			set_byte, // get byte
			SETL("val", new_val), // update val
			SETL("i", SUB(VARL("i"), UN(mem_size, 1))) // i--
			));

	ILPureEffectPair fval = x86_il_floating_from_int(VARL("val"), RZ_FLOAT_IEEE754_BIN_80);
	RzILOpEffect *f_init = SEQ2(fval.eff, SETL("f", fval.val));

	/* Check sign byte (index 9) checking if sign byte is zero */
	RzILOpPure *sign_byte = LOADW(8, ADD(VARL("mem"), UN(mem_size, 9)));
	RzILOpFloat *final_float = ITE(IS_ZERO(sign_byte), VARL("f"), FNEG(VARL("f")));

	return SEQ6(
		mem_init, i_init, val_init, // Local vars init
		bcd_decode_loop, // BCD decoding loop
		f_init, // Conversion to 80-bit float
		x86_il_st_push(final_float, RZ_FLOAT_IEEE754_BIN_80) // Push the value onto the FPU stack
	);
}

/**
 * FBSTP
 * Pop the float in ST(0), convert it to BCD and store
 */
IL_LIFTER(fbstp) {
	ut8 mem_size = analysis->bits;

	ILPureEffectPair pop = x86_il_st_pop_with_val();

	ILPureEffectPair val = x86_il_int_from_floating(pop.val, 64);
	RzILOpEffect *val_init = SEQ2(val.eff, SETL("val", val.val));
	RzILOpEffect *sgn_init = SETL("sgn", MSB(VARL("val")));
	RzILOpEffect *val_abs = SETL("val", ITE(VARL("sgn"), NEG(VARL("val")), VARL("val")));

	RzILOpEffect *mem_init = SETL("mem", x86_il_get_memaddr(ins->structure->operands[0].mem));
	RzILOpEffect *i_init = SETL("i", UN(mem_size, 0));
	RzILOpPure *byte_mem = ADD(VARL("mem"), VARL("i"));

	RzILOpPure *upper_nibble = DIV(MOD(VARL("val"), UN(64, 100)), UN(64, 10));
	RzILOpPure *lower_nibble = MOD(VARL("val"), UN(64, 10));
	RzILOpPure *new_byte = UNSIGNED(8, LOGOR(SHIFTL0(upper_nibble, UN(8, 4)), lower_nibble));

	RzILOpEffect *bcd_encode_loop = REPEAT( // while
		ULT(VARL("i"), UN(mem_size, 9)), // i < 9
		SEQ3(
			STOREW(byte_mem, new_byte), // store byte
			SETL("val", DIV(VARL("val"), UN(64, 100))), // val /= 100
			SETL("i", ADD(VARL("i"), UN(mem_size, 1))) // i++
			));

	RzILOpEffect *update_mem = SETL("mem", DUP(byte_mem));
	RzILOpEffect *store_sign = BRANCH(VARL("sgn"), STOREW(VARL("mem"), UN(8, 0xff)), STOREW(VARL("mem"), UN(8, 0)));

	RzILOpEffect *noexcept_case = SEQ5(
		mem_init, i_init, // init loop vars
		bcd_encode_loop, // convert val to bcd
		update_mem, store_sign // update mem pointer and store the saved sign in the bcd
	);
	RzILOpEffect *maybe_except = BRANCH(
		SGE(VARL("val"), UN(64, 1e18)), // |val| >= 1e18
		GOTO("int"), // throw exception if val can't fit in 18-digit BCD
		noexcept_case);

	return SEQ5(
		val_init, pop.eff, // get val from ST(0) and pop
		sgn_init, val_abs, // val = |val| and store sign
		maybe_except);
}

/* Arithmetic instructions */

/**
 * FABS
 * Clears the sign bit of ST(0) to create absolute value
 */
IL_LIFTER(fabs) {
	RzILOpFloat *abs_value = FABS(x86_il_get_st_reg(X86_REG_ST0));
	return SEQ2(x86_il_set_st_reg(X86_REG_ST0, abs_value, RZ_FLOAT_IEEE754_BIN_80), x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE));
}

#define FLOATING_ARITHMETIC_IL(op) \
	do { \
		RzILOpFloat *src; \
		X86Reg dest_reg; \
		RzILOpEffect *src_eff = NULL; \
\
		/* TODO: Check whether all the enumerated cases here are correct, through \
		 * code coverage. */ \
		switch (ins->structure->op_count) { \
		case 1: \
			/* Need to convert a 32-bit or 64-bit memory operand */ \
			dest_reg = X86_REG_ST0; \
			ILPureEffectPair resized = x86_il_resize_floating(x86_il_get_floating_op(0), RZ_FLOAT_IEEE754_BIN_80); \
			src = resized.val; \
			src_eff = resized.eff; \
			break; \
		case 2: \
			/* ST(i) operand, so no need for resizing */ \
			dest_reg = ins->structure->operands[0].reg; \
			src = x86_il_get_floating_op(0); \
			break; \
		default: \
			rz_warn_if_reached(); \
			return NULL; \
		} \
\
		ILPureEffectPair result = x86_il_##op##_with_rmode(src, x86_il_get_st_reg(dest_reg)); \
		RzILOpEffect *ret = SEQ2(result.eff, x86_il_set_st_reg(dest_reg, result.val, RZ_FLOAT_IEEE754_BIN_80)); \
\
		if (src_eff) { \
			ret = SEQ2(src_eff, ret); \
		} \
		return ret; \
	} while (0)

#define FLOATING_ARITHMETIC_POP_IL(op) \
	do { \
		X86Reg dest_reg = X86_REG_ST1; \
\
		if (ins->structure->op_count == 2) { \
			/* Destination register passed in as the first operand */ \
			dest_reg = ins->structure->operands[0].reg; \
		} \
\
		ILPureEffectPair result = x86_il_##op##_with_rmode(x86_il_get_st_reg(X86_REG_ST0), x86_il_get_st_reg(dest_reg)); \
		return SEQ3(result.eff, x86_il_set_st_reg(dest_reg, result.val, RZ_FLOAT_IEEE754_BIN_80), x86_il_st_pop()); \
	} while (0)

#define FLOATING_INT_ARITHMETIC_IL(op) \
	do { \
		ILPureEffectPair float_val = x86_il_floating_from_int(x86_il_get_op(0), RZ_FLOAT_IEEE754_BIN_80); \
		ILPureEffectPair result = x86_il_##op##_with_rmode(float_val.val, x86_il_get_st_reg(X86_REG_ST0)); \
		return SEQ3(float_val.eff, result.eff, x86_il_set_st_reg(X86_REG_ST0, result.val, RZ_FLOAT_IEEE754_BIN_80)); \
	} while (0)

/**
 * FADD
 * Add floating point values
 */
IL_LIFTER(fadd) {
	/* Have a unified IL lifter for FADD and FADDP since Capstone has removed the
	 * distinction after version 4, which I think is a terrible thing. */
	if (ins->structure->opcode[0] == 0xde) {
		// FADDP
		FLOATING_ARITHMETIC_POP_IL(fadd);
	} else {
		// FADD
		FLOATING_ARITHMETIC_IL(fadd);
	}
}

/**
 * FIADD
 * Add an integer to ST(0)
 */
IL_LIFTER(fiadd) {
	FLOATING_INT_ARITHMETIC_IL(fadd);
}

/**
 * FMUL
 * Multiply floating point values
 */
IL_LIFTER(fmul) {
	FLOATING_ARITHMETIC_IL(fmul);
}

/**
 * FMULP
 * Multiply ST(0) to ST(i) and pop the stack
 */
IL_LIFTER(fmulp) {
	FLOATING_ARITHMETIC_POP_IL(fmul);
}

/**
 * FIMUL
 * Multiply an integer to ST(0)
 */
IL_LIFTER(fimul) {
	FLOATING_INT_ARITHMETIC_IL(fmul);
}

/**
 * FSUB
 * Subtract floating point value
 */
IL_LIFTER(fsub) {
	FLOATING_ARITHMETIC_IL(fsub);
}

/**
 * FSUBP
 * Subtract ST(0) from ST(i) and pop the stack
 */
IL_LIFTER(fsubp) {
	FLOATING_ARITHMETIC_POP_IL(fsub);
}

/**
 * FISUB
 * Subtract an integer from ST(0)
 */
IL_LIFTER(fisub) {
	FLOATING_INT_ARITHMETIC_IL(fsub);
}

/**
 * FSUBR
 * Reverse subtract floating point value
 */
IL_LIFTER(fsubr) {
	FLOATING_ARITHMETIC_IL(fsubr);
}

/**
 * FSUBRP
 * Subtract ST(i) from ST(0), store the result in ST(i) and pop the stack
 */
IL_LIFTER(fsubrp) {
	FLOATING_ARITHMETIC_POP_IL(fsubr);
}

/**
 * FISUBR
 * Subtract ST(0) from an integer and store the result in ST(0)
 */
IL_LIFTER(fisubr) {
	FLOATING_INT_ARITHMETIC_IL(fsubr);
}

/**
 * FDIV
 * Divide floating point value
 */
IL_LIFTER(fdiv) {
	FLOATING_ARITHMETIC_IL(fdiv);
}

/**
 * FDIVP
 * Divide ST(0) from ST(i) and pop the stack
 */
IL_LIFTER(fdivp) {
	FLOATING_ARITHMETIC_POP_IL(fdiv);
}

/**
 * FIDIV
 * Divide an integer from ST(0)
 */
IL_LIFTER(fidiv) {
	FLOATING_INT_ARITHMETIC_IL(fdiv);
}

/**
 * FDIVR
 * Reverse divide floating point value
 */
IL_LIFTER(fdivr) {
	FLOATING_ARITHMETIC_IL(fdivr);
}

/**
 * FDIVRP
 * Divide ST(i) from ST(0), store the result in ST(i) and pop the stack
 */
IL_LIFTER(fdivrp) {
	FLOATING_ARITHMETIC_POP_IL(fdiv);
}

/**
 * FIDIVR
 * Divide ST(0) from an integer and store the result in ST(0)
 */
IL_LIFTER(fidivr) {
	FLOATING_INT_ARITHMETIC_IL(fdivr);
}

RzILOpEffect *fcom_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis, RzILOpPure *op1_override) {
	RzILOpPure *st0 = x86_il_get_st_reg(X86_REG_ST0);
	RzILOpPure *op1;

	if (op1_override) {
		op1 = op1_override;
	} else if (ins->structure->op_count == 0) {
		/* ST(1) is the default operand */
		op1 = x86_il_get_st_reg(X86_REG_ST1);
	} else {
		op1 = x86_il_get_floating_op(0);
	}

	// TODO: Set the C0, C2, C3 bits depending on invalid arithmetic operand exception (#IA).
	return SEQ4(
		x86_il_set_fpu_flag(X86_FPU_C0, FLT(st0, op1)),
		x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE),
		x86_il_set_fpu_flag(X86_FPU_C2, IL_FALSE),
		x86_il_set_fpu_flag(X86_FPU_C3, FEQ(DUP(st0), DUP(op1))));
}

/**
 * FCOM
 * Compare floating point values and store the result in the FPU control word
 */
IL_LIFTER(fcom) {
	return fcom_helper(ins, pc, analysis, NULL);
}

/**
 * FCOMP
 * Compare floating point values, store the result in the FPU control word and pop the stack
 */
IL_LIFTER(fcomp) {
	return SEQ2(fcom_helper(ins, pc, analysis, NULL), x86_il_st_pop());
}

/**
 * FICOM
 * Compare the floating point value in ST(0) with an integer and store the result in the FPU control word
 */
IL_LIFTER(ficom) {
	ILPureEffectPair float_val = x86_il_floating_from_int(x86_il_get_op(0), RZ_FLOAT_IEEE754_BIN_80);
	return SEQ2(float_val.eff, fcom_helper(ins, pc, analysis, float_val.val));
}

/**
 * FCOMPP
 * Compare floating point values, store the result in the FPU control word and pop the stack twice
 */
IL_LIFTER(fcompp) {
	/* This function takes in no operands, so we pass in the [op1_override] argument in [fcom_helper]. */
	return SEQ3(fcom_helper(ins, pc, analysis, x86_il_get_st_reg(X86_REG_ST1)), x86_il_st_pop(), x86_il_st_pop());
}

/**
 * FICOMP
 * Compare the floating point value in ST(0) with an integer, store the result in the FPU control word and pop the stack
 */
IL_LIFTER(ficomp) {
	ILPureEffectPair float_val = x86_il_floating_from_int(x86_il_get_op(0), RZ_FLOAT_IEEE754_BIN_80);
	return SEQ2(float_val.eff, SEQ2(fcom_helper(ins, pc, analysis, float_val.val), x86_il_st_pop()));
}

RzILOpEffect *fcomi_helper(const X86ILIns *ins, ut64 pc, RzAnalysis *analysis) {
	RzILOpPure *st0 = x86_il_get_st_reg(X86_REG_ST0);
	RzILOpPure *sti = x86_il_get_floating_op(0);

	// TODO: Set the ZF, PF, CF depending on invalid arithmetic operand exception (#IA).
	return SEQ4(
		x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE),
		SETG(EFLAGS(ZF), FEQ(st0, sti)),
		SETG(EFLAGS(PF), IL_FALSE),
		SETG(EFLAGS(CF), FLT(DUP(st0), DUP(sti))));
}

/**
 * FCOMI
 * Compare ST(0) and ST(i) and set the EFLAGS accordingly
 */
IL_LIFTER(fcomi) {
	return fcomi_helper(ins, pc, analysis);
}

#if CS_API_MAJOR > 4
/**
 * FCOMIP
 * Compare ST(0) and ST(i), set the EFLAGS accordingly and pop the stack
 */
IL_LIFTER(fcomip) {
	return SEQ2(fcomi_helper(ins, pc, analysis), x86_il_st_pop());
}
#endif

/**
 * FCHS
 * Change the sign of ST(0)
 */
IL_LIFTER(fchs) {
	return SEQ2(
		x86_il_set_st_reg(X86_REG_ST0, FNEG(x86_il_get_st_reg(X86_REG_ST0)), RZ_FLOAT_IEEE754_BIN_80),
		x86_il_set_fpu_flag(X86_FPU_C1, IL_FALSE));
}

/**
 * FTST
 * Test the value in ST(0) (i.e. compare with 0.0)
 */
IL_LIFTER(ftst) {
	/* We reuse the [fcom_helper] function here by passing in the [op1_override] argument. */
	return fcom_helper(ins, pc, analysis, F80(0.0));
}

/**
 * FRNDINT
 * Round ST(0) to an integer
 */
IL_LIFTER(frndint) {
	ILPureEffectPair int_from_float = x86_il_int_from_floating(x86_il_get_st_reg(X86_REG_ST0), 64);
	ILPureEffectPair float_from_int = x86_il_floating_from_int(int_from_float.val, RZ_FLOAT_IEEE754_BIN_80);

	/* Not very sure about whether the rounded integer should be limited to 64 bits or not. */
	return SEQ3(int_from_float.eff, float_from_int.eff, x86_il_set_st_reg(X86_REG_ST0, float_from_int.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FSQRT
 * Calculate the square root of ST(0)
 */
IL_LIFTER(fsqrt) {
	ILPureEffectPair fsqrt_res = x86_il_fsqrt_with_rmode(x86_il_get_st_reg(X86_REG_ST0));
	return SEQ2(fsqrt_res.eff, x86_il_set_st_reg(X86_REG_ST0, fsqrt_res.val, RZ_FLOAT_IEEE754_BIN_80));
}

/**
 * FNOP
 * No-op
 */
IL_LIFTER(fnop) {
	return NOP();
}

/**
 * FISTTP
 * Round ST(0) to an integer (using RZ_FLOAT_RMODE_RTZ), store the integer in the memory operand and pop the stack
 */
IL_LIFTER(fisttp) {
	ILPureEffectPair int_from_float = x86_il_int_from_floating(x86_il_get_st_reg(X86_REG_ST0), ins->structure->operands[0].size * BITS_PER_BYTE);
	return SEQ3(int_from_float.eff, x86_il_set_op(0, int_from_float.val), x86_il_st_pop());
}

#include <rz_il/rz_il_opbuilder_end.h>
