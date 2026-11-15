// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file il_sse_ops.inc
 *
 * Contains the IL implementations for x86 SSE/SSE2 scalar floating point
 * instructions, i.e. the ones operating on the low element of an XMM register
 * (the `*sd` doubles and `*ss` singles) plus the scalar conversions between
 * integers and floats.
 *
 * The legacy (non-VEX) encodings leave the upper bits of the destination XMM
 * register unmodified, which is what these lifters emulate.
 *
 * Rounding follows the MXCSR default (round to nearest, ties to even). MXCSR is
 * not modelled here, so a different rounding mode programmed into MXCSR is not
 * reflected, the same way the rest of the x86 lifter does not model every
 * control register.
 *
 * References:
 *  - Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 2
 *    (ADDSD, ADDSS, ..., CVTSI2SD, CVTTSD2SI, ...)
 */

#include "common.h"
#include <rz_il/rz_il_opbuilder_begin.h>

/**
 * \brief Read operand \p op as a scalar float of format \p fmt.
 *
 * Handles XMM register operands (reinterpreting the low bits of the 128-bit
 * register as a float) and memory operands (loading the matching width).
 */
static RzILOpFloat *x86_il_get_scalar_floating_op(X86Op op, RzFloatFormat fmt, int bits, ut64 pc) {
	ut8 width = x86_format_to_width(fmt);
	if (op.type == X86_OP_REG) {
		/* XMM register: reinterpret the low `width` bits as a float */
		return BV2F(fmt, CAST(width, IL_FALSE, x86_il_get_reg_bits(op.reg.value, bits, pc)));
	}
	/* memory operand: load `width` bits and reinterpret them as a float */
	return BV2F(fmt, LOADW(width, x86_il_get_memaddr_bits(op.mem, bits, pc)));
}

/**
 * \brief Write the scalar float \p val (of format \p fmt) into the low bits of
 * the destination XMM register operand \p op, leaving the upper bits unmodified
 * (legacy SSE semantics).
 */
static RzILOpEffect *x86_il_set_scalar_floating_op(X86Op op, RZ_OWN RZ_NONNULL RzILOpFloat *val, RzFloatFormat fmt, int bits, ut64 pc) {
	ut8 width = x86_format_to_width(fmt);
	RzILOpBitVector *result = UNSIGNED(128, F2BV(val));
	RzILOpBitVector *old = x86_il_get_reg_bits(op.reg.value, bits, pc);
	/* Clear the low `width` bits of the old value while keeping the upper bits,
	 * then merge in the freshly computed scalar. */
	RzILOpBitVector *upper = SHIFTL0(SHIFTR0(old, UN(8, width)), UN(8, width));
	return x86_il_set_reg_bits(op.reg.value, LOGOR(upper, result), bits);
}

/* Scalar arithmetic: ADDSD, ADDSS, SUBSD, SUBSS, MULSD, MULSS, DIVSD, DIVSS */

/* dest[scalar] = dest[scalar] <il_op> src[scalar]; upper bits of dest preserved */
#define SSE_SCALAR_ARITHMETIC(il_op, fmt) \
	do { \
		RzFloatFormat _fmt = (fmt); \
		RzILOpFloat *dst = x86_il_get_scalar_floating_op(ins->operands[0], _fmt, analysis->bits, pc); \
		RzILOpFloat *src = x86_il_get_scalar_floating_op(ins->operands[1], _fmt, analysis->bits, pc); \
		RzILOpFloat *res = il_op(RZ_FLOAT_RMODE_RNE, dst, src); \
		return x86_il_set_scalar_floating_op(ins->operands[0], res, _fmt, analysis->bits, pc); \
	} while (0)

/**
 * ADDSD
 * Add the low double precision floating point values
 */
IL_LIFTER(addsd) {
	SSE_SCALAR_ARITHMETIC(FADD, RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * ADDSS
 * Add the low single precision floating point values
 */
IL_LIFTER(addss) {
	SSE_SCALAR_ARITHMETIC(FADD, RZ_FLOAT_IEEE754_BIN_32);
}

/**
 * SUBSD
 * Subtract the low double precision floating point values
 */
IL_LIFTER(subsd) {
	SSE_SCALAR_ARITHMETIC(FSUB, RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * SUBSS
 * Subtract the low single precision floating point values
 */
IL_LIFTER(subss) {
	SSE_SCALAR_ARITHMETIC(FSUB, RZ_FLOAT_IEEE754_BIN_32);
}

/**
 * MULSD
 * Multiply the low double precision floating point values
 */
IL_LIFTER(mulsd) {
	SSE_SCALAR_ARITHMETIC(FMUL, RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * MULSS
 * Multiply the low single precision floating point values
 */
IL_LIFTER(mulss) {
	SSE_SCALAR_ARITHMETIC(FMUL, RZ_FLOAT_IEEE754_BIN_32);
}

/**
 * DIVSD
 * Divide the low double precision floating point values
 */
IL_LIFTER(divsd) {
	SSE_SCALAR_ARITHMETIC(FDIV, RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * DIVSS
 * Divide the low single precision floating point values
 */
IL_LIFTER(divss) {
	SSE_SCALAR_ARITHMETIC(FDIV, RZ_FLOAT_IEEE754_BIN_32);
}

/* Integer to scalar float: CVTSI2SD, CVTSI2SS */

/* dest[scalar] = (float) signed_int(src); upper bits of dest preserved */
#define SSE_CVT_SI2F(fmt) \
	do { \
		RzFloatFormat _fmt = (fmt); \
		RzILOpBitVector *int_val = x86_il_get_op(1); \
		RzILOpFloat *res = SINT2F(_fmt, RZ_FLOAT_RMODE_RNE, int_val); \
		return x86_il_set_scalar_floating_op(ins->operands[0], res, _fmt, analysis->bits, pc); \
	} while (0)

/**
 * CVTSI2SD
 * Convert a signed integer to a double precision floating point value
 */
IL_LIFTER(cvtsi2sd) {
	SSE_CVT_SI2F(RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * CVTSI2SS
 * Convert a signed integer to a single precision floating point value
 */
IL_LIFTER(cvtsi2ss) {
	SSE_CVT_SI2F(RZ_FLOAT_IEEE754_BIN_32);
}

/* Scalar float to integer: CVTSD2SI, CVTSS2SI, CVTTSD2SI, CVTTSS2SI */

/* dest = (signed int) src[scalar], rounded using \p rmode */
#define SSE_CVT_F2SI(fmt, rmode) \
	do { \
		RzILOpFloat *f = x86_il_get_scalar_floating_op(ins->operands[1], (fmt), analysis->bits, pc); \
		ut32 width = ins->operands[0].size * BITS_PER_BYTE; \
		return x86_il_set_op(0, F2SINT(width, rmode, f)); \
	} while (0)

/**
 * CVTSD2SI
 * Convert a double precision floating point value to a signed integer
 */
IL_LIFTER(cvtsd2si) {
	SSE_CVT_F2SI(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RNE);
}

/**
 * CVTSS2SI
 * Convert a single precision floating point value to a signed integer
 */
IL_LIFTER(cvtss2si) {
	SSE_CVT_F2SI(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RNE);
}

/**
 * CVTTSD2SI
 * Convert (with truncation) a double precision floating point value to a signed integer
 */
IL_LIFTER(cvttsd2si) {
	SSE_CVT_F2SI(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_RMODE_RTZ);
}

/**
 * CVTTSS2SI
 * Convert (with truncation) a single precision floating point value to a signed integer
 */
IL_LIFTER(cvttss2si) {
	SSE_CVT_F2SI(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_RMODE_RTZ);
}

/* Scalar float to scalar float: CVTSD2SS, CVTSS2SD */

/* dest[scalar] = convert(src[scalar]) from \p src_fmt to \p dst_fmt */
#define SSE_CVT_F2F(src_fmt, dst_fmt) \
	do { \
		RzFloatFormat _dst = (dst_fmt); \
		RzILOpFloat *f = x86_il_get_scalar_floating_op(ins->operands[1], (src_fmt), analysis->bits, pc); \
		RzILOpFloat *res = FCONVERT(_dst, RZ_FLOAT_RMODE_RNE, f); \
		return x86_il_set_scalar_floating_op(ins->operands[0], res, _dst, analysis->bits, pc); \
	} while (0)

/**
 * CVTSD2SS
 * Convert a double precision floating point value to a single precision floating point value
 */
IL_LIFTER(cvtsd2ss) {
	SSE_CVT_F2F(RZ_FLOAT_IEEE754_BIN_64, RZ_FLOAT_IEEE754_BIN_32);
}

/**
 * CVTSS2SD
 * Convert a single precision floating point value to a double precision floating point value
 */
IL_LIFTER(cvtss2sd) {
	SSE_CVT_F2F(RZ_FLOAT_IEEE754_BIN_32, RZ_FLOAT_IEEE754_BIN_64);
}

#include <rz_il/rz_il_opbuilder_end.h>
