// SPDX-FileCopyrightText: 2022 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file float.c
 * This file implements IEEE-754 binary float number operations (32/64/128)
 * IEEE binary representations, use binary digits to represent float. machine-friendly
 * binary32 format (single) : use a 32 bits bitvector to represent float
 * 	32 bits = 1 (sign bit) + 8 (exponent bits) + 23 (mantissa bits)
 * 	exponent value range : -126 ~ 127
 * binary64 format (double) : use a 64 bits bitvector to represent float
 *  	64 bits = 1 (sign bit) + 11 (exponent bits) + 52 (mantissa bits)
 * 	exponent value range : -1022 ~ 1023
 * binary128 format, use a 128 bits bitvector to represent float
 *  	128 bits = 1 (sign bit) + 15 (exponent bits) + 112 (mantissa bits)
 * 	exponent value range : -16382 ~ 16383
 **/

#include "float_internal.c"
#include <rz_userconf.h>
#include <math.h>
#include <fenv.h>

/**
 * \defgroup Generate Nan and infinite for float/double/long double
 * @ {
 */
#define define_types_gen_nan(fname, ftype) \
	RZ_API ftype rz_types_gen_##fname##_nan() { \
		static ftype zero = 0; \
		ftype ret = zero / zero; \
		feclearexcept(FE_ALL_EXCEPT); \
		return ret; \
	}

#define define_types_gen_inf(fname, ftype) \
	RZ_API ftype rz_types_gen_##fname##_inf() { \
		static ftype zero = 0; \
		static ftype one = 1.0; \
		ftype ret = one / zero; \
		feclearexcept(FE_ALL_EXCEPT); \
		return ret; \
	}

define_types_gen_nan(f32, float);
define_types_gen_nan(f64, double);
define_types_gen_nan(f128, long double);
define_types_gen_inf(f32, float);
define_types_gen_inf(f64, double);
define_types_gen_inf(f128, long double);
/**@}*/

/**
 * \brief return the bitvector string of a float
 * \param f float
 * \return char* string of bitvector
 */
RZ_API RZ_OWN char *rz_float_as_bit_string(RZ_NULLABLE RzFloat *f) {
	if (!f || !f->s) {
		return NULL;
	}
	return rz_bv_as_string(f->s);
}

/**
 * \brief return the bitvector hex string of a float
 * \param f float
 * \param use_pad use padding before the hex string
 * \return char* hex string of bitvector
 */
RZ_API RZ_OWN char *rz_float_as_hex_string(RZ_NULLABLE RzFloat *f, bool use_pad) {
	if (!f || !f->s) {
		return NULL;
	}
	return rz_bv_as_hex_string(f->s, use_pad);
}

/**
 * \brief return a human-readable string of float
 * \param f float
 * \return a human-readable string of float.
 * exponent part and mantissa part would be split as follows:
 * 'sign' 'exponent part' | 'mantissa part'
 *  1.0f would be shown as +01111111|00000000000000000000000
 */
RZ_API RZ_OWN char *rz_float_as_string(RZ_NULLABLE RzFloat *f) {
	if (!f || !f->s) {
		return NULL;
	}

	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_TOTAL_LEN);

	char *str = (char *)malloc(total + 2);
	if (!str) {
		return NULL;
	}

	ut32 pos = rz_bv_len(f->s) - 1;
	ut32 i;

	str[0] = rz_float_is_negative(f) ? '-' : '+';
	pos -= 1;

	for (i = 0; i < exp_len; ++i) {
		str[1 + i] = rz_bv_get(f->s, pos - i) ? '1' : '0';
	}
	str[1 + exp_len] = '|';

	for (i = 0; i < man_len; ++i) {
		str[exp_len + 2 + i] = rz_bv_get(f->s, pos - exp_len - i) ? '1' : '0';
	}

	str[total + 1] = '\0';
	return str;
}

static int float_exponent(RzFloat *f) {
	RzBitVector *expt = rz_float_get_exponent_squashed(f);
	if (!expt) {
		return 0;
	}
	int value = (int)rz_bv_to_ut32(expt);
	rz_bv_free(expt);
	return value;
}

static bool float_is_mantissa_zero(RzFloat *f) {
	RzBitVector *mantissa = rz_float_get_mantissa_squashed(f);
	if (!mantissa) {
		return false;
	}
	bool is_zero = rz_bv_is_zero_vector(mantissa);
	rz_bv_free(mantissa);
	return is_zero;
}

#define define_cast_to_type(fname, ftype, f_ldexp) \
	static ftype cast_to_##fname(RzFloat *f) { \
		const ftype zero = 0.0; \
		const ftype one = 1.0; \
		const ftype two = 2.0; \
		bool is_negative = rz_float_is_negative(f); \
		if (rz_float_is_inf(f)) { \
			return is_negative ? (one / zero) : (-one / zero); \
		} else if (rz_float_is_nan(f)) { \
			return zero / zero; \
		} else if (rz_float_is_zero(f)) { \
			return zero; \
		} \
		int bias = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_BIAS) - 1; \
		ut32 manl = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN); \
		int exponent = float_exponent(f) - bias; \
		ftype fractional = 0.0; \
		for (ut32 i = 0; i < manl; ++i) { \
			if (rz_bv_get(f->s, i)) { \
				fractional += one; \
			} \
			fractional /= two; \
		} \
		if (!(!float_exponent(f) && !float_is_mantissa_zero(f))) { \
			fractional += one; \
			fractional /= two; \
		} \
		ftype result = f_ldexp(fractional, exponent); \
		return is_negative ? -result : result; \
	}

define_cast_to_type(float, float, ldexpf);
define_cast_to_type(double, double, ldexp);
define_cast_to_type(long_double, long double, ldexpl);

/**
 * \brief return a decimal number (like -1.56) in string form of the float
 * \param f  Float
 * \return   A human-readable decimal in string form of float.
 */
RZ_API RZ_OWN char *rz_float_as_dec_string(RZ_NULLABLE RzFloat *f) {
	if (!f || !f->s) {
		return NULL;
	}

	RzFloatSpec type = rz_float_detect_spec(f);
	switch (type) {
	case RZ_FLOAT_SPEC_ZERO:
		return strdup("0.0");
	case RZ_FLOAT_SPEC_PINF:
		return strdup("+inf");
	case RZ_FLOAT_SPEC_NINF:
		return strdup("-inf");
	case RZ_FLOAT_SPEC_QNAN:
		/* fall-thru */
	case RZ_FLOAT_SPEC_SNAN:
		return strdup("nan");
	default:
		break;
	}

	long double result = 0;
	switch (f->r) {
	case RZ_FLOAT_IEEE754_BIN_32:
		result = cast_to_float(f);
		break;
	case RZ_FLOAT_IEEE754_BIN_64:
		result = cast_to_double(f);
		break;
	case RZ_FLOAT_IEEE754_BIN_80:
		result = cast_to_long_double(f);
		break;
	case RZ_FLOAT_IEEE754_BIN_128:
		result = cast_to_long_double(f);
		break;
	case RZ_FLOAT_IEEE754_DEC_64:
		/* fall-thru */
	case RZ_FLOAT_IEEE754_DEC_128:
		/* fall-thru */
	default:
		RZ_LOG_ERROR("float: string: unsupported format %u\n", f->r);
		return NULL;
	}

	return rz_str_newf("%" LDBLFMTg, result);
}

/*
 * Common NaN and Inf detection
 * */
#define PROC_SPECIAL_FLOAT_START(left, right) \
	{ \
		RzFloatSpec l_type, r_type; \
		l_type = rz_float_detect_spec((left)); \
		r_type = rz_float_detect_spec((right)); \
		bool l_is_inf = (l_type == RZ_FLOAT_SPEC_PINF || l_type == RZ_FLOAT_SPEC_NINF); \
		bool r_is_inf = (r_type == RZ_FLOAT_SPEC_PINF || r_type == RZ_FLOAT_SPEC_NINF); \
		bool l_is_nan = (l_type == RZ_FLOAT_SPEC_SNAN || l_type == RZ_FLOAT_SPEC_QNAN); \
		bool r_is_nan = (r_type == RZ_FLOAT_SPEC_SNAN || r_type == RZ_FLOAT_SPEC_QNAN); \
		bool l_is_zero = l_type == RZ_FLOAT_SPEC_ZERO; \
		bool r_is_zero = r_type == RZ_FLOAT_SPEC_ZERO;

#define PROC_SPECIAL_FLOAT_END }

/**
 * \brief Get const attributes from float
 * \param format RzFloatFormat, format of a float
 * \param which_info Specify an attribute
 * \return ut32 const value bind with `which_info`
 */
RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info) {
	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return rz_float_info_bin32(which_info);
	case RZ_FLOAT_IEEE754_BIN_64:
		return rz_float_info_bin64(which_info);
	case RZ_FLOAT_IEEE754_BIN_80:
		return rz_float_info_bin80(which_info);
	case RZ_FLOAT_IEEE754_BIN_128:
		return rz_float_info_bin128(which_info);
	case RZ_FLOAT_IEEE754_DEC_64:
	case RZ_FLOAT_IEEE754_DEC_128:
	default:
		RZ_LOG_ERROR("float: info: Unsupported format %u\n", format);
		return 0;
	}
}

/**
 * Finish the bv inside the float, and set all to NULL
 * \param f float
 */
RZ_API void rz_float_fini(RZ_NONNULL RzFloat *f) {
	rz_return_if_fail(f);
	rz_bv_free(f->s);
	memset(f, 0, sizeof(RzFloat));
}

/**
 * Destroy the float structure
 * \param f float
 */
RZ_API void rz_float_free(RZ_NULLABLE RzFloat *f) {
	if (!f) {
		return;
	}
	rz_float_fini(f);
	free(f);
}

/**
 * Init the bitvector inside float
 * \param f float
 * \return return true if init success else return false
 */
RZ_API bool rz_float_init(RZ_NONNULL RzFloat *f, RzFloatFormat format) {
	rz_return_val_if_fail(f, false);
	rz_float_fini(f);

	ut32 total = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	f->s = rz_bv_new(total);
	if (!f->s) {
		return false;
	}

	return true;
}

/**
 * Create float and init it
 * \param format float format
 * \return return an RzFloat instance with zero value
 */
RZ_API RZ_OWN RzFloat *rz_float_new(RzFloatFormat format) {
	RzFloat *f = RZ_NEW0(RzFloat);
	if (!f) {
		return NULL;
	}
	f->s = NULL;

	if (!rz_float_init(f, format)) {
		rz_float_free(f);
		return NULL;
	}

	f->r = format;

	return f;
}

/**
 * Duplicate a float
 * \param f float
 * \return a copy of float
 */
RZ_API RZ_OWN RzFloat *rz_float_dup(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	RzFloat *cp = RZ_NEW0(RzFloat);
	if (!cp) {
		RZ_LOG_ERROR("float: dup: Cannot allocate RzFloat\n");
		return NULL;
	}

	cp->r = f->r;
	cp->s = rz_bv_dup(f->s);
	cp->exception = f->exception;

	return cp;
}

#define define_cast_from_value(fname, ftype, f_frexp) \
	static bool cast_from_##fname##_value(RzFloat *f, ftype value) { \
		const ftype zero = 0.0; \
		const ftype one = 1.0; \
		const ftype two = 2.0; \
		bool is_negative = false; \
		if (value <= zero) { \
			is_negative = true; \
			value = -value; \
		} \
		int exponent = 0; \
		ftype fractional = f_frexp(value, &exponent); \
		int bias = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_BIAS) - 1; \
		ut32 expl = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN); \
		ut32 manl = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN); \
		if (exponent <= -bias) { \
			exponent--; \
		} \
		exponent += bias; \
		while (exponent < 0) { \
			/* denormalize */ \
			fractional /= two; \
			exponent++; \
		} \
		for (ut32 i = 0; i < manl && fractional != zero; ++i) { \
			fractional *= two; \
			if (fractional >= one) { \
				fractional -= one; \
				rz_bv_set(f->s, manl - i, true); \
			} \
		} \
		if (roundl(fractional) > 0.5l) { \
			rz_bv_set(f->s, 0, true); \
		} \
		RzBitVector *expbv = rz_bv_new_from_ut64(expl, exponent); \
		if (!expbv) { \
			return false; \
		} \
		rz_bv_copy_nbits(expbv, 0, f->s, manl, expl); \
		rz_bv_free(expbv); \
		rz_bv_set(f->s, f->s->len - 1, is_negative); \
		return true; \
	}

define_cast_from_value(float, float, frexpf);
define_cast_from_value(double, double, frexp);
define_cast_from_value(long_double, long double, frexpl);

/**
 * Set float bv from C type `float`
 * \param f      A normal float
 * \param value  Value of type `float`
 * \return       True if success
 */
RZ_API bool rz_float_set_from_f32(RZ_NONNULL RzFloat *f, float value) {
	rz_return_val_if_fail(f, false);

	// TODO : should we support single float to a given format float ?
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	if (exp_len != 8 || man_len != 23) {
		RZ_LOG_ERROR("float: failed to cast float32 to other float conversion\n");
		return false;
	}

	return cast_from_float_value(f, value);
}

/**
 * Set float bv from C type `double`
 * \param f      A normal float
 * \param value  Value of type `double`
 * \return       True if success
 */
RZ_API bool rz_float_set_from_f64(RZ_NONNULL RzFloat *f, double value) {
	rz_return_val_if_fail(f, false);

	// TODO : should we support double float to a given format float ?
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	if (exp_len != 11 || man_len != 52) {
		RZ_LOG_ERROR("float: failed to cast float64 to other float conversion\n");
		return false;
	}

	return cast_from_double_value(f, value);
}

/**
 * Set float bv from C type `long double`
 * \param f      A normal float
 * \param value  Value of type `long double`
 * \return       True if success
 */
RZ_API bool rz_float_set_from_f80(RZ_NONNULL RzFloat *f, long double value) {
	rz_return_val_if_fail(f, false);

	// TODO : should we support quadruple float to a given format float ?
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	if (exp_len != 15 || man_len != 64) {
		RZ_LOG_ERROR("float: failed to cast float80 to other float conversion\n");
		return false;
	}

	return cast_from_long_double_value(f, value);
}

/**
 * Set float bv from C type `long double`
 * \param f      A normal float
 * \param value  Value of type `long double`
 * \return       True if success
 */
RZ_API bool rz_float_set_from_f128(RZ_NONNULL RzFloat *f, long double value) {
	rz_return_val_if_fail(f, false);

	// TODO : should we support quadruple float to a given format float ?
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	if (exp_len != 15 || man_len != 112) {
		RZ_LOG_ERROR("float: failed to cast float128 to other float conversion\n");
		return false;
	}

	return cast_from_long_double_value(f, value);
}

/**
 * \brief create a float by given the single float value
 * \param value single float value
 * \return RzFloat representation of single float
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_f32(float value) {
	if (isinf(value)) {
		return rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_32, value != F32_PINF);
	} else if (isnan(value)) {
		return rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_32);
	} else if (value == 0) {
		return rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_32);
	}

	RzFloat *f = rz_float_new(RZ_FLOAT_IEEE754_BIN_32);
	if (!f) {
		RZ_LOG_ERROR("float: failed to allocate float32\n");
		return NULL;
	}
	if (!rz_float_set_from_f32(f, value)) {
		RZ_LOG_ERROR("float: failed converting to float32\n");
		rz_float_free(f);
		return NULL;
	}
	return f;
}

/**
 * \brief create a float64 by given the double value
 * \param value  Double value
 * \return       RzFloat representation of double
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_f64(double value) {
	if (isinf(value)) {
		return rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_64, value != F64_PINF);
	} else if (isnan(value)) {
		return rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_64);
	} else if (value == 0) {
		return rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_64);
	}

	RzFloat *f = rz_float_new(RZ_FLOAT_IEEE754_BIN_64);
	if (!f) {
		RZ_LOG_ERROR("float: failed to allocate float64\n");
		return NULL;
	}

	if (!rz_float_set_from_f64(f, value)) {
		RZ_LOG_ERROR("float: failed converting to float64\n");
		rz_float_free(f);
		return NULL;
	}

	return f;
}

/**
 * \brief Create a float80 by given the long double value
 * \param value  Long double value
 * \return       RzFloat representation of long double
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_f80(long double value) {
	if (isinf(value)) {
		return rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_80, value != F128_PINF);
	} else if (isnan(value)) {
		return rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_80);
	} else if (value == 0) {
		return rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_80);
	}

	RzFloat *f = rz_float_new(RZ_FLOAT_IEEE754_BIN_80);
	if (!f) {
		RZ_LOG_ERROR("float: failed to allocate float80\n");
		return NULL;
	}

	if (!rz_float_set_from_f80(f, value)) {
		RZ_LOG_ERROR("float: failed converting to float80\n");
		rz_float_free(f);
		return NULL;
	}

	return f;
}

/**
 * \brief Create a float128 by given the long double value
 * \param value  Long double value
 * \return       RzFloat representation of long double
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_f128(long double value) {
	if (isinf(value)) {
		return rz_float_new_inf(RZ_FLOAT_IEEE754_BIN_128, value != F128_PINF);
	} else if (isnan(value)) {
		return rz_float_new_qnan(RZ_FLOAT_IEEE754_BIN_128);
	} else if (value == 0) {
		return rz_float_new_zero(RZ_FLOAT_IEEE754_BIN_128);
	}

	RzFloat *f = rz_float_new(RZ_FLOAT_IEEE754_BIN_128);
	if (!f) {
		RZ_LOG_ERROR("float: failed to allocate float128\n");
		return NULL;
	}

	if (!rz_float_set_from_f128(f, value)) {
		RZ_LOG_ERROR("float: failed converting to float128\n");
		rz_float_free(f);
		return NULL;
	}

	return f;
}

/**
 * \brief      Tries to convert a bitvector with a fixed size into a float number
 *
 * \param[in]  bv    The bitvector to cast
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_bv(RZ_NONNULL const RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);

	RzFloat *f = NULL;
	switch (bv->len) {
	case 32:
		f = rz_float_new(RZ_FLOAT_IEEE754_BIN_32);
		break;
	case 64:
		f = rz_float_new(RZ_FLOAT_IEEE754_BIN_64);
		break;
	case 80:
		f = rz_float_new(RZ_FLOAT_IEEE754_BIN_80);
		break;
	case 128:
		f = rz_float_new(RZ_FLOAT_IEEE754_BIN_128);
		break;
	default:
		RZ_LOG_ERROR("float: Error in casting bitvector with size %u to float\n", bv->len);
		return NULL;
	}

	if (!f) {
		return NULL;
	}

	rz_bv_copy(bv, f->s);
	return f;
}

/**
 * \brief create RzFloat by giving hex value, most used in writing testcases
 * ref : http://www.jhauser.us/arithmetic/TestFloat-3/doc/TestFloat-general.html
 * \param value 32-bit/64-bit value to represent 32-bit/64-bit bitvector (big endian)
 * \param format float format
 * \return new RzFloat
 */
static RZ_OWN RzFloat *float_new_from_ut64(ut64 value, RzFloatFormat format) {
	RzFloat *ret = NULL;
	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		/* fall-thru */
	case RZ_FLOAT_IEEE754_BIN_64:
		ret = RZ_NEW0(RzFloat);
		if (!ret) {
			RZ_LOG_ERROR("float: Cannot allocate RzFloat\n");
			break;
		}
		ret->r = format;
		ret->s = rz_bv_new_from_ut64(rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN), value);
		break;
	default:
		// could not carry hex value larger than ut64 max
		RZ_LOG_ERROR("float: unsupported float format type %u\n", format);
		break;
	}
	return ret;
}

/**
 * \brief create RzFloat by giving 64-bit hex value, most used in writing testcases
 * \param value 64-bit value to represent 64-bit bitvector (big endian)
 * \return RzFloat-binary64
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_ut64_as_f64(ut64 value) {
	return float_new_from_ut64(value, RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * \brief create RzFloat by giving 32-bit hex value, most used in writing testcases
 * \param value 32-bit value to represent 32-bit bitvector (big endian)
 * \return RzFloat-binary32
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_ut32_as_f32(ut32 value) {
	return float_new_from_ut64(value, RZ_FLOAT_IEEE754_BIN_32);
}

/**
 * \brief Cut out the exponent part of float bitvector, get a bitvector representation of exponent.
 * 	The length is depending on the exponent width (specified by `format`)
 * \param f float
 * \return bitvector representation of exponent part
 */
RZ_API RZ_OWN RzBitVector *rz_float_get_exponent_squashed(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	return get_exp_squashed(f->s, f->r);
}

/**
 * \brief Cut out the mantissa part of float bitvector, get a bitvector representation of mantissa part.
 * 	The length is depending on the mantissa width (specified by `format`)
 * \param f float
 * \return bitvector representation of mantissa part
 */
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_squashed(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	return get_man_squashed(f->s, f->r);
}

/**
 * \brief  Get a bitvector representation of mantissa, twice as long as `bv` length.
 * 	   padding zero before mantissa bits.
 * \param f float number
 * \return bitvector representation of mantissa part with twice the length
 */
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_stretched(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	return get_man_stretched(f->s, f->r);
}

/**
 * \brief Get a bitvector representation of exponent, as long as `bv` length
 * 	  padding zero before squashed exponent bits
 * \param f float number
 * \return bitvector representation of exponent part with the same length of float `bv`
 */
RZ_API RZ_OWN RzBitVector *rz_float_get_exponent(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	return get_exp(f->s, f->r);
}

/**
 * \brief Get a bitvector representation of mantissa, as long as `bv` length
 * \param f float number
 * \return bitvector representation of mantissa part with the same length of float `bv`
 */
RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	return get_man(f->s, f->r);
}

/**
 * \brief Get sign bit of float
 * \param f float num
 * \return bool value of sign bit
 */
RZ_API bool rz_float_is_negative(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, false);
	return get_sign(f->s, f->r);
}

/**
 * \brief alias of rz_float_is_negative, return sign bit
 * \param f float num
 * \return bool value of sign bit
 */
RZ_API bool rz_float_get_sign(RZ_NONNULL RzFloat *f) {
	return rz_float_is_negative(f);
}

/**
 * \brief set sign bit of a given float
 * \param f float num
 * \param new_sign sign bit
 * \return true if success
 */
RZ_API bool rz_float_set_sign(RZ_NONNULL RzFloat *f, bool new_sign) {
	rz_return_val_if_fail(f, false);
	rz_bv_set(f->s, rz_bv_len(f->s) - 1, new_sign);
	return true;
}

/**
 * \brief return the unsigned value of exponent part bitvector, aka biased exp in ieee
 * \param f float
 * \return biased exponent value, as unsigned integer
 */
RZ_API RZ_OWN ut32 rz_float_get_exponent_val(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, 0);
	return float_exponent(f);
}

/**
 * \brief assume float number has the form of (sig * 2^exp), return real exponent
 * \param f float number
 * \return real exponent value (without bias), as unsigned integer
 */
RZ_API RZ_OWN st32 rz_float_get_exponent_val_no_bias(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, 0);
	RzFloatFormat format = f->r;
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ut32 exp = float_exponent(f);
	st32 exp_no_bias = exp == 0 ? (1 - bias) : (exp - bias);

	return exp_no_bias;
}

/**
 * \brief detect special num type of a float
 * \param f float
 * \return RZ_FLOAT_SPEC_NOT if f is not NaN/Zero/Infinity, else return a RzFloatSpec enum
 */
RZ_API RzFloatSpec rz_float_detect_spec(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, RZ_FLOAT_SPEC_NOT);

	RzFloatSpec ret = RZ_FLOAT_SPEC_NOT;
	RzBitVector *exp_squashed = get_exp_squashed(f->s, f->r);
	RzBitVector *mantissa_squashed = get_man_squashed(f->s, f->r);
	bool sign = get_sign(f->s, f->r);

	if (rz_bv_is_all_one(exp_squashed)) {
		// full exp with 0 mantissa -> inf
		if (rz_bv_is_zero_vector(mantissa_squashed)) {
			ret = sign ? RZ_FLOAT_SPEC_NINF : RZ_FLOAT_SPEC_PINF;
		} else {
			// detect signal or quiet nan
			bool is_quiet = rz_bv_msb(mantissa_squashed);
			ret = is_quiet ? RZ_FLOAT_SPEC_QNAN : RZ_FLOAT_SPEC_SNAN;
		}
	}

	if (rz_bv_is_zero_vector(exp_squashed)) {
		if (rz_bv_is_zero_vector(mantissa_squashed))
			ret = RZ_FLOAT_SPEC_ZERO;
	}

	rz_bv_free(exp_squashed);
	rz_bv_free(mantissa_squashed);

	return ret;
}

/**
 * detect if the float number is infinite
 * \param f float
 * \return true if it's an infinity, else false
 */
RZ_API bool rz_float_is_inf(RZ_NONNULL RzFloat *f) {
	RzFloatSpec type = rz_float_detect_spec(f);
	if ((type == RZ_FLOAT_SPEC_PINF) || (type == RZ_FLOAT_SPEC_NINF))
		return true;
	return false;
}

/**
 * detect if the float number is NaN
 * \param f float
 * \return true if it's NaN, else false
 */
RZ_API bool rz_float_is_nan(RZ_NONNULL RzFloat *f) {
	RzFloatSpec type = rz_float_detect_spec(f);
	if ((type == RZ_FLOAT_SPEC_SNAN) || (type == RZ_FLOAT_SPEC_QNAN))
		return true;
	return false;
}

/**
 * detect if the float number is zero
 * \param f  Float
 * \return   True if it's zero, else false
 */
RZ_API bool rz_float_is_zero(RZ_NONNULL RzFloat *f) {
	RzFloatSpec type = rz_float_detect_spec(f);
	return type == RZ_FLOAT_SPEC_ZERO;
}

/**
 * \brief      Compares 2 float numbers allowing imperfect bits
 *
 * \param      x    The float X
 * \param      y    The float Y
 *
 * \return     True if the two floats are equal, otherwise false
 */
RZ_API bool rz_float_is_equal(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y) {
	rz_return_val_if_fail(x && y, false);
	RzBitVector *xb = x->s;
	RzBitVector *yb = y->s;

	if (xb->len != yb->len) {
		rz_warn_if_reached();
		return false;
	}

	for (ut32 i = 1; i < xb->len; ++i) {
		if (rz_bv_get(xb, i) != rz_bv_get(yb, i)) {
			return false;
		}
	}

	return true;
}

static void set_inf(RzFloat *f, bool is_negative) {
	RzBitVector *bv = f->s;
	ut32 exp_start = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set sign bit (MSB), keep mantissa as zero-bv
	rz_bv_set(bv, bv->len - 1, is_negative);
}

static void set_qnan(RzFloat *f) {
	RzBitVector *bv = f->s;
	ut32 exp_start = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set is_quiet to 1
	rz_bv_set(bv, exp_start - 1, true);

	// set sig as non-zero
	rz_bv_set(bv, 0, true);
}

static void set_snan(RzFloat *f) {
	RzBitVector *bv = f->s;
	ut32 exp_start = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set is_quiet to 0 (msb of mantissa part)
	rz_bv_set(bv, exp_start - 1, false);

	// set sig as non-zero
	rz_bv_set(bv, 0, true);
}

/**
 * Sets the float to infinity and specify the sign bit
 * \param f            Float
 * \param is_negative  Sign bit of infinity, negative flag
 * \return             On success returns true, otherwise false
 */
RZ_API bool rz_float_set_from_inf(RZ_NONNULL RzFloat *f, bool is_negative) {
	rz_return_val_if_fail(f, false);
	set_inf(f, is_negative);
	return true;
}

/**
 * Sets the float to zero
 * \param f  Float
 * \return   On success returns true, otherwise false
 */
RZ_API bool rz_float_set_from_zero(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, false);
	return rz_bv_set_all(f->s, false);
}

/**
 * Sets the float to quiet NaN
 * \param f  Float
 * \return   On success returns true, otherwise false
 */
RZ_API bool rz_float_set_from_qnan(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, false);
	set_qnan(f);
	return true;
}

/**
 * Sets the float to signal NaN
 * \param f  Float
 * \return   On success returns true, otherwise false
 */
RZ_API bool rz_float_set_from_snan(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, false);
	set_snan(f);
	return true;
}

/**
 * Generate a infinity float and specify the sign bit
 * \param format       Format of float to generate
 * \param is_negative  Sign bit of infinity, negative flag
 * \return             An infinity float
 */
RZ_API RZ_OWN RzFloat *rz_float_new_inf(RzFloatFormat format, bool is_negative) {
	// gen an Infinite num for return
	RzFloat *ret = rz_float_new(format);
	if (!ret || !ret->s) {
		rz_float_free(ret);
		return NULL;
	}
	set_inf(ret, is_negative);
	return ret;
}

/**
 * Generate a positive zero
 * \param format float format
 * \return zero float
 */
RZ_API RZ_OWN RzFloat *rz_float_new_zero(RzFloatFormat format) {
	return rz_float_new(format);
}

/**
 * Generate a quiet NaN
 * \param format float format
 * \return Quiet NaN float
 */
RZ_API RZ_OWN RzFloat *rz_float_new_qnan(RzFloatFormat format) {
	// gen a quiet NaN for return
	RzFloat *ret = rz_float_new(format);
	if (!ret || !ret->s) {
		rz_float_free(ret);
		return NULL;
	}
	set_qnan(ret);
	return ret;
}

/**
 * Generate a signal NaN
 * \param format float format
 * \return Signal NaN float
 */
RZ_API RZ_OWN RzFloat *rz_float_new_snan(RzFloatFormat format) {
	// gen a signal NaN for return
	RzFloat *ret = rz_float_new(format);
	if (!ret || !ret->s) {
		rz_float_free(ret);
		return NULL;
	}
	set_snan(ret);
	return ret;
}

/**
 * \brief propagate NaN and trigger signal (set exception for a NaN),
 * used in float arithmetic to deal with NaN operand
 */
static RZ_OWN RzFloat *propagate_float_nan(RZ_NONNULL RzFloat *left, RzFloatSpec ltype, RZ_NONNULL RzFloat *right, RzFloatSpec rtype) {
	bool l_is_sig_nan = ltype == RZ_FLOAT_SPEC_SNAN;
	bool r_is_sig_nan = rtype == RZ_FLOAT_SPEC_SNAN;

	// gen a quiet NaN for return
	RzFloatFormat format = left->r;
	RzFloat *ret = rz_float_new(left->r);
	RzBitVector *bv = ret->s;
	ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set is_quiet to 1
	rz_bv_set(bv, exp_start - 1, true);

	// signal an exception
	if (l_is_sig_nan || r_is_sig_nan) {
		ret->exception |= RZ_FLOAT_E_INVALID_OP;
	}

	return ret;
}

/**
 * \brief add magnitude (absolute value)
 */
static RZ_OWN RzFloat *fadd_mag(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, bool sign, RzFloatRMode mode) {
	RzFloat *result = NULL;

	/* Process NaN and Inf cases */
	PROC_SPECIAL_FLOAT_START(left, right)
	// propagate NaN
	if (l_is_nan || r_is_nan) {
		return propagate_float_nan(left, l_type, right, r_type);
	}

	if (l_is_inf || r_is_inf) {
		// inf + inf = inf
		return rz_float_new_inf(left->r, sign);
	}

	if (l_is_zero || r_is_zero) {
		return rz_float_dup(l_is_zero ? right : left);
	}
	PROC_SPECIAL_FLOAT_END

	/* Process normal cases */
	// Extract attribute from format
	RzFloatFormat format = left->r;
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);

	// Extract fields from num
	RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
	RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
	RzBitVector *l_mantissa = get_man(left->s, left->r);
	RzBitVector *r_mantissa = get_man(right->s, right->r);

	if (!l_exp_squashed || !r_exp_squashed || !l_mantissa || !r_mantissa) {
		RZ_LOG_ERROR("float: fadd: Error when parsing RzFloat\n");
		return NULL;
	}

	RzBitVector *l_borrowed_sig = l_mantissa;
	RzBitVector *r_borrowed_sig = r_mantissa;
	RzBitVector *result_sig = NULL;
	RzBitVector *exp_one = rz_bv_new_one(exp_len);
	bool unused;

	// Handle normal float add
	ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
	ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
	st32 exp_diff = (st32)(l_exp_val - r_exp_val);
	ut32 abs_exp_diff = exp_diff;
	ut32 l_borrow_exp_val = l_exp_val;
	ut32 r_borrow_exp_val = r_exp_val;

	// left shift to prevent some tail bits being discard during calculating
	// should reserve 3 bits before mantissa : ABCM MMMM MMMM MMMM ...
	// C : for the hidden significant bit
	// B : carry bit
	// A : a space for possible overflow during rounding
	// M : represent for mantissa bits
	ut32 shift_dist = (exp_len + 1) - 3; // mantissa have (exp_len + sign_len) free bits, and then reserve 3 bits
	ut32 hidden_bit_pos = total_len - 3; // the 3rd bit counted from MSB
	ut32 carry_bit_pos = total_len - 2; // the 2nd bit counted from MSB

	if (exp_diff == 0) {
		// normalized float, hidden bit is 1, recover it in significant
		// 1.MMMM MMMM ...
		if (l_borrow_exp_val != 0) {
			rz_bv_lshift(l_mantissa, shift_dist);
			rz_bv_lshift(r_mantissa, shift_dist);
			rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
			rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
		} else {
			// sub-normal + sub-normal
			// sub-normal float, hidden bit is 0, so we do nothing to sigs
			// 0.MMMM MMMM ...
			// calculate and then pack to return
			result = RZ_NEW0(RzFloat);
			result->r = format;
			result->s = rz_bv_add(left->s, r_mantissa, &unused);
			goto clean;
		}
	} else { // exp_diff != 0
		rz_bv_lshift(l_mantissa, shift_dist);
		rz_bv_lshift(r_mantissa, shift_dist);
		// should align exponent, chose the max(l_exp, r_exp) as final exp
		if (exp_diff < 0) {
			// swap to keep l_exp > r_exp
			l_borrowed_sig = r_mantissa;
			r_borrowed_sig = l_mantissa;
			l_borrow_exp_val = r_exp_val;
			r_borrow_exp_val = l_exp_val;
			abs_exp_diff = -exp_diff;
		}

		// check if the small one (right) is normalized ?
		if (r_borrow_exp_val != 0) {
			// normalized, and then we recover the leading bit 1
			// 1.MMMM MMMM ...
			rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
		} else {
			// sub-normal (or denormalized float) case
			// in IEEE, the value of exp is (1 - bias) for sub-normal, instead of (0 - bias)
			// but we considered it as (0 - bias) when calculate the exp_diff = l_exp_field - r_exp_field
			// we should r-shift (l_exp_field - bias) - (1 - bias) = l_exp_field - 1,
			// but we r-shift (l_exp_field - bias) - (0 - bias) = l_exp_filed
			// thus we need to l-shift 1 bit to fix this incompatible
			rz_bv_lshift(r_borrowed_sig, 1);
		}

		// revealed the hidden bit of the bigger one : 1.MMMM
		rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
		// aligned exponent, and generate sticky bit
		rz_bv_shift_right_jammed(r_borrowed_sig, abs_exp_diff);
	}

	// set result exponent
	ut32 result_exp_val = l_borrow_exp_val;

	// now l_exp == r_exp
	// calculate significant
	result_sig = rz_bv_add(l_borrowed_sig, r_borrowed_sig, &unused);

	if (rz_bv_get(result_sig, carry_bit_pos)) {
		result_exp_val += 1;
	}

	// round
	result = round_float_bv_new(
		sign,
		result_exp_val,
		result_sig,
		format,
		format,
		mode);

// clean
clean:
	rz_bv_free(l_exp_squashed);
	rz_bv_free(l_mantissa);
	rz_bv_free(r_exp_squashed);
	rz_bv_free(r_mantissa);
	rz_bv_free(result_sig);
	rz_bv_free(exp_one);
	return result;
}

/**
 * \brief sub magnitude (absolute value)
 */
static RZ_OWN RzFloat *fsub_mag(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, bool sign, RzFloatRMode mode) {
	RzFloat *result = NULL;

	/* Process NaN and Inf cases */
	PROC_SPECIAL_FLOAT_START(left, right)
	// propagate NaN
	if (l_is_nan || r_is_nan) {
		return propagate_float_nan(left, l_type, right, r_type);
	}

	bool l_sign = rz_float_is_negative(left);
	bool r_sign = rz_float_is_negative(right);
	if (l_is_inf || r_is_inf) {
		if (l_is_inf && r_is_inf) {
			// +inf - inf = NaN
			return rz_float_new_qnan(left->r);
		}
		return l_is_inf ? rz_float_new_inf(left->r, l_sign) : rz_float_new_inf(left->r, r_sign);
	}

	if (l_is_zero || r_is_zero) {
		RzFloat *ret_spec = rz_float_dup(l_is_zero ? right : left);
		if (l_is_zero) {
			rz_bv_set(ret_spec->s, ret_spec->s->len - 1, !r_sign);
		}
		return ret_spec;
	}
	PROC_SPECIAL_FLOAT_END

	// Extract attribute from format
	RzFloatFormat format = left->r;
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);

	// Extract fields from num
	RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
	RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
	RzBitVector *l_mantissa = get_man(left->s, left->r);
	RzBitVector *r_mantissa = get_man(right->s, right->r);

	if (!l_exp_squashed || !r_exp_squashed || !l_mantissa || !r_mantissa) {
		RZ_LOG_ERROR("float: fsub: Error when parsing RzFloat\n");
		rz_bv_free(l_exp_squashed);
		rz_bv_free(r_exp_squashed);
		rz_bv_free(l_mantissa);
		rz_bv_free(r_mantissa);
		return NULL;
	}

	RzBitVector *l_borrowed_sig = l_mantissa;
	RzBitVector *r_borrowed_sig = r_mantissa;
	RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
	bool unused;

	// Handle normal float add
	ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
	ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
	st32 exp_diff = (st32)(l_exp_val - r_exp_val);
	ut32 abs_exp_diff = exp_diff;
	ut32 l_borrow_exp_val = l_exp_val;
	ut32 r_borrow_exp_val = r_exp_val;
	st32 res_exp_val;

	// similar to `add`, but remember that sub would never produce a carry bit
	// we create ABMM MMMM MMMM MMMM ...
	// B : for the leading significant bit
	// A : space
	ut32 shift_dist = (exp_len + 1) - 2; // mantissa have (exp_len + sign_len) free bits, and then reserve 2 bits
	ut32 hidden_bit_pos = total_len - 2; // the 2nd bit counted from MSB

	// if l_exp = r_exp
	if (exp_diff == 0) {
		// compare result
		ut8 sdiff_neg = rz_bv_ule(l_mantissa, r_mantissa);
		ut8 sdiff_pos = rz_bv_ule(r_mantissa, l_mantissa);
		ut8 sig_diff_is_zero = sdiff_neg && sdiff_pos;
		RzBitVector *sig_diff = NULL;
		if (sig_diff_is_zero) {
			// pack to return, exp = 0, sig = 0
			result = RZ_NEW0(RzFloat);
			result->r = format;
			result->s = rz_bv_new_zero(total_len);
			rz_bv_set(result->s, total_len - 1, mode == RZ_FLOAT_RMODE_RTN);
			goto clean;
		}

		// calculate the correct sig diff
		if (sdiff_neg) {
			sign = !sign;
			sig_diff = rz_bv_sub(r_mantissa, l_mantissa, &unused);
		} else {
			sig_diff = rz_bv_sub(l_mantissa, r_mantissa, &unused);
		}

		// normalize sig
		// clz - exp_len - sign_len + 1 (reserve the leading bit) = clz - exp_len
		shift_dist = rz_bv_clz(sig_diff) - exp_len;
		res_exp_val = (st32)(l_exp_val - shift_dist);
		if (res_exp_val < 0) {
			// too tiny after shifting, limit to exp_A
			shift_dist = l_exp_val;
			res_exp_val = 0;
		}
		// normalize sig diff, reveal the hidden bit pos
		rz_bv_lshift(sig_diff, shift_dist);

		result_exp_squashed = rz_bv_new_from_ut64(l_exp_squashed->len, res_exp_val);
		result = RZ_NEW0(RzFloat);
		result->r = format;
		result->s = pack_float_bv(sign, result_exp_squashed, sig_diff, format);

		rz_bv_free(sig_diff);
		goto clean;
	} else {
		rz_bv_lshift(l_mantissa, shift_dist);
		rz_bv_lshift(r_mantissa, shift_dist);
		// l_exp != r_exp
		if (exp_diff < 0) {
			// swap to keep l_exp > r_exp
			l_borrow_exp_val = r_exp_val;
			r_borrow_exp_val = l_exp_val;
			l_borrowed_sig = r_mantissa;
			r_borrowed_sig = l_mantissa;
			abs_exp_diff = -exp_diff;
			sign = !sign;
		}

		// check if the small one (right) is sub-normal ?
		if (r_borrow_exp_val != 0) {
			// normalized, and then we recover the leading bit 1
			// 1.MMMM MMMM ...
			rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
		}

		// revealed the hidden bit of the bigger one : 1.MMMM
		rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
		// aligned exponent, and generate sticky bit
		rz_bv_shift_right_jammed(r_borrowed_sig, abs_exp_diff);
	}

	// result_exp = bigger_exp
	res_exp_val = l_borrow_exp_val;
	// result_sig = bigger_sig - small_sig
	result_sig = rz_bv_sub(l_borrowed_sig, r_borrowed_sig, &unused);

	ut32 borrow_pos = hidden_bit_pos;
	if (!rz_bv_get(result_sig, borrow_pos)) {
		// borrow happens
		res_exp_val -= 1;
	}

	result = round_float_bv_new(
		sign,
		res_exp_val,
		result_sig,
		format,
		format,
		mode);

clean:
	rz_bv_free(l_exp_squashed);
	rz_bv_free(l_mantissa);
	rz_bv_free(r_exp_squashed);
	rz_bv_free(r_mantissa);
	rz_bv_free(result_exp_squashed);
	rz_bv_free(result_sig);

	return result;
}

/**
 * \defgroup rz_float_arithmetic_group Arithmetic Operations
 * implements add, sub, mul, div, fma, rem, sqrt for binary32/binary64/binary128
 * \{
 */

/**
 * calculate \p left + \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_add_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	bool l_sign = rz_float_is_negative(left);
	bool r_sign = rz_float_is_negative(right);
	if (l_sign == r_sign) {
		return fadd_mag(left, right, l_sign, mode);
	}
	return fsub_mag(left, right, l_sign, mode);
}

/**
 * calculate \p left - \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	bool l_sign = rz_float_is_negative(left);
	bool r_sign = rz_float_is_negative(right);
	if (l_sign == r_sign) {
		return fsub_mag(left, right, l_sign, mode);
	}
	return fadd_mag(left, right, l_sign, mode);
}

/**
 * calculate \p left * \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	RzFloat *result = NULL;

	/* Process NaN and Inf cases */
	PROC_SPECIAL_FLOAT_START(left, right)
	// propagate NaN
	if (l_is_nan || r_is_nan) {
		return propagate_float_nan(left, l_type, right, r_type);
	}

	bool l_sign = rz_float_is_negative(left);
	bool r_sign = rz_float_is_negative(right);
	bool spec_sign = l_sign ^ r_sign;

	if (l_is_inf) {
		return r_is_zero ? rz_float_new_qnan(left->r) : rz_float_new_inf(left->r, spec_sign);
	}

	if (r_is_inf) {
		return l_is_zero ? rz_float_new_qnan(left->r) : rz_float_new_inf(left->r, spec_sign);
	}

	if (l_is_zero || r_is_zero) {
		// 0 * x = 0
		return rz_float_new(left->r);
	}
	PROC_SPECIAL_FLOAT_END

	// Extract attribute from format
	RzFloatFormat format = left->r;
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ut32 extra_len = total_len;

	// Extract fields from num
	RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
	RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
	RzBitVector *l_mantissa = get_man_stretched(left->s, left->r);
	RzBitVector *r_mantissa = get_man_stretched(right->s, right->r);
	RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
	bool l_sign = get_sign(left->s, left->r);
	bool r_sign = get_sign(right->s, right->r);
	bool result_sign = l_sign ^ r_sign;

	// Handle normal float multiply
	ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
	ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
	ut32 shift_dist;

	// no biased one
	rz_bv_lshift(l_mantissa, exp_len - 1);
	rz_bv_lshift(r_mantissa, exp_len - 1);

	st32 lexp_nobias = rz_float_get_exponent_val_no_bias(left);
	st32 rexp_nobias = rz_float_get_exponent_val_no_bias(right);
	st32 result_exp_val = lexp_nobias + rexp_nobias;

	// remember we would like to make 01.MM MMMM ... (but leave higher extra bits empty)
	ut32 hidden_bit_pos = total_len - 2;

	// set leading bit
	if (l_exp_val != 0) {
		rz_bv_set(l_mantissa, hidden_bit_pos, true);
	}

	if (r_exp_val != 0) {
		rz_bv_set(r_mantissa, hidden_bit_pos, true);
	}

	// multiplication
	// since operands have 0H.MMMM... form, and 0H.MMMMM...
	// result would be 00XX.MMMM...
	result_sig = rz_bv_mul(l_mantissa, r_mantissa);

	// check if a carry happen, if not, l-shift to force a leading 1
	// check MSB and the bit after MSB
	if (rz_bv_get(result_sig, total_len + extra_len - 3)) {
		// carry case, think about 01.10 * 01.10 => 0001.0010
		// 001X.MMMM... -> 001.0MMMMM..
		result_exp_val += 1;
		rz_bv_shift_right_jammed(result_sig, 1);
	}

	// check result and normalize it if needed
	ut32 clz = rz_bv_clz(result_sig);
	if (clz > 3) {
		// means there are sub normal as factor
		// try shift
		shift_dist = clz - 3;
		if (result_exp_val - (st32)shift_dist < 1 - bias) {
			// too small, represent as sub-normal
			shift_dist = result_exp_val - (1 - bias);
		}
		rz_bv_lshift(result_sig, shift_dist);

		// biased one
		result_exp_val = 0;

		// for those who may be sub-normal, use fake hidden bit for rounding
		// note that result sig has 000H.MMMM... form
		rz_bv_set(result_sig, rz_bv_len(result_sig) - 4, true);
	}
	// others has 0001.MMMM...
	else {
		result_exp_val += bias;
	}

	result = round_float_bv_new(
		result_sign,
		result_exp_val,
		result_sig,
		format,
		format,
		mode);

	rz_bv_free(l_exp_squashed);
	rz_bv_free(r_exp_squashed);
	rz_bv_free(l_mantissa);
	rz_bv_free(r_mantissa);
	rz_bv_free(result_exp_squashed);
	rz_bv_free(result_sig);

	return result;
}

/**
 * \brief calculate \p left / \p right and round the result after, return the result
 * \details
 * Inf / not Inf -> Inf
 * non-0 / 0 -> Inf
 * Inf / Inf -> invalid
 * 0 / 0 -> invalid
 * 0 / not 0 -> 0
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_div_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	RzFloat *result = NULL;

	PROC_SPECIAL_FLOAT_START(left, right)
	bool l_sign = rz_float_is_negative(left);
	bool r_sign = rz_float_is_negative(right);
	bool sign = l_sign ^ r_sign;
	RzFloat *spec_ret = NULL;

	if (l_is_nan || r_is_nan) {
		return rz_float_new_qnan(left->r);
	}

	if (l_is_inf) {
		if (!r_is_inf) {
			return rz_float_new_inf(left->r, sign);
		} else {
			spec_ret = rz_float_new_qnan(left->r);
			spec_ret->exception |= RZ_FLOAT_E_INVALID_OP;
			return spec_ret;
		}
	} else {
		if (r_is_inf) {
			return rz_float_new_zero(left->r);
		}
	}

	if (l_is_zero) {
		if (r_is_zero) {
			spec_ret = rz_float_new_qnan(left->r);
			spec_ret->exception |= RZ_FLOAT_E_INVALID_OP;
			return spec_ret;
		} else {
			return rz_float_new(left->r);
		}
	} else {
		if (r_is_zero) {
			return rz_float_new_inf(left->r, sign);
		}
	}
	PROC_SPECIAL_FLOAT_END

	// Extract attribute from format
	RzFloatFormat format = left->r;
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ut32 extra_len = total_len;

	// Extract fields from num
	RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
	RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
	RzBitVector *l_mantissa = get_man_stretched(left->s, left->r);
	RzBitVector *r_mantissa = get_man_stretched(right->s, right->r);
	RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
	bool l_sign = get_sign(left->s, left->r);
	bool r_sign = get_sign(right->s, right->r);
	bool result_sign = l_sign ^ r_sign;

	// Handle normal float multiply
	ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
	ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
	ut32 shift_dist;

	// normalize sub-normal num
	// similar to multiplication
	if (l_exp_val == 0) {
		// is sub-normal
		shift_dist = rz_bv_clz(l_mantissa) - (1 + exp_len) + 1 - extra_len;
		l_exp_val = 1 - shift_dist;
		rz_bv_lshift(l_mantissa, shift_dist);
	}

	if (r_exp_val == 0) {
		// is sub-normal
		shift_dist = rz_bv_clz(r_mantissa) - (1 + exp_len) + 1 - extra_len;
		r_exp_val = 1 - shift_dist;
		rz_bv_lshift(r_mantissa, shift_dist);
	}

	ut32 result_exp_val = l_exp_val - r_exp_val + bias;

	// remember we would like to make the pattern 01.MM MMMM ...
	shift_dist = (exp_len + 1) - 2;
	ut32 hiddent_bit_pos = total_len - (1 + exp_len);

	// set leading bit
	rz_bv_set(l_mantissa, hiddent_bit_pos, true);
	rz_bv_set(r_mantissa, hiddent_bit_pos, true);

	// shift to make sure left is large enough to div
	// Fx = Mx * 2^x, Fy = My * 2^y
	// we have Mx as 01MM MMMM MMMM ...
	// now expand left operand to have more bits
	// dividend 01MM ..MM 0000 0000 0000 ...
	// divisor  00...0000 01MM MMMM MMMM ...
	rz_bv_lshift(l_mantissa, shift_dist + extra_len);
	rz_bv_lshift(r_mantissa, shift_dist);

	// both dividend and divisor have the form 1.MM...
	// and thus the first bit-1 must be set in
	// a. LSB of extra bits (dividend sig >= divisor sig)
	// b. MSB of original bits (dividend sig < divisor sig)
	// the clz should be 31 or 32 respectively
	result_sig = rz_bv_div(l_mantissa, r_mantissa);
	ut32 clz = rz_bv_clz(result_sig);

	// check if normalization needed
	shift_dist = clz == extra_len ? 1 : 0;

	// Convert to original length bitvector
	// normalize it
	// and make 01MM MMMM MMMM ... format
	rz_bv_shift_right_jammed(result_sig, 2 - shift_dist);

	// dec exp according to normalization
	// exp -= shift
	result_exp_val -= shift_dist;

	if ((st32)result_exp_val < 0) {
		// underflow ?
		result_exp_val = 0;
	}

	result = round_float_bv_new(
		result_sign,
		result_exp_val,
		result_sig,
		format,
		format,
		mode);

	rz_bv_free(l_exp_squashed);
	rz_bv_free(r_exp_squashed);
	rz_bv_free(l_mantissa);
	rz_bv_free(r_mantissa);
	rz_bv_free(result_exp_squashed);
	rz_bv_free(result_sig);

	return result;
}

/**
 * \brief calculate remainder of \p left % \p right and round the result after
 * \details
 * Any % 0 => NaN
 * Inf % Any => NaN, invalid
 * Any % Inf -> Any
 * 0 % Any -> 0
 * \param quo_rnd quotient round mode, fmod use RTZ, frem use RNE
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
static RZ_OWN RzFloat *rz_float_rem_internal(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode quo_rnd, RzFloatRMode mode) {
	PROC_SPECIAL_FLOAT_START(left, right)
	RzFloat *spec_ret = NULL;

	if (l_is_nan || r_is_nan) {
		return rz_float_new_qnan(left->r);
	}

	if (l_is_inf || r_is_zero) {
		spec_ret = rz_float_new_qnan(left->r);
		spec_ret->exception |= RZ_FLOAT_E_INVALID_OP;
		return spec_ret;
	}

	if (r_is_inf) {
		return rz_float_dup(left);
	}

	if (l_is_zero) {
		return rz_float_new_zero(left->r);
	}
	PROC_SPECIAL_FLOAT_END

	// extract info from args
	// left = mx * 2^(ex), right = my * 2^(ey)
	RzBitVector *mx = rz_float_get_mantissa(left);
	RzBitVector *my = rz_float_get_mantissa(right);
	RzBitVector *exp_x = rz_float_get_exponent(left);
	RzBitVector *exp_y = rz_float_get_exponent(right);
	ut32 bias = rz_float_get_format_info(left->r, RZ_FLOAT_INFO_BIAS);
	st32 ex = (st32)(rz_bv_to_ut32(exp_x) - bias);
	st32 ey = (st32)(rz_bv_to_ut32(exp_y) - bias);
	rz_bv_free(exp_x);
	rz_bv_free(exp_y);

	bool sign_x = rz_float_is_negative(left);

	/* quo(-x,-y) = quo(x,y), rem(-x,-y) = -rem(x,y)
	 * quo(-x,y) = -quo(x,y), rem(-x,y)  = -rem(x,y)
	 * thus quo = sign(x/y)*quo(|x|,|y|), rem = sign(x)*rem(|x|,|y|) */
	bool sign_z = sign_x;

	// reveal the hidden bit in IEEE, adjust exponent and mantissa
	ut32 man_len = rz_float_get_format_info(left->r, RZ_FLOAT_INFO_MAN_LEN);

	rz_bv_set(mx, man_len, true);
	ex -= man_len;
	rz_bv_set(my, man_len, true);
	ey -= man_len;

	// every mantissa would become an big integer with clz(num) = 0
	ex -= rz_bv_clz(mx);
	ey -= rz_bv_clz(my);
	rz_bv_lshift(mx, rz_bv_clz(mx));
	rz_bv_lshift(my, rz_bv_clz(my));

	// help flag
	bool tiny = 0;
	st32 compare = false;
	bool quo_is_odd = false;

	// result of rem(x, y)
	RzBitVector *mz = NULL;
	ut32 ez;
	RzFloat *z;

	// make last bit of mantissa is 1
	// TODO : add a scan function to bitvector lib (like clz but cnted from LSB to MSB)
	ut32 k;
	for (k = 0; k < my->len; ++k) {
		if (rz_bv_get(my, k)) {
			break;
		}
	}

	ey += k;
	rz_bv_rshift(my, k);

	// q = x/y = mx/(my*2^(ey-ex))
	if (ex <= ey) {
		// detect magnitude
		ut32 sx = mx->len - rz_bv_clz(mx);
		ut32 sy = my->len - rz_bv_clz(my);
		ut32 mag_level_mx = sx + ex;
		ut32 mag_level_my = sy + ey;

		if (mag_level_mx < mag_level_my) {
			// tiny, quotient = 0, remainder = mx
			tiny = 1;
			z = rz_float_dup(left);
			goto clean;
		} else {
			// mx mod my*2^(ey-ex)
			// construct real number real_my = 2^(ey - ex) * my
			RzBitVector *real_my = rz_bv_prepend_zero(my, my->len);
			rz_bv_lshift(real_my, ey - ex);

			// stretch mx to have the same length for calculation
			RzBitVector *stretched_mx = rz_bv_prepend_zero(mx, mx->len);
			RzBitVector *stretched_mz = rz_bv_mod(stretched_mx, real_my);
			mz = rz_bv_cut_head(stretched_mz, my->len);

			rz_bv_free(real_my);
			rz_bv_free(stretched_mx);
			rz_bv_free(stretched_mz);
		}
	} else {
		// ex > ey
		// preprocess for rounding
		if (quo_rnd == RZ_FLOAT_RMODE_RTN) {
			// let my = my * 2
			rz_bv_lshift(my, 1);
		}

		// r = mx * (2^(ex - ey) mod my) mod my
		// 1. build 2^(ex - ey) bv
		ut32 aligned_length = ex - ey + 1;

		RzBitVector *two_exponent_fact;
		RzBitVector *stretched_my;
		bool is_stretched = false;
		if (aligned_length < my->len) {
			two_exponent_fact = rz_bv_new(my->len);
			stretched_my = rz_bv_dup(my);
		} else {
			is_stretched = true;
			two_exponent_fact = rz_bv_new(aligned_length);
			stretched_my = rz_bv_prepend_zero(my, aligned_length - my->len);
		}
		rz_bv_set(two_exponent_fact, aligned_length - 1, true);

		// 2. mod my for the 1st time
		RzBitVector *fact_mod = rz_bv_mod(two_exponent_fact, stretched_my);

		RzBitVector *mx_fact;
		mx_fact = is_stretched ? rz_bv_cut_head(fact_mod, aligned_length - my->len) : rz_bv_dup(fact_mod);

		// 3. mul with mx, and then mod my
		// mul maybe overflow, so stretch both
		RzBitVector *mx_ext = rz_bv_prepend_zero(mx, mx->len);
		RzBitVector *mx_fact_ext = rz_bv_prepend_zero(mx_fact, mx_fact->len);
		RzBitVector *my_ext = rz_bv_prepend_zero(my, my->len);
		RzBitVector *mul_ext = rz_bv_mul(mx_ext, mx_fact_ext);
		RzBitVector *mz_ext;
		mz_ext = rz_bv_mod(mul_ext, my_ext);
		mz = rz_bv_cut_head(mz_ext, my->len);

		// free temp bv
		rz_bv_free(two_exponent_fact);
		rz_bv_free(stretched_my);
		rz_bv_free(fact_mod);
		rz_bv_free(mx_fact);
		rz_bv_free(mx_ext);
		rz_bv_free(mul_ext);
		rz_bv_free(my_ext);
		rz_bv_free(mz_ext);
		rz_bv_free(mx_fact_ext);

		// rounding
		if (quo_rnd == RZ_FLOAT_RMODE_RTN) {
			// let my = my / 2
			rz_bv_shift_right_jammed(my, 1);
			quo_is_odd = rz_bv_ule(my, mz);
			if (quo_is_odd) {
				// mz = mz - my
				RzBitVector *tmp = rz_bv_sub(mz, my, NULL);
				rz_bv_free(mz);
				mz = tmp;
				tmp = NULL;
			}
		}
	}

	// r == 0, return 0
	if (rz_bv_is_zero_vector(mz)) {
		z = rz_float_new_zero(left->r);
		rz_bv_set(z->s, z->s->len, sign_z);
		goto clean;
	}

	// 2r < y ? round(r) : round(r-my)
	if (quo_rnd == RZ_FLOAT_RMODE_RTN) {
		// r = 2 * r
		rz_bv_lshift(mz, 1);

		if (tiny) {
			// detect magnitude
			ut32 sz = mx->len - rz_bv_clz(mx);
			ut32 sy = my->len - rz_bv_clz(my);
			ut32 mag_level_mz = sz + ex;
			ut32 mag_level_my = sy + ey;

			if (mag_level_mz > mag_level_my) {
				// equal
				compare = 0;
			} else {
				// sz >= ey + sr - ex, shift is safe
				// my * 2^(ey - ex)
				rz_bv_lshift(my, ey - ex);
				compare = rz_bv_cmp(mz, my);
			}
		} else {
			// cmp mz with my
			compare = rz_bv_cmp(mz, my);
		}

		rz_bv_shift_right_jammed(mz, 1);
		if ((compare > 0) ||
			((mode == RZ_FLOAT_RMODE_RTN) && (compare == 0) && (quo_is_odd))) {
			// r = mz - my
			RzBitVector *tmp = rz_bv_sub(mz, my, NULL);
			rz_bv_free(mz);
			mz = tmp;
			tmp = NULL;
		}
	}

	// result exponent
	ez = ex > ey ? ey : ex;

	// normalize
	// make total - clz = man_len + 1, a normalized mz with hidden bit set
	ut32 exp_len = rz_float_get_format_info(left->r, RZ_FLOAT_INFO_EXP_LEN);
	st32 shift_dist = (st32)(rz_bv_clz(mz) - exp_len);
	ez -= shift_dist;
	if (shift_dist < 0) {
		rz_bv_shift_right_jammed(mz, -shift_dist);
	} else {
		rz_bv_lshift(mz, shift_dist);
	}

	// recover IEEE mantissa and exponent
	ez += man_len;
	ez = ez == 1 - bias ? 0 : ez + bias;

	// apply to round_float_bv required format
	// 01 MMMM MMMM ...
	shift_dist = (st32)(exp_len - 1);
	rz_bv_lshift(mz, shift_dist);

	z = round_float_bv_new(
		sign_z,
		ez,
		mz,
		left->r,
		left->r,
		mode);
clean:
	rz_bv_free(mx);
	rz_bv_free(my);
	rz_bv_free(mz);
	return z;
}

/**
 * \brief calculate \p left % \p right and round the result after, return the result
 * \details
 * Any % 0 => NaN
 * Inf % Any => NaN, invalid
 * Any % Inf -> Any
 * 0 % Any -> 0
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	return rz_float_rem_internal(left, right, RZ_FLOAT_RMODE_RNE, mode);
}

/**
 * \brief calculate \p left % \p right and round the result after, return the result
 * \details
 * Any % 0 => NaN
 * Inf % Any => NaN, invalid
 * Any % Inf -> Any
 * 0 % Any -> 0
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_mod_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	return rz_float_rem_internal(left, right, RZ_FLOAT_RMODE_RTZ, mode);
}

/**
 * calculate \p a * \p b + \p c, and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_fma_ieee_bin(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode) {
	// process NaN / Inf
	{
		RzFloatSpec a_type, b_type, c_type;
		a_type = rz_float_detect_spec(a);
		b_type = rz_float_detect_spec(b);
		c_type = rz_float_detect_spec(c);
		bool a_is_inf = (a_type == RZ_FLOAT_SPEC_PINF || a_type == RZ_FLOAT_SPEC_NINF);
		bool b_is_inf = (b_type == RZ_FLOAT_SPEC_PINF || b_type == RZ_FLOAT_SPEC_NINF);
		bool c_is_inf = (c_type == RZ_FLOAT_SPEC_PINF || c_type == RZ_FLOAT_SPEC_NINF);
		bool a_is_nan = (a_type == RZ_FLOAT_SPEC_SNAN || a_type == RZ_FLOAT_SPEC_QNAN);
		bool b_is_nan = (b_type == RZ_FLOAT_SPEC_SNAN || b_type == RZ_FLOAT_SPEC_QNAN);
		bool c_is_nan = (c_type == RZ_FLOAT_SPEC_SNAN || c_type == RZ_FLOAT_SPEC_QNAN);

		bool a_sign = get_sign(a->s, a->r);
		bool b_sign = get_sign(b->s, b->r);
		bool c_sign = get_sign(c->s, c->r);

		// simplified, may not be exactly correct
		if (a_is_nan || b_is_nan || c_is_nan) {
			return rz_float_new_qnan(a->r);
		}

		if (a_is_inf || b_is_inf || c_is_inf) {
			return rz_float_new_inf(a->r, a_is_inf ? a_sign : b_is_inf ? b_sign
										   : c_sign);
		}
	}

	// Extract attribute from format
	RzFloatFormat format = a->r;
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ut32 extra_len = total_len;

	// extra fields from a and b for multiply
	RzBitVector *a_exp_squashed = get_exp_squashed(a->s, a->r);
	RzBitVector *b_exp_squashed = get_exp_squashed(b->s, b->r);
	RzBitVector *a_mantissa = get_man_stretched(a->s, a->r);
	RzBitVector *b_mantissa = get_man_stretched(b->s, b->r);
	RzBitVector *mul_sig = NULL;
	bool a_sign = get_sign(a->s, a->r);
	bool b_sign = get_sign(b->s, b->r);
	bool mul_sign = a_sign ^ b_sign;
	bool res_sign;
	ut32 res_exp_val;
	RzBitVector *res_sig;
	RzFloat *ret_f;

	// Handle normal float multiply
	ut32 a_exp_val = rz_bv_to_ut32(a_exp_squashed);
	ut32 b_exp_val = rz_bv_to_ut32(b_exp_squashed);
	ut32 shift_dist;

	// remember we would like to make 01.MM MMMM ... (but leave higher extra bits empty)
	shift_dist = (exp_len + 1) - 2;
	ut32 hidden_bit_pos = total_len - 2;

	rz_bv_lshift(a_mantissa, shift_dist);
	rz_bv_lshift(b_mantissa, shift_dist);

	st32 aexp_nobias = rz_float_get_exponent_val_no_bias(a);
	st32 bexp_nobias = rz_float_get_exponent_val_no_bias(b);
	st32 mul_exp_val = aexp_nobias + bexp_nobias;

	// set leading bit
	if (a_exp_val != 0) {
		rz_bv_set(a_mantissa, hidden_bit_pos, true);
	}

	if (b_exp_val != 0) {
		rz_bv_set(b_mantissa, hidden_bit_pos, true);
	}

	// multiplication
	mul_sig = rz_bv_mul(a_mantissa, b_mantissa);

	// check if a carry happen, if not, l-shift to force a leading 1
	// check MSB and the bit after MSB
	if (rz_bv_get(mul_sig, total_len + extra_len - 3)) {
		// carry case, think about 01.10 * 01.10 => 0001.0010
		// 001X.MMMM... -> 001.0MMMMM..
		mul_exp_val += 1;
		rz_bv_shift_right_jammed(mul_sig, 1);
	}

	// check result and normalize it if needed
	ut32 clz = rz_bv_clz(mul_sig);
	if (clz > 3) {
		// means there are sub normal as factor
		// try shift
		shift_dist = clz - 3;
		if (mul_exp_val - (st32)shift_dist < 1 - bias) {
			// too small, represent as sub-normal
			shift_dist = mul_exp_val - (1 - bias);
		}
		rz_bv_lshift(mul_sig, shift_dist);

		// biased one
		mul_exp_val = 0;

		// for those who may be sub-normal, use fake hidden bit for rounding
		// note that result sig has 000H.MMMM... form
		rz_bv_set(mul_sig, rz_bv_len(mul_sig) - 4, true);
	}
	// others has 0001.MMMM...
	else {
		mul_exp_val += bias;
	}

	// note that mul sig has 000H.MMMM form
	// addition we have 00H.MMMM form
	rz_bv_lshift(mul_sig, 1);

	// calculating addition
	RzBitVector *c_exp_squashed = get_exp_squashed(c->s, c->r);
	ut32 c_exp_val = rz_bv_to_ut32(c_exp_squashed);
	bool c_sign = get_sign(c->s, c->r);
	RzBitVector *c_mantissa = get_man_stretched(c->s, c->r);

	res_sign = mul_sign;
	if (!c_exp_val) {
		if (rz_bv_is_zero_vector(c_mantissa)) {
			res_exp_val = mul_exp_val - 1;
			res_sig = mul_sig;
			mul_sig = NULL;
			goto round;
		}

		// normalize sub-normal c
		// TODO : create a function - normalize_subnorm
		shift_dist = rz_bv_clz(c_mantissa) - (1 + exp_len) + 1;
		res_exp_val = 1 - shift_dist;
		rz_bv_lshift(c_mantissa, shift_dist);
	}

	// prepare c_sig for addition
	// set hidden bit 1 and shift to construct (00H.M MMMM ...)
	hidden_bit_pos = total_len - 3;
	rz_bv_lshift(c_mantissa, exp_len - 2);
	rz_bv_set(c_mantissa, hidden_bit_pos, true);
	rz_bv_lshift(c_mantissa, extra_len);

	st32 exp_diff_val = (st32)(mul_exp_val - c_exp_val);
	st32 abs_exp_diff_val = exp_diff_val > 0 ? exp_diff_val : -exp_diff_val;
	if (mul_sign == c_sign) {
		// addition
		if (exp_diff_val <= 0) {
			res_exp_val = c_exp_val;
			rz_bv_shift_right_jammed(mul_sig, abs_exp_diff_val);
		} else {
			res_exp_val = mul_exp_val;
			rz_bv_shift_right_jammed(c_mantissa, abs_exp_diff_val);
		}

		// calc
		res_sig = rz_bv_add(mul_sig, c_mantissa, NULL);

		// check if we should normalize when carry
		ut32 new_total_len = rz_bv_len(res_sig);
		if (rz_bv_get(res_sig, new_total_len - 2)) {
			res_exp_val += 1;
			rz_bv_shift_right_jammed(res_sig, 1);
		}
	} else {
		// sub
		if (exp_diff_val < 0) {
			res_sign = c_sign;
			res_exp_val = c_exp_val;
			rz_bv_shift_right_jammed(mul_sig, abs_exp_diff_val);
			res_sig = rz_bv_sub(c_mantissa, mul_sig, NULL);
		} else if (exp_diff_val == 0) {
			res_exp_val = mul_exp_val;
			res_sig = rz_bv_sub(mul_sig, c_mantissa, NULL);
			if (rz_bv_is_zero_vector(res_sig)) {
				goto zero;
			}
			if (rz_bv_msb(res_sig)) {
				// if negative, turn to (+/- absolute val) from 2's complement
				res_sign = !res_sign;
				RzBitVector *tmp = rz_bv_complement_2(res_sig);
				rz_bv_free(res_sig);
				res_sig = tmp;
				tmp = NULL;
			}

		} else {
			// exp_diff > 0
			res_exp_val = mul_exp_val;
			rz_bv_shift_right_jammed(c_mantissa, abs_exp_diff_val);
			res_sig = rz_bv_sub(mul_sig, c_mantissa, NULL);
		}

		// note that we have 00H.MMMMM... form
		shift_dist = rz_bv_clz(res_sig) - 2;
		res_exp_val -= shift_dist;
		if (shift_dist < 0) {
			rz_bv_shift_right_jammed(res_sig, -shift_dist);
		} else {
			rz_bv_lshift(res_sig, shift_dist);
		}
	}

	// drop extra length
	// recovered to original length
	rz_bv_shift_right_jammed(res_sig, extra_len);
	RzBitVector *tmp = rz_bv_cut_head(res_sig, extra_len);
	rz_bv_free(res_sig);
	res_sig = tmp;
	tmp = NULL;

	goto round;

zero:
	// complete zero
	ret_f = rz_float_new(format);
	ret_f->s = rz_bv_new(total_len);
	rz_bv_set(ret_f->s, total_len - 1, mode == RZ_FLOAT_RMODE_RTN);
	goto clean;
round:
	ret_f = round_float_bv_new(
		res_sign,
		res_exp_val,
		res_sig,
		format,
		format,
		mode);
clean:
	rz_bv_free(a_mantissa);
	rz_bv_free(a_exp_squashed);
	rz_bv_free(b_mantissa);
	rz_bv_free(b_exp_squashed);
	rz_bv_free(mul_sig);
	rz_bv_free(c_exp_squashed);
	rz_bv_free(c_mantissa);
	rz_bv_free(res_sig);

	return ret_f;
}

/**
 * calculate the root of \p n, and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_sqrt_ieee_bin(RZ_NONNULL RzFloat *n, RzFloatRMode mode) {
	// Use Newton method now, May Optimize
	RzFloat *eps = rz_float_new_zero(n->r);
	ut32 bias = rz_float_get_format_info(n->r, RZ_FLOAT_INFO_BIAS);
	ut32 man_len = rz_float_get_format_info(n->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 eps_magic = bias - man_len;

	RzBitVector *eps_bv = rz_bv_new_from_ut64(n->s->len, eps_magic);
	rz_bv_lshift(eps_bv, man_len);
	RzFloat *x = rz_float_new_from_bv(eps_bv);
	rz_bv_free(eps_bv);

	while (true) {
		RzFloat *q = rz_float_div_ieee_bin(n, x, mode);
		RzFloat *sum = rz_float_add_ieee_bin(x, q, mode);
		RzFloat *sum_half = rz_half_float(sum);
		RzFloat *abs = rz_float_sub_ieee_bin(x, sum_half, mode);
		rz_make_fabs(abs);

		// abs <= eps, both are positive
		if (rz_bv_ule(abs->s, eps->s)) {
			rz_float_free(q);
			rz_float_free(abs);
			rz_float_free(sum);
			rz_float_free(sum_half);
			break;
		}

		rz_float_free(x);
		x = sum_half;
		sum_half = NULL;

		rz_float_free(q);
		rz_float_free(abs);
		rz_float_free(sum);
		sum = NULL;
		q = NULL;
		abs = NULL;
	}

	rz_float_free(eps);
	return x;
}

/** \} */ // end rz_float_arithmetic_group

/**
 * get the absolute value of given float
 * \param f float
 */
RZ_API RZ_OWN RzFloat *rz_float_abs(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);
	RzFloat *abs = rz_float_dup(f);
	if (rz_float_is_negative(f)) {
		// change sign if negative
		rz_make_fabs(abs);
	}
	return abs;
}

/**
 * Truncate the float and convert to an integer (discard decimal bits)
 * \param f float
 * \return an integer with float type
 */
RZ_API RZ_OWN RzFloat *rz_float_trunc(RZ_NONNULL RzFloat *f) {
	// Round to zero
	rz_return_val_if_fail(f, NULL);
	ut32 exp_val = float_exponent(f);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 max_pt_pos = man_len;
	ut32 bias = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_BIAS);

	if (exp_val < bias) {
		// magnitude < 1.0
		return rz_float_new_zero(f->r);
	}

	ut32 pt_pos;
	ut32 shift_dist = exp_val - bias;
	pt_pos = max_pt_pos <= shift_dist ? max_pt_pos : shift_dist;

	// set mantissa bits after pt_pos as zero
	RzFloat *ret = rz_float_dup(f);
	for (ut32 i = 0; i < max_pt_pos - pt_pos; ++i) {
		rz_bv_set(ret->s, i, false);
	}

	return ret;
}

/**
 * \brief round float to an integral valued float with the same format
 * \detail [fround m x] is the floating-point number closest to [x]
 * rounded to an integral, using the rounding mode [m].
 * \param f float
 * \param mode round mode
 * \return round float
 */
RZ_API RZ_OWN RzFloat *rz_float_round_to_integral(RZ_NONNULL RzFloat *f, RzFloatRMode mode) {
	rz_return_val_if_fail(f, NULL);
	RzFloat *ret;
	RzBitVector *tmp, *rounded;
	ut32 exp = float_exponent(f);
	RzFloatFormat format = f->r;
	bool sign = get_sign(f->s, format);
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	bool is_subnormal = exp == 0;
	st32 exp_no_bias = is_subnormal ? (1 - bias) : (exp - bias);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);

	// rounding float to get an integer means
	// we should try to reserve `exponent` bits of mantissa
	// drop extra bits or append zeros
	// 1.MM..M * 2^exp = 1MM..M * 2^0 (integer)
	bool should_inc = false;
	RzBitVector *sig = rz_float_get_mantissa(f);

	// sub normal one has no hidden bit, others should set to 1
	if (!is_subnormal) {
		rz_bv_set(sig, man_len, true);
	}

	if (exp_no_bias >= 0) {
		// has `exp_no_bias` + 3 + 1 length
		tmp = round_significant(sign, sig, exp_no_bias, mode, &should_inc);
	} else {
		// float 1.M..M * 2^exp, when exp < 0
		// flatten it and we have 0.0..1M..M (|exp|+1 zeros before 1MMM...)
		// set a fake 1 before radix point, and we can use round_significant to round
		ut32 remained_zeros = total_len - man_len - 1;
		RzBitVector *fake_f;
		if (-exp_no_bias > remained_zeros) {
			// prepend
			fake_f = rz_bv_prepend_zero(sig, -exp_no_bias - remained_zeros);
		} else {
			fake_f = rz_bv_dup(sig);
		}
		rz_bv_set(fake_f, rz_bv_len(fake_f) - 1, true);
		tmp = round_significant(sign, fake_f, 0, mode, &should_inc);

		// unset the fake 1 in tmp
		// tmp has 3 + 1 + precision = 4
		rz_bv_set(tmp, 0, false);
		rz_bv_free(fake_f);
	}
	rz_bv_free(sig);
	sig = NULL;

	// rounded result, rounded has (3 + 1 + precision) length
	if (should_inc) {
		// WARN: possible overflow => no enough length
		RzBitVector *bv_one;
		bv_one = rz_bv_new_one(rz_bv_len(tmp));
		rounded = rz_bv_add(tmp, bv_one, NULL);
		rz_bv_free(bv_one);
	} else {
		rounded = rz_bv_dup(tmp);
	}
	rz_bv_free(tmp);
	tmp = NULL;

	// now we have an integer bitv, convert it to significant
	// 0001 MMMM = 1.MMMM * 2^4
	st32 integral_exp_val = rz_bv_len(rounded) - rz_bv_clz(rounded) - 1;
	if (integral_exp_val < 0) {
		// -1, means rounded is all zero
		ret = rz_float_new_zero(format);
		rz_float_set_sign(ret, sign);

		rz_bv_free(rounded);
		return ret;
	}
	RzBitVector *integeral_exp = rz_bv_new_from_ut64(32, integral_exp_val + bias);

	if (man_len > integral_exp_val) {
		sig = rz_bv_append_zero(rounded, man_len - integral_exp_val);
		rz_bv_free(rounded);
		rounded = NULL;
	} else {
		// right shift zero bits
		rz_bv_rshift(rounded, integral_exp_val - man_len);
		sig = rounded;
		rounded = NULL;
	}

	ret = RZ_NEW0(RzFloat);
	if (!ret) {
		rz_bv_free(integeral_exp);
		rz_bv_free(sig);
		return ret;
	}

	ret->r = format;
	ret->s = pack_float_bv(sign, integeral_exp, sig, format);

	rz_bv_free(integeral_exp);
	rz_bv_free(sig);
	return ret;
}

/**
 * cast_float s m x is the closest to x floating number of sort s.
 * The bitvector x is interpreted as an unsigned integer in the two-complement form.
 * \param bv integer represented in bitvector
 * \param format float format
 * \param mode rounding mode
 * \return closest float of given integer
 */
RZ_API RZ_OWN RzFloat *rz_float_cast_float(RZ_NONNULL RzBitVector *bv, RzFloatFormat format, RzFloatRMode mode) {
	rz_return_val_if_fail(bv, NULL);
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ut32 exp_max_no_bias = bias;

	ut32 width = rz_bv_len(bv) - rz_bv_clz(bv);
	ut32 order = width - 1;
	if (order > exp_max_no_bias) {
		// error: not representable
		return rz_float_new_inf(format, 0);
	}

	// unsigned bv, as positive one
	RzFloat *cast_float = rz_float_round_bv_and_pack(0, order + bias, bv, format, mode);
	return cast_float;
}

/**
 * cast_sfloat s rm x is the closest to x floating-point number of sort x.
 * The bitvector x is interpreted as a signed integer in the two-complement form.
 * \param bv integer represented in bitvector, signed one in 2's complement
 * \param format format of float
 * \param mode rounding mode
 * \return float closest to given integer
 */
RZ_API RZ_OWN RzFloat *rz_float_cast_sfloat(RZ_NONNULL RzBitVector *bv, RzFloatFormat format, RzFloatRMode mode) {
	rz_return_val_if_fail(bv, NULL);

	RzBitVector *bv_abs;

	// make absolute value if neg
	bool sign = rz_bv_msb(bv);
	bv_abs = sign ? rz_bv_complement_2(bv) : rz_bv_dup(bv);

	RzFloat *cast_float = rz_float_cast_float(bv_abs, format, mode);
	rz_bv_free(bv_abs);

	if (!cast_float) {
		return NULL;
	}

	// set sign of float
	rz_float_set_sign(cast_float, sign);
	return cast_float;
}

/**
 * cast_int s rm x returns an integer closest to x.
 * The resulting bitvector should be interpreted as an unsigned two-complement integer.
 * \param f float
 * \param length length of returned bitvector
 * \param mode rounding mode
 * \return unsigned bitvector converted from f
 */
RZ_API RZ_OWN RzBitVector *rz_float_cast_int(RZ_NONNULL RzFloat *f, ut32 length, RzFloatRMode mode) {
	rz_return_val_if_fail(f, NULL);
	return rz_float_cast_sint(f, length, mode);
}

/**
 * cast_sint s rm x returns an integer closest to x.
 * The resulting bitvector should be interpreted as a signed two-complement integer.
 * \param f float
 * \param length length of returnded bitvector
 * \param mode rounding mode
 * \return signed bitvector in 2's complement
 */
RZ_API RZ_OWN RzBitVector *rz_float_cast_sint(RZ_NONNULL RzFloat *f, ut32 length, RzFloatRMode mode) {
	rz_return_val_if_fail(f, NULL);

	RzBitVector *ret = rz_bv_new(length);
	RzBitVector *tmp, *rounded;
	ut32 exp = float_exponent(f);
	RzFloatFormat format = f->r;
	bool sign = get_sign(f->s, format);
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	bool is_subnormal = exp == 0;
	st32 exp_no_bias = is_subnormal ? (1 - bias) : (exp - bias);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);

	// rounding float to get an integer means
	// we should try to reserve `exponent` bits of mantissa
	// drop extra bits or append zeros
	// 1.MM..M * 2^exp = 1MM..M * 2^0 (integer)
	bool should_inc = false;
	RzBitVector *sig = rz_float_get_mantissa(f);

	// sub normal one has no hidden bit, others should set to 1
	if (!is_subnormal) {
		rz_bv_set(sig, man_len, true);
	}

	if (exp_no_bias >= 0) {
		// has `exp_no_bias` + 3 + 1 length
		tmp = round_significant(sign, sig, exp_no_bias, mode, &should_inc);
	} else {
		// float 1.M..M * 2^exp, when exp < 0
		// flatten it and we have 0.0..1M..M (|exp|+1 zeros before 1MMM...)
		// set a fake 1 before radix point, and we can use round_significant to round
		ut32 remained_zeros = total_len - man_len - 1;
		RzBitVector *fake_f;
		if (-exp_no_bias > remained_zeros) {
			// prepend
			fake_f = rz_bv_prepend_zero(sig, -exp_no_bias - remained_zeros);
		} else {
			fake_f = rz_bv_dup(sig);
		}
		rz_bv_set(fake_f, rz_bv_len(fake_f) - 1, true);
		tmp = round_significant(sign, fake_f, 0, mode, &should_inc);

		// unset the fake 1 in tmp
		// tmp has 3 + 1 + precision = 4
		rz_bv_set(tmp, 0, false);
		rz_bv_free(fake_f);
	}
	rz_bv_free(sig);
	sig = NULL;

	// rounded result
	if (should_inc) {
		// WARN: possible overflow => no enough length
		RzBitVector *bv_one;
		bv_one = rz_bv_new_one(rz_bv_len(tmp));
		rounded = rz_bv_add(tmp, bv_one, NULL);
		rz_bv_free(bv_one);
	} else {
		rounded = rz_bv_dup(tmp);
	}
	rz_bv_free(tmp);
	tmp = NULL;

	// assume we r handling absolute value
	// now for negative, convert it to 2's complement
	if (sign) {
		// to keep it an negative, make ret all set to bit 1
		rz_bv_toggle_all(ret);
		tmp = rz_bv_complement_2(rounded);
		rz_bv_free(rounded);
		rounded = tmp;
		tmp = NULL;
	}

	// WARN: possible overflow if length < exp_no_bias
	// WARN: higher bits may be cut off
	rz_bv_copy_nbits(rounded, 0, ret, 0, rz_bv_len(rounded));
	rz_bv_free(rounded);
	return ret;
}

/**
 * convert float from format A to a new format B
 * \param f float
 * \param format new format
 * \param mode rounding mode
 * \return converted float with format B
 */
RZ_API RZ_OWN RzFloat *rz_float_convert(RZ_NONNULL RzFloat *f, RzFloatFormat format, RzFloatRMode mode) {
	rz_return_val_if_fail(f, NULL);

	if (rz_float_is_nan(f)) {
		return rz_float_new_qnan(format);
	}

	if (rz_float_is_inf(f)) {
		return rz_float_new_inf(format, rz_float_get_sign(f));
	}

	if (rz_float_is_zero(f)) {
		RzFloat *ret_zero = rz_float_new_zero(format);
		rz_float_set_sign(ret_zero, rz_float_get_sign(f));
		return ret_zero;
	}

	ut32 exp = float_exponent(f);
	RzFloatFormat old_format = f->r;
	bool sign = get_sign(f->s, old_format);
	ut32 man_len = rz_float_get_format_info(old_format, RZ_FLOAT_INFO_MAN_LEN);

	// recover hidden bit if it's a normal float
	// for sub-normal, we also set a fake hidden bit 1 to use round_float
	RzBitVector *sig = rz_float_get_mantissa(f);
	rz_bv_set(sig, man_len, 1);

	// shift to make significant a integer
	// 1.MM..M * 2^exp_no_bias == 1MM..M * 2^(exp_no_bias - man_len)
	// 0.MM..M * 2^exp_no_bias == 00..1X..X * 2^(exp_no_bias - man_len)
	RzFloat *ret = round_float_bv_new(sign, exp, sig, old_format, format, mode);

	rz_bv_free(sig);
	return ret;
}

/**
 * calculate \p left + \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_add(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	return rz_float_add_ieee_bin(x, y, mode);
}

/**
 * calculate \p left - \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_sub(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	return rz_float_sub_ieee_bin(x, y, mode);
}

/**
 * calculate \p left * \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_mul(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	return rz_float_mul_ieee_bin(x, y, mode);
}

/**
 * \brief calculate \p left / \p right and round the result after, return the result
 * \details
 * Inf / not Inf -> Inf
 * non-0 / 0 -> Inf
 * Inf / Inf -> invalid
 * 0 / 0 -> invalid
 * 0 / not 0 -> 0
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_div(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	return rz_float_div_ieee_bin(x, y, mode);
}

/**
 * \brief calculate \p left % \p right and round the result after, return the result
 * \details
 * Any % 0 => NaN
 * Inf % Any => NaN, invalid
 * Any % Inf -> Any
 * 0 % Any -> 0
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_rem(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	return rz_float_rem_ieee_bin(x, y, mode);
}

/**
 * \brief calculate \p left % \p right and round the result after, return the result
 * \details
 * Any % 0 => NaN
 * Inf % Any => NaN, invalid
 * Any % Inf -> Any
 * 0 % Any -> 0
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_mod(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y, RzFloatRMode mode) {
	return rz_float_mod_ieee_bin(x, y, mode);
}

/**
 * calculate \p a * \p b + \p c, and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_fma(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode) {
	return rz_float_fma_ieee_bin(a, b, c, mode);
}

/**
 * calculate the root of \p n, and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_sqrt(RZ_NONNULL RzFloat *n, RzFloatRMode mode) {
	return rz_float_sqrt_ieee_bin(n, mode);
}

/**
 * get the negative one of given float
 * BAP ref: val fneg : 'f float -> 'f float
 * \param f float number
 * \return negative float `f`
 */
RZ_API RZ_OWN RzFloat *rz_float_neg(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);

	RzFloat *ret = rz_float_dup(f);
	rz_bv_toggle(ret->s, rz_bv_len(ret->s) - 1);

	return ret;
}

/**
 * get least floating-point number representable in (sort x) that is greater than given float
 * BAP ref: val fsucc : 'f float -> 'f float
 * \param f float number
 * \return next float number (least number that is greater than current)
 */
RZ_API RZ_OWN RzFloat *rz_float_succ(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);

	ut32 len = rz_bv_len(f->s);
	RzBitVector *bv = rz_bv_dup(f->s);
	RzBitVector *one = rz_bv_new_one(len);
	RzBitVector *bv_next;
	RzFloat *ret = NULL;
	if (rz_float_is_negative(f)) {
		// neg succ is x - unit(1)
		bv_next = rz_bv_sub(bv, one, NULL);
	} else {
		// pos succ is x + unit(1)
		bv_next = rz_bv_add(bv, one, NULL);
	}

	ret = rz_float_new_from_bv(bv_next);

	rz_bv_free(one);
	rz_bv_free(bv);
	rz_bv_free(bv_next);

	return ret;
}

/**
 * get greatest floating-point number representable in (sort x) that is less than given float
 * BAP ref: fpred : 'f float -> 'f float
 * \param f float number
 * \return previous float number (greatest number that is less than current)
 */
RZ_API RZ_OWN RzFloat *rz_float_pred(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, NULL);

	ut32 len = rz_bv_len(f->s);
	RzBitVector *bv = rz_bv_dup(f->s);
	RzBitVector *one = rz_bv_new_one(len);
	RzBitVector *bv_next;
	RzFloat *ret = NULL;
	if (rz_float_is_negative(f)) {
		// neg pred is x + unit(1)
		bv_next = rz_bv_add(bv, one, NULL);
	} else {
		// pos pred is x - unit(1)
		bv_next = rz_bv_sub(bv, one, NULL);
	}

	ret = rz_float_new_from_bv(bv_next);

	rz_bv_free(one);
	rz_bv_free(bv);
	rz_bv_free(bv_next);

	return ret;
}

/**
 * compare two float number, if
 * used for forder val forder : 'f float -> 'f float -> bool
 * \param x float number
 * \param y float number
 * \return 1 if x > y, 0 if x == y, -1 if x < y
 */
RZ_API RZ_OWN st32 rz_float_cmp(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y) {
	rz_return_val_if_fail(x && y, -2);

	RZ_BORROW RzBitVector *x_bv = rz_bv_dup(x->s);
	RZ_BORROW RzBitVector *y_bv = rz_bv_dup(y->s);

	bool x_sign = rz_bv_msb(x_bv);
	bool y_sign = rz_bv_msb(y_bv);
	st32 cmp;

	if (rz_bv_eq(x_bv, y_bv)) {
		rz_bv_free(x_bv);
		rz_bv_free(y_bv);
		return 0;
	}

	if (x_sign == y_sign) {
		cmp = rz_bv_ule(x_bv, y_bv) ? -1 : 1;
		if (x_sign) {
			// negative
			cmp = -cmp;
		}
	} else {
		cmp = rz_bv_ule(x_bv, y_bv) ? 1 : -1;
	}

	rz_bv_free(x_bv);
	rz_bv_free(y_bv);
	return cmp;
}

/**
 * \brief packer of round_significant
 * \details detect if should drop extra tailing bits in rounding
 * GRS konwn as G(guard bit), R(round bit), and S(sticky bit)
 * they are 3 bits after the LSB bit of rounded result, which is drop in rounding
 * \param sign sign of given significant bitvector, 1 is negative
 * \param sig bitvector, required to have 0..01M..M form, exponent is managed by caller
 * assumption1: radix point is right after 1, that means the real value of such a bitvector is 1.MMM..M
 * assumption2: `sig` is an unsigned bitvector
 * \param precision number of how many `M` bits to be reserved in rounding
 * \param mode rounding mode
 * \param should_inc pointer to a bool:
 * 0 if drop GRS,
 * 1 means caller should round by adding ULP to `return bitv`
 * \return new bitvector would be 0001MM...M, which length is `precision + 1 + 3`
 */
RZ_API RZ_OWN RzBitVector *rz_float_round_significant(bool sign, RzBitVector *sig, ut32 precision, RzFloatRMode mode, bool *should_inc) {
	return round_significant(sign, sig, precision, mode, should_inc);
}

/**
 * \brief packer of round_float_bv_new
 * \details new version of rounding
 * this function is a wrapper of round_significant, it manage the rounded result and exponent change
 * |f| = sig * 2^exp_no_bias
 * TODO : report exception
 * TODO : test and then replace the old version
 * \param sign sign of bitvector
 * \param exp exponent value, biased one
 * \param sig significant, expect unsigned bitvector, treated as integer
 * \param format format of float type
 * \param mode rounding mode
 * \return a float of type `format`, converted from `sig`
 */
RZ_API RZ_OWN RzFloat *rz_float_round_bv_and_pack(bool sign, st32 exp, RzBitVector *sig, RzFloatFormat format, RzFloatRMode mode) {
	return round_float_bv_new(sign, exp, sig, format, format, mode);
}
