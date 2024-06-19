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
#include <softfloat.h>

/**
 * \defgroup Generate Nan and infinite for float/double/long double
 * @ {
 */
#define define_types_gen_nan(fname, ftype) \
	RZ_API ftype rz_types_gen_##fname##_nan() { \
		/* The static modifier is on purpose and necessary for all compilers \
		 * to avoid optimizing them and generate NaN values portably */ \
		static ftype zero = 0; \
		ftype ret = zero / zero; \
		feclearexcept(FE_ALL_EXCEPT); \
		return ret; \
	}

#define define_types_gen_inf(fname, ftype) \
	RZ_API ftype rz_types_gen_##fname##_inf() { \
		/* The static modifier is on purpose and necessary for all compilers \
		 * to avoid optimizing them and generate INF values portably */ \
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

/** \defgroup Helper utilities to inter-operate with SoftFloat.
 * @ {
 */
static inline float32_t to_float32(RzFloat *f32) {
	rz_warn_if_fail(f32->r == RZ_FLOAT_IEEE754_BIN_32);
	float32_t ret = {
		.v = rz_bv_to_ut32(f32->s)
	};
	return ret;
}

static inline float64_t to_float64(RzFloat *f64) {
	rz_warn_if_fail(f64->r == RZ_FLOAT_IEEE754_BIN_64);
	float64_t ret = {
		.v = rz_bv_to_ut64(f64->s)
	};
	return ret;
}

static inline extFloat80_t to_float80(RzFloat *f80) {
	rz_warn_if_fail(f80->r == RZ_FLOAT_IEEE754_BIN_80);

	extFloat80_t ret;
	ret.signif = rz_bv_to_ut64(f80->s);

	ut16 upper = 0;
	for (ut8 i = 0; i < 16; i++) {
		upper <<= 1;
		upper |= rz_bv_get(f80->s, 80 - i - 1);
	}
	ret.signExp = upper;

	return ret;
}

static inline float128_t to_float128(RzFloat *f128) {
	rz_warn_if_fail(f128->r != RZ_FLOAT_IEEE754_BIN_128);

	float128_t ret;
	ret.v[0] = rz_bv_to_ut64(f128->s);

	ut64 upper = 0;
	for (ut8 i = 0; i < 64; i++) {
		upper <<= 1;
		upper |= rz_bv_get(f128->s, 128 - i - 1);
	}
	ret.v[1] = upper;

	return ret;
}

static inline RzFloat *set_exception_flags(RzFloat *f) {
	if (softfloat_exceptionFlags & softfloat_flag_inexact) {
		f->exception |= RZ_FLOAT_E_INEXACT;
	}
	if (softfloat_exceptionFlags & softfloat_flag_underflow) {
		f->exception |= RZ_FLOAT_E_UNDERFLOW;
	}
	if (softfloat_exceptionFlags & softfloat_flag_overflow) {
		f->exception |= RZ_FLOAT_E_OVERFLOW;
	}
	if (softfloat_exceptionFlags & softfloat_flag_infinite) {
		f->exception |= RZ_FLOAT_E_DIV_ZERO;
	}
	if (softfloat_exceptionFlags & softfloat_flag_invalid) {
		f->exception |= RZ_FLOAT_E_INVALID_OP;
	}

	softfloat_exceptionFlags = 0;
	return f;
}

static inline RzFloat *of_float32(float32_t f32) {
	RzFloat *ret = rz_float_new(RZ_FLOAT_IEEE754_BIN_32);

	rz_bv_set_from_ut64(ret->s, f32.v);
	return set_exception_flags(ret);
}

static inline RzFloat *of_float64(float64_t f64) {
	RzFloat *ret = rz_float_new(RZ_FLOAT_IEEE754_BIN_64);

	rz_bv_set_from_ut64(ret->s, f64.v);
	return set_exception_flags(ret);
}

static inline RzFloat *of_float80(extFloat80_t f80) {
	RzFloat *ret = rz_float_new(RZ_FLOAT_IEEE754_BIN_80);

	rz_bv_set_from_ut64(ret->s, f80.signif);

	ut16 upper = f80.signExp;
	for (ut8 i = 0; i < 16; i++) {
		rz_bv_set(ret->s, 64 + i, upper & 1);
		upper >>= 1;
	}

	return set_exception_flags(ret);
}

static inline RzFloat *of_float128(float128_t f128) {
	RzFloat *ret = rz_float_new(RZ_FLOAT_IEEE754_BIN_128);

	rz_bv_set_from_ut64(ret->s, f128.v[0]);

	ut64 upper = f128.v[1];
	for (ut8 i = 0; i < 64; i++) {
		rz_bv_set(ret->s, 64 + i, upper & 1);
		upper >>= 1;
	}

	return set_exception_flags(ret);
}

static int8_t rounding_mode_mapping[] = {
	[RZ_FLOAT_RMODE_RNE] = softfloat_round_near_even,
	[RZ_FLOAT_RMODE_RNA] = softfloat_round_near_maxMag,
	[RZ_FLOAT_RMODE_RTP] = softfloat_round_max,
	[RZ_FLOAT_RMODE_RTN] = softfloat_round_min,
	[RZ_FLOAT_RMODE_RTZ] = softfloat_round_minMag,
	[RZ_FLOAT_RMODE_UNK] = 6,
};

static inline void set_float_rounding_mode(RzFloatRMode mode) {
	softfloat_roundingMode = rounding_mode_mapping[mode];
}
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
		if (f->r == RZ_FLOAT_IEEE754_BIN_80) { \
			/* Special case, see [rz_float_info_bin80] for more. */ \
			manl--; \
		} \
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
	case RZ_FLOAT_IEEE754_BIN_16:
		return rz_float_info_bin16(which_info);
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
		/* manbv is the significand's bitvector. */ \
		RzBitVector *manbv = rz_bv_new_from_ut64(manl + 1, 0); \
		if (!manbv) { \
			return false; \
		} \
		for (ut32 i = 0; i < manl && fractional != zero; ++i) { \
			fractional *= two; \
			if (fractional >= one) { \
				fractional -= one; \
				rz_bv_set(manbv, manl - i, true); \
			} \
		} \
		if (roundl(fractional) > 0.5l) { \
			rz_bv_set(manbv, 0, true); \
		} \
		RzBitVector *expbv = rz_bv_new_from_ut64(expl, exponent); \
		if (!expbv) { \
			return false; \
		} \
		rz_bv_free(f->s); \
		f->s = pack_float_bv(is_negative, expbv, manbv, f->r); \
		rz_bv_free(manbv); \
		rz_bv_free(expbv); \
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
	case 16:
		f = rz_float_new(RZ_FLOAT_IEEE754_BIN_16);
		break;
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
	rz_return_val_if_fail(left && right && left->r == right->r, NULL);

	RzFloatFormat format = left->r;
	set_float_rounding_mode(mode);

	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return of_float32(f32_add(to_float32(left), to_float32(right)));
	case RZ_FLOAT_IEEE754_BIN_64:
		return of_float64(f64_add(to_float64(left), to_float64(right)));
	case RZ_FLOAT_IEEE754_BIN_80:
		return of_float80(extF80_add(to_float80(left), to_float80(right)));
	case RZ_FLOAT_IEEE754_BIN_128:
		return of_float128(f128_add(to_float128(left), to_float128(right)));
	default:
		RZ_LOG_ERROR("float: ADD operation unimplemented for format %d\n", format);
		return NULL;
	}
}

/**
 * calculate \p left - \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	rz_return_val_if_fail(left && right && left->r == right->r, NULL);

	RzFloatFormat format = left->r;
	set_float_rounding_mode(mode);

	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return of_float32(f32_sub(to_float32(left), to_float32(right)));
	case RZ_FLOAT_IEEE754_BIN_64:
		return of_float64(f64_sub(to_float64(left), to_float64(right)));
	case RZ_FLOAT_IEEE754_BIN_80:
		return of_float80(extF80_sub(to_float80(left), to_float80(right)));
	case RZ_FLOAT_IEEE754_BIN_128:
		return of_float128(f128_sub(to_float128(left), to_float128(right)));
	default:
		RZ_LOG_ERROR("float: SUB operation unimplemented for format %d\n", format);
		return NULL;
	}
}

/**
 * calculate \p left * \p right and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_API RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	rz_return_val_if_fail(left && right && left->r == right->r, NULL);

	RzFloatFormat format = left->r;
	set_float_rounding_mode(mode);

	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return of_float32(f32_mul(to_float32(left), to_float32(right)));
	case RZ_FLOAT_IEEE754_BIN_64:
		return of_float64(f64_mul(to_float64(left), to_float64(right)));
	case RZ_FLOAT_IEEE754_BIN_80:
		return of_float80(extF80_mul(to_float80(left), to_float80(right)));
	case RZ_FLOAT_IEEE754_BIN_128:
		return of_float128(f128_mul(to_float128(left), to_float128(right)));
	default:
		RZ_LOG_ERROR("float: MUL operation unimplemented for format %d\n", format);
		return NULL;
	}
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
	rz_return_val_if_fail(left && right && left->r == right->r, NULL);

	RzFloatFormat format = left->r;
	set_float_rounding_mode(mode);

	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return of_float32(f32_div(to_float32(left), to_float32(right)));
	case RZ_FLOAT_IEEE754_BIN_64:
		return of_float64(f64_div(to_float64(left), to_float64(right)));
	case RZ_FLOAT_IEEE754_BIN_80:
		return of_float80(extF80_div(to_float80(left), to_float80(right)));
	case RZ_FLOAT_IEEE754_BIN_128:
		return of_float128(f128_div(to_float128(left), to_float128(right)));
	default:
		RZ_LOG_ERROR("float: DIV operation unimplemented for format %d\n", format);
		return NULL;
	}
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
 *
 * Can be positive or negative. Range: [ -abs(right)/2, abs(right)/2 ]
 */
RZ_API RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	rz_return_val_if_fail(left && right && left->r == right->r, NULL);

	RzFloatFormat format = left->r;
	set_float_rounding_mode(mode);

	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return of_float32(f32_rem(to_float32(left), to_float32(right)));
	case RZ_FLOAT_IEEE754_BIN_64:
		return of_float64(f64_rem(to_float64(left), to_float64(right)));
	case RZ_FLOAT_IEEE754_BIN_80:
		return of_float80(extF80_rem(to_float80(left), to_float80(right)));
	case RZ_FLOAT_IEEE754_BIN_128:
		return of_float128(f128_rem(to_float128(left), to_float128(right)));
	default:
		RZ_LOG_ERROR("float: REM operation unimplemented for format %d\n", format);
		return NULL;
	}
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
 *
 * Mod is guaranteed to be of the same sign as \p left.
 * Range:
 * 		- [ 0, abs(right) )		if left >= 0
 * 		- ( -abs(right), 0 ]	if left <= 0
 */
RZ_API RZ_OWN RzFloat *rz_float_mod_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	rz_return_val_if_fail(left && right && left->r == right->r, NULL);

	RzFloat *ret = rz_float_rem_ieee_bin(left, right, mode);
	if (rz_float_get_sign(ret) != rz_float_get_sign(left)) {
		if (rz_float_is_zero(ret)) {
			/* If a zero is returned, it should still have the same sign as the dividend. */
			rz_float_set_sign(ret, rz_float_get_sign(left));
		} else {
			RzFloat *same_sign = NULL;
			RzFloat *right_abs = rz_float_abs(right);

			if (rz_float_is_negative(ret)) {
				same_sign = rz_float_add(ret, right_abs, mode);
			} else {
				same_sign = rz_float_sub(ret, right_abs, mode);
			}

			rz_float_free(ret);
			ret = same_sign;
		}
	}

	return ret;
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
	rz_return_val_if_fail(n, NULL);

	RzFloatFormat format = n->r;
	set_float_rounding_mode(mode);

	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return of_float32(f32_sqrt(to_float32(n)));
	case RZ_FLOAT_IEEE754_BIN_64:
		return of_float64(f64_sqrt(to_float64(n)));
	case RZ_FLOAT_IEEE754_BIN_80:
		return of_float80(extF80_sqrt(to_float80(n)));
	case RZ_FLOAT_IEEE754_BIN_128:
		return of_float128(f128_sqrt(to_float128(n)));
	default:
		RZ_LOG_ERROR("float: SQRT operation unimplemented for format %d\n", format);
		return NULL;
	}
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
	if (old_format == RZ_FLOAT_IEEE754_BIN_80) {
		/* Special case, see [rz_float_info_bin80] for more. */
		man_len--;
	}

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
