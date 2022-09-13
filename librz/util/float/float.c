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
RZ_API RZ_OWN char *rz_float_as_string(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f && f->s, NULL);

	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_TOTAL_LEN);

	char *str = (char *)malloc(total + 2);
	if (!str) {
		return NULL;
	}

	ut32 pos = rz_bv_len(f->s) - 1;
	ut32 i;

	str[0] = rz_float_get_sign(f) ? '-' : '+';
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
RZ_IPI ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info) {
	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return rz_float_info_bin32(which_info);
	case RZ_FLOAT_IEEE754_BIN_64:
		return rz_float_info_bin64(which_info);
	case RZ_FLOAT_IEEE754_BIN_128:
		return rz_float_info_bin128(which_info);
	case RZ_FLOAT_IEEE754_DEC_64:
	case RZ_FLOAT_IEEE754_DEC_128:
	default:
		RZ_LOG_ERROR("FORMAT NOT IMPLEMENTED YET");
		rz_warn_if_reached();
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
	RzFloat *f = RZ_NEW(RzFloat);
	if (!f) {
		return NULL;
	}
	f->s = NULL;

	if (!rz_float_init(f, format)) {
		free(f);
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
	RzFloat *cp = RZ_NEW(RzFloat);
	if (!cp) {
		RZ_LOG_ERROR("Dup float failed")
		return NULL;
	}

	cp->r = f->r;
	cp->s = rz_bv_dup(f->s);
	cp->exception = f->exception;

	return cp;
}

/**
 * Set float bv from C type `float`
 * \param f a normal float
 * \param value value of type `float`
 * \return true if success
 */
// TODO : a better way to deal with the different physical implementation
RZ_API bool rz_float_set_from_single(RZ_NONNULL RzFloat *f, float value) {
	rz_return_val_if_fail(f, false);

	// TODO : should we support single float -> a given format float ?
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	// check if given RzFloat is a IEEE754-binary32
	if (exp_len != 8 || man_len != 23) {
		RZ_LOG_WARN("Do not support single to other float conversion in set_from");
		return false;
	}

	rz_bv_set_from_bytes_le(f->s, (ut8 *)&value, 0, exp_len + man_len + 1);
	return f;
}

/**
 * Set float bv from C type `double`
 * \param f a normal float
 * \param value value of type `double`
 * \return true if success
 */
// TODO : a better way to deal with the different physical implementation
RZ_API bool rz_float_set_from_double(RZ_NONNULL RzFloat *f, double value) {
	rz_return_val_if_fail(f, false);

	// TODO : should we support double float -> a given format float ?
	ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
	if (exp_len != 11 || man_len != 52) {
		RZ_LOG_WARN("Do not support double to other float conversion in set_from");
		return false;
	}

	rz_bv_set_from_bytes_le(f->s, (ut8 *)&value, 0, exp_len + man_len + 1);
	return f;
}

/**
 * \brief create a float by given the single float value
 * \param value single float value
 * \return RzFloat representation of single float
 */
// TODO : a better way to deal with the different physical implementation
RZ_API RZ_OWN RzFloat *rz_float_new_from_single(float value) {
	RzFloat *f = rz_float_new(RZ_FLOAT_IEEE754_BIN_32);
	if (!f) {
		RZ_LOG_ERROR("Failed to new a single float")
		return NULL;
	}

	if (!rz_float_set_from_single(f, value)) {
		RZ_LOG_ERROR("Error in set float from single")
		rz_float_free(f);
		return NULL;
	}
	return f;
}

/**
 * \brief create a float by given the double float value
 * \param value double float value
 * \return RzFloat representation of double float
 */
// TODO : a better way to deal with the different physical implementation
RZ_API RZ_OWN RzFloat *rz_float_new_from_double(double value) {
	RzFloat *f = rz_float_new(RZ_FLOAT_IEEE754_BIN_64);
	if (!f) {
		RZ_LOG_ERROR("Failed to new a double float")
		return NULL;
	}

	if (!rz_float_set_from_double(f, value)) {
		RZ_LOG_ERROR("Error in set float from double")
		rz_float_free(f);
		return NULL;
	}

	return f;
}

/**
 * \brief create RzFloat by giving hex value, most used in writing testcases
 * ref : http://www.jhauser.us/arithmetic/TestFloat-3/doc/TestFloat-general.html
 * \param hex_value 32-bit/64-bit hex value to represent 32-bit/64-bit bitvector
 * \param format float format
 * \return new RzFloat
 */
static RZ_OWN RzFloat *rz_float_new_from_hex(ut64 hex_value, RzFloatFormat format) {
	if ((format == RZ_FLOAT_IEEE754_BIN_32) || (format == RZ_FLOAT_IEEE754_BIN_64)) {
		RzFloat *ret = RZ_NEW(RzFloat);
		ret->r = format;
		ret->s = rz_bv_new_from_ut64(rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN), hex_value);
		return ret;
	} else {
		// could not carry hex value larger than ut64 max
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * \brief create RzFloat by giving 64-bit hex value, most used in writing testcases
 * \param hex_value 64-bit hex_value
 * \return RzFloat-binary64
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_hex_as_f64(ut64 hex_value) {
	return rz_float_new_from_hex(hex_value, RZ_FLOAT_IEEE754_BIN_64);
}

/**
 * \brief create RzFloat by giving 32-bit hex value, most used in writing testcases
 * \param hex_value 32-bit hex_value
 * \return RzFloat-binary32
 */
RZ_API RZ_OWN RzFloat *rz_float_new_from_hex_as_f32(ut32 hex_value) {
	return rz_float_new_from_hex(hex_value, RZ_FLOAT_IEEE754_BIN_32);
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
RZ_API bool rz_float_get_sign(RZ_NONNULL RzFloat *f) {
	rz_return_val_if_fail(f, false);
	return get_sign(f->s, f->r);
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
 * Generate a infinity float and specify the sign bit
 * \param format format of float to generate
 * \param sign sign bit of infinity, is_negative flag
 * \return an infinity float
 */
RZ_API RZ_OWN RzFloat *rz_float_new_inf(RzFloatFormat format, bool sign) {
	// gen an Infinite num for return
	RzFloat *ret = rz_float_new(format);
	if (!ret || !ret->s) {
		rz_float_free(ret);
		return NULL;
	}
	RzBitVector *bv = ret->s;
	ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set sign bit (MSB), keep mantissa as zero-bv
	rz_bv_set(bv, bv->len - 1, sign);

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
	RzBitVector *bv = ret->s;
	ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set is_quiet to 1
	rz_bv_set(bv, exp_start - 1, true);

	// set sig as non-zero
	rz_bv_set(bv, 0, true);

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
	RzBitVector *bv = ret->s;
	ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);

	// set exponent part to all 1
	rz_bv_set_range(bv, exp_start, exp_end - 1, true);

	// set is_quiet to 0 (msb of mantissa part)
	rz_bv_set(bv, exp_start - 1, false);

	// set sig as non-zero
	rz_bv_set(bv, 0, true);

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
		RZ_LOG_ERROR("Error when parsing rz-float")
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

	// if it produce a carry bit, we should normalize it (rshift 1 and exp + 1)
	// but we do nothing, instead, we makes every non-carry number have the same
	// form : 01X.M MMMM MMMM ... = 01.XM MMMM MMMM ... * (0b10)
	//           ^------- point
	// we don't need to ++exp explicitly,
	// because after rounding, if the bit before point (carry bit) is 1
	// we could add sig and exp directly, to represent (exp + 1) operation
	// since the leading sig bit is an overlapping bit of exp part and sig part
	if (!rz_bv_get(result_sig, carry_bit_pos) && !rz_bv_msb(result_sig)) {
		result_exp_val -= 1;
		rz_bv_lshift(result_sig, 1);
	}

	// round
	result = round_float_bv(sign, result_exp_val, result_sig, format, mode);

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

	bool l_sign = rz_float_get_sign(left);
	bool r_sign = rz_float_get_sign(right);
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
		RZ_LOG_ERROR("Error when parsing rz-float")
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

		// check if the small one (right) is normalized ?
		if (r_borrow_exp_val != 0) {
			// normalized, and then we recover the leading bit 1
			// 1.MMMM MMMM ...
			rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
		} else {
			// r_borrow << 1;
			rz_bv_lshift(r_borrowed_sig, 1);
		}

		// revealed the hidden bit of the bigger one : 1.MMMM
		rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
		// aligned exponent, and generate sticky bit
		rz_bv_shift_right_jammed(r_borrowed_sig, abs_exp_diff);
	}

	// result_exp = bigger_exp
	res_exp_val = l_borrow_exp_val - 1;
	// result_sig = bigger_sig - small_sig
	result_sig = rz_bv_sub(l_borrowed_sig, r_borrowed_sig, &unused);

	// normalize, already shifted free bits, reserve 1 will be fine
	shift_dist = rz_bv_clz(result_sig) - 1;
	res_exp_val -= shift_dist;
	rz_bv_lshift(result_sig, shift_dist);

	result = round_float_bv(sign, res_exp_val, result_sig, format, mode);

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
RZ_IPI RZ_OWN RzFloat *rz_float_add_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	bool l_sign = rz_float_get_sign(left);
	bool r_sign = rz_float_get_sign(right);
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
RZ_IPI RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	bool l_sign = rz_float_get_sign(left);
	bool r_sign = rz_float_get_sign(right);
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
RZ_IPI RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	RzFloat *result = NULL;

	/* Process NaN and Inf cases */
	PROC_SPECIAL_FLOAT_START(left, right)
	// propagate NaN
	if (l_is_nan || r_is_nan) {
		return propagate_float_nan(left, l_type, right, r_type);
	}

	bool l_sign = rz_float_get_sign(left);
	bool r_sign = rz_float_get_sign(right);
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

	// normalize sub-normal num
	if (l_exp_val == 0) {
		// is sub-normal
		// shift_dist = ctz - (sign + exponent width) + 1 (the leading sig bit) - extra bits
		// note that stretched bv has 2 * total_len long, the extra bits has (total_len) long
		shift_dist = rz_bv_clz(l_mantissa) - (1 + exp_len) + 1 - extra_len;

		// sub_nor_exp = 1 - bias
		// normalized_exp = sub_nor_exp - shift_dist = 1 - bias - shift_dist
		// = (1 - shift_dist) - bias
		// so the value of exponent field is (1 - shift_dist)
		l_exp_val = 1 - shift_dist;
		rz_bv_lshift(l_mantissa, shift_dist);
	}

	if (r_exp_val == 0) {
		// is sub-normal
		shift_dist = rz_bv_clz(r_mantissa) - (1 + exp_len) + 1 - extra_len;
		r_exp_val = 1 - shift_dist;
		rz_bv_lshift(r_mantissa, shift_dist);
	}

	ut32 result_exp_val = l_exp_val + r_exp_val - bias;

	// remember we would like to make 01.MM MMMM ... (but leave higher extra bits empty)
	shift_dist = (exp_len + 1) - 2;
	ut32 hiddent_bit_pos = total_len - 2;

	rz_bv_lshift(l_mantissa, shift_dist);
	rz_bv_lshift(r_mantissa, shift_dist + 1); // +1 due to leading 0 will accumulate

	// set leading bit
	rz_bv_set(l_mantissa, hiddent_bit_pos, true);
	rz_bv_set(r_mantissa, hiddent_bit_pos + 1, true);

	// multiplication
	result_sig = rz_bv_mul(l_mantissa, r_mantissa);
	// recovered to lower bits
	rz_bv_shift_right_jammed(result_sig, extra_len);
	// cut extra bits from MSB
	RzBitVector *tmp = rz_bv_cut_head(result_sig, extra_len);
	rz_bv_free(result_sig);
	result_sig = tmp;
	tmp = NULL;

	// check if a carry happen, if not, l-shift to force a leading 1
	// check MSB and the bit after MSB
	if (!rz_bv_get(result_sig, total_len - 2) && !rz_bv_msb(result_sig)) {
		result_exp_val -= 1;
		rz_bv_lshift(result_sig, 1);
	}

	result = round_float_bv(result_sign, result_exp_val, result_sig, format, mode);

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
RZ_IPI RZ_OWN RzFloat *rz_float_div_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	RzFloat *result = NULL;

	PROC_SPECIAL_FLOAT_START(left, right)
	bool l_sign = rz_float_get_sign(left);
	bool r_sign = rz_float_get_sign(right);
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
	RzBitVector *tmp = rz_bv_cut_head(result_sig, extra_len);
	rz_bv_free(result_sig);
	result_sig = tmp;
	tmp = NULL;

	// dec exp according to normalization
	// exp -= shift
	// exp -= 1 for rounding
	result_exp_val -= shift_dist + 1;

	if ((st32)result_exp_val < 0) {
		// underflow ?
		result_exp_val = 0;
	}

	result = round_float_bv(result_sign, result_exp_val, result_sig, format, mode);
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

	bool sign_x = rz_float_get_sign(left);

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
	RzBitVector *mz;
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
	ez += bias;

	// apply to round_float_bv required format
	// 01 MMMM MMMM ...
	shift_dist = (st32)(exp_len - 1);
	rz_bv_lshift(mz, shift_dist);

	z = round_float_bv(sign_z, ez - 1, mz, left->r, mode);
clean:
	rz_bv_free(mx);
	rz_bv_free(my);
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
RZ_IPI RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
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
RZ_IPI RZ_OWN RzFloat *rz_float_mod_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode) {
	return rz_float_rem_internal(left, right, RZ_FLOAT_RMODE_RTZ, mode);
}

/**
 * calculate \p a * \p b + \p c, and round the result after, return the result
 * \param mode rounding mode
 * \return result of arithmetic operation
 */
RZ_IPI RZ_OWN RzFloat *rz_float_fma_ieee_bin(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode) {
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

	// normalize sub-normal num
	if (a_exp_val == 0) {
		// is sub-normal
		// shift_dist = ctz - (sign + exponent width) + 1 (the leading sig bit) - extra bits
		// note that stretched bv has 2 * total_len long, the extra bits has (total_len) long
		shift_dist = rz_bv_clz(a_mantissa) - (1 + exp_len) + 1 - extra_len;

		// sub_nor_exp = 1 - bias
		// normalized_exp = sub_nor_exp - shift_dist = 1 - bias - shift_dist
		// = (1 - shift_dist) - bias
		// so the value of exponent field is (1 - shift_dist)
		a_exp_val = 1 - shift_dist;
		rz_bv_lshift(a_mantissa, shift_dist);
	}

	if (b_exp_val == 0) {
		// is sub-normal
		shift_dist = rz_bv_clz(b_mantissa) - (1 + exp_len) + 1 - extra_len;
		b_exp_val = 1 - shift_dist;
		rz_bv_lshift(b_mantissa, shift_dist);
	}

	ut32 mul_exp_val = a_exp_val + b_exp_val - bias + 1;

	// remember we would like to make 01.MM MMMM ... (but leave higher extra bits empty)
	shift_dist = (exp_len + 1) - 2;
	ut32 hiddent_bit_pos = total_len - 2;

	rz_bv_lshift(a_mantissa, shift_dist);
	rz_bv_lshift(b_mantissa, shift_dist);

	// set leading bit
	rz_bv_set(a_mantissa, hiddent_bit_pos, true);
	rz_bv_set(b_mantissa, hiddent_bit_pos, true);
	// multiplication
	mul_sig = rz_bv_mul(a_mantissa, b_mantissa);

	// check if a carry happen, if not, l-shift to force a leading 1
	// check MSB and the bit after MSB
	ut64 new_total_len = total_len + extra_len;
	if (!rz_bv_get(mul_sig, new_total_len - 3) &&
		!rz_bv_get(mul_sig, new_total_len - 2) &&
		!rz_bv_get(mul_sig, new_total_len - 1)) {
		mul_exp_val -= 1;
		rz_bv_lshift(mul_sig, 1);
	}

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
	// set hidden bit 1 and shift (001.M MMMM ...)
	hiddent_bit_pos = total_len - 3;
	rz_bv_lshift(c_mantissa, exp_len - 2);
	rz_bv_set(c_mantissa, hiddent_bit_pos, true);
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

		// check if we should normalize
		if (!rz_bv_get(res_sig, new_total_len - 1) &&
			!rz_bv_get(res_sig, new_total_len - 2)) {
			res_exp_val -= 1;
			rz_bv_lshift(res_sig, 1);
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

		shift_dist = rz_bv_clz(res_sig) - 1;
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
	ret_f = round_float_bv(res_sign, res_exp_val, res_sig, format, mode);
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
RZ_IPI RZ_OWN RzFloat *rz_float_sqrt_ieee_bin(RZ_NONNULL RzFloat *n, RzFloatRMode mode) {
	// Use Newton method now, May Optimize
	RzFloat *eps = rz_float_new_zero(n->r);
	ut32 bias = rz_float_get_format_info(n->r, RZ_FLOAT_INFO_BIAS);
	ut32 man_len = rz_float_get_format_info(n->r, RZ_FLOAT_INFO_MAN_LEN);
	ut32 eps_magic = bias - man_len;

	RzBitVector *eps_bv = rz_bv_new_from_ut64(n->s->len, eps_magic);
	rz_bv_lshift(eps_bv, man_len);
	RzFloat *x = rz_float_new(n->r);
	x->s = eps_bv;

	while (true) {
		RzFloat *q = rz_float_div_ieee_bin(n, x, mode);
		RzFloat *sum = rz_float_add_ieee_bin(x, q, mode);
		RzFloat *sum_half = rz_half_float(sum);
		RzFloat *abs = rz_float_sub_ieee_bin(x, sum_half, mode);
		rz_make_fabs(abs);
		// abs <= eps, both are positive
		if (rz_bv_ule(abs->s, eps->s))
			break;
		rz_float_free(x);
		rz_float_free(q);
		rz_float_free(abs);
		rz_float_free(sum);
		x = sum_half;
		sum = NULL;
		sum_half = NULL;
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
	if (rz_float_get_sign(f)) {
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
	RzBitVector *exp_bv = get_exp_squashed(f->s, f->r);
	ut32 exp_val = rz_bv_to_ut32(exp_bv);
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

	rz_bv_free(exp_bv);
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
