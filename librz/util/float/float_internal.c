// SPDX-FileCopyrightText: 2022 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

/**
 * \file : Internal function for float
 * \brief : Should be included directly in float.c
 */
static inline ut32 rz_float_info_bin16(RzFloatInfo which_info) {
	switch (which_info) {
	case RZ_FLOAT_INFO_BASE:
		return 2;
	case RZ_FLOAT_INFO_EXP_LEN:
		return 5;
	case RZ_FLOAT_INFO_MAN_LEN:
		return 10;
	case RZ_FLOAT_INFO_TOTAL_LEN:
		return 16;
	case RZ_FLOAT_INFO_BIAS:
		return 15;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static inline ut32 rz_float_info_bin32(RzFloatInfo which_info) {
	switch (which_info) {
	case RZ_FLOAT_INFO_BASE:
		return 2;
	case RZ_FLOAT_INFO_EXP_LEN:
		return 8;
	case RZ_FLOAT_INFO_MAN_LEN:
		return 23;
	case RZ_FLOAT_INFO_TOTAL_LEN:
		return 32;
	case RZ_FLOAT_INFO_BIAS:
		return 127;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static inline ut32 rz_float_info_bin64(RzFloatInfo which_info) {
	switch (which_info) {
	case RZ_FLOAT_INFO_BASE:
		return 2;
	case RZ_FLOAT_INFO_EXP_LEN:
		return 11;
	case RZ_FLOAT_INFO_MAN_LEN:
		return 52;
	case RZ_FLOAT_INFO_TOTAL_LEN:
		return 64;
	case RZ_FLOAT_INFO_BIAS:
		return 1023;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static inline ut32 rz_float_info_bin80(RzFloatInfo which_info) {
	switch (which_info) {
	case RZ_FLOAT_INFO_BASE:
		return 2;
	case RZ_FLOAT_INFO_EXP_LEN:
		return 15;
	case RZ_FLOAT_INFO_MAN_LEN:
		/* The mantissa is actually 63 bits, but we also include the integer bit
		 * in the mantissa. Doing this so that the invariant of
		 * man_len + exp_len + 1 == total_len holds true. */
		return 64;
	case RZ_FLOAT_INFO_TOTAL_LEN:
		return 80;
	case RZ_FLOAT_INFO_BIAS:
		return 16383;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static inline ut32 rz_float_info_bin128(RzFloatInfo which_info) {
	switch (which_info) {
	case RZ_FLOAT_INFO_BASE:
		return 2;
	case RZ_FLOAT_INFO_EXP_LEN:
		return 15;
	case RZ_FLOAT_INFO_MAN_LEN:
		return 112;
	case RZ_FLOAT_INFO_TOTAL_LEN:
		return 128;
	case RZ_FLOAT_INFO_BIAS:
		return 16383;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

/**
 * Shift right, but keeps LSB true if hit 1 during shift
 * \param x RzBitVector, pointer to bv
 * \param dist shift distance, positive or zero
 * \return ret bool, return true if shift success
 */
static bool rz_bv_shift_right_jammed(RzBitVector *bv, ut32 dist) {
	rz_return_val_if_fail(bv, false);

	bool lsb = false;
	for (ut32 i = 0; i < dist; ++i) {
		bool b = rz_bv_get(bv, i);
		if (b) {
			lsb = true;
			break;
		}
	}

	rz_bv_rshift(bv, dist);
	rz_bv_set(bv, 0, lsb);
	return true;
}

/**
 * Get a bitvector representation of exponent, have the same length of parameter `bv`
 * \param bv RzBitVector, the bitvector interpreted as float
 * \param format RzFloatFormat, specifying the format of float
 * \return a bitvector representation of exponent
 */
static RZ_OWN RzBitVector *get_exp(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
	rz_return_val_if_fail(bv, NULL);

	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	RzBitVector *res = rz_bv_new(exp_len + man_len + 1);
	if (!res) {
		RZ_LOG_ERROR("rz_float : failed to create bitvector");
		return NULL;
	}
	rz_bv_copy_nbits(bv, man_len, res, 0, exp_len);

	return res;
}

/**
 * Get a bitvector representation of mantissa, have the same length of parameter `bv`
 * \param bv RzBitVector, the bitvector interpreted as float
 * \param format RzFloatFormat, specifying the format of float
 * \return a bitvector representation of mantissa
 */
static RZ_OWN RzBitVector *get_man(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
	rz_return_val_if_fail(bv, NULL);

	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	RzBitVector *res = rz_bv_new(exp_len + man_len + 1);
	if (!res) {
		RZ_LOG_ERROR("rz_float : failed to create bitvector");
		return NULL;
	}
	rz_bv_copy_nbits(bv, 0, res, 0, man_len);

	return res;
}

/**
 * Get a bitvector representation of mantissa, twice as long as `bv` length.
 * \param bv RzBitVector, the bitvector interpreted as float
 * \param format RzFloatFormat, specifying the format of float
 * \return a bitvector representation of mantissa
 */
static RZ_OWN RzBitVector *get_man_stretched(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
	rz_return_val_if_fail(bv, NULL);

	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 total = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	RzBitVector *res = rz_bv_new(total * 2);
	if (!res) {
		RZ_LOG_ERROR("rz_float : failed to create bitvector");
		return NULL;
	}
	rz_bv_copy_nbits(bv, 0, res, 0, man_len);

	return res;
}

/**
 * Get a bitvector representation of exponent. The length is depending on the exponent width (specified by `format`)
 * \param bv RzBitVector, the bitvector interpreted as float
 * \param format RzFloatFormat, specifying the format of float
 * \return a bitvector representation of exponent
 */
static RZ_OWN RzBitVector *get_exp_squashed(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
	rz_return_val_if_fail(bv, NULL);

	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	RzBitVector *res = rz_bv_new(exp_len);
	if (!res) {
		RZ_LOG_ERROR("rz_float : failed to create bitvector");
		return NULL;
	}
	rz_bv_copy_nbits(bv, man_len, res, 0, exp_len);

	return res;
}

/**
 * Get a bitvector representation of mantissa. The length is depending on the mantissa width (specified by `format`)
 * \param bv RzBitVector, the bitvector interpreted as float
 * \param format RzFloatFormat, specifying the format of float
 * \return a bitvector representation of mantissa
 */
static RZ_OWN RzBitVector *get_man_squashed(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
	rz_return_val_if_fail(bv, NULL);

	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	RzBitVector *res = rz_bv_new(man_len);
	if (!res) {
		RZ_LOG_ERROR("rz_float : failed to create bitvector");
		return NULL;
	}
	rz_bv_copy_nbits(bv, 0, res, 0, man_len);
	return res;
}

/**
 * Get the sign of bv
 * \param bv RzBitVector, the bitvector interpreted as float
 * \param format RzFloatFormat, specifying the format of float
 * \return bool sign of float bv
 */
static RZ_OWN bool get_sign(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
	rz_return_val_if_fail(bv, false);
	return rz_bv_get(bv, bv->len - 1);
}

/**
 * make a float becomes positive, would changed the float itself
 * \param f float to be converted
 * \return true if success
 */
static bool rz_make_fabs(RzFloat *f) {
	return rz_bv_set(f->s, f->s->len - 1, false);
}

/**
 * Pack sign, exponent, and significant together to float bv
 * \param sign sign of float
 * \param exp exponent part, can be squashed or normal
 * \param sig significant part (mantissa with a leading bit 1), can be squashed or normal
 * \param format format of float
 * \return RzBitVector the final bitvector representation of RzFloat
 */
static RZ_OWN RzBitVector *pack_float_bv(bool sign, RZ_BORROW RZ_NONNULL const RzBitVector *exp, RZ_BORROW RZ_NONNULL const RzBitVector *sig, RzFloatFormat format) {
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 total = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	RzBitVector *ret = rz_bv_new(total);

	// copy exp to ret
	rz_bv_copy_nbits(exp, 0, ret, man_len, exp_len);

	if (format == RZ_FLOAT_IEEE754_BIN_80) {
		/* 80-bit floats have a special bit at position 63 (man_len) which is
		 * called the integer bit. We need to account for that, hence the
		 * branching here. See https://en.wikipedia.org/wiki/Extended_precision
		 * for more. */
		rz_bv_set(ret, man_len - 1, true);
		rz_bv_copy_nbits(sig, 1, ret, 0, man_len - 1);
	} else {
		rz_bv_copy_nbits(sig, 0, ret, 0, man_len);
	}

	rz_bv_set(ret, total - 1, sign);

	return ret;
}

/**
 * detect if should drop extra tailing bits in rounding
 * GRS konwn as G(guard bit), R(round bit), and S(sticky bit)
 * they are 3 bits after the LSB bit of rounded result, which is drop in rounding
 * note that this function has no concept to float format
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
static RzBitVector *round_significant(bool sign, RzBitVector *sig, ut32 precision, RzFloatRMode mode, bool *should_inc) {
	rz_return_val_if_fail(sig && should_inc, NULL);

	ut32 sig_len = rz_bv_len(sig) - rz_bv_clz(sig);
	ut32 mantissa_len = sig_len - 1;
	ut32 ret_len = precision + 3 + 1;
	RzBitVector *ret;

	if (mantissa_len < ret_len) {
		// copy and shift in one operation
		// equal to the following operations
		// 1. copy bv from sig to ret
		// 2. align `ret` to `1 MM..M 000` form by shifting left
		ret = rz_bv_new(ret_len);
		rz_bv_copy_nbits(sig, 0, ret, ret_len - sig_len, sig_len);
	} else {
		// if it's greater than `ret`, right shift and cut
		// use jammed version of right shift to get sticky bit
		ut32 shift_dist = sig_len - ret_len;
		RzBitVector *sig_dup = rz_bv_dup(sig);
		rz_bv_shift_right_jammed(sig_dup, shift_dist);
		ret = rz_bv_cut_head(sig_dup, rz_bv_len(sig) - ret_len);
		rz_bv_free(sig_dup);
	}

	// default is drop
	*should_inc = false;

	if (mode == RZ_FLOAT_RMODE_RNE || mode == RZ_FLOAT_RMODE_RNA) {
		bool guard_bit = rz_bv_get(ret, 2);
		bool round_bit = rz_bv_get(ret, 1);
		bool sticky_bit = rz_bv_get(ret, 0);
		rz_bv_rshift(ret, 3);

		// for G R S bits
		//     > 1 0 0 : round up
		//     = 1 0 0 : ties
		//     < 1 0 0 : round down
		if (guard_bit == 0) {
			*should_inc = 0;
		} else if (!round_bit && !sticky_bit) {
			// ties
			if (mode == RZ_FLOAT_RMODE_RNE) {
				bool is_odd = rz_bv_get(ret, 0);
				*should_inc = is_odd ? 1 : 0;
			}
			if (mode == RZ_FLOAT_RMODE_RNA) {
				*should_inc = 1;
			}
		} else {
			*should_inc = 1;
		}

		return ret;
	}

	if (mode == (sign ? RZ_FLOAT_RMODE_RTN : RZ_FLOAT_RMODE_RTP)) {
		*should_inc = 1;
		// rshift to remove RGS
		rz_bv_rshift(ret, 3);
		return ret;
	}

	// mode == RTZ or others, simply drop bits
	rz_bv_rshift(ret, 3);
	return ret;
}

/**
 * \brief Rounding method.
 * this function is a wrapper of round_significant, it manage the rounded result and exponent change
 * |f| = sig * 2^exp_no_bias
 * \details it assumes first bit 1 as the hidden bit, and radix point is right after it.
 * TODO : report exception
 * \param sign sign of bitvector
 * \param exp exponent value, biased
 * \param sig significant, form: 1.MMMM...., for sub-normal,
 * caller should set a fake hidden bit to match this format.
 * \param format float sort of given exp and sig
 * \param new_format format of target float sort
 * \param mode rounding mode
 * \return a float of type `format`, converted from `sig`
 */
static RZ_OWN RzFloat *round_float_bv_new(bool sign, st32 exp, RzBitVector *sig, RzFloatFormat format, RzFloatFormat new_format, RzFloatRMode mode) {
	rz_return_val_if_fail(sig, NULL);
	RzFloat *ret;

	ut32 new_man_len = rz_float_get_format_info(new_format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 new_total_len = rz_float_get_format_info(new_format, RZ_FLOAT_INFO_TOTAL_LEN);
	st32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	st32 new_bias = rz_float_get_format_info(new_format, RZ_FLOAT_INFO_BIAS);
	st32 exp_val = exp;
	st32 exp_max = bias + bias;
	st32 exp_min = 0;

	// check overflow and underflow
	if (exp_val > exp_max) {
		ret = rz_float_new_inf(new_format, sign);
		ret->exception = RZ_FLOAT_E_OVERFLOW;
		return ret;
	}
	if (exp_val < exp_min) {
		ret = rz_float_new_qnan(new_format);
		ret->exception = RZ_FLOAT_E_UNDERFLOW;
		return ret;
	}

	bool should_inc = false;
	ut32 bit_prec = new_man_len;
	RzBitVector *rounded_tmp = round_significant(sign, sig, bit_prec, mode, &should_inc);

	if (rounded_tmp == NULL) {
		// TODO: error and report in code
		// should_inc / sig is NULL
		return NULL;
	}

	// convert rounded bitv to fit given format
	RzBitVector *rounded_sig = rz_bv_prepend_zero(rounded_tmp, new_total_len - rz_bv_len(rounded_tmp));

	// free rounded tmp result
	rz_bv_free(rounded_tmp);
	rounded_tmp = NULL;

	if (should_inc) {
		ut32 sig_carry_pos = new_man_len + 1;
		RzBitVector *one = rz_bv_new_one(new_total_len);
		rounded_tmp = rz_bv_add(rounded_sig, one, NULL);
		rz_bv_free(one);

		bool sig_carry = rz_bv_get(rounded_tmp, sig_carry_pos);
		if (sig_carry) {
			// change exponent, renormalize
			exp_val += 1;
			if (exp_val > exp_max) {
				// overflow
				ret = rz_float_new_inf(new_format, sign);
				ret->exception = RZ_FLOAT_E_OVERFLOW;
				rz_bv_free(rounded_sig);
				rz_bv_free(rounded_tmp);
				return ret;
			}

			// renormalize significant
			// it has a carry, so last bit is 0 after carry
			// safely right shift
			rz_bv_rshift(rounded_tmp, 1);
		}

		rz_bv_free(rounded_sig);
		rounded_sig = rounded_tmp;
		rounded_tmp = NULL;
	}

	RzBitVector *exp_bv;
	if (exp_val == 0) {
		// sub normal one, zero exp bv
		exp_bv = rz_bv_new_zero(new_total_len - new_man_len - 1);
		// hidden bit set to 0
		rz_bv_set(rounded_sig, new_man_len, 0);
	} else {
		// normal one
		exp_bv = rz_bv_new_from_ut64(new_total_len, exp_val - bias + new_bias);
	}

	// pack to float
	ret = RZ_NEW0(RzFloat);
	if (!ret) {
		rz_bv_free(exp_bv);
		rz_bv_free(rounded_sig);
		return NULL;
	}
	ret->s = pack_float_bv(sign, exp_bv, rounded_sig, new_format);
	ret->r = new_format;

	rz_bv_free(exp_bv);
	rz_bv_free(rounded_sig);
	return ret;
}
