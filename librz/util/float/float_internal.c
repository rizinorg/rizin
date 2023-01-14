// SPDX-FileCopyrightText: 2022 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

/**
 * \file : Internal function for float
 * \brief : Should be included directly in float.c
 */

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
 * get the half value of a float (by decreasing exponent value)
 * \param f float
 * \return half value of a float
 */
static RzFloat *rz_half_float(RzFloat *f) {
	ut32 total = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_TOTAL_LEN);
	ut32 exp_start = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);

	// for exp sub 1
	RzBitVector *sub = rz_bv_new(total);
	rz_bv_set(sub, exp_start, true);
	RzFloat *half = rz_float_new(f->r);
	half->s = rz_bv_sub(f->s, sub, NULL);

	rz_bv_free(sub);
	return half;
}

/**
 * Pack sign, exponent, and significant together to float bv
 * \param sign sign of float
 * \param exp exponent part, can be squashed or normal
 * \param sig significant part (mantissa with a leading bit 1), can be squashed or normal
 * \param format format of float
 * \return RzBitVector the final bitvector representation of RzFloat
 */
static RZ_OWN RzBitVector *pack_float_bv(bool sign, RzBitVector *exp, RzBitVector *sig, RzFloatFormat format) {
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	ut32 total = man_len + exp_len + 1;
	RzBitVector *ret = rz_bv_new(total);
	// copy exp to ret
	rz_bv_copy_nbits(exp, 0, ret, man_len, exp_len);
	rz_bv_copy_nbits(sig, 0, ret, 0, man_len);
	rz_bv_set(ret, total - 1, sign);

	return ret;
}

/**
 * Detecting if a significant should be rounded
 * \param sig RzBitVector significant bv before rounding `point` is at the 2nd bit counted from MSB (01.MM MMMM ...)
 * \param r_bits_bound ut32 boundary of round bits
 * \return bool return true if significant should be rounded, else return false
 */
static inline bool detect_should_round(RzBitVector *sig, ut32 r_bits_bound) {
	bool should_round = false;
	for (ut32 i = 0; i < r_bits_bound; ++i) {
		if (rz_bv_get(sig, i) == true) {
			should_round = true;
			break;
		}
	}
	return should_round;
}

/**
 * Detecting if the round bits is in the halfway (MSB is 1, the other bits is 0)
 * \param sig RzBitVector significant bv before rounding `point` is at the 2nd bit counted from MSB (01.MM MMMM ...)
 * \param r_bits_bound ut32 boundary of round bits
 * \return bool return true if significant should be rounded, else return false
 */
static bool detect_halfway(RzBitVector *sig, ut32 r_bits_bound) {
	for (ut32 i = 0; i < r_bits_bound - 1; ++i) {
		if (rz_bv_get(sig, i) == true) {
			return false;
		}
	}

	if (rz_bv_get(sig, r_bits_bound - 1) == true) {
		return true;
	}

	return false;
}

/**
 * Generate an infinite bitvector
 * \param sign sign of an inf
 * \param format RzFloatFormat format of float
 * \return an infinite bitvector
 */
static RZ_OWN RzBitVector *gen_inf_bv(bool sign, RzFloatFormat format) {
	return NULL;
}

/**
 * Trying to round float component
 * \param sign sign of float
 * \param exp ut32 value of exponent
 * \param sig RzBitVector significant bv before rounding `point` is at the 2nd bit counted from MSB (01.MM MMMM ...)
 * \param format RzFloatFormat format of float
 * \param mode Rounding mode
 * \return RzFloat A rounded float
 */
static RZ_OWN RzFloat *
round_float_bv(bool sign, ut32 exp, RzBitVector *sig, RzFloatFormat format, RzFloatRMode mode) {
	ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
	ut32 emax = ((bias + 1) << 1) - 1;
	ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);

	bool is_rne = (mode == RZ_FLOAT_RMODE_RNE);
	bool is_rna = (mode == RZ_FLOAT_RMODE_RNA);
	RzFloat *ret = RZ_NEW0(RzFloat);
	ret->r = format;
	ret->s = NULL;

	// add 1 to the LSB of sig
	ut32 round_inc_val = (bias + 1) >> 1;

	// handle round to max(+inf)/min(-inf)
	// if + && round towards +inf : use bias as inc
	// if - && round towards -inf : use bias as inc
	if (!is_rne && !is_rna) {
		round_inc_val =
			(mode == (sign ? RZ_FLOAT_RMODE_RTN : RZ_FLOAT_RMODE_RTP))
			? bias
			: 0;
	}

	// get round bits
	// every num before rounding have the following pattern
	// 01MM MMMM MMMM ...
	// we will leave (sign_len + exp_len) bits before mantissa part
	// and thus the lower (sign_len + exp_len - 2) bits will be r-shifted out
	// in another word, the lower bits will be guard bit, round bit and sticky bits
	ut32 round_bits_bound = (exp_len + 1 - 2);
	ut32 should_round = detect_should_round(sig, round_bits_bound);
	// ut32 guard_bit_pos = round_bits_bound - 1;
	ut32 is_halfway = detect_halfway(sig, round_bits_bound);

	RzBitVector *possible_sig = NULL;
	bool unused;
	RzBitVector *round_inc_bv = rz_bv_new_from_ut64(sig->len, round_inc_val);
	possible_sig = rz_bv_add(sig, round_inc_bv, &unused);

	if (exp >= emax - 2) {
		// handle overflow and underflow
		if ((st32)exp < 0) {
			// extremely small
			bool is_tiny = (exp < -1) || (!(rz_bv_msb(possible_sig)));

			rz_bv_shift_right_jammed(possible_sig, (ut32)(-(st32)exp));
			exp = 0;

			// update round info
			should_round = detect_should_round(possible_sig, round_bits_bound);
			is_halfway = detect_halfway(sig, round_bits_bound);

			if (is_tiny && should_round) {
				ret->exception |= RZ_FLOAT_E_UNDERFLOW;
			}
		} else if ((exp > emax - 2) || (rz_bv_msb(possible_sig))) {
			// overflow
			ret->exception |= RZ_FLOAT_E_OVERFLOW;
			ret->exception |= RZ_FLOAT_E_INEXACT;

			// gen a num near inf
			if (round_inc_val) {
				ret->s = gen_inf_bv(sign, format);
			} else {
				RzBitVector *one = rz_bv_new_one(total_len);
				RzBitVector *inf = gen_inf_bv(sign, format);
				ret->s = rz_bv_sub(inf, one, &unused);
				rz_bv_free(one);
				rz_bv_free(inf);
				inf = NULL;
				one = NULL;
			}

			rz_bv_free(possible_sig);
			rz_bv_free(round_inc_bv);
			return ret;
		}
	}

	// shift for packing
	rz_bv_rshift(possible_sig, round_bits_bound);

	if (should_round) {
		ret->exception |= RZ_FLOAT_E_INEXACT;
	}

	// detect half way
	if (is_halfway && is_rne) {
		// set lsb == 0
		rz_bv_set(possible_sig, 0, false);
	}

	if (rz_bv_is_zero_vector(possible_sig)) {
		// NaN
		exp = 0;
	}

	// pack float
	RzBitVector *exp_bv = rz_bv_new_from_ut64(total_len, exp);
	ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	rz_bv_lshift(exp_bv, man_len);
	ret->s = rz_bv_add(exp_bv, possible_sig, &unused);
	rz_bv_set(ret->s, total_len - 1, sign);

	// clean
	rz_bv_free(round_inc_bv);
	rz_bv_free(exp_bv);
	rz_bv_free(possible_sig);

	return ret;
}

/**
 * detect if should drop extra tailing bits in rounding
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
		ret = rz_bv_cut_head(sig_dup, shift_dist);
	}

	// default is drop
	*should_inc = false;

	if (mode == RZ_FLOAT_RMODE_RNE || mode == RZ_FLOAT_RMODE_RNA) {
		bool guard_bit = rz_bv_get(ret, 2);
		bool round_bit = rz_bv_get(ret, 1);
		bool sticky_bit = rz_bv_get(ret, 0);

		// for G R S bits
		//     > 1 0 0 : round up
		//     = 1 0 0 : ties
		//     < 1 0 0 : round down
		if (guard_bit == 0) {
			*should_inc = 0;
		} else if (!round_bit && !sticky_bit) {
			// ties
			if (mode == RZ_FLOAT_RMODE_RNE) {
				bool is_odd = rz_bv_get(sig, 0);
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
 * new version of rounding
 * this function is a wrapper of round_significant, it manage the rounded result and exponent change
 * TODO : report exception
 * TODO : test and then replace the old version
 * \param sign sign of bitvector
 * \param exp exponent value, no bias
 * \param sig significant, expect unsigned bitvector
 * \param format format of float type
 * \param mode rounding mode
 * \return a float of type `format`, converted from `sig`
 */
static RZ_OWN RzFloat *round_float_bv_new(bool sign, ut32 exp, RzBitVector *sig, RzFloatFormat format, RzFloatRMode mode) {
	rz_return_val_if_fail(sig, NULL);
	RzFloat *ret;

	ut32 sig_len = rz_bv_len(sig) - rz_bv_clz(sig);
	if (sig_len == 0) {
		// TODO: add set_sign and use set_sign function
		ret = rz_float_new_zero(format);
		rz_bv_set(ret->s, rz_bv_len(ret->s) - 1, sign);
		return ret;
	}

	exp += sig_len - 1;
	ut32 exp_max = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);

	// check overflow
	if (exp > exp_max) {
		ret = rz_float_new_inf(format, sign);
		return ret;
	}

	bool should_inc;
	ut32 bit_prec = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
	RzBitVector *rounded_tmp = round_significant(sign, sig, bit_prec, mode, &should_inc);

	if (rounded_tmp == NULL) {
		// TODO: error and report in code
		// should_inc / sig is NULL
		return NULL;
	}

	// convert rounded bitv to fit given format
	ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	RzBitVector *rounded_sig = rz_bv_prepend_zero(rounded_tmp, total_len - rz_bv_len(rounded_tmp));

	// free rounded tmp result
	rz_bv_free(rounded_tmp);
	rounded_tmp = NULL;

	if (should_inc) {
		ut32 sig_carry_pos = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN) + 1;
		RzBitVector *one = rz_bv_new_one(total_len);
		rounded_tmp = rz_bv_add(rounded_sig, one, NULL);
		rz_bv_free(one);

		bool sig_carry = rz_bv_get(rounded_tmp, sig_carry_pos);
		if (sig_carry) {
			// change exponent, renormalize
			exp += 1;
			if (exp > exp_max) {
				// overflow
				ret = rz_float_new_inf(format, sign);
				rz_bv_free(rounded_sig);
				rz_bv_free(rounded_tmp);
				return ret;
			}

			// renormalize significant
			rz_bv_rshift(rounded_tmp, 1);
		}

		rz_bv_free(rounded_sig);
		rounded_sig = rounded_tmp;
		rounded_tmp = NULL;
	}

	// pack to float
	ret = rz_float_new(format);
	rz_bv_copy(rounded_sig, ret->s);

	rz_bv_free(rounded_sig);
	return ret;
}