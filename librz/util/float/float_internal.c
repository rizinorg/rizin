#include "rz_util.h"

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
            return 0;
    }
}


// TODO : move this to bitvector.c in the future
/**
 * Check if every bits of the bitvector are set to 1
 * \param x RzBitVector, pointer to bv
 * \return ret bool, return true if bv is a full bitvector, false if not
 */
static bool rz_bv_is_full_vector(RZ_NONNULL const RzBitVector *x) {
    rz_return_val_if_fail(x, false);

    if (x->len <= 64) {
        return x->bits.small_u == ~0;
    }

    rz_return_val_if_fail(x->bits.large_a, false);

    for (ut32 i = 0; i < x->_elem_len; ++i) {
        if (x->bits.large_a[i] == 0) {
            return false;
        }
    }
    return true;
}

/**
 * Shift right, but keeps LSB true if hit 1 during shift
 * \param x RzBitVector, pointer to bv
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
 * @param bv RzBitVector, the bitvector interpreted as float
 * @param format RzFloatFormat, specifying the format of float
 * @return a bitvector representation of exponent
 */
static RZ_OWN RzBitVector *get_exp(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(exp_len + man_len + 1);
    rz_bv_copy_nbits(bv, man_len, res, 0, exp_len);

    return res;
}

/**
 * Get a bitvector representation of mantissa, have the same length of parameter `bv`
 * @param bv RzBitVector, the bitvector interpreted as float
 * @param format RzFloatFormat, specifying the format of float
 * @return a bitvector representation of mantissa
 */
static RZ_OWN RzBitVector *get_man(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(exp_len + man_len + 1);
    rz_bv_copy_nbits(bv, 0, res, 0, man_len);

    return res;
}

/**
 * Get a bitvector representation of mantissa, twice as long as `bv` length.
 * @param bv RzBitVector, the bitvector interpreted as float
 * @param format RzFloatFormat, specifying the format of float
 * @return a bitvector representation of mantissa
 */
static RZ_OWN RzBitVector *get_man_stretched(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 total = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
    RzBitVector *res = rz_bv_new(total * 2);
    rz_bv_copy_nbits(bv, 0, res, 0, man_len);
}

/**
 * Get a bitvector representation of exponent. The length is depending on the exponent width (specified by `format`)
 * @param bv RzBitVector, the bitvector interpreted as float
 * @param format RzFloatFormat, specifying the format of float
 * @return a bitvector representation of exponent
 */
static RZ_OWN RzBitVector *get_exp_squashed(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(exp_len);
    rz_bv_copy_nbits(bv, man_len, res, 0, exp_len);

    return res;
}

/**
 * Get a bitvector representation of mantissa. The length is depending on the mantissa width (specified by `format`)
 * @param bv RzBitVector, the bitvector interpreted as float
 * @param format RzFloatFormat, specifying the format of float
 * @return a bitvector representation of mantissa
 */
static RZ_OWN RzBitVector *get_man_squashed(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(man_len);
    rz_bv_copy_nbits(bv, 0, res, 0, man_len);

    return res;
}

/**
 * Get the sign of bv
 * @param bv RzBitVector, the bitvector interpreted as float
 * @param format RzFloatFormat, specifying the format of float
 * @return bool sign of float bv
 */
static RZ_OWN bool get_sign(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    return rz_bv_get(bv, bv->len - 1);
}

static bool is_signal_nan_bv(RzBitVector *float_bv, RzFloatFormat format) {
    RzBitVector *exp = get_exp_squashed(float_bv, format);
    RzBitVector *sig = get_man_squashed(float_bv, format);
    bool ret = false;

    if (!rz_bv_is_full_vector(exp) || !rz_bv_is_zero_vector(sig)) {
        ret = false;
    } else {
        ret = rz_bv_msb(sig) ? false : true;
    }

    rz_bv_free(exp);
    rz_bv_free(sig);
    return ret;
}

static bool is_nan_bv(RzBitVector *float_bv, RzFloatFormat format) {
    RzBitVector *exp = get_exp_squashed(float_bv, format);
    RzBitVector *sig = get_man_squashed(float_bv, format);
    bool ret = false;

    if (!rz_bv_is_full_vector(exp) || !rz_bv_is_zero_vector(sig)) {
        ret = false;
    } else {
        ret = true;
    }

    rz_bv_free(exp);
    rz_bv_free(sig);
    return ret;
}

/**
 * Pack sign, exponent, and significant together to float bv
 * @param sign sign of float
 * @param exp exponent part, can be squashed or normal
 * @param sig significant part (mantissa with a leading bit 1), can be squashed or normal
 * @param format format of float
 * @return RzBitVector the final bitvector representation of RzFloat
 */
static RZ_OWN RzBitVector *pack_float_bv(bool sign, RzBitVector *exp, RzBitVector *sig, RzFloatFormat format)
{
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 total = man_len + exp_len;
    RzBitVector *ret = rz_bv_new(total);
    /// copy exp to ret
    rz_bv_copy_nbits(exp, 0, ret, man_len, exp_len);
    rz_bv_copy_nbits(sig, 0, ret, 0, man_len);
    rz_bv_set(ret, total - 1, sign);

    return ret;
}

/**
 * Detecting if a significant should be rounded
 * @param sig RzBitVector significant bv before rounding `point` is at the 2nd bit counted from MSB (01.MM MMMM ...)
 * @param r_bits_bound ut32 boundary of round bits
 * @return bool return true if significant should be rounded, else return false
 */
inline bool detect_should_round(RzBitVector *sig, ut32 r_bits_bound)
{
    bool should_round = false;
    for (ut32 i = 0; i < r_bits_bound; ++i)
    {
        if (rz_bv_get(sig, i) == true){
            should_round = true;
            break;
        }
    }
    return should_round;
}

/**
 * Detecting if the round bits is in the halfway (MSB is 1, the other bits is 0)
 * @param sig RzBitVector significant bv before rounding `point` is at the 2nd bit counted from MSB (01.MM MMMM ...)
 * @param r_bits_bound ut32 boundary of round bits
 * @return bool return true if significant should be rounded, else return false
 */
static bool detect_halfway(RzBitVector *sig, ut32 r_bits_bound)
{
    for (ut32 i = 0; i < r_bits_bound - 1; ++i)
    {
        if (rz_bv_get(sig, i) == true)
        {
            return false;
        }
    }

    if (rz_bv_get(sig, r_bits_bound - 1) == true)
    {
        return true;
    }

    return false;
}

/**
 * Generate an infinite bitvector
 * @param sign sign of an inf
 * @param format RzFloatFormat format of float
 * @return an infinite bitvector
 */
static RZ_OWN RzBitVector *gen_inf_bv(bool sign, RzFloatFormat format)
{
    return NULL;
}

/**
 * Trying to round float component
 * @param sign sign of float
 * @param exp ut32 value of exponent
 * @param sig RzBitVector significant bv before rounding `point` is at the 2nd bit counted from MSB (01.MM MMMM ...)
 * @param format RzFloatFormat format of float
 * @param mode Rounding mode
 * @return RzFloat A rounded float
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

    /// add 1 to the LSB of sig
    ut32 round_inc_val = (bias + 1) >> 1;

    /// handle round to max(+inf)/min(-inf)
    /// if + && round towards +inf : use bias as inc
    /// if - && round towards -inf : use bias as inc
    if (!is_rne && !is_rna)
    {
        round_inc_val =
                (mode == (sign ? RZ_FLOAT_RMODE_RTN : RZ_FLOAT_RMODE_RTP))
                ? bias
                : 0;
    }

    /// get round bits
    /// every num before rounding have the following pattern
    /// 01MM MMMM MMMM ...
    /// we will leave (sign_len + exp_len) bits before mantissa part
    /// and thus the lower (sign_len + exp_len - 2) bits will be r-shifted out
    /// in another word, the lower bits will be guard bit, round bit and sticky bits
    ut32 round_bits_bound = (exp_len + 1 - 2);
    ut32 should_round = detect_should_round(sig, round_bits_bound);
    ut32 guard_bit_pos = round_bits_bound - 1;
    ut32 is_halfway = detect_halfway(sig, round_bits_bound);

    RzBitVector *possible_sig = NULL;
    bool unused;
    RzBitVector *round_inc_bv = rz_bv_new_from_ut64(sig->len, round_inc_val);
    possible_sig = rz_bv_add(sig, round_inc_bv, &unused);

    if (exp >= emax - 2)
    {
        /// handle overflow and underflow
        if ((st32)exp < 0)
        {
            /// extremely small
            bool is_tiny = (exp < -1)
                    || (!(rz_bv_msb(possible_sig)));

            rz_bv_shift_right_jammed(possible_sig, (ut32)(-(st32)exp));
            exp = 0;

            /// update round info
            should_round = detect_should_round(possible_sig, round_bits_bound);
            is_halfway = detect_halfway(sig, round_bits_bound);

            if (is_tiny && should_round) {
                ret->exception |= RZ_FLOAT_E_UNDERFLOW;
            }
        }
        else if ((exp > emax - 2) || (rz_bv_msb(possible_sig)))
        {
            /// overflow
            ret->exception |= RZ_FLOAT_E_OVERFLOW;
            ret->exception |= RZ_FLOAT_E_INEXACT;

            /// gen a num near inf
            if (round_inc_val) {
                ret->s = gen_inf_bv(sign, format);
            }
            else {
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

    /// shift for packing
    rz_bv_rshift(possible_sig, round_bits_bound);

    if (should_round) {
        ret->exception |= RZ_FLOAT_E_INEXACT;
    }

    /// detect half way
    if (is_halfway && is_rne)
    {
        /// set lsb == 0
        rz_bv_set(possible_sig, 0, false);
    }

    if (rz_bv_is_zero_vector(possible_sig))
    {
        /// NaN
        exp = 0;
    }

    /// pack float
    RzBitVector *exp_bv = rz_bv_new_from_ut64(total_len, exp);
    ret->s = rz_bv_add(exp_bv, possible_sig, &unused);
    rz_bv_set(ret->s, total_len - 1, sign);

    /// clean
    rz_bv_free(round_inc_bv);
    rz_bv_free(exp_bv);
    rz_bv_free(possible_sig);

    return ret;
}


























