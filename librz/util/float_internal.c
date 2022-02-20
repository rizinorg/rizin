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

// TODO : move this to bitvector.c in the future
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

static RZ_OWN RzBitVector *get_exp(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(exp_len + man_len + 1);
    rz_bv_copy_nbits(bv, man_len, res, 0, exp_len);

    return res;
}

static RZ_OWN RzBitVector *get_man(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(exp_len + man_len + 1);
    rz_bv_copy_nbits(bv, 0, res, 0, man_len);

    return res;
}

static RZ_OWN RzBitVector *get_exp_squashed(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(exp_len);
    rz_bv_copy_nbits(bv, man_len, res, 0, exp_len);

    return res;
}

static RZ_OWN RzBitVector *get_man_squashed(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    RzBitVector *res = rz_bv_new(man_len);
    rz_bv_copy_nbits(bv, 0, res, 0, man_len);

    return res;
}

static RZ_OWN bool get_sign(RZ_NONNULL RzBitVector *bv, RzFloatFormat format) {
    rz_return_val_if_fail(bv, NULL);

    return rz_bv_get(bv, bv->len - 1);
}

static RZ_OWN RzBitVector *create_inf_nan_pattern(ut32 len, ut32 exp_len) {
    RzBitVector *bv = rz_bv_new(len);
    for (ut32 i = 0; i < exp_len; ++i) {
        rz_bv_set(bv, i, true);
    }
    return bv;
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

static RZ_OWN RzFloat *propagate_nan(RzBitVector *left, RzBitVector *right, RzFloatFormat format) {
    RzBitVector *ret_bv;
    // TODO : move float_new to header
    RzFloat *ret = RZ_NEW0(RzFloat);

    RzBitVector *magic = rz_bv_new(left->len);
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 total = exp_len + man_len;
    rz_bv_set(magic, total - (exp_len + 2), true);

    if (is_signal_nan_bv(left, format) || is_signal_nan_bv(right, format)) {
        if (is_nan_bv(left, format)) {
            ret_bv = rz_bv_or(left, magic);
            rz_bv_free(magic);
            ret->s = ret_bv;
            ret->r = format;
            ret->exception |= RZ_FLOAT_E_INVALID_OP;
            return ret;
        }
    }

    left = is_nan_bv(left, format) ? left : right;
    ret_bv = rz_bv_or(left, magic);
    rz_bv_free(magic);
    ret->s = ret_bv;
    ret->r = format;
    return ret;
}

static RZ_OWN RzFloat *
round_float_bv(bool sign, RzBitVector *exp, RzBitVector *sig, RzFloatFormat format, RzFloatRMode mode) {
    bool round_to_even = (mode == RZ_FLOAT_RMODE_RNE);
    RzBitVector *borrow_round_inc = NULL;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    RzBitVector *tmp = NULL, *tmp2 = NULL;
    RzFloat *ret;
    bool carry;

    ret = RZ_NEW0(RzFloat);
    ret->r = format;

    /// generate magic pattern
    /// 1. normal round inc
    RzBitVector *m1 = rz_bv_new(sig->len);
    rz_bv_set(m1, exp_len - 2, true);
    /// 2. round to min/max inc
    RzBitVector *m2 = rz_bv_new(sig->len);
    for (ut32 i = 0; i < exp_len - 1; ++i) {
        rz_bv_set(m2, i, true);
    }
    /// 3. zero
    RzBitVector *zero = rz_bv_new_zero(sig->len);
    /// 4. m3 to pack float
    RzBitVector *m3 = rz_bv_new(sig->len);
    for (ut32 i = 0; i < exp_len; ++i) {
        rz_bv_set(m3, i, true);
    }
    /// 5. exp bound
    RzBitVector *exp_bound = rz_bv_dup(m3);
    rz_bv_set(exp_bound, 1, false);
    /// 6. sig bound
    RzBitVector *sig_bound = rz_bv_new(sig->len);
    rz_bv_set(sig_bound, sig->len, true);
    /// 7. -1 == ~0
    RzBitVector *neg_one = rz_bv_not(zero);
    /// 8. 1
    RzBitVector *one = rz_bv_new_one(sig->len);
    /// 9. ~1
    RzBitVector *not_one = rz_bv_not(one);

    /// generate round increment
    if (!round_to_even && (mode != RZ_FLOAT_RMODE_RNA)) {
        if (mode == (sign ? RZ_FLOAT_RMODE_RTN : RZ_FLOAT_RMODE_RTP)) {
            borrow_round_inc = m2;
        } else {
            borrow_round_inc = zero;
        }
    } else {
        borrow_round_inc = m1;
    }

    RzBitVector *round_bits = rz_bv_and(sig, m2);
    bool is_tiny = false;

    if (rz_bv_ule(exp_bound, exp)) {
        /// calculate sig + inc
        tmp = rz_bv_add(sig, borrow_round_inc, &carry);
        if (rz_bv_sle(exp, zero) && !rz_bv_is_zero_vector(exp)) {
            /// TODO : add skipped check tininess before rounding in Berkley softfloat
            /// exp < -1 || sig + inc < bound
            is_tiny = (rz_bv_sle(exp, neg_one) && !rz_bv_is_zero_vector(exp)) ||
                      (rz_bv_sle(tmp, sig_bound) && !rz_bv_eq(tmp, sig_bound));
            // sig = jammed_shift_r(sig, -exp)
            rz_bv_free(tmp);
            tmp = NULL;
            rz_bv_shift_right_jammed(sig, -rz_bv_to_ut32(exp));

            // exp = 0
            rz_bv_free(exp);
            exp = rz_bv_dup(zero);

            rz_bv_free(round_bits);
            round_bits = rz_bv_and(sig, m2);

            if (is_tiny && !rz_bv_is_zero_vector(round_bits)) {
                ret->exception |= RZ_FLOAT_E_UNDERFLOW;
            }
        }
        else if ((rz_bv_sle(exp_bound, exp) && !rz_bv_is_zero_vector(exp))
            || rz_bv_ule(sig_bound, tmp))
        {
            ret->exception |= RZ_FLOAT_E_OVERFLOW | RZ_FLOAT_E_INEXACT;
            rz_bv_free(tmp);
            tmp = pack_float_bv(sign, exp_bound, zero, format);
            ret->s = rz_bv_sub(
                    tmp,
                    rz_bv_is_zero_vector(borrow_round_inc) ? one : zero,
                    &carry);
            rz_bv_free(tmp);
            tmp = NULL;
            goto clean_local;
        }
    }

    tmp = rz_bv_add(sig, borrow_round_inc, &carry);
    rz_bv_rshift(tmp, exp_len - 1);
    rz_bv_free(sig);
    sig = tmp;
    tmp = NULL;

    if (!rz_bv_is_zero_vector(round_bits)) {
        ret->exception |= RZ_FLOAT_E_INEXACT;
    }

    bool mask_bit;
    tmp = rz_bv_xor(round_bits, m1);
    mask_bit = rz_bv_is_zero_vector(tmp) & round_to_even;
    rz_bv_free(tmp);
    tmp = rz_bv_and(
            sig,
            mask_bit ? not_one : neg_one);
    rz_bv_free(sig);
    sig = tmp;
    tmp = NULL;

    if (rz_bv_is_zero_vector(sig)) {
        rz_bv_free(exp);
        exp = rz_bv_dup(zero);
    }

    ret->s = pack_float_bv(sign, exp, sig, format);
clean_local:
    rz_bv_free(m1);
    rz_bv_free(m2);
    rz_bv_free(m3);
    rz_bv_free(zero);
    rz_bv_free(one);
    rz_bv_free(not_one);
    rz_bv_free(neg_one);
    rz_bv_free(exp_bound);
    rz_bv_free(sig_bound);
    rz_bv_free(round_bits);
    return ret;
}


























