#include "float_internal.c"

/// Be used in RzFloat
RZ_API ut32 rz_float_get_format_info(RzFloatFormat format, RzFloatInfo which_info) {
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
            RZ_LOG_ERROR("TODO");
            return 0;
    }
}

RZ_API void rz_float_fini(RZ_NONNULL RzFloat *f) {
    rz_return_if_fail(f);
    rz_bv_free(f->s);
    memset(f, 0, sizeof(RzFloat));
}

RZ_API void rz_float_free(RZ_NULLABLE RzFloat *f) {
    if (!f) {
        return;
    }
    rz_float_fini(f);
    free(f);
}

RZ_API bool rz_float_init(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, false);
    RzFloatFormat format = f->r;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);

    f->s = rz_bv_new(1 + exp_len + man_len);
    if (!f->s) {
        return false;
    }

    return true;
}

RZ_API RZ_OWN RzFloat *rz_float_new(RzFloatFormat format) {
    RzFloat *f = RZ_NEW(RzFloat);
    if (!f) {
        return NULL;
    }
    f->r = format;

    if (!rz_float_init(f)) {
        free(f);
        return NULL;
    }

    return f;
}

RZ_API RZ_OWN RzFloat *rz_float_dup(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, NULL);
    RzFloat *cp = RZ_NEW(RzFloat);
    if (!cp) {
        RZ_LOG_ERROR("Dup float failed")
        return NULL;
    }

    cp->r = f->r;
    cp->s = rz_bv_dup(f->s);

    return cp;
}

RZ_API bool rz_float_set_from_single(RZ_NONNULL RzFloat *f, float value) {
    rz_return_val_if_fail(f, false);

    /// TODO : should we support single float -> a given format float ?
    /// NOTE: Implement set a single float from single only
    ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
    /// check if given RzFloat is a IEEE754-binary32
    if (exp_len != 8 || man_len != 23) {
        RZ_LOG_WARN("Do not support single to other float conversion in set_from");
        return false;
    }

    rz_bv_set_from_bytes_le(
            f->s,
            (ut8 *) &value,
            0,
            exp_len + man_len + 1);

    return f;
}

RZ_API bool rz_float_set_from_double(RZ_NONNULL RzFloat *f, double value) {
    rz_return_val_if_fail(f, false);

    /// TODO : should we support double float -> a given format float ?
    /// NOTE: Implement set a single float from single only
    ut32 exp_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(f->r, RZ_FLOAT_INFO_MAN_LEN);
    /// check if given RzFloat is a IEEE754-binary32
    if (exp_len != 11 || man_len != 52) {
        RZ_LOG_WARN("Do not support double to other float conversion in set_from");
        return false;
    }

    rz_bv_set_from_bytes_le(
            f->s,
            (ut8 *) &value,
            0,
            exp_len + man_len + 1);

    return f;
}

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

RZ_API RZ_OWN RzBitVector *rz_float_get_exponent_squashed(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, NULL);
    return get_exp_squashed(f->s, f->r);
}

RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_squashed(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, NULL);
    return get_man_squashed(f->s, f->r);
}

RZ_API RZ_OWN RzBitVector *rz_float_get_exponent(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, NULL);
    return get_exp(f->s, f->r);
}

RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, NULL);
    return get_man(f->s, f->r);
}

RZ_API bool rz_float_get_sign(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, false);
    return get_sign(f->s, f->r);
}

static RZ_OWN RzFloat *rz_float_add_mag(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, bool sign, RzFloatRMode mode) {
    rz_return_val_if_fail(left && right, NULL);
    RzBitVector *l_exp = rz_float_get_exponent(left);
    RzBitVector *l_mantissa = rz_float_get_mantissa(left);
    RzBitVector *r_exp = rz_float_get_exponent(right);
    RzBitVector *r_mantissa = rz_float_get_mantissa(right);
    RzBitVector *result_bv; /// be packed into float, do not free
    RzBitVector *result_exp, *result_sig;  /// free after packed to result_bv
    RzBitVector *tmp; /// free and set to NULL after use immediately
    RzBitVector *borrow_l_man, *borrow_l_exp; /// borrowed bv, do not free
    RzBitVector *borrow_r_exp, *borrow_r_man; /// borrowed bv, do not free
    RzFloat *ret;

    /// Create Magic Patterns for float arithmetic
    ut32 exp_len = rz_float_get_format_info(left->r, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(left->r, RZ_FLOAT_INFO_MAN_LEN);
    ut32 total = man_len + exp_len + 1;
    /// 1. inf/NaN exponent pattern
    RzBitVector *m1 = create_inf_nan_pattern(total, exp_len);
    /// 2. for l_exp == r_exp normal case
    RzBitVector *m2 = rz_bv_new(total);
    rz_bv_set(m2, total - exp_len, true);
    /// 3. for l_exp != r_exp case
    RzBitVector *m3 = rz_bv_new(total);
    rz_bv_set(m3, total - 3, true);
    /// 4. for l_exp != r_exp limit
    RzBitVector *m4 = rz_bv_new(total);
    rz_bv_set(m3, total - 2, true);

    bool carry, borrow;
    RzBitVector *exp_diff = rz_bv_sub(l_exp, r_exp, &borrow);

    /// l_exp == r_exp
    if (rz_bv_is_zero_vector(exp_diff)) {
        /// l_exp == r_exp == 0
        if (rz_bv_is_zero_vector(l_exp)) {
            result_bv = rz_bv_add(left->s, r_mantissa, &carry);
            goto pack_float;
        }

        /// l_exp == r_exp == inf or NaN
        if (rz_bv_eq(l_exp, m1)) {
            /// is NaN
            if (!rz_bv_is_zero_vector(l_mantissa) || !rz_bv_is_zero_vector(r_mantissa)) {
                ret = propagate_nan(left->s, right->s, left->r);
                goto clean_local;
            }

            /// is Inf
            result_bv = rz_bv_dup(left->s);
            goto pack_float;
        }

        /// normal case l_exp == r_exp
        result_exp = rz_bv_dup(l_exp);
        tmp = rz_bv_add(l_mantissa, r_mantissa, &carry);
        result_sig = rz_bv_add(m2, tmp, &carry);
        rz_bv_free(tmp);tmp = NULL;
        rz_bv_lshift(result_sig, exp_len - 2);
    } else {
        /// l_exp != r_exp
        rz_bv_lshift(l_mantissa, exp_len - 2);
        rz_bv_lshift(r_mantissa, exp_len - 2);

        /// exp_diff < 0, swap to keep l >= r
        bool swap = borrow;
        if (swap) {
            borrow_l_exp = r_exp;
            borrow_l_man = r_mantissa;
            borrow_r_exp = l_exp;
            borrow_r_man = l_mantissa;
            /// exp_diff = -exp_diff
            tmp = rz_bv_neg(exp_diff);
            rz_bv_free(exp_diff);
            exp_diff = tmp;
            tmp = NULL;
        } else {
            borrow_l_exp = l_exp;
            borrow_l_man = l_mantissa;
            borrow_r_exp = r_exp;
            borrow_r_man = r_mantissa;
        }

        /// exp == inf/NaN
        if (rz_bv_eq(borrow_l_exp, m1)) {
            /// is NaN
            if (!rz_bv_is_zero_vector(borrow_l_man)) {
                /// goto propagate NaN
                ret = propagate_nan(left->s, right->s, left->r);
                goto clean_local;
            }

            /// is Inf
            result_bv = rz_bv_dup(left->s);
            goto pack_float;
        }

        /// normal case
        result_exp = rz_bv_dup(borrow_l_exp);
        if (!rz_bv_is_zero_vector(borrow_r_exp)) {
            /// borrow_r_man += m3
            tmp = rz_bv_add(borrow_r_man, m3, &carry);
            rz_bv_free(borrow_r_man);
            borrow_r_man = tmp;
            tmp = NULL;
        } else {
            rz_bv_lshift(borrow_r_man, 1);
        }

        /// borrow_r_man = Jamed_shift(borrow_r_man)
         rz_bv_shift_right_jammed(borrow_r_man, rz_bv_to_ut32(exp_diff));

        /// calculate significant
        tmp = rz_bv_add(borrow_l_man, borrow_r_man, &carry);
        result_sig = rz_bv_add(m3, tmp, &carry);
        rz_bv_free(tmp);
        if (rz_bv_ule(result_sig, m4) && !rz_bv_eq(result_sig, m4)) {
            /// result_exp -= 1; result_mantissa <<= 1
            RzBitVector *one = rz_bv_new_one(result_exp->len);
            tmp = rz_bv_sub(result_exp, one, &borrow);
            rz_bv_free(result_exp);
            rz_bv_free(one);
            result_exp = tmp;
            tmp = NULL;
            rz_bv_lshift(result_sig, 1);
        }

        /// swap back for clean
        if (swap) {
            l_exp = borrow_r_exp;
            l_mantissa = borrow_r_man;
            r_exp = borrow_l_exp;
            r_mantissa = borrow_l_man;
        } else {
            r_exp = borrow_r_exp;
            r_mantissa = borrow_r_man;
            l_exp = borrow_l_exp;
            l_mantissa = borrow_r_man;
        }
    }
    ret = round_float_bv(sign, result_exp, result_sig, left->r, mode);
    goto clean_local;

pack_float:
    ret = RZ_NEW(RzFloat);
    ret->r = left->r;
    ret->s = result_bv;

clean_local:
    /// clean
    rz_bv_free(l_exp);
    rz_bv_free(l_mantissa);
    rz_bv_free(r_exp);
    rz_bv_free(r_mantissa);
    rz_bv_free(exp_diff);
    rz_bv_free(m1);
    rz_bv_free(m2);
    rz_bv_free(m3);
    rz_bv_free(m4);
    rz_bv_free(result_exp);
    rz_bv_free(result_sig);

    return ret;
}

static RZ_OWN RzFloat *rz_float_sub_mag(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, bool sign, RzFloatRMode mode)
{
    RzBitVector *l_exp = rz_float_get_exponent(left);
    RzBitVector *l_mantissa = rz_float_get_mantissa(left);
    RzBitVector *r_exp = rz_float_get_exponent(right);
    RzBitVector *r_mantissa = rz_float_get_mantissa(right);
    RzBitVector *result_bv; /// be packed into float, do not free
    RzBitVector *result_exp, *result_sig;  /// free after packed to result_bv
    RzBitVector *tmp; /// free and set to NULL after use immediately
    RzBitVector *borrow_l_man, *borrow_l_exp; /// borrowed bv, do not free
    RzBitVector *borrow_r_exp, *borrow_r_man; /// borrowed bv, do not free
    RzFloat *ret;

    RzFloatFormat format = left->r;
    RzFloatException exception = 0;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 total = exp_len + man_len;

    /// Generate Magic Patterns
    /// 1. inf/NaN exponent pattern
    RzBitVector *m1 = create_inf_nan_pattern(total, exp_len);
    /// 2. default NaN
    RzBitVector *default_nan = rz_bv_new(left->s->len);
    for (ut32 i = man_len; i < total - 1; ++i) {
        rz_bv_set(default_nan, i, true);
    }
    /// 3. zero
    RzBitVector *zero = rz_bv_new(left->s->len);
    /// 4. one
    RzBitVector *one = rz_bv_new_one(left->s->len);

    bool borrow, carry;
    RzBitVector *exp_diff = rz_bv_sub(l_exp, r_exp, &borrow);

    /// l_exp == r_exp
    if (rz_bv_is_zero_vector(exp_diff))
    {
        if (rz_bv_is_zero_vector(l_exp))
        {
            result_bv = rz_bv_add(left->s, r_mantissa, &carry);
            goto pack_float;
        }

        /// is inf or NaN
        if (rz_bv_eq(l_exp, m1))
        {
            // NaN
            if (!rz_bv_is_zero_vector(l_mantissa) || !rz_bv_is_zero_vector(r_mantissa))
            {
                ret = propagate_nan(left->s, right->s, format);
                goto clean_local;
            }

            // Inf
            exception |= RZ_DIFF_OP_INVALID;
            result_bv = rz_bv_dup(default_nan);
            goto pack_float;
        }

        RzBitVector *sig_diff = rz_bv_sub(l_mantissa, r_mantissa, &borrow);
        if (rz_bv_is_zero_vector(sig_diff))
        {
            result_bv = pack_float_bv(mode == RZ_FLOAT_RMODE_RTN, zero, zero, format);
            goto pack_float;
        }

        if (!rz_bv_is_zero_vector(l_exp))
        {
            tmp = rz_bv_sub(l_exp, one, &borrow);
            rz_bv_free(l_exp);
            l_exp = tmp;
            tmp = NULL;
        }

        ut32 shift_dist = rz_bv_clz(sig_diff) - 11;
        tmp = rz_bv_new_from_ut64(l_exp->len, shift_dist);
        result_exp = rz_bv_sub(l_exp, tmp, &borrow);
        rz_bv_free(tmp);
        tmp = NULL;

        /// result_exp < 0
        if (borrow) {
            shift_dist = rz_bv_to_ut32(l_exp);
            rz_bv_free(result_exp);
            result_exp = rz_bv_dup(zero);
        }

        rz_bv_lshift(sig_diff, shift_dist);
        result_bv = pack_float_bv(sign, result_exp, sig_diff, format);
    }

pack_float:
clean_local:
    return ret;
}

RZ_API RZ_OWN RzFloat *rz_float_add(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right);

RZ_API void test_internal_in_develop(void) {
    float val = 1.5f;
    RzFloat *f = rz_float_new_from_single(val);

    char *str = rz_bv_as_string(f->s);
    RzBitVector *exp = rz_float_get_exponent_squashed(f);
    RzBitVector *mantissa = rz_float_get_mantissa_squashed(f);
    char *exp_s = rz_bv_as_string(exp);
    char *m_s = rz_bv_as_string(mantissa);
    bool sign = rz_float_get_sign(f);

    printf("[FLOAT] 1.5f : %s\n", str);
    printf("[FLOAT] pack : 1.5f : %c | %s | %s\n",
           sign ? '1' : '0',
           exp_s,
           m_s);

    rz_bv_free(exp);
    rz_bv_free(mantissa);
    free(exp_s);
    free(m_s);
    free(str);
    rz_float_free(f);
}