#include "float_internal.c"

/**
 * This file implements IEEE-754 binary float number (32/64/128)
 */

typedef enum foperation_enum {
    INTERN_FOP_ADD,
    INTERN_FOP_SUB,
    INTERN_FOP_MUL,
    INTERN_FOP_DIV,
    INTERN_FOP_REM
} InternalFOpEnum;

/**
 * Get const attribute from float
 * @param format RzFloatFormat, format of a float
 * @param which_info Specify an attribute
 * @return ut32 const value bind with `which_info`
 */
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

/**
 * Finish the bv inside the float, and set all to NULL
 * @param f float
 */
RZ_API void rz_float_fini(RZ_NONNULL RzFloat *f) {
    rz_return_if_fail(f);
    rz_bv_free(f->s);
    memset(f, 0, sizeof(RzFloat));
}

/**
 * Destroy the float structure
 * @param f float
 */
RZ_API void rz_float_free(RZ_NULLABLE RzFloat *f) {
    if (!f) {
        return;
    }
    rz_float_fini(f);
    free(f);
}

/**
 * Init the bv inside float
 * @param f float
 * @return return true if init success else return false
 */
RZ_API bool rz_float_init(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, false);
    rz_float_fini(f);

    RzFloatFormat format = f->r;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 man_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);

    f->s = rz_bv_new(1 + exp_len + man_len);
    if (!f->s) {
        return false;
    }

    return true;
}

/**
 * Create bv and init it
 * @param format float format
 * @return return an RzFloat instance with zero value
 */
RZ_API RZ_OWN RzFloat *rz_float_new(RzFloatFormat format) {
    RzFloat *f = RZ_NEW(RzFloat);
    if (!f) {
        return NULL;
    }
    f->r = format;
    f->s = NULL;

    if (!rz_float_init(f)) {
        free(f);
        return NULL;
    }

    return f;
}

/**
 * Duplicate a float
 * @param f float
 * @return a copy of float
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

    return cp;
}

/**
 * Set float bv from C type `float`
 * @param f a normal float
 * @param value value of type `float`
 * @return true if success
 */
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

/**
 * Set float bv from C type `double`
 * @param f a normal float
 * @param value value of type `double`
 * @return true if success
 */
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

RZ_API RZ_OWN RzBitVector *rz_float_get_mantissa_stretched(RZ_NONNULL RzFloat *f) {
    rz_return_val_if_fail(f, NULL);
    return get_man_stretched(f->s, f->r);
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

RZ_API RzFloatSpec rz_float_detect_spec(RZ_NONNULL RzFloat *f)
{
    rz_return_val_if_fail(f, RZ_FLOAT_SPEC_NOT);

    RzFloatSpec ret = RZ_FLOAT_SPEC_NOT;
    RzBitVector *exp_squashed = get_exp_squashed(f->s, f->r);
    RzBitVector *mantissa_squashed = get_man_squashed(f->s, f->r);
    bool sign = get_sign(f->s, f->r);

    if (rz_bv_is_full_vector(exp_squashed))
    {
        /// full exp with 0 mantissa -> inf
        if (rz_bv_is_zero_vector(mantissa_squashed))
        {
            ret = sign ? RZ_FLOAT_SPEC_PINF : RZ_FLOAT_SPEC_NINF;
        }
        else
        {
            /// detect signal or quiet nan
            bool is_quiet = rz_bv_msb(mantissa_squashed);
            ret = is_quiet ? RZ_FLOAT_SPEC_QNAN : RZ_FLOAT_SPEC_SNAN;
        }
    }

    if (rz_bv_is_zero_vector(exp_squashed))
    {
        if (rz_bv_is_zero_vector(mantissa_squashed))
            ret = RZ_FLOAT_SPEC_ZERO;
    }

    rz_bv_free(exp_squashed);
    rz_bv_free(mantissa_squashed);

    return ret;
}

RZ_API bool rz_float_is_inf(RZ_NONNULL RzFloat *f)
{
    RzFloatSpec type = rz_float_detect_spec(f);
    if ((type == RZ_FLOAT_SPEC_PINF) || (type == RZ_FLOAT_SPEC_NINF))
        return true;
    return false;
}

RZ_API bool rz_float_is_nan(RZ_NONNULL RzFloat *f)
{
    RzFloatSpec type = rz_float_detect_spec(f);
    if ((type == RZ_FLOAT_SPEC_SNAN) || (type == RZ_FLOAT_SPEC_QNAN))
        return true;
    return false;
}

static RZ_OWN RzFloat *gen_inf_float(RzFloatFormat format, bool sign)
{
    /// gen a quiet NaN for return
    RzFloat *ret = rz_float_new(format);
    RzBitVector *bv = ret->s;
    ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    for (ut32 i = exp_start; i < exp_end; ++i)
    {
        rz_bv_set(bv, i, true);
    }

    /// set sign bit (MSB)
    rz_bv_set(bv, bv->len - 1, sign);

    return ret;
}

static RZ_OWN RzFloat *gen_qnan_float(RzFloatFormat format)
{
    /// gen a quiet NaN for return
    RzFloat *ret = rz_float_new(format);
    RzBitVector *bv = ret->s;
    ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    for (ut32 i = exp_start; i < exp_end; ++i)
    {
        rz_bv_set(bv, i, true);
    }
    /// set is_quiet to 1
    rz_bv_set(bv, exp_start - 1, true);
}

static RZ_OWN RzFloat *propagate_float_nan(RZ_NONNULL RzFloat *left, RzFloatSpec ltype, RZ_NONNULL RzFloat *right, RzFloatSpec rtype)
{
    bool l_is_sig_nan = ltype == RZ_FLOAT_SPEC_SNAN;
    bool r_is_sig_nan = rtype == RZ_FLOAT_SPEC_SNAN;

    /// gen a quiet NaN for return
    RzFloatFormat format = left->r;
    RzFloat *ret = rz_float_new(left->r);
    RzBitVector *bv = ret->s;
    ut32 exp_start = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 exp_end = exp_start + rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    for (ut32 i = exp_start; i < exp_end; ++i)
    {
        rz_bv_set(bv, i, true);
    }
    /// set is_quiet to 1
    rz_bv_set(bv, exp_start - 1, true);

    /// signal an exception
    if (l_is_sig_nan || r_is_sig_nan)
    {
        ret->exception |= RZ_FLOAT_E_INVALID_OP;
    }

    return ret;
}

// TODO : handle inf/NaN
static RZ_OWN RzFloat *handle_special_float(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, InternalFOpEnum op)
{
    RzFloatSpec l_type, r_type;
    l_type = rz_float_detect_spec(left);
    r_type = rz_float_detect_spec(right);

    bool l_is_inf = (l_type == RZ_FLOAT_SPEC_PINF || l_type == RZ_FLOAT_SPEC_NINF);
    bool r_is_inf = (r_type == RZ_FLOAT_SPEC_PINF || r_type == RZ_FLOAT_SPEC_NINF);
    bool l_is_nan = (l_type == RZ_FLOAT_SPEC_SNAN || l_type == RZ_FLOAT_SPEC_QNAN);
    bool r_is_nan = (r_type == RZ_FLOAT_SPEC_SNAN || r_type == RZ_FLOAT_SPEC_QNAN);
    bool l_is_zero = l_type == RZ_FLOAT_SPEC_ZERO;
    bool r_is_zero = r_type == RZ_FLOAT_SPEC_ZERO;

    /// propagate NaN
    if (l_is_nan || r_is_nan) {
        return propagate_float_nan(left, l_type, right, r_type);
    }

    bool l_sign = rz_float_get_sign(left);
    bool r_sign = rz_float_get_sign(right);
    bool sign = l_sign ^ r_sign;

    RzFloatFormat format = left->r;
    RzFloat *ret = NULL;

    switch (op) {
        case INTERN_FOP_ADD:
        case INTERN_FOP_SUB:
            if (l_is_inf || r_is_inf) {
                ret = gen_inf_float(format, l_sign);
                break;
            }
            if (l_is_zero) {
                ret = rz_float_dup(right);
                if (op == INTERN_FOP_SUB) {
                    rz_bv_set(ret->s, ret->s->len - 1, !r_sign);
                }
                break;
            }
            if (r_is_zero) {
                ret = rz_float_dup(left);
                break;
            }
            break;
        case INTERN_FOP_MUL:
            if (l_is_inf || r_is_inf) {
                ret = gen_inf_float(format, sign);
                break;
            }
            if (l_is_zero || r_is_zero) {
                /// 0 * x = 0
                ret = rz_float_new(format);
                break;
            }
            break;
        case INTERN_FOP_DIV:
            /**
             * Inf / not Inf -> Inf
             * Inf / Inf -> invalid
             * 0 / 0 -> invalid
             * 0 / not 0 -> 0
             * not 0 / 0 -> Inf */
        case INTERN_FOP_REM:
            if (l_is_inf) {
                if (!r_is_inf) {
                    ret = gen_inf_float(format, sign);
                }
                else {
                    ret = gen_qnan_float(format);
                    ret->exception |= RZ_FLOAT_E_INVALID_OP;
                }
                break;
            }

            if (l_is_zero) {
                if (r_is_zero) {
                    ret = gen_qnan_float(format);
                    ret->exception |= RZ_FLOAT_E_INVALID_OP;
                }
                else {
                    ret = rz_float_new(format);
                }
            }
            else {
                if (r_is_zero) {
                    ret = gen_inf_float(format, sign);
                }
            }
            break;
        default:
            rz_warn_if_reached();
    }

    return ret;
}

static RZ_OWN RzFloat *fadd_mag(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, bool sign, RzFloatRMode mode) {
    RzFloat *result = NULL;
    result = handle_special_float(left, right, INTERN_FOP_ADD);
    if (result) {
        /// contains INF/NaN
        return result;
    }
    /// Extract attribute from format
    RzFloatFormat format = left->r;
    ut32 mantissa_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);

    /// Extract fields from num
    RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
    RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
    RzBitVector *l_mantissa = get_man(left->s, left->r);
    RzBitVector *r_mantissa = get_man(left->s, left->r);
    RzBitVector *l_borrowed_exp = l_exp_squashed;
    RzBitVector *r_borrowed_exp = r_exp_squashed;
    RzBitVector *l_borrowed_sig = l_mantissa;
    RzBitVector *r_borrowed_sig = r_mantissa;
    RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
    RzBitVector *tmp = NULL;
    RzBitVector *exp_one = rz_bv_new_one(exp_len);
    bool unused;

    /// Handle normal float add
    st32 exp_diff = (st32) (rz_bv_to_ut32(l_exp_squashed) - rz_bv_to_ut32(r_exp_squashed));
    ut32 abs_exp_diff = exp_diff;

    /// left shift to prevent some tail bits being discard during calculating
    /// should reserve 3 bits before mantissa : ABCM MMMM MMMM MMMM ...
    /// C : for the hidden significant bit
    /// B : carry bit
    /// A : a space for possible overflow during rounding
    /// M : represent for mantissa bits
    ut32 shift_dist = (exp_len + 1) - 3;    /// mantissa have (exp_len + sign_len) free bits, and then reserve 3 bits
    ut32 hidden_bit_pos = total_len - 3;    /// the 3rd bit counted from MSB
    ut32 carry_bit_pos = total_len - 2;     /// the 2nd bit counted from MSB

    if (exp_diff == 0) {
        /// normalized float, hidden bit is 1, recover it in significant
        /// 1.MMMM MMMM ...
        if (!rz_bv_is_zero_vector(l_exp_squashed)) {
            rz_bv_lshift(l_mantissa, shift_dist);
            rz_bv_lshift(r_mantissa, shift_dist);
            rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
            rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
        }
        else {
            /// sub-normal + sub-normal
            /// sub-normal float, hidden bit is 0, so we do nothing to sigs
            /// 0.MMMM MMMM ...
            /// calculate and then pack to return
            result = RZ_NEW0(RzFloat);
            result->r = format;
            result->s = rz_bv_add(left->s, r_mantissa, &unused);
            goto clean;
        }
    } else {   /// exp_diff != 0
        rz_bv_lshift(l_mantissa, shift_dist);
        rz_bv_lshift(r_mantissa, shift_dist);
        /// should align exponent, chose the max(l_exp, r_exp) as final exp
        if (exp_diff < 0) {
            /// swap to keep l_exp > r_exp
            l_borrowed_exp = r_exp_squashed;
            r_borrowed_exp = l_exp_squashed;
            l_borrowed_sig = r_mantissa;
            r_borrowed_sig = l_mantissa;
            abs_exp_diff = -exp_diff;
        }

        /// check if the small one (right) is normalized ?
        if (!rz_bv_is_zero_vector(r_borrowed_exp)) {
            /// normalized, and then we recover the leading bit 1
            /// 1.MMMM MMMM ...
            rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
        } else {
            /// sub-normal (or denormalized float) case
            /// in IEEE, the value of exp is (1 - bias) for sub-normal, instead of (0 - bias)
            /// but we considered it as (0 - bias) when calculate the exp_diff = l_exp_field - r_exp_field
            /// we should r-shift (l_exp_field - bias) - (1 - bias) = l_exp_field - 1,
            /// but we r-shift (l_exp_field - bias) - (0 - bias) = l_exp_filed
            /// thus we need to l-shift 1 bit to fix this incompatible
            rz_bv_lshift(r_borrowed_sig, 1);
        }

        /// revealed the hidden bit of the bigger one : 1.MMMM
        rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
        /// aligned exponent, and generate sticky bit
        rz_bv_shift_right_jammed(r_borrowed_sig, abs_exp_diff);
    }

    /// set result exponent
    result_exp_squashed = rz_bv_dup(l_borrowed_exp);

    /// now l_exp == r_exp
    /// calculate significant
    result_sig = rz_bv_add(l_borrowed_sig, r_borrowed_sig, &unused);

    /// if it produce a carry bit, we should normalize it (rshift 1 and exp + 1)
    /// but we do nothing, instead, we makes every non-carry number have the same
    /// form : 01X.M MMMM MMMM ... = 01.XM MMMM MMMM ... * (0b10)
    ///           ^------- point
    /// we don't need to ++exp explicitly,
    /// because after rounding, if the bit before point (carry bit) is 1
    /// we could add sig and exp directly, to represent (exp + 1) operation
    /// since the leading sig bit is an overlapping bit of exp part and sig part
    if (!rz_bv_get(result_sig, carry_bit_pos) && !rz_bv_msb(result_sig)) {
        tmp = rz_bv_sub(result_exp_squashed, exp_one, &unused);
        rz_bv_free(result_exp_squashed);
        result_exp_squashed = tmp;
        rz_bv_lshift(result_sig, 1);
    }

    ut32 todo_use_exp = rz_bv_to_ut32(result_exp_squashed);
    /// round
    result = round_float_bv(sign, todo_use_exp, result_sig, format, mode);

    /// clean
    clean:
    rz_bv_free(l_exp_squashed);
    rz_bv_free(l_mantissa);
    rz_bv_free(r_exp_squashed);
    rz_bv_free(r_mantissa);
    rz_bv_free(result_exp_squashed);
    rz_bv_free(result_sig);
    rz_bv_free(exp_one);
    return result;
}

static RZ_OWN RzFloat *fsub_mag(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, bool sign, RzFloatRMode mode) {
    RzFloat *result = NULL;
    result = handle_special_float(left, right, INTERN_FOP_SUB);
    if (result) {
        /// contains INF/NaN
        return result;
    }
    /// Extract attribute from format
    RzFloatFormat format = left->r;
    ut32 mantissa_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_MAN_LEN);
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);

    /// Extract fields from num
    RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
    RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
    RzBitVector *l_mantissa = get_man(left->s, left->r);
    RzBitVector *r_mantissa = get_man(left->s, left->r);
    RzBitVector *l_borrowed_exp = l_exp_squashed;
    RzBitVector *r_borrowed_exp = r_exp_squashed;
    RzBitVector *l_borrowed_sig = l_mantissa;
    RzBitVector *r_borrowed_sig = r_mantissa;
    RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
    RzBitVector *tmp = NULL;
    bool unused;

    /// Handle normal float add
    ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
    st32 exp_diff = (st32) (l_exp_val - rz_bv_to_ut32(r_exp_squashed));
    ut32 abs_exp_diff = exp_diff;
    ut32 res_exp_val;

    /// similar to `add`, but remember that sub would never produce a carry bit
    /// we create ABMM MMMM MMMM MMMM ...
    /// B : for the leading significant bit
    /// A : space
    ut32 shift_dist = (exp_len + 1) - 2;    /// mantissa have (exp_len + sign_len) free bits, and then reserve 2 bits
    ut32 hidden_bit_pos = total_len - 2;    /// the 2nd bit counted from MSB

    /// if l_exp = r_exp
    if (exp_diff == 0) {
        /// compare result
        ut8 sdiff_neg = rz_bv_ule(l_mantissa, r_mantissa);
        ut8 sdiff_pos = rz_bv_ule(r_mantissa, l_mantissa);
        ut8 sig_diff_is_zero = sdiff_neg && sdiff_pos;
        RzBitVector *sig_diff = NULL;
        if (sig_diff_is_zero)
        {
            /// pack to return, exp = 0, sig = 0
            result = RZ_NEW0(RzFloat);
            result->r = format;
            result->s = rz_bv_new_zero(total_len);
            rz_bv_set(result->s, total_len - 1, mode == RZ_FLOAT_RMODE_RTN);
            goto clean;
        }

        /// all normalized number
        if (l_exp_val != 0)
        {
            /// for easier pack
            l_exp_val -= 1;
        }

        /// calculate the correct sig diff
        if (sdiff_neg)
        {
            sign = !sign;
            sig_diff = rz_bv_sub(l_mantissa, r_mantissa, &unused);
        }
        else
        {
            sig_diff = rz_bv_sub(r_mantissa, l_mantissa, &unused);
        }

        /// normalize sig
        /// clz - exp_len - sign_len + 1 (reserve the leading bit) = clz - exp_len
        shift_dist = rz_bv_clz(sig_diff) - exp_len;
        res_exp_val = l_exp_val - shift_dist;
        if (res_exp_val < 0)
        {
            /// too tiny after shifting, limit to exp_A
            shift_dist = l_exp_val;
            res_exp_val = 0;
        }

        result_exp_squashed = rz_bv_new_from_ut64(l_exp_squashed->len, res_exp_val);
        result = RZ_NEW0(RzFloat);
        result->r = format;
        result->s = pack_float_bv(sign, result_exp_squashed, sig_diff, format);
        goto clean;
    }
    else {
        rz_bv_lshift(l_mantissa, shift_dist);
        rz_bv_lshift(r_mantissa, shift_dist);
        /// l_exp != r_exp
        if (exp_diff < 0) {
            /// swap to keep l_exp > r_exp
            l_borrowed_exp = r_exp_squashed;
            r_borrowed_exp = l_exp_squashed;
            l_borrowed_sig = r_mantissa;
            r_borrowed_sig = l_mantissa;
            abs_exp_diff = -exp_diff;
            sign = !sign;
        }

        /// check if the small one (right) is normalized ?
        if (!rz_bv_is_zero_vector(r_borrowed_exp)) {
            /// normalized, and then we recover the leading bit 1
            /// 1.MMMM MMMM ...
            rz_bv_set(r_borrowed_sig, hidden_bit_pos, true);
        } else {
            /// r_borrow << 1;
            rz_bv_lshift(r_borrowed_sig, 1);
        }

        /// revealed the hidden bit of the bigger one : 1.MMMM
        rz_bv_set(l_borrowed_sig, hidden_bit_pos, true);
        /// aligned exponent, and generate sticky bit
        rz_bv_shift_right_jammed(r_borrowed_sig, abs_exp_diff);
    }

    /// result_exp = bigger_exp
    res_exp_val = rz_bv_to_ut32(l_borrowed_exp);
    /// result_sig = bigger_sig - small_sig
    result_sig = rz_bv_sub(l_borrowed_sig, r_borrowed_sig, &unused);

    /// normalize, already shifted free bits, reserve 1 will be fine
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

/// for 32/64/128
RZ_API RZ_OWN RzFloat *rz_float_add_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode)
{
    bool l_sign = rz_float_get_sign(left);
    bool r_sign = rz_float_get_sign(right);
    if (l_sign == r_sign)
    {
        return fadd_mag(left, right, l_sign, mode);
    }
    return fsub_mag(left, right, l_sign, mode);
}

RZ_API RZ_OWN RzFloat *rz_float_sub_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode)
{
    bool l_sign = rz_float_get_sign(left);
    bool r_sign = rz_float_get_sign(right);
    if (l_sign == r_sign)
    {
        return fsub_mag(left, right, l_sign, mode);
    }
    return fadd_mag(left, right, l_sign, mode);
}

RZ_API RZ_OWN RzFloat *rz_float_mul_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode)
{
    RzFloat *result = NULL;
    result = handle_special_float(left, right, INTERN_FOP_MUL);
    if (result) {
        /// contains INF/NaN
        return result;
    }
    /// Extract attribute from format
    RzFloatFormat format = left->r;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
    ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
    ut32 extra_len = total_len;

    /// Extract fields from num
    RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
    RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
    RzBitVector *l_mantissa = get_man_stretched(left->s, left->r);
    RzBitVector *r_mantissa = get_man_stretched(right->s, right->r);
    RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
    bool l_sign = get_sign(left->s, left->r);
    bool r_sign = get_sign(right->s, right->r);
    bool result_sign = l_sign ^ r_sign;

    /// Handle normal float multiply
    ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
    ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
    ut32 shift_dist;

    /// normalize sub-normal num
    if (l_exp_val == 0)
    {
        /// is sub-normal
        /// shift_dist = ctz - (sign + exponent width) + 1 (the leading sig bit) - extra bits
        /// note that stretched bv has 2 * total_len long, the extra bits has (total_len) long
        shift_dist = rz_bv_clz(l_mantissa) - (1 + exp_len) + 1 - extra_len;

        /// sub_nor_exp = 1 - bias
        /// normalized_exp = sub_nor_exp - shift_dist = 1 - bias - shift_dist
        /// = (1 - shift_dist) - bias
        /// so the value of exponent field is (1 - shift_dist)
        l_exp_val = 1 - shift_dist;
        rz_bv_lshift(l_mantissa, shift_dist);
    }

    if (r_exp_val == 0)
    {
        /// is sub-normal
        shift_dist = rz_bv_clz(r_mantissa) - (1 + exp_len) + 1 - extra_len;
        r_exp_val = 1 - shift_dist;
        rz_bv_lshift(r_mantissa, shift_dist);
    }

    ut32 result_exp_val = l_exp_val + r_exp_val - bias;

    /// remember we would like to make 01.MM MMMM ... (but leave higher extra bits empty)
    shift_dist = (exp_len + 1) - 2;
    ut32 hiddent_bit_pos = total_len - 2;

    rz_bv_lshift(l_mantissa, shift_dist);
    rz_bv_lshift(r_mantissa, shift_dist + 1); /// +1 due to leading 0 will accumulate

    /// set leading bit
    rz_bv_set(l_mantissa, hiddent_bit_pos, true);
    rz_bv_set(r_mantissa, hiddent_bit_pos + 1, true);

    /// multiplication
    result_sig = rz_bv_mul(l_mantissa, r_mantissa);
    /// recovered to lower bits
    rz_bv_shift_right_jammed(result_sig, extra_len);
    /// cut extra bits from MSB
    RzBitVector *tmp = rz_bv_cut_head(result_sig, extra_len);
    rz_bv_free(result_sig);
    result_sig = tmp;

    /// check if a carry happen, if not, l-shift to force a leading 1
    /// check MSB and the bit after MSB
    if (!rz_bv_get(result_sig, total_len - 2) && !rz_bv_msb(result_sig))
    {
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

RZ_API RZ_OWN RzFloat *rz_float_div_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode)
{
    RzFloat *result = NULL;
    result = handle_special_float(left, right, INTERN_FOP_DIV);
    if (result) {
        /// contains INF/NaN
        return result;
    }
    /// Extract attribute from format
    RzFloatFormat format = left->r;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
    ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
    ut32 extra_len = total_len;

    /// Extract fields from num
    RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
    RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
    RzBitVector *l_mantissa = get_man_stretched(left->s, left->r);
    RzBitVector *r_mantissa = get_man_stretched(left->s, left->r);
    RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
    bool l_sign = get_sign(left->s, left->r);
    bool r_sign = get_sign(left->s, left->r);
    bool result_sign = l_sign ^ r_sign;

    /// Handle normal float multiply
    ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
    ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
    ut32 shift_dist;

    /// normalize sub-normal num
    /// similar to multiplication
    if (l_exp_val == 0)
    {
        /// is sub-normal
        shift_dist = rz_bv_clz(l_mantissa) - (1 + exp_len) + 1 - extra_len;
        l_exp_val = 1 - shift_dist;
        rz_bv_lshift(l_mantissa, shift_dist);
    }

    if (r_exp_val == 0)
    {
        /// is sub-normal
        shift_dist = rz_bv_clz(r_mantissa) - (1 + exp_len) + 1 - extra_len;
        r_exp_val = 1 - shift_dist;
        rz_bv_lshift(r_mantissa, shift_dist);
    }

    ut32 result_exp_val = l_exp_val - r_exp_val + bias;

    /// remember we would like to make the pattern 01.MM MMMM ...
    shift_dist = (exp_len + 1) - 2;
    ut32 hiddent_bit_pos = total_len - 2;

    /// set leading bit
    rz_bv_set(l_mantissa, hiddent_bit_pos, true);
    rz_bv_set(r_mantissa, hiddent_bit_pos, true);

    /// shift to make sure left is large enough to div
    /// Fx = Mx * 2^x, Fy = My * 2^y
    /// we have Mx as 01MM MMMM MMMM ...
    /// now expand left operand to have more bits
    /// dividend 01MM ..MM 0000 0000 0000 ...
    /// divisor  00...0000 01MM MMMM MMMM ...
    /// scaled_res = (Mx / My) * 2^(-extra_len) * 2^(x - y)
    /// left shift clz - 1 bits, to keep result have the same 01MM MMMM ... form for rounding
    /// shift_res = (Mx / My) * 2^(-extra_len) * 2^(x - y) * 2^(-(clz - 1))
    /// shift right extra_len bits, and discard higher bits
    /// res = (Mx / My) * 2^(x - y) * 2^(clz - 1)
    rz_bv_lshift(l_mantissa, shift_dist + extra_len);
    rz_bv_lshift(r_mantissa, shift_dist);

    ut32 clz = rz_bv_clz(result_sig);
    result_sig = rz_bv_div(l_mantissa, r_mantissa);
    result_exp_val -= clz - 1;

    if (result_exp_val < 0) {
        /// underflow ?
        result_exp_val = 0;
    }

    rz_bv_lshift(result_sig, clz - 1);
    rz_bv_shift_right_jammed(result_sig, extra_len);
    RzBitVector *tmp = rz_bv_cut_head(result_sig, extra_len);
    rz_bv_free(result_sig);
    result_sig = tmp;
    tmp = NULL;

    result = round_float_bv(result_sign, result_exp_val, result_sig, format, mode);
    rz_bv_free(l_exp_squashed);
    rz_bv_free(r_exp_squashed);
    rz_bv_free(l_mantissa);
    rz_bv_free(r_mantissa);
    rz_bv_free(result_exp_squashed);
    rz_bv_free(result_sig);

    return result;
}

RZ_API RZ_OWN RzFloat *rz_float_rem_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode)
{
    RzFloat *result = NULL;
    result = handle_special_float(left, right, INTERN_FOP_REM);
    if (result) {
        /// contains INF/NaN
        return result;
    }
    /// Extract attribute from format
    RzFloatFormat format = left->r;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
    ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
    ut32 extra_len = total_len;

    /// Extract fields from num
    RzBitVector *l_exp_squashed = get_exp_squashed(left->s, left->r);
    RzBitVector *r_exp_squashed = get_exp_squashed(right->s, right->r);
    RzBitVector *l_mantissa = get_man_stretched(left->s, left->r);
    RzBitVector *r_mantissa = get_man_stretched(left->s, left->r);
    RzBitVector *result_sig = NULL, *result_exp_squashed = NULL;
    bool l_sign = get_sign(left->s, left->r);
    bool r_sign = get_sign(left->s, left->r);
    bool result_sign = l_sign ^ r_sign;

    /// Handle normal float multiply
    ut32 l_exp_val = rz_bv_to_ut32(l_exp_squashed);
    ut32 r_exp_val = rz_bv_to_ut32(r_exp_squashed);
    ut32 shift_dist;

    /// normalize sub-normal num
    /// similar to multiplication
    if (l_exp_val == 0)
    {
        /// is sub-normal
        shift_dist = rz_bv_clz(l_mantissa) - (1 + exp_len) + 1 - extra_len;
        l_exp_val = 1 - shift_dist;
        rz_bv_lshift(l_mantissa, shift_dist);
    }

    if (r_exp_val == 0)
    {
        /// is sub-normal
        shift_dist = rz_bv_clz(r_mantissa) - (1 + exp_len) + 1 - extra_len;
        r_exp_val = 1 - shift_dist;
        rz_bv_lshift(r_mantissa, shift_dist);
    }

    ut32 result_exp_val = l_exp_val - r_exp_val + bias;

    /// remember we would like to make the pattern 01.MM MMMM ...
    shift_dist = (exp_len + 1) - 2;
    ut32 hiddent_bit_pos = total_len - 2;

    /// set leading bit
    rz_bv_set(l_mantissa, hiddent_bit_pos, true);
    rz_bv_set(r_mantissa, hiddent_bit_pos, true);

    /// shift to make sure left is large enough to div
    /// Fx = Mx * 2^x, Fy = My * 2^y
    /// we have Mx as 01MM MMMM MMMM ...
    /// now expand left operand to have more bits
    /// dividend 01MM ..MM 0000 0000 0000 ...
    /// divisor  00...0000 01MM MMMM MMMM ...
    /// scaled_res = (Mx / My) * 2^(-extra_len) * 2^(x - y)
    /// left shift clz - 1 bits, to keep result have the same 01MM MMMM ... form for rounding
    /// shift_res = (Mx / My) * 2^(-extra_len) * 2^(x - y) * 2^(-(clz - 1))
    /// shift right extra_len bits, and discard higher bits
    /// res = (Mx / My) * 2^(x - y) * 2^(clz - 1)
    rz_bv_lshift(l_mantissa, shift_dist + extra_len);
    rz_bv_lshift(r_mantissa, shift_dist);

    ut32 clz = rz_bv_clz(result_sig);
    result_sig = rz_bv_mod(l_mantissa, r_mantissa);
    result_exp_val -= clz - 1;

    if (result_exp_val < 0) {
        /// underflow ?
        result_exp_val = 0;
    }

    rz_bv_lshift(result_sig, clz - 1);
    rz_bv_shift_right_jammed(result_sig, extra_len);
    RzBitVector *tmp = rz_bv_cut_head(result_sig, extra_len);
    rz_bv_free(result_sig);
    result_sig = tmp;
    tmp = NULL;

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
 * calculate a + b * c, and then round the result
 * @param a
 * @param b
 * @param c
 * @param mode
 * @return
 */
RZ_API RZ_OWN RzFloat *rz_float_fma_ieee_bin(RZ_NONNULL RzFloat *a, RZ_NONNULL RzFloat *b, RZ_NONNULL RzFloat *c, RzFloatRMode mode)
{
    /// TODO : handle NaN / Inf / Zero

    /// Extract attribute from format
    RzFloatFormat format = a->r;
    ut32 exp_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_EXP_LEN);
    ut32 total_len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
    ut32 bias = rz_float_get_format_info(format, RZ_FLOAT_INFO_BIAS);
    ut32 extra_len = total_len;

    /// extra fields from a and b for multiply
    RzBitVector *a_exp_squashed = get_exp_squashed(a->s, a->r);
    RzBitVector *b_exp_squashed = get_exp_squashed(b->s, b->r);
    RzBitVector *a_mantissa = get_man_stretched(a->s, a->r);
    RzBitVector *b_mantissa = get_man_stretched(b->s, b->r);
    RzBitVector *mul_sig = NULL;
    bool a_sign = get_sign(a->s, a->r);
    bool b_sign = get_sign(b->s, b->r);
    bool mul_sign = a_sign ^ b_sign;

    /// Handle normal float multiply
    ut32 a_exp_val = rz_bv_to_ut32(a_exp_squashed);
    ut32 b_exp_val = rz_bv_to_ut32(b_exp_squashed);
    ut32 shift_dist;

    /// normalize sub-normal num
    if (a_exp_val == 0)
    {
        /// is sub-normal
        /// shift_dist = ctz - (sign + exponent width) + 1 (the leading sig bit) - extra bits
        /// note that stretched bv has 2 * total_len long, the extra bits has (total_len) long
        shift_dist = rz_bv_clz(a_mantissa) - (1 + exp_len) + 1 - extra_len;

        /// sub_nor_exp = 1 - bias
        /// normalized_exp = sub_nor_exp - shift_dist = 1 - bias - shift_dist
        /// = (1 - shift_dist) - bias
        /// so the value of exponent field is (1 - shift_dist)
        a_exp_val = 1 - shift_dist;
        rz_bv_lshift(a_mantissa, shift_dist);
    }

    if (b_exp_val == 0)
    {
        /// is sub-normal
        shift_dist = rz_bv_clz(b_mantissa) - (1 + exp_len) + 1 - extra_len;
        b_exp_val = 1 - shift_dist;
        rz_bv_lshift(b_mantissa, shift_dist);
    }

    ut32 mul_exp_val = a_exp_val + b_exp_val - bias + 1;

    /// remember we would like to make 01.MM MMMM ... (but leave higher extra bits empty)
    shift_dist = (exp_len + 1) - 2;
    ut32 hiddent_bit_pos = total_len - 2;

    rz_bv_lshift(a_mantissa, shift_dist);
    rz_bv_lshift(b_mantissa, shift_dist + 1);

    /// set leading bit
    rz_bv_set(a_mantissa, hiddent_bit_pos, true);
    rz_bv_set(b_mantissa, hiddent_bit_pos + 1, true);

    /// multiplication
    mul_sig = rz_bv_mul(a_mantissa, b_mantissa);

    /// recovered to lower bits
    rz_bv_shift_right_jammed(mul_sig, extra_len);

    /// cut extra bits from MSB
    RzBitVector *tmp = rz_bv_cut_head(mul_sig, extra_len);
    rz_bv_free(mul_sig);
    mul_sig = tmp;

    /// check if a carry happen, if not, l-shift to force a leading 1
    /// check MSB and the bit after MSB
    if (!rz_bv_get(mul_sig, total_len - 2) && !rz_bv_msb(mul_sig))
    {
        mul_exp_val -= 1;
        rz_bv_lshift(mul_sig, 1);
    }

    RzBitVector *mul_exp = rz_bv_new_from_ut64(total_len, mul_exp_val);
    RzFloat *mul_res = RZ_NEW0(RzFloat);
    mul_res->r = format;
    mul_res->s = pack_float_bv(mul_sign, mul_exp, mul_sig, format);

    rz_bv_free(mul_exp);
    rz_bv_free(a_mantissa);
    rz_bv_free(a_exp_squashed);
    rz_bv_free(b_mantissa);
    rz_bv_free(b_exp_squashed);
    rz_bv_free(mul_sig);

    RzFloat *res = rz_float_add_ieee_bin(mul_res, c, mode);
    rz_float_free(mul_res);
    mul_res = NULL;
    return res;
}

RZ_API RZ_OWN RzFloat *rz_float_sqrt_ieee_bin(RZ_NONNULL RzFloat *left, RZ_NONNULL RzFloat *right, RzFloatRMode mode)
{
    /// TODO
}

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