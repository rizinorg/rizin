#include <rz_il/definitions/float.h>

/** For IEEE 754 only **/
/** 32/64/128 bits **/
/** check : http://weitz.de/ieee/ **/
/** check : https://www.h-schmidt.net/FloatConverter/IEEE754.html **/
/**
 * Interprets `x` as a floating number
 * \param r Float format, an interpretation to bitvector x
 * \param bv BitVector x
 * \return f RzILFloat
 */

static ut32 get_float_format_len(RzILFloatFormat r) {
	switch (r) {
	case RZIL_FLOAT_IEEE754_32:
		return 32;
	case RZIL_FLOAT_IEEE754_64:
		return 64;
	case RZIL_FLOAT_IEEE754_128:
		return 128;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

ut32 rzil_float_get_bias_num(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, 0);
	switch (f->r) {
	case RZIL_FLOAT_IEEE754_32:
		return 127;
	case RZIL_FLOAT_IEEE754_64:
		return 1023;
	case RZIL_FLOAT_IEEE754_128:
		return 16383;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

ut32 rzil_float_get_exp_start_pos(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, 0);
	switch (f->r) {
	case RZIL_FLOAT_IEEE754_32:
		return 23;
	case RZIL_FLOAT_IEEE754_64:
		return 52;
	case RZIL_FLOAT_IEEE754_128:
		return 112;
	default:
		rz_warn_if_reached();
		return 0;
	}
}

static bool check_valid_float_bv(RzILFloat *f) {
	rz_return_val_if_fail(f, false);
	ut32 len = rz_il_bv_len(f->s);
	ut32 valid_len = get_float_format_len(f->r);
	return len == valid_len;
}

RZ_API ut32 rzil_float_get_exp_len(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, 0);
	ut32 exp_len = get_float_format_len(f->r) - rzil_float_get_exp_start_pos(f) - 1;
	return exp_len;
}

RZ_API ut32 rzil_float_get_frac_len(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, 0);
	ut32 exp_len = rzil_float_get_exp_len(f);
	ut32 frac_len = get_float_format_len(f->r) - exp_len - 1;
	return frac_len;
}

RZ_API RzILFloat *rzil_float_new(RzILFloatFormat r, RzILBitVector *bv) {
	RzILFloat *result = RZ_NEW0(RzILFloat);
	if (!result || !bv) {
		return NULL;
	}

	result->r = r;
	result->s = bv;

	if (check_valid_float_bv(result)) {
		return result;
	}

	RZ_FREE(result);
	return NULL;
}

/**
 * Return sign bit with exponent part
 * \param f float
 * \return bv bitvector contains (sign bit and exponent bits)
 */
RZ_API RzILBitVector *rzil_float_get_sigexp(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, NULL);
	RzILBitVector *raw_bv = f->s;
	ut32 delta = rzil_float_get_frac_len(f);
	RzILBitVector *res = rz_il_bv_cut_tail(raw_bv, delta);
	return res;
}

RZ_API RzILBitVector *rzil_float_get_frac(RzILFloat *f) {
	rz_return_val_if_fail(f, NULL);
	RzILBitVector *raw_bv = f->s;
	ut32 delta = rzil_float_get_exp_len(f) + 1;
	RzILBitVector *res = rz_il_bv_cut_head(raw_bv, delta);
	return res;
}

RZ_API bool rzil_float_get_sign(RzILFloat *f) {
	rz_return_val_if_fail(f, NULL);
	RzILBitVector *bv = f->s;
	return rz_il_bv_msb(bv);
}

RZ_API RzILBitVector *rzil_float_get_exp(RzILFloat *f) {
	rz_return_val_if_fail(f, NULL);
	RzILBitVector *raw_bv = f->s;

	ut32 start_pos = rzil_float_get_exp_start_pos(f);
	ut32 exp_len = rzil_float_get_exp_len(f);

	RzILBitVector *exp = rz_il_bv_new(exp_len);
	rz_il_bv_copy_nbits(raw_bv, start_pos, exp, 0, exp_len);

	return exp;
}

RZ_API RzILBitVector *rzil_float_get_bias(RzILFloat *f) {
	rz_return_val_if_fail(f, NULL);
	ut32 exp_len = rzil_float_get_exp_len(f);

	// create 0b11111111..
	RzILBitVector *bv = rz_il_bv_new(exp_len);
	rz_il_bv_toggle_all(bv);

	// toggle msb bit
	rz_il_bv_toggle(bv, exp_len - 1);

	return bv;
}

/**
 * Fbits return bitvector interpretation of float
 * \param f Float
 * \return bv BitVectors
 */
RZ_API RzILBitVector *rzil_float_fbits(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, NULL);
	return f->s;
}

typedef bool (*ChkBitVecCB)(RzILBitVector *bv, ut32 start, ut32 len);
static bool check_part_bv(RZ_NONNULL RzILBitVector *bv, ut32 start, ut32 len, ChkBitVecCB checker) {
	return checker(bv, start, len);
}

static bool check_all_zero(RZ_NONNULL RzILBitVector *bv, ut32 start, ut32 len) {
	for (ut32 i = 0, pos = start; i < len; ++i, ++pos) {
		if (rz_il_bv_get(bv, pos) == true) {
			return false;
		}
	}
	return true;
}

static bool check_all_one(RZ_NONNULL RzILBitVector *bv, ut32 start, ut32 len) {
	for (ut32 i = 0, pos = start; i < len; ++i, ++pos) {
		if (rz_il_bv_get(bv, pos) == false) {
			return false;
		}
	}
	return true;
}

///< Check float attribute, mode-irrelevant
RZ_API bool rzil_float_is_pos_inf(RZ_NONNULL RzILFloat *f) {
	bool sign_bit = rzil_float_get_sign(f);
	if (sign_bit) {
		// negative number
		return false;
	}

	if (!rzil_float_is_inf(f)) {
		return false;
	}

	return true;
}

RZ_API bool rzil_float_is_neg_inf(RZ_NONNULL RzILFloat *f) {
	bool sign_bit = rzil_float_get_sign(f);
	if (!sign_bit) {
		return false;
	}

	if (!rzil_float_is_inf(f)) {
		return false;
	}

	return true;
}

RZ_API bool rzil_float_is_inf(RZ_NONNULL RzILFloat *f) {
	ut32 exp_start = rzil_float_get_exp_start_pos(f);
	ut32 exp_len = rzil_float_get_exp_len(f);
	if (!check_part_bv(f->s, exp_start, exp_len, check_all_one)) {
		// not infinite (exp bits should be all 1)
		return false;
	}

	ut32 frac_start = 0;
	ut32 frac_len = rzil_float_get_frac_len(f);
	if (!check_part_bv(f->s, frac_start, frac_len, check_all_zero)) {
		// not infinite (frac bits should be all 0)
		return false;
	}

	return true;
}

RZ_API bool rzil_float_is_nan(RZ_NONNULL RzILFloat *f) {
	ut32 exp_start = rzil_float_get_exp_start_pos(f);
	ut32 exp_len = rzil_float_get_exp_len(f);

	// exp should be all 1
	if (!check_part_bv(f->s, exp_start, exp_len, check_all_one)) {
		return false;
	}

	ut32 frac_start = 0;
	ut32 frac_len = rzil_float_get_frac_len(f);
	if (check_part_bv(f->s, frac_start, frac_len, check_all_zero)) {
		return false;
	}

	return true;
}

RZ_API bool rzil_float_is_finite(RZ_NONNULL RzILFloat *f) {
	ut32 exp_start = rzil_float_get_exp_start_pos(f);
	ut32 exp_len = rzil_float_get_exp_len(f);

	// exp should not be all 1
	if (check_part_bv(f->s, exp_start, exp_len, check_all_one)) {
		return false;
	}

	return true;
}

RZ_API bool rzil_float_is_fzero(RZ_NONNULL RzILFloat *f) {
	ut32 exp_start = rzil_float_get_exp_start_pos(f);
	ut32 exp_len = rzil_float_get_exp_len(f);
	ut32 frac_start = 0;
	ut32 frac_len = rzil_float_get_frac_len(f);

	if (!check_part_bv(f->s, exp_start, exp_len, check_all_zero)) {
		return false;
	}

	if (!check_part_bv(f->s, frac_start, frac_len, check_all_zero)) {
		return false;
	}

	return true;
}

RZ_API bool rzil_float_is_fpos(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, false);

	// Warning : the fpos to zero is undefined
	// Use return false here
	if (rzil_float_is_fzero(f)) {
		return false;
	}

	return rz_il_bv_msb(f->s) ? true : false;
}

RZ_API bool rzil_float_is_fneg(RZ_NONNULL RzILFloat *f) {
	rz_return_val_if_fail(f, false);

	// Warning : the fneg to zero is undefined
	// Use return false here
	if (rzil_float_is_fzero(f)) {
		return false;
	}

	return rz_il_bv_msb(f->s) ? false : true;
}

/**
 * Round Mode with arithmetic functions
 */

// Round Mode will modify the bitvector directly
// TODO
bool rzil_float_round(RzILFloat *f, RzILFloatRMode rmode) {
	switch (rmode) {
	case RZIL_FLOAT_RMODE_RNA:
	case RZIL_FLOAT_RMODE_RNE:
	case RZIL_FLOAT_RMODE_RTN:
	case RZIL_FLOAT_RMODE_RTP:
	case RZIL_FLOAT_RMODE_RTZ:
	default:
		break;
	}
}

bool rzil_float_requal(RzILFloatRMode r1, RzILFloatRMode r2) {
	// CHECKME : http://binaryanalysisplatform.github.io/bap/api/master/bap-core-theory/Bap_core_theory/Theory/module-type-Float/index.html
	return r1 == r2;
}

RzILFloat *rzil_float_fneg(RzILFloat *f) {
	RzILFloat *result = rzil_float_new(f->r, rz_il_bv_dup(f->s));
	if (!result) {
		return NULL;
	}
	rz_il_bv_toggle(result->s, get_float_format_len(f->r) - 1);
	return result;
}

RzILFloat *rzil_float_fabs(RzILFloat *f) {
	RzILFloat *result = rzil_float_new(f->r, rz_il_bv_dup(f->s));
	if (!result) {
		return NULL;
	}

	if (rzil_float_is_fneg(f)) {
		rz_il_bv_toggle(result->s, get_float_format_len(f->r) - 1);
		return result;
	}

	return result;
}

// TODO : implement
static ut32 get_exp_delta(RzILFloat *a, RzILFloat *b, RzILFloat **bigger_exp_float, RzILFloat **smaller) {
	*smaller = b;
	*bigger_exp_float = a;
	return 0u;
}

// TODO
static void normalize_float(RzILFloat *f);

// ref: https://www.quora.com/How-do-I-add-IEEE-754-floating-point-numbers
RzILFloat *rzil_float_fadd(RzILFloatRMode r, RzILFloat *a, RzILFloat *b) {
	rz_return_val_if_fail(a && b, NULL);

	RzILFloat *bigger_exp = NULL;
	RzILFloat *smaller_exp = NULL;
	ut32 exp_delta = get_exp_delta(a, b, &bigger_exp, &smaller_exp);

	RzILBitVector *big_frac = rzil_float_get_frac(bigger_exp);
	RzILBitVector *small_frac = rzil_float_get_frac(smaller_exp);

	RzILFloat *result = rzil_float_new(bigger_exp->r, rz_il_bv_new(get_float_format_len(bigger_exp->r)));
	if (!result) {
		rz_il_bv_free(big_frac);
		rz_il_bv_free(small_frac);
		return NULL;
	}

	// realign exponent and adjust frac
	rz_il_bv_rshift(small_frac, exp_delta);

	// add frac
	RzILBitVector *frac = rz_il_bv_add(big_frac, small_frac);
	rz_il_bv_copy_nbits(frac, 0, result->s, 0, rzil_float_get_frac_len(bigger_exp));

	// normalize
	normalize_float(result);

	// round
	rzil_float_round(result, r);

	return result;
}

RzILFloat *rzil_float_fsub(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fmul(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fdiv(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fsqrt(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fmodulo(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fmad(RzILFloatRMode r, RzILFloat *a, RzILFloat *b, RzILFloat *c);
RzILFloat *rzil_float_fround(RzILFloatRMode r, RzILFloat *a, RzILFloat *b);
RzILFloat *rzil_float_fsucc(RzILFloat *a);
RzILFloat *rzil_float_fpred(RzILFloat *a);
bool rzil_float_forder(RzILFloat *x, RzILFloat *y);
