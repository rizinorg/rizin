/**
 * \file this file contains some float function used in rzil fbasic theory
 * To avoid conflict during developing, I put some float operation here at first
 * Some of them should be moved to rz_util/float in the future and resolve conflict to merge
 */
#include <rz_il/definitions/float.h>

/**
 * create a float by specifying `format` and `bitv`
 * BAP ref : ('r, 's) format Float.t Value.sort -> 's bitv -> ('r, 's) format float
 * \param format format of float, see RzFloatFormat enum
 * \param bv bitvector representation of float
 * \return float instance
 */
RZ_API RZ_OWN RzFloat *rz_il_float_new(RZ_NONNULL RzFloatFormat format, RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail((format != RZ_FLOAT_UNK) && bv, NULL);
	// Task :
	// 1. dup bv to make float
	// 2. make sure bv length is equal with what `format` defined
	// TODO : should we support cast here ?
	//	interpret 31-bit vector as IEEE-BIN64 etc.

	ut32 len = rz_float_get_format_info(format, RZ_FLOAT_INFO_TOTAL_LEN);
	if (len != bv->len) {
		return NULL;
	}

	RzFloat *f = RZ_NEW0(RzFloat);
	if (!f) {
		return NULL;
	}

	RzBitVector *dup_bv = rz_bv_dup(bv);
	if (!dup_bv) {
		free(f);
		return NULL;
	}

	f->s = bv;
	f->r = format;

	return f;
}

/**
 * get the negative one of given float
 * BAP ref: val fneg : 'f float -> 'f float
 * \param f float number
 * \return negative float `f`
 */
RZ_API RZ_OWN RzFloat *rz_il_float_neg(RZ_NONNULL RzFloat *f) {
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
RZ_API RZ_OWN RzFloat *rz_il_float_succ(RZ_NONNULL RzFloat *f) {
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
RZ_API RZ_OWN RzFloat *rz_il_float_pred(RZ_NONNULL RzFloat *f) {
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
RZ_API RZ_OWN st32 rz_il_float_cmp(RZ_NONNULL RzFloat *x, RZ_NONNULL RzFloat *y) {
	rz_return_val_if_fail(x && y, -2);

	RZ_BORROW RzBitVector *x_bv = x->s;
	RZ_BORROW RzBitVector *y_bv = y->s;

	if (!rz_bv_sle(x_bv, y_bv)) {
		// x > y
		return 1;
	} else if (rz_bv_eq(x_bv, y_bv)) {
		// x == y
		return 0;
	} else {
		return -1;
	}
}

/**
 * convert rmode into const string for exporting info
 * \param mode round mode
 * \return round mode string
 */
RZ_API const char *rz_il_float_stringify_rmode(RzFloatRMode mode) {
	switch (mode) {
	case RZ_FLOAT_RMODE_RNA:
		return "rna";
	case RZ_FLOAT_RMODE_RNE:
		return "rne";
	case RZ_FLOAT_RMODE_RTN:
		return "rtn";
	case RZ_FLOAT_RMODE_RTZ:
		return "rtz";
	case RZ_FLOAT_RMODE_RTP:
		return "rtp";
	default:
		return "unk_round";
	}
}

/**
 * convert format to human readable string
 * \param format float format
 * \return float format string
 */
RZ_API const char *rz_il_float_stringify_format(RzFloatFormat format) {
	switch (format) {
	case RZ_FLOAT_IEEE754_BIN_32:
		return "ieee754-bin32";
	case RZ_FLOAT_IEEE754_BIN_64:
		return "ieee754-bin64";
	case RZ_FLOAT_IEEE754_BIN_80:
		return "ieee754-bin80";
	case RZ_FLOAT_IEEE754_DEC_64:
		return "ieee754-dec64";
	case RZ_FLOAT_IEEE754_DEC_128:
		return "ieee754-dec128";
	default:
		return "unk_format";
	}
}

