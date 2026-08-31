// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file Constant Value Domain
 *
 * This is the abstract domain of either a single constant value or the universal set.
 */

#include <rz_inquiry.h>

typedef struct {
	/**
	 * \brief Set if the abstract value represents a single constant bitvector.
	 * If set, the bit vector below is a valid concrete value.
	 * If unset it is a top value, i.e. represents the set of all bitvectors.
	 */
	bool is_const;
	/**
	 * \brief The single constant value.
	 * If is_const is unset this might hold garbage.
	 */
	RzBitVector *bv;
} ValueData;

/**
 * \brief Abstract data getter from the RzAbsIntVal
 */
#define AD(av) ((ValueData *)rz_absint_val_unpack(av))

static RzAbsIntVal *pack(ValueData *val) {
	return rz_absint_val_pack(val);
}

static RZ_OWN RzAbsIntVal *val_new_top() {
	ValueData *ad = RZ_NEW0(ValueData);
	ad->is_const = false;
	ad->bv = rz_bv_new(64);
	return pack(ad);
}

static void val_free(RzAbsIntVal *val) {
	if (!val) {
		return;
	}
	ValueData *adata = AD(val);
	rz_bv_free(adata->bv);
	free(adata);
}

static bool val_is_top(RZ_NONNULL const RzAbsIntVal *val) {
	return !AD(val)->is_const;
}

bool static val_may_be_bool(RZ_NONNULL const RzAbsIntVal *val, bool value) {
	if (!AD(val)->is_const) {
		return true;
	}
	return value != rz_bv_is_zero_vector(AD(val)->bv);
}

static void val_set_top(RZ_NONNULL RzAbsIntVal *val) {
	AD(val)->is_const = false;
}

static void val_set_const_bool(RZ_OUT RZ_NONNULL RzAbsIntVal *dst, bool src) {
	AD(dst)->is_const = true;
	rz_bv_cast_inplace(AD(dst)->bv, 1, false);
	rz_bv_set_from_ut64(AD(dst)->bv, src ? 1 : 0);
}

static void val_set_const_bv(RZ_OUT RZ_NONNULL RzAbsIntVal *dst, RZ_IN RZ_NONNULL RzBitVector *src) {
	AD(dst)->is_const = true;
	rz_bv_cast_inplace(AD(dst)->bv, rz_bv_len(src), false);
	rz_bv_copy(AD(dst)->bv, src);
}

void val_copy(RzAbsIntVal *dst_val, const RzAbsIntVal *src_val) {
	ValueData *dst = AD(dst_val);
	ValueData *src = AD(src_val);
	rz_return_if_fail(dst && src && dst->bv && src->bv);
	rz_bv_cast_inplace(dst->bv, rz_bv_len(src->bv), false);
	rz_bv_copy(dst->bv, src->bv);
	dst->is_const = src->is_const;
}

/**
 * \brief Join (least upper bound) on values
 * \return True if a was changed
 */
static bool join_val(RZ_BORROW RZ_INOUT RzAbsIntVal *a, RZ_BORROW RZ_IN const RzAbsIntVal *b) {
	ValueData *ad = AD(a);
	ValueData *bd = AD(b);
	if (ad->is_const && bd->is_const && rz_bv_eq(ad->bv, bd->bv)) {
		// identical values, a already has the least upper bound
		return false;
	}
	// for anything else, the least upper bound is top
	bool changed = ad->is_const;
	ad->is_const = false;
	return changed;
}

bool val_as_str(RZ_NONNULL const RzAbsIntVal *val, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(val && sb, false);
	ValueData *av = AD(val);
	if (av->is_const) {
		char *s = rz_bv_as_hex_string(av->bv, false);
		if (!s) {
			return false;
		}
		rz_strbuf_append(sb, s);
		free(s);
	} else {
		rz_strbuf_append(sb, RZ_ABSINT_STR_TOP);
	}
	return true;
}

static bool to_concrete_const(RZ_NONNULL const RzAbsIntVal *val, RZ_NULLABLE RZ_OUT RzBitVector *out) {
	if (!AD(val)->is_const) {
		return false;
	}
	if (out) {
		rz_bv_cast_inplace(out, rz_bv_len(AD(val)->bv), false);
		rz_bv_copy(out, AD(val)->bv);
	}
	return true;
}

static void eval_cast(ut32 length, RZ_NONNULL const RzAbsIntVal *fill, RZ_INOUT RZ_NONNULL RzAbsIntVal *val) {
	if (!AD(val)->is_const || !AD(fill)->is_const) {
		val_set_top(val);
		return;
	}
	rz_bv_cast_inplace(AD(val)->bv, length, !rz_bv_is_zero_vector(AD(fill)->bv));
}

static void eval_shift(bool right, RZ_NONNULL RZ_INOUT RzAbsIntVal *x, RZ_NONNULL const RzAbsIntVal *y, RZ_NONNULL const RzAbsIntVal *fill_bit) {
	if (!AD(x)->is_const || !AD(y)->is_const || !AD(fill_bit)->is_const) {
		// Hint: there are some more cases that could be handled better:
		// - x is either all 1 or all 0 => any shift will produce the same result
		// - y is 0 => fill_bit may be top and the result is still known to be just x
		// but not sure if these are worth the extra control flow for practical purposes
		return;
	}
	bool (*shift)(RzBitVector *bv, ut32 size, bool fill_bit);
	shift = right ? rz_bv_rshift_fill : rz_bv_lshift_fill;
	shift(AD(x)->bv, rz_bv_to_ut64(AD(y)->bv), !rz_bv_is_zero_vector(AD(fill_bit)->bv));
}

static void eval_binop(RzILOpPureCode code, RZ_NONNULL RZ_INOUT RzAbsIntVal *x, RZ_NONNULL const RzAbsIntVal *y) {
	if (!AD(x)->is_const || !AD(y)->is_const) {
		val_set_top(x);
		return;
	}
	RzBitVector *xv = AD(x)->bv;
	RzBitVector *yv = AD(y)->bv;
	switch (code) {
	case RZ_IL_OP_APPEND:
		rz_bv_append_inplace(xv, yv);
		break;
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_AND:
		rz_bv_and_inplace(xv, yv);
		break;
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_OR:
		rz_bv_or_inplace(xv, yv);
		break;
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_XOR:
		rz_bv_xor_inplace(xv, yv);
		break;
	case RZ_IL_OP_ADD:
		rz_bv_add_inplace(xv, yv, NULL);
		break;
	case RZ_IL_OP_SUB:
		rz_bv_sub_inplace(xv, yv, NULL);
		break;
	case RZ_IL_OP_SLE:
		val_set_const_bool(x, rz_bv_sle(xv, yv));
		break;
	case RZ_IL_OP_ULE:
		val_set_const_bool(x, rz_bv_ule(xv, yv));
		break;
	case RZ_IL_OP_EQ:
		val_set_const_bool(x, rz_bv_eq(xv, yv));
		break;
	case RZ_IL_OP_MUL:
		rz_bv_mul_inplace(xv, yv);
		break;
	case RZ_IL_OP_MOD:
		rz_bv_mod_inplace(xv, yv);
		break;
	case RZ_IL_OP_DIV:
		rz_bv_div_inplace(xv, yv);
		break;
	default:
		// unimplemented
		val_set_top(x);
		break;
	}
}

static void eval_unop(RzILOpPureCode code, RZ_NONNULL RZ_INOUT RzAbsIntVal *val) {
	if (!AD(val)->is_const) {
		return;
	}
	RzBitVector *bv = AD(val)->bv;
	switch (code) {
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_INV:
		rz_bv_not_inplace(bv);
		break;
	case RZ_IL_OP_IS_ZERO:
		val_set_const_bool(val, rz_bv_is_zero_vector(bv));
		break;
	case RZ_IL_OP_LSB:
		val_set_const_bool(val, rz_bv_lsb(bv));
		break;
	case RZ_IL_OP_MSB:
		val_set_const_bool(val, rz_bv_msb(bv));
		break;
	case RZ_IL_OP_NEG:
		rz_bv_neg_inplace(bv);
		break;
	default:
		// unimplemented
		val_set_top(val);
		break;
	}
}

RZ_IPI RzAbsIntValueDomain rz_absint_value_domain_const = {
	.name = "constant",
	.val_new_top = val_new_top,
	.val_free = val_free,
	.set_top = val_set_top,
	.set_const_bool = val_set_const_bool,
	.set_const_bv = val_set_const_bv,
	.is_top = val_is_top,
	.may_be_bool = val_may_be_bool,
	.to_concrete_const = to_concrete_const,
	.copy = val_copy,
	.join = join_val,
	.val_as_str = val_as_str,
	.eval_cast = eval_cast,
	.eval_shift = eval_shift,
	.eval_binop = eval_binop,
	.eval_unop = eval_unop
};

RZ_API RzInquiryPlugin rz_inquiry_plugin_interpreter_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/top abstractions.",
	.license = "LGPL-3.0-only",
	.value_domain = &rz_absint_value_domain_const,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_INTERPRETER,
	.data = &interpreter_prototype
};
#endif
