// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/value.h>

/**
 * Returns a new RzILVal (Any type)
 * \param  type RzILVarType to set of the value
 * \return val  RzILVal, pointer to this value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_new(RzILTypePure type) {
	RzILVal *ret;
	ret = RZ_NEW0(RzILVal);
	if (!ret) {
		return NULL;
	}
	ret->type = type;
	return ret;
}

/**
 * Returns a new RzILVal (Bitvector type)
 * \param  bv  RzBitVector to set
 * \return val RzILVal, pointer to this value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_new_bitv(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILVal *ret = rz_il_value_new(RZ_IL_TYPE_PURE_BITVECTOR);
	if (!ret) {
		return NULL;
	}
	ret->data.bv = bv;
	return ret;
}

/**
 * Returns a new RzILVal (Bool type)
 * \param  b   RzILBool to set
 * \return val RzILVal, pointer to this value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_new_bool(RZ_NONNULL RzILBool *b) {
	rz_return_val_if_fail(b, NULL);
	RzILVal *ret = rz_il_value_new(RZ_IL_TYPE_PURE_BOOL);
	if (!ret) {
		return NULL;
	}
	ret->data.b = b;
	return ret;
}

/**
 * Create a value of the given sort filled with all zeroes or false
 */
RZ_API RZ_OWN RzILVal *rz_il_value_new_zero_of(RzILSortPure sort) {
	RzILVal *ret = rz_il_value_new(sort.type);
	if (!ret) {
		return NULL;
	}
	switch (sort.type) {
	case RZ_IL_TYPE_PURE_BOOL:
		ret->data.b = rz_il_bool_new(false);
		if (!ret->data.b) {
			rz_il_value_free(ret);
			return NULL;
		}
		break;
	case RZ_IL_TYPE_PURE_BITVECTOR:
		ret->data.bv = rz_bv_new_zero(sort.props.bv.length);
		if (!ret->data.bv) {
			rz_il_value_free(ret);
			return NULL;
		}
		break;
	}
	return ret;
}

/**
 * Clone an RzILVal
 * \param  val  RzILVal, pointer to the value you want to dump
 * \return dump RzILVal, pointer to the dumped value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_dup(RZ_NONNULL const RzILVal *val) {
	rz_return_val_if_fail(val, NULL);
	RzILBool *b = NULL;
	RzBitVector *bv = NULL;

	switch (val->type) {
	case RZ_IL_TYPE_PURE_BOOL:
		b = rz_il_bool_new(val->data.b->b);
		return b ? rz_il_value_new_bool(b) : NULL;
	case RZ_IL_TYPE_PURE_BITVECTOR:
		bv = rz_bv_dup(val->data.bv);
		return bv ? rz_il_value_new_bitv(bv) : NULL;
	default:
		rz_warn_if_reached();
		return NULL;
	}
}

/**
 * Free a RzILVal value
 * \param val RzILVal, pointer to the RzILVal instance
 */
RZ_API void rz_il_value_free(RZ_NULLABLE RzILVal *val) {
	if (!val) {
		return;
	}
	switch (val->type) {
	case RZ_IL_TYPE_PURE_BOOL:
		rz_il_bool_free(val->data.b);
		break;
	case RZ_IL_TYPE_PURE_BITVECTOR:
		rz_bv_free(val->data.bv);
		break;
	default:
		break;
	}
	free(val);
}

/**
 * Get the sort that \p val belongs to
 */
RZ_API RzILSortPure rz_il_value_get_sort(RZ_NONNULL RzILVal *val) {
	RzILSortPure r = { 0 };
	r.type = val->type;
	if (val->type == RZ_IL_TYPE_PURE_BITVECTOR) {
		r.props.bv.length = rz_bv_len(val->data.bv);
	}
	return r;
}

/**
 * Convert the value's contents to a bitvector.
 * For bitvector values, this is simply a copy of the value,
 * for boolean it is a 1-bit bitvector of 1 or 0.
 */
RZ_API RZ_OWN RzBitVector *rz_il_value_to_bv(RZ_NONNULL const RzILVal *val) {
	rz_return_val_if_fail(val, NULL);
	switch (val->type) {
	case RZ_IL_TYPE_PURE_BOOL:
		return rz_bv_new_from_ut64(1, val->data.b->b ? 1 : 0);
	case RZ_IL_TYPE_PURE_BITVECTOR:
		return rz_bv_dup(val->data.bv);
	default:
		rz_warn_if_reached();
		return NULL;
	}
}
