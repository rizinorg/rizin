// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/value.h>

/**
 * Returns a new RzILVal (Bitvector type)
 * \param  bv  RzBitVector to set
 * \return val RzILVal, pointer to this value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_new_bitv(RZ_NONNULL RzBitVector *bv) {
	rz_return_val_if_fail(bv, NULL);
	RzILVal *ret = rz_il_value_new(RZIL_VAR_TYPE_BV);
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
	RzILVal *ret = rz_il_value_new(RZIL_VAR_TYPE_BOOL);
	if (!ret) {
		return NULL;
	}
	ret->data.b = b;
	return ret;
}

/**
 * Returns a new RzILVal (Any type)
 * \param  type RzILVarType to set of the value
 * \return val  RzILVal, pointer to this value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_new(RzILVarType type) {
	RzILVal *ret;
	ret = RZ_NEW0(RzILVal);
	if (!ret) {
		return NULL;
	}
	ret->type = type;
	return ret;
}

/**
 * Clone an RzILVal
 * \param  val  RzILVal, pointer to the value you want to dump
 * \return dump RzILVal, pointer to the dumped value
 */
RZ_API RZ_OWN RzILVal *rz_il_value_dup(RZ_NONNULL RzILVal *val) {
	rz_return_val_if_fail(val, NULL);
	RzILBool *b = NULL;
	RzBitVector *bv = NULL;

	switch (val->type) {
	case RZIL_VAR_TYPE_BOOL:
		b = rz_il_bool_new(val->data.b->b);
		return b ? rz_il_value_new_bool(b) : NULL;
	case RZIL_VAR_TYPE_BV:
		bv = rz_bv_dup(val->data.bv);
		return bv ? rz_il_value_new_bitv(bv) : NULL;
	case RZIL_VAR_TYPE_UNK:
		return rz_il_value_new_unk();
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
	case RZIL_VAR_TYPE_BOOL:
		rz_il_bool_free(val->data.b);
		break;
	case RZIL_VAR_TYPE_BV:
		rz_bv_free(val->data.bv);
		break;
	case RZIL_VAR_TYPE_UNK:
	default:
		break;
	}

	free(val);
}
