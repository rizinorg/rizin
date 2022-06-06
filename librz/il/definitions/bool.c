// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/bool.h>

/**
 * Create a new RzILBool instance
 * \param true_or_false bool, set bool as true or false
 * \return bool RzILBool, pointer to bool value
 */
RZ_API RzILBool *rz_il_bool_new(bool true_or_false) {
	RzILBool *ret = RZ_NEW0(RzILBool);
	if (!ret) {
		return NULL;
	}
	ret->b = true_or_false;
	return ret;
}

/**
 * result of a `AND` b
 * \param a RzILBool, operand of `AND`
 * \param b RzILBool, operand of `AND`
 * \return bool RzILBool, pointer to the result
 */
RZ_API RzILBool *rz_il_bool_and(RZ_NONNULL RzILBool *a, RZ_NONNULL RzILBool *b) {
	rz_return_val_if_fail(a && b, NULL);
	bool result = a->b && b->b;
	RzILBool *ret = rz_il_bool_new(result);
	return ret;
}

/**
 * result of a `OR` b
 * \param a RzILBool, operand of `AND`
 * \param b RzILBool, operand of `AND`
 * \return bool RzILBool, pointer to the result
 */
RZ_API RzILBool *rz_il_bool_or(RZ_NONNULL RzILBool *a, RZ_NONNULL RzILBool *b) {
	rz_return_val_if_fail(a && b, NULL);
	bool result = a->b || b->b;
	RzILBool *ret = rz_il_bool_new(result);
	return ret;
}

/**
 * result of a `XOR` b
 * \param a RzILBool, operand of `AND`
 * \param b RzILBool, operand of `AND`
 * \return bool RzILBool, pointer to the result
 */
RZ_API RzILBool *rz_il_bool_xor(RZ_NONNULL RzILBool *a, RZ_NONNULL RzILBool *b) {
	rz_return_val_if_fail(a && b, NULL);
	bool result = a->b != b->b;
	return rz_il_bool_new(result);
}

/**
 * result of `NOT` a
 * \param a RzILBool, operand of `AND`
 * \return bool RzILBool, pointer to the result
 */
RZ_API RzILBool *rz_il_bool_not(RZ_NONNULL RzILBool *a) {
	rz_return_val_if_fail(a, NULL);
	bool result = !a->b;
	RzILBool *ret = rz_il_bool_new(result);
	return ret;
}

/**
 * Free RzILBool instance
 * \param bool_var RzILBool, pointer to the bool instance
 */
RZ_API void rz_il_bool_free(RzILBool *bool_var) {
	if (!bool_var) {
		return;
	}
	free(bool_var);
}
