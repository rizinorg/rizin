// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/bool.h>

/**
 * RzILBool is immutable, so there are only two distinct values and every
 * RzILBool is one of these two shared instances. They are const so that any
 * stray write faults immediately instead of silently corrupting every bool.
 */
static const RzILBool il_bool_false = { .b = false };
static const RzILBool il_bool_true = { .b = true };

/**
 * Get the RzILBool instance for a truth value
 * \param true_or_false bool, set bool as true or false
 * \return bool RzILBool, pointer to the shared (immutable) bool value
 */
RZ_API RzILBool *rz_il_bool_new(bool true_or_false) {
	return (RzILBool *)(true_or_false ? &il_bool_true : &il_bool_false);
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
	// Every RzILBool is one of the shared instances, so there is nothing to free.
	(void)bool_var;
}
