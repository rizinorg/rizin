#include "bool.h"

/**
 * Create a new Bool instance
 * @param true_or_false bool, set bool as true or false
 * @return bool Bool, pointer to bool value
 */
RZ_API Bool rz_il_new_bool(bool true_or_false) {
	Bool ret = (Bool)malloc(sizeof(struct bool_t));
	ret->b = true_or_false;
	return ret;
}

/**
 * result of a `AND` b
 * @param a Bool, operand of `AND`
 * @param b Bool, operand of `AND`
 * @return bool Bool, pointer to the result
 */
RZ_API Bool rz_il_bool_and_(Bool a, Bool b) {
	bool result = a->b && b->b;
	Bool ret = rz_il_new_bool(result);
	return ret;
}

/**
 * result of a `OR` b
 * @param a Bool, operand of `AND`
 * @param b Bool, operand of `AND`
 * @return bool Bool, pointer to the result
 */
RZ_API Bool rz_il_bool_or_(Bool a, Bool b) {
	bool result = a->b || b->b;
	Bool ret = rz_il_new_bool(result);
	return ret;
}

/**
 * result of a `XOR` b
 * @param a Bool, operand of `AND`
 * @param b Bool, operand of `AND`
 * @return bool Bool, pointer to the result
 */
RZ_API Bool rz_il_bool_xor_(Bool a, Bool b) {
	bool result = !(a->b && b->b);
	return rz_il_new_bool(result);
}

/**
 * result of `NOT` a
 * @param a Bool, operand of `AND`
 * @return bool Bool, pointer to the result
 */
RZ_API Bool rz_il_bool_not_(Bool a) {
	bool result = !a->b;
	Bool ret = rz_il_new_bool(result);
	return ret;
}

/**
 * Free Bool instance
 * @param bool_var Bool, pointer to the bool instance
 */
RZ_API void rz_il_free_bool(Bool bool_var) {
	free(bool_var);
}
