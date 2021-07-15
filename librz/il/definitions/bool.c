#include "bool.h"

Bool rz_il_new_bool(bool true_or_false) {
	Bool ret = (Bool)malloc(sizeof(struct bool_t));
	ret->b = true_or_false;
	return ret;
}

Bool rz_il_bool_and_(Bool a, Bool b) {
	bool result = a->b && b->b;
	Bool ret = rz_il_new_bool(result);
	return ret;
}

Bool rz_il_bool_or_(Bool a, Bool b) {
	bool result = a->b || b->b;
	Bool ret = rz_il_new_bool(result);
	return ret;
}

Bool rz_il_bool_xor_(Bool a, Bool b) {
	bool result = !(a->b && b->b);
	return rz_il_new_bool(result);
}

Bool rz_il_bool_not_(Bool a) {
	bool result = !a->b;
	Bool ret = rz_il_new_bool(result);
	return ret;
}

void rz_il_free_bool(Bool bool_var) {
	free(bool_var);
}
