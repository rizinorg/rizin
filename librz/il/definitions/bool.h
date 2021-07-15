#ifndef BUILD_BOOL_H
#define BUILD_BOOL_H
#include "common.h"

struct bool_t {
	bool b;
};
typedef struct bool_t *Bool;

Bool rz_il_new_bool(bool true_or_false);
Bool rz_il_bool_and_(Bool a, Bool b);
Bool rz_il_bool_or_(Bool a, Bool b);
Bool rz_il_bool_xor_(Bool a, Bool b);
Bool rz_il_bool_not_(Bool a);
void rz_il_free_bool(Bool bool_var);

#endif //BUILD_BOOL_H
