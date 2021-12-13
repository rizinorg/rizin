// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>
#include <rz_il/vm_layer.h>
#include <rz_il/rzil_vm.h>

static RzILEvent *il_event_new_read_from_name(RzILVM *vm, const char *name, RzILVal *value) {
	rz_return_val_if_fail(vm && name, NULL);
	RzBitVector *num = NULL;
	if (value->type == RZIL_VAR_TYPE_BOOL) {
		num = rz_bv_new_from_ut64(1, value->data.b->b);
	} else {
		num = value->data.bv;
	}

	RzILEvent *evt = rz_il_event_var_read_new(name, num);
	if (value->type == RZIL_VAR_TYPE_BOOL) {
		rz_bv_free(num);
	}
	return evt;
}

void *rz_il_handler_ite(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpIte *op_ite = op->op.ite;

	RzILBool *condition = rz_il_evaluate_bool(vm, op_ite->condition, type);
	RzILVal *ret;

	*type = RZIL_OP_ARG_VAL;
	if (condition->b) {
		ret = rz_il_evaluate_val(vm, op_ite->x, type); // true branch
	} else {
		ret = rz_il_evaluate_val(vm, op_ite->y, type); // false branch
	}
	rz_il_bool_free(condition);
	return ret;
}

void *rz_il_handler_var(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	bool is_local = false;

	RzILOpVar *var_op = op->op.var;
	RzILVal *val = rz_il_hash_find_val_by_name(vm, var_op->v);
	if (!val) {
		val = rz_il_hash_find_local_val_by_name(vm, var_op->v);
		is_local = true;
	}
	val = rz_il_value_dup(val);

	if (!is_local) {
		rz_il_vm_event_add(vm, il_event_new_read_from_name(vm, var_op->v, val));
	}

	*type = RZIL_OP_ARG_VAL;
	return val;
}

void *rz_il_handler_unk(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	// has UNK
	RzILVal *val = rz_il_value_new_unk();
	*type = RZIL_OP_ARG_VAL;
	return val;
}

void *rz_il_handler_unimplemented(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	const char *ops[] = {
		"VAR", "UNK", "ITE", "B0", "B1", "INV", "AND_", "OR_",
		"BITV", "MSB", "LSB", "NEG", "NOT", "ADD", "SUB", "MUL",
		"DIV", "SDIV", "MOD", "SMOD", "LOGAND", "LOGOR", "LOGXOR",
		"SHIFTR", "SHIFTL", "SLE", "ULE", "CAST", "CONCAT",
		"APPEND", "LOAD", "STORE", "PERFORM", "SET", "JMP", "GOTO",
		"SEQ", "BLK", "REPEAT", "BRANCH", "INVALID"
	};
	RZ_LOG_ERROR("RzIL: unimplemented op handler (%s).\n", ops[op->code]);
	// has UNK
	RzILVal *val = rz_il_value_new_unk();
	*type = RZIL_OP_ARG_VAL;
	return val;
}
