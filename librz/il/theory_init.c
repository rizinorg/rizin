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

void *rz_il_handler_ite(RzILVM *vm, RzILOpPure *op, RzILPureType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsIte *op_ite = &op->op.ite;

	RzILBool *condition = rz_il_evaluate_bool(vm, op_ite->condition);
	if (!condition) {
		return NULL;
	}
	RzILVal *ret;
	if (condition->b) {
		ret = rz_il_evaluate_pure(vm, op_ite->x, type); // true branch
	} else {
		ret = rz_il_evaluate_pure(vm, op_ite->y, type); // false branch
	}
	rz_il_bool_free(condition);
	return ret;
}

void *rz_il_handler_var(RzILVM *vm, RzILOpPure *op, RzILPureType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	bool is_local = false;

	RzILOpArgsVar *var_op = &op->op.var;
	RzILVal *val = rz_il_hash_find_val_by_name(vm, var_op->v);
	if (!val) {
		val = rz_il_hash_find_local_val_by_name(vm, var_op->v);
		is_local = true;
	}

	if (!val) {
		return NULL;
	}

	if (!is_local) {
		rz_il_vm_event_add(vm, il_event_new_read_from_name(vm, var_op->v, val));
	}

	void *ret = NULL;
	switch (val->type) {
	case RZIL_VAR_TYPE_BOOL:
		*type = RZ_IL_PURE_TYPE_BOOL;
		ret = rz_il_bool_new(val->data.b->b);
		break;
	case RZIL_VAR_TYPE_BV:
		*type = RZ_IL_PURE_TYPE_BITV;
		ret = rz_bv_dup(val->data.bv);
		break;
	default:
		break;
	}
	return ret;
}

void *rz_il_handler_unk(RzILVM *vm, RzILOpPure *op, RzILPureType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}

void *rz_il_handler_pure_unimplemented(RzILVM *vm, RzILOpPure *op, RzILPureType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RZ_LOG_ERROR("RzIL: unimplemented op handler (%d).\n", (int)op->code);
	return NULL;
}

bool rz_il_handler_effect_unimplemented(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, NULL);
	RZ_LOG_ERROR("RzIL: unimplemented op handler (%d).\n", (int)op->code);
	return false;
}
