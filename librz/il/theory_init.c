// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_vm.h>

static RzILEvent *il_event_new_read_from_name(RzILVM *vm, const char *name, RzILVal *value) {
	rz_return_val_if_fail(vm && name, NULL);
	RzBitVector *num = NULL;
	if (value->type == RZ_IL_TYPE_PURE_BOOL) {
		num = rz_bv_new_from_ut64(1, value->data.b->b);
	} else {
		num = value->data.bv;
	}

	RzILEvent *evt = rz_il_event_var_read_new(name, num);
	if (value->type == RZ_IL_TYPE_PURE_BOOL) {
		rz_bv_free(num);
	}
	return evt;
}

void *rz_il_handler_ite(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
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

void *rz_il_handler_var(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsVar *var_op = &op->op.var;
	RzILVal *val = rz_il_vm_get_var_value(vm, var_op->kind, var_op->v);
	if (!val) {
		return NULL;
	}

	if (var_op->kind == RZ_IL_VAR_KIND_GLOBAL) {
		rz_il_vm_event_add(vm, il_event_new_read_from_name(vm, var_op->v, val));
	}

	void *ret = NULL;
	switch (val->type) {
	case RZ_IL_TYPE_PURE_BOOL:
		*type = RZ_IL_TYPE_PURE_BOOL;
		ret = rz_il_bool_new(val->data.b->b);
		break;
	case RZ_IL_TYPE_PURE_BITVECTOR:
		*type = RZ_IL_TYPE_PURE_BITVECTOR;
		ret = rz_bv_dup(val->data.bv);
		break;
	default:
		break;
	}
	return ret;
}

void *rz_il_handler_let(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsLet *args = &op->op.let;
	RzILVal *v = rz_il_evaluate_val(vm, args->exp);
	if (!v) {
		return NULL;
	}
	RzILLocalPurePrev prev = rz_il_vm_push_local_pure_var(vm, args->name, v);
	void *r = rz_il_evaluate_pure(vm, args->body, type);
	rz_il_vm_pop_local_pure_var(vm, args->name, prev);
	return r;
}

void *rz_il_handler_unk(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	return NULL;
}

void *rz_il_handler_pure_unimplemented(RzILVM *vm, RzILOpPure *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RZ_LOG_ERROR("RzIL: unimplemented op handler (%d).\n", (int)op->code);
	return NULL;
}

bool rz_il_handler_effect_unimplemented(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, NULL);
	RZ_LOG_ERROR("RzIL: unimplemented op handler (%d).\n", (int)op->code);
	return false;
}
