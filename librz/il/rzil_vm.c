// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>

/**
 * Create A new global variable in VM
 * \param  vm         RzILVM, pointer to VM
 * \param  name       string, name of this variable
 * \param  is_mutable bool, sets if variable is const or not
 * \return var        RzILVar, pointer to the new variable in VM
 */
RZ_API RZ_BORROW RzILVar *rz_il_vm_create_global_variable(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVarType type, bool is_mutable) {
	rz_return_val_if_fail(vm && name, NULL);
	if (rz_pvector_len(&vm->vm_global_variable_list) >= RZ_IL_VM_MAX_VAR) {
		RZ_LOG_ERROR("RzIL: reached max number of variables that the VM can handle.\n");
		return NULL;
	}

	// create , store, update count
	RzILVar *var = rz_il_variable_new(name, type, is_mutable);
	rz_pvector_push(&vm->vm_global_variable_list, var);
	return var;
}

/**
 * Create A new local variable in VM
 * \param  vm         RzILVM, pointer to VM
 * \param  name       string, name of this variable
 * \param  is_mutable bool, sets if variable is const or not
 * \return var        RzILVar, pointer to the new variable in VM
 */
RZ_API RZ_BORROW RzILVar *rz_il_vm_create_local_variable(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVarType type, bool is_mutable) {
	rz_return_val_if_fail(vm && name, NULL);
	if (rz_pvector_len(&vm->vm_global_variable_list) >= RZ_IL_VM_MAX_VAR) {
		RZ_LOG_ERROR("RzIL: reached max number of variables that the VM can handle.\n");
		return NULL;
	}

	// create , store, update count
	RzILVar *var = rz_il_variable_new(name, type, is_mutable);
	rz_pvector_push(&vm->vm_local_variable_list, var);
	return var;
}

/**
 * Create a new value in VM (BitVector type)
 * \param vm RzILVM, pointer to VM
 * \param bitv RzBitVector, enum to specify the type of this value
 * \return val RzILVal, pointer to the new value in VM
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_create_value_bitv(RZ_NONNULL RzILVM *vm, RZ_NULLABLE RzBitVector *bitv) {
	rz_return_val_if_fail(vm && bitv, NULL);
	if (vm->val_count >= RZ_IL_VM_MAX_VAL) {
		RZ_LOG_ERROR("No More Values\n");
		return NULL;
	}

	RzILVal *val = rz_il_value_new_bitv(bitv);
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Create a new value in VM (Boolean type)
 * \param vm RzILVM, pointer to VM
 * \param type RzILVarType, enum to specify the type of this value
 * \return val RzILVal, pointer to the new value in VM
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_create_value_bool(RZ_NONNULL RzILVM *vm, bool value) {
	rz_return_val_if_fail(vm, NULL);
	if (vm->val_count >= RZ_IL_VM_MAX_VAL) {
		RZ_LOG_ERROR("No More Values\n");
		return NULL;
	}
	RzILBool *b = rz_il_bool_new(value);
	if (!b) {
		rz_warn_if_reached();
		return NULL;
	}
	RzILVal *val = rz_il_value_new_bool(b);
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Create a new value in VM with (Unknown type)
 * \param vm RzILVM, pointer to VM
 * \param type RzILVarType, enum to specify the type of this value
 * \return val RzILVal, pointer to the new value in VM
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_create_value_unk(RZ_NONNULL RzILVM *vm) {
	rz_return_val_if_fail(vm, NULL);
	if (vm->val_count >= RZ_IL_VM_MAX_VAL) {
		RZ_LOG_ERROR("No More Values\n");
		return NULL;
	}

	RzILVal *val = rz_il_value_new_unk();
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Add a register in VM (create a variable and value, and then bind value to variable)
 * \param vm RzILVM, pointer to this vm
 * \param name string, the name of register
 * \param length ut32, width of register
 */
RZ_API void rz_il_vm_add_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, ut32 length) {
	rz_return_if_fail(vm && name && length > 0);
	RzBitVector *bv = rz_bv_new_zero(length);
	if (!bv) {
		rz_warn_if_reached();
		return;
	}
	RzILVar *var = rz_il_vm_create_global_variable(vm, name, RZIL_VAR_TYPE_BV, true);
	RzILVal *val = rz_il_vm_create_value_bitv(vm, bv);
	rz_il_hash_bind(vm, var, val);
}

/**
 * Add a register in VM (create a variable and value, and then bind value to variable)
 * \param vm RzILVM, pointer to this vm
 * \param name string, the name of register
 * \param value bool, value of the bit register
 */
RZ_API void rz_il_vm_add_bit_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, bool value) {
	rz_return_if_fail(vm && name);
	RzILVar *var = rz_il_vm_create_global_variable(vm, name, RZIL_VAR_TYPE_BOOL, true);
	RzILVal *val = rz_il_vm_create_value_bool(vm, value);
	rz_il_hash_bind(vm, var, val);
}

/**
 * Make a temporary value (type `RzILVal`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVal *val) {
	rz_return_val_if_fail(vm && val, NULL);
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Make a temporary value (type `RzBitVector`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzBitVector *bitv) {
	rz_return_val_if_fail(vm && bitv, NULL);
	RzILVal *val = rz_il_value_new_bitv(bitv);
	if (!val) {
		return NULL;
	}
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Make a temporary value (type `RzILBool`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_bool(RZ_NONNULL RzILVM *vm, bool value) {
	rz_return_val_if_fail(vm, NULL);
	RzILBool *b = rz_il_bool_new(value);
	if (!b) {
		rz_warn_if_reached();
		return NULL;
	}
	RzILVal *val = rz_il_value_new_bool(b);
	if (!val) {
		return NULL;
	}
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Find the global value bind to the given variable
 * \param vm RzILVM, pointer to VM
 * \param var RzILVar, pointer to a variable
 * \return val RzILVal, pointer to the value of variable
 */
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_val_by_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var) {
	rz_return_val_if_fail(vm && var, NULL);
	return rz_il_hash_find_val_by_name(vm, var->var_name);
}

/**
 * Find the global value by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return val RzILVal, pointer to the value of variable with name `var_name`
 */
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_val_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(vm && var_name, NULL);
	return ht_pp_find(vm->vm_global_bind_table, var_name, NULL);
}

/**
 * Find the local value bind to the given variable
 * \param vm RzILVM, pointer to VM
 * \param var RzILVar, pointer to a variable
 * \return val RzILVal, pointer to the value of variable
 */
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_local_val_by_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var) {
	rz_return_val_if_fail(vm && var, NULL);
	return rz_il_hash_find_local_val_by_name(vm, var->var_name);
}

/**
 * Find the local value by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return val RzILVal, pointer to the value of variable with name `var_name`
 */
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_local_val_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(vm && var_name, NULL);
	return ht_pp_find(vm->vm_local_bind_table, var_name, NULL);
}

/**
 * Find the global variable by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return var RzILVar, pointer to the variable
 */
RZ_API RZ_BORROW RzILVar *rz_il_find_var_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(vm && var_name, NULL);
	RzILVar *var;
	void **it;
	rz_pvector_foreach (&vm->vm_global_variable_list, it) {
		var = (RzILVar *)*it;
		if (!strcmp(var_name, var->var_name)) {
			return var;
		}
	}
	return NULL;
}

/**
 * Find the local variable by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return var RzILVar, pointer to the variable
 */
RZ_API RZ_BORROW RzILVar *rz_il_find_local_var_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(vm && var_name, NULL);
	RzILVar *var;
	void **it;
	rz_pvector_foreach (&vm->vm_local_variable_list, it) {
		var = (RzILVar *)*it;
		if (!strcmp(var_name, var->var_name)) {
			return var;
		}
	}
	return NULL;
}

/**
 * Cancel the binding between global var and its val, make it available to bind another value
 * \param vm pointer to VM
 * \param var RzILVar, variable you want to cancel its original binding
 */
RZ_API void rz_il_hash_cancel_binding(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var) {
	rz_return_if_fail(vm && var);
	RzILVal *val = rz_il_hash_find_val_by_name(vm, var->var_name);
	rz_il_rm_from_bag(vm->vm_global_value_set, val);
	ht_pp_delete(vm->vm_global_bind_table, var->var_name);
}

/**
 * Bind global variable and value
 * \param vm pointer to VM
 * \param var RzILVar, variable
 * \param val RzILVal, value
 */
RZ_API void rz_il_hash_bind(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var, RZ_NONNULL RzILVal *val) {
	rz_return_if_fail(vm && var && val);
	ht_pp_update(vm->vm_global_bind_table, var->var_name, val);
}

/**
 * Cancel the binding between local var and its val, make it available to bind another value
 * \param vm pointer to VM
 * \param var RzILVar, variable you want to cancel its original binding
 */
RZ_API void rz_il_hash_cancel_local_binding(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var) {
	rz_return_if_fail(vm && var);
	ht_pp_delete(vm->vm_local_bind_table, var->var_name);
}

/**
 * Bind local variable and value
 * \param vm pointer to VM
 * \param var RzILVar, variable
 * \param val RzILVal, value
 */
RZ_API void rz_il_hash_local_bind(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var, RZ_NONNULL RzILVal *val) {
	rz_return_if_fail(vm && var && val);
	ht_pp_update(vm->vm_local_bind_table, var->var_name, val);
}

/**
 * Find the bitvector address by given name
 * \param vm RzILVM* vm, pointer to VM
 * \param lbl_name string, the name of label
 * \return addr RzBitVector, address which has RzBitVector type
 */
RZ_API RZ_BORROW RzBitVector *rz_il_hash_find_addr_by_lblname(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *lbl_name) {
	rz_return_val_if_fail(vm && lbl_name, NULL);
	bool found = false;
	RzILEffectLabel *label = ht_pp_find(vm->vm_global_label_table, lbl_name, &found);
	if (!found) {
		return NULL;
	}
	return label->addr;
}

/**
 * Find the label instance by name
 * \param vm RzILVM, pointer to VM
 * \param lbl_name string, the name of label
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_find_label_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *lbl_name) {
	rz_return_val_if_fail(vm && lbl_name, NULL);
	return ht_pp_find(vm->vm_global_label_table, lbl_name, NULL);
}

/**
 * Create a label in VM
 * \param vm RzILVM, pointer to VM
 * \param name string, name of label
 * \param addr RzBitVector, label address
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_create_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_NONNULL RZ_BORROW RzBitVector *addr) {
	rz_return_val_if_fail(vm && name && addr, NULL);
	HtPP *lbl_table = vm->vm_global_label_table;

	RzILEffectLabel *lbl = rz_il_effect_label_new(name, EFFECT_LABEL_ADDR);
	lbl->addr = rz_bv_dup(addr);
	ht_pp_insert(lbl_table, name, lbl);
	return lbl;
}

/**
 * Create a label without address, use rz_il_vm_update_label to update address for it
 * \param vm RzILVM, pointer to VM
 * \param name string, name of this label
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_create_label_lazy(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(vm && name, NULL);
	HtPP *lbl_table = vm->vm_global_label_table;

	RzILEffectLabel *lbl = rz_il_effect_label_new(name, EFFECT_LABEL_ADDR);
	lbl->addr = NULL;
	ht_pp_insert(lbl_table, name, lbl);

	return lbl;
}

/**
 * Update the address info of a label
 * \param vm RzILVM, pointer to VM
 * \param name string, name of this label
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_update_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL char *name, RZ_NONNULL RZ_BORROW RzBitVector *addr) {
	rz_return_val_if_fail(vm && name && addr, NULL);
	RzILEffectLabel *lbl = ht_pp_find(vm->vm_global_label_table, name, NULL);
	if (lbl->addr) {
		rz_bv_free(lbl->addr);
	}
	lbl->addr = rz_bv_dup(addr);

	return lbl;
}

/**
 * Store an opcode list to address
 * \param vm RzILVM, pointer to VM
 * \param addr RzBitVector, address of this opcode list
 * \param oplist RzPVector of RzILOp, core theory opcodes
 */
RZ_API void rz_il_vm_store_opcodes_to_addr(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzBitVector *addr, RZ_NONNULL RzPVector *oplist) {
	rz_return_if_fail(vm && addr && oplist);
	ht_pp_insert(vm->ct_opcodes, addr, oplist);
}

/**
 * Make a core theory opcode vector
 * \param num int, number of total opcodes
 * \param ... op RzILOp, op will be pushed to vector one by one
 * \return oplist RzPVector*, pointer to the opcode
 */
RZ_API RZ_OWN RzPVector *rz_il_make_oplist(ut32 num, ...) {
	va_list args;
	RzILOpEffect *cur_op;
	RzPVector *oplist = rz_pvector_new((RzPVectorFree)rz_il_op_effect_free);

	va_start(args, num);
	for (ut32 i = 0; i < num; ++i) {
		cur_op = va_arg(args, RzILOpEffect *);
		rz_pvector_push(oplist, cur_op);
	}
	va_end(args);

	return oplist;
}

static void *eval_pure(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILPureType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpPureHandler handler = vm->op_handler_pure_table[op->code];
	rz_return_val_if_fail(handler, NULL);
	return handler(vm, op, type);
}

static bool eval_effect(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, NULL);
	RzILOpEffectHandler handler = vm->op_handler_effect_table[op->code];
	rz_return_val_if_fail(handler, NULL);
	return handler(vm, op);
}

static const char *pure_type_name(RzILPureType type) {
	switch (type) {
		case RZ_IL_PURE_TYPE_BITV:
			return "bitvector";
		case RZ_IL_PURE_TYPE_BOOL:
			return "bool";
		default:
			return "unknown";
	}
}

/**
 * Evaluate the given pure op, asserting it returns a bitvector.
 * \return value in bitvector, or NULL if an error occurred (e.g. the op returned some other type)
 */
RZ_API RZ_NULLABLE RZ_OWN RzBitVector *rz_il_evaluate_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpBitVector *op) {
	rz_return_val_if_fail(vm && op, NULL);
	// check type and auto convertion between bitv/bool/val
	RzILPureType type = -1;
	void *res = eval_pure(vm, op, &type);
	if (!res) {
		// propagate error
		return NULL;
	}
	if (type != RZ_IL_PURE_TYPE_BITV) {
		RZ_LOG_ERROR("RzIL: type error: expected bitvector, got %s\n", pure_type_name(type));
		return NULL;
	}
	return res;
}

/**
 * Evaluate the given pure op, asserting it returns a bool.
 * \return value in bool, or NULL if an error occurred (e.g. the op returned some other type)
 */
RZ_API RZ_NULLABLE RZ_OWN RzILBool *rz_il_evaluate_bool(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpBool *op) {
	rz_return_val_if_fail(vm && op, NULL);
	// check type and auto convertion between bitv/bool/val
	RzILPureType type = -1;
	void *res = eval_pure(vm, op, &type);
	if (!res) {
		// propagate error
		return NULL;
	}
	if (type != RZ_IL_PURE_TYPE_BOOL) {
		RZ_LOG_ERROR("RzIL: type error: expected bool, got %s\n", pure_type_name(type));
		return NULL;
	}
	return res;
}

/**
 * Evaluate the given pure op, returning the resulting bool or bitvector.
 * \return val, RzILVal*, RzILVal type value
 */
RZ_API RZ_NULLABLE RZ_OWN RzILVal *rz_il_evaluate_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op) {
	rz_return_val_if_fail(vm && op, NULL);
	// check type and auto convertion between bitv/bool/val
	RzILPureType type = -1;
	void *res = eval_pure(vm, op, &type);
	if (!res) {
		// propagate error
		return NULL;
	}
	switch (type) {
	case RZ_IL_PURE_TYPE_BOOL:
		return rz_il_value_new_bool(res);
	case RZ_IL_PURE_TYPE_BITV:
		return rz_il_value_new_bitv(res);
	default:
		RZ_LOG_ERROR("RzIL: type error: expected bitvector, got %s\n", pure_type_name(type));
		return NULL;
	}
}

/**
 * Evaluate the given pure op, returning the resulting value and its type.
 */
RZ_API RZ_NULLABLE RZ_OWN RzILVal *rz_il_evaluate_pure(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILPureType *type) {
	rz_return_val_if_fail(vm && op, NULL);
	return eval_pure(vm, op, type);
}

/**
 * Evaluate (execute) the given effect op
 * \return false if an error occured and the execution should be aborted
 */
RZ_API bool rz_il_evaluate_effect(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);
	return eval_effect(vm, op);
}
