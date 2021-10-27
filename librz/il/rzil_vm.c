// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>

/**
 * Create A new variable in VM
 * \param vm RzILVM, pointer to VM
 * \param name string, name of this variable
 * \return var RzILVar, pointer to the new variable in VM
 */
RZ_API RzILVar *rz_il_vm_create_variable(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(vm && name, NULL);
	if (vm->var_count >= RZ_IL_VM_MAX_VAR) {
		RZ_LOG_ERROR("No More Vars here\n");
		return NULL;
	}

	// create , store, update count
	RzILVar *var = rz_il_new_variable(name);
	vm->vm_global_variable_list[vm->var_count] = var;
	vm->var_count++;

	return var;
}

/**
 * Create a new value in VM
 * \param vm RzILVM, pointer to VM
 * \param type RZIL_VAR_TYPE, enum to specify the type of this value
 * \return val RzILVal, pointer to the new value in VM
 */
RZ_API RzILVal *rz_il_vm_create_value(RZ_NONNULL RzILVM *vm, RZ_NONNULL RZIL_VAR_TYPE type) {
	rz_return_val_if_fail(vm, NULL);
	if (vm->val_count >= RZ_IL_VM_MAX_VAL) {
		RZ_LOG_ERROR("No More Values\n");
		return NULL;
	}

	RzILVal *val = rz_il_value_new();
	val->type = type;

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
	rz_return_if_fail(vm && name);
	rz_return_if_fail(length > 0);
	RzILVar *var = rz_il_vm_create_variable(vm, name);
	var->type = RZIL_VAR_TYPE_BV;
	RzILVal *val = rz_il_vm_create_value(vm, RZIL_VAR_TYPE_BV);
	val->data.bv = rz_il_bv_new(length);
	rz_il_hash_bind(vm, var, val);
}

/**
 * Make a temporary value (type `RzILVal`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RzILVal *rz_il_vm_fortify_val(RzILVM *vm, RzILVal *val) {
	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Make a temporary value (type `RzILBitVector`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RzILVal *rz_il_vm_fortify_bitv(RzILVM *vm, RzILBitVector *bitv) {
	RzILVal *val = rz_il_value_new();
	if (!val) {
		return NULL;
	}
	val->type = RZIL_VAR_TYPE_BV;
	val->data.bv = bitv;

	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Make a temporary value (type `RzILBool`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RzILVal *rz_il_vm_fortify_bool(RzILVM *vm, RzILBool *b) {
	RzILVal *val = rz_il_value_new();
	if (!val) {
		return NULL;
	}
	val->type = RZIL_VAR_TYPE_BOOL;
	val->data.b = b;

	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

/**
 * Find the value bind to the given variable
 * \param vm RzILVM, pointer to VM
 * \param var RzILVar, pointer to a variable
 * \return val RzILVal, pointer to the value of variable
 */
RZ_API RzILVal *rz_il_hash_find_val_by_var(RzILVM *vm, RzILVar *var) {
	if (!var) {
		RZ_LOG_ERROR("Empty var detected\n");
		return NULL;
	}
	char *var_name = var->var_name;
	RzILVal *ret = rz_il_hash_find_val_by_name(vm, var_name);
	return ret;
}

/**
 * Find the value by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return val RzILVal, pointer to the value of variable with name `var_name`
 */
RZ_API RzILVal *rz_il_hash_find_val_by_name(RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(var_name, NULL);
	RzILVal *ret = ht_pp_find(vm->vm_global_bind_table, var_name, NULL);
	return ret;
}

/**
 * Find the variable by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return var RzILVar, pointer to the variable
 */
RZ_API RzILVar *rz_il_find_var_by_name(RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(var_name, NULL);
	RzILVar *var;
	for (int i = 0; i < vm->var_count; ++i) {
		var = vm->vm_global_variable_list[i];
		if (strcmp(var_name, var->var_name) == 0) {
			return var;
		}
	}
	return NULL;
}

/**
 * Cancel the binding between var and its val, make it available to bind another value
 * \param vm pointer to VM
 * \param var RzILVar, variable you want to cancel its original binding
 */
RZ_API void rz_il_hash_cancel_binding(RzILVM *vm, RzILVar *var) {
	char *var_id = var->var_name;
	RzILVal *val = rz_il_hash_find_val_by_name(vm, var_id);
	rz_il_rm_from_bag(vm->vm_global_value_set, val);
	ht_pp_delete(vm->vm_global_bind_table, var_id);
}

/**
 * Bind variable and value
 * \param vm pointer to VM
 * \param var RzILVar, variable
 * \param val RzILVal, value
 */
RZ_API void rz_il_hash_bind(RzILVM *vm, RzILVar *var, RzILVal *val) {
	rz_return_if_fail(vm);
	if (!var) {
		RZ_LOG_ERROR("Cannot bind to an NULL\n");
		return;
	}
	if (!val) {
		RZ_LOG_ERROR("Val is NULL, fail to bind to a variable\n");
		return;
	}
	char *var_id = var->var_name;
	ht_pp_update(vm->vm_global_bind_table, var_id, val);
}

/**
 * Find the bitvector address by given name
 * \param vm RzILVM* vm, pointer to VM
 * \param lbl_name string, the name of label
 * \return addr RzILBitVector, address which has RzILBitVector type
 */
RZ_API RzILBitVector *rz_il_hash_find_addr_by_lblname(RzILVM *vm, RZ_NONNULL const char *lbl_name) {
	HtPP *lbl_table = vm->vm_global_label_table;
	RzILBitVector *ret;
	bool found = false;

	rz_return_val_if_fail(lbl_name, NULL);
	RzILEffectLabel *label = ht_pp_find(lbl_table, lbl_name, &found);
	if (found) {
		ret = label->addr;
		return ret;
	}
	return NULL;
}

/**
 * Find the label instance by name
 * \param vm RzILVM, pointer to VM
 * \param lbl_name string, the name of label
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RzILEffectLabel *rz_il_vm_find_label_by_name(RzILVM *vm, RZ_NONNULL const char *lbl_name) {
	rz_return_val_if_fail(lbl_name, NULL);
	RzILEffectLabel *lbl = ht_pp_find(vm->vm_global_label_table, lbl_name, NULL);
	return lbl;
}

/**
 * Create a label in VM
 * \param vm RzILVM, pointer to VM
 * \param name string, name of label
 * \param addr RzILBitVector, label address
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RzILEffectLabel *rz_il_vm_create_label(RzILVM *vm, RZ_NONNULL const char *name, RzILBitVector *addr) {
	rz_return_val_if_fail(name, NULL);
	HtPP *lbl_table = vm->vm_global_label_table;

	RzILEffectLabel *lbl = rz_il_effect_label_new(name, EFFECT_LABEL_ADDR);
	lbl->addr = rz_il_bv_dup(addr);
	ht_pp_insert(lbl_table, name, lbl);

	return lbl;
}

/**
 * Create a label without address, use rz_il_vm_update_label to update address for it
 * \param vm RzILVM, pointer to VM
 * \param name string, name of this label
 * \return lbl RzILEffectLabel, pointer to label instance
 */
RZ_API RzILEffectLabel *rz_il_vm_create_label_lazy(RzILVM *vm, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(name, NULL);
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
RZ_API RzILEffectLabel *rz_il_vm_update_label(RzILVM *vm, RZ_NONNULL char *name, RzILBitVector *addr) {
	rz_return_val_if_fail(name, NULL);
	RzILEffectLabel *lbl = ht_pp_find(vm->vm_global_label_table, name, NULL);
	if (lbl->addr) {
		rz_il_bv_free(lbl->addr);
	}
	lbl->addr = rz_il_bv_dup(addr);

	return lbl;
}

/**
 * Store an opcode list to address
 * \param vm RzILVM, pointer to VM
 * \param addr RzILBitVector, address of this opcode list
 * \param oplist RzPVector of RzILOp, core theory opcodes
 */
RZ_API void rz_il_vm_store_opcodes_to_addr(RzILVM *vm, RzILBitVector *addr, RzPVector *oplist) {
	rz_return_if_fail(addr && oplist);
	ht_pp_insert(vm->ct_opcodes, addr, oplist);
}

/**
 * Make a core theory opcode vector
 * \param num int, number of total opcodes
 * \param ... op RzILOp, op will be pushed to vector one by one
 * \return oplist RzPVector*, pointer to the opcode
 */
RZ_API RzPVector *rz_il_make_oplist(int num, ...) {
	va_list args;
	RzILOp *cur_op;
	RzPVector *oplist = rz_pvector_new((RzPVectorFree)rz_il_free_op);

	va_start(args, num);
	for (int i = 0; i < num; ++i) {
		cur_op = va_arg(args, RzILOp *);
		rz_pvector_push(oplist, cur_op);
	}
	va_end(args);

	return oplist;
}

// WARN : convertion breaks the original data
static RzILBool *bitv_to_bool(RzILBitVector *bitv) {
	RzILBool *result = rz_il_bool_new(!rz_il_bv_is_zero_vector(bitv));
	rz_il_bv_free(bitv);
	return result;
}

static RzILVal *bitv_to_val(RzILBitVector *bitv) {
	RzILVal *ret = rz_il_value_new();
	ret->type = RZIL_VAR_TYPE_BV;
	ret->data.bv = bitv;
	return ret;
}

static RzILVal *bool_to_val(RzILBool *b) {
	RzILVal *ret = rz_il_value_new();
	ret->type = RZIL_VAR_TYPE_BOOL;
	ret->data.b = b;
	return ret;
}

static RzILBitVector *val_to_bitv(RzILVal *val) {
	RzILBitVector *ret;
	if (val->type != RZIL_VAR_TYPE_BV) {
		RZ_LOG_ERROR("RzIL : Expected bool, but UNK/BOOL detected\n");
		return NULL;
	}

	ret = val->data.bv;
	RZ_FREE(val);
	return ret;
}

static RzILBool *val_to_bool(RzILVal *val) {
	RzILBool *ret;
	if (val->type != RZIL_VAR_TYPE_BOOL) {
		if (val->type == RZIL_VAR_TYPE_BV) {
			return bitv_to_bool(val_to_bitv(val));
		}
		RZ_LOG_ERROR("RzIL : Expected bool, but UNK detected\n");
		return NULL;
	}

	ret = val->data.b;
	RZ_FREE(val);
	return ret;
}

/**
 * Evaluate the an expression (Opcode) and return a bitvector value
 * This function will automatically convert valid value(Bool/BitVector/RzILVal) into bitv
 * to ensure caller to get a bitvector type value.
 * \param vm, RzILVM*, pointer to RzILVM
 * \param op, RzILOp* Pointer to opcode
 * \param type, RzILOpArgType*, a pointer to store type info for error-checking
 * \return bitv, value in bitvector
 */
RZ_API RzILBitVector *rz_il_evaluate_bitv(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	// check type and auto convertion between bitv/bool/val
	void *input = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	// check if type is bitv
	// else, convert to bitv if possible
	// else report error
	switch (t) {
	case RZIL_OP_ARG_BITV:
		return (RzILBitVector *)input;
	case RZIL_OP_ARG_BOOL:
		*type = RZIL_OP_ARG_BOOL;
		RZ_LOG_ERROR("TODO : BOOL TO BITV\n");
		return NULL;
	case RZIL_OP_ARG_VAL:
		*type = RZIL_OP_ARG_BITV;
		return val_to_bitv(input);
	case RZIL_OP_ARG_EFF:
	case RZIL_OP_ARG_MEM:
	default:
		RZ_LOG_ERROR("RzIL : Expected Bool/BitVector/RzILVal\n");
		break;
	}

	return NULL;
}

/**
 * Evaluate the an expression (Opcode) and return a bool value
 * This function will automatically convert valid value(Bool/BitVector/RzILVal) into bool
 * to ensure caller to get a bool type value.
 * \param vm, RzILVM*, pointer to RzILVM
 * \param op, RzILOp* Pointer to opcode
 * \param type, RzILOpArgType*, a pointer to store type info for error-checking
 * \return bool, Bool*, the value of this expression
 */
RZ_API RzILBool *rz_il_evaluate_bool(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	void *result = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	// check if type is bitv
	// else, convert to bitv if possible
	// else report error
	switch (t) {
	case RZIL_OP_ARG_BITV:
		*type = RZIL_OP_ARG_BOOL;
		return bitv_to_bool(result);
	case RZIL_OP_ARG_BOOL:
		return result;
	case RZIL_OP_ARG_VAL:
		*type = RZIL_OP_ARG_BOOL;
		return val_to_bool(result);
	case RZIL_OP_ARG_EFF:
	case RZIL_OP_ARG_MEM:
	default:
		RZ_LOG_ERROR("RzIL : Expected BitVector/Bool/RzILVal\n");
		break;
	}

	return NULL;
}

/**
 * Evaluate the an expression (Opcode) and return a RzILVal
 * This function will automatically convert valid value (Bitv/Bool/RzILVal) into RzILVal
 * to ensure caller to get a RzILVal type value.
 * \param vm, RzILVM*, pointer to RzILVM
 * \param op, RzILOp* Pointer to opcode
 * \param type, RzILOpArgType*, a pointer to store type info for error-checking
 * \return val, RzILVal*, RzILVal type value
 */
RZ_API RzILVal *rz_il_evaluate_val(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	void *result = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	// check if type is bitv
	// else, convert to bitv if possible
	// else report error
	switch (t) {
	case RZIL_OP_ARG_BITV:
		*type = RZIL_OP_ARG_VAL;
		return bitv_to_val(result);
	case RZIL_OP_ARG_BOOL:
		*type = RZIL_OP_ARG_VAL;
		return bool_to_val(result);
	case RZIL_OP_ARG_VAL:
		return result;
	case RZIL_OP_ARG_EFF:
	case RZIL_OP_ARG_MEM:
	default:
		RZ_LOG_ERROR("BRzIL : Expected RzILVal/BitVector/Bool\n");
		break;
	}

	return NULL;
}

/**
 * Evaluate the an expression (Opcode) and return a effect
 * This function will automatically convert valid value into effect
 * to ensure caller to get an effect type value.
 * \param vm, RzILVM*, pointer to RzILVM
 * \param op, RzILOp* Pointer to opcode
 * \param type, RzILOpArgType*, a pointer to store type info for error-checking
 * \return effect, RzILEffect*, expression value
 */
RZ_API RzILEffect *rz_il_evaluate_effect(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	void *result = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	// check if type is bitv
	// else, convert to bitv if possible
	// else report error
	switch (t) {
	case RZIL_OP_ARG_EFF:
		return result;
	case RZIL_OP_ARG_BITV:
		rz_il_bv_free(result);
		break;
	case RZIL_OP_ARG_BOOL:
		rz_il_bool_free(result);
		break;
	case RZIL_OP_ARG_VAL:
		rz_il_value_free(result);
		break;
	case RZIL_OP_ARG_MEM:
		rz_il_mem_free(result);
		break;
	default:
		RZ_LOG_ERROR("RzIL : Expected Effect\n");
		break;
	}

	return NULL;
}

/**
 * It invoke handler to execute an opcode (the root one)
 * during the execution, subroutines (handler) might use `evaluate_*` families
 * to evaluate sub expressions. And `evaluate_*` families will also invoke this
 * function to handle different opcodes. And thus this is a recursive function
 * \param vm, RzILVM*, pointer to RzILVM
 * \param root, RzILOp*, pointer to opcode
 * \param type, RzILOpArgType*, pointer to store the type info of root value
 * \return the value of root expression, the type info stored in RzILOpArgType type
 */
// recursively parse and evaluate
RZ_API void *rz_il_parse_op_root(RzILVM *vm, RzILOp *root, RzILOpArgType *type) {
	RzILOpHandler handler = vm->op_handler_table[root->code];
	return handler ? handler(vm, root, type) : NULL;
}
