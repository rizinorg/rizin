// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>

/**
 * Create A new variable in VM
 * \param vm RzILVM, pointer to VM
 * \param name string, name of this variable
 * \return var RzILVar, pointer to the new variable in VM
 */
RZ_API RZ_BORROW RzILVar *rz_il_vm_create_variable(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVarType type) {
	rz_return_val_if_fail(vm && name, NULL);
	if (vm->var_count >= RZ_IL_VM_MAX_VAR) {
		RZ_LOG_ERROR("RzIL: reached max number of variables that the VM can handle.\n");
		return NULL;
	}

	// create , store, update count
	RzILVar *var = rz_il_variable_new(name, type);
	vm->vm_global_variable_list[vm->var_count] = var;
	vm->var_count++;

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
	RzILVar *var = rz_il_vm_create_variable(vm, name, RZIL_VAR_TYPE_BV);
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
	RzILVar *var = rz_il_vm_create_variable(vm, name, RZIL_VAR_TYPE_BOOL);
	RzILVal *val = rz_il_vm_create_value_bool(vm, value);
	rz_il_hash_bind(vm, var, val);
}

/**
 * Make a temporary value (type `RzILVal`) inside vm become a value store in VM
 * \param vm RzILVM, pointer to VM
 * \param temp_val_index int, the index of temporary value you attempt to fortify
 * \return val RzILVal, pointer to the fortified value
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_val(RzILVM *vm, RzILVal *val) {
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
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_bitv(RzILVM *vm, RzBitVector *bitv) {
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
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_bool(RzILVM *vm, bool value) {
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
 * Find the value bind to the given variable
 * \param vm RzILVM, pointer to VM
 * \param var RzILVar, pointer to a variable
 * \return val RzILVal, pointer to the value of variable
 */
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_val_by_var(RzILVM *vm, RzILVar *var) {
	rz_return_val_if_fail(vm && var, NULL);
	return rz_il_hash_find_val_by_name(vm, var->var_name);
}

/**
 * Find the value by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return val RzILVal, pointer to the value of variable with name `var_name`
 */
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_val_by_name(RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(vm && var_name, NULL);
	return ht_pp_find(vm->vm_global_bind_table, var_name, NULL);
}

/**
 * Find the variable by variable name
 * \param vm RzILVM, pointer to VM
 * \param var_name string, the name of variable
 * \return var RzILVar, pointer to the variable
 */
RZ_API RZ_BORROW RzILVar *rz_il_find_var_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name) {
	rz_return_val_if_fail(vm && var_name, NULL);
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
RZ_API void rz_il_hash_cancel_binding(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var) {
	rz_return_if_fail(vm && var);
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
RZ_API void rz_il_hash_bind(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var, RZ_NONNULL RzILVal *val) {
	rz_return_if_fail(vm && var && val);
	ht_pp_update(vm->vm_global_bind_table, var->var_name, val);
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
	RzILOp *cur_op;
	RzPVector *oplist = rz_pvector_new((RzPVectorFree)rz_il_op_free);

	va_start(args, num);
	for (ut32 i = 0; i < num; ++i) {
		cur_op = va_arg(args, RzILOp *);
		rz_pvector_push(oplist, cur_op);
	}
	va_end(args);

	return oplist;
}

// WARN : convertion breaks the original data
static RzILBool *bitv_to_bool(RzBitVector *bitv) {
	RzILBool *result = rz_il_bool_new(!rz_bv_is_zero_vector(bitv));
	rz_bv_free(bitv);
	return result;
}

static RzBitVector *val_to_bitv(RzILVal *val) {
	RzBitVector *ret;
	if (val->type != RZIL_VAR_TYPE_BV) {
		RZ_LOG_ERROR("RzIL: Expected bitvector, but unknown or bool type detected\n");
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
		RZ_LOG_ERROR("RzIL: Expected bool or bitvector, but unknown type detected\n");
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
RZ_API RZ_OWN RzBitVector *rz_il_evaluate_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	// check type and auto convertion between bitv/bool/val
	void *input = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	switch (t) {
	case RZIL_OP_ARG_BITV:
	case RZIL_OP_ARG_BOOL:
		return (RzBitVector *)input;
	case RZIL_OP_ARG_VAL:
		*type = RZIL_OP_ARG_BITV;
		return val_to_bitv(input);
	case RZIL_OP_ARG_EFF:
	case RZIL_OP_ARG_MEM:
	default:
		RZ_LOG_ERROR("RzIL: unknown RzILOpArgType bitvector type\n");
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
RZ_API RZ_OWN RzILBool *rz_il_evaluate_bool(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
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
		RZ_LOG_ERROR("RzIL: unknown RzILOpArgType bool type\n");
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
RZ_API RZ_OWN RzILVal *rz_il_evaluate_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	void *result = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	// check if type is bitv
	// else, convert to bitv if possible
	// else report error
	switch (t) {
	case RZIL_OP_ARG_BITV:
		*type = RZIL_OP_ARG_VAL;
		return rz_il_value_new_bitv(result);
	case RZIL_OP_ARG_BOOL:
		*type = RZIL_OP_ARG_VAL;
		return rz_il_value_new_bool(result);
	case RZIL_OP_ARG_VAL:
		return result;
	case RZIL_OP_ARG_EFF:
	case RZIL_OP_ARG_MEM:
	default:
		RZ_LOG_ERROR("RzIL: unknown RzILOpArgType value type\n");
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
RZ_API RZ_OWN RzILEffect *rz_il_evaluate_effect(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	void *result = rz_il_parse_op_root(vm, op, type);
	RzILOpArgType t = *type;

	// check if type is bitv
	// else, convert to bitv if possible
	// else report error
	switch (t) {
	case RZIL_OP_ARG_EFF:
		return result;
	case RZIL_OP_ARG_BITV:
		rz_bv_free(result);
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
		RZ_LOG_ERROR("RzIL: unknown RzILEffect type\n");
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
RZ_API RZ_OWN void *rz_il_parse_op_root(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *root, RZ_NONNULL RzILOpArgType *type) {
	rz_return_val_if_fail(vm && root && type, NULL);
	RzILOpHandler handler = vm->op_handler_table[root->code];
	rz_return_val_if_fail(handler, NULL);
	return handler(vm, root, type);
}
