// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * RzIL Virtual Machine Setup and Management
 * For the actual evaluation (emulation), see il_vm_eval.c
 */

#include <rz_il/rz_il_vm.h>

extern RZ_IPI RzILOpPureHandler rz_il_op_handler_pure_table_default[RZIL_OP_PURE_MAX];
extern RZ_IPI RzILOpEffectHandler rz_il_op_handler_effect_table_default[RZIL_OP_EFFECT_MAX];

static void free_label_kv(HtPPKv *kv) {
	free(kv->key);
	RzILEffectLabel *lbl = kv->value;

	if (lbl->type == EFFECT_LABEL_HOOK || lbl->type == EFFECT_LABEL_SYSCALL) {
		lbl->addr = NULL;
	}
	rz_bv_free(lbl->addr);
	free(lbl->label_id);
	free(lbl);
}

static void free_bind_var(HtPPKv *kv) {
	free(kv->key);
}

static void free_bind_var_val(HtPPKv *kv) {
	free(kv->key);
	rz_il_value_free(kv->value);
}

/**
 * initiate an empty VM
 * \param vm RzILVM, pointer to an empty VM
 * \param start_addr ut64, initiation pc address
 * \param addr_size  ut32, size of the address in VM
 */
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, bool big_endian) {
	rz_return_val_if_fail(vm, false);

	rz_pvector_init(&vm->vm_global_variable_list, (RzPVectorFree)rz_il_variable_free);
	rz_pvector_init(&vm->vm_local_variable_list, (RzPVectorFree)rz_il_variable_free);
	rz_pvector_init(&vm->vm_memory, (RzPVectorFree)rz_il_mem_free);

	vm->vm_global_value_set = rz_il_new_bag(RZ_IL_VM_MAX_VAL, (RzILBagFreeFunc)rz_il_value_free);
	if (!vm->vm_global_value_set) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM value bag\n");
		rz_il_vm_fini(vm);
		return false;
	}

	// Key : string
	// Val : RzILEffectLabel
	// Do not dump it since its single signed here, and will be free in `close`
	HtPPOptions lbl_options = { 0 };
	lbl_options.cmp = (HtPPListComparator)strcmp;
	lbl_options.hashfn = (HtPPHashFunction)sdb_hash;
	lbl_options.dupkey = (HtPPDupKey)strdup;
	lbl_options.dupvalue = NULL;
	lbl_options.freefn = (HtPPKvFreeFunc)free_label_kv;
	lbl_options.elem_size = sizeof(HtPPKv);
	lbl_options.calcsizeK = (HtPPCalcSizeK)strlen;
	vm->vm_global_label_table = ht_pp_new_opt(&lbl_options);
	if (!vm->vm_global_label_table) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM label hashmap\n");
		rz_il_vm_fini(vm);
		return false;
	}

	// Binding Table for Variable and Value
	HtPPOptions bind_options = { 0 };
	bind_options.cmp = (HtPPListComparator)strcmp;
	bind_options.hashfn = (HtPPHashFunction)sdb_hash;
	bind_options.dupkey = (HtPPDupKey)strdup;
	bind_options.dupvalue = NULL;
	bind_options.freefn = (HtPPKvFreeFunc)free_bind_var;
	bind_options.elem_size = sizeof(HtPPKv);
	bind_options.calcsizeK = (HtPPCalcSizeK)strlen;
	vm->vm_global_bind_table = ht_pp_new_opt(&bind_options);
	if (!vm->vm_global_bind_table) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM global hashmap\n");
		rz_il_vm_fini(vm);
		return false;
	}

	bind_options.freefn = (HtPPKvFreeFunc)free_bind_var_val;
	vm->vm_local_bind_table = ht_pp_new_opt(&bind_options);
	if (!vm->vm_local_bind_table) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM local hashmap\n");
		rz_il_vm_fini(vm);
		return false;
	}

	vm->pc = rz_bv_new_from_ut64(addr_size, start_addr);
	if (!vm->pc) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM program counter\n");
		rz_il_vm_fini(vm);
		return false;
	}

	// init jump table of labels
	vm->op_handler_pure_table = RZ_NEWS0(RzILOpPureHandler, RZIL_OP_PURE_MAX);
	memcpy(vm->op_handler_pure_table, rz_il_op_handler_pure_table_default, sizeof(RzILOpPureHandler) * RZIL_OP_PURE_MAX);
	vm->op_handler_effect_table = RZ_NEWS0(RzILOpEffectHandler, RZIL_OP_EFFECT_MAX);
	memcpy(vm->op_handler_effect_table, rz_il_op_handler_effect_table_default, sizeof(RzILOpEffectHandler) * RZIL_OP_EFFECT_MAX);

	vm->lab_count = 0;
	vm->val_count = 0;
	vm->addr_size = addr_size;
	vm->big_endian = big_endian;

	vm->events = rz_list_newf((RzListFree)rz_il_event_free);
	if (!vm->events) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM event list\n");
		rz_il_vm_fini(vm);
		return false;
	}
	return true;
}

/**
 * Close and clean vm
 * \param vm RzILVM* pointer to VM
 */
RZ_API void rz_il_vm_fini(RzILVM *vm) {
	if (vm->vm_global_value_set) {
		rz_il_free_bag(vm->vm_global_value_set);
		vm->vm_global_value_set = NULL;
	}
	rz_pvector_fini(&vm->vm_global_variable_list);
	rz_il_reg_binding_free(vm->reg_binding);
	rz_pvector_fini(&vm->vm_local_variable_list);
	rz_pvector_fini(&vm->vm_memory);

	ht_pp_free(vm->vm_global_bind_table);
	vm->vm_global_bind_table = NULL;

	ht_pp_free(vm->vm_local_bind_table);
	vm->vm_local_bind_table = NULL;

	ht_pp_free(vm->vm_global_label_table);
	vm->vm_global_label_table = NULL;

	free(vm->op_handler_pure_table);
	vm->op_handler_pure_table = NULL;
	free(vm->op_handler_effect_table);
	vm->op_handler_effect_table = NULL;

	rz_bv_free(vm->pc);
	vm->pc = NULL;

	rz_list_free(vm->events);
	vm->events = NULL;
}

/**
 * Create a new empty VM
 * \param vm RzILVM, pointer to an empty VM
 * \param start_addr ut64, initiation pc address
 * \param addr_size  ut32, size of the address in VM
 */
RZ_API RzILVM *rz_il_vm_new(ut64 start_addr, ut32 addr_size, bool big_endian) {
	RzILVM *vm = RZ_NEW0(RzILVM);
	if (!vm) {
		return NULL;
	}
	rz_il_vm_init(vm, start_addr, addr_size, big_endian);
	return vm;
}

/**
 * Close, clean and free vm
 * \param vm RzILVM* pointer to VM
 */
RZ_API void rz_il_vm_free(RzILVM *vm) {
	if (!vm) {
		return;
	}
	rz_il_vm_fini(vm);
	free(vm);
}

/**
 * Add a memory to VM at the given index.
 * Ownership of the memory is transferred to the VM.
 */
RZ_API void rz_il_vm_add_mem(RzILVM *vm, RzILMemIndex index, RZ_OWN RzILMem *mem) {
	if (index < rz_pvector_len(&vm->vm_memory)) {
		rz_mem_free(rz_pvector_at(&vm->vm_memory, index));
	}
	rz_pvector_reserve(&vm->vm_memory, index + 1);
	// Fill up with NULLs until the given index
	while (rz_pvector_len(&vm->vm_memory) < index + 1) {
		rz_pvector_push(&vm->vm_memory, NULL);
	}
	rz_pvector_set(&vm->vm_memory, index, mem);
}

RZ_API RzILMem *rz_il_vm_get_mem(RzILVM *vm, RzILMemIndex index) {
	if (index >= rz_pvector_len(&vm->vm_memory)) {
		return NULL;
	}
	return rz_pvector_at(&vm->vm_memory, index);
}

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
