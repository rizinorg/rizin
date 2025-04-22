// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * RzIL Virtual Machine Setup and Management
 * For the actual evaluation (emulation), see il_vm_eval.c
 */

#include <rz_il/rz_il_vm.h>

extern RZ_IPI RzILOpPureHandler rz_il_op_handler_pure_table_default[RZ_IL_OP_PURE_MAX];
extern RZ_IPI RzILOpEffectHandler rz_il_op_handler_effect_table_default[RZ_IL_OP_EFFECT_MAX];

/**
 * initiate an empty VM
 * \param vm RzILVM, pointer to an empty VM
 * \param start_addr ut64, initiation pc address
 * \param addr_size  ut32, size of the address in VM
 */
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, bool big_endian) {
	rz_return_val_if_fail(vm, false);

	if (!rz_il_var_set_init(&vm->global_vars)) {
		rz_il_vm_fini(vm);
		return false;
	}
	if (!rz_il_var_set_init(&vm->local_vars)) {
		rz_il_vm_fini(vm);
		return false;
	}
	if (!rz_il_var_set_init(&vm->local_pure_vars)) {
		rz_il_vm_fini(vm);
		return false;
	}
	rz_pvector_init(&vm->vm_memory, (RzPVectorFree)rz_il_mem_free);

	vm->vm_global_label_table = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_il_effect_label_free);
	if (!vm->vm_global_label_table) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM label hashmap\n");
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
	vm->op_handler_pure_table = RZ_NEWS0(RzILOpPureHandler, RZ_IL_OP_PURE_MAX);
	memcpy(vm->op_handler_pure_table, rz_il_op_handler_pure_table_default, sizeof(RzILOpPureHandler) * RZ_IL_OP_PURE_MAX);
	vm->op_handler_effect_table = RZ_NEWS0(RzILOpEffectHandler, RZ_IL_OP_EFFECT_MAX);
	memcpy(vm->op_handler_effect_table, rz_il_op_handler_effect_table_default, sizeof(RzILOpEffectHandler) * RZ_IL_OP_EFFECT_MAX);

	vm->lab_count = 0;
	vm->val_count = 0;
	vm->addr_size = addr_size;
	vm->big_endian = big_endian;

	vm->events = rz_pvector_new((RzPVectorFree)rz_il_event_free);
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
	rz_il_var_set_fini(&vm->global_vars);
	rz_il_var_set_fini(&vm->local_vars);
	rz_il_var_set_fini(&vm->local_pure_vars);

	rz_pvector_fini(&vm->vm_memory);

	ht_sp_free(vm->vm_global_label_table);
	vm->vm_global_label_table = NULL;

	free(vm->op_handler_pure_table);
	vm->op_handler_pure_table = NULL;
	free(vm->op_handler_effect_table);
	vm->op_handler_effect_table = NULL;

	rz_bv_free(vm->pc);
	vm->pc = NULL;

	rz_pvector_free(vm->events);
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
 * Get the number of bits of the program counter bitvector
 */
RZ_API ut32 rz_il_vm_get_pc_len(RzILVM *vm) {
	return rz_bv_len(vm->pc);
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
 * Create a new global variable of the given sort and assign it to all-zero/false
 */
RZ_API RZ_BORROW RzILVar *rz_il_vm_create_global_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILSortPure sort) {
	rz_return_val_if_fail(vm && name, NULL);
	RzILVar *var = rz_il_var_set_create_var(&vm->global_vars, name, sort);
	if (!var) {
		return NULL;
	}
	RzILVal *val = rz_il_value_new_zero_of(sort);
	if (!val) {
		return NULL;
	}
	rz_il_var_set_bind(&vm->global_vars, name, val);
	return var;
}

/**
 * Set the value of a global variable to the given value.
 * The variable must already exist.
 */
RZ_API void rz_il_vm_set_global_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_OWN RzILVal *val) {
	rz_return_if_fail(vm && name && val);
	rz_il_var_set_bind(&vm->global_vars, name, val);
}

/**
 * Set the value of a local variable to the given value.
 * The variable is created with the sort of \p val if it does not already exist.
 */
RZ_API void rz_il_vm_set_local_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_OWN RzILVal *val) {
	rz_return_if_fail(vm && name && val);
	rz_il_var_set_create_var(&vm->local_vars, name, rz_il_value_get_sort(val));
	rz_il_var_set_bind(&vm->local_vars, name, val);
}

/**
 * \brief Create and assign a new local let binding.
 *
 * This is meant to be called right before evaluating the body of a let expression. Inside the body, \p name will then be bound to \p val.
 * Because there might already exist an outer binding of the same name shadowing this one, the previous value is returned.
 * After evaluating the body, call rz_il_vm_pop_local_pure_var(), passing this value.
 */
RZ_API RzILLocalPurePrev rz_il_vm_push_local_pure_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVal *val) {
	rz_return_val_if_fail(vm && name && val, NULL);
	RzILVal *r = rz_il_var_set_remove_var(&vm->local_pure_vars, name);
	rz_il_var_set_create_var(&vm->local_pure_vars, name, rz_il_value_get_sort(val));
	rz_il_var_set_bind(&vm->local_pure_vars, name, val);
	return r;
}

/**
 * \brief Remove a local let binding and restore the state for the outer context.
 * \param prev pass here the return value of rz_il_vm_push_local_pure_var()
 */
RZ_API void rz_il_vm_pop_local_pure_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILLocalPurePrev prev) {
	rz_return_if_fail(vm && name);
	RzILVal *r = rz_il_var_set_remove_var(&vm->local_pure_vars, name);
	rz_warn_if_fail(r); // the var should always be bound when calling this function
	rz_il_value_free(r);
	if (prev) {
		rz_il_var_set_create_var(&vm->local_pure_vars, name, rz_il_value_get_sort(prev));
		rz_il_var_set_bind(&vm->local_pure_vars, name, prev);
	}
}

static RzILVarSet *var_set_of_kind(RzILVM *vm, RzILVarKind kind) {
	switch (kind) {
	case RZ_IL_VAR_KIND_GLOBAL:
		return &vm->global_vars;
	case RZ_IL_VAR_KIND_LOCAL:
		return &vm->local_vars;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		return &vm->local_pure_vars;
	}
	rz_warn_if_reached();
	return NULL;
}

RZ_API RZ_BORROW RzILVar *rz_il_vm_get_var(RZ_NONNULL RzILVM *vm, RzILVarKind kind, const char *name) {
	rz_return_val_if_fail(vm && name, NULL);
	return rz_il_var_set_get(var_set_of_kind(vm, kind), name);
}

RZ_API RZ_OWN RzPVector /*<RzILVar *>*/ *rz_il_vm_get_all_vars(RZ_NONNULL RzILVM *vm, RzILVarKind kind) {
	rz_return_val_if_fail(vm, NULL);
	return rz_il_var_set_get_all(var_set_of_kind(vm, kind));
}

/**
 * Get the current value of the variable identified by its \p name and \p kind.
 */
RZ_API RZ_BORROW RzILVal *rz_il_vm_get_var_value(RZ_NONNULL RzILVM *vm, RzILVarKind kind, const char *name) {
	rz_return_val_if_fail(vm && name, NULL);
	return rz_il_var_set_get_value(var_set_of_kind(vm, kind), name);
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
	RzILEffectLabel *label = ht_sp_find(vm->vm_global_label_table, lbl_name, &found);
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
	return ht_sp_find(vm->vm_global_label_table, lbl_name, NULL);
}

RZ_API void rz_il_vm_add_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILEffectLabel *label) {
	rz_return_if_fail(vm && label);
	ht_sp_update(vm->vm_global_label_table, label->label_id, label);
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
	RzILEffectLabel *lbl = rz_il_effect_label_new(name, EFFECT_LABEL_ADDR);
	lbl->addr = rz_bv_dup(addr);
	rz_il_vm_add_label(vm, lbl);
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
	RzILEffectLabel *lbl = rz_il_effect_label_new(name, EFFECT_LABEL_ADDR);
	lbl->addr = NULL;
	rz_il_vm_add_label(vm, lbl);
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
	RzILEffectLabel *lbl = ht_sp_find(vm->vm_global_label_table, name, NULL);
	if (lbl->addr) {
		rz_bv_free(lbl->addr);
	}
	lbl->addr = rz_bv_dup(addr);
	return lbl;
}
