// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/vm_layer.h>

// Handler for core theory opcode
void *rz_il_handler_ite(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_var(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_unk(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

void *rz_il_handler_bitv(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_msb(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_lsb(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_ule(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_sle(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_neg(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_logical_not(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_add(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_sub(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_mul(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_div(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_sdiv(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_mod(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_smod(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_shiftl(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_shiftr(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_logical_and(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_logical_or(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_logical_xor(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

void *rz_il_handler_bool_false(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_bool_true(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_bool_and(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_bool_or(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_bool_xor(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_bool_inv(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

void *rz_il_handler_cast(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_append(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

void *rz_il_handler_nop(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_set(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_let(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_jmp(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_goto(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_seq(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_branch(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

void *rz_il_handler_load(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
void *rz_il_handler_store(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

// TODO: remove me when all the handlers are implemented
void *rz_il_handler_unimplemented(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

static RzILOpHandler op_handler_table_default[RZIL_OP_MAX] = {
	rz_il_handler_var, /* RZIL_OP_VAR */
	rz_il_handler_unk, /* RZIL_OP_UNK */
	rz_il_handler_ite, /* RZIL_OP_ITE */
	rz_il_handler_bool_false, /* RZIL_OP_B0 */
	rz_il_handler_bool_true, /* RZIL_OP_B1 */
	rz_il_handler_bool_inv, /* RZIL_OP_INV */
	rz_il_handler_bool_and, /* RZIL_OP_AND */
	rz_il_handler_bool_or, /* RZIL_OP_OR */
	rz_il_handler_bool_xor, /* RZIL_OP_XOR */
	rz_il_handler_bitv, /* RZIL_OP_BITV */
	rz_il_handler_msb, /* RZIL_OP_MSB */
	rz_il_handler_lsb, /* RZIL_OP_LSB */
	rz_il_handler_neg, /* RZIL_OP_NEG */
	rz_il_handler_logical_not, /* RZIL_OP_LOGNOT */
	rz_il_handler_add, /* RZIL_OP_ADD */
	rz_il_handler_sub, /* RZIL_OP_SUB */
	rz_il_handler_mul, /* RZIL_OP_MUL */
	rz_il_handler_div, /* RZIL_OP_DIV */
	rz_il_handler_mod, /* RZIL_OP_MOD */
	rz_il_handler_sdiv, /* RZIL_OP_SDIV */
	rz_il_handler_smod, /* RZIL_OP_SMOD */
	rz_il_handler_logical_and, /* RZIL_OP_LOGAND */
	rz_il_handler_logical_or, /* RZIL_OP_LOGOR */
	rz_il_handler_logical_xor, /* RZIL_OP_LOGXOR */
	rz_il_handler_shiftr, /* RZIL_OP_SHIFTR */
	rz_il_handler_shiftl, /* RZIL_OP_SHIFTL */
	rz_il_handler_sle, /* RZIL_OP_SLE */
	rz_il_handler_ule, /* RZIL_OP_ULE */
	rz_il_handler_cast, /* RZIL_OP_CAST */
	rz_il_handler_unimplemented, // &rz_il_handler_concat, /* RZIL_OP_CONCAT */
	rz_il_handler_append, /* RZIL_OP_APPEND */
	rz_il_handler_load, /* RZIL_OP_LOAD */
	rz_il_handler_store, /* RZIL_OP_STORE */
	rz_il_handler_nop, /* RZIL_OP_NOP */
	rz_il_handler_set, /* RZIL_OP_SET */
	rz_il_handler_let, /* RZIL_OP_LET */
	rz_il_handler_jmp, /* RZIL_OP_JMP */
	rz_il_handler_goto, /* RZIL_OP_GOTO */
	rz_il_handler_seq, /* RZIL_OP_SEQ */
	rz_il_handler_unimplemented, // &rz_il_handler_blk, /* RZIL_OP_BLK */
	rz_il_handler_unimplemented, // &rz_il_handler_repeat, /* RZIL_OP_REPEAT */
	rz_il_handler_branch, /* RZIL_OP_BRANCH */
	rz_il_handler_unimplemented, // &rz_il_handler_invalid, /* RZIL_OP_INVALID */
};

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

static void free_opcode_kv(HtPPKv *kv) {
	rz_bv_free(kv->key);
	rz_pvector_free(kv->value);
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
 * \param ro_memory  RzBuffer, read only memory to use for reads in the VM
 */
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, RzBuffer *ro_memory, bool big_endian) {
	rz_return_val_if_fail(vm && ro_memory, false);

	rz_pvector_init(&vm->vm_global_variable_list, (RzPVectorFree)rz_il_variable_free);
	rz_pvector_init(&vm->vm_local_variable_list, (RzPVectorFree)rz_il_variable_free);

	vm->vm_memory = rz_buf_new_sparse_overlay(ro_memory, RZ_BUF_SPARSE_WRITE_MODE_SPARSE);
	if (!vm->vm_memory) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM memory buffer\n");
		rz_il_vm_fini(vm);
		return false;
	}

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

	// Table for storing the core theory opcodes
	HtPPOptions ops_options = { 0 };
	ops_options.cmp = (HtPPListComparator)rz_bv_cmp;
	ops_options.hashfn = (HtPPHashFunction)rz_bv_hash;
	ops_options.dupkey = (HtPPDupKey)rz_bv_dup;
	ops_options.dupvalue = NULL; // dump key only, since the opcode used in hash map only
	ops_options.freefn = free_opcode_kv;
	ops_options.elem_size = sizeof(HtPPKv);
	vm->ct_opcodes = ht_pp_new_opt(&ops_options);
	if (!vm->ct_opcodes) {
		RZ_LOG_ERROR("RzIL: cannot allocate VM core theory op codes\n");
		rz_il_vm_fini(vm);
		return false;
	}

	// init jump table of labels
	vm->op_handler_table = RZ_NEWS0(RzILOpHandler, RZIL_OP_MAX);
	memcpy(vm->op_handler_table, op_handler_table_default, sizeof(RzILOpHandler) * RZIL_OP_MAX);

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
	rz_pvector_fini(&vm->vm_local_variable_list);

	rz_buf_free(vm->vm_memory);
	vm->vm_memory = NULL;

	ht_pp_free(vm->ct_opcodes);
	vm->ct_opcodes = NULL;

	ht_pp_free(vm->vm_global_bind_table);
	vm->vm_global_bind_table = NULL;

	ht_pp_free(vm->vm_local_bind_table);
	vm->vm_local_bind_table = NULL;

	ht_pp_free(vm->vm_global_label_table);
	vm->vm_global_label_table = NULL;

	free(vm->op_handler_table);
	vm->op_handler_table = NULL;

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
 * \param ro_memory  RzBuffer, read only memory to use for reads in the VM
 */
RZ_API RzILVM *rz_il_vm_new(ut64 start_addr, ut32 addr_size, RzBuffer *ro_memory, bool big_endian) {
	rz_return_val_if_fail(ro_memory, NULL);
	RzILVM *vm = RZ_NEW0(RzILVM);
	if (!vm) {
		return NULL;
	}
	rz_il_vm_init(vm, start_addr, addr_size, ro_memory, big_endian);
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

static RzBitVector *read_n_bits(RzILVM *vm, ut32 n_bits, RzBitVector *key) {
	RzBitVector *value = rz_bv_new_zero(n_bits);
	if (!value) {
		rz_warn_if_reached();
		return NULL;
	}

	ut64 address = rz_bv_to_ut64(key);
	ut32 n_bytes = rz_bv_len_bytes(value);

	ut8 *data = calloc(n_bytes, 1);
	if (!data) {
		rz_warn_if_reached();
		return value;
	}

	// we ignore bad reads.
	rz_buf_read_at(vm->vm_memory, address, data, n_bytes);
	if (vm->big_endian) {
		value = rz_bv_new_from_bytes_be(data, 0, n_bits);
	} else {
		value = rz_bv_new_from_bytes_le(data, 0, n_bits);
	}
	free(data);
	return value;
}

static void write_n_bits(RzILVM *vm, RzBitVector *value, RzBitVector *key) {
	ut64 address = rz_bv_to_ut64(key);
	ut32 n_bytes = rz_bv_len_bytes(value);

	ut8 *data = calloc(n_bytes, 1);
	if (!data) {
		rz_warn_if_reached();
		return;
	}

	if (vm->big_endian) {
		rz_bv_set_to_bytes_be(value, data);
	} else {
		rz_bv_set_to_bytes_le(value, data);
	}

	// we ignore bad writes.
	rz_buf_write_at(vm->vm_memory, address, data, n_bytes);
	free(data);
}

/**
 * Load data from memory by given key and generates an RZIL_EVENT_MEM_READ event
 * \param  vm     RzILVM, pointer to VM
 * \param  n_bits ut32, how many bits to read from memory
 * \param  key    RzBitVector, aka address, a key to load data from memory
 * \return val    Bitvector, data at the address, has `vm->min_unit_size` length
 */
RZ_API RzBitVector *rz_il_vm_mem_load(RzILVM *vm, ut32 n_bits, RzBitVector *key) {
	rz_return_val_if_fail(vm && key && n_bits > 0, NULL);
	RzBitVector *value = read_n_bits(vm, n_bits, key);
	rz_il_vm_event_add(vm, rz_il_event_mem_read_new(key, value));
	return value;
}

/**
 * Store data to memory by key, will create a key-value pair
 * or update the key-value pair if key existed; also generates
 * an RZIL_EVENT_MEM_WRITE event
 * \param  vm    RzILVM* pointer to VM
 * \param  key   RzBitVector, aka address, a key to store data from memory
 * \param  value RzBitVector, aka value to store in memory
 */
RZ_API void rz_il_vm_mem_store(RzILVM *vm, RzBitVector *key, RzBitVector *value) {
	rz_return_if_fail(vm && key && value);
	RzBitVector *old_value = read_n_bits(vm, value->len, key);

	write_n_bits(vm, value, key);
	rz_il_vm_event_add(vm, rz_il_event_mem_write_new(key, old_value, value));
	rz_bv_free(old_value);
}

/**
 * Step execute a single RZIL root
 * \param vm, RzILVM, pointer to the VM
 * \param root, RzILOp*, the root of an opcode tree
 */
RZ_API void rz_il_vm_step(RzILVM *vm, RzILOp *root) {
	RzILOpArgType type = RZIL_OP_ARG_INIT;
	rz_il_parse_op_root(vm, root, &type);
}

/**
 * Adds to the VM a new event into the VM event list
 * \param vm, RzILVM, pointer to the VM
 * \param evt, RzILEvent, pointer to the event
 */
RZ_API void rz_il_vm_event_add(RzILVM *vm, RzILEvent *evt) {
	rz_return_if_fail(vm && vm->events && evt);
	if (!rz_list_append(vm->events, evt)) {
		rz_warn_if_reached();
		rz_il_event_free(evt);
	}
}

/**
 * Execute the opcodes uplifted from raw instructions.A list may contain multiple opcode trees
 * \param vm pointer to VM
 * \param op_list, a list of op roots.
 * \param op_size, how much the pc value has to increate of.
 */
RZ_API void rz_il_vm_list_step(RzILVM *vm, RzPVector *op_list, ut32 op_size) {
	rz_return_if_fail(vm && op_list);

	rz_list_purge(vm->events);

	void **iter;
	rz_pvector_foreach (op_list, iter) {
		RzILOp *root = *iter;
		rz_il_vm_step(vm, root);
	}

	RzBitVector *step = rz_bv_new_from_ut64(vm->pc->len, op_size);
	RzBitVector *next_pc = rz_bv_add(vm->pc, step, NULL);
	rz_il_vm_event_add(vm, rz_il_event_pc_write_new(vm->pc, next_pc));
	rz_bv_free(vm->pc);
	rz_bv_free(step);
	vm->pc = next_pc;

	// remove any local defined variable
	void **it;
	rz_pvector_foreach (&vm->vm_local_variable_list, it) {
		RzILVar *var = *it;
		rz_il_hash_cancel_local_binding(vm, var);
	}
	rz_pvector_clear(&vm->vm_local_variable_list);
}
