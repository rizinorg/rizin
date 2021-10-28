// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/vm_layer.h>

static void free_label_kv(HtPPKv *kv) {
	free(kv->key);
	RzILEffectLabel *lbl = kv->value;

	if (lbl->type == EFFECT_LABEL_HOOK || lbl->type == EFFECT_LABEL_SYSCALL) {
		lbl->addr = NULL;
	}
	rz_il_bv_free(lbl->addr);
	free(lbl->label_id);
	free(lbl);
}

static void free_opcode_kv(HtPPKv *kv) {
	rz_il_bv_free(kv->key);
	rz_pvector_free(kv->value);
}

static void free_bind_var_val(HtPPKv *kv) {
	free(kv->key);
}

/**
 * initiate an empty VM
 * \param vm RzILVM, pointer to an empty VM
 * \param start_addr ut64, initiation pc address
 * \param addr_size ut32, size of the address in VM
 * \param data_size ut32, size of the minimal data unit in VM
 */
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, ut32 data_size) {
	vm->addr_size = addr_size;
	vm->data_size = data_size;

	vm->vm_global_variable_list = RZ_NEWS0(RzILVar *, RZ_IL_VM_MAX_VAR);
	if (!vm->vm_global_variable_list) {
		RZ_LOG_ERROR("[VM INIT FAILED] : variable\n");
		rz_il_vm_fini(vm);
		return false;
	}

	vm->vm_global_value_set = rz_il_new_bag(RZ_IL_VM_MAX_VAL, (RzILBagFreeFunc)rz_il_value_free);
	if (!vm->vm_global_value_set) {
		RZ_LOG_ERROR("[VM INIT FAILED] : value bag\n");
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

	// Binding Table for Variable and Value
	HtPPOptions bind_options = { 0 };
	bind_options.cmp = (HtPPListComparator)strcmp;
	bind_options.hashfn = (HtPPHashFunction)sdb_hash;
	bind_options.dupkey = (HtPPDupKey)strdup;
	bind_options.dupvalue = NULL;
	bind_options.freefn = (HtPPKvFreeFunc)free_bind_var_val;
	bind_options.elem_size = sizeof(HtPPKv);
	bind_options.calcsizeK = (HtPPCalcSizeK)strlen;
	vm->vm_global_bind_table = ht_pp_new_opt(&bind_options);

	// TODO : More Arguments for vm init to control
	//      1. Minimal unit size in memory
	//      2. Multiple Memory
	//      3. pc length
	vm->mems = (RzILMem **)calloc(RZ_IL_VM_MAX_TEMP, sizeof(RzILMem *));
	if (!vm->mems) {
		RZ_LOG_ERROR("[VM INIT FAILED] : mem\n");
		rz_il_vm_fini(vm);
		return false;
	}
	vm->pc = rz_il_bv_new_from_ut64(addr_size, start_addr);

	// Table for storing the core theory opcodes
	HtPPOptions ops_options = { 0 };
	ops_options.cmp = (HtPPListComparator)rz_il_bv_cmp;
	ops_options.hashfn = (HtPPHashFunction)rz_il_bv_hash;
	ops_options.dupkey = (HtPPDupKey)rz_il_bv_dup;
	ops_options.dupvalue = NULL; // dump key only, since the opcode used in hash map only
	ops_options.freefn = free_opcode_kv;
	ops_options.elem_size = sizeof(HtPPKv);
	vm->ct_opcodes = ht_pp_new_opt(&ops_options);

	// init jump table of labels
	vm->op_handler_table = RZ_NEWS0(RzILOpHandler, RZIL_OP_MAX);
	vm->op_handler_table[RZIL_OP_VAR] = &rz_il_handler_var;
	vm->op_handler_table[RZIL_OP_UNK] = &rz_il_handler_unk;
	vm->op_handler_table[RZIL_OP_ITE] = &rz_il_handler_ite;

	vm->op_handler_table[RZIL_OP_B0] = &rz_il_handler_b0;
	vm->op_handler_table[RZIL_OP_B1] = &rz_il_handler_b1;
	vm->op_handler_table[RZIL_OP_INV] = &rz_il_handler_inv;
	vm->op_handler_table[RZIL_OP_AND_] = &rz_il_handler_and_;
	vm->op_handler_table[RZIL_OP_OR_] = &rz_il_handler_or_;

	vm->op_handler_table[RZIL_OP_INT] = &rz_il_handler_int;
	vm->op_handler_table[RZIL_OP_MSB] = &rz_il_handler_msb;
	vm->op_handler_table[RZIL_OP_LSB] = &rz_il_handler_lsb;

	vm->op_handler_table[RZIL_OP_NEG] = &rz_il_handler_neg;
	vm->op_handler_table[RZIL_OP_NOT] = &rz_il_handler_not;
	vm->op_handler_table[RZIL_OP_ADD] = &rz_il_handler_add;
	vm->op_handler_table[RZIL_OP_SUB] = &rz_il_handler_sub;
	vm->op_handler_table[RZIL_OP_MUL] = &rz_il_handler_mul;
	vm->op_handler_table[RZIL_OP_DIV] = &rz_il_handler_div;
	vm->op_handler_table[RZIL_OP_MOD] = &rz_il_handler_mod;
	vm->op_handler_table[RZIL_OP_SDIV] = &rz_il_handler_sdiv;
	vm->op_handler_table[RZIL_OP_SMOD] = &rz_il_handler_smod;
	vm->op_handler_table[RZIL_OP_LOGAND] = &rz_il_handler_logical_and;
	vm->op_handler_table[RZIL_OP_LOGOR] = &rz_il_handler_logical_or;
	vm->op_handler_table[RZIL_OP_LOGXOR] = &rz_il_handler_logical_xor;
	vm->op_handler_table[RZIL_OP_SHIFTR] = &rz_il_handler_shiftr;
	vm->op_handler_table[RZIL_OP_SHIFTL] = &rz_il_handler_shiftl;

	vm->op_handler_table[RZIL_OP_SLE] = &rz_il_handler_unimplemented; // &rz_il_handler_sle;
	vm->op_handler_table[RZIL_OP_ULE] = &rz_il_handler_unimplemented; // &rz_il_handler_ule;
	vm->op_handler_table[RZIL_OP_CAST] = &rz_il_handler_cast;
	vm->op_handler_table[RZIL_OP_CONCAT] = &rz_il_handler_unimplemented; // &rz_il_handler_concat;
	vm->op_handler_table[RZIL_OP_APPEND] = &rz_il_handler_unimplemented; // &rz_il_handler_append;

	vm->op_handler_table[RZIL_OP_LOAD] = &rz_il_handler_load;
	vm->op_handler_table[RZIL_OP_STORE] = &rz_il_handler_store;

	vm->op_handler_table[RZIL_OP_PERFORM] = &rz_il_handler_perform;
	vm->op_handler_table[RZIL_OP_SET] = &rz_il_handler_set;
	vm->op_handler_table[RZIL_OP_JMP] = &rz_il_handler_unimplemented; // &rz_il_handler_jmp;
	vm->op_handler_table[RZIL_OP_GOTO] = &rz_il_handler_goto;
	vm->op_handler_table[RZIL_OP_SEQ] = &rz_il_handler_seq;
	vm->op_handler_table[RZIL_OP_BLK] = &rz_il_handler_unimplemented; // &rz_il_handler_blk;
	vm->op_handler_table[RZIL_OP_REPEAT] = &rz_il_handler_unimplemented; // &rz_il_handler_repeat;
	vm->op_handler_table[RZIL_OP_BRANCH] = &rz_il_handler_branch;
	vm->op_handler_table[RZIL_OP_INVALID] = &rz_il_handler_unimplemented; // &rz_il_handler_invalid;

	vm->var_count = 0;
	vm->val_count = 0;
	vm->mem_count = 0;
	return true;
}

/**
 * Close and clean vm
 * \param vm RzILVM* pointer to VM
 */
RZ_API void rz_il_vm_fini(RzILVM *vm) {
	RzILVar *var;

	if (vm->vm_global_value_set) {
		rz_il_free_bag(vm->vm_global_value_set);
	}

	if (vm->vm_global_variable_list) {
		for (ut32 i = 0; i < RZ_IL_VM_MAX_VAR; ++i) {
			if (vm->vm_global_variable_list[i] != NULL) {
				var = vm->vm_global_variable_list[i];
				rz_il_free_variable(var);
				vm->vm_global_variable_list[i] = NULL;
			}
		}
		free(vm->vm_global_variable_list);
	}

	if (vm->ct_opcodes) {
		ht_pp_free(vm->ct_opcodes);
	}

	if (vm->mems) {
		for (ut32 i = 0; i < vm->mem_count; ++i) {
			rz_il_mem_free(vm->mems[i]);
		}
		free(vm->mems);
	}

	if (vm->vm_global_bind_table != NULL) {
		ht_pp_free(vm->vm_global_bind_table);
	}

	if (vm->vm_global_label_table != NULL) {
		ht_pp_free(vm->vm_global_label_table);
	}

	if (vm->op_handler_table != NULL) {
		free(vm->op_handler_table);
	}
	rz_il_bv_free(vm->pc);
}

/**
 * Create a new empty VM
 * \param vm RzILVM, pointer to an empty VM
 * \param start_addr ut64, initiation pc address
 * \param addr_size ut32, size of the address in VM
 * \param data_size ut32, size of the minimal data unit in VM
 */
RZ_API RzILVM *rz_il_vm_new(ut64 start_addr, ut32 addr_size, ut32 data_size) {
	RzILVM *vm = RZ_NEW0(RzILVM);
	if (!vm) {
		return NULL;
	}
	rz_il_vm_init(vm, start_addr, addr_size, data_size);
	return vm;
}

/**
 * Close, clean and free vm
 * \param vm RzILVM* pointer to VM
 */
RZ_API void rz_il_vm_free(RzILVM *vm) {
	rz_il_vm_fini(vm);
	free(vm);
}

/**
 * Convert to bitvector from ut64
 * similar API in librz/il/definition/bitvector.h
 * \param addr ut64, an address
 * \return RzILBitVector, 64-bit bitvector
 */
RZ_API RzILBitVector *rz_il_ut64_addr_to_bv(ut64 addr) {
	return rz_il_bv_new_from_ut64(64, addr);
}

/**
 * Convert to ut64 from bitvector
 * similar API in librz/il/definition/bitvector.h
 * \param addr RzILBitVector, a bitvector address
 * \return ut64, the value of bitvector
 */
RZ_API ut64 rz_il_bv_addr_to_ut64(RzILBitVector *addr) {
	return rz_il_bv_to_ut64(addr);
}

/**
 * the same as rz_il_bv_free, free a bitvector address
 * \param addr RzILBitVector, a bitvector to free
 */
RZ_API void rz_il_free_bv_addr(RzILBitVector *addr) {
	rz_il_bv_free(addr);
}

/**
 * Add a memory in VM. We design this to support multiple memory in the future
 * \param vm RzILVM, pointer to VM
 * \param min_unit_size ut32, size of minimal unit of the vm
 * \return Mem memory, return a pointer to the newly created memory
 */
RZ_API RzILMem *rz_il_vm_add_mem(RzILVM *vm, ut32 min_unit_size) {
	RzILMem *mem = rz_il_mem_new(min_unit_size);
	vm->mems[vm->mem_count] = mem;
	vm->mem_count += 1;
	return mem;
}

RZ_API char *rz_il_op2str(RzILOPCode opcode) {
	char *ctops[64] = {
		"VAR",
		"UNK",
		"ITE",
		"B0",
		"B1",
		"INV",
		"AND_",
		"OR_",
		"INT",
		"MSB",
		"LSB",
		"NEG",
		"NOT",
		"ADD",
		"SUB",
		"MUL",
		"DIV",
		"SDIV",
		"MOD",
		"SMOD",
		"LOGAND",
		"LOGOR",
		"LOGXOR",
		"SHIFTR",
		"SHIFTL",
		"SLE",
		"ULE",
		"CAST",
		"CONCAT",
		"APPEND",
		"LOAD",
		"STORE",
		"PERFORM",
		"SET",
		"JMP",
		"GOTO",
		"SEQ",
		"BLK",
		"REPEAT",
		"BRANCH",
		"INVALID",
	};
	return ctops[opcode];
}

/**
 * Load data from memory by given key
 * \param vm RzILVM, pointer to VM
 * \param mem_index ut32, index to choose a memory
 * \param key RzILBitVector, aka address, a key to load data from memory
 * \return val Bitvector, data at the address, has `vm->min_unit_size` length
 */
RZ_API RzILBitVector *rz_il_vm_mem_load(RzILVM *vm, ut32 mem_index, RzILBitVector *key) {
	RzILMem *m;

	if (vm && vm->mems) {
		if (mem_index >= vm->mem_count || mem_index < 0) {
			return NULL;
		}
		m = vm->mems[mem_index];
		return rz_il_mem_load(m, key);
	}
	return NULL;
}

/**
 * Store data to memory by key, will create a key-value pair
 * or update the key-value pair if key existed.
 * \param vm RzILVM* pointer to VM
 * \param mem_index ut32, index to choose a memory
 * \param key RzILBitVector, aka address, a key to load data from memory
 * \return val Bitvector, data at the address, must have `vm->min_unit_size` length
 * \return mem Mem, the memory you store data to
 */
RZ_API RzILMem *rz_il_vm_mem_store(RzILVM *vm, ut32 mem_index, RzILBitVector *key, RzILBitVector *value) {
	RzILMem *m;

	if (vm && vm->mems) {
		if (mem_index >= vm->mem_count || mem_index < 0) {
			return NULL;
		}
		m = vm->mems[mem_index];
		return rz_il_mem_store(m, key, value);
	}
	return NULL;
}

/**
 * Step execute a single RZIL root
 * @param vm, RzILVM, pointer to the VM
 * @param root, RzILOp*, the root of an opcode tree
 */
RZ_API void rz_il_vm_step(RzILVM *vm, RzILOp *root) {
	RzILOpArgType type = RZIL_OP_ARG_INIT;
	rz_il_parse_op_root(vm, root, &type);
}

/**
 * Execute the opcodes uplifted from raw instructions.A list may contain multiple opcode trees
 * \param vm pointer to VM
 * \param op_list, a list of op roots.
 * \param op_size, how much the pc value has to increate of.
 */
RZ_API void rz_il_vm_list_step(RzILVM *vm, RzPVector *op_list, ut32 op_size) {
	void **iter;
	rz_pvector_foreach (op_list, iter) {
		RzILOp *root = *iter;
		rz_il_vm_step(vm, root);
	}

	RzILBitVector *step = rz_il_bv_new_from_ut32(vm->pc->len, op_size);
	RzILBitVector *next_pc = rz_il_bv_add(vm->pc, step);
	rz_il_bv_free(vm->pc);
	rz_il_bv_free(step);
	vm->pc = next_pc;
}
