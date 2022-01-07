// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * RzIL Virtual Machine Evaluation (Emulation)
 */

#include <rz_il/rz_il_vm.h>

// Handler for core theory opcodes
void *rz_il_handler_ite(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_var(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_let(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);

void *rz_il_handler_bitv(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_msb(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_lsb(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_is_zero(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_eq(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_ule(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_sle(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_neg(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_logical_not(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_add(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_sub(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_mul(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_div(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_sdiv(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_mod(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_smod(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_shiftl(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_shiftr(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_logical_and(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_logical_or(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_logical_xor(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);

void *rz_il_handler_bool_false(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_bool_true(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_bool_and(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_bool_or(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_bool_xor(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_bool_inv(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);

void *rz_il_handler_cast(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
void *rz_il_handler_append(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);

bool rz_il_handler_nop(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_set(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_jmp(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_goto(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_seq(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_blk(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_repeat(RzILVM *vm, RzILOpEffect *op);
bool rz_il_handler_branch(RzILVM *vm, RzILOpEffect *op);

void *rz_il_handler_load(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
bool rz_il_handler_store(RzILVM *vm, RzILOpEffect *op);
void *rz_il_handler_loadw(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
bool rz_il_handler_storew(RzILVM *vm, RzILOpEffect *op);

// TODO: remove me when all the handlers are implemented
void *rz_il_handler_pure_unimplemented(RzILVM *vm, RzILOpPure *op, RzILTypePure *type);
bool rz_il_handler_effect_unimplemented(RzILVM *vm, RzILOpEffect *op);

RZ_IPI RzILOpPureHandler rz_il_op_handler_pure_table_default[RZ_IL_OP_PURE_MAX] = {
	[RZ_IL_OP_VAR] = rz_il_handler_var,
	[RZ_IL_OP_ITE] = rz_il_handler_ite,
	[RZ_IL_OP_LET] = rz_il_handler_let,
	[RZ_IL_OP_B0] = rz_il_handler_bool_false,
	[RZ_IL_OP_B1] = rz_il_handler_bool_true,
	[RZ_IL_OP_INV] = rz_il_handler_bool_inv,
	[RZ_IL_OP_AND] = rz_il_handler_bool_and,
	[RZ_IL_OP_OR] = rz_il_handler_bool_or,
	[RZ_IL_OP_XOR] = rz_il_handler_bool_xor,
	[RZ_IL_OP_BITV] = rz_il_handler_bitv,
	[RZ_IL_OP_MSB] = rz_il_handler_msb,
	[RZ_IL_OP_LSB] = rz_il_handler_lsb,
	[RZ_IL_OP_IS_ZERO] = rz_il_handler_is_zero,
	[RZ_IL_OP_NEG] = rz_il_handler_neg,
	[RZ_IL_OP_LOGNOT] = rz_il_handler_logical_not,
	[RZ_IL_OP_ADD] = rz_il_handler_add,
	[RZ_IL_OP_SUB] = rz_il_handler_sub,
	[RZ_IL_OP_MUL] = rz_il_handler_mul,
	[RZ_IL_OP_DIV] = rz_il_handler_div,
	[RZ_IL_OP_MOD] = rz_il_handler_mod,
	[RZ_IL_OP_SDIV] = rz_il_handler_sdiv,
	[RZ_IL_OP_SMOD] = rz_il_handler_smod,
	[RZ_IL_OP_LOGAND] = rz_il_handler_logical_and,
	[RZ_IL_OP_LOGOR] = rz_il_handler_logical_or,
	[RZ_IL_OP_LOGXOR] = rz_il_handler_logical_xor,
	[RZ_IL_OP_SHIFTR] = rz_il_handler_shiftr,
	[RZ_IL_OP_SHIFTL] = rz_il_handler_shiftl,
	[RZ_IL_OP_EQ] = rz_il_handler_eq,
	[RZ_IL_OP_SLE] = rz_il_handler_sle,
	[RZ_IL_OP_ULE] = rz_il_handler_ule,
	[RZ_IL_OP_CAST] = rz_il_handler_cast,
	[RZ_IL_OP_CONCAT] = rz_il_handler_pure_unimplemented,
	[RZ_IL_OP_APPEND] = rz_il_handler_append,
	[RZ_IL_OP_LOAD] = rz_il_handler_load,
	[RZ_IL_OP_LOADW] = rz_il_handler_loadw,
};

RZ_IPI RzILOpEffectHandler rz_il_op_handler_effect_table_default[RZ_IL_OP_EFFECT_MAX] = {
	[RZ_IL_OP_STORE] = rz_il_handler_store,
	[RZ_IL_OP_STOREW] = rz_il_handler_storew,
	[RZ_IL_OP_NOP] = rz_il_handler_nop,
	[RZ_IL_OP_SET] = rz_il_handler_set,
	[RZ_IL_OP_JMP] = rz_il_handler_jmp,
	[RZ_IL_OP_GOTO] = rz_il_handler_goto,
	[RZ_IL_OP_SEQ] = rz_il_handler_seq,
	[RZ_IL_OP_BLK] = rz_il_handler_blk,
	[RZ_IL_OP_REPEAT] = rz_il_handler_repeat,
	[RZ_IL_OP_BRANCH] = rz_il_handler_branch,
};

/**
 * Load data from memory by given key and generates an RZ_IL_EVENT_MEM_READ event
 * \param  vm     RzILVM, pointer to VM
 * \param  key    RzBitVector, aka address, a key to load data from memory
 * \return val    Bitvector, data at the address, has `vm->min_unit_size` length
 */
RZ_API RzBitVector *rz_il_vm_mem_load(RzILVM *vm, RzILMemIndex index, RzBitVector *key) {
	rz_return_val_if_fail(vm && key, NULL);
	RzILMem *mem = rz_il_vm_get_mem(vm, index);
	if (!mem) {
		RZ_LOG_ERROR("Non-existent mem %u referenced\n", (unsigned int)index);
		return NULL;
	}
	RzBitVector *value = rz_il_mem_load(mem, key);
	rz_il_vm_event_add(vm, rz_il_event_mem_read_new(key, value));
	return value;
}

/**
 * Store data to memory by key, will create a key-value pair
 * or update the key-value pair if key existed; also generates
 * an RZ_IL_EVENT_MEM_WRITE event
 * \param  vm    RzILVM* pointer to VM
 * \param  key   RzBitVector, aka address, a key to store data from memory
 * \param  value RzBitVector, aka value to store in memory
 */
RZ_API void rz_il_vm_mem_store(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value) {
	rz_return_if_fail(vm && key && value);
	RzILMem *mem = rz_il_vm_get_mem(vm, index);
	if (!mem) {
		RZ_LOG_ERROR("Non-existent mem %u referenced\n", (unsigned int)index);
		return;
	}
	RzBitVector *old_value = rz_il_mem_load(mem, key);
	rz_il_mem_store(mem, key, value);
	rz_il_vm_event_add(vm, rz_il_event_mem_write_new(key, old_value, value));
	rz_bv_free(old_value);
}

/**
 * Load data from memory by given key and generates an RZ_IL_EVENT_MEM_READ event
 * \param  vm     RzILVM, pointer to VM
 * \param  key    RzBitVector, aka address, a key to load data from memory
 * \return val    Bitvector, data at the address, has `vm->min_unit_size` length
 */
RZ_API RzBitVector *rz_il_vm_mem_loadw(RzILVM *vm, RzILMemIndex index, RzBitVector *key, ut32 n_bits) {
	rz_return_val_if_fail(vm && key, NULL);
	RzILMem *mem = rz_il_vm_get_mem(vm, index);
	if (!mem) {
		RZ_LOG_ERROR("Non-existent mem %u referenced\n", (unsigned int)index);
		return NULL;
	}
	RzBitVector *value = rz_il_mem_loadw(mem, key, n_bits, vm->big_endian);
	rz_il_vm_event_add(vm, rz_il_event_mem_read_new(key, value));
	return value;
}

/**
 * Store data to memory by key, will create a key-value pair
 * or update the key-value pair if key existed; also generates
 * an RZ_IL_EVENT_MEM_WRITE event
 * \param  vm    RzILVM* pointer to VM
 * \param  key   RzBitVector, aka address, a key to store data from memory
 * \param  value RzBitVector, aka value to store in memory
 */
RZ_API void rz_il_vm_mem_storew(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value) {
	rz_return_if_fail(vm && key && value);
	RzILMem *mem = rz_il_vm_get_mem(vm, index);
	if (!mem) {
		RZ_LOG_ERROR("Non-existent mem %u referenced\n", (unsigned int)index);
		return;
	}
	RzBitVector *old_value = rz_il_mem_loadw(mem, key, rz_bv_len(value), vm->big_endian);
	rz_il_mem_storew(mem, key, value, vm->big_endian);
	rz_il_vm_event_add(vm, rz_il_event_mem_write_new(key, old_value, value));
	rz_bv_free(old_value);
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
RZ_API bool rz_il_vm_step(RzILVM *vm, RzILOpEffect *op, ut32 op_size) {
	rz_return_val_if_fail(vm && op, false);

	rz_list_purge(vm->events);

	bool succ = rz_il_evaluate_effect(vm, op);

	RzBitVector *step = rz_bv_new_from_ut64(vm->pc->len, op_size);
	RzBitVector *next_pc = rz_bv_add(vm->pc, step, NULL);
	rz_il_vm_event_add(vm, rz_il_event_pc_write_new(vm->pc, next_pc));
	rz_bv_free(vm->pc);
	rz_bv_free(step);
	vm->pc = next_pc;

	// remove any local defined variable (local pure vars are unbound automatically)
	rz_il_var_set_reset(&vm->local_vars);
	return succ;
}

static void *eval_pure(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILTypePure *type) {
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

static const char *pure_type_name(RzILTypePure type) {
	switch (type) {
	case RZ_IL_TYPE_PURE_BITVECTOR:
		return "bitvector";
	case RZ_IL_TYPE_PURE_BOOL:
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
	RzILTypePure type = -1;
	void *res = eval_pure(vm, op, &type);
	if (!res) {
		// propagate error
		return NULL;
	}
	if (type != RZ_IL_TYPE_PURE_BITVECTOR) {
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
	RzILTypePure type = -1;
	void *res = eval_pure(vm, op, &type);
	if (!res) {
		// propagate error
		return NULL;
	}
	if (type != RZ_IL_TYPE_PURE_BOOL) {
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
	RzILTypePure type = -1;
	void *res = eval_pure(vm, op, &type);
	if (!res) {
		// propagate error
		return NULL;
	}
	switch (type) {
	case RZ_IL_TYPE_PURE_BOOL:
		return rz_il_value_new_bool(res);
	case RZ_IL_TYPE_PURE_BITVECTOR:
		return rz_il_value_new_bitv(res);
	default:
		RZ_LOG_ERROR("RzIL: type error: expected bitvector, got %s\n", pure_type_name(type));
		return NULL;
	}
}

/**
 * Evaluate the given pure op, returning the resulting value and its type.
 */
RZ_API RZ_NULLABLE RZ_OWN void *rz_il_evaluate_pure(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILTypePure *type) {
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
