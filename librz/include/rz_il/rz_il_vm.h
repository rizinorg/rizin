// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VM_H
#define RZ_IL_VM_H

#include <rz_il/definitions/definitions.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_events.h>
#include <rz_il/rz_il_reg.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_il_vm_t RzILVM;

/**
 * \brief Evaluation callback for a single pure opcode
 * \param type when returning a non-null value, this must be set to the respective type.
 * \return The evaluated value of the type indicated by *type, or NULL if an error occured and the execution should be aborted
 */
typedef void *(*RzILOpPureHandler)(RzILVM *vm, RzILOpPure *op, RZ_NONNULL RZ_OUT RzILTypePure *type);

/**
 * \brief Evaluation (execution) callback for a single effect opcode
 * \return false if an error occured and the execution should be aborted
 */
typedef bool (*RzILOpEffectHandler)(RzILVM *vm, RzILOpEffect *op);

typedef void (*RzILVmHook)(RzILVM *vm, RzILOpEffect *op);

/**
 *  \struct rz_il_vm_t
 *  \brief core theory VM structure
 */
struct rz_il_vm_t {
	RZ_NULLABLE RzILRegBinding *reg_binding; ///< Optional, specifies which (global) variables are bound to registers
	RzILVarSet global_vars; ///< All global variables (usually bound to registers)
	RzILVarSet local_vars; ///< All local variables, created by local set ops
	RzILVarSet local_pure_vars; ///< All local variables, during execution temporarily bound by let, only usable in pure expressions and immutable
	RzPVector /*<RzILMem>*/ vm_memory; ///< Memories available in the VM, by their index. May be sparse (contain NULLs).
	ut32 val_count, lab_count; ///< count for VM predefined things
	ut32 addr_size; ///< size of address space
	HtPP *vm_global_label_table; ///< Hashtable to maintain the label and address
	HtPP *vm_local_label_table; ///< Hashtable to maintain the label and address
	RzBitVector *pc; ///< Program Counter of VM
	RzILOpPureHandler *op_handler_pure_table; ///< Array of Handler, handler can be indexed by opcode
	RzILOpEffectHandler *op_handler_effect_table; ///< Array of Handler, handler can be indexed by opcode
	RzList *events; ///< List of events that has happened in the last step
	bool big_endian; ///< Sets the endianness of the memory reads/writes operations
};

// VM high level operations
RZ_API RzILVM *rz_il_vm_new(ut64 start_addr, ut32 addr_size, bool big_endian);
RZ_API void rz_il_vm_free(RzILVM *vm);
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, bool big_endian);
RZ_API void rz_il_vm_fini(RzILVM *vm);

// VM Event operations
RZ_API void rz_il_vm_event_add(RzILVM *vm, RzILEvent *evt);

// Memory operations
RZ_API void rz_il_vm_add_mem(RzILVM *vm, RzILMemIndex index, RZ_OWN RzILMem *mem);
RZ_API RzILMem *rz_il_vm_get_mem(RzILVM *vm, RzILMemIndex index);

RZ_API RzBitVector *rz_il_vm_mem_load(RzILVM *vm, RzILMemIndex index, RzBitVector *key);
RZ_API void rz_il_vm_mem_store(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value);
RZ_API RzBitVector *rz_il_vm_mem_loadw(RzILVM *vm, RzILMemIndex index, RzBitVector *key, ut32 n_bits);
RZ_API void rz_il_vm_mem_storew(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value);

// Labels
RZ_API RZ_BORROW RzBitVector *rz_il_hash_find_addr_by_lblname(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *lbl_name);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_find_label_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *lbl_name);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_create_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_NONNULL RZ_BORROW RzBitVector *addr);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_create_label_lazy(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_update_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL char *name, RZ_NONNULL RZ_BORROW RzBitVector *addr);

// Variables
RZ_API RZ_BORROW RzILVar *rz_il_vm_create_global_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILSortPure sort);
RZ_API void rz_il_vm_set_global_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_OWN RzILVal *val);
RZ_API void rz_il_vm_set_local_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_OWN RzILVal *val);
typedef RZ_NULLABLE RzILVal *RzILLocalPurePrev;
RZ_API RzILLocalPurePrev rz_il_vm_push_local_pure_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVal *val);
RZ_API void rz_il_vm_pop_local_pure_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILLocalPurePrev prev);
RZ_API RZ_BORROW RzILVar *rz_il_vm_get_var(RZ_NONNULL RzILVM *vm, RzILVarKind kind, const char *name);
RZ_API RZ_OWN RzPVector /* <RzILVar> */ *rz_il_vm_get_all_vars(RZ_NONNULL RzILVM *vm, RzILVarKind kind);
RZ_API RZ_BORROW RzILVal *rz_il_vm_get_var_value(RZ_NONNULL RzILVM *vm, RzILVarKind kind, const char *name);

// Printing/Export
RZ_API void rz_il_op_pure_stringify(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_op_effect_stringify(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL RzStrBuf *sb);

RZ_API void rz_il_op_pure_json(RZ_NONNULL RzILOpPure *op, RZ_NONNULL PJ *pj);
RZ_API void rz_il_op_effect_json(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL PJ *pj);

RZ_API void rz_il_event_stringify(RZ_NONNULL RzILEvent *evt, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj);

// Evaluation (Emulation)
RZ_API RZ_NULLABLE RZ_OWN RzBitVector *rz_il_evaluate_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpBitVector *op);
RZ_API RZ_NULLABLE RZ_OWN RzILBool *rz_il_evaluate_bool(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpBool *op);
RZ_API RZ_NULLABLE RZ_OWN RzILVal *rz_il_evaluate_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op);
RZ_API RZ_NULLABLE RZ_OWN void *rz_il_evaluate_pure(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILTypePure *type);
RZ_API bool rz_il_evaluate_effect(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpEffect *op);

RZ_API bool rz_il_vm_step(RzILVM *vm, RzILOpEffect *op, ut32 op_size);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VM_H
