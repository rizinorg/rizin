// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_VM_H
#define RZIL_VM_H

#include <rz_il/definitions/definitions.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_il/rz_il_events.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_IL_VM_MAX_VAR 2048
#define RZ_IL_VM_MAX_VAL 1024

typedef enum {
	RZ_IL_PURE_TYPE_BOOL, ///< RzILBool
	RZ_IL_PURE_TYPE_BITV ///< RzBitVector
} RzILPureType;

typedef struct rz_il_vm_t RzILVM;

/**
 * \brief Evaluation callback for a single pure opcode
 * \param type when returning a non-null value, this must be set to the respective type.
 * \return The evaluated value of the type indicated by *type, or NULL if an error occured and the execution should be aborted
 */
typedef void *(*RzILOpPureHandler)(RzILVM *vm, RzILOpPure *op, RZ_NONNULL RZ_OUT RzILPureType *type);

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
	RzILBag *vm_global_value_set; ///< Store all RzILVal instance
	RzPVector /*<RzILVar*>*/ vm_global_variable_list; ///< Store all the global RzILVar instance
	RzPVector /*<RzILVar*>*/ vm_local_variable_list; ///< Store all the local RzILVar instance
	RzPVector /*<RzILMem*>*/ vm_memory; ///< Memories available in the VM, by their inded. May be sparse (contain NULLs).
	ut32 val_count, lab_count; ///< count for VM predefined things
	ut32 addr_size; ///< size of address space
	HtPP *vm_global_bind_table; ///< Hashtable to record relationships between global var and val
	HtPP *vm_local_bind_table; ///< Hashtable to record relationships between local var and val
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
RZ_API void rz_il_vm_add_mem(RzILVM *vm, RzILMemIndex index, RZ_OWN RzILMem *mem);
RZ_API RzILMem *rz_il_vm_get_mem(RzILVM *vm, RzILMemIndex index);
RZ_API bool rz_il_vm_list_step(RzILVM *vm, RzILOpEffect *op, ut32 op_size);

// VM Event operations
RZ_API void rz_il_vm_event_add(RzILVM *vm, RzILEvent *evt);

// Memory operations
RZ_API RzBitVector *rz_il_vm_mem_load(RzILVM *vm, RzILMemIndex index, RzBitVector *key);
RZ_API void rz_il_vm_mem_store(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value);
RZ_API RzBitVector *rz_il_vm_mem_loadw(RzILVM *vm, RzILMemIndex index, RzBitVector *key, ut32 n_bits);
RZ_API void rz_il_vm_mem_storew(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value);

// VM operations about Variable and Value
RZ_API RZ_BORROW RzBitVector *rz_il_hash_find_addr_by_lblname(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *lbl_name);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_find_label_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *lbl_name);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_create_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RZ_NONNULL RZ_BORROW RzBitVector *addr);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_create_label_lazy(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name);
RZ_API RZ_BORROW RzILEffectLabel *rz_il_vm_update_label(RZ_NONNULL RzILVM *vm, RZ_NONNULL char *name, RZ_NONNULL RZ_BORROW RzBitVector *addr);

RZ_API RZ_BORROW RzILVal *rz_il_hash_find_val_by_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var);
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_val_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name);
RZ_API RZ_BORROW RzILVar *rz_il_find_var_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name);

RZ_API RZ_BORROW RzILVal *rz_il_hash_find_local_val_by_var(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var);
RZ_API RZ_BORROW RzILVal *rz_il_hash_find_local_val_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name);
RZ_API RZ_BORROW RzILVar *rz_il_find_local_var_by_name(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *var_name);

RZ_API RZ_BORROW RzILVar *rz_il_vm_create_global_variable(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVarType type, bool is_mutable);
RZ_API RZ_BORROW RzILVar *rz_il_vm_create_local_variable(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, RzILVarType type, bool is_mutable);
RZ_API RZ_BORROW RzILVal *rz_il_vm_create_value_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzBitVector *bitv);
RZ_API RZ_BORROW RzILVal *rz_il_vm_create_value_bool(RZ_NONNULL RzILVM *vm, bool value);
RZ_API RZ_BORROW RzILVal *rz_il_vm_create_value_unk(RZ_NONNULL RzILVM *vm);

RZ_API void rz_il_hash_bind(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var, RZ_NONNULL RzILVal *val);
RZ_API void rz_il_hash_cancel_binding(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var);

RZ_API void rz_il_hash_local_bind(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var, RZ_NONNULL RzILVal *val);
RZ_API void rz_il_hash_cancel_local_binding(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVar *var);

RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILVal *val);
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzBitVector *val);
RZ_API RZ_BORROW RzILVal *rz_il_vm_fortify_bool(RZ_NONNULL RzILVM *vm, bool val);

RZ_API void rz_il_vm_add_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, ut32 length);
RZ_API void rz_il_vm_add_bit_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, bool value);

RZ_API void rz_il_op_pure_stringify(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_op_effect_stringify(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL RzStrBuf *sb);

RZ_API void rz_il_op_pure_json(RZ_NONNULL RzILOpPure *op, RZ_NONNULL PJ *pj);
RZ_API void rz_il_op_effect_json(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL PJ *pj);

RZ_API void rz_il_event_stringify(RZ_NONNULL RzILEvent *evt, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj);

// VM auto convert functions
RZ_API RZ_NULLABLE RZ_OWN RzBitVector *rz_il_evaluate_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpBitVector *op);
RZ_API RZ_NULLABLE RZ_OWN RzILBool *rz_il_evaluate_bool(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpBool *op);
RZ_API RZ_NULLABLE RZ_OWN RzILVal *rz_il_evaluate_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op);
RZ_API RZ_NULLABLE RZ_OWN RzILVal *rz_il_evaluate_pure(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILPureType *type);
RZ_API bool rz_il_evaluate_effect(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpEffect *op);

// recursively parse and evaluate
RZ_API RZ_OWN void *rz_il_parse_op_root(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOpEffect *op);

#ifdef __cplusplus
}
#endif

#endif // RZIL_VM_H
