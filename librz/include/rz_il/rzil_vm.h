// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_VM_H
#define RZIL_VM_H

#include <rz_il/definitions/definitions.h>
#include <rz_il/rzil_opcodes.h>
#include <rz_il/rzil_vm_events.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_IL_VM_MAX_VAR  2048
#define RZ_IL_VM_MAX_VAL  1024
#define RZ_IL_VM_MAX_LAB  1024
#define RZ_IL_VM_MAX_EFF  1024
#define RZ_IL_VM_MAX_FLG  1024
#define RZ_IL_VM_MAX_TEMP 32

typedef enum {
	RZIL_OP_ARG_BOOL,
	RZIL_OP_ARG_BITV,
	RZIL_OP_ARG_VAL,
	RZIL_OP_ARG_EFF,
	RZIL_OP_ARG_MEM,
	RZIL_OP_ARG_INIT
} RzILOpArgType;

typedef struct rz_il_vm_t RzILVM;
typedef void *(*RzILOpHandler)(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
typedef void (*RzILVmHook)(RzILVM *vm, RzILOp *op);

/**
 *  \struct rz_il_vm_t
 *  \brief core theory VM structure
 */
struct rz_il_vm_t {
	RzILBag *vm_global_value_set; ///< Store all RzILVal instance
	RzPVector /*<RzILVar*>*/ vm_global_variable_list; ///< Store all the global RzILVar instance
	RzPVector /*<RzILVar*>*/ vm_local_variable_list; ///< Store all the local RzILVar instance

	RzPVector /*<RzILMem*>*/ vm_memory; ///< Array of Memory, memory are actually hashmap in VM
	ut32 val_count, lab_count; ///< count for VM predefined things
	ut32 addr_size; ///< size of address space
	ut32 data_size; ///< size of minimal data unit

	HtPP *vm_global_bind_table; ///< Hashtable to record relationships between global var and val
	HtPP *vm_local_bind_table; ///< Hashtable to record relationships between local var and val
	HtPP *vm_global_label_table; ///< Hashtable to maintain the label and address
	HtPP *vm_local_label_table; ///< Hashtable to maintain the label and address

	HtPP *ct_opcodes; ///< Hashtable to maintain address and opcodes

	RzBitVector *pc; ///< Program Counter of VM

	RzILOpHandler *op_handler_table; ///< Array of Handler, handler can be indexed by opcode

	RzList *events; ///< List of events that has happened in the last step
};

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

// VM store and load core theory opcodes
RZ_API void rz_il_vm_store_opcodes_to_addr(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzBitVector *addr, RZ_NONNULL RzPVector *oplist);
RZ_API RZ_OWN RzPVector *rz_il_make_oplist(ut32 num, ...);
#define rz_il_make_nop_list() rz_il_make_oplist(0, NULL)

RZ_API void rz_il_op_stringify(RZ_NONNULL RzILOp *op, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_oplist_stringify(RZ_NONNULL RzPVector *oplist, RZ_NONNULL RzStrBuf *sb);

RZ_API void rz_il_op_json(RZ_NONNULL RzILOp *op, RZ_NONNULL PJ *pj);
RZ_API void rz_il_oplist_json(RZ_NONNULL RzPVector *oplist, RZ_NONNULL PJ *pj);

RZ_API void rz_il_event_stringify(RZ_NONNULL RzILEvent *evt, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj);

// VM auto convert functions
RZ_API RZ_OWN RzBitVector *rz_il_evaluate_bitv(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type);
RZ_API RZ_OWN RzILBool *rz_il_evaluate_bool(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type);
RZ_API RZ_OWN RzILVal *rz_il_evaluate_val(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type);
RZ_API RZ_OWN void rz_il_evaluate_effect(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type);

// recursively parse and evaluate
RZ_API RZ_OWN void *rz_il_parse_op_root(RZ_NONNULL RzILVM *vm, RZ_NONNULL RzILOp *op, RZ_NONNULL RzILOpArgType *type);

#ifdef __cplusplus
}
#endif

#endif // RZIL_VM_H
