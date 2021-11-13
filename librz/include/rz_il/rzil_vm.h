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
	RzILVar **vm_global_variable_list; ///< Store all RzILVar instance

	RzILMem **mems; ///< Array of Memory, memory are actually hashmap in VM
	int var_count, val_count, mem_count, lab_count; ///< count for VM predefined things
	ut32 addr_size; ///< size of address space
	ut32 data_size; ///< size of minimal data unit

	HtPP *vm_global_bind_table; ///< Hashtable to record relationships between var and val
	HtPP *vm_global_label_table; ///< Hashtable to maintain the label and address

	HtPP *ct_opcodes; ///< Hashtable to maintain address and opcodes

	RzILBitVector *pc; ///< Program Counter of VM

	RzILOpHandler *op_handler_table; ///< Array of Handler, handler can be indexed by opcode

	RzList *events; ///< List of events that has happened in the last step
};

// VM operations about Variable and Value
RZ_API RzILBitVector *rz_il_hash_find_addr_by_lblname(RzILVM *vm, const char *lbl_name);
RZ_API RzILEffectLabel *rz_il_vm_find_label_by_name(RzILVM *vm, const char *lbl_name);
RZ_API RzILEffectLabel *rz_il_vm_create_label(RzILVM *vm, const char *name, RzILBitVector *addr);
RZ_API RzILEffectLabel *rz_il_vm_create_label_lazy(RzILVM *vm, const char *name);
RZ_API RzILEffectLabel *rz_il_vm_update_label(RzILVM *vm, char *name, RzILBitVector *addr);
RZ_API RzILVal *rz_il_hash_find_val_by_var(RzILVM *vm, RzILVar *var);
RZ_API RzILVal *rz_il_hash_find_val_by_name(RzILVM *vm, const char *var_name);
RZ_API RzILVar *rz_il_find_var_by_name(RzILVM *vm, const char *var_name);

RZ_API RzILVar *rz_il_vm_create_variable(RzILVM *vm, const char *name);
RZ_API RzILVal *rz_il_vm_create_value(RzILVM *vm, RZIL_VAR_TYPE type);
RZ_API void rz_il_hash_bind(RzILVM *vm, RzILVar *var, RzILVal *val);
RZ_API void rz_il_hash_cancel_binding(RzILVM *vm, RzILVar *var);

RZ_API RzILVal *rz_il_vm_fortify_val(RzILVM *vm, RzILVal *val);
RZ_API RzILVal *rz_il_vm_fortify_bitv(RzILVM *vm, RzILBitVector *val);
RZ_API RzILVal *rz_il_vm_fortify_bool(RzILVM *vm, RzILBool *val);

RZ_API void rz_il_vm_add_reg(RZ_NONNULL RzILVM *vm, RZ_NONNULL const char *name, ut32 length);

// VM store and load core theory opcodes
RZ_API void rz_il_vm_store_opcodes_to_addr(RzILVM *vm, RzILBitVector *addr, RzPVector *oplist);
RZ_API RzPVector *rz_il_make_oplist(int num, ...);

RZ_API void rz_il_op_stringify(RZ_NONNULL RzILOp *op, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_oplist_stringify(RZ_NONNULL RzPVector *oplist, RZ_NONNULL RzStrBuf *sb);

RZ_API void rz_il_op_json(RZ_NONNULL RzILOp *op, RZ_NONNULL PJ *pj);
RZ_API void rz_il_oplist_json(RZ_NONNULL RzPVector *oplist, RZ_NONNULL PJ *pj);

RZ_API void rz_il_event_stringify(RZ_NONNULL RzILEvent *evt, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_event_json(RZ_NONNULL RzILEvent *evt, RZ_NONNULL PJ *pj);

// VM auto convert functions
RZ_API RzILBitVector *rz_il_evaluate_bitv(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
RZ_API RzILBool *rz_il_evaluate_bool(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
RZ_API RzILVal *rz_il_evaluate_val(RzILVM *vm, RzILOp *op, RzILOpArgType *type);
RZ_API RzILEffect *rz_il_evaluate_effect(RzILVM *vm, RzILOp *op, RzILOpArgType *type);

// recursively parse and evaluate
RZ_API void *rz_il_parse_op_root(RzILVM *vm, RzILOp *root, RzILOpArgType *type);

#ifdef __cplusplus
}
#endif

#endif // RZIL_VM_H
