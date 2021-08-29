// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_VM_H
#define RZIL_VM_H

#include "definitions/definitions.h"
#include "rzil_opcodes.h"

#define RZ_IL_VM_MAX_VAR  2048
#define RZ_IL_VM_MAX_VAL  1024
#define RZ_IL_VM_MAX_LAB  1024
#define RZ_IL_VM_MAX_EFF  1024
#define RZ_IL_VM_MAX_FLG  1024
#define RZ_IL_VM_MAX_TEMP 32

typedef struct rz_il_vm_t *RzILVM;
typedef void (*RzILOpHandler)(RzILVM vm, RzILOp op);
typedef void (*RzILVmHook)(RzILVM vm, RzILOp op);

/**
 *  \struct rz_il_vm_t
 *  \brief core theory VM structure
 */
struct rz_il_vm_t {
	RzILBag vm_global_value_set; ///< Store all RzILVal instance
	RzILVar *vm_global_variable_list; ///< Store all RzILVar instance

	RzILMem *mems; ///< Array of Memory, memory are actually hashmap in VM
	int var_count, val_count, mem_count, lab_count; ///< count for VM predefined things
	int addr_size; ///< size of address
	int data_size; ///< size of minimal data unit

	RzILTemp *temp_value_list; ///< Array of temporary values

	HtPP *vm_global_bind_table; ///< Hashtable to record relationships between var and val
	HtPP *vm_global_label_table; ///< Hashtable to maintain the label and address

	HtPP *ct_opcodes; ///< Hashtable to maintain address and opcodes

	RzILBitVector pc; ///< Program Counter of VM

	RzILOpHandler *op_handler_table; ///< Array of Handler, handler can be indexed by opcode

	int easy_debug; ///< Debug only, used to locate the bug
};

// VM operations about Variable and Value
RZ_API RzILBitVector rz_il_hash_find_addr_by_lblname(RzILVM vm, const char *lbl_name);
RZ_API RzILEffectLabel rz_il_vm_find_label_by_name(RzILVM vm, const char *lbl_name);
RZ_API RzILEffectLabel rz_il_vm_create_label(RzILVM vm, char *name, RzILBitVector addr);
RZ_API RzILEffectLabel rz_il_vm_create_label_lazy(RzILVM vm, char *name);
RZ_API RzILEffectLabel rz_il_vm_update_label(RzILVM vm, char *name, RzILBitVector addr);
RZ_API RzILVal rz_il_hash_find_val_by_var(RzILVM vm, RzILVar var);
RZ_API RzILVal rz_il_hash_find_val_by_name(RzILVM vm, const char *var_name);
RZ_API RzILVar rz_il_find_var_by_name(RzILVM vm, const char *var_name);

RZ_API RzILVar rz_il_vm_create_variable(RzILVM vm, char *name);
RZ_API RzILVal rz_il_vm_create_value(RzILVM vm, RZIL_VAR_TYPE type);
RZ_API void rz_il_hash_bind(RzILVM vm, RzILVar var, RzILVal val);
RZ_API void rz_il_hash_cancel_binding(RzILVM vm, RzILVar var);

RZ_API RzILVal rz_il_vm_fortify_val(RzILVM vm, int temp_val_index);
RZ_API RzILVal rz_il_vm_fortify_bitv(RzILVM vm, int temp_val_index);
RZ_API RzILVal rz_il_vm_fortify_bool(RzILVM vm, int temp_val_index);
RZ_API void rz_il_make_bool_temp(RzILVM vm, int store_index, RzILBool b);
RZ_API void rz_il_make_val_temp(RzILVM vm, int store_index, RzILVal val);
RZ_API void rz_il_make_bv_temp(RzILVM vm, int store_index, RzILBitVector bv);
RZ_API void rz_il_make_eff_temp(RzILVM vm, int store_index, RzILEffect eff);
RZ_API void *rz_il_get_temp(RzILVM vm, int index);
RZ_API RzILBitVector rz_il_get_bv_temp(RzILVM vm, int index);
RZ_API RzILBool rz_il_get_bool_temp(RzILVM vm, int index);
RZ_API RzILVal rz_il_get_val_temp(RzILVM vm, int index);
RZ_API void rz_il_clean_temp(RzILVM vm, RzILTemp temp);
RZ_API void rz_il_clean_temps(RzILVM vm);
RZ_API void rz_il_empty_temp(RzILVM vm, int index);

RZ_API void rz_il_vm_add_reg(RzILVM vm, char *name, int length);

// VM store and load core theory opcodes
RZ_API RzPVector *rz_il_make_oplist(int num, ...);
RZ_API void rz_il_vm_store_opcodes_to_addr(RzILVM vm, RzILBitVector addr, RzPVector *oplist);
RZ_API RzPVector *rz_il_vm_load_opcodes(RzILVM vm, RzILBitVector addr);
RZ_API RzPVector *rz_il_vm_load_opcodes_at_pc(RzILVM vm);
RZ_API RzPVector *rz_il_make_oplist_with_id(ut64 id, int num, ...);

// Handler for core theory opcode
void rz_il_handler_ite(RzILVM vm, RzILOp op);
void rz_il_handler_var(RzILVM vm, RzILOp op);
void rz_il_handler_unk(RzILVM vm, RzILOp op);

void rz_il_handler_int(RzILVM vm, RzILOp op);
void rz_il_handler_msb(RzILVM vm, RzILOp op);
void rz_il_handler_lsb(RzILVM vm, RzILOp op);
void rz_il_handler_ule(RzILVM vm, RzILOp op);
void rz_il_handler_sle(RzILVM vm, RzILOp op);
void rz_il_handler_neg(RzILVM vm, RzILOp op);
void rz_il_handler_not(RzILVM vm, RzILOp op);
void rz_il_handler_add(RzILVM vm, RzILOp op);
void rz_il_handler_sub(RzILVM vm, RzILOp op);
void rz_il_handler_mul(RzILVM vm, RzILOp op);
void rz_il_handler_div(RzILVM vm, RzILOp op);
void rz_il_handler_sdiv(RzILVM vm, RzILOp op);
void rz_il_handler_mod(RzILVM vm, RzILOp op);
void rz_il_handler_smod(RzILVM vm, RzILOp op);
void rz_il_handler_shiftl(RzILVM vm, RzILOp op);
void rz_il_handler_shiftr(RzILVM vm, RzILOp op);

void rz_il_handler_b0(RzILVM vm, RzILOp op);
void rz_il_handler_b1(RzILVM vm, RzILOp op);
void rz_il_handler_and_(RzILVM vm, RzILOp op);
void rz_il_handler_or_(RzILVM vm, RzILOp op);
void rz_il_handler_inv(RzILVM vm, RzILOp op);

void rz_il_handler_perform(RzILVM vm, RzILOp op);
void rz_il_handler_set(RzILVM vm, RzILOp op);
void rz_il_handler_jmp(RzILVM vm, RzILOp op);
void rz_il_handler_goto(RzILVM vm, RzILOp op);
void rz_il_handler_seq(RzILVM vm, RzILOp op);
void rz_il_handler_blk(RzILVM vm, RzILOp op);
void rz_il_handler_repeat(RzILVM vm, RzILOp op);
void rz_il_handler_branch(RzILVM vm, RzILOp op);

void rz_il_handler_load(RzILVM vm, RzILOp op);
void rz_il_handler_store(RzILVM vm, RzILOp op);

#endif // RZIL_VM_H
