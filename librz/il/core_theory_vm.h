#ifndef BUILD_CORE_THEORY_VM_H
#define BUILD_CORE_THEORY_VM_H

#include "definitions/wrapper.h"
#include "core_theory_opcodes.h"

// TODO replace with rz hash table
// TODO find a proper way to handle var and val
#define VM_MAX_VAR  2048
#define VM_MAX_VAL  1024
#define VM_MAX_LAB  1024
#define VM_MAX_EFF  1024
#define VM_MAX_FLG  1024
#define VM_MAX_TEMP 32

typedef struct rz_il_vm_t *RzILVM;
typedef void (*RzILOpHandler)(RzILVM vm, RzILOp op);
typedef void (*RzILVmHook)(RzILVM vm, RzILOp op);

// Main structure of VM
struct rz_il_vm_t {
	// record the Var and Val in VM
	// persistent Variable, Value and effects
	RzILBag vm_global_value_set;
	RzILVar *vm_global_variable_list;

	// Memory : should support memory switch
	Mem *mems;
	int var_count, val_count, mem_count, lab_count;

	RzILTemp *temp_value_list;

	// binding relationships
	HtPP *vm_global_bind_table;
	HtPP *vm_global_label_table; // [label->name]->label

	// core theory opcodes
	//      key : Address (BitVector)
	//      val : opcode struct list (RzList of RzILOp)
	HtPP *ct_opcodes;

	// pc
	BitVector pc;

	// op handler table
	//      key : opcode
	//      val : function pointer
	RzILOpHandler *op_handler_table;

	// locate position for debug
	int easy_debug;
};

// VM operations about Variable and Value
BitVector rz_il_hash_find_addr_by_lblname(RzILVM vm, string lbl_name);
EffectLabel rz_il_vm_find_label_by_name(RzILVM vm, string lbl_name);
EffectLabel rz_il_vm_create_label(RzILVM vm, string name, BitVector addr);
EffectLabel rz_il_vm_create_label_lazy(RzILVM vm, string name);
EffectLabel rz_il_vm_update_label(RzILVM vm, string name, BitVector addr);
RzILVal rz_il_hash_find_val_by_var(RzILVM vm, RzILVar var);
RzILVal rz_il_hash_find_val_by_name(RzILVM vm, string var_name);
RzILVar rz_il_find_var_by_name(RzILVM vm, string var_name);

RzILVar rz_il_vm_create_variable(RzILVM vm, string name);
RzILVal rz_il_vm_create_value(RzILVM vm, RZIL_VAR_TYPE type);
void rz_il_vm_add_reg(RzILVM vm, string name, int length);
RzILVal rz_il_vm_fortify_val(RzILVM vm, int temp_val_index);
RzILVal rz_il_vm_fortify_bitv(RzILVM vm, int temp_val_index);
RzILVal rz_il_vm_fortify_bool(RzILVM vm, int temp_val_index);
void rz_il_hash_bind(RzILVM vm, RzILVar var, RzILVal val);
void rz_il_hash_cancel_binding(RzILVM vm, RzILVar var);

void rz_il_make_bool_temp(RzILVM vm, int store_index, Bool b);
void rz_il_make_val_temp(RzILVM vm, int store_index, RzILVal val);
void rz_il_make_bv_temp(RzILVM vm, int store_index, BitVector bv);
void rz_il_make_eff_temp(RzILVM vm, int store_index, Effect eff);
void *rz_il_get_temp(RzILVM vm, int index);
BitVector rz_il_get_bv_temp(RzILVM vm, int index);
Bool rz_il_get_bool_temp(RzILVM vm, int index);
RzILVal rz_il_get_val_temp(RzILVM vm, int index);
void rz_il_clean_temp(RzILVM vm, RzILTemp temp);
void rz_il_clean_temps(RzILVM vm);
void rz_il_empty_temp(RzILVM vm, int index);

// VM store and load core theory opcodes
RzPVector *rz_il_make_oplist(int num, ...);
void rz_il_vm_store_opcodes_to_addr(RzILVM vm, BitVector addr, RzPVector *oplist);
RzPVector *rz_il_vm_load_opcodes(RzILVM vm, BitVector addr);
RzPVector *rz_il_make_oplist_with_id(ut64 id, int num, ...);

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

// debug info
bool print_bind(void *user, const void *k, const void *v);
void rz_il_print_vm(RzILVM vm);
void rz_il_print_vm_mem(RzILVM vm);
void rz_il_print_vm_temps(RzILVM vm);
void rz_il_print_vm_labels(RzILVM vm);
void rz_il_vm_debug_easy(RzILVM vm);

#endif //BUILD_CORE_THEORY_VM_H
