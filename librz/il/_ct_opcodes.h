#ifndef BUILD__CT_OPCODES_H
#define BUILD__CT_OPCODES_H

#include "definitions/wrapper.h"

// All `ret` members are index to their type-specific array
//      bool, RzILVal, BitVector => RzILVal array (the vm_global_value_list)
//      RzVar => RzILVar array (vm_global_variable_list)
//      DataEffect, CtrlEffect, Effect => Effect array (the vm_global_effects)

// Bit Vector
// What's the meaning of `int s x`
// TODO : we can merge the structures which have the same
//        members, and use the typedef to identify them
struct rzil_op_int_t {
	// int s x
	int length; // sort (type) -- s
	int value; // const       -- x
	RzIL_BITV int ret;
};

struct rzil_op_msb_lsb_t {
	RzIL_BITV int bv;
	RzIL_BOOL int ret;
};

struct rzil_op_neg_t {
	RzIL_BITV int bv;
	RzIL_BITV int ret;
};

struct rzil_op_not_t {
	RzIL_BITV int bv;
	RzIL_BITV int ret;
};

struct rzil_op_alg_log_operations_t {
	RzIL_BITV int x;
	RzIL_BITV int y;
	RzIL_BITV int ret;
};

struct rzil_op_sle_ule_t {
	RzIL_BITV int x;
	RzIL_BITV int y;
	RzIL_BOOL int ret;
};

struct rzil_op_shift_t {
	RzIL_BOOL int fill_bit;
	RzIL_BITV int x;
	RzIL_BITV int y;
	RzIL_BITV int ret;
};

// Effect
struct rzil_op_perform_t {
	RzIL_EFF int eff;
	RzIL_EFF int ret;
};

struct rzil_op_set_t {
	RzIL_VAR string v;
	RzIL_PURE_VAL int x;
	RzIL_PURE_VAL int ret;
};

struct rzil_op_jmp_t {
	RzIL_BITV int dst;
	RzIL_EFF int ret_ctrl_eff;
};

struct rzil_op_goto_t {
	RzIL_LABLE string lbl;
	RzIL_EFF int ret_ctrl_eff;
};

struct rzil_op_seq_t {
	RzIL_EFF int x;
	RzIL_EFF int y;
	RzIL_EFF int ret;
};

struct rzil_op_blk_t {
	RzIL_EFF int data_eff;
	RzIL_EFF int ctrl_eff;
	RzIL_EFF int ret;
};

struct rzil_op_repeat_t {
	RzIL_BOOL int condition;
	RzIL_EFF int data_eff;
	RzIL_EFF int ret;
};

struct rzil_op_branch_t {
	RzIL_BOOL int condition;
	RzIL_EFF int true_eff;
	RzIL_EFF int false_eff;
	RzIL_EFF int ret;
};

// Init
struct rzil_op_ite_t {
	RzIL_BOOL int condition;
	RzIL_PURE_VAL int x;
	RzIL_PURE_VAL int y;
	RzIL_PURE_VAL int ret;
};

struct rzil_op_var_t {
	RzIL_VAR string v;
	RzIL_PURE_VAL int ret;
};

struct rzil_op_unk_t {
	RzIL_PURE_VAL int ret;
};

// BOOL
struct rzil_op_b_t {
	RzIL_BOOL int ret;
};

struct rzil_op_and__t {
	RzIL_BOOL int x;
	RzIL_BOOL int y;
	RzIL_BOOL int ret;
};

struct rzil_op_or__t {
	RzIL_BOOL int x;
	RzIL_BOOL int y;
	RzIL_BOOL int ret;
};

struct rzil_op_inv_t {
	RzIL_BOOL int x;
	RzIL_BOOL int ret;
};

// Mem
struct rzil_op_load_t {
	RzIL_MEM int mem;
	RzIL_BITV int key;
	RzIL_BITV int ret;
};

struct rzil_op_store_t {
	RzIL_MEM int mem;
	RzIL_BITV int key;
	RzIL_BITV int value;
	RzIL_MEM int ret;
};

#endif //BUILD__CT_OPCODES_H
