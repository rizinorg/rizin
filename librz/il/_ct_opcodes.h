// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * @file _ct_opcodes.h
 * @brief signatures of core theory opcodes
 *
 * Modular Hierarchy of the whole core theory
 * (we implement the Minimal part only)
 *                          o Core
 *                            |
 *             Trans o--------+--------o Float
 *                            |        |
 *                            o Basic  o FBasic
 *                            |
 *                            o Minimal
 *                            |
 *           +-------+--------+--------+-------+
 *           |       |        |        |       |
 *           o       o        o        o       o
 *         Init    Bool     Bitv    Memory   Effect
 *
 * See also the references :
 * 0. A gentle introduction to core theory http://binaryanalysisplatform.github.io/bap/api/odoc/bap-core-theory/Bap_core_theory/index.html
 * 1. http://binaryanalysisplatform.github.io/bap/api/odoc/bap-core-theory/Bap_core_theory/Theory/index.html
 * 2. For core and array theories https://smtlib.cs.uiowa.edu/theories.shtml
 */

#ifndef BUILD__CT_OPCODES_H
#define BUILD__CT_OPCODES_H

#include "definitions/wrapper.h"

/**
 *  \struct rzil_op_int_t
 *  \brief op structure for `msb` and `lsb` (val int : 's Bitv.t Value.sort -> word -> 's bitv)
 *
 *  int s x is a bitvector constant x of sort s.
 */
struct rzil_op_int_t {
	int length; ///< s -- sort(type), length of bitvector
	int value; ///< x -- value of bitvector
	RzIL_BITV int ret; ///< index of BitVector in temp_value_list
};

/**
 *  \struct rzil_op_msb_lsb_t
 *  \brief op structure for `msb` and `lsb` ('s bitv -> bool)
 *  [MSB] msb x is the most significant bit of x.
 *  [LSB] lsb x is the least significant bit of x.
 */
struct rzil_op_msb_lsb_t {
	RzIL_BITV int bv; ///< index of bitvector operand
	RzIL_BOOL int ret; ///< index of return Bool value in temp_value_list
};

/**
 *  \struct rzil_neg_t
 *  \brief op structure for `neg` ('s bitv -> 's bitv)
 *
 *  neg x is two-complement unary minus
 */
struct rzil_op_neg_t {
	RzIL_BITV int bv; ///< index of bitvector operand
	RzIL_BITV int ret; ///< index of return BitVector value in temp_value_list
};

/**
 *  \struct rzil_not_t
 *  \brief op structure for `not` ('s bitv -> 's bitv)
 *
 *  neg x is one-complement unary minus
 */
struct rzil_op_not_t {
	RzIL_BITV int bv; ///< index of bitvector operand
	RzIL_BITV int ret; ///< index of return BitVector value in temp_value_list
};

/**
 *  \struct rzil_op_alg_log_operations_t
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [ADD] add x y addition modulo 2^'s
 *  [SUB] sub x y subtraction modulo 2^'s
 *  [MUL] mul x y multiplication modulo 2^'s
 *  [DIV] div x y unsigned division modulo 2^'s truncating towards 0. The division by zero is defined to be a vector of all ones of size 's.
 *  [MOD] modulo x y is the remainder of div x y modulo 2^'s.
 *  [SDIV] sdiv x y is signed division of x by y modulo 2^'s.
 *  [SMDO] smodulo x y is the signed remainder of div x y modulo 2^'s.
 *  [LOGAND] logand x y is a bitwise logical and of x and y.
 *  [LOGOR] logor x y is a bitwise logical or of x and y.
 *  [LOGXOR] logxor x y is a bitwise logical xor of x and y.
 */
struct rzil_op_alg_log_operations_t {
	RzIL_BITV int x; ///< index of Operand 1
	RzIL_BITV int y; ///< index of Operand 2
	RzIL_BITV int ret; ///< index of store result in temp_value_list
};

/**
 *  \struct rzil_op_sle_ule_t
 *  \brief op structure for sle/ule ('a bitv -> 'a bitv -> bool)
 *
 *  [SLE] sle x y binary predicate for singed less than or equal
 *  [ULE] ule x y binary predicate for unsigned less than or equal
 */
struct rzil_op_sle_ule_t {
	RzIL_BITV int x; ///< index of operand 1
	RzIL_BITV int y; ///< index of operand 2
	RzIL_BOOL int ret; ///< index of store bool result in temp_value_list
};

/**
 *  \struct rzil_op_shift_t
 *  \brief op structure for lshift and rshift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [LSHIFT] shiftl s x m shifts x left by m bits filling with s.
 *  [RSHIFT] shiftr s x m shifts x right by m bits filling with s.
 */
struct rzil_op_shift_t {
	RzIL_BOOL int fill_bit; ///< index of fill bit
	RzIL_BITV int x; ///< index of operand 1
	RzIL_BITV int y; ///< index of operand 2
	RzIL_BITV int ret; ///< index of store bitvector result
};

/**
 *  \struct rzil_op_perform_t
 *  \brief op structure for `perform` ('a Effect.sort -> 'a eff)
 *
 *  perform s performs a generic effect of sort s.
 *  normally we set ret to -1 to show that no more effect after perform this one
 */
struct rzil_op_perform_t {
	RzIL_EFF int eff; ///< index of effect to perform
	RzIL_EFF int ret; ///< index of store bitvector result
};

/**
 *  \struct rzil_op_set_t
 *  \brief op structure for `set` ('a var -> 'a pure -> data eff)
 *
 *  set v x changes the value stored in v to the value of x.
 */
struct rzil_op_set_t {
	RzIL_VAR string v; ///< name of variable
	RzIL_PURE_VAL int x; ///< index of RzILVal
	RzIL_EFF int ret; ///< index of store Effect result
};

/**
 *  \struct rzil_op_jmp_t
 *  \brief op structure for `jmp` (_ bitv -> ctrl eff)
 *
 *  jmp dst passes the control to a program located at dst.
 */
struct rzil_op_jmp_t {
	RzIL_BITV int dst; ///< index of destination address (BitVector)
	RzIL_EFF int ret_ctrl_eff; ///< index of store control effect
};

/**
 *  \struct rzil_op_goto_t
 *  \brief op structure for `goto` (label -> ctrl eff)
 *
 *  goto lbl passes the control to a program labeled with lbl.
 */
struct rzil_op_goto_t {
	RzIL_LABLE string lbl; ///< name of the label
	RzIL_EFF int ret_ctrl_eff; ///< index of store control effect
};

/**
 *  \struct rzil_op_seq_t
 *  \brief op structure for `Seq` ('a eff -> 'a eff -> 'a eff)
 *
 *  seq x y performs effect x, after that perform effect y. Pack two effects into one.
 */
struct rzil_op_seq_t {
	RzIL_EFF int x; ///< index of the first effect
	RzIL_EFF int y; ///< index of the second effect
	RzIL_EFF int ret; ///< index of store the packed effect
};

/**
 *  \struct rzil_op_blk_t
 *  \brief op structure for `blk` (label -> data eff -> ctrl eff -> unit eff)
 *
 *  blk lbl data ctrl a labeled sequence of effects.
 */
struct rzil_op_blk_t {
	RzIL_EFF int data_eff; ///< index of data_eff
	RzIL_EFF int ctrl_eff; ///< index of ctrl_eff
	RzIL_EFF int ret; ///< index of store the packed effect
};

/**
 *  \struct rzil_op_repeat_t
 *  \brief op structure for `repeat` (bool -> data eff -> data eff)
 *
 *  repeat c data repeats data effects until the condition c holds.
 */
struct rzil_op_repeat_t {
	RzIL_BOOL int condition; ///< index of BOOL condition
	RzIL_EFF int data_eff; ///< index of data effect
	RzIL_EFF int ret; ///< index of data effect result
};

/**
 *  \struct rzil_op_branch_t
 *  \brief op structure for `branch` (bool -> 'a eff -> 'a eff -> 'a eff)
 *
 *  branch c lhs rhs if c holds then performs lhs else rhs.
 */
struct rzil_op_branch_t {
	RzIL_BOOL int condition; ///< index of BOOL condition
	RzIL_EFF int true_eff; ///< index of true effect, set to -1 means do nothing
	RzIL_EFF int false_eff; ///< index of false effect, set to -1 means do nothing
	RzIL_EFF int ret; ///< index of store the chosen effect
};

/**
 *  \struct rzil_op_ite_t
 *  \brief op structure for `ite` (bool -> 'a pure -> 'a pure -> 'a pure)
 *
 *  ite c x y is x if c evaluates to b1 else y.
 */
struct rzil_op_ite_t {
	RzIL_BOOL int condition; ///< index of BOOL condition
	RzIL_PURE_VAL int x; ///< index of RzILVal operand 1
	RzIL_PURE_VAL int y; ///< index of RzILVal operand 2
	RzIL_PURE_VAL int ret; ///< index of the chosen RzILVal
};

/**
 *  \struct rzil_op_var_t
 *  \brief op structure for `var` ('a var -> 'a pure)
 *
 *  var v is the value of the variable v.
 */
struct rzil_op_var_t {
	RzIL_VAR string v; ///< name of variable
	RzIL_PURE_VAL int ret; ///< index of RzILVal value of the variable
};

/**
 *  \struct rzil_op_unk_t
 *  \brief op structure for `unk` ('a Value.sort -> 'a pure)
 *
 *  unk s an unknown value of sort s. This term explicitly denotes a term with undefined or unknown value.
 */
struct rzil_op_unk_t {
	RzIL_PURE_VAL int ret; ///< index of store the UNK
};

/**
 *  \struct rzil_op_b_t
 *  \brief op structure for `b0` and `b1` (bool)
 *
 *  [B0] b0 is false aka 0 bit
 *  [B1] b1 is true aka 1 bit
 */
struct rzil_op_b_t {
	RzIL_BOOL int ret; ///< index of store the B0/B1
};

/**
 *  \struct rzil_op_and__t
 *  \brief op structure for `and_` (bool -> bool -> bool)
 *
 *  and_ x y is a conjunction of x and y.
 */
struct rzil_op_and__t {
	RzIL_BOOL int x; ///< index of the BOOL operand
	RzIL_BOOL int y; ///< index of the BOOL operand
	RzIL_BOOL int ret; ///< index of store the BOOL result
};

/**
 *  \struct rzil_op_or__t
 *  \brief op structure for `or_` (bool -> bool -> bool)
 *
 *  or_ x y is a disjunction of x and y.
 */
struct rzil_op_or__t {
	RzIL_BOOL int x; ///< index of the BOOL operand
	RzIL_BOOL int y; ///< index of the BOOL operand
	RzIL_BOOL int ret; ///< index of store the BOOL result
};

/**
 *  \struct rzil_op_inv_t
 *  \brief op structure for `inv` (bool -> bool)
 *
 *  inv x inverts x.
 */
struct rzil_op_inv_t {
	RzIL_BOOL int x; ///< index of the BOOL operand
	RzIL_BOOL int ret; ///< index of store the BOOL result
};

/**
 *  \struct rzil_op_load_t
 *  \brief op structure for `load` (('a, 'b) mem -> 'a bitv -> 'b bitv)
 *
 *  load m k is the value associated with the key k in the memory m.
 */
struct rzil_op_load_t {
	RzIL_MEM int mem; ///< index of the memory in vm (different from the temp_val_list)
	RzIL_BITV int key; ///< index of the BitVector key (address)
	RzIL_BITV int ret; ///< index of store the data loaded from memory
};

/**
 *  \struct rzil_op_store_t
 *  \brief op structure for `store` (('a, 'b) mem -> 'a bitv -> 'b bitv -> ('a, 'b) mem)
 *
 *  store m k x a memory m in which the key k is associated with the word x.
 */
struct rzil_op_store_t {
	RzIL_MEM int mem; ///< index of memory in vm
	RzIL_BITV int key; ///< index of the BitVector key (address)
	RzIL_BITV int value; ///< index of the RzILVal value (data) to store
	RzIL_MEM int ret; ///< The returned Mem index.
};

#endif //BUILD__CT_OPCODES_H
