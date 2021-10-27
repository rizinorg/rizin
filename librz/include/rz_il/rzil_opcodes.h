// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_OPCODES_H
#define RZIL_OPCODES_H

#include <rz_il/definitions/definitions.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RzILOp_t RzILOp;
/**
 * \file rzil_opcodes.h
 * \brief signatures of core theory opcodes
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
 *         Init    RzILBool     Bitv    Memory   Effect
 *
 * See also the references :
 * 0. A gentle introduction to core theory http://binaryanalysisplatform.github.io/bap/api/odoc/bap-core-theory/Bap_core_theory/index.html
 * 1. http://binaryanalysisplatform.github.io/bap/api/odoc/bap-core-theory/Bap_core_theory/Theory/index.html
 * 2. For core and array theories https://smtlib.cs.uiowa.edu/theories.shtml
 */

/**
 *  \struct rzil_op_int_t
 *  \brief op structure for `int` (val int : 's Bitv.t Value.sort -> word -> 's bitv)
 *
 *  int s x is a bitvector constant x of sort s.
 */
struct rzil_op_int_t {
	ut32 length; ///< s -- sort(type), length of bitvector
	int value; ///< x -- value of bitvector
};

/**
 *  \struct rzil_op_msb_lsb_t
 *  \brief op structure for `msb` and `lsb` ('s bitv -> bool)
 *  [MSB] msb x is the most significant bit of x.
 *  [LSB] lsb x is the least significant bit of x.
 */
struct rzil_op_msb_lsb_t {
	RzILOp *bv; ///< index of bitvector operand
};

/**
 *  \struct rzil_neg_t
 *  \brief op structure for `neg` ('s bitv -> 's bitv)
 *
 *  neg x is two-complement unary minus
 */
struct rzil_op_neg_t {
	RzILOp *bv; ///< index of bitvector operand
};

/**
 *  \struct rzil_not_t
 *  \brief op structure for `not` ('s bitv -> 's bitv)
 *
 *  neg x is one-complement unary minus
 */
struct rzil_op_not_t {
	RzILOp *bv; ///< index of bitvector operand
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
	RzILOp *x; ///< index of Operand 1
	RzILOp *y; ///< index of Operand 2
};

/**
 *  \struct rzil_op_sle_ule_t
 *  \brief op structure for sle/ule ('a bitv -> 'a bitv -> bool)
 *
 *  [SLE] sle x y binary predicate for singed less than or equal
 *  [ULE] ule x y binary predicate for unsigned less than or equal
 */
struct rzil_op_sle_ule_t {
	RzILOp *x; ///< index of operand 1
	RzILOp *y; ///< index of operand 2
};

/**
 *  \struct rzil_op_cast_t
 *  \brief op structure for casting bitv
 */
struct rzil_op_cast_t {
	ut32 length; ///< new bits lenght
	int shift; ///< shift old bits (positive is << and >> negative)
	RzILOp *val; ///< value to cast
};

/**
 *  \struct rzil_op_shift_t
 *  \brief op structure for lshift and rshift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [LSHIFT] shiftl s x m shifts x left by m bits filling with s.
 *  [RSHIFT] shiftr s x m shifts x right by m bits filling with s.
 */
struct rzil_op_shift_t {
	RzILOp *fill_bit; ///< index of fill bit
	RzILOp *x; ///< index of operand 1
	RzILOp *y; ///< index of operand 2
};

/**
 *  \struct rzil_op_perform_t
 *  \brief op structure for `perform` ('a Effect.sort -> 'a eff)
 *
 *  perform s performs a generic effect of sort s.
 *  normally we set ret to -1 to show that no more effect after perform this one
 */
struct rzil_op_perform_t {
	RzILOp *eff; ///< index of effect to perform
};

/**
 *  \struct rzil_op_set_t
 *  \brief op structure for `set` ('a var -> 'a pure -> data eff)
 *
 *  set v x changes the value stored in v to the value of x.
 */
struct rzil_op_set_t {
	const char *v; ///< name of variable, const one
	RzILOp *x; ///< index of RzILVal
};

/**
 *  \struct rzil_op_jmp_t
 *  \brief op structure for `jmp` (_ bitv -> ctrl eff)
 *
 *  jmp dst passes the control to a program located at dst.
 */
struct rzil_op_jmp_t {
	RzILOp *dst; ///< index of destination address (RzILBitVector)
};

/**
 *  \struct rzil_op_goto_t
 *  \brief op structure for `goto` (label -> ctrl eff)
 *
 *  goto lbl passes the control to a program labeled with lbl.
 */
struct rzil_op_goto_t {
	const char *lbl; ///< name of the label, const one
};

/**
 *  \struct rzil_op_seq_t
 *  \brief op structure for `Seq` ('a eff -> 'a eff -> 'a eff)
 *
 *  seq x y performs effect x, after that perform effect y. Pack two effects into one.
 */
struct rzil_op_seq_t {
	RzILOp *x; ///< index of the first effect
	RzILOp *y; ///< index of the second effect
};

/**
 *  \struct rzil_op_blk_t
 *  \brief op structure for `blk` (label -> data eff -> ctrl eff -> unit eff)
 *
 *  blk lbl data ctrl a labeled sequence of effects.
 */
struct rzil_op_blk_t {
	RzILOp *data_eff; ///< index of data_eff
	RzILOp *ctrl_eff; ///< index of ctrl_eff
};

/**
 *  \struct rzil_op_repeat_t
 *  \brief op structure for `repeat` (bool -> data eff -> data eff)
 *
 *  repeat c data repeats data effects until the condition c holds.
 */
struct rzil_op_repeat_t {
	RzILOp *condition; ///< index of BOOL condition
	RzILOp *data_eff; ///< index of data effect
};

/**
 *  \struct rzil_op_branch_t
 *  \brief op structure for `branch` (bool -> 'a eff -> 'a eff -> 'a eff)
 *
 *  branch c lhs rhs if c holds then performs lhs else rhs.
 */
struct rzil_op_branch_t {
	RzILOp *condition; ///< index of BOOL condition
	RzILOp *true_eff; ///< index of true effect, set to -1 means do nothing
	RzILOp *false_eff; ///< index of false effect, set to -1 means do nothing
};

/**
 *  \struct rzil_op_ite_t
 *  \brief op structure for `ite` (bool -> 'a pure -> 'a pure -> 'a pure)
 *
 *  ite c x y is x if c evaluates to b1 else y.
 */
struct rzil_op_ite_t {
	RzILOp *condition; ///< index of BOOL condition
	RzILOp *x; ///< index of RzILVal operand 1
	RzILOp *y; ///< index of RzILVal operand 2
};

/**
 *  \struct rzil_op_var_t
 *  \brief op structure for `var` ('a var -> 'a pure)
 *
 *  var v is the value of the variable v.
 */
struct rzil_op_var_t {
	const char *v; ///< name of variable, const one
};

/**
 *  \struct rzil_op_and__t
 *  \brief op structure for `and_` (bool -> bool -> bool)
 *
 *  and_ x y is a conjunction of x and y.
 */
struct rzil_op_and__t {
	RzILOp *x; ///< index of the BOOL operand
	RzILOp *y; ///< index of the BOOL operand
};

/**
 *  \struct rzil_op_or__t
 *  \brief op structure for `or_` (bool -> bool -> bool)
 *
 *  or_ x y is a disjunction of x and y.
 */
struct rzil_op_or__t {
	RzILOp *x; ///< index of the BOOL operand
	RzILOp *y; ///< index of the BOOL operand
};

/**
 *  \struct rzil_op_inv_t
 *  \brief op structure for `inv` (bool -> bool)
 *
 *  inv x inverts x.
 */
struct rzil_op_inv_t {
	RzILOp *x; ///< index of the BOOL operand
	RzILOp *ret; ///< index of store the BOOL result
};

/**
 *  \struct rzil_op_load_t
 *  \brief op structure for `load` (('a, 'b) mem -> 'a bitv -> 'b bitv)
 *
 *  load m k is the value associated with the key k in the memory m.
 */
struct rzil_op_load_t {
	int mem; ///< index of the memory in VM (different from the temp_val_list)
	RzILOp *key; ///< index of the RzILBitVector key (address)
};

/**
 *  \struct rzil_op_store_t
 *  \brief op structure for `store` (('a, 'b) mem -> 'a bitv -> 'b bitv -> ('a, 'b) mem)
 *
 *  store m k x a memory m in which the key k is associated with the word x.
 */
struct rzil_op_store_t {
	int mem; ///< index of memory in VM
	RzILOp *key; ///< index of the RzILBitVector key (address)
	RzILOp *value; ///< index of the RzILVal value (data) to store
};

// TODO : a better way to map enum to string
// Remember to add new opcode in rz_il_op2str
// if you add a new one.
typedef enum {
	// Init
	RZIL_OP_VAR,
	RZIL_OP_UNK,
	RZIL_OP_ITE,

	// RzILBool
	RZIL_OP_B0,
	RZIL_OP_B1,
	RZIL_OP_INV,
	RZIL_OP_AND_,
	RZIL_OP_OR_,

	// RzILBitVector
	RZIL_OP_INT,
	RZIL_OP_MSB,
	RZIL_OP_LSB,
	RZIL_OP_NEG,
	RZIL_OP_NOT,
	RZIL_OP_ADD,
	RZIL_OP_SUB,
	RZIL_OP_MUL,
	RZIL_OP_DIV,
	RZIL_OP_SDIV,
	RZIL_OP_MOD,
	RZIL_OP_SMOD,
	RZIL_OP_LOGAND,
	RZIL_OP_LOGOR,
	RZIL_OP_LOGXOR,
	RZIL_OP_SHIFTR,
	RZIL_OP_SHIFTL,
	RZIL_OP_SLE,
	RZIL_OP_ULE,
	RZIL_OP_CAST,
	RZIL_OP_CONCAT,
	RZIL_OP_APPEND,
	// ...

	// Memory
	RZIL_OP_LOAD,
	RZIL_OP_STORE,

	// Effects (opcode with side effects)
	RZIL_OP_PERFORM,
	RZIL_OP_SET,
	RZIL_OP_JMP,
	RZIL_OP_GOTO,
	RZIL_OP_SEQ,
	RZIL_OP_BLK,
	RZIL_OP_REPEAT,
	RZIL_OP_BRANCH,

	RZIL_OP_INVALID,
	RZIL_OP_MAX,
} RzILOPCode;

/// support core theory opcode
/// define every CoreTheory opcode struct */
/// for example : ite in Ocaml
///               val ite : bool -> 'a pure -> 'a pure -> 'a pure
///               ite c x y is x if c evaluates to b1 else y.
/// they are defined in specific modules
typedef struct rzil_op_ite_t RzILOpIte;
typedef struct rzil_op_var_t RzILOpVar;

typedef struct rzil_op_msb_lsb_t RzILOpMsb;
typedef struct rzil_op_msb_lsb_t RzILOpLsb;
typedef struct rzil_op_sle_ule_t RzILOpSle;
typedef struct rzil_op_sle_ule_t RzILOpUle;
typedef struct rzil_op_cast_t RzILOpCast;
typedef struct rzil_op_not_t RzILOpNot;
typedef struct rzil_op_neg_t RzILOpNeg;
typedef struct rzil_op_alg_log_operations_t RzILOpAdd;
typedef struct rzil_op_alg_log_operations_t RzILOpSub;
typedef struct rzil_op_alg_log_operations_t RzILOpMul;
typedef struct rzil_op_alg_log_operations_t RzILOpDiv;
typedef struct rzil_op_alg_log_operations_t RzILOpSdiv;
typedef struct rzil_op_alg_log_operations_t RzILOpMod;
typedef struct rzil_op_alg_log_operations_t RzILOpSmod;
typedef struct rzil_op_alg_log_operations_t RzILOpLogand;
typedef struct rzil_op_alg_log_operations_t RzILOpLogor;
typedef struct rzil_op_alg_log_operations_t RzILOpLogxor;
typedef struct rzil_op_shift_t RzILOpShiftl;
typedef struct rzil_op_shift_t RzILOpShiftr;
typedef struct rzil_op_int_t RzILOpInt;

typedef struct rzil_op_and__t RzILOpAnd_;
typedef struct rzil_op_or__t RzILOpOr_;
typedef struct rzil_op_inv_t RzILOpInv;

typedef struct rzil_op_perform_t RzILOpPerform;
typedef struct rzil_op_set_t RzILOpSet;
typedef struct rzil_op_jmp_t RzILOpJmp;
typedef struct rzil_op_goto_t RzILOpGoto;
typedef struct rzil_op_seq_t RzILOpSeq;
typedef struct rzil_op_blk_t RzILOpBlk;
typedef struct rzil_op_repeat_t RzILOpRepeat;
typedef struct rzil_op_branch_t RzILOpBranch;

typedef struct rzil_op_load_t RzILOpLoad;
typedef struct rzil_op_store_t RzILOpStore;

// Then define a union to union all of these struct
typedef union {
	RzILOpIte *ite;
	RzILOpVar *var;
	void *unk;

	void *b0;
	void *b1;
	RzILOpAnd_ *and_;
	RzILOpOr_ *or_;
	RzILOpInv *inv;

	RzILOpInt *int_;
	RzILOpMsb *msb;
	RzILOpLsb *lsb;
	RzILOpUle *ule;
	RzILOpSle *sle;
	RzILOpCast *cast;
	RzILOpNeg *neg;
	RzILOpNot *not_;
	RzILOpAdd *add;
	RzILOpSub *sub;
	RzILOpMul *mul;
	RzILOpDiv *div;
	RzILOpSdiv *sdiv;
	RzILOpSmod *smod;
	RzILOpMod *mod;
	RzILOpLogand *logand;
	RzILOpLogor *logor;
	RzILOpLogxor *logxor;
	RzILOpShiftl *shiftl;
	RzILOpShiftr *shiftr;

	RzILOpPerform *perform;
	RzILOpSet *set;
	RzILOpJmp *jmp;
	RzILOpGoto *goto_;
	RzILOpSeq *seq;
	RzILOpBlk *blk;
	RzILOpRepeat *repeat;
	RzILOpBranch *branch;

	RzILOpLoad *load;
	RzILOpStore *store;

	void *nil;
	// ... More
} _RzILOp;

struct RzILOp_t {
	ut64 id;
	RzILOPCode code;
	_RzILOp op;
};
// Opcode
RZ_API RzILOp *rz_il_new_op(RzILOPCode code);
RZ_API void rz_il_free_op(RzILOp *op);

#ifdef __cplusplus
}
#endif

#endif // RZIL_OPCODES_H
