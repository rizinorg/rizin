// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_OPCODES_H
#define RZ_IL_OPCODES_H

#include <rz_il/definitions/definitions.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
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

typedef struct rz_il_op_pure_t RzILOpPure;

typedef RzILOpPure RzILOpBool;
typedef RzILOpPure RzILOpBitVector;

typedef struct rz_il_op_effect_t RzILOpEffect;

/**
 * \brief value is a bitvector constant.
 *
 * In BAP: `int : 's Bitv.t Value.sort -> word -> 's bitv`
 */
typedef struct rz_il_op_args_bv_t {
	RzBitVector *value; ///< value of bitvector
} RzILOpArgsBv;

/**
 *  \brief op structure for `'s bitv -> bool`
 *  [MSB] msb x is the most significant bit of x.
 *  [LSB] lsb x is the least significant bit of x.
 *  [IS_ZERO] is_zero x holds if x is a bitvector of all zeros.
 */
struct rz_il_op_args_un_bv_b_t {
	RzILOpBitVector *bv;
};

typedef struct rz_il_op_args_un_bv_b_t RzILOpArgsMsb;
typedef struct rz_il_op_args_un_bv_b_t RzILOpArgsLsb;
typedef struct rz_il_op_args_un_bv_b_t RzILOpArgsIsZero;

/**
 * op structure for
 * `not` ('s bitv -> 's bitv)
 *   not x is one-complement negation.
 * `neg` ('s bitv -> 's bitv)
 *   neg x is two-complement unary minus
 */
struct rz_il_op_args_bv_unop_t {
	RzILOpBitVector *bv; ///< unary operand
};

typedef struct rz_il_op_args_bv_unop_t RzILOpArgsLogNot;
typedef struct rz_il_op_args_bv_unop_t RzILOpArgsNeg;

/**
 *  \brief op structure for two-operand algorithm and logical operations ('s bitv -> 's bitv -> 's bitv)
 *
 *  [ADD] add x y addition modulo 2^'s
 *  [SUB] sub x y subtraction modulo 2^'s
 *  [MUL] mul x y multiplication modulo 2^'s
 *  [DIV] div x y unsigned division modulo 2^'s truncating towards 0. The division by zero is defined to be a vector of all ones of size 's.
 *  [MOD] modulo x y is the remainder of div x y modulo 2^'s.
 *  [SDIV] sdiv x y is signed division of x by y modulo 2^'s.
 *  [SMOD] smodulo x y is the signed remainder of div x y modulo 2^'s.
 *  [LOGAND] logand x y is a bitwise logical and of x and y.
 *  [LOGOR] logor x y is a bitwise logical or of x and y.
 *  [LOGXOR] logxor x y is a bitwise logical xor of x and y.
 */
struct rz_il_op_args_alg_log_operations_t {
	RzILOpBitVector *x; ///< left operand
	RzILOpBitVector *y; ///< right operand
};

typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsAdd;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsSub;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsMul;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsDiv;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsSdiv;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsMod;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsSmod;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsLogand;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsLogor;
typedef struct rz_il_op_args_alg_log_operations_t RzILOpArgsLogxor;

/**
 *  \brief op structure for binary comparison ops ('a bitv -> 'a bitv -> bool)
 *
 *  [EQ] eq x y binary predicate for bitwise equality
 *  [SLE] sle x y binary predicate for singed less than or equal
 *  [ULE] ule x y binary predicate for unsigned less than or equal
 */
struct rz_il_op_args_cmp_t {
	RzILOpBitVector *x; ///< index of operand 1
	RzILOpBitVector *y; ///< index of operand 2
};

typedef struct rz_il_op_args_cmp_t RzILOpArgsEq;
typedef struct rz_il_op_args_cmp_t RzILOpArgsSle;
typedef struct rz_il_op_args_cmp_t RzILOpArgsUle;

/**
 *  \brief op structure for casting bitv
 */
typedef struct rz_il_op_args_cast_t {
	ut32 length; ///< new bits length
	RzILOpBool *fill; ///< If m = size val - length > 0 then m fill-bits are prepended to the most significant part of the vector.
	RzILOpBitVector *val; ///< value to cast
} RzILOpArgsCast;

/**
 *  \struct rz_il_op_args_append_t
 *  \brief op structure for appending 2 bitv: MSB:LSB high:low
 */
typedef struct rz_il_op_args_append_t {
	RzILOpBitVector *high; ///< bitvector occupying the most significant bits
	RzILOpBitVector *low; ///< bitvector occupying the least significant bits
} RzILOpArgsAppend;

/**
 *  \brief op structure for lshift and rshift (bool -> 's bitv -> 'b bitv -> 's bitv)
 *
 *  [LSHIFT] shiftl s x m shifts x left by m bits filling with s.
 *  [RSHIFT] shiftr s x m shifts x right by m bits filling with s.
 */
struct rz_il_op_args_shift_t {
	RzILOpBool *fill_bit; ///< index of fill bit
	RzILOpBitVector *x; ///< index of operand 1
	RzILOpBitVector *y; ///< index of operand 2
};

typedef struct rz_il_op_args_shift_t RzILOpArgsShiftLeft;
typedef struct rz_il_op_args_shift_t RzILOpArgsShiftRight;

/**
 * \brief op structure for `set` ('a var -> 'a pure -> data eff)
 *
 * set v x changes the value stored in v to the value of x.
 */
typedef struct rz_il_op_args_set_t {
	const char *v; ///< name of variable, const one
	bool is_local; ///< whether a global variable should be set or a local optionally created and set
	RzILOpPure *x; ///< value to set the variable to
} RzILOpArgsSet;

/**
 * \brief op structure for `let_ : 'a var -> 'a pure -> 'b pure -> 'b pure`
 *
 * `let_ v exp body` binds the value of exp to v body.
 */
typedef struct rz_il_op_args_let_t {
	const char *name; ///< name of variable
	RzILOpPure *exp; ///< value/expression to bind the variable to
	RzILOpPure *body; ///< body in which the variable will be bound and that produces the result
} RzILOpArgsLet;

/**
 *  \brief op structure for `jmp` (_ bitv -> ctrl eff)
 *
 *  jmp dst passes the control to a program located at dst.
 */
typedef struct rz_il_op_args_jmp_t {
	RzILOpBitVector *dst; ///< index of destination address
} RzILOpArgsJmp;

/**
 *  \brief op structure for `goto` (label -> ctrl eff)
 *
 *  goto lbl passes the control to a program labeled with lbl.
 */
typedef struct rz_il_op_args_goto_t {
	const char *lbl; ///< name of the label, const one
} RzILOpArgsGoto;

/**
 *  \brief op structure for `Seq` ('a eff -> 'a eff -> 'a eff)
 *
 *  seq x y performs effect x, after that perform effect y. Pack two effects into one.
 */
typedef struct rz_il_op_args_seq_t {
	RzILOpEffect *x; ///< perform this first
	RzILOpEffect *y; ///< perform this second
} RzILOpArgsSeq;

/**
 *  \brief op structure for `blk` (label -> data eff -> ctrl eff -> unit eff)
 *
 *  blk lbl data ctrl a labeled sequence of effects.
 */
typedef struct rzil_op_blk_t {
	const char *label; ///< name of the label, const one
	RzILOpEffect *data_eff; ///< index of data_eff
	RzILOpEffect *ctrl_eff; ///< index of ctrl_eff
} RzILOpArgsBlk;

/**
 *  \brief op structure for `repeat` (bool -> data eff -> data eff)
 *
 *  repeat c data repeats data effects till the condition c holds.
 */
typedef struct rzil_op_repeat_t {
	RzILOpBool *condition; ///< index of BOOL condition
	RzILOpEffect *data_eff; ///< index of data effect
} RzILOpArgsRepeat;

/**
 *  \brief op structure for `branch` (bool -> 'a eff -> 'a eff -> 'a eff)
 *
 *  branch c lhs rhs if c holds then performs lhs else rhs.
 */
typedef struct rz_il_op_args_branch_t {
	RzILOpBool *condition;
	RZ_NONNULL RzILOpEffect *true_eff; ///< effect for when condition evaluates to true
	RZ_NONNULL RzILOpEffect *false_eff; ///< effect for when condition evaluates to false
} RzILOpArgsBranch;

/**
 *  \brief op structure for `ite` (bool -> 'a pure -> 'a pure -> 'a pure)
 *
 *  ite c x y is x if c evaluates to b1 else y.
 */
typedef struct rz_il_op_args_ite_t {
	RzILOpBool *condition; ///< index of BOOL condition
	RzILOpPure *x; ///< index of RzILVal operand 1
	RzILOpPure *y; ///< index of RzILVal operand 2
} RzILOpArgsIte;

/**
 *  \brief op structure for `var` ('a var -> 'a pure)
 *
 *  var v is the value of the variable v.
 */
typedef struct rz_il_op_args_var_t {
	const char *v; ///< name of variable, const one
	RzILVarKind kind; ///< set of variables to pick from
} RzILOpArgsVar;

/**
 *  \brief op structure for `and`, `or` and `xor` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val and_ : bool -> bool -> bool
 *    val or_ : bool -> bool -> bool
 *  and(x, y) is a conjunction of x and y.
 *  or(x, y)  is a conjunction of x or y.
 *  xor(x, y) is a conjunction of x xor y.
 */
struct rz_il_op_args_bool_operation_t {
	RzILOpBool *x; ///< left operand
	RzILOpBool *y; ///< right operand
};

typedef struct rz_il_op_args_bool_operation_t RzILOpArgsBoolAnd;
typedef struct rz_il_op_args_bool_operation_t RzILOpArgsBoolOr;
typedef struct rz_il_op_args_bool_operation_t RzILOpArgsBoolXor;

/**
 *  \brief op structure for `inv` (!bool -> bool)
 *
 *	BAP equivalent:
 *	  val inv : bool -> bool
 *  inv(x) inverts x (also known as not operation).
 */
struct rz_il_op_args_bool_inv_t {
	RzILOpBool *x; ///< single operand
};

typedef struct rz_il_op_args_bool_inv_t RzILOpArgsBoolInv;

/**
 *  \brief op structure for `load` (('a, 'b) mem -> 'a bitv -> 'b bitv)
 *
 *  load m k is the value associated with the key k in the memory m.
 */
typedef struct rz_il_op_args_load_t {
	RzILMemIndex mem; ///< index of the mem inside the vm to use
	RzILOpBitVector *key; ///< index of the cell (address) in mem, must have exactly the size of a key in the memory
} RzILOpArgsLoad;

/**
 *  \brief op structure for `store` (('a, 'b) mem -> 'a bitv -> 'b bitv -> ('a, 'b) mem)
 *
 *  store m k x a memory m in which the key k is associated with the word x.
 */
typedef struct rz_il_op_args_store_t {
	RzILMemIndex mem; ///< index of memory in the vm to use
	RzILOpBitVector *key; ///< address where to store to, must have exactly the size of a key in the memory
	RzILOpBitVector *value; ///< value to store, must have exactly the size of a memory cell
} RzILOpArgsStore;

/**
 * \brief Load an entire word of arbitrary bit size from a memory
 *
 * Endianness is determined by the vm
 */
typedef struct rz_il_op_args_loadw_t {
	RzILMemIndex mem; ///< index of the mem inside the vm to use
	RzILOpBitVector *key; ///< memory index of the RzBitVector key (address)
	ut32 n_bits; ///< n of bits to read, and of the resulting bitvector
} RzILOpArgsLoadW;

/**
 * \brief Store an entire word of arbitrary bit size into a memory
 *
 * Endianness is determined by the vm
 */
typedef struct rz_il_op_args_storew_t {
	RzILMemIndex mem; ///< index of memory in the vm to use
	RzILOpBitVector *key; ///< address where to store to
	RzILOpBitVector *value; ///< value to store, arbitrary size
} RzILOpArgsStoreW;

/////////////////////////////
// Opcodes of type 'a pure //

typedef enum {
	// Init
	RZ_IL_OP_VAR,
	RZ_IL_OP_ITE,
	RZ_IL_OP_LET,

	// RzILBool
	RZ_IL_OP_B0,
	RZ_IL_OP_B1,
	RZ_IL_OP_INV,
	RZ_IL_OP_AND,
	RZ_IL_OP_OR,
	RZ_IL_OP_XOR,

	// RzBitVector
	RZ_IL_OP_BITV,
	RZ_IL_OP_MSB,
	RZ_IL_OP_LSB,
	RZ_IL_OP_IS_ZERO,
	RZ_IL_OP_NEG,
	RZ_IL_OP_LOGNOT,
	RZ_IL_OP_ADD,
	RZ_IL_OP_SUB,
	RZ_IL_OP_MUL,
	RZ_IL_OP_DIV,
	RZ_IL_OP_SDIV,
	RZ_IL_OP_MOD,
	RZ_IL_OP_SMOD,
	RZ_IL_OP_LOGAND,
	RZ_IL_OP_LOGOR,
	RZ_IL_OP_LOGXOR,
	RZ_IL_OP_SHIFTR,
	RZ_IL_OP_SHIFTL,
	RZ_IL_OP_EQ,
	RZ_IL_OP_SLE,
	RZ_IL_OP_ULE,
	RZ_IL_OP_CAST,
	RZ_IL_OP_APPEND,
	// ...

	// Memory
	RZ_IL_OP_LOAD,
	RZ_IL_OP_LOADW,

	RZ_IL_OP_PURE_MAX
} RzILOpPureCode;

/**
 * \brief An IL op performing a pure computation, 'a pure
 *
 * BAP uses ocaml's type system for statically differentiating between different
 * kinds of pure ops. Some ops however are polymorphic over all pure types,
 * such as `ite : bool -> 'a pure -> 'a pure -> 'a pure`, which is not directly possible in C.
 * So our pure ops are dynamically typed (only on the level of C, the IL is still fully statically typed)
 * and we simply use typedefs like `RzILOpBool` and `RzILOpBitVector` to at least weakly indicate which concrete type is required.
 */
struct rz_il_op_pure_t {
	RzILOpPureCode code;
	union {
		RzILOpArgsIte ite;
		RzILOpArgsVar var;
		RzILOpArgsLet let;

		RzILOpArgsBoolAnd booland;
		RzILOpArgsBoolOr boolor;
		RzILOpArgsBoolXor boolxor;
		RzILOpArgsBoolInv boolinv;

		RzILOpArgsBv bitv;
		RzILOpArgsMsb msb;
		RzILOpArgsLsb lsb;
		RzILOpArgsIsZero is_zero;
		RzILOpArgsEq eq;
		RzILOpArgsUle ule;
		RzILOpArgsSle sle;
		RzILOpArgsCast cast;
		RzILOpArgsNeg neg;
		RzILOpArgsLogNot lognot;
		RzILOpArgsAdd add;
		RzILOpArgsSub sub;
		RzILOpArgsMul mul;
		RzILOpArgsDiv div;
		RzILOpArgsSdiv sdiv;
		RzILOpArgsSmod smod;
		RzILOpArgsMod mod;
		RzILOpArgsLogand logand;
		RzILOpArgsLogor logor;
		RzILOpArgsLogxor logxor;
		RzILOpArgsShiftLeft shiftl;
		RzILOpArgsShiftRight shiftr;
		RzILOpArgsAppend append;

		RzILOpArgsLoad load;
		RzILOpArgsLoadW loadw;
	} op;
};

RZ_API void rz_il_op_pure_free(RZ_NULLABLE RzILOpPure *op);
RZ_API RzILOpPure *rz_il_op_pure_dup(RZ_NONNULL RzILOpPure *op);

RZ_API RZ_OWN RzILOpPure *rz_il_op_new_ite(RZ_NONNULL RzILOpPure *condition, RZ_NULLABLE RzILOpPure *x, RZ_NULLABLE RzILOpPure *y);
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_var(RZ_NONNULL const char *var, RzILVarKind kind);
RZ_API RZ_OWN RzILOpPure *rz_il_op_new_let(RZ_NONNULL const char *name, RZ_NONNULL RzILOpPure *exp, RZ_NONNULL RzILOpPure *body);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_b0();
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_b1();
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_and(RZ_NONNULL RzILOpBool *x, RZ_NONNULL RzILOpBool *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_or(RZ_NONNULL RzILOpBool *x, RZ_NONNULL RzILOpBool *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_xor(RZ_NONNULL RzILOpBool *x, RZ_NONNULL RzILOpBool *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bool_inv(RZ_NONNULL RzILOpBool *x);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_bitv(RZ_NONNULL RzBitVector *value);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_bitv_from_ut64(ut32 length, ut64 number);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_bitv_from_st64(ut32 length, st64 number);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_bitv_max(ut32 length);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_msb(RZ_NONNULL RzILOpPure *val);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_lsb(RZ_NONNULL RzILOpPure *val);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_zero(RZ_NONNULL RzILOpPure *bv);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_non_zero(RZ_NONNULL RzILOpPure *bv);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_eq(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_ule(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_sle(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_ult(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_slt(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_uge(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_sge(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_ugt(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_sgt(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_cast(ut32 length, RZ_NONNULL RzILOpBool *fill, RZ_NONNULL RzILOpBitVector *val);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_unsigned(ut32 length, RZ_NONNULL RzILOpBitVector *val); // "zero extension"
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_signed(ut32 length, RZ_NONNULL RzILOpBitVector *val); // "sign extension"
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_neg(RZ_NONNULL RzILOpBitVector *value);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_not(RZ_NONNULL RzILOpBitVector *value);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_add(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_sub(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_mul(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_div(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_sdiv(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_smod(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_mod(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_and(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_or(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_log_xor(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_shiftl(RZ_NONNULL RzILOpBool *fill_bit, RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *sh);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_shiftr(RZ_NONNULL RzILOpBool *fill_bit, RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *sh);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_shiftr_arith(RZ_NONNULL RzILOpBitVector *x, RZ_NONNULL RzILOpBitVector *y);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_append(RZ_NONNULL RzILOpBitVector *high, RZ_NONNULL RzILOpBitVector *low);

RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_load(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_loadw(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key, ut32 n_bits);

///////////////////////////////
// Opcodes of type 'a effect //

typedef enum {
	RZ_IL_OP_STORE,
	RZ_IL_OP_STOREW,

	RZ_IL_OP_EMPTY,
	RZ_IL_OP_NOP,
	RZ_IL_OP_SET,
	RZ_IL_OP_JMP,
	RZ_IL_OP_GOTO,
	RZ_IL_OP_SEQ,
	RZ_IL_OP_BLK,
	RZ_IL_OP_REPEAT,
	RZ_IL_OP_BRANCH,

	RZ_IL_OP_EFFECT_MAX
} RzILOpEffectCode;

struct rz_il_op_effect_t {
	RzILOpEffectCode code;
	union {
		RzILOpArgsSet set;
		RzILOpArgsJmp jmp;
		RzILOpArgsGoto goto_;
		RzILOpArgsSeq seq;
		RzILOpArgsBlk blk;
		RzILOpArgsRepeat repeat;
		RzILOpArgsBranch branch;

		RzILOpArgsStore store;
		RzILOpArgsStoreW storew;
	} op;
};

RZ_API void rz_il_op_effect_free(RZ_NULLABLE RzILOpEffect *op);

RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_empty();
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_nop();
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_set(RZ_NONNULL const char *v, bool is_local, RZ_NONNULL RzILOpPure *x);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_jmp(RZ_NONNULL RzILOpBitVector *dst);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_goto(RZ_NONNULL const char *label);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_seq(RZ_NONNULL RzILOpEffect *x, RZ_NONNULL RzILOpEffect *y);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_seqn(ut32 n, ...);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_blk(RZ_NONNULL const char *label, RZ_NONNULL RzILOpEffect *data_effect, RZ_NONNULL RzILOpEffect *ctrl_effect);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_repeat(RZ_NONNULL RzILOpBool *condition, RZ_NONNULL RzILOpEffect *data_effect);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_branch(RZ_NONNULL RzILOpBool *condition, RZ_NULLABLE RzILOpEffect *true_effect, RZ_NULLABLE RzILOpEffect *false_effect);

RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_store(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key, RZ_NONNULL RzILOpBitVector *value);
RZ_API RZ_OWN RzILOpEffect *rz_il_op_new_storew(RzILMemIndex mem, RZ_NONNULL RzILOpBitVector *key, RZ_NONNULL RzILOpBitVector *value);

// Printing/Export
RZ_API RZ_NONNULL const char *rz_il_op_pure_code_stringify(RzILOpPureCode code);

RZ_API void rz_il_op_pure_stringify(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzStrBuf *sb);
RZ_API void rz_il_op_effect_stringify(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL RzStrBuf *sb);

RZ_API void rz_il_op_pure_json(RZ_NONNULL RzILOpPure *op, RZ_NONNULL PJ *pj);
RZ_API void rz_il_op_effect_json(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL PJ *pj);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_OPCODES_H
