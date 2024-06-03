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
typedef RzILOpPure RzILOpFloat;

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

/**
 * \brief value for a float constant
 * `float s x` interprets x as a floating-point number in format s.
 * In BAP : `( 'r, 's ) format Float.t Value.sort -> 's bitv -> ( 'r, 's ) format float
 */
typedef struct rz_il_op_args_float_t {
	RzFloatFormat r;
	RzILOpBitVector *bv;
} RzILOpArgsFloat;

/**
 * \brief op structure for unary without rmode
 */
struct rz_il_op_args_float_unary_t {
	RzILOpFloat *f;
};

/**
 * \brief opstructure for fbits : ( 'r, 's ) format float -> 's bitv
 * fbits x is a bitvector representation of the floating-point number x.
 */
typedef struct rz_il_op_args_float_unary_t RzILOpArgsFbits;

/**
 * \brief op structure for 'f float -> bool
 * [IS_FINITE] is_finite x holds if x represents a finite number.
 * [IS_NAN] is_nan x holds if x represents a not-a-number (NaN).
 * [IS_INF] is_inf x holds if x represents an infinite number.
 * [IS_FZERO] is_fzero x holds if x represents a zero.
 * [IS_FNEG] is_fpos x holds if x represents a positive number.
 * [IS_FPOS] is_fneg x hold if x represents a negative number.
 */
typedef struct rz_il_op_args_float_unary_t RzILOpArgsIsFinite;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsIsNan;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsIsInf;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsIsFzero;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsIsFpos;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsIsFneg;

/**
 * op structure for 'f float -> float
 * [FNEG] fneg x is -x
 * [FABS] fabs x is absolute value of x (|x|)
 * [FSUCC] fsucc x is the least floating-point number representable in (sort x) that is greater than x.
 * [FPRED] fpred x is the greatest floating-point number representable in (sort x) that is less than x.
 */
typedef struct rz_il_op_args_float_unary_t RzILOpArgsFneg;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsFabs;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsFsucc;
typedef struct rz_il_op_args_float_unary_t RzILOpArgsFpred;

/**
 * \brief op structure for cast to bv from float
 * [FCAST_INT] `f_cast_int s rm x` returns an integer closest to x.
 * [FCAST_SINT] `f_cast_sint s rm x` returns an integer closest to x.
 */
struct rz_il_op_args_float_cast_int_t {
	ut32 length;
	RzFloatRMode mode;
	RzILOpFloat *f;
};

typedef struct rz_il_op_args_float_cast_int_t RzILOpArgsFCastint;
typedef struct rz_il_op_args_float_cast_int_t RzILOpArgsFCastsint;

/**
 * \brief for cast to float from bv
 * 'f Float.t Value.sort -> rmode -> 'a bitv -> 'f float
 * [FCAST_FLOAT] `cast_float s rm x` is the closest to x floating-point number of sort x.
 * 	note that : The bitvector x is interpreted as an unsigned integer in the two-complement form.
 * [FCAST_SFLOAT] `cast_sfloat s rm x` is the closest to x floating-point number of sort x.
 * 	note that : The bitvector x is interpreted as a signed integer in the two-complement form.
 */
struct rz_il_op_args_float_cast_float_t {
	RzFloatFormat format;
	RzFloatRMode mode;
	RzILOpBitVector *bv;
};

typedef struct rz_il_op_args_float_cast_float_t RzILOpArgsFCastfloat;
typedef struct rz_il_op_args_float_cast_float_t RzILOpArgsFCastsfloat;

/**
 * \brief convert between different float format
 * 'f Float.t Value.sort -> rmode -> _ float -> 'f float
 * [FCONVERT] `fconvert f r x` is the closest to x floating number in format f.
 */
struct rz_il_op_args_float_fconvert_t {
	RzFloatFormat format;
	RzFloatRMode mode;
	RzILOpFloat *f;
};
typedef struct rz_il_op_args_float_fconvert_t RzILOpArgsFconvert;

/**
 * \brief op structure of requal
 *  rmode -> rmode -> bool
 * requal x y holds if rounding modes are equal.
 */
typedef struct rz_il_op_args_float_requal_t {
	RzFloatRMode x;
	RzFloatRMode y;
} RzILOpArgsFrequal;

/**
 * \brief op structure of binary op without rmode
 * ('float -> 'flaat -> bool)
 * forder x y holds if floating-point number x is less than y.
 */
typedef struct rz_il_op_args_float_binop_t {
	RzILOpFloat *x;
	RzILOpFloat *y;
} RzILOpArgsForder;

/**
 * \brief op structure for float operation (unary op with rmode)
 * `rmode -> 'f float -> 'f float`
 * [FROUND]
 * [FSQRT] fsqrt m x returns the closest floating-point number to r, where r is such number that r*r is equal to x.
 * [FRSQRT] reverse sqrt, rsqrt m x is the closest floating-point number to 1 / sqrt x.
 */
struct rz_il_op_args_float_alg_unop_t {
	RzFloatRMode rmode;
	RzILOpFloat *f;
};
typedef struct rz_il_op_args_float_alg_unop_t RzILOpArgsFround;
typedef struct rz_il_op_args_float_alg_unop_t RzILOpArgsFsqrt;
typedef struct rz_il_op_args_float_alg_unop_t RzILOpArgsFrsqrt;

/**
 * \brief op structure for float basic arithmetic operations (binary op with rmode)
 * rmode -> 'f float -> 'f float -> 'f float
 * [FADD]
 */
struct rz_il_op_args_float_alg_binop_t {
	RzFloatRMode rmode;
	RzILOpFloat *x;
	RzILOpFloat *y;
};

typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFadd;
typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFsub;
typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFmul;
typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFdiv;
typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFmod;
typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFhypot;
typedef struct rz_il_op_args_float_alg_binop_t RzILOpArgsFpow;

/**
 * \brief op structure of ternary op in float
 * rmode -> 'f float -> 'f float -> 'f float -> 'f float
 */
struct rz_il_op_args_float_alg_terop_t {
	RzFloatRMode rmode;
	RzILOpFloat *x;
	RzILOpFloat *y;
	RzILOpFloat *z;
};
typedef struct rz_il_op_args_float_alg_terop_t RzILOpArgsFmad;

/**
 * \brief op structure for some float binary op requiring `int`
 * rmode -> 'f float -> 'a bitv -> 'f float
 */
struct rz_il_op_args_float_alg_hybrid_binop_t {
	RzFloatRMode rmode;
	RzILOpFloat *f;
	RzILOpBitVector *n;
};

typedef struct rz_il_op_args_float_alg_hybrid_binop_t RzILOpArgsFrootn;
typedef struct rz_il_op_args_float_alg_hybrid_binop_t RzILOpArgsFpown;
typedef struct rz_il_op_args_float_alg_hybrid_binop_t RzILOpArgsFcompound;

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

	// RzILFloat
	RZ_IL_OP_FLOAT,
	RZ_IL_OP_FBITS,
	RZ_IL_OP_IS_FINITE,
	RZ_IL_OP_IS_NAN,
	RZ_IL_OP_IS_INF,
	RZ_IL_OP_IS_FZERO,
	RZ_IL_OP_IS_FNEG,
	RZ_IL_OP_IS_FPOS,
	RZ_IL_OP_FNEG,
	RZ_IL_OP_FABS,
	RZ_IL_OP_FCAST_INT,
	RZ_IL_OP_FCAST_SINT,
	RZ_IL_OP_FCAST_FLOAT,
	RZ_IL_OP_FCAST_SFLOAT,
	RZ_IL_OP_FCONVERT,
	RZ_IL_OP_FREQUAL,
	RZ_IL_OP_FSUCC,
	RZ_IL_OP_FPRED,
	RZ_IL_OP_FORDER,
	RZ_IL_OP_FROUND,
	RZ_IL_OP_FSQRT,
	RZ_IL_OP_FRSQRT,
	RZ_IL_OP_FADD,
	RZ_IL_OP_FSUB,
	RZ_IL_OP_FMUL,
	RZ_IL_OP_FDIV,
	RZ_IL_OP_FMOD,
	RZ_IL_OP_FHYPOT,
	RZ_IL_OP_FPOW,
	RZ_IL_OP_FMAD,
	RZ_IL_OP_FROOTN,
	RZ_IL_OP_FPOWN,
	RZ_IL_OP_FCOMPOUND,
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

		RzILOpArgsFloat float_;
		RzILOpArgsFbits fbits;
		RzILOpArgsIsFinite is_finite;
		RzILOpArgsIsNan is_nan;
		RzILOpArgsIsInf is_inf;
		RzILOpArgsIsFzero is_fzero;
		RzILOpArgsIsFneg is_fneg;
		RzILOpArgsIsFpos is_fpos;
		RzILOpArgsFneg fneg;
		RzILOpArgsFabs fabs;
		RzILOpArgsFCastint fcast_int;
		RzILOpArgsFCastsint fcast_sint;
		RzILOpArgsFCastfloat fcast_float;
		RzILOpArgsFCastsfloat fcast_sfloat;
		RzILOpArgsFconvert fconvert;
		RzILOpArgsFrequal frequal;
		RzILOpArgsFsucc fsucc;
		RzILOpArgsFpred fpred;
		RzILOpArgsForder forder;
		RzILOpArgsFround fround;
		RzILOpArgsFsqrt fsqrt;
		RzILOpArgsFrsqrt frsqrt;
		RzILOpArgsFadd fadd;
		RzILOpArgsFsub fsub;
		RzILOpArgsFmul fmul;
		RzILOpArgsFdiv fdiv;
		RzILOpArgsFmod fmod;
		RzILOpArgsFmad fmad;
		RzILOpArgsFpow fpow;
		RzILOpArgsFpown fpown;
		RzILOpArgsFrootn frootn;
		RzILOpArgsFcompound fcompound;
		RzILOpArgsFhypot fhypot;
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

RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_float_from_rz_float(RZ_NONNULL RZ_OWN RzFloat *fl);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_float(RzFloatFormat format, RZ_NONNULL RzILOpBitVector *bv);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_float_from_f32(float f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_float_from_f64(double f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_float_from_f80(long double f);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_fbits(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_finite(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_nan(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_inf(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_fzero(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_fneg(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_is_fpos(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fneg(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fabs(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_fcast_int(ut32 length, RzFloatRMode mode, RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBitVector *rz_il_op_new_fcast_sint(ut32 length, RzFloatRMode mode, RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fcast_float(RzFloatFormat format, RzFloatRMode mode, RZ_NONNULL RzILOpBitVector *bv);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fcast_sfloat(RzFloatFormat format, RzFloatRMode mode, RZ_NONNULL RzILOpBitVector *bv);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fconvert(RzFloatFormat format, RzFloatRMode mode, RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_frequal(RzFloatRMode x, RzFloatRMode y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fsucc(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fpred(RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_forder(RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fround(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fsqrt(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_frsqrt(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *f);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fadd(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fsub(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fmul(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fdiv(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fmod(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fhypot(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fpow(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fmad(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpFloat *y, RZ_NONNULL RzILOpFloat *z);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_frootn(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpBitVector *n);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fpown(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpBitVector *n);
RZ_API RZ_OWN RzILOpFloat *rz_il_op_new_fcompound(RzFloatRMode rmode, RZ_NONNULL RzILOpFloat *x, RZ_NONNULL RzILOpBitVector *n);

RZ_API RZ_OWN RzILOpBitVector *rz_il_extract32(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length);
RZ_API RZ_OWN RzILOpBitVector *rz_il_extract64(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length);
RZ_API RZ_OWN RzILOpBitVector *rz_il_sextract32(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length);
RZ_API RZ_OWN RzILOpBitVector *rz_il_sextract64(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length);
RZ_API RZ_OWN RzILOpBitVector *rz_il_deposit64(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length, RZ_BORROW RzILOpBitVector *fieldval);
RZ_API RZ_OWN RzILOpBitVector *rz_il_deposit32(RZ_BORROW RzILOpBitVector *value, RZ_BORROW RzILOpBitVector *start, RZ_BORROW RzILOpBitVector *length, RZ_BORROW RzILOpBitVector *fieldval);
RZ_API RZ_OWN RzILOpBitVector *rz_il_bswap16(RZ_BORROW RzILOpBitVector *t);
RZ_API RZ_OWN RzILOpBitVector *rz_il_bswap32(RZ_BORROW RzILOpBitVector *t);
RZ_API RZ_OWN RzILOpBitVector *rz_il_bswap64(RZ_BORROW RzILOpBitVector *t);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_ne(RZ_NONNULL RzILOpPure *x, RZ_NONNULL RzILOpPure *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fneq(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_feq(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_flt(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fle(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fgt(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y);
RZ_API RZ_OWN RzILOpBool *rz_il_op_new_fge(RZ_NONNULL RZ_OWN RzILOpFloat *x, RZ_NONNULL RZ_OWN RzILOpFloat *y);

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

RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_il_op_pure_graph(RZ_NONNULL RzILOpPure *op, RZ_NULLABLE const char *name);
RZ_API RZ_OWN RzGraph /*<RzGraphNodeInfo *>*/ *rz_il_op_effect_graph(RZ_NONNULL RzILOpEffect *op, RZ_NULLABLE const char *name);

RZ_API void rz_il_op_pure_stringify(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzStrBuf *sb, bool pretty);
RZ_API void rz_il_op_effect_stringify(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL RzStrBuf *sb, bool pretty);

RZ_API void rz_il_op_pure_json(RZ_NONNULL RzILOpPure *op, RZ_NONNULL PJ *pj);
RZ_API void rz_il_op_effect_json(RZ_NONNULL RzILOpEffect *op, RZ_NONNULL PJ *pj);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_OPCODES_H
