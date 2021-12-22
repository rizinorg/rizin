// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_OPCODES_H
#define RZIL_OPCODES_H

#include <rz_il/definitions/definitions.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rz_il_op_t RzILOp;
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
 *  \struct rzil_op_bv_t
 *  \brief op structure for bitvector
 *
 *  value is a bitvector constant.
 */
struct rzil_op_bv_t {
	RzBitVector *value; ///< value of bitvector
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
struct rzil_op_logical_not_t {
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
 *  [SMOD] smodulo x y is the signed remainder of div x y modulo 2^'s.
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
 *  \struct rzil_op_append_t
 *  \brief op structure for appending 2 bitv: MSB:LSB bv1:bv2
 */
struct rzil_op_append_t {
	RzILOp *x; ///< index of the bv 1
	RzILOp *y; ///< index of the bv 2
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
 *  \struct rzil_op_let_t
 *  \brief op structure for `set` ('a var -> 'a pure -> data eff)
 *
 *  set v x changes the value stored in v to the value of x.
 */
struct rzil_op_let_t {
	const char *v; ///< name of variable, const one
	bool mut; ///< define is local variable is const or not
	RzILOp *x; ///< index of RzILVal
};

/**
 *  \struct rzil_op_jmp_t
 *  \brief op structure for `jmp` (_ bitv -> ctrl eff)
 *
 *  jmp dst passes the control to a program located at dst.
 */
struct rzil_op_jmp_t {
	RzILOp *dst; ///< index of destination address (RzBitVector)
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
 *  \struct rzil_op_bool_operation_t
 *  \brief op structure for `and`, `or` and `xor` (bool -> bool -> bool)
 *
 *  BAP equivalent:
 *    val and_ : bool -> bool -> bool
 *    val or_ : bool -> bool -> bool
 *  and(x, y) is a conjunction of x and y.
 *  or(x, y)  is a conjunction of x or y.
 *  xor(x, y) is a conjunction of x xor y.
 */
struct rzil_op_bool_operation_t {
	RzILOp *x; ///< index of the BOOL operand
	RzILOp *y; ///< index of the BOOL operand
};

/**
 *  \struct rzil_op_bool_inv_t
 *  \brief op structure for `inv` (!bool -> bool)
 *
 *	BAP equivalent:
 *	  val inv : bool -> bool
 *  inv(x) inverts x (also known as not operation).
 */
struct rzil_op_bool_inv_t {
	RzILOp *x; ///< index of the BOOL operand
};

/**
 *  \struct rzil_op_load_t
 *  \brief op structure for `load` (('a, 'b) mem -> 'a bitv -> 'b bitv)
 *
 *  load m k is the value associated with the key k in the memory m.
 */
typedef struct rzil_op_load_t {
	RzILMemIndex mem; ///< index of the mem inside the vm to use
	RzILOp *key; ///< memory index of the RzBitVector key (address), must have exactly the size of a key in the memory
} RzILOpLoad;

/**
 *  \struct rzil_op_store_t
 *  \brief op structure for `store` (('a, 'b) mem -> 'a bitv -> 'b bitv -> ('a, 'b) mem)
 *
 *  store m k x a memory m in which the key k is associated with the word x.
 */
typedef struct rzil_op_store_t {
	RzILMemIndex mem; ///< index of memory in the vm to use
	RzILOp *key; ///< address where to store to, must have exactly the size of a key in the memory
	RzILOp *value; ///< value to store, must have exactly the size of a memory cell
} RzILOpStore;

/**
 * \brief Load an entire word of arbitrary bit size from a memory
 *
 * Endianness is determined by the vm
 */
typedef struct rzil_op_loadw_t {
	RzILMemIndex mem; ///< index of the mem inside the vm to use
	RzILOp *key; ///< memory index of the RzBitVector key (address)
	ut32 n_bits; ///< n of bits to read, and of the resulting bitvector
} RzILOpLoadW;

/**
 * \brief Store an entire word of arbitrary bit size into a memory
 *
 * Endianness is determined by the vm
 */
typedef struct rzil_op_storew_t {
	RzILMemIndex mem; ///< index of memory in the vm to use
	RzILOp *key; ///< address where to store to
	RzILOp *value; ///< value to store, arbitrary size
} RzILOpStoreW;

typedef enum {
	// Init
	RZIL_OP_VAR,
	RZIL_OP_UNK,
	RZIL_OP_ITE,

	// RzILBool
	RZIL_OP_B0,
	RZIL_OP_B1,
	RZIL_OP_INV,
	RZIL_OP_AND,
	RZIL_OP_OR,
	RZIL_OP_XOR,

	// RzBitVector
	RZIL_OP_BITV,
	RZIL_OP_MSB,
	RZIL_OP_LSB,
	RZIL_OP_NEG,
	RZIL_OP_LOGNOT,
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
	RZIL_OP_LOADW,
	RZIL_OP_STOREW,

	// Effects (opcode with side effects)
	RZIL_OP_NOP,
	RZIL_OP_SET,
	RZIL_OP_LET,
	RZIL_OP_JMP,
	RZIL_OP_GOTO,
	RZIL_OP_SEQ,
	RZIL_OP_BLK,
	RZIL_OP_REPEAT,
	RZIL_OP_BRANCH,

	RZIL_OP_INVALID,
	RZIL_OP_MAX,
} RzILOpCode;

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
typedef struct rzil_op_logical_not_t RzILOpLogNot;
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
typedef struct rzil_op_shift_t RzILOpShiftLeft;
typedef struct rzil_op_shift_t RzILOpShiftRight;
typedef struct rzil_op_bv_t RzILOpBv;
typedef struct rzil_op_append_t RzILOpAppend;

typedef struct rzil_op_bool_operation_t RzILOpBoolAnd;
typedef struct rzil_op_bool_operation_t RzILOpBoolOr;
typedef struct rzil_op_bool_operation_t RzILOpBoolXor;
typedef struct rzil_op_bool_inv_t RzILOpBoolInv;

typedef struct rzil_op_set_t RzILOpSet;
typedef struct rzil_op_let_t RzILOpLet;
typedef struct rzil_op_jmp_t RzILOpJmp;
typedef struct rzil_op_goto_t RzILOpGoto;
typedef struct rzil_op_seq_t RzILOpSeq;
typedef struct rzil_op_blk_t RzILOpBlk;
typedef struct rzil_op_repeat_t RzILOpRepeat;
typedef struct rzil_op_branch_t RzILOpBranch;

// Then define a union to union all of these struct
typedef union {
	RzILOpIte *ite;
	RzILOpVar *var;

	RzILOpBoolAnd *booland;
	RzILOpBoolOr *boolor;
	RzILOpBoolXor *boolxor;
	RzILOpBoolInv *boolinv;

	RzILOpBv *bitv;
	RzILOpMsb *msb;
	RzILOpLsb *lsb;
	RzILOpUle *ule;
	RzILOpSle *sle;
	RzILOpCast *cast;
	RzILOpNeg *neg;
	RzILOpLogNot *lognot;
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
	RzILOpShiftLeft *shiftl;
	RzILOpShiftRight *shiftr;
	RzILOpAppend *append;

	RzILOpSet *set;
	RzILOpLet *let;
	RzILOpJmp *jmp;
	RzILOpGoto *goto_;
	RzILOpSeq *seq;
	RzILOpBlk *blk;
	RzILOpRepeat *repeat;
	RzILOpBranch *branch;

	RzILOpLoad *load;
	RzILOpStore *store;
	RzILOpLoadW *loadw;
	RzILOpStoreW *storew;
} RzILOpUnion;

struct rz_il_op_t {
	RzILOpCode code;
	RzILOpUnion op;
};

// Opcode
RZ_API void rz_il_op_free(RZ_NULLABLE RzILOp *op);

RZ_API RZ_OWN RzILOp *rz_il_op_new_ite(RZ_NONNULL RzILOp *condition, RZ_NULLABLE RzILOp *x, RZ_NULLABLE RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_unk();
RZ_API RZ_OWN RzILOp *rz_il_op_new_var(RZ_NONNULL const char *var);
RZ_API RZ_OWN RzILOp *rz_il_op_new_b0();
RZ_API RZ_OWN RzILOp *rz_il_op_new_b1();
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_and(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_or(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_xor(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_bool_inv(RZ_NONNULL RzILOp *x);
RZ_API RZ_OWN RzILOp *rz_il_op_new_bitv(RZ_NONNULL RzBitVector *value);
RZ_API RZ_OWN RzILOp *rz_il_op_new_bitv_from_ut64(ut32 length, ut64 number);
RZ_API RZ_OWN RzILOp *rz_il_op_new_bitv_from_st64(ut32 length, st64 number);
RZ_API RZ_OWN RzILOp *rz_il_op_new_msb(RZ_NONNULL RzILOp *val);
RZ_API RZ_OWN RzILOp *rz_il_op_new_lsb(RZ_NONNULL RzILOp *val);
RZ_API RZ_OWN RzILOp *rz_il_op_new_ule(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_sle(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_cast(ut32 length, int shift, RZ_NONNULL RzILOp *val);
RZ_API RZ_OWN RzILOp *rz_il_op_new_neg(RZ_NONNULL RzILOp *value);
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_not(RZ_NONNULL RzILOp *value);
RZ_API RZ_OWN RzILOp *rz_il_op_new_add(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_sub(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_mul(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_div(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_sdiv(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_smod(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_mod(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_and(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_or(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_log_xor(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_shiftl(RZ_NONNULL RzILOp *fill_bit, RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_shiftr(RZ_NONNULL RzILOp *fill_bit, RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_append(RZ_NONNULL RzILOp *high, RZ_NONNULL RzILOp *low);
RZ_API RZ_OWN RzILOp *rz_il_op_new_nop();
RZ_API RZ_OWN RzILOp *rz_il_op_new_set(RZ_NONNULL const char *var, RZ_NONNULL RzILOp *x);
RZ_API RZ_OWN RzILOp *rz_il_op_new_let(RZ_NONNULL const char *var, RZ_NONNULL RzILOp *x, bool is_mutable);
RZ_API RZ_OWN RzILOp *rz_il_op_new_jmp(RZ_NONNULL RzILOp *dst);
RZ_API RZ_OWN RzILOp *rz_il_op_new_goto(RZ_NONNULL const char *label);
RZ_API RZ_OWN RzILOp *rz_il_op_new_seq(RZ_NONNULL RzILOp *x, RZ_NONNULL RzILOp *y);
RZ_API RZ_OWN RzILOp *rz_il_op_new_blk(RZ_NONNULL RzILOp *data_effect, RZ_NONNULL RzILOp *ctrl_effect);
RZ_API RZ_OWN RzILOp *rz_il_op_new_repeat(RZ_NONNULL RzILOp *condition, RZ_NONNULL RzILOp *data_effect);
RZ_API RZ_OWN RzILOp *rz_il_op_new_branch(RZ_NONNULL RzILOp *condition, RZ_NULLABLE RzILOp *true_effect, RZ_NULLABLE RzILOp *false_effect);
RZ_API RZ_OWN RzILOp *rz_il_op_new_load(RzILMemIndex mem, RZ_NONNULL RzILOp *key);
RZ_API RZ_OWN RzILOp *rz_il_op_new_store(RzILMemIndex mem, RZ_NONNULL RzILOp *key, RZ_NONNULL RzILOp *value);
// TODO: loadw, storew here
RZ_API RZ_OWN RzILOp *rz_il_op_new_invalid();

#ifdef __cplusplus
}
#endif

#endif // RZIL_OPCODES_H
