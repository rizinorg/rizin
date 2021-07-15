#ifndef RZIL_CORE_THEORY_DEFINITIONS_H
#include "_ct_opcodes.h"

typedef enum {
	// Init
	RZIL_OP_VAR,
	RZIL_OP_UNK,
	RZIL_OP_ITE,

	// Bool
	RZIL_OP_B0,
	RZIL_OP_B1,
	RZIL_OP_INV,
	RZIL_OP_AND_,
	RZIL_OP_OR_,

	// BitVector
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

	RZIL_OP_INVALID
} CoreTheoryOPCode;

// support core theory opcode
/* define every CoreTheory opcode strucut ()*/
// for example : ite in Ocaml
//               val ite : bool -> 'a pure -> 'a pure -> 'a pure
//               ite c x y is x if c evaluates to b1 else y.
// they are defined in specific modules
// TODO : Add More
typedef struct rzil_op_ite_t *RzILOpIte;
typedef struct rzil_op_var_t *RzILOpVar;
typedef struct rzil_op_unk_t *RzILOpUnk;

typedef struct rzil_op_msb_lsb_t *RzILOpMsb;
typedef struct rzil_op_msb_lsb_t *RzILOpLsb;
typedef struct rzil_op_sle_ule_t *RzILOpSle;
typedef struct rzil_op_sle_ule_t *RzILOpUle;
typedef struct rzil_op_not_t *RzILOpNot;
typedef struct rzil_op_neg_t *RzILOpNeg;
typedef struct rzil_op_alg_log_operations_t *RzILOpAdd;
typedef struct rzil_op_alg_log_operations_t *RzILOpSub;
typedef struct rzil_op_alg_log_operations_t *RzILOpMul;
typedef struct rzil_op_alg_log_operations_t *RzILOpDiv;
typedef struct rzil_op_alg_log_operations_t *RzILOpSdiv;
typedef struct rzil_op_alg_log_operations_t *RzILOpMod;
typedef struct rzil_op_alg_log_operations_t *RzILOpSmod;
typedef struct rzil_op_alg_log_operations_t *RzILOpLogand;
typedef struct rzil_op_alg_log_operations_t *RzILOpLogor;
typedef struct rzil_op_alg_log_operations_t *RzILOpLogxor;
typedef struct rzil_op_shift_t *RzILOpShiftl;
typedef struct rzil_op_shift_t *RzILOpShiftr;
typedef struct rzil_op_int_t *RzILOpInt;

typedef struct rzil_op_b_t *RzILOpB0;
typedef struct rzil_op_b_t *RzILOpB1;
typedef struct rzil_op_and__t *RzILOpAnd_;
typedef struct rzil_op_or__t *RzILOpOr_;
typedef struct rzil_op_inv_t *RzILOpInv;

typedef struct rzil_op_perform_t *RzILOpPerform;
typedef struct rzil_op_set_t *RzILOpSet;
typedef struct rzil_op_jmp_t *RzILOpJmp;
typedef struct rzil_op_goto_t *RzILOpGoto;
typedef struct rzil_op_seq_t *RzILOpSeq;
typedef struct rzil_op_blk_t *RzILOpBlk;
typedef struct rzil_op_repeat_t *RzILOpRepeat;
typedef struct rzil_op_branch_t *RzILOpBranch;

typedef struct rzil_op_load_t *RzILOpLoad;
typedef struct rzil_op_store_t *RzILOpStore;

// Then define a union to union all of these struct
typedef union {
	RzILOpIte ite;
	RzILOpVar var;
	RzILOpUnk unk;

	RzILOpB0 b0;
	RzILOpB1 b1;
	RzILOpAnd_ and_;
	RzILOpOr_ or_;
	RzILOpInv inv;

	RzILOpInt int_;
	RzILOpMsb msb;
	RzILOpLsb lsb;
	RzILOpUle ule;
	RzILOpSle sle;
	RzILOpNeg neg;
	RzILOpNot not ;
	RzILOpAdd add;
	RzILOpSub sub;
	RzILOpMul mul;
	RzILOpDiv div;
	RzILOpSdiv sdiv;
	RzILOpSmod smod;
	RzILOpMod mod;
	RzILOpLogand logand;
	RzILOpLogor logor;
	RzILOpLogxor logxor;
	RzILOpShiftl shiftl;
	RzILOpShiftr shiftr;

	RzILOpPerform perform;
	RzILOpSet set;
	RzILOpJmp jmp;
	RzILOpGoto goto_;
	RzILOpSeq seq;
	RzILOpBlk blk;
	RzILOpRepeat repeat;
	RzILOpBranch branch;

	RzILOpLoad load;
	RzILOpStore store;

	void *nil;
	// ... More
} _RzILOp;

struct RzILOp_t {
	ut64 id;
	CoreTheoryOPCode code;
	_RzILOp op;
};
typedef struct RzILOp_t *RzILOp;
// Opcode
RzILOp rz_il_new_op(CoreTheoryOPCode code);
void rz_il_free_op(RzILOp op);

#define RZIL_CORE_THEORY_DEFINITIONS_H
#endif //RZIL_CORE_THEORY_DEFINITIONS_H
