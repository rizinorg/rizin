#include "core_theory_opcodes.h"

#define RZIL_OP_NEW(size) calloc(1, (size))

// Opcode
RzILOp rz_il_new_empty_op(void) {
	RzILOp ret = (RzILOp)malloc(sizeof(struct RzILOp_t));
	ret->id = 0;
	ret->code = OP_INVALID;
	ret->op.nil = NULL;

	return ret;
}

RzILOp rz_il_new_op(CoreTheoryOPCode code) {
	RzILOp ret = (RzILOp)malloc(sizeof(struct RzILOp_t));
	// TODO : Instruction id
	ret->id = 0;
	ret->code = code;

	switch (code) {
	case OP_VAR:
		ret->op.var = (RzILOpVar)RZIL_OP_NEW(sizeof(struct rzil_op_var_t));
		break;
	case OP_ITE:
		ret->op.ite = (RzILOpIte)RZIL_OP_NEW(sizeof(struct rzil_op_ite_t));
		break;
	case OP_UNK:
		ret->op.unk = (RzILOpUnk)RZIL_OP_NEW(sizeof(struct rzil_op_unk_t));
		break;
	case OP_B0:
	case OP_B1:
		ret->op.b0 = (RzILOpB0)RZIL_OP_NEW(sizeof(struct rzil_op_b_t));
		break;
	case OP_AND_:
		ret->op.and_ = (RzILOpAnd_)RZIL_OP_NEW(sizeof(struct rzil_op_and__t));
		break;
	case OP_OR_:
		ret->op.or_ = (RzILOpOr_)RZIL_OP_NEW(sizeof(struct rzil_op_or__t));
		break;
	case OP_INV:
		ret->op.inv = (RzILOpInv)RZIL_OP_NEW(sizeof(struct rzil_op_inv_t));
		break;
	case OP_INT:
		ret->op.int_ = (RzILOpInt)RZIL_OP_NEW(sizeof(struct rzil_op_int_t));
		break;
	case OP_MSB:
	case OP_LSB:
		ret->op.lsb = (RzILOpMsb)RZIL_OP_NEW(sizeof(struct rzil_op_msb_lsb_t));
		break;
	case OP_NEG:
		ret->op.neg = (RzILOpNeg)RZIL_OP_NEW(sizeof(struct rzil_op_neg_t));
		break;
	case OP_NOT:
		ret->op.not = (RzILOpNot)RZIL_OP_NEW(sizeof(struct rzil_op_not_t));
		break;
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_DIV:
	case OP_SDIV:
	case OP_MOD:
	case OP_SMOD:
	case OP_LOGAND:
	case OP_LOGOR:
	case OP_LOGXOR:
		// trick to set union members
		ret->op.add = RZIL_OP_NEW(sizeof(struct rzil_op_alg_log_operations_t));
		break;
	case OP_LOAD:
		ret->op.load = RZIL_OP_NEW(sizeof(struct rzil_op_load_t));
		break;
	case OP_STORE:
		ret->op.store = RZIL_OP_NEW(sizeof(struct rzil_op_store_t));
		break;
	case OP_SET:
		ret->op.set = (RzILOpSet)RZIL_OP_NEW(sizeof(struct rzil_op_set_t));
		break;
	case OP_PERFORM:
		ret->op.perform = (RzILOpPerform)RZIL_OP_NEW(sizeof(struct rzil_op_perform_t));
		break;
	case OP_BRANCH:
		ret->op.branch = (RzILOpBranch)RZIL_OP_NEW(sizeof(struct rzil_op_branch_t));
		break;
	case OP_GOTO:
		ret->op.goto_ = (RzILOpGoto)RZIL_OP_NEW(sizeof(struct rzil_op_goto_t));
		break;
	default:
		free(ret);
		ret = NULL;
		printf("Unknown opcode\n");
		break;
	}

	return ret;
}

void rz_il_free_op(RzILOp op) {
	switch (op->code) {
	case OP_VAR:
		free(op->op.var);
		break;
	case OP_SET:
		free(op->op.set);
		break;
	case OP_GOTO:
		free(op->op.goto_);
		break;
	// 4 Int memebers
	case OP_STORE:
	case OP_ITE:
	case OP_BRANCH:
	case OP_SHIFTR:
	case OP_SHIFTL:
		free(op->op.ite);
		break;
	// 3 Int members
	case OP_INT:
	case OP_ADD:
	case OP_SUB:
	case OP_MUL:
	case OP_DIV:
	case OP_MOD:
	case OP_SDIV:
	case OP_SMOD:
	case OP_LOGXOR:
	case OP_LOGAND:
	case OP_LOGOR:
	case OP_ULE:
	case OP_SLE:
	case OP_SEQ:
	case OP_BLK:
	case OP_AND_:
	case OP_OR_:
	case OP_LOAD:
		free(op->op.int_);
		break;
	case OP_PERFORM:
	case OP_MSB:
	case OP_LSB:
	case OP_NEG:
	case OP_NOT:
	case OP_JMP:
	case OP_INV:
		free(op->op.inv);
		break;
	case OP_UNK:
	case OP_B0:
	case OP_B1:
		free(op->op.b0);
		break;
	default:
		printf("[WIP]\n");
		break;
	}
	free(op);
}
