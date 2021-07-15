#include "core_theory_opcodes.h"

#define RZIL_OP_NEW(size) calloc(1, (size))

// Opcode
RzILOp rz_il_new_empty_op(void) {
	RzILOp ret = (RzILOp)malloc(sizeof(struct RzILOp_t));
	ret->id = 0;
	ret->code = RZIL_OP_INVALID;
	ret->op.nil = NULL;

	return ret;
}

RzILOp rz_il_new_op(CoreTheoryOPCode code) {
	RzILOp ret = (RzILOp)malloc(sizeof(struct RzILOp_t));
	// TODO : Instruction id
	ret->id = 0;
	ret->code = code;

	switch (code) {
	case RZIL_OP_VAR:
		ret->op.var = (RzILOpVar)RZIL_OP_NEW(sizeof(struct rzil_op_var_t));
		break;
	case RZIL_OP_ITE:
		ret->op.ite = (RzILOpIte)RZIL_OP_NEW(sizeof(struct rzil_op_ite_t));
		break;
	case RZIL_OP_UNK:
		ret->op.unk = (RzILOpUnk)RZIL_OP_NEW(sizeof(struct rzil_op_unk_t));
		break;
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		ret->op.b0 = (RzILOpB0)RZIL_OP_NEW(sizeof(struct rzil_op_b_t));
		break;
	case RZIL_OP_AND_:
		ret->op.and_ = (RzILOpAnd_)RZIL_OP_NEW(sizeof(struct rzil_op_and__t));
		break;
	case RZIL_OP_OR_:
		ret->op.or_ = (RzILOpOr_)RZIL_OP_NEW(sizeof(struct rzil_op_or__t));
		break;
	case RZIL_OP_INV:
		ret->op.inv = (RzILOpInv)RZIL_OP_NEW(sizeof(struct rzil_op_inv_t));
		break;
	case RZIL_OP_INT:
		ret->op.int_ = (RzILOpInt)RZIL_OP_NEW(sizeof(struct rzil_op_int_t));
		break;
	case RZIL_OP_MSB:
	case RZIL_OP_LSB:
		ret->op.lsb = (RzILOpMsb)RZIL_OP_NEW(sizeof(struct rzil_op_msb_lsb_t));
		break;
	case RZIL_OP_NEG:
		ret->op.neg = (RzILOpNeg)RZIL_OP_NEW(sizeof(struct rzil_op_neg_t));
		break;
	case RZIL_OP_NOT:
		ret->op.not = (RzILOpNot)RZIL_OP_NEW(sizeof(struct rzil_op_not_t));
		break;
	case RZIL_OP_ADD:
	case RZIL_OP_SUB:
	case RZIL_OP_MUL:
	case RZIL_OP_DIV:
	case RZIL_OP_SDIV:
	case RZIL_OP_MOD:
	case RZIL_OP_SMOD:
	case RZIL_OP_LOGAND:
	case RZIL_OP_LOGOR:
	case RZIL_OP_LOGXOR:
		// trick to set union members
		ret->op.add = RZIL_OP_NEW(sizeof(struct rzil_op_alg_log_operations_t));
		break;
	case RZIL_OP_LOAD:
		ret->op.load = RZIL_OP_NEW(sizeof(struct rzil_op_load_t));
		break;
	case RZIL_OP_STORE:
		ret->op.store = RZIL_OP_NEW(sizeof(struct rzil_op_store_t));
		break;
	case RZIL_OP_SET:
		ret->op.set = (RzILOpSet)RZIL_OP_NEW(sizeof(struct rzil_op_set_t));
		break;
	case RZIL_OP_PERFORM:
		ret->op.perform = (RzILOpPerform)RZIL_OP_NEW(sizeof(struct rzil_op_perform_t));
		break;
	case RZIL_OP_BRANCH:
		ret->op.branch = (RzILOpBranch)RZIL_OP_NEW(sizeof(struct rzil_op_branch_t));
		break;
	case RZIL_OP_GOTO:
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
	case RZIL_OP_VAR:
		free(op->op.var);
		break;
	case RZIL_OP_SET:
		free(op->op.set);
		break;
	case RZIL_OP_GOTO:
		free(op->op.goto_);
		break;
	// 4 Int memebers
	case RZIL_OP_STORE:
	case RZIL_OP_ITE:
	case RZIL_OP_BRANCH:
	case RZIL_OP_SHIFTR:
	case RZIL_OP_SHIFTL:
		free(op->op.ite);
		break;
	// 3 Int members
	case RZIL_OP_INT:
	case RZIL_OP_ADD:
	case RZIL_OP_SUB:
	case RZIL_OP_MUL:
	case RZIL_OP_DIV:
	case RZIL_OP_MOD:
	case RZIL_OP_SDIV:
	case RZIL_OP_SMOD:
	case RZIL_OP_LOGXOR:
	case RZIL_OP_LOGAND:
	case RZIL_OP_LOGOR:
	case RZIL_OP_ULE:
	case RZIL_OP_SLE:
	case RZIL_OP_SEQ:
	case RZIL_OP_BLK:
	case RZIL_OP_AND_:
	case RZIL_OP_OR_:
	case RZIL_OP_LOAD:
		free(op->op.int_);
		break;
	case RZIL_OP_PERFORM:
	case RZIL_OP_MSB:
	case RZIL_OP_LSB:
	case RZIL_OP_NEG:
	case RZIL_OP_NOT:
	case RZIL_OP_JMP:
	case RZIL_OP_INV:
		free(op->op.inv);
		break;
	case RZIL_OP_UNK:
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		free(op->op.b0);
		break;
	default:
		printf("[WIP]\n");
		break;
	}
	free(op);
}
