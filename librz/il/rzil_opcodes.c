// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_opcodes.h>

RzILOp *rz_il_new_empty_op(void) {
	RzILOp *ret = RZ_NEW0(RzILOp);
	if (!ret) {
		return NULL;
	}
	ret->id = 0;
	ret->code = RZIL_OP_INVALID;
	ret->op.nil = NULL;

	return ret;
}

/**
 * Create an empty core theory op, argument of the op should be set in analysis_[arch]
 * \param code RzILOPCode, enum to specify the op type
 * \return RzILOp, a pointer to an empty opcode instance
 */
RZ_API RzILOp *rz_il_new_op(RzILOPCode code) {
	RzILOp *ret = RZ_NEW0(RzILOp);
	if (!ret) {
		return NULL;
	}
	ret->id = 0;
	ret->code = code;

	switch (code) {
	case RZIL_OP_VAR:
		ret->op.var = RZ_NEW0(RzILOpVar);
		break;
	case RZIL_OP_ITE:
		ret->op.ite = RZ_NEW0(RzILOpIte);
		break;
	case RZIL_OP_UNK:
		ret->op.unk = NULL;
		break;
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		ret->op.b0 = NULL;
		break;
	case RZIL_OP_AND_:
		ret->op.and_ = RZ_NEW0(RzILOpAnd_);
		break;
	case RZIL_OP_OR_:
		ret->op.or_ = RZ_NEW0(RzILOpOr_);
		break;
	case RZIL_OP_INV:
		ret->op.inv = RZ_NEW0(RzILOpInv);
		break;
	case RZIL_OP_INT:
		ret->op.int_ = RZ_NEW0(RzILOpInt);
		break;
	case RZIL_OP_MSB:
	case RZIL_OP_LSB:
		ret->op.lsb = RZ_NEW0(RzILOpLsb);
		break;
	case RZIL_OP_NEG:
		ret->op.neg = RZ_NEW0(RzILOpNeg);
		break;
	case RZIL_OP_NOT:
		ret->op.not_ = RZ_NEW0(RzILOpNot);
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
		ret->op.add = RZ_NEW0(RzILOpAdd);
		break;
	case RZIL_OP_LOAD:
		ret->op.load = RZ_NEW0(RzILOpLoad);
		break;
	case RZIL_OP_STORE:
		ret->op.store = RZ_NEW0(RzILOpStore);
		break;
	case RZIL_OP_SET:
		ret->op.set = RZ_NEW0(RzILOpSet);
		break;
	case RZIL_OP_CAST:
		ret->op.cast = RZ_NEW0(RzILOpCast);
		break;
	case RZIL_OP_PERFORM:
		ret->op.perform = RZ_NEW0(RzILOpPerform);
		break;
	case RZIL_OP_BRANCH:
		ret->op.branch = RZ_NEW0(RzILOpBranch);
		break;
	case RZIL_OP_GOTO:
		ret->op.goto_ = RZ_NEW0(RzILOpGoto);
		break;
	default:
		free(ret);
		ret = NULL;
		RZ_LOG_ERROR("Unknown opcode\n");
		rz_warn_if_reached();
		break;
	}

	return ret;
}

/**
 * Free core theory opcode instance
 * \param op RzILOp, pointer to opcode instance
 */
RZ_API void rz_il_free_op(RzILOp *op) {
	if (!op) {
		return;
	}
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
		RZ_LOG_ERROR("[WIP]\n");
		rz_warn_if_reached();
		break;
	}
	free(op);
}
