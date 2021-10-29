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
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		// do nothing
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
		rz_warn_if_reached();
		RZ_LOG_ERROR("RzIl: unknown opcode %u\n", code);
		RZ_FREE(ret);
		break;
	}

	return ret;
}

#define rz_il_free_op_0(s) free(op->op.s)

#define rz_il_free_op_1(s, v0) \
	rz_il_free_op(op->op.s->v0); \
	free(op->op.s)

#define rz_il_free_op_2(s, v0, v1) \
	rz_il_free_op(op->op.s->v0); \
	rz_il_free_op(op->op.s->v1); \
	free(op->op.s)

#define rz_il_free_op_3(s, v0, v1, v2) \
	rz_il_free_op(op->op.s->v0); \
	rz_il_free_op(op->op.s->v1); \
	rz_il_free_op(op->op.s->v2); \
	free(op->op.s)

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
		rz_il_free_op_0(var);
		break;
	case RZIL_OP_UNK:
		rz_il_free_op_0(unk);
		break;
	case RZIL_OP_ITE:
		rz_il_free_op_3(ite, condition, x, y);
		break;
	case RZIL_OP_B0:
		rz_il_free_op_0(b0);
		break;
	case RZIL_OP_B1:
		rz_il_free_op_0(b1);
		break;
	case RZIL_OP_INV:
		rz_il_free_op_2(inv, ret, x);
		break;
	case RZIL_OP_AND_:
		rz_il_free_op_2(and_, x, y);
		break;
	case RZIL_OP_OR_:
		rz_il_free_op_2(or_, x, y);
		break;
	case RZIL_OP_INT:
		rz_il_free_op_0(int_);
		break;
	case RZIL_OP_MSB:
		rz_il_free_op_1(msb, bv);
		break;
	case RZIL_OP_LSB:
		rz_il_free_op_1(lsb, bv);
		break;
	case RZIL_OP_NEG:
		rz_il_free_op_1(neg, bv);
		break;
	case RZIL_OP_NOT:
		rz_il_free_op_1(not_, bv);
		break;
	case RZIL_OP_ADD:
		rz_il_free_op_2(add, x, y);
		break;
	case RZIL_OP_SUB:
		rz_il_free_op_2(sub, x, y);
		break;
	case RZIL_OP_MUL:
		rz_il_free_op_2(mul, x, y);
		break;
	case RZIL_OP_DIV:
		rz_il_free_op_2(div, x, y);
		break;
	case RZIL_OP_SDIV:
		rz_il_free_op_2(sdiv, x, y);
		break;
	case RZIL_OP_MOD:
		rz_il_free_op_2(mod, x, y);
		break;
	case RZIL_OP_SMOD:
		rz_il_free_op_2(smod, x, y);
		break;
	case RZIL_OP_LOGAND:
		rz_il_free_op_2(logand, x, y);
		break;
	case RZIL_OP_LOGOR:
		rz_il_free_op_2(logor, x, y);
		break;
	case RZIL_OP_LOGXOR:
		rz_il_free_op_2(logxor, x, y);
		break;
	case RZIL_OP_SHIFTR:
		rz_il_free_op_3(shiftr, fill_bit, x, y);
		break;
	case RZIL_OP_SHIFTL:
		rz_il_free_op_3(shiftl, fill_bit, x, y);
		break;
	case RZIL_OP_SLE:
		rz_il_free_op_2(sle, x, y);
		break;
	case RZIL_OP_ULE:
		rz_il_free_op_2(ule, x, y);
		break;
	case RZIL_OP_CAST:
		rz_il_free_op_1(cast, val);
		break;
	case RZIL_OP_CONCAT:
		rz_warn_if_reached();
		break;
	case RZIL_OP_APPEND:
		rz_warn_if_reached();
		break;
	case RZIL_OP_LOAD:
		rz_il_free_op_1(load, key);
		break;
	case RZIL_OP_STORE:
		rz_il_free_op_2(store, key, value);
		break;
	case RZIL_OP_PERFORM:
		rz_il_free_op_1(perform, eff);
		break;
	case RZIL_OP_SET:
		rz_il_free_op_1(set, x);
		break;
	case RZIL_OP_JMP:
		rz_il_free_op_1(jmp, dst);
		break;
	case RZIL_OP_GOTO:
		rz_il_free_op_0(goto_);
		break;
	case RZIL_OP_SEQ:
		rz_il_free_op_2(seq, x, y);
		break;
	case RZIL_OP_BLK:
		rz_il_free_op_2(blk, data_eff, ctrl_eff);
		break;
	case RZIL_OP_REPEAT:
		rz_il_free_op_2(repeat, condition, data_eff);
		break;
	case RZIL_OP_BRANCH:
		rz_il_free_op_3(branch, condition, true_eff, false_eff);
		break;
	case RZIL_OP_INVALID:
		break;
	default:
		rz_warn_if_reached();
		RZ_LOG_ERROR("RzIl: unknown opcode %u\n", op->code);
		break;
	}
	free(op);
}
#undef rz_il_free_op_0
#undef rz_il_free_op_1
#undef rz_il_free_op_2
#undef rz_il_free_op_3
