// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_traverse.h>

/**
 * \brief Recurse into \p op, pre-order, depth-first
 *
 * \param op the op to traverse
 * \param cb callback to be called with each node encountered
 * \param user passed to \p cb
 * \return false if cb returned RZ_IL_RECURSE_BREAK at some point, true otherwise
 */
RZ_API bool rz_il_op_pure_recurse(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILRecursePureCB cb, void *user) {
#define RECURSE(child_op) rz_il_op_pure_recurse(child_op, cb, user)
	RzILRecurseCont cont = cb(op, user);
	if (cont == RZ_IL_RECURSE_BREAK) {
		return false;
	}
	if (cont == RZ_IL_RECURSE_STEP_OVER) {
		return true;
	}
	switch (op->code) {
	case RZ_IL_OP_ITE:
		return RECURSE(op->op.ite.condition) && RECURSE(op->op.ite.x) && RECURSE(op->op.ite.y);
	case RZ_IL_OP_LET:
		return RECURSE(op->op.let.exp) && RECURSE(op->op.let.body);
	case RZ_IL_OP_INV:
		return RECURSE(op->op.boolinv.x);
	case RZ_IL_OP_AND:
		return RECURSE(op->op.booland.x) && RECURSE(op->op.booland.y);
	case RZ_IL_OP_OR:
		return RECURSE(op->op.boolor.x) && RECURSE(op->op.boolor.y);
	case RZ_IL_OP_XOR:
		return RECURSE(op->op.boolxor.x) && RECURSE(op->op.boolxor.y);
	case RZ_IL_OP_MSB:
		return RECURSE(op->op.msb.bv);
	case RZ_IL_OP_LSB:
		return RECURSE(op->op.lsb.bv);
	case RZ_IL_OP_IS_ZERO:
		return RECURSE(op->op.is_zero.bv);
	case RZ_IL_OP_NEG:
		return RECURSE(op->op.neg.bv);
	case RZ_IL_OP_LOGNOT:
		return RECURSE(op->op.lognot.bv);
	case RZ_IL_OP_ADD:
		return RECURSE(op->op.add.x) && RECURSE(op->op.add.y);
	case RZ_IL_OP_SUB:
		return RECURSE(op->op.sub.x) && RECURSE(op->op.sub.y);
	case RZ_IL_OP_MUL:
		return RECURSE(op->op.mul.x) && RECURSE(op->op.mul.y);
	case RZ_IL_OP_DIV:
		return RECURSE(op->op.div.x) && RECURSE(op->op.div.y);
	case RZ_IL_OP_SDIV:
		return RECURSE(op->op.sdiv.x) && RECURSE(op->op.sdiv.y);
	case RZ_IL_OP_MOD:
		return RECURSE(op->op.mod.x) && RECURSE(op->op.mod.y);
	case RZ_IL_OP_SMOD:
		return RECURSE(op->op.smod.x) && RECURSE(op->op.smod.y);
	case RZ_IL_OP_LOGAND:
		return RECURSE(op->op.logand.x) && RECURSE(op->op.logand.y);
	case RZ_IL_OP_LOGOR:
		return RECURSE(op->op.logor.x) && RECURSE(op->op.logor.y);
	case RZ_IL_OP_LOGXOR:
		return RECURSE(op->op.logxor.x) && RECURSE(op->op.logxor.y);
	case RZ_IL_OP_SHIFTR:
		return RECURSE(op->op.shiftr.x) && RECURSE(op->op.shiftr.y);
	case RZ_IL_OP_SHIFTL:
		return RECURSE(op->op.shiftl.x) && RECURSE(op->op.shiftl.y);
	case RZ_IL_OP_EQ:
		return RECURSE(op->op.eq.x) && RECURSE(op->op.eq.y);
	case RZ_IL_OP_SLE:
		return RECURSE(op->op.sle.x) && RECURSE(op->op.sle.y);
	case RZ_IL_OP_ULE:
		return RECURSE(op->op.ule.x) && RECURSE(op->op.ule.y);
	case RZ_IL_OP_CAST:
		return RECURSE(op->op.cast.val) && RECURSE(op->op.cast.fill);
	case RZ_IL_OP_APPEND:
		return RECURSE(op->op.append.high) && RECURSE(op->op.append.low);
	case RZ_IL_OP_FLOAT:
		return RECURSE(op->op.float_.bv);
	case RZ_IL_OP_FBITS:
		return RECURSE(op->op.fbits.f);
	case RZ_IL_OP_IS_FINITE:
		return RECURSE(op->op.is_finite.f);
	case RZ_IL_OP_IS_NAN:
		return RECURSE(op->op.is_nan.f);
	case RZ_IL_OP_IS_INF:
		return RECURSE(op->op.is_inf.f);
	case RZ_IL_OP_IS_FZERO:
		return RECURSE(op->op.is_fzero.f);
	case RZ_IL_OP_IS_FNEG:
		return RECURSE(op->op.is_fneg.f);
	case RZ_IL_OP_IS_FPOS:
		return RECURSE(op->op.is_fpos.f);
	case RZ_IL_OP_FNEG:
		return RECURSE(op->op.fneg.f);
	case RZ_IL_OP_FABS:
		return RECURSE(op->op.fabs.f);
	case RZ_IL_OP_FCAST_INT:
		return RECURSE(op->op.fcast_int.f);
	case RZ_IL_OP_FCAST_SINT:
		return RECURSE(op->op.fcast_sint.f);
	case RZ_IL_OP_FCAST_FLOAT:
		return RECURSE(op->op.fcast_float.bv);
	case RZ_IL_OP_FCAST_SFLOAT:
		return RECURSE(op->op.fcast_sfloat.bv);
	case RZ_IL_OP_FCONVERT:
		return RECURSE(op->op.fconvert.f);
	case RZ_IL_OP_FSUCC:
		return RECURSE(op->op.fsucc.f);
	case RZ_IL_OP_FPRED:
		return RECURSE(op->op.fpred.f);
	case RZ_IL_OP_FORDER:
		return RECURSE(op->op.forder.x) && RECURSE(op->op.forder.y);
	case RZ_IL_OP_FROUND:
		return RECURSE(op->op.fround.f);
	case RZ_IL_OP_FSQRT:
		return RECURSE(op->op.fsqrt.f);
	case RZ_IL_OP_FRSQRT:
		return RECURSE(op->op.frsqrt.f);
	case RZ_IL_OP_FADD:
		return RECURSE(op->op.fadd.x) && RECURSE(op->op.fadd.y);
	case RZ_IL_OP_FSUB:
		return RECURSE(op->op.fsub.x) && RECURSE(op->op.fsub.y);
	case RZ_IL_OP_FMUL:
		return RECURSE(op->op.fmul.x) && RECURSE(op->op.fmul.y);
	case RZ_IL_OP_FDIV:
		return RECURSE(op->op.fdiv.x) && RECURSE(op->op.fdiv.y);
	case RZ_IL_OP_FMOD:
		return RECURSE(op->op.fmod.x) && RECURSE(op->op.fmod.y);
	case RZ_IL_OP_FHYPOT:
		return RECURSE(op->op.fhypot.x) && RECURSE(op->op.fhypot.y);
	case RZ_IL_OP_FPOW:
		return RECURSE(op->op.fpow.x) && RECURSE(op->op.fpow.y);
	case RZ_IL_OP_FMAD:
		return RECURSE(op->op.fmad.x) && RECURSE(op->op.fmad.y) && RECURSE(op->op.fmad.z);
	case RZ_IL_OP_FROOTN:
		return RECURSE(op->op.frootn.f) && RECURSE(op->op.frootn.n);
	case RZ_IL_OP_FPOWN:
		return RECURSE(op->op.fpown.f) && RECURSE(op->op.fpown.n);
	case RZ_IL_OP_FCOMPOUND:
		return RECURSE(op->op.fcompound.f) && RECURSE(op->op.fcompound.n);
	case RZ_IL_OP_FEXCEPT:
		return RECURSE(op->op.fexcept.x);
	case RZ_IL_OP_LOAD:
		return RECURSE(op->op.load.key);
	case RZ_IL_OP_LOADW:
		return RECURSE(op->op.loadw.key);
	default:
		return true;
	}
#undef RECURSE
}

/**
 * \brief Recurse into \p op, pre-order, depth-first
 *
 * \param op the op to traverse
 * \param effect_cb callback to be called with each effect node encountered. If NULL, RZ_IL_RECURSE_STEP_INTO is assumed.
 * \param effect_user passed to \p effect_cb
 * \param pure_cb callback to be called with each effect node encountered. If NULL, no recursion into pure ops is done.
 * \param pure_user passed to \p pure_cb
 * \return false if any of the two callbacks returned RZ_IL_RECURSE_BREAK at some point, true otherwise
 */
RZ_API bool rz_il_op_effect_recurse(RZ_NONNULL RzILOpEffect *op,
	RZ_NULLABLE RzILRecurseEffectCB effect_cb, void *effect_user,
	RZ_NULLABLE RzILRecursePureCB pure_cb, void *pure_user) {
#define RECURSE(child_op)      rz_il_op_effect_recurse(child_op, effect_cb, effect_user, pure_cb, pure_user)
#define RECURSE_PURE(child_op) (!pure_cb || rz_il_op_pure_recurse(child_op, pure_cb, pure_user))
	if (effect_cb) {
		RzILRecurseCont cont = effect_cb(op, effect_user);
		if (cont == RZ_IL_RECURSE_BREAK) {
			return false;
		}
		if (cont == RZ_IL_RECURSE_STEP_OVER) {
			return true;
		}
	}
	switch (op->code) {
	case RZ_IL_OP_STORE:
		return RECURSE_PURE(op->op.store.value) && RECURSE_PURE(op->op.store.key);
	case RZ_IL_OP_STOREW:
		return RECURSE_PURE(op->op.storew.value) && RECURSE_PURE(op->op.storew.key);
	case RZ_IL_OP_SET:
		return RECURSE_PURE(op->op.set.x);
	case RZ_IL_OP_SEQ:
		return RECURSE(op->op.seq.x) && RECURSE(op->op.seq.y);
	case RZ_IL_OP_BLK:
		return RECURSE(op->op.blk.data_eff) && RECURSE(op->op.blk.ctrl_eff);
	case RZ_IL_OP_REPEAT:
		return RECURSE_PURE(op->op.repeat.condition) && RECURSE(op->op.repeat.data_eff);
	case RZ_IL_OP_BRANCH:
		return RECURSE_PURE(op->op.branch.condition) && RECURSE(op->op.branch.true_eff) && RECURSE(op->op.branch.false_eff);
	default:
		return true;
	}
#undef RECURSE
#undef RECURSE_PURE
}
