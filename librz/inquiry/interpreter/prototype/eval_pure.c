// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_il/rz_il_opcodes.h"
#include "rz_util/rz_bitvector.h"

/**
 * \brief Evaluate a pure.
 */
RZ_IPI bool interpreter_prototype_eval_pure(
	RzInterpreterAbstrState *state,
	const RzILOpPure *pure,
	RZ_OUT ProtoIntrprAbstrData *out,
	HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	void *plugin_data) {

	switch (pure->code) {
	default:
	case RZ_IL_OP_VAR: {
		ut64 vhash = pure->op.var.hash;
		HtUP *ht_vals;
		switch (pure->op.var.kind) {
		case RZ_IL_VAR_KIND_GLOBAL:
			ht_vals = state->globals;
			break;
		case RZ_IL_VAR_KIND_LOCAL:
			ht_vals = state->locals;
			break;
		case RZ_IL_VAR_KIND_LOCAL_PURE:
			ht_vals = state->lets;
			break;
		}
		RzInterpreterAbstrVal *av = ht_up_find(ht_vals, vhash, NULL);
		if (!av) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			goto map_to_bottom;
		}
		copy_abstr_data(out, av->abstr_data);
		break;
	}
	case RZ_IL_OP_ITE:
	case RZ_IL_OP_LET:
	case RZ_IL_OP_B0:
	case RZ_IL_OP_B1:
	case RZ_IL_OP_BITV:
		// TODO
	case RZ_IL_OP_CAST:
	case RZ_IL_OP_APPEND:
		// TODO
	case RZ_IL_OP_INV:
	case RZ_IL_OP_AND:
	case RZ_IL_OP_OR:
	case RZ_IL_OP_XOR:
	case RZ_IL_OP_MSB:
	case RZ_IL_OP_LSB:
	case RZ_IL_OP_IS_ZERO:
	case RZ_IL_OP_NEG:
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_ADD:
	case RZ_IL_OP_SUB:
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_SHIFTR:
	case RZ_IL_OP_SHIFTL:
	case RZ_IL_OP_EQ:
	case RZ_IL_OP_SLE:
	case RZ_IL_OP_ULE:
		// TODO
	case RZ_IL_OP_MUL:
	case RZ_IL_OP_DIV:
	case RZ_IL_OP_SDIV:
	case RZ_IL_OP_MOD:
	case RZ_IL_OP_SMOD:
	case RZ_IL_OP_FLOAT:
	case RZ_IL_OP_FBITS:
	case RZ_IL_OP_IS_FINITE:
	case RZ_IL_OP_IS_NAN:
	case RZ_IL_OP_IS_INF:
	case RZ_IL_OP_IS_FZERO:
	case RZ_IL_OP_IS_FNEG:
	case RZ_IL_OP_IS_FPOS:
	case RZ_IL_OP_FNEG:
	case RZ_IL_OP_FABS:
	case RZ_IL_OP_FCAST_INT:
	case RZ_IL_OP_FCAST_SINT:
	case RZ_IL_OP_FCAST_FLOAT:
	case RZ_IL_OP_FCAST_SFLOAT:
	case RZ_IL_OP_FCONVERT:
	case RZ_IL_OP_FREQUAL:
	case RZ_IL_OP_FSUCC:
	case RZ_IL_OP_FPRED:
	case RZ_IL_OP_FORDER:
	case RZ_IL_OP_FROUND:
	case RZ_IL_OP_FSQRT:
	case RZ_IL_OP_FRSQRT:
	case RZ_IL_OP_FADD:
	case RZ_IL_OP_FSUB:
	case RZ_IL_OP_FMUL:
	case RZ_IL_OP_FDIV:
	case RZ_IL_OP_FMOD:
	case RZ_IL_OP_FHYPOT:
	case RZ_IL_OP_FPOW:
	case RZ_IL_OP_FMAD:
	case RZ_IL_OP_FROOTN:
	case RZ_IL_OP_FPOWN:
	case RZ_IL_OP_FCOMPOUND:
	case RZ_IL_OP_FEXCEPT:
	case RZ_IL_OP_LOAD:
	case RZ_IL_OP_LOADW:
		// Not implemented.
		goto map_to_bottom;
	}

	// TODO: Check filter if the values should be reported/pushed into the yield queue.

	return true;

map_to_bottom:
	out->is_concrete = false;
	return true;
}
