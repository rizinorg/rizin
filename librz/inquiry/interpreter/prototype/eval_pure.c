// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include <rz_util/rz_bitvector.h>

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
		if (!read_var_from_state(state, pure->op.var.kind, pure->op.var.hash, out)) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			goto map_to_bottom;
		}
		break;
	}
	case RZ_IL_OP_LET: {
		ut64 vhash = pure->op.let.hash;
		if (!interpreter_prototype_eval_pure(state, pure->op.let.exp, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: LET expression failed to evaluate.\n");
			goto map_to_bottom;
		}
		write_var_to_state(state, RZ_IL_VAR_KIND_LOCAL_PURE, vhash, out);
		// Evaluate body
		if (!interpreter_prototype_eval_pure(state, pure->op.let.body, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: LET body failed to evaluate.\n");
			goto map_to_bottom;
		}
		// No need to free the LET variable.
		// It is simply overwritten next time.
		break;
	}
	case RZ_IL_OP_ITE: {
		if (!interpreter_prototype_eval_pure(state, pure->op.ite.condition, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: ITE condition failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			// Can't decide which pure to evaluate.
			goto map_to_bottom;
		}

		if (abstr_is_true(state, out)) {
			if (!interpreter_prototype_eval_pure(state, pure->op.ite.x, out, yield_queues, plugin_data)) {
				RZ_LOG_ERROR("prototype: ITE x failed to evaluate.\n");
				goto map_to_bottom;
			}
		} else {
			if (!interpreter_prototype_eval_pure(state, pure->op.ite.y, out, yield_queues, plugin_data)) {
				RZ_LOG_ERROR("prototype: ITE y failed to evaluate.\n");
				goto map_to_bottom;
			}
		}
		break;
	}
	case RZ_IL_OP_B0:
		if (rz_bv_len(out->bv) != 1) {
			rz_bv_cast_inplace(out->bv, 1, false);
		}
		rz_bv_set(out->bv, 0, false);
		out->is_concrete = true;
		break;
	case RZ_IL_OP_B1:
		if (rz_bv_len(out->bv) != 1) {
			rz_bv_cast_inplace(out->bv, 1, false);
		}
		rz_bv_set(out->bv, 0, true);
		out->is_concrete = true;
		break;
	case RZ_IL_OP_CAST: {
		if (!interpreter_prototype_eval_pure(state, pure->op.cast.val, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: CAST val failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			break;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!interpreter_prototype_eval_pure(state, pure->op.cast.fill, &fill_bit, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: CAST fill failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!fill_bit.is_concrete) {
			break;
		}
		rz_bv_cast_inplace(out->bv, pure->op.cast.length, abstr_is_true(state, &fill_bit));
		break;
	}
	case RZ_IL_OP_BITV:
		rz_bv_cast_inplace(out->bv, rz_bv_len(pure->op.bitv.value), false);
		rz_bv_copy(out->bv, pure->op.bitv.value);
		out->is_concrete = true;
		break;
	case RZ_IL_OP_APPEND: {
		STACK_ABSTR_DATA_OUT(high);
		if (!interpreter_prototype_eval_pure(state, pure->op.append.high, &high, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: APPEND high failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!high.is_concrete) {
			rz_bv_fini(high.bv);
			goto map_to_bottom;
		}
		if (!interpreter_prototype_eval_pure(state, pure->op.append.low, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: APPEND low failed to evaluate.\n");
			rz_bv_fini(high.bv);
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			rz_bv_fini(high.bv);
			goto map_to_bottom;
		}
		rz_bv_cast_inplace(out->bv, rz_bv_len(out->bv) + rz_bv_len(high.bv), false);
		rz_bv_copy_nbits(high.bv, 0, out->bv, rz_bv_len(out->bv), rz_bv_len(high.bv));
		out->is_concrete = true;
		rz_bv_fini(high.bv);
		break;
	}
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_INV:
		if (!interpreter_prototype_eval_pure(state, pure->op.boolinv.x, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: INV x failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (out->is_concrete) {
			rz_bv_not_inplace(out->bv);
		}
		break;
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_AND: {
		if (!interpreter_prototype_eval_pure(state, pure->op.booland.x, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: AND x failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, pure->op.booland.y, &y, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: AND y failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		if (!rz_bv_and_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_OR: {
		if (!interpreter_prototype_eval_pure(state, pure->op.boolor.x, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: OR x failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, pure->op.boolor.y, &y, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: OR y failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		if (!rz_bv_or_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_XOR: {
		if (!interpreter_prototype_eval_pure(state, pure->op.boolxor.x, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: XOR x failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, pure->op.boolxor.y, &y, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: XOR y failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		if (!rz_bv_xor_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_IS_ZERO:
	case RZ_IL_OP_LSB:
	case RZ_IL_OP_MSB: {
		bool (*truth_test)(const RzBitVector *bv);
		RzILOpBitVector *bv;
		switch (pure->code) {
		default:
			rz_warn_if_reached();
			goto map_to_bottom;
		case RZ_IL_OP_IS_ZERO:
			bv = pure->op.is_zero.bv;
			truth_test = rz_bv_is_zero_vector;
			break;
		case RZ_IL_OP_LSB:
			bv = pure->op.lsb.bv;
			truth_test = rz_bv_lsb;
			break;
		case RZ_IL_OP_MSB:
			bv = pure->op.msb.bv;
			truth_test = rz_bv_msb;
			break;
		}
		if (!interpreter_prototype_eval_pure(state, bv, out, yield_queues, plugin_data)) {
			RZ_LOG_ERROR("prototype: MSB bv failed to evaluate.\n");
			goto map_to_bottom;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		rz_bv_cast_inplace(out->bv, 1, false);
		// TODO: Truth bit.
		rz_bv_set(out->bv, 0, truth_test(out->bv));
		break;
	}
	case RZ_IL_OP_NEG:
	case RZ_IL_OP_ADD:
	case RZ_IL_OP_SUB:
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
