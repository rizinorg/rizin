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
	RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
	void *plugin_data) {

	switch (pure->code) {
	default:
	case RZ_IL_OP_VAR: {
		if (!read_var_from_state(state, pure->op.var.kind, pure->op.var.hash, out)) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			return false;
		}
		break;
	}
	case RZ_IL_OP_LET: {
		ut64 vhash = pure->op.let.hash;
		if (!interpreter_prototype_eval_pure(state, pure->op.let.exp, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: LET expression failed to evaluate.\n");
			return false;
		}
		write_var_to_state(state, RZ_IL_VAR_KIND_LOCAL_PURE, vhash, out);
		// Evaluate body
		if (!interpreter_prototype_eval_pure(state, pure->op.let.body, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: LET body failed to evaluate.\n");
			return false;
		}
		// No need to free the LET variable.
		// It is simply overwritten next time.
		break;
	}
	case RZ_IL_OP_ITE: {
		if (!interpreter_prototype_eval_pure(state, pure->op.ite.condition, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: ITE condition failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			// Can't decide which pure to evaluate.
			goto map_to_bottom;
		}

		if (abstr_is_true(state, out)) {
			if (!interpreter_prototype_eval_pure(state, pure->op.ite.x, out, yield_queues, io_request, io_result, plugin_data)) {
				RZ_LOG_ERROR("prototype: ITE x failed to evaluate.\n");
				return false;
			}
		} else {
			if (!interpreter_prototype_eval_pure(state, pure->op.ite.y, out, yield_queues, io_request, io_result, plugin_data)) {
				RZ_LOG_ERROR("prototype: ITE y failed to evaluate.\n");
				return false;
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
		if (!interpreter_prototype_eval_pure(state, pure->op.cast.val, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: CAST val failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			break;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!interpreter_prototype_eval_pure(state, pure->op.cast.fill, &fill_bit, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: CAST fill failed to evaluate.\n");
			return false;
		}
		if (!fill_bit.is_concrete) {
			break;
		}
		rz_bv_cast_inplace(out->bv, pure->op.cast.length, abstr_is_true(state, &fill_bit));
		break;
	}
	case RZ_IL_OP_BITV:
		rz_bv_cast_inplace(out->bv, rz_bv_len(pure->op.bitv.value), false);
		rz_bv_copy(pure->op.bitv.value, out->bv);
		out->is_concrete = true;
		break;
	case RZ_IL_OP_APPEND: {
		STACK_ABSTR_DATA_OUT(high);
		if (!interpreter_prototype_eval_pure(state, pure->op.append.high, &high, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: APPEND high failed to evaluate.\n");
			return false;
		}
		if (!high.is_concrete) {
			rz_bv_fini(high.bv);
			goto map_to_bottom;
		}
		if (!interpreter_prototype_eval_pure(state, pure->op.append.low, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: APPEND low failed to evaluate.\n");
			rz_bv_fini(high.bv);
			return false;
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
	case RZ_IL_OP_INV: {
		RzILOpPure *x = pure->code == RZ_IL_OP_INV ? pure->op.boolinv.x : pure->op.lognot.bv;
		if (!interpreter_prototype_eval_pure(state, x, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: INV x failed to evaluate.\n");
			return false;
		}
		if (out->is_concrete) {
			rz_bv_not_inplace(out->bv);
		}
		break;
	}
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_AND: {
		RzILOpPure *px = pure->code == RZ_IL_OP_AND ? pure->op.booland.x : pure->op.logand.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_AND ? pure->op.booland.y : pure->op.logand.y;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: AND x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: AND y failed to evaluate.\n");
			return false;
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
		RzILOpPure *px = pure->code == RZ_IL_OP_OR ? pure->op.boolor.x : pure->op.logor.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_OR ? pure->op.boolor.y : pure->op.logor.y;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: OR x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: OR y failed to evaluate.\n");
			return false;
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
		RzILOpPure *px = pure->code == RZ_IL_OP_XOR ? pure->op.boolxor.x : pure->op.logxor.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_XOR ? pure->op.boolxor.y : pure->op.logxor.y;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: XOR x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: XOR y failed to evaluate.\n");
			return false;
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
		if (!interpreter_prototype_eval_pure(state, bv, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: MSB/LSB/IS_ZERO bv failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		bool truth = truth_test(out->bv);
		rz_bv_cast_inplace(out->bv, 1, false);
		// TODO: Truth bit.
		rz_bv_set(out->bv, 0, truth);
		break;
	}
	case RZ_IL_OP_NEG: {
		if (!interpreter_prototype_eval_pure(state, pure->op.neg.bv, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: NEG bv failed to evaluate.\n");
			return false;
		}
		if (out->is_concrete) {
			rz_bv_neg_inplace(out->bv);
		}
		break;
	}
	case RZ_IL_OP_ADD: {
		RzILOpPure *px = pure->op.add.x;
		RzILOpPure *py = pure->op.add.y;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: ADD x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: ADD y failed to evaluate.\n");
			return false;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		if (!rz_bv_add_inplace(out->bv, y.bv, NULL)) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_SUB: {
		RzILOpPure *px = pure->op.sub.x;
		RzILOpPure *py = pure->op.sub.y;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SUB y failed to evaluate.\n");
			return false;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		if (!rz_bv_sub_inplace(out->bv, y.bv, NULL)) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_SHIFTL:
	case RZ_IL_OP_SHIFTR: {
		RzILOpPure *px = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.x : pure->op.shiftl.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.y : pure->op.shiftl.y;
		RzILOpPure *pfill_bit = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.fill_bit : pure->op.shiftl.fill_bit;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) y failed to evaluate.\n");
			return false;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!interpreter_prototype_eval_pure(state, pfill_bit, &fill_bit, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) fill_bit failed to evaluate.\n");
			return false;
		}
		if (!fill_bit.is_concrete) {
			rz_bv_fini(fill_bit.bv);
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		bool (*shift)(RzBitVector *bv, ut32 size, bool fill_bit);
		shift = pure->code == RZ_IL_OP_SHIFTR ? rz_bv_rshift_fill : rz_bv_lshift_fill;
		if (!shift(out->bv, rz_bv_to_ut64(y.bv), abstr_is_true(state, &fill_bit))) {
			rz_bv_fini(fill_bit.bv);
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(fill_bit.bv);
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_SLE:
	case RZ_IL_OP_ULE:
	case RZ_IL_OP_EQ: {
		bool (*cmp)(RzBitVector *x, RzBitVector *y);
		RzILOpPure *px;
		RzILOpPure *py;
		switch (pure->code) {
		default:
			goto map_to_bottom;
		case RZ_IL_OP_SLE:
			px = pure->op.sle.x;
			py = pure->op.sle.y;
			cmp = rz_bv_sle;
			break;
		case RZ_IL_OP_ULE:
			px = pure->op.ule.x;
			py = pure->op.ule.y;
			cmp = rz_bv_ule;
			break;
		case RZ_IL_OP_EQ:
			px = pure->op.eq.x;
			py = pure->op.eq.y;
			cmp = rz_bv_eq;
			break;
		}

		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: CMP x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: CMP y failed to evaluate.\n");
			return false;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		bool cmp_is_true = cmp(out->bv, y.bv);
		rz_bv_cast_inplace(out->bv, 1, false);
		rz_bv_set(out->bv, 0, cmp_is_true);
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_LOADW:
	case RZ_IL_OP_LOAD: {
		RzILOpPure *key = pure->code == RZ_IL_OP_LOAD ? pure->op.load.key : pure->op.loadw.key;
		if (!interpreter_prototype_eval_pure(state, key, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: LOAD/LOADW key failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		report_xref_yield(state, yield_queues, rz_bv_to_ut64(AD(state->pc->abstr_data)->bv), out, RZ_ANALYSIS_XREF_TYPE_DATA);
		ut64 addr = rz_bv_to_ut64(out->bv);
		size_t addr_bits = pure->code == RZ_IL_OP_LOAD ? state->il_config->mem_key_size : pure->op.loadw.n_bits;
		if (!load_abstr_data(state, addr, addr_bits, out, io_request, io_result)) {
			goto map_to_bottom;
		}
		break;
	}
	case RZ_IL_OP_MUL: {
		RzILOpPure *px = pure->op.mul.x;
		RzILOpPure *py = pure->op.mul.y;
		if (!interpreter_prototype_eval_pure(state, px, out, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: MUL x failed to evaluate.\n");
			return false;
		}
		if (!out->is_concrete) {
			goto map_to_bottom;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(state, py, &y, yield_queues, io_request, io_result, plugin_data)) {
			RZ_LOG_ERROR("prototype: MUL y failed to evaluate.\n");
			return false;
		}
		if (!y.is_concrete) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		if (!rz_bv_mul_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_bottom;
		}
		rz_bv_fini(y.bv);
		break;
	}
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
		RZ_LOG_DEBUG("\nUnhandled op\n");
		// Not implemented.
		goto map_to_bottom;
	}
	return true;

map_to_bottom:
	out->is_concrete = false;
	return true;
}
