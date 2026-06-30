// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "eval.h"
#include "rz_util/rz_assert.h"
#include <rz_util/rz_bitvector.h>

#include <rz_inquiry.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_util.h>

#include "rz_util/rz_bitvector.h"

static void adata_free(ProtoIntrprAbstrData *adata) {
	if (!adata) {
		return;
	}
	rz_bv_free(adata->bv);
	free(adata);
}

/**
 * \brief Abstract data getter from the RzInterpAbstrVal
 */
#define AD(av) ((ProtoIntrprAbstrData *)av)

/**
 * \brief Evaluate a pure.
 */
RZ_IPI bool interpreter_prototype_eval_pure(
	RzInterpRunContext *ctx,
	const RzILOpPure *pure,
	RZ_OUT ProtoIntrprAbstrData *out) {
	switch (pure->code) {
	default:
	case RZ_IL_OP_VAR: {
		if (!read_var_from_state(ctx->astate, pure->op.var.kind, pure->op.var.hash, out)) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			return false;
		}
		break;
	}
	case RZ_IL_OP_LET: {
		ut64 vhash = pure->op.let.hash;
		if (!interpreter_prototype_eval_pure(ctx, pure->op.let.exp, out)) {
			RZ_LOG_ERROR("prototype: LET expression failed to evaluate.\n");
			return false;
		}
		write_var_to_state(ctx->astate, RZ_IL_VAR_KIND_LOCAL_PURE, vhash, out);
		// Evaluate body
		if (!interpreter_prototype_eval_pure(ctx, pure->op.let.body, out)) {
			RZ_LOG_ERROR("prototype: LET body failed to evaluate.\n");
			return false;
		}
		// No need to free the LET variable.
		// It is simply overwritten next time.
		break;
	}
	case RZ_IL_OP_ITE: {
		if (!interpreter_prototype_eval_pure(ctx, pure->op.ite.condition, out)) {
			RZ_LOG_ERROR("prototype: ITE condition failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			// Can't decide which pure to evaluate.
			goto map_to_top;
		}

		if (abstr_is_true(ctx->inst, out)) {
			if (!interpreter_prototype_eval_pure(ctx, pure->op.ite.x, out)) {
				RZ_LOG_ERROR("prototype: ITE x failed to evaluate.\n");
				return false;
			}
		} else {
			if (!interpreter_prototype_eval_pure(ctx, pure->op.ite.y, out)) {
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
		out->is_const = true;
		break;
	case RZ_IL_OP_B1:
		if (rz_bv_len(out->bv) != 1) {
			rz_bv_cast_inplace(out->bv, 1, false);
		}
		rz_bv_set(out->bv, 0, true);
		out->is_const = true;
		break;
	case RZ_IL_OP_CAST: {
		if (!interpreter_prototype_eval_pure(ctx, pure->op.cast.val, out)) {
			RZ_LOG_ERROR("prototype: CAST val failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!interpreter_prototype_eval_pure(ctx, pure->op.cast.fill, &fill_bit)) {
			RZ_LOG_ERROR("prototype: CAST fill failed to evaluate.\n");
			return false;
		}
		if (!fill_bit.is_const) {
			rz_bv_fini(fill_bit.bv);
			goto map_to_top;
		}
		rz_bv_cast_inplace(out->bv, pure->op.cast.length, abstr_is_true(ctx->inst, &fill_bit));
		break;
	}
	case RZ_IL_OP_BITV:
		rz_bv_cast_inplace(out->bv, rz_bv_len(pure->op.bitv.value), false);
		rz_bv_copy(out->bv, pure->op.bitv.value);
		out->is_const = true;
		break;
	case RZ_IL_OP_APPEND: {
		STACK_ABSTR_DATA_OUT(high);
		if (!interpreter_prototype_eval_pure(ctx, pure->op.append.high, &high)) {
			RZ_LOG_ERROR("prototype: APPEND high failed to evaluate.\n");
			return false;
		}
		if (!high.is_const) {
			rz_bv_fini(high.bv);
			goto map_to_top;
		}
		if (!interpreter_prototype_eval_pure(ctx, pure->op.append.low, out)) {
			RZ_LOG_ERROR("prototype: APPEND low failed to evaluate.\n");
			rz_bv_fini(high.bv);
			return false;
		}
		if (!out->is_const) {
			rz_bv_fini(high.bv);
			goto map_to_top;
		}
		rz_bv_cast_inplace(out->bv, rz_bv_len(out->bv) + rz_bv_len(high.bv), false);
		rz_bv_copy_nbits(high.bv, 0, out->bv, rz_bv_len(out->bv), rz_bv_len(high.bv));
		out->is_const = true;
		rz_bv_fini(high.bv);
		break;
	}
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_INV: {
		RzILOpPure *x = pure->code == RZ_IL_OP_INV ? pure->op.boolinv.x : pure->op.lognot.bv;
		if (!interpreter_prototype_eval_pure(ctx, x, out)) {
			RZ_LOG_ERROR("prototype: INV x failed to evaluate.\n");
			return false;
		}
		if (out->is_const) {
			rz_bv_not_inplace(out->bv);
		}
		break;
	}
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_AND: {
		RzILOpPure *px = pure->code == RZ_IL_OP_AND ? pure->op.booland.x : pure->op.logand.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_AND ? pure->op.booland.y : pure->op.logand.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: AND x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: AND y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_and_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_OR: {
		RzILOpPure *px = pure->code == RZ_IL_OP_OR ? pure->op.boolor.x : pure->op.logor.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_OR ? pure->op.boolor.y : pure->op.logor.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: OR x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: OR y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_or_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_XOR: {
		RzILOpPure *px = pure->code == RZ_IL_OP_XOR ? pure->op.boolxor.x : pure->op.logxor.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_XOR ? pure->op.boolxor.y : pure->op.logxor.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: XOR x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: XOR y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_xor_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
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
			goto map_to_top;
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
		if (!interpreter_prototype_eval_pure(ctx, bv, out)) {
			RZ_LOG_ERROR("prototype: MSB/LSB/IS_ZERO bv failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		bool truth = truth_test(out->bv);
		rz_bv_cast_inplace(out->bv, 1, false);
		// TODO: Truth bit.
		rz_bv_set(out->bv, 0, truth);
		break;
	}
	case RZ_IL_OP_NEG: {
		if (!interpreter_prototype_eval_pure(ctx, pure->op.neg.bv, out)) {
			RZ_LOG_ERROR("prototype: NEG bv failed to evaluate.\n");
			return false;
		}
		if (out->is_const) {
			rz_bv_neg_inplace(out->bv);
		}
		break;
	}
	case RZ_IL_OP_ADD: {
		RzILOpPure *px = pure->op.add.x;
		RzILOpPure *py = pure->op.add.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: ADD x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: ADD y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_add_inplace(out->bv, y.bv, NULL)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_SUB: {
		RzILOpPure *px = pure->op.sub.x;
		RzILOpPure *py = pure->op.sub.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: SUB y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_sub_inplace(out->bv, y.bv, NULL)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_SHIFTL:
	case RZ_IL_OP_SHIFTR: {
		RzILOpPure *px = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.x : pure->op.shiftl.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.y : pure->op.shiftl.y;
		RzILOpPure *pfill_bit = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.fill_bit : pure->op.shiftl.fill_bit;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!interpreter_prototype_eval_pure(ctx, pfill_bit, &fill_bit)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) fill_bit failed to evaluate.\n");
			return false;
		}
		if (!fill_bit.is_const) {
			rz_bv_fini(fill_bit.bv);
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		bool (*shift)(RzBitVector *bv, ut32 size, bool fill_bit);
		shift = pure->code == RZ_IL_OP_SHIFTR ? rz_bv_rshift_fill : rz_bv_lshift_fill;
		if (!shift(out->bv, rz_bv_to_ut64(y.bv), abstr_is_true(ctx->inst, &fill_bit))) {
			rz_bv_fini(fill_bit.bv);
			rz_bv_fini(y.bv);
			goto map_to_top;
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
			goto map_to_top;
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

		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: CMP x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: CMP y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		bool cmp_is_true = cmp(out->bv, y.bv);
		rz_bv_cast_inplace(out->bv, 1, false);
		rz_bv_set(out->bv, 0, cmp_is_true);
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_LOADW:
	case RZ_IL_OP_LOAD: {
		STACK_ABSTR_DATA_OUT(ld_addr);
		RzILOpPure *key = pure->code == RZ_IL_OP_LOAD ? pure->op.load.key : pure->op.loadw.key;
		RzILMemIndex mem_idx = pure->code == RZ_IL_OP_LOAD ? 0 : pure->op.loadw.mem;
		if (!interpreter_prototype_eval_pure(ctx, key, &ld_addr)) {
			RZ_LOG_ERROR("prototype: LOAD/LOADW key failed to evaluate.\n");
			rz_bv_fini(ld_addr.bv);
			return false;
		}
		if (!ld_addr.is_const) {
			rz_bv_fini(ld_addr.bv);
			goto map_to_top;
		}
		if (rz_bv_len(ld_addr.bv) == 64) {
			// TODO: Remove normalization.
			// Unset bit 63 is required, because the RzBuffer API only supports
			// st64 addresses.
			RzBitVector mask = { 0 };
			rz_bv_init(&mask, 64);
			rz_bv_set_from_ut64(&mask, 0x7fffffffffffffff);
			rz_bv_and_inplace(ld_addr.bv, &mask);
		}

		report_yield_xref(ctx, 0, ctx->astate->pc, &ld_addr, RZ_ANALYSIS_XREF_TYPE_MEM_READ);
		size_t n_bits = pure->code == RZ_IL_OP_LOAD ? ctx->inst->il_ctx->config->mem_key_size : pure->op.loadw.n_bits;
		if (!load_abstr_data(ctx->inst, mem_idx, &ld_addr, n_bits, out)) {
			rz_bv_fini(ld_addr.bv);
			goto map_to_top;
		}
		rz_bv_fini(ld_addr.bv);
		break;
	}
	case RZ_IL_OP_MUL: {
		RzILOpPure *px = pure->op.mul.x;
		RzILOpPure *py = pure->op.mul.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: MUL x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: MUL y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_mul_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_MOD: {
		RzILOpPure *px = pure->op.mod.x;
		RzILOpPure *py = pure->op.mod.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: MOD x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: MOD y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_mod_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_DIV: {
		RzILOpPure *px = pure->op.div.x;
		RzILOpPure *py = pure->op.div.y;
		if (!interpreter_prototype_eval_pure(ctx, px, out)) {
			RZ_LOG_ERROR("prototype: DIV x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!interpreter_prototype_eval_pure(ctx, py, &y)) {
			RZ_LOG_ERROR("prototype: DIV y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		if (!rz_bv_div_inplace(out->bv, y.bv)) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		rz_bv_fini(y.bv);
		break;
	}
	case RZ_IL_OP_SDIV:
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
		RZ_LOG_ERROR("Unhandled pure %" PFMT32d "\n", pure->code);
		// Not implemented.
		goto map_to_top;
	}
	return true;

map_to_top:
	out->is_const = false;
	return true;
}


#define MAX_INVOCATIONS_PER_BLOCK 3

bool state_as_str(RZ_NONNULL const RzInterpAbstrState *state,
	RZ_NONNULL RZ_OUT RzStrBuf *sb);

RZ_OWN RzInterpAbstrVal *clone_val(const RzInterpAbstrVal *val) {
	ProtoIntrprAbstrData *r = RZ_NEW0(ProtoIntrprAbstrData);
	if (!r) {
		return NULL;
	}
	r->is_const = AD(val)->is_const;
	r->bv = rz_bv_dup(AD(val)->bv);
	return r;
}

static bool eval(RZ_NONNULL RzInterpRunContext *ctx, RZ_NONNULL const RzILCacheBlock *il_bb) {

	// Reset call candidate tracking for each basic block.
	memset(&ctx->call_cand, 0, sizeof(ctx->call_cand));

	// Now execute the actual effects of the BLOCK.
	RzInterpAbstrState *astate = ctx->astate;
	void **it;
	rz_pvector_foreach (il_bb->il_ops, it) {
		ut64 pc = astate->pc;
		RZ_LOG_DEBUG("prototype: Eval PC = 0x%" PFMT64x "\n", pc);
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		state_as_str(ctx->astate, &sb);
		RZ_LOG_DEBUG("%s\n", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		rz_strbuf_init(&sb);
		if (pc == il_bb->addr) {
			rz_strbuf_append(&sb, "ENTRY ");
		}
		if (rz_vector_index_ptr(&il_bb->il_ops->v, rz_pvector_len(il_bb->il_ops) - 1) == it) {
			rz_strbuf_append(&sb, "EXIT ");
		}
		state_as_str_short(ctx->inst, &sb, ctx->astate);
		rz_meta_set_string(ctx->inst->a, RZ_META_TYPE_COMMENT, pc, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		RzILCacheInsnPkt *pkt = *it;

		// Prepare next pc, the evalutation may overwrite this.
		ut64 next_pc = pc + pkt->insn_pkt_size;
		set_pc(ctx->astate, next_pc);

		if (!interpreter_prototype_eval_effect(ctx, pkt->effect, pkt->insn_pkt_size)) {
			return false;
		}
		if (astate->pc_state != RZ_INTERP_PC_CONST || astate->pc != next_pc) {
			// Unreachable or a jump happened somewhere other than fallthrough, so we can't continue
			// interpreting the block linearly, but have to push the new location
			break;
		}
	}

	if (astate->pc_state != RZ_INTERP_PC_UNREACHABLE) {
		rz_interp_run_push(ctx, ctx->astate);
	}

	return true;
}

static bool init_state(RZ_BORROW RzInterpAbstrState *state) {
	state->pc = 0;
	state->pc_state = RZ_INTERP_PC_UNREACHABLE;

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		ProtoIntrprAbstrData *av = adata_new_top();
		if (!av) {
			break;
		}
		ht_up_update(state->globals, djb2_reg_name, av);
	}
	rz_iterator_free(it);
	return true;
}

static bool reset_state(RZ_BORROW RzInterpAbstrState *state, ut64 entry_point) {
	state->pc_state = RZ_INTERP_PC_CONST;
	state->pc = entry_point;

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(state->globals, djb2_reg_name, NULL);
		rz_bv_set_from_ut64(AD(av)->bv, 0);
		AD(av)->is_const = false;
	}
	rz_iterator_free(it);
	state->bb_addr = 0;
	state->bb_size = 0;
	return true;
}

static bool fini_state(RZ_BORROW RzInterpAbstrState *state) {
	RzIterator *it = ht_up_as_iter(state->globals);
	RzInterpAbstrVal **v;
	rz_iterator_foreach(it, v) {
		adata_free(*v);
	}
	rz_iterator_free(it);

	it = ht_up_as_iter(state->locals);
	rz_iterator_foreach(it, v) {
		adata_free(*v);
	}
	rz_iterator_free(it);

	it = ht_up_as_iter(state->lets);
	rz_iterator_foreach(it, v) {
		adata_free(*v);
	}
	rz_iterator_free(it);
	return true;
}

/**
 * \brief Join (least upper bound) on values
 * \return True if a was changed
 */
static bool join_val(RZ_BORROW RZ_INOUT RzInterpAbstrVal *a, RZ_BORROW RZ_IN const RzInterpAbstrVal *b) {
	ProtoIntrprAbstrData *ad = AD(a);
	ProtoIntrprAbstrData *bd = AD(b);
	if (ad->is_const && bd->is_const && rz_bv_eq(ad->bv, bd->bv)) {
		// identical values, a already has the least upper bound
		return false;
	}
	// for anything else, the least upper bound is top
	bool changed = ad->is_const;
	ad->is_const = false;
	return changed;
}

/**
 * \brief Join (least upper bound) on var sets
 * \return True if a was changed
 */
static bool join_vars(RZ_BORROW RZ_INOUT HtUP *a, RZ_BORROW RZ_IN HtUP *b) {
	RzIterator *it = ht_up_as_iter_keys(a);
	ut64 *k;
	bool changed = false;
	rz_iterator_foreach(it, k) {
		RzInterpAbstrVal *av = ht_up_find(a, *k, NULL);
		RzInterpAbstrVal *bv = ht_up_find(b, *k, NULL);
		if (!av || !bv) {
			continue;
		}
		if (join_val(av, bv)) {
			changed = true;
		}
	}
	return changed;
}

bool join_state(RZ_BORROW RZ_INOUT RzInterpAbstrState *a, RZ_BORROW RZ_IN const RzInterpAbstrState *b) {
	bool global_change = join_vars(a->globals, b->globals);
	bool local_change = join_vars(a->locals, b->locals);
	// lets are not be relevant here since they are immutable within their scope
	return global_change || local_change;
}

bool val_as_str(RZ_NONNULL const RzInterpAbstrVal *val, RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(val && sb, false);
	ProtoIntrprAbstrData *av = AD(val);
	if (av->is_const) {
		char *s = rz_bv_as_hex_string(av->bv, false);
		if (!s) {
			return false;
		}
		rz_strbuf_append(sb, s);
		free(s);
	} else {
		rz_strbuf_append(sb, "⊤");
	}
	return true;
}

bool state_as_str(RZ_NONNULL const RzInterpAbstrState *state,
	RZ_NONNULL RZ_OUT RzStrBuf *sb) {
	rz_return_val_if_fail(state && sb, false);

	rz_strbuf_append(sb, "Globals\n\n");
	rz_strbuf_append(sb, "\tpc = ");
	if (state->pc_state == RZ_INTERP_PC_CONST) {
		rz_strbuf_appendf(sb, "0x%" PFMT64x, state->pc);
	} else {
		rz_strbuf_append(sb, state->pc_state == RZ_INTERP_PC_ANY ? "⊤" : "⊥");
	}
	rz_strbuf_append(sb, "\n\n");

	RzIterator *it = ht_up_as_iter_keys(state->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		const char *gname = ht_up_find(state->var_name_hashes, *k, NULL);
		rz_strbuf_appendf(sb, "\t%s = ", gname);
		RzInterpAbstrVal *av = ht_up_find(state->globals, *k, NULL);
		val_as_str(av, sb);
		rz_strbuf_append(sb, "\n");
	}
	rz_iterator_free(it);
	return true;
}

void state_as_str_short(RzInterpInstance *iset, RZ_OUT RzStrBuf *out, RzInterpAbstrState *astate) {
	bool first = true;
	RzIterator *it = ht_up_as_iter_keys(astate->globals);
	ut64 *k;
	rz_iterator_foreach(it, k) {
		ut64 djb2_reg_name = *k;
		RzInterpAbstrVal *av = ht_up_find(astate->globals, djb2_reg_name, NULL);
		ProtoIntrprAbstrData *val = AD(av);
		if (!val->is_const) {
			continue;
		}
		if (!first) {
			rz_strbuf_append(out, ", ");
		}
		first = false;
		const char *varname = ht_up_find(astate->var_name_hashes, djb2_reg_name, NULL);
		rz_strbuf_appendf(out, "%s = ", varname);
		iset->plugin->val_as_str(av, out);
	}
}

static RzInterpPlugin rz_interpreter_plugin_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/top abstractions.",
	.license = "LGPL-3.0-only",
	.supported_yields = { RZ_INTERP_YIELD_KIND_XREF, RZ_INTERP_YIELD_KIND_CALL_CANDIDATE },
	.clone_val = clone_val,
	.eval = eval,
	.init_state = init_state,
	.reset_state = reset_state,
	.fini_state = fini_state,
	.join_state = join_state,
	.state_as_str = state_as_str,
	.val_as_str = val_as_str
};

RZ_API RzInquiryPlugin rz_inquiry_plugin_interpreter_prototype = {
	.p_interpreter = &rz_interpreter_plugin_prototype,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_INTERPRETER,
	.data = &interpreter_prototype
};
#endif
