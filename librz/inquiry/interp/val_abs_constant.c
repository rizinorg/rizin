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

typedef struct {
	/**
	 * \brief Set if the abstract value represents a single constant bitvector.
	 * If set, the bit vector below is a valid concrete value.
	 * If unset it is a top value, i.e. represents the set of all bitvectors.
	 */
	bool is_const;
	/**
	 * \brief The single constant value.
	 * If is_const is unset this might hold garbage.
	 */
	RzBitVector *bv;
} ProtoIntrprAbstrData;

/**
 * \brief Abstract data getter from the RzInterpAbstrVal
 */
#define AD(av) ((ProtoIntrprAbstrData *)rz_interp_abstr_val_unpack(av))

static RzInterpAbstrVal *pack(ProtoIntrprAbstrData *val) {
	return rz_interp_abstr_val_pack(val);
}

/**
 * \brief In bytes
 *
 * TODO: find a sweet spot here where this size is as small is possible,
 * but in practice only very few heap allocations have to happen.
 */
#define BV_STACK_MAX_SIZE 0x100

/**
 * \brief Initializes an AbstractData object on the stack.
 * The bitvector pre-allocates BV_STACK_MAX_SIZE bytes on the stack for large bit vectors.
 * Any value larger than these bits will be stored in heap allocated memory.
 * Because of this the bit vector should always be passed to rz_bv_fini() after usage.
 */
#define STACK_ABSTR_DATA_OUT(name) \
	ut8 _##name##_bv_large_buf[BV_STACK_MAX_SIZE] = { 0 }; \
	RzBitVector _##name##_bv_large = { .len = BV_STACK_MAX_SIZE, ._elem_len = BV_STACK_MAX_SIZE, .bits.large_a = _##name##_bv_large_buf, .stack_alloc = true }; \
	ProtoIntrprAbstrData name = { .is_const = false, .bv = &_##name##_bv_large };

static RZ_OWN RzInterpAbstrVal *val_new_top() {
	ProtoIntrprAbstrData *ad = RZ_NEW0(ProtoIntrprAbstrData);
	ad->is_const = false;
	ad->bv = rz_bv_new(BV_STACK_MAX_SIZE);
	return pack(ad);
}

static void val_free(RzInterpAbstrVal *val) {
	if (!val) {
		return;
	}
	ProtoIntrprAbstrData *adata = AD(val);
	rz_bv_free(adata->bv);
	free(adata);
}

static bool val_is_top(RZ_NONNULL const RzInterpAbstrVal *val) {
	return !AD(val)->is_const;
}

bool static val_may_be_bool(RZ_NONNULL const RzInterpAbstrVal *val, bool value) {
	if (!AD(val)->is_const) {
		return true;
	}
	return value != rz_bv_is_zero_vector(AD(val)->bv);
}

static void val_set_top(RZ_NONNULL RzInterpAbstrVal *val) {
	AD(val)->is_const = false;
}

static bool eval_pure(RzInterpRunContext *ctx, const RzILOpPure *pure, RZ_OUT RzInterpAbstrVal *out_val) {
	ProtoIntrprAbstrData *out = AD(out_val);
	switch (pure->code) {
	default:
	case RZ_IL_OP_VAR: {
		if (!read_var_from_state(ctx->inst, ctx->astate, pure->op.var.kind, pure->op.var.hash, out_val)) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			return false;
		}
		break;
	}
	case RZ_IL_OP_LET: {
		ut64 vhash = pure->op.let.hash;
		if (!eval_pure(ctx, pure->op.let.exp, out_val)) {
			RZ_LOG_ERROR("prototype: LET expression failed to evaluate.\n");
			return false;
		}
		write_var_to_state(ctx->inst, ctx->astate, RZ_IL_VAR_KIND_LOCAL_PURE, vhash, out_val);
		// Evaluate body
		if (!eval_pure(ctx, pure->op.let.body, out_val)) {
			RZ_LOG_ERROR("prototype: LET body failed to evaluate.\n");
			return false;
		}
		// No need to free the LET variable.
		// It is simply overwritten next time.
		break;
	}
	case RZ_IL_OP_ITE: {
		if (!eval_pure(ctx, pure->op.ite.condition, out_val)) {
			RZ_LOG_ERROR("prototype: ITE condition failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			// Can't decide which pure to evaluate.
			goto map_to_top;
		}

		// TODO: eval both if top
		if (!val_may_be_bool(out_val, false)) {
			if (!eval_pure(ctx, pure->op.ite.x, out_val)) {
				RZ_LOG_ERROR("prototype: ITE x failed to evaluate.\n");
				return false;
			}
		} else {
			if (!eval_pure(ctx, pure->op.ite.y, out_val)) {
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
		if (!eval_pure(ctx, pure->op.cast.val, out_val)) {
			RZ_LOG_ERROR("prototype: CAST val failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!eval_pure(ctx, pure->op.cast.fill, pack(&fill_bit))) {
			RZ_LOG_ERROR("prototype: CAST fill failed to evaluate.\n");
			return false;
		}
		if (!fill_bit.is_const) {
			rz_bv_fini(fill_bit.bv);
			goto map_to_top;
		}
		rz_bv_cast_inplace(out->bv, pure->op.cast.length, !rz_bv_is_zero_vector(fill_bit.bv));
		break;
	}
	case RZ_IL_OP_BITV:
		rz_bv_cast_inplace(out->bv, rz_bv_len(pure->op.bitv.value), false);
		rz_bv_copy(out->bv, pure->op.bitv.value);
		out->is_const = true;
		break;
	case RZ_IL_OP_APPEND: {
		STACK_ABSTR_DATA_OUT(high);
		if (!eval_pure(ctx, pure->op.append.high, pack(&high))) {
			RZ_LOG_ERROR("prototype: APPEND high failed to evaluate.\n");
			return false;
		}
		if (!high.is_const) {
			rz_bv_fini(high.bv);
			goto map_to_top;
		}
		if (!eval_pure(ctx, pure->op.append.low, pack(out))) {
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
		if (!eval_pure(ctx, x, out_val)) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: AND x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: OR x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: XOR x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, bv, out_val)) {
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
		if (!eval_pure(ctx, pure->op.neg.bv, out_val)) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: ADD x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: SUB x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
			RZ_LOG_ERROR("prototype: SHIFT(L/R) y failed to evaluate.\n");
			return false;
		}
		if (!y.is_const) {
			rz_bv_fini(y.bv);
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(fill_bit);
		if (!eval_pure(ctx, pfill_bit, pack(&fill_bit))) {
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
		if (!shift(out->bv, rz_bv_to_ut64(y.bv), !rz_bv_is_zero_vector(fill_bit.bv))) {
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

		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: CMP x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, key, pack(&ld_addr))) {
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

		report_yield_xref(ctx, 0, ctx->astate->pc, pack(&ld_addr), RZ_ANALYSIS_XREF_TYPE_MEM_READ);
		size_t n_bits = pure->code == RZ_IL_OP_LOAD ? ctx->inst->il_ctx->config->mem_key_size : pure->op.loadw.n_bits;
		if (!load_abstr_data(ctx->inst, mem_idx, ld_addr.bv, n_bits, out_val)) {
			rz_bv_fini(ld_addr.bv);
			goto map_to_top;
		}
		rz_bv_fini(ld_addr.bv);
		break;
	}
	case RZ_IL_OP_MUL: {
		RzILOpPure *px = pure->op.mul.x;
		RzILOpPure *py = pure->op.mul.y;
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: MUL x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: MOD x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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
		if (!eval_pure(ctx, px, out_val)) {
			RZ_LOG_ERROR("prototype: DIV x failed to evaluate.\n");
			return false;
		}
		if (!out->is_const) {
			goto map_to_top;
		}
		STACK_ABSTR_DATA_OUT(y);
		if (!eval_pure(ctx, py, pack(&y))) {
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

void val_copy(RzInterpAbstrVal *dst_val, const RzInterpAbstrVal *src_val) {
	ProtoIntrprAbstrData *dst = AD(dst_val);
	ProtoIntrprAbstrData *src = AD(src_val);
	rz_return_if_fail(dst && src && dst->bv && src->bv);
	rz_bv_cast_inplace(dst->bv, rz_bv_len(src->bv), false);
	rz_bv_copy(dst->bv, src->bv);
	dst->is_const = src->is_const;
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

static bool to_concrete_const(RZ_NONNULL const RzInterpAbstrVal *val, RZ_NULLABLE RZ_OUT RzBitVector *out) {
	if (!AD(val)->is_const) {
		return false;
	}
	if (out) {
		rz_bv_cast_inplace(out, rz_bv_len(AD(val)->bv), false);
		rz_bv_copy(out, AD(val)->bv);
	}
	return true;
}

static RzInterpPlugin rz_interpreter_plugin_prototype = {
	.name = "constant",
	.val_new_top = val_new_top,
	.val_free = val_free,
	.set_top = val_set_top,
	.is_top = val_is_top,
	.may_be_bool = val_may_be_bool,
	.to_concrete_const = to_concrete_const,
	.copy = val_copy,
	.eval_pure = eval_pure,
	.join = join_val,
	.val_as_str = val_as_str,
};

RZ_API RzInquiryPlugin rz_inquiry_plugin_interpreter_prototype = {
	.name = "abstr_int_prototype",
	.author = "Rot127",
	.version = "0.1p",
	.desc = "A prototype interpreter for constant/top abstractions.",
	.license = "LGPL-3.0-only",
	.p_interpreter = &rz_interpreter_plugin_prototype,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_INTERPRETER,
	.data = &interpreter_prototype
};
#endif
