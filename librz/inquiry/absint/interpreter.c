// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2025-2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * \brief Core abstract interpretation
 *
 * The implementation here delegates the actual value abstraction to pluggable RzAbsIntValueDomains
 * and requests information from rizin through callbacks. It is thus able to run on arbitrary threads
 * if the callbacks behave accordingly.
 */

// Our analysis loop works by first performing abstract interpretation until a fixpoint is reached,
// and only in a second pass collecting analysis information from it such as xrefs.
// That is because before the fixpoint, abstract states will not yet represent all possible concrete states.
//
// Other approaches are conceivable, such as doing analysis every time a block is evaluated and if
// it is evaluated again, throwing away the previous results, so we encapsulate the logic for when to
// do what in these functions:

#include "absint_priv.h"

typedef enum {
	EVAL_RESULT_OK,
	EVAL_RESULT_ERROR,
	EVAL_RESULT_BREAK
} EvalResult;

static void interp_add_comment(RzAbsIntRunContext *ctx, ut64 addr, const char *cmt) {
	// building the commment string passed to this function is expensive, so assert that it is only called
	// when actually requested.
	rz_return_if_fail(interp_is_analyzing(ctx) && (ctx->res_dimen & RZ_ABSINT_RESULT_DIMEN_COMMENTS));
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	char *existing = ht_up_find(ctx->res->comments, addr, NULL);
	if (existing) {
		rz_strbuf_appendf(&sb, "%s; ", existing);
	}
	rz_strbuf_append(&sb, cmt);
	char *val = rz_strbuf_drain_nofree(&sb);
	if (!ht_up_update(ctx->res->comments, addr, val)) {
		free(val);
	}
}

RZ_API RZ_OWN RzAbsIntInstance *rz_absint_instance_new(RzAnalysis *analysis, RZ_NONNULL RZ_BORROW const RzAbsIntConfig *config) {
	rz_return_val_if_fail(analysis && config && config->val_domain && config->io_read && config->lift_block, NULL);

	RzAbsIntInstance *inst = RZ_NEW0(RzAbsIntInstance);
	if (!inst) {
		return NULL;
	}
	inst->config = *config;

	const RzAnalysisPlugin *cur = rz_analysis_plugin_current(analysis);
	if (!cur || !cur->arch) {
		goto err_inst;
	}
	if (!cur->il_config) {
		RZ_LOG_ERROR("Plugin %s does not support RzIL.\n", rz_str_get_null(cur->arch));
		goto err_inst;
	}
	inst->arch_name = cur->arch;

	RzAnalysisILContext *il_ctx = rz_analysis_il_context_resolve(analysis);
	if (!il_ctx) {
		RZ_LOG_ERROR("Failed to create analysis IL context.\n");
		goto err_inst;
	}

	inst->il_ctx = il_ctx;

	inst->var_name_hashes = ht_up_new(NULL, free);
	if (!inst->var_name_hashes) {
		goto err_il_ctx;
	}
	for (size_t i = 0; i < il_ctx->reg_binding->regs_count; i++) {
		const char *rname = il_ctx->reg_binding->regs[i].name;
		ut64 djb2_reg_hash = rz_str_djb2_hash(rname);
		if (!ht_up_insert(inst->var_name_hashes, djb2_reg_hash, rz_str_dup(rname))) {
			RZ_LOG_ERROR("DJB2 hash collision of the register name %s. DJB2 hash = 0x%" PFMT64x "\n",
				rname, djb2_reg_hash);
			goto err_var_name_hashes;
		}
	}

	return inst;
err_var_name_hashes:
	ht_up_free(inst->var_name_hashes);
err_il_ctx:
	rz_analysis_il_context_free(il_ctx);
err_inst:
	free(inst);
	return NULL;
}

RZ_API void rz_absint_instance_free(RZ_OWN RZ_NULLABLE RzAbsIntInstance *inst) {
	if (!inst) {
		return;
	}
	ht_up_free(inst->var_name_hashes);
	rz_analysis_il_context_free(inst->il_ctx);
	free(inst);
}

static void report_yield_xref(
	RzAbsIntRunContext *ctx,
	size_t insn_pkt_size,
	ut64 from,
	const RzAbsIntVal *to,
	RzAnalysisXRefType type) {
	if (!interp_is_analyzing(ctx) || !(ctx->res_dimen & RZ_ABSINT_RESULT_DIMEN_XREFS)) {
		return;
	}
	RzBitVector to_bv;
	rz_bv_init(&to_bv, 64);
	if (!val_domain(ctx->inst)->to_concrete_const(to, &to_bv) || rz_bv_len(&to_bv) > 64) {
		// Isn't reported
		// TODO: we might also want to report multiple values here depending on the value domain
		goto cleanup;
	}
	if (type == RZ_ANALYSIS_XREF_TYPE_CODE &&
		RZ_STR_EQ(ctx->inst->arch_name, "hexagon") &&
		from + insn_pkt_size == rz_bv_to_ut64(&to_bv)) {
		// Ugly work around.
		// Because we don't have RzArch yet the Hexagon plugin adds a JUMP at the
		// end of each and every instruction packet.
		// This is necessary because the RzIL VM would otherwise just add 4 to the PC,
		// which is too little for a packet with 2+ instructions.
		// We don't want to report the code references to the next instruction
		// packet. So skip them here.
		goto cleanup;
	}

	ut64 to_addr = rz_bv_to_ut64(&to_bv);
	RzAnalysisXRef *xref = rz_vector_push(&ctx->res->xrefs, NULL);
	if (!xref) {
		goto cleanup;
	}
	xref->from = from;
	xref->to = to_addr;
	xref->type = type;
cleanup:
	rz_bv_fini(&to_bv);
}

static void write_var_to_state(RzAbsIntInstance *inst,
	RzAbsIntState *astate,
	RzILVarKind kind,
	ut64 var_id,
	const RzAbsIntVal *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = astate->lets;
		break;
	}
	RzAbsIntVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		if (kind == RZ_IL_VAR_KIND_GLOBAL) {
			RZ_LOG_WARN("New global variable created: 0x%" PFMT64x "\n", var_id)
			return;
		}
		av = val_domain(inst)->val_new_top();
		if (!av) {
			rz_warn_if_reached();
			return;
		}
		ht_up_insert(ht_vals, var_id, av);
	}
	val_domain(inst)->copy(av, data);
}

static bool read_var_from_state(RzAbsIntInstance *inst,
	RzAbsIntState *astate,
	RzILVarKind kind,
	ut64 var_id,
	RZ_OUT RzAbsIntVal *data) {
	HtUP *ht_vals;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return false;
	case RZ_IL_VAR_KIND_GLOBAL:
		ht_vals = astate->globals;
		break;
	case RZ_IL_VAR_KIND_LOCAL:
		ht_vals = astate->locals;
		break;
	case RZ_IL_VAR_KIND_LOCAL_PURE:
		ht_vals = astate->lets;
		break;
	}
	RzAbsIntVal *av = ht_up_find(ht_vals, var_id, NULL);
	if (!av) {
		// Variable doesn't exist.
		// This should never happen and is a bug.
		rz_warn_if_reached();
		return false;
	}
	val_domain(inst)->copy(data, av);
	return true;
}

static void store_abstr_data(
	RzAbsIntInstance *iset,
	RzILMemIndex mem_idx,
	const RzAbsIntVal *addr,
	const RzAbsIntVal *src) {
	// TODO: handle with memory abstractions
	// See: https://github.com/rizinorg/rizin/issues/6749
}

static EvalResult load_abstr_data(
	RzAbsIntInstance *inst,
	RzILMemIndex mem_idx,
	const RzBitVector *addr,
	size_t n_bits,
	RZ_OUT RzAbsIntVal *out) {
	RzAbsIntIOReadRequest io_req = { 0 };

	RzBitVector out_bv;
	rz_bv_init(&out_bv, n_bits);

	io_req.addr = addr;
	io_req.ld_data = &out_bv;
	io_req.mem_idx = mem_idx;
	io_req.n_bits = n_bits;
	io_req.big_endian = inst->il_ctx->config->big_endian;
	RzAbsIntIOReadResult read_res = inst->config.io_read(&io_req, inst->config.cb_user);
	if (read_res == RZ_ABSINT_IO_READ_RESULT_BREAK) {
		return EVAL_RESULT_BREAK;
	}
	if (read_res != RZ_ABSINT_IO_READ_RESULT_OK) {
		val_domain(inst)->set_top(out);
		return EVAL_RESULT_OK;
	}
	val_domain(inst)->set_const_bv(out, &out_bv);

	char *bytes = rz_bv_as_hex_string(&out_bv, true);
	RZ_LOG_DEBUG("prototype: READ @ mem:%" PFMT32d " 0x%" PFMT64x " : %s\n", mem_idx, rz_bv_to_ut64(io_req.addr), bytes);
	free(bytes);
	return EVAL_RESULT_OK;
}

static bool set_abstr_pc(RzAbsIntInstance *inst, RzAbsIntState *state, RzAbsIntVal *pc) {
	rz_return_val_if_fail(state && pc, false);
	RzBitVector pc_bv;
	rz_bv_init(&pc_bv, 64);
	if (val_domain(inst)->to_concrete_const(pc, &pc_bv)) {
		state->pc_state = RZ_ABSINT_PC_CONST;
		state->pc = rz_bv_to_ut64(&pc_bv);
	} else {
		state->pc_state = RZ_ABSINT_PC_ANY;
	}
	rz_bv_fini(&pc_bv);
	RZ_LOG_DEBUG("prototype: set_abstr_pc() - Set PC: 0x%" PFMT64x " (%s)\n",
		state->pc, state->pc_state == RZ_ABSINT_PC_CONST ? "Constant" : "Top");
	return true;
}

/**
 * \brief Decide whether the given value, when stored, may be assumed to be a return address
 *
 * We define a call as a jump that is preceded by a store (to register or memory) of some value
 * that may be a matching return address. The store and jump must happen in the same block
 * and not have any in-edges or other jumps in between them.
 * This function's implementation defines our notion of what "matching return address" means.
 * As new edge-cases, e.g. in different architectures, are discovered, it may be refined successively.
 *
 * The overall idea of this kind of call identification is from:
 * Rev.ng: a unified binary analysis framework to recover CFGs and function boundaries (CC 2017)
 * https://doi.org/10.1145/3033019.3033028
 * https://web.archive.org/web/20250904202421/https://hexhive.epfl.ch/publications/files/17CC.pdf
 */
static bool value_indicates_ret_addr_write(RzAbsIntRunContext *ctx, RzAbsIntVal *val) {
	RzBitVector bv;
	rz_bv_init(&bv, 64);
	// Hint: pc addrs coming from the lifters are currently just opaque bitvectors.
	// So we do not know whether the constant contents of val are actually taken from the architecture's
	// pc register or match the instruction address by chance only.
	// We could add a flag to RzILOpArgsBV that would be set by lifters to indicate that the constant value
	// originates from the pc and use that here.
	// This may also help with the sparc workaround.
	// The downside is that a pattern like this in non-relocatable code would not be detected as call:
	// 0x42 mov lr, 0x4a
	// 0x46 mov pc, r0
	// 0x4a ...
	// but it is questionable whether that should be even detected at all, since there is no way to know
	// if it is intended as call or jump.
	bool ret = val_domain(ctx->inst)->to_concrete_const(val, &bv) &&
		(rz_bv_to_ut64(&bv) == ctx->il_block_end ||
			// Sparc stores the call instruction PC into o8.
			// The return instruction jumps then to o7+8.
			(rz_str_startswith(ctx->inst->arch_name, "sparc") && rz_bv_to_ut64(&bv) == ctx->astate->pc - 4));
	rz_bv_fini(&bv);
	return ret;
}

static EvalResult eval_pure(RzAbsIntRunContext *ctx, const RzILOpPure *pure, RZ_OUT RzAbsIntVal *out) {
#define EVAL_SUB_OR_RETURN_CLEANUP(op, out, cleanup) \
	do { \
		EvalResult res = eval_pure(ctx, (op), (out)); \
		if (RZ_UNLIKELY(res == EVAL_RESULT_BREAK)) { \
			cleanup return EVAL_RESULT_BREAK; \
		} \
		if (RZ_UNLIKELY(res != EVAL_RESULT_OK)) { \
			RZ_LOG_ERROR("eval_pure failed to evaluate " #op "\n"); \
			cleanup goto map_to_top; \
		} \
	} while (0)
#define EVAL_SUB_OR_RETURN(op, out) EVAL_SUB_OR_RETURN_CLEANUP(op, out, )
	switch (pure->code) {
	default:
	case RZ_IL_OP_VAR: {
		if (!read_var_from_state(ctx->inst, ctx->astate, pure->op.var.kind, pure->op.var.hash, out)) {
			RZ_LOG_ERROR("prototype: VAR failed to evaluate. The %s '%s' doesn't exist.\n",
				rz_il_var_kind_name(pure->op.var.kind),
				pure->op.var.v);
			return EVAL_RESULT_ERROR;
		}
		break;
	}
	case RZ_IL_OP_LET: {
		ut64 vhash = pure->op.let.hash;
		EVAL_SUB_OR_RETURN(pure->op.let.exp, out);
		write_var_to_state(ctx->inst, ctx->astate, RZ_IL_VAR_KIND_LOCAL_PURE, vhash, out);
		EVAL_SUB_OR_RETURN(pure->op.let.body, out);
		// No need to free the LET variable.
		// It is simply overwritten next time.
		break;
	}
	case RZ_IL_OP_ITE: {
		EVAL_SUB_OR_RETURN(pure->op.ite.condition, out);
		RzBitVector cond_bv;
		rz_bv_init(&cond_bv, 64);
		if (!val_domain(ctx->inst)->to_concrete_const(out, &cond_bv)) {
			// Can't decide which pure to evaluate.
			// TODO: must eval both and join instead!
			rz_bv_fini(&cond_bv);
			goto map_to_top;
		}
		bool cond_bool = !rz_bv_is_zero_vector(&cond_bv);
		rz_bv_fini(&cond_bv);

		// TODO: eval both if top
		if (cond_bool) {
			EVAL_SUB_OR_RETURN(pure->op.ite.x, out);
		} else {
			EVAL_SUB_OR_RETURN(pure->op.ite.y, out);
		}
		break;
	}
	case RZ_IL_OP_B0:
		val_domain(ctx->inst)->set_const_bool(out, false);
		break;
	case RZ_IL_OP_B1:
		val_domain(ctx->inst)->set_const_bool(out, true);
		break;
	case RZ_IL_OP_CAST: {
		EVAL_SUB_OR_RETURN(pure->op.cast.val, out);
		RzAbsIntVal *fill_bit = val_domain(ctx->inst)->val_new_top();
		if (!fill_bit) {
			return EVAL_RESULT_ERROR;
		}
		EVAL_SUB_OR_RETURN_CLEANUP(pure->op.cast.fill, fill_bit, {
			val_domain(ctx->inst)->val_free(fill_bit);
		});
		val_domain(ctx->inst)->eval_cast(pure->op.cast.length, fill_bit, out);
		val_domain(ctx->inst)->val_free(fill_bit);
		break;
	}
	case RZ_IL_OP_BITV:
		val_domain(ctx->inst)->set_const_bv(out, pure->op.bitv.value);
		break;
	case RZ_IL_OP_APPEND:
	case RZ_IL_OP_LOGAND:
	case RZ_IL_OP_AND:
	case RZ_IL_OP_LOGOR:
	case RZ_IL_OP_OR:
	case RZ_IL_OP_LOGXOR:
	case RZ_IL_OP_XOR:
	case RZ_IL_OP_ADD:
	case RZ_IL_OP_SUB:
	case RZ_IL_OP_SLE:
	case RZ_IL_OP_ULE:
	case RZ_IL_OP_EQ:
	case RZ_IL_OP_MUL:
	case RZ_IL_OP_MOD:
	case RZ_IL_OP_DIV: {
		RzILOpPure *px;
		RzILOpPure *py;
		if (pure->code == RZ_IL_OP_APPEND) {
			// we use low as the x/out value because in the case of constant operands,
			// appending high bits to a bitvector is more efficient than prepending
			// low bits in place.
			px = pure->op.append.low;
			py = pure->op.append.high;
		} else {
			px = pure->op.binop.x;
			py = pure->op.binop.y;
		}
		EVAL_SUB_OR_RETURN(px, out);
		// Hint: As an optimization, we could short-circuit if out is top here.
		// However it entirely depends on the plugin whether this is possible, or we lose a lot of precision by doing so.
		RzAbsIntVal *y = val_domain(ctx->inst)->val_new_top();
		if (!y) {
			return EVAL_RESULT_ERROR;
		}
		EVAL_SUB_OR_RETURN_CLEANUP(py, y, {
			val_domain(ctx->inst)->val_free(y);
		});
		val_domain(ctx->inst)->eval_binop(pure->code, out, y);
		val_domain(ctx->inst)->val_free(y);
		break;
	}
	case RZ_IL_OP_LOGNOT:
	case RZ_IL_OP_INV:
	case RZ_IL_OP_IS_ZERO:
	case RZ_IL_OP_LSB:
	case RZ_IL_OP_MSB:
	case RZ_IL_OP_NEG: {
		EVAL_SUB_OR_RETURN(pure->op.unop.x, out);
		val_domain(ctx->inst)->eval_unop(pure->code, out);
		break;
	}
	case RZ_IL_OP_SHIFTL:
	case RZ_IL_OP_SHIFTR: {
		RzILOpPure *px = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.x : pure->op.shiftl.x;
		RzILOpPure *py = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.y : pure->op.shiftl.y;
		RzILOpPure *pfill_bit = pure->code == RZ_IL_OP_SHIFTR ? pure->op.shiftr.fill_bit : pure->op.shiftl.fill_bit;
		EVAL_SUB_OR_RETURN(px, out);
		// Hint: As an optimization, we could short-circuit if out is top here.
		// However it entirely depends on the plugin whether this is possible, or we lose a lot of precision by doing so.
		RzAbsIntVal *y = val_domain(ctx->inst)->val_new_top();
		if (!y) {
			return EVAL_RESULT_ERROR;
		}
		EVAL_SUB_OR_RETURN_CLEANUP(py, y, {
			val_domain(ctx->inst)->val_free(y);
		});
		RzAbsIntVal *fill_bit = val_domain(ctx->inst)->val_new_top();
		if (!fill_bit) {
			val_domain(ctx->inst)->val_free(y);
			return EVAL_RESULT_ERROR;
		}
		EVAL_SUB_OR_RETURN_CLEANUP(pfill_bit, fill_bit, {
			val_domain(ctx->inst)->val_free(y);
			val_domain(ctx->inst)->val_free(fill_bit);
		});
		val_domain(ctx->inst)->eval_shift(pure->code == RZ_IL_OP_SHIFTR, out, y, fill_bit);
		val_domain(ctx->inst)->val_free(y);
		val_domain(ctx->inst)->val_free(fill_bit);
		break;
	}
	case RZ_IL_OP_LOADW:
	case RZ_IL_OP_LOAD: {
		RzILOpPure *key = pure->code == RZ_IL_OP_LOAD ? pure->op.load.key : pure->op.loadw.key;
		RzILMemIndex mem_idx = pure->code == RZ_IL_OP_LOAD ? pure->op.load.mem : pure->op.loadw.mem;
		EVAL_SUB_OR_RETURN(key, out);

		// Hint: Instead of supporting only a single constant load addr and mapping all other
		// loads to top, if the concrete set of the address is reasonably small, we could load
		// from all possible addresses and join the results.
		RzBitVector ld_addr;
		rz_bv_init(&ld_addr, 64);
		if (!val_domain(ctx->inst)->to_concrete_const(out, &ld_addr)) {
			rz_bv_fini(&ld_addr);
			goto map_to_top;
		}
		if (rz_bv_len(&ld_addr) == 64) {
			// TODO: Remove normalization.
			// Unset bit 63 is required, because the RzBuffer API only supports
			// st64 addresses.
			RzBitVector mask = { 0 };
			rz_bv_init(&mask, 64);
			rz_bv_set_from_ut64(&mask, 0x7fffffffffffffff);
			rz_bv_and_inplace(&ld_addr, &mask);
		}

		report_yield_xref(ctx, 0, ctx->insn_addr, out, RZ_ANALYSIS_XREF_TYPE_MEM_READ);
		size_t n_bits = pure->code == RZ_IL_OP_LOAD ? 8 : pure->op.loadw.n_bits;
		EvalResult res = load_abstr_data(ctx->inst, mem_idx, &ld_addr, n_bits, out);
		rz_bv_fini(&ld_addr);
		if (res == EVAL_RESULT_BREAK) {
			return EVAL_RESULT_BREAK;
		}
		if (res != EVAL_RESULT_OK) {
			goto map_to_top;
		}
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
	return EVAL_RESULT_OK;

map_to_top:
	val_domain(ctx->inst)->set_top(out);
	return EVAL_RESULT_OK;
#undef EVAL_SUB_OR_RETURN_CLEANUP
#undef EVAL_SUB_OR_RETURN
}

static void eval_call(RzAbsIntRunContext *ctx) {
	// For calls, assume control flow will continue like fallthrough.
	// But any data that may be modified by the callee must be set to top.
	// TODO: this should depend on the ABI, some data may be preserved.
	RzIterator *it = ht_up_as_iter(ctx->astate->globals);
	RzAbsIntVal **av;
	rz_iterator_foreach(it, av) {
		val_domain(ctx->inst)->set_top(*av);
	}
	rz_iterator_free(it);
}

static EvalResult eval_effect(RzAbsIntRunContext *ctx, const RzILOpEffect *effect, size_t insn_pkt_size) {
	rz_return_val_if_fail(ctx->astate->pc_state == RZ_ABSINT_PC_CONST, EVAL_RESULT_ERROR);
#define EVAL_SUB_OR_RETURN_CLEANUP(op, cleanup_local) \
	do { \
		res = eval_effect(ctx, (op), insn_pkt_size); \
		if (RZ_UNLIKELY(res != EVAL_RESULT_OK)) { \
			if (res != EVAL_RESULT_BREAK) { \
				RZ_LOG_ERROR("eval_effect failed to evaluate " #op "\n"); \
			} \
			cleanup_local goto cleanup; \
		} \
	} while (0)
#define EVAL_SUB_OR_RETURN(op) EVAL_SUB_OR_RETURN_CLEANUP(op, )
#define EVAL_PURE_OR_RETURN_CLEANUP(op, dst, cleanup_local) \
	do { \
		dst = val_domain(ctx->inst)->val_new_top(); \
		if (RZ_UNLIKELY(!(dst))) { \
			res = EVAL_RESULT_ERROR; \
			cleanup_local goto cleanup; \
		} \
		res = eval_pure(ctx, (op), (dst)); \
		if (RZ_UNLIKELY(res != EVAL_RESULT_OK)) { \
			if (res != EVAL_RESULT_BREAK) { \
				RZ_LOG_ERROR("eval_effect failed to evaluate " #op "\n"); \
			} \
			cleanup_local goto cleanup; \
		} \
	} while (0);
#define EVAL_PURE_OR_RETURN(op) EVAL_PURE_OR_RETURN_CLEANUP(op, eval_out, )
	RzAbsIntVal *eval_out = NULL;
	EvalResult res = EVAL_RESULT_OK;

	switch (effect->code) {
	default:
	case RZ_IL_OP_EMPTY:
		break;
	case RZ_IL_OP_NOP: {
		break;
	}
	case RZ_IL_OP_SEQ: {
		EVAL_SUB_OR_RETURN(effect->op.seq.x);
		EVAL_SUB_OR_RETURN(effect->op.seq.y);
		break;
	}
	case RZ_IL_OP_SET: {
		ut64 vhash = effect->op.set.hash;
		EVAL_PURE_OR_RETURN(effect->op.set.x);
		RzILVarKind kind = effect->op.set.is_local ? RZ_IL_VAR_KIND_LOCAL : RZ_IL_VAR_KIND_GLOBAL;
		write_var_to_state(ctx->inst, ctx->astate, kind, vhash, eval_out);
		if (value_indicates_ret_addr_write(ctx, eval_out) &&
			kind == RZ_IL_VAR_KIND_GLOBAL) {
			// Hint: this ret-addr store detection currently only works across a single interp block.
			// Consider the following ARMv4 code for an indirect call (blx was introduced in ARMv5):
			// ```
			// A> mov lr, pc
			// B> mov pc, r0
			// C> ...
			// ```
			//
			// both A and B are block entries.
			//
			// 1. If A is discovered before B, the call is recognized at that point. Once B is detected, C will not be
			//    reached by fallthrough anymore.
			// 2. If B is discovered before A, the call is not recognized in the first place because A and B are two
			//    separate blocks already.
			//
			// It is inconvenient that we may have a fixpoint where C could be considered only partially evaluated,
			// but as long as we don't find a practical example where this happens and thus also don't have a good
			// example for the expected analysis outcome, we leave it as-is.
			//
			// Making C reachable even with the in-edge at B could work by for example by marking A as ret-addr-storing
			// and using that information when evaluating B.
			ctx->block_stores_ret_addr = true;
			if (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
				RZ_LOG_INFO("  set: value indicates ret addr write\n");
			}
		}
		break;
	}
	case RZ_IL_OP_JMP: {
		EVAL_PURE_OR_RETURN(effect->op.jmp.dst);
		RzBitVector eval_out_bv;
		rz_bv_init(&eval_out_bv, 64);
		bool is_const = val_domain(ctx->inst)->to_concrete_const(eval_out, &eval_out_bv);
		if (!is_const) {
			RZ_LOG_DEBUG("PC is going to be set to an abstract value! Current PC = 0x%" PFMT64x "\n", ctx->astate->pc);
		}
		bool is_call = ctx->block_stores_ret_addr;

		if (is_const) {
			RZ_LOG_DEBUG("prototype: JMP - Set PC: 0x%" PFMT64x " -> 0x%" PFMT64x "\n", ctx->astate->pc, rz_bv_to_ut64(&eval_out_bv));
			RzAnalysisXRefType xref_type = RZ_ANALYSIS_XREF_TYPE_CODE;
			if (is_call) {
				xref_type = RZ_ANALYSIS_XREF_TYPE_CALL;
			}
			report_yield_xref(ctx, insn_pkt_size, ctx->insn_addr, eval_out, xref_type);
		}

		if (is_call) {
			if (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
				RZ_LOG_INFO("  call detected\n");
			}
			eval_call(ctx);
		} else {
			set_abstr_pc(ctx->inst, ctx->astate, eval_out);
		}
		rz_bv_fini(&eval_out_bv);
		break;
	}
	case RZ_IL_OP_BRANCH: {
		EVAL_PURE_OR_RETURN(effect->op.branch.condition);
		bool may_be_true = val_domain(ctx->inst)->may_be_bool(eval_out, true);
		bool may_be_false = val_domain(ctx->inst)->may_be_bool(eval_out, false);
		ut64 fallthrough_pc = ctx->astate->pc;
		if (may_be_true && may_be_false) {
			RzAbsIntState *true_state = rz_absint_state_clone(ctx->inst, ctx->astate);
			RzAbsIntState *false_state = ctx->astate;
			ctx->astate = true_state;
			EVAL_SUB_OR_RETURN(effect->op.branch.true_eff);
			ctx->astate = false_state;
			EVAL_SUB_OR_RETURN(effect->op.branch.false_eff);
			if (true_state->pc_state == false_state->pc_state && true_state->pc == false_state->pc) {
				// identical target location, simply join the data and continue
				join_state(ctx->inst, false_state, true_state);
			} else if (interp_is_collecting_states(ctx)) {
				// different jump targets, branch rather than resorting to top pc
				rz_absint_run_push(ctx, true_state, true_state->pc_state == RZ_ABSINT_PC_CONST && true_state->pc == fallthrough_pc);
				if (true_state->pc_state == RZ_ABSINT_PC_CONST && !rz_vector_contains(&ctx->block->jump_targets, &true_state->pc)) {
					rz_vector_push(&ctx->block->jump_targets, &true_state->pc);
				}
				// false_state is already in ctx->inst->astate and will be continued automatically
			}
			rz_absint_state_free(ctx->inst, true_state);
		} else if (may_be_true) {
			EVAL_SUB_OR_RETURN(effect->op.branch.true_eff);
		} else if (may_be_false) {
			EVAL_SUB_OR_RETURN(effect->op.branch.false_eff);
		}
		break;
	}
	case RZ_IL_OP_STORE:
	case RZ_IL_OP_STOREW: {
		RzILOpPure *key = effect->code == RZ_IL_OP_STORE ? effect->op.store.key : effect->op.storew.key;
		RzAbsIntVal *st_addr;
		EVAL_PURE_OR_RETURN_CLEANUP(key, st_addr, {
			val_domain(ctx->inst)->val_free(st_addr);
		});
		RzILMemIndex mem_idx = effect->code == RZ_IL_OP_STORE ? 0 : effect->op.storew.mem;
		RzBitVector st_addr_bv;
		rz_bv_init(&st_addr_bv, 64);
		if (val_domain(ctx->inst)->to_concrete_const(st_addr, &st_addr_bv)) {
			if (rz_bv_len(&st_addr_bv) == 64) {
				// TODO: Remove normalization.
				// Unset bit 63 is required, because the RzBuffer API only supports
				// st64 addresses.
				RzBitVector mask = { 0 };
				rz_bv_init(&mask, 64);
				rz_bv_set_from_ut64(&mask, 0x7fffffffffffffff);
				rz_bv_and_inplace(&st_addr_bv, &mask);
			}
			report_yield_xref(ctx, insn_pkt_size, ctx->insn_addr, st_addr, RZ_ANALYSIS_XREF_TYPE_MEM_WRITE);
		}

		RzILOpPure *pval = effect->code == RZ_IL_OP_STORE ? effect->op.store.value : effect->op.storew.value;
		EVAL_PURE_OR_RETURN_CLEANUP(pval, eval_out, {
			rz_bv_fini(&st_addr_bv);
			val_domain(ctx->inst)->val_free(st_addr);
		});
		if (value_indicates_ret_addr_write(ctx, eval_out)) {
			ctx->block_stores_ret_addr = true;
			if (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
				RZ_LOG_INFO("  store/storew: value indicates ret addr write\n");
			}
		}
		store_abstr_data(ctx->inst, mem_idx, st_addr, eval_out);
		val_domain(ctx->inst)->val_free(st_addr);
		rz_bv_fini(&st_addr_bv);
		break;
	}
	case RZ_IL_OP_GOTO:
	case RZ_IL_OP_BLK:
	case RZ_IL_OP_REPEAT:
		RZ_LOG_ERROR("Unhandled effect %" PFMT32d "\n", effect->code);
		// Ignore for now.
		break;
	}
cleanup:
	val_domain(ctx->inst)->val_free(eval_out);
	return res;
#undef EVAL_SUB_OR_RETURN_CLEANUP
#undef EVAL_SUB_OR_RETURN
#undef EVAL_PURE_OR_RETURN_CLEANUP
#undef EVAL_PURE_OR_RETURN
}

static EvalResult eval_block(RZ_NONNULL RzAbsIntRunContext *ctx, RZ_NONNULL RzAbsIntBlock *interp_block, RZ_NONNULL const RzILCacheBlock *il_block) {
	ctx->block = interp_block;
	ctx->il_block_end = il_block->addr + il_block->size;
	ctx->block_stores_ret_addr = false;

	ut64 interp_block_end = rz_absint_block_get_end(ctx->block);

	if (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
		RZ_LOG_INFO("Evaluating absint block @ 0x%" PFMT64x "\n", interp_block->entry_state->pc);
	}

	// Now execute the actual effects of the BLOCK.
	RzAbsIntState *astate = ctx->astate;
	void **it;
	rz_pvector_foreach (il_block->il_ops, it) {
		ut64 pc = astate->pc;

		if (pc > interp_block_end) {
			// block is truncated
			break;
		}

		RzILCacheInsnPkt *pkt = *it;
		ctx->insn_addr = pc;

		// Prepare next pc, the evalutation may overwrite this.
		ut64 next_pc = pc + pkt->insn_pkt_size;
		rz_absint_state_set_pc_const(ctx->astate, next_pc);

		if (interp_is_analyzing(ctx) && (ctx->res_dimen & RZ_ABSINT_RESULT_DIMEN_COMMENTS)) {
			RzStrBuf sb;
			rz_strbuf_init(&sb);
			rz_absint_state_as_str_short(ctx->inst, ctx->astate, &sb);
			interp_add_comment(ctx, ctx->insn_addr, rz_strbuf_get(&sb));
			rz_strbuf_fini(&sb);
			if (pc == il_block->addr) {
				interp_add_comment(ctx, ctx->insn_addr, "<-");
			}
			if (rz_vector_index_ptr(&il_block->il_ops->v, rz_pvector_len(il_block->il_ops) - 1) == it) {
				interp_add_comment(ctx, ctx->insn_addr, "->");
			}
		}

		EvalResult res = eval_effect(ctx, pkt->effect, pkt->insn_pkt_size);
		if (RZ_UNLIKELY(res != EVAL_RESULT_OK)) {
			if (res != EVAL_RESULT_BREAK) {
				RZ_LOG_ERROR("Failed to evaluate op at 0x%" PFMT64x "\n", ctx->insn_addr);
			}
			return res;
		}
		if (astate->pc_state != RZ_ABSINT_PC_CONST) {
			// unreachable or unknown jump
			break;
		}
		if (interp_is_collecting_states(ctx) && astate->pc != next_pc) {
			// Constant jump other than fallthrough, meaning interpretation will continue in another block
			interp_block_add_non_fallthrough_target(ctx->block, astate->pc);
			break;
		}
	}

	if (interp_is_collecting_states(ctx) && astate->pc_state != RZ_ABSINT_PC_UNREACHABLE) {
		bool fallthrough = false;
		if (astate->pc_state == RZ_ABSINT_PC_CONST && astate->pc == interp_block_end + 1) {
			fallthrough = true;
			ctx->block->is_fallthrough = true;
		}
		rz_absint_run_push(ctx, ctx->astate, fallthrough);
	}

	if (ctx->inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
		RZ_LOG_INFO("Finished evaluating absint block @ 0x%" PFMT64x "\n\n", interp_block->entry_state->pc);
	}

	return EVAL_RESULT_OK;
}

RZ_API bool rz_absint_run_context_init(RZ_BORROW RZ_NONNULL RzAbsIntRunContext *ctx, RZ_BORROW RZ_NONNULL RzAbsIntInstance *inst) {
	rz_return_val_if_fail(ctx && inst, false);
	ctx->inst = inst;
	ctx->astate = NULL;
	ctx->res = NULL;
	ctx->queue = rz_list_new();
	if (!ctx->queue) {
		return false;
	}
	interp_blocks_init(ctx);
	return true;
}

RZ_API void rz_absint_run_context_fini(RZ_NULLABLE RzAbsIntRunContext *ctx) {
	if (!ctx) {
		return;
	}
	rz_list_free(ctx->queue);
	interp_blocks_fini(ctx->inst, &ctx->blocks);
}

static RzAbsIntLiftBlockResult interp_lift_block(RzAbsIntInstance *inst, ut64 addr, const RzILCacheBlock **block_out) {
	RzAbsIntLiftBlockResult res = inst->config.lift_block(addr, block_out, inst->config.cb_user);
	if (res == RZ_ABSINT_LIFT_BLOCK_RESULT_FAILED) {
		RZ_LOG_ERROR("Failed to lift block at 0x%" PFMT64X "\n", addr);
	}
	return res;
}

/**
 * \brief Run the interpreter from a single entrypoint until a fixpoint is reached.
 * It does not follow calls!
 * The CFG it discovers should be considered a function.
 */
RZ_API RzAbsIntResultCode rz_absint_run(RZ_BORROW RZ_NONNULL RzAbsIntInstance *inst, ut64 entry_point, RzAbsIntResultDimen dimen, RZ_NONNULL RZ_OUT RzAbsIntResult **res_out) {
	rz_return_val_if_fail(inst && res_out, RZ_ABSINT_RESULT_FAILED);

	// Initialization
	RzAbsIntResult *res = NULL;
	RzAbsIntResultCode ret = RZ_ABSINT_RESULT_FAILED;
	RzAbsIntRunContext ctx = { 0 };
	if (!rz_absint_run_context_init(&ctx, inst)) {
		return RZ_ABSINT_RESULT_FAILED;
	}

	// Prepare the initial state from the given entry point
	// Hint: nothing speaks against supporting multiple entry points in a single run
	RzAbsIntState *estate = rz_absint_state_new(inst);
	if (!estate || !reset_state(inst, estate, entry_point)) {
		rz_absint_state_free(inst, estate);
		goto cleanup;
	}
	rz_absint_run_push(&ctx, estate, false);
	rz_absint_state_free(inst, estate);

	// Loop and interpret until a fixpoint has been reached
	while (true) {
		RzAbsIntBlock *interp_block = rz_absint_run_pop(&ctx);
		if (!interp_block) {
			// No uninterpreted states left, fixpoint reached.
			break;
		}
		ctx.astate = rz_absint_state_clone(inst, interp_block->entry_state);

		const RzILCacheBlock *il_block;
		RzAbsIntLiftBlockResult lift_res = interp_lift_block(inst, ctx.astate->pc, &il_block);
		if (lift_res == RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK) {
			ret = RZ_ABSINT_RESULT_BREAK;
			rz_absint_state_free(inst, ctx.astate);
			goto cleanup;
		}
		if (lift_res != RZ_ABSINT_LIFT_BLOCK_RESULT_OK) {
			// Failed lifting, keep the entry state unimplemented
			rz_absint_state_free(inst, ctx.astate);
			continue;
		}

		rz_absint_block_resolve_bounds(&ctx, interp_block, il_block);

		// Evaluate the effect on the abstract state.
		if (eval_block(&ctx, interp_block, il_block) == EVAL_RESULT_BREAK) {
			ret = RZ_ABSINT_RESULT_BREAK;
			rz_absint_state_free(inst, ctx.astate);
			goto cleanup;
		}
		// TODO: ctx.astate could be moved instead of freeing, or it could be reused for the next iteration
		rz_absint_state_free(inst, ctx.astate);
	}

	// Fixpoint reached, collect results.
	res = RZ_NEW0(RzAbsIntResult);
	if (!res) {
		goto cleanup;
	}
	res->entry = entry_point;

	if (inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
		RzStrBuf sb = { 0 };
		rz_strbuf_init(&sb);
		interp_block_tree_as_str(&ctx.blocks, &sb);
		RZ_LOG_INFO("%s", rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);
	}

	if (dimen != RZ_ABSINT_RESULT_DIMEN_BASE) {
		if (inst->config.trace_opts & RZ_ABSINT_TRACE_EVAL_BLOCK) {
			RZ_LOG_INFO("=============== analysis pass ===============\n\n");
		}

		// Evaluate all blocks again once to collect analysis information.
		// We do this in an additional pass because until now, the collected abstract states
		// did not fully represent all reachable concrete states.
		if (dimen & RZ_ABSINT_RESULT_DIMEN_XREFS) {
			rz_vector_init(&res->xrefs, sizeof(RzAnalysisXRef), NULL, NULL);
		}
		if (dimen & RZ_ABSINT_RESULT_DIMEN_COMMENTS) {
			res->comments = ht_up_new(NULL, free);
			if (!res->comments) {
				goto cleanup_res;
			}
		}
		ctx.res = res;
		ctx.res_dimen = dimen;
		RzIntervalTreeIter it;
		RzAbsIntBlock *interp_block;
		rz_interval_tree_foreach (&ctx.blocks, it, interp_block) {
			// Note: depending on what info is requested, i.e. whether the entry states are read again later,
			// this might not have to be cloned but could just be interpreted further.
			ctx.astate = rz_absint_state_clone(inst, interp_block->entry_state);
			const RzILCacheBlock *il_block;
			RzAbsIntLiftBlockResult lift_res = interp_lift_block(inst, ctx.astate->pc, &il_block);
			if (lift_res == RZ_ABSINT_LIFT_BLOCK_RESULT_BREAK) {
				ret = RZ_ABSINT_RESULT_BREAK;
				rz_absint_state_free(inst, ctx.astate);
				goto cleanup;
			}
			if (lift_res != RZ_ABSINT_LIFT_BLOCK_RESULT_OK) {
				rz_absint_state_free(inst, ctx.astate);
				continue;
			}
			if (eval_block(&ctx, interp_block, il_block) == EVAL_RESULT_BREAK) {
				ret = RZ_ABSINT_RESULT_BREAK;
				rz_absint_state_free(inst, ctx.astate);
				goto cleanup_res;
			}
			rz_absint_state_free(inst, ctx.astate);
		}
	}

	memmove(&res->blocks, &ctx.blocks, sizeof(ctx.blocks));
	memset(&ctx.blocks, 0, sizeof(ctx.blocks));
	ret = RZ_ABSINT_RESULT_OK;
	*res_out = res;
	goto cleanup;

cleanup_res:
	rz_absint_result_free(inst, res);
cleanup:
	rz_absint_run_context_fini(&ctx);
	return ret;
}

RZ_API void rz_absint_result_free(RZ_NULLABLE RzAbsIntInstance *inst, RZ_OWN RZ_NULLABLE RzAbsIntResult *res) {
	if (!res) {
		return;
	}
	rz_vector_fini(&res->xrefs);
	ht_up_free(res->comments);
	if (inst) {
		interp_blocks_fini(inst, &res->blocks);
	}
	free(res);
}

static void bb_add_target(RzAnalysisBlock *abb, ut64 target) {
	if (abb->jump == UT64_MAX && abb->fail != target) {
		abb->jump = target;
	} else if (abb->fail == UT64_MAX && abb->jump != target) {
		abb->fail = target;
	} else if (abb->fail != target && abb->jump != target) {
		RZ_LOG_WARN("The basic block at 0x%" PFMT64x " has more than two outgoing edges.\n"
			    "\t\tHas jump = 0x%" PFMT64x " fail = 0x%" PFMT64x ". Will miss = 0x%" PFMT64x "\n",
			abb->addr, abb->jump, abb->fail,
			target);
	}
}

/**
 * \brief Applies the results of the abstract interpreter to RzAnalysis.
 *
 * It converts the \p res->blocks to a function with name \p fcn_name (or a generated name if NULL).
 * Directly applicable results like xrefs and comments are simply added to RzAnalysis.
 *
 * \param res The results.
 * \param analysis The RzAnalysis instance to add the results to.
 * \param fcn_name Optionally given function name for the function it creates for the \p res->blocks.
 *
 * \return True for success, false in case of failure.
 */
RZ_API bool rz_absint_result_apply_to_analysis(RZ_NONNULL RzAbsIntResult *res, RZ_NONNULL RzAnalysis *analysis, RZ_NULLABLE const char *fcn_name) {
	rz_return_val_if_fail(res && analysis, false);
	char name_alt[128];
	RzAnalysisFunction *func = rz_analysis_create_function(analysis, fcn_name ? fcn_name : rz_strf(name_alt, "inquiry.0x%" PFMT64x, res->entry), res->entry, RZ_ANALYSIS_FCN_TYPE_FCN);
	if (!func) {
		// TODO: handle better than skipping everything
		// rz_analysis_create_function() already prints the more detailed reason if there is any
		RZ_LOG_ERROR("Could not apply analysis result as function @ 0x%" PFMT64x ": func == NULL\n", res->entry);
		return false;
	}
	RzIntervalTreeIter it;
	RzAbsIntBlock *block;
	rz_interval_tree_foreach (&res->blocks, it, block) {
		if (block->added_to_analysis) {
			// has been merged into the previous already
			continue;
		}
		ut64 start = rz_absint_block_get_start(block);
		ut64 end_excl = rz_absint_block_get_end(block) + 1;

		// Merge consecutive blocks if there is no in-edge between them.
		// Splits like this happen in the first place because interp blocks only reach until the
		// first jump. This may be a call however, which just falls through.
		RzIntervalTreeIter next_it = it;
		while (block->is_fallthrough && rz_vector_empty(&block->jump_targets)) {
			rz_rbtree_iter_next(&next_it);
			RzIntervalNode *next_node = NULL;
			while (rz_rbtree_iter_has(&next_it)) {
				RzIntervalNode *n = rz_interval_tree_iter_get(&next_it);
				if (n->start >= end_excl) {
					if (n->start == end_excl) {
						next_node = n;
					}
					break;
				}
				rz_rbtree_iter_next(&next_it);
			}
			RzAbsIntBlock *next_block;
			if (!next_node || (next_block = next_node->data)->non_fallthrough_in) {
				// no consecutive block or there is a consecutive block, but is has an in-edge from somewhere else
				break;
			}
			next_block->added_to_analysis = true;
			end_excl = next_node->end + 1;
			block = next_block;
		}

		RzAnalysisBlock *abb = rz_analysis_create_block(analysis, start, end_excl - start);
		if (!abb) {
			// TODO: Handle the case of existing blocks better, e.g. just use the existing block
			// and optionally update its contents with some new information we have gained.
			RZ_LOG_ERROR("Failed to create block @ 0x%" PFMT64x "%s\n", start,
				rz_analysis_get_block_at(analysis, start) ? " because there is already a block and handling this is not yet implemented" : "");
			continue;
		}

		// TODO: analyze_ops should eventually not be used here since it does its own analysis.
		// Instead, we should manually apply our analysis info to it.
		// Keep in mind we might have to add info from multiple merged blocks here (see merging above)
		// and that our interp block works on instruction packets, not instructions
		rz_analysis_block_analyze_ops(abb);

		rz_analysis_function_add_block(func, abb);
		abb->jump = UT64_MAX;
		abb->fail = UT64_MAX;
		ut64 *target;
		rz_vector_foreach (&block->jump_targets, target) {
			bb_add_target(abb, *target);
		}
		if (block->is_fallthrough) {
			bb_add_target(abb, end_excl);
		}
	}

	// Hint: Some of the xrefs, specifically code and call ones, could be determined from
	// the information in blocks as well. So an optimization could be to make the interpreter
	// only emit explicit xref info for all remaining events, e.g. mem read/write.
	RzAnalysisXRef *xref;
	rz_vector_foreach (&res->xrefs, xref) {
		if (!rz_analysis_xrefs_set(analysis, xref->from, xref->to, xref->type)) {
			RZ_LOG_ERROR("failed to set xref\n");
		}
	}

	if (res->comments) {
		RzIterator *it = ht_up_as_iter_keys(res->comments);
		ut64 *k;
		rz_iterator_foreach(it, k) {
			const char *cmt = ht_up_find(res->comments, *k, NULL);
			if (cmt) {
				rz_meta_set_string(analysis, RZ_META_TYPE_COMMENT, *k, cmt);
			}
		}
		rz_iterator_free(it);
	}

	return true;
}

extern RZ_IPI RzAbsIntValueDomain rz_absint_value_domain_const;

/**
 * \brief Get the inquiry-builtin value domain by its id
 * \return non-null value domain if \p dom is a valid enum member
 */
RZ_API RZ_NULLABLE const RzAbsIntValueDomain *rz_absint_builtin_value_domain(RzAbsIntBuiltinValueDomain dom) {
	// We do not export the domain variables directly because Windows dllexport/dllimport asymmetry
	// would need extra care for it.
	switch (dom) {
	case RZ_ABSINT_VALUE_DOMAIN_CONST:
		return &rz_absint_value_domain_const;
	}
	return NULL;
}
