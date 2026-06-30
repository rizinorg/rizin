// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include "rz_analysis.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_log.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

#include "eval.h"

RZ_API void rz_interp_yield_rbuf_free(RZ_OWN RZ_NULLABLE RzInterpYieldRBuf *yield_rbufs) {
	if (!yield_rbufs) {
		return;
	}
	if (yield_rbufs->rbuf) {
		rz_th_ring_buf_free(yield_rbufs->rbuf);
	}
	if (yield_rbufs->filter_data && yield_rbufs->filter_data->io_boundaries) {
		rz_pvector_free(yield_rbufs->filter_data->io_boundaries);
	}
	free(yield_rbufs->filter_data);
	free(yield_rbufs);
}

RZ_API RZ_OWN RzInterpYieldRBuf *rz_interp_yield_rbuf_new(RzInterpYieldKind kind,
	RzInterpYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data) {
	RzInterpYieldRBuf *yield_rbufs = RZ_NEW0(RzInterpYieldRBuf);
	if (!yield_rbufs) {
		return NULL;
	}
	RzThreadRingBuf *rbuf = NULL;
	switch (kind) {
	default:
		rz_warn_if_reached();
		return NULL;
	case RZ_INTERP_YIELD_KIND_CALL_CANDIDATE:
		rbuf = rz_th_ring_buf_new(RZ_INTERP_YIELD_RBUF_SIZE, sizeof(RzAnalysisCallCandidate));
		break;
	case RZ_INTERP_YIELD_KIND_CONTROL_FLOW:
		rbuf = rz_th_ring_buf_new(RZ_INTERP_YIELD_RBUF_SIZE, sizeof(RzInterpCtrlFlow));
		break;
	case RZ_INTERP_YIELD_KIND_XREF:
		if (filter_data) {
			yield_rbufs->filter_data = RZ_NEW0(RzInterpYieldFilterData);
			yield_rbufs->filter_data->io_boundaries = filter_data;
		}
		rbuf = rz_th_ring_buf_new(RZ_INTERP_YIELD_RBUF_SIZE, sizeof(RzAnalysisXRef));
		if (!rbuf) {
			rz_pvector_free(filter_data);
			return NULL;
		}
		break;
	}
	if (!rbuf) {
		free(yield_rbufs);
		return NULL;
	}
	yield_rbufs->kind = kind;
	yield_rbufs->rbuf = rbuf;
	yield_rbufs->filter = filter;
	return yield_rbufs;
}

/**
 * \brief Initializes an abstract state for specified abstract kinds. Optionally with a list of registers.
 * The register name list should always be given if the architecture has some.
 */
RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_new(
	const char *arch_name,
	RZ_BORROW RZ_NONNULL RzAnalysisILContext *il_context) {
	rz_return_val_if_fail(il_context, NULL);
	RzInterpAbstrState *state = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	state->arch_name = arch_name;
	// Initialize the register file with uninitialized abstract values.
	state->var_name_hashes = ht_up_new(NULL, free);
	state->globals = ht_up_new(NULL, free);
	for (size_t i = 0; i < il_context->reg_binding->regs_count; i++) {
		const char *rname = il_context->reg_binding->regs[i].name;
		RzInterpAbstrVal *aval = NULL; // RZ_NEW0(RzInterpAbstrVal);
		// if (!aval) {
		// 	ht_up_free(state->globals);
		// 	ht_up_free(state->var_name_hashes);
		// 	free(state);
		// 	return NULL;
		// }

		ut64 djb2_reg_hash = rz_str_djb2_hash(rname);
		if (!ht_up_insert(state->globals, djb2_reg_hash, aval) ||
			!ht_up_insert(state->var_name_hashes, djb2_reg_hash, rz_str_dup(rname))) {
			RZ_LOG_ERROR("Failed to add %s to the global variable map. "
				     "DJB2 hash collision of the register name. DJB2 hash = 0x%" PFMT64x "\n",
				rname, djb2_reg_hash);
			ht_up_free(state->globals);
			ht_up_free(state->var_name_hashes);
			free(state);
		}
	}
	state->locals = ht_up_new(NULL, free);
	state->lets = ht_up_new(NULL, free);
	return state;
}

RZ_API void rz_interp_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpAbstrState *state) {
	if (!state) {
		return;
	}
	if (state->var_name_hashes) {
		ht_up_free(state->var_name_hashes);
	}
	if (state->globals) {
		ht_up_free(state->globals);
	}
	if (state->locals) {
		ht_up_free(state->locals);
	}
	if (state->lets) {
		ht_up_free(state->lets);
	}
	free(state);
}

static HtUP *var_set_clone(const RzInterpInstance *iset, HtUP *vars) {
	HtUP *r = ht_up_new(NULL, free);
	if (!r) {
		return NULL;
	}
	RzIterator *it = ht_up_as_iter_keys(vars);
	ut64 *key;
	rz_iterator_foreach(it, key) {
		RzInterpAbstrVal *val = iset->plugin->clone_val(ht_up_find(vars, *key, NULL));
		if (!val) {
			continue;
		}
		ht_up_insert(r, *key, val);
	}
	return r;
}

RZ_API RZ_OWN RzInterpAbstrState *rz_interp_abstr_state_clone(RZ_NONNULL RzInterpInstance *iset, const RzInterpAbstrState *state) {
	RzInterpAbstrState *r = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	r->arch_name = state->arch_name;
	r->pc = state->pc;
	r->pc_state = state->pc_state;
	r->uninterpreted = state->uninterpreted;
	r->var_name_hashes = ht_up_new(NULL, free);
	RzIterator *it = ht_up_as_iter_keys(state->var_name_hashes);
	ut64 *key;
	rz_iterator_foreach(it, key) {
		char *n = strdup(ht_up_find(state->var_name_hashes, *key, NULL));
		if (!n) {
			continue;
		}
		ht_up_insert(r->var_name_hashes, *key, n);
	}

	r->globals = var_set_clone(iset, state->globals);
	r->locals = var_set_clone(iset, state->locals);
	r->lets = var_set_clone(iset, state->lets);
	return r;
}

RZ_API void rz_interp_instance_free(RZ_OWN RZ_NULLABLE RzInterpInstance *iset) {
	if (!iset) {
		return;
	}
	if (iset->io_request_rbuf) {
		rz_th_ring_buf_free(iset->io_request_rbuf);
	}
	if (iset->io_result_rbuf) {
		rz_th_ring_buf_free(iset->io_result_rbuf);
	}
	if (iset->entry_points) {
		rz_th_ring_buf_free(iset->entry_points);
	}
	if (iset->run_state_sync) {
		rz_th_sem_free(iset->run_state_sync);
	}
	if (iset->run_state) {
		rz_interp_run_state_free(iset->run_state);
	}
	rz_analysis_il_context_free(iset->il_ctx);
	free(iset);
}

static bool setup_ipc_objects(
	RZ_OUT RzThreadRingBuf **io_request_rbuf,
	RZ_OUT RzThreadRingBuf **io_result_rbuf,
	RZ_OUT RzThreadRingBuf **entry_points) {
	*io_request_rbuf = NULL;
	*io_result_rbuf = NULL;
	*entry_points = NULL;

	// Setup the IO queues. Each interpreter instance needs it's own queue at
	// for writing IO. Because the writing is done on the IO cache, and each
	// instance needs its own cache.
	*io_request_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIOReadRequest));
	*io_result_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIOResult));
	*entry_points = rz_th_ring_buf_new(RZ_INTERP_ENTRY_POINTS_RBUF_SIZE, sizeof(ut64));
	if (!*io_request_rbuf || !*io_result_rbuf || !*entry_points) {
		rz_warn_if_reached();
		goto error_free;
	}

	return true;

error_free:
	rz_th_ring_buf_free(*io_request_rbuf);
	rz_th_ring_buf_free(*io_result_rbuf);
	rz_th_ring_buf_free(*entry_points);
	return false;
}

/**
 * \brief Initializes a new RzInterpSet and returns it.
 * If it fails, all arguments are freed.
 */
RZ_API RZ_OWN RzInterpInstance *rz_interp_instance_new(
	RzAnalysis *analysis,
	RZ_NONNULL RZ_OWN RzInterpPlugin *plugin,
	RZ_NONNULL RZ_BORROW RzILCacheClient *il_cache_client,
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	rz_return_val_if_fail(plugin && ignored_code && analysis && il_cache_client, NULL);

	RzInterpInstance *iset = RZ_NEW0(RzInterpInstance);
	if (!iset) {
		return NULL;
	}

	RzAnalysisILContext *il_ctx = rz_analysis_il_context_resolve(analysis);
	if (!il_ctx) {
		free(iset);
		RZ_LOG_ERROR("Failed to create analysis IL context.\n");
		return NULL;
	}

	RzThreadRingBuf *io_request_rbuf = NULL;
	RzThreadRingBuf *io_result_rbuf = NULL;
	RzThreadRingBuf *entry_points = NULL;
	if (!setup_ipc_objects(&io_request_rbuf, &io_result_rbuf, &entry_points)) {
		free(iset);
		rz_analysis_il_context_free(il_ctx);
		return NULL;
	}

	iset->a = analysis;
	iset->plugin = plugin;
	iset->run_state = rz_interp_run_state_new();
	iset->il_ctx = il_ctx;
	iset->il_cache_client = il_cache_client;
	iset->entry_points = entry_points;
	iset->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF] = yield_rbufs[RZ_INTERP_YIELD_KIND_XREF];
	iset->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE] = yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE];
	iset->yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW] = yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW];
	iset->io_request_rbuf = io_request_rbuf;
	iset->io_result_rbuf = io_result_rbuf;
	iset->run_state_sync = rz_th_sem_new(0);
	iset->ignored_code = ignored_code;

	return iset;
}

RZ_API void rz_interp_run_push(RZ_BORROW RZ_NONNULL RzInterpRunContext *ctx, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as) {
	if (as->pc_state == RZ_INTERP_PC_ANY) {
		RZ_LOG_DEBUG("Encountered state with unknown/top pc\n");
		return;
	}
	if (as->pc_state != RZ_INTERP_PC_CONST) {
		rz_warn_if_reached();
		return;
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	state_as_str_short(ctx->inst, &sb, as);
	RZ_LOG_DEBUG("PUSH 0x%" PFMT64x ": %s\n", as->pc, rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);
	RzInterpAbstrState *existing = ht_up_find(ctx->pc_states, as->pc, NULL);
	if (existing) {
		if (ctx->inst->plugin->join_state(existing, as) && !existing->uninterpreted) {
			existing->uninterpreted = true;
			rz_list_push(ctx->queue, existing);
		}
	} else {
		RzInterpAbstrState *c = rz_interp_abstr_state_clone(ctx->inst, as);
		if (!c) {
			return;
		}
		ht_up_insert(ctx->pc_states, as->pc, c);
		c->uninterpreted = true;
		rz_list_push(ctx->queue, c);
	}
}

static RzInterpAbstrState *rz_interp_run_pop(RZ_BORROW RZ_NONNULL RzInterpRunContext *ctx) {
	RzInterpAbstrState *r = rz_list_pop(ctx->queue);
	if (!r) {
		return NULL;
	}
	r->uninterpreted = false;
	return r;
}

/**
 * \brief Run the interpreter from a single entrypoint until a fixpoint is reached
 */
static bool rz_interp_run(RzInterpInstance *inst, ut64 entry_point) {
	// Initialization
	bool success = false;
	RzInterpRunContext ctx = {
		.inst = inst,
		.astate = NULL,
		.queue = rz_list_new(),
		.pc_states = ht_up_new(NULL, free)
	};
	if (!ctx.queue || !ctx.pc_states) {
		goto cleanup;
	}

	// Prepare the initial state from the given entry point
	// Hint: nothing speaks against supporting multiple entry points in a single run
	const RzAnalysisPlugin *cur = rz_analysis_plugin_current(inst->a);
	RzInterpAbstrState *estate = rz_interp_abstr_state_new(cur->arch, inst->il_ctx);
	if (inst->plugin->reset) {
		// TODO: should rather be local to the RzInterpRunContext if it is reset every run
		// inst->plugin->reset(inst->interp_priv);
		memset(&ctx.call_cand, 0, sizeof(ctx.call_cand));
	}
	if (!inst->plugin->init_state(estate) || !inst->plugin->reset_state(estate, entry_point)) {
		rz_warn_if_reached();
		rz_interp_abstr_state_free(estate);
		goto cleanup;
	}
	rz_interp_run_push(&ctx, estate);
	rz_interp_abstr_state_free(estate);

	// Loop and interpret until a fixpoint has been reached
	while (true) {
		RzInterpAbstrState *next = rz_interp_run_pop(&ctx);
		if (!next) {
			// No uninterpreted states left, fixpoint reached.
			success = true;
			break;
		}
		ctx.astate = rz_interp_abstr_state_clone(inst, next);

		const RzILCacheBlock *il_bb = rz_il_cache_client_lift_il_block(inst->il_cache_client, ctx.astate->pc);
		if (!il_bb) {
			// Lifting failed, TODO: handle this better
			break;
		}

		// DEBUG comments
		RzStrBuf sb;
		rz_strbuf_init(&sb);
		const char *old_cmt = rz_meta_get_string(inst->a, RZ_META_TYPE_COMMENT, il_bb->addr);
		if (old_cmt) {
			rz_strbuf_appendf(&sb, "%s; ", old_cmt);
		}
		rz_strbuf_append(&sb, "ENTRY ");
		state_as_str_short(inst, &sb, ctx.astate);
		// rz_meta_set_string(iset->a, RZ_META_TYPE_COMMENT, il_bb->addr, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		ctx.astate->bb_addr = il_bb->addr;
		ctx.astate->bb_size = il_bb->size;
		// Evaluate the effect on the abstract state.
		if (!inst->plugin->eval(&ctx, il_bb)) {
			RZ_LOG_DEBUG("interpreter: Eval failed\n");
			success = false;
			break;
		}
	}

cleanup:
	rz_list_free(ctx.queue);
	ht_up_free(ctx.pc_states);
	return success;
}

/**
 * \brief Interpreter thread
 */
RZ_API bool rz_interp_instance_th(RZ_NONNULL RZ_OWN RzInterpInstance *inst) {
	rz_return_val_if_fail(inst &&
			inst->il_cache_client &&
			inst->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF] &&
			inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE] &&
			inst->yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW] &&
			inst->run_state_sync &&
			inst->plugin &&
			inst->plugin->eval &&
			inst->plugin->init_state &&
			inst->plugin->fini_state,
		false);

	bool success = true;

	RZ_LOG_DEBUG("interpreter: Main: Hello.\n");

	//
	// Start interpretation
	//


	// TODO: It is probably better to make the following stuff while-loops.
	// Because otherwise it doesn't make sense without the docs.
	// But while debugging and developing, I keep it this way to separate clearly
	// what the interpreter does in each state.

INIT:
	// prepare state at the procedure entrypoint
	RZ_LOG_DEBUG("interpreter: Enter INIT\n");
	rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_INIT);

	ut64 entry_point;
	if (rz_th_ring_buf_take_blocking(inst->entry_points, &entry_point) != RZ_THREAD_RING_BUF_OK) {
		// No more entry points to interpret => Terminate.
		// OR.
		success = true;
		goto TERM;
	}

// EMU
	RZ_LOG_DEBUG("interpreter: Enter EMU\n");
	rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_EMU);

	if (!rz_interp_run(inst, entry_point)) {
		RZ_LOG_ERROR("Interpreter run failed for entry point 0x%" PFMT64x "\n", entry_point);
	}

// CLEAN
	RZ_LOG_DEBUG("interpreter: Enter CLEAN\n");
	rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_CLEAN);

	// Wait until RzInquiry asks to start again.
	rz_th_sem_wait(inst->run_state_sync);

	// Clean can only transition to Init.
	goto INIT;

TERM: {
	RZ_LOG_DEBUG("interpreter: Enter TERM\n");
	rz_interp_run_state_set(inst->run_state, RZ_INTERP_RUN_STATE_TERM);
	return success;
}
}
