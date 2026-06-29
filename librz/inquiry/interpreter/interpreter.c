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

#include "inquiry/interpreter/prototype/eval.h"

RZ_API void rz_interpreter_yield_rbuf_free(RZ_OWN RZ_NULLABLE RzInterpYieldRBuf *yield_rbufs) {
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

RZ_API RZ_OWN RzInterpYieldRBuf *rz_interpreter_yield_rbuf_new(RzInterpYieldKind kind,
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
RZ_API RZ_OWN RzInterpAbstrState *rz_interpreter_abstr_state_new(
	const char *arch_name,
	RzInterpAbstraction kinds,
	RZ_BORROW RZ_NONNULL RzAnalysisILContext *il_context) {
	rz_return_val_if_fail(il_context, NULL);
	RzInterpAbstrState *state = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	state->arch_name = arch_name;
	state->kinds = kinds;
	// Initialize the register file with uninitialized abstract values.
	state->var_name_hashes = ht_up_new(NULL, free);
	state->globals = ht_up_new(NULL, free);
	for (size_t i = 0; i < il_context->reg_binding->regs_count; i++) {
		const char *rname = il_context->reg_binding->regs[i].name;
		RzInterpAbstrVal *aval = RZ_NEW0(RzInterpAbstrVal);
		if (!aval) {
			ht_up_free(state->globals);
			ht_up_free(state->var_name_hashes);
			free(state);
			return NULL;
		}

		aval->kind = RZ_INTERP_ABSTRACTION_UNDEF;
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

RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpAbstrState *state) {
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

static HtUP *var_set_clone(const RzInterpSet *iset, HtUP *vars) {
	HtUP *r = ht_up_new(NULL, free);
	if (!r) {
		return NULL;
	}
	RzIterator *it = ht_up_as_iter_keys(vars);
	ut64 *key;
	rz_iterator_foreach(it, key) {
		RzInterpAbstrVal *val = iset->plugin->clone_val(ht_up_find(vars, *key, NULL), iset->interp_priv);
		if (!val) {
			continue;
		}
		ht_up_insert(r, *key, val);
	}
	return r;
}

RZ_API RZ_OWN RzInterpAbstrState *rz_interpreter_abstr_state_clone(RZ_NONNULL RzInterpSet *iset, const RzInterpAbstrState *state) {
	RzInterpAbstrState *r = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	r->arch_name = state->arch_name;
	r->kinds = state->kinds;
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

RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpSet *iset) {
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
	if (iset->astate) {
		rz_interpreter_abstr_state_free(iset->astate);
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
RZ_API RZ_OWN RzInterpSet *rz_interpreter_set_new(
	RzAnalysis *analysis,
	RZ_NONNULL RZ_OWN RzInterpPlugin *plugin,
	RzInterpAbstraction abstraction,
	RZ_NONNULL RZ_BORROW RzILCacheClient *il_cache_client,
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	rz_return_val_if_fail(plugin && ignored_code && analysis && il_cache_client, NULL);

	if (abstraction != (plugin->supported_abstractions & abstraction)) {
		RZ_LOG_ERROR("Plugin does not support all required abstractions.\n");
		return NULL;
	}

	RzInterpSet *iset = RZ_NEW0(RzInterpSet);
	if (!iset) {
		return NULL;
	}

	RzAnalysisILContext *il_ctx = rz_analysis_il_context_resolve(analysis);
	if (!il_ctx) {
		free(iset);
		RZ_LOG_ERROR("Failed to create analysis IL context.\n");
		return NULL;
	}

	const RzAnalysisPlugin *cur = rz_analysis_plugin_current(analysis);
	RzInterpAbstrState *state = rz_interpreter_abstr_state_new(cur->arch, abstraction, il_ctx);
	if (!state) {
		free(iset);
		rz_analysis_il_context_free(il_ctx);
		return NULL;
	}

	RzThreadRingBuf *io_request_rbuf = NULL;
	RzThreadRingBuf *io_result_rbuf = NULL;
	RzThreadRingBuf *entry_points = NULL;
	if (!setup_ipc_objects(&io_request_rbuf, &io_result_rbuf, &entry_points)) {
		free(iset);
		rz_analysis_il_context_free(il_ctx);
		rz_interpreter_abstr_state_free(state);
		return NULL;
	}

	iset->a = analysis;
	iset->plugin = plugin;
	iset->astate = state;
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

	iset->fcn_state.pc_states = ht_up_new(NULL, free);
	iset->fcn_state.queue = rz_list_new();

	return iset;
}

RZ_API void rz_interp_set_push(RZ_BORROW RZ_NONNULL RzInterpSet *iset, RZ_BORROW RZ_NONNULL RzInterpAbstrState *as) {
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
	state_as_str_short(iset, &sb, as);
	RZ_LOG_DEBUG("PUSH 0x%" PFMT64x ": %s\n", as->pc, rz_strbuf_get(&sb));
	rz_strbuf_fini(&sb);
	RzInterpAbstrState *existing = ht_up_find(iset->fcn_state.pc_states, as->pc, NULL);
	if (existing) {
		if (iset->plugin->join_state(existing, as, iset->interp_priv) && !existing->uninterpreted) {
			existing->uninterpreted = true;
			rz_list_push(iset->fcn_state.queue, existing);
		}
	} else {
		RzInterpAbstrState *c = rz_interpreter_abstr_state_clone(iset, as);
		if (!c) {
			return;
		}
		ht_up_insert(iset->fcn_state.pc_states, as->pc, c);
		c->uninterpreted = true;
		rz_list_push(iset->fcn_state.queue, c);
	}
}

RZ_API RZ_NULLABLE RZ_BORROW RzInterpAbstrState *rz_interp_set_pop(RZ_BORROW RZ_NONNULL RzInterpSet *iset) {
	RzInterpAbstrState *r = rz_list_pop(iset->fcn_state.queue);
	if (!r) {
		return NULL;
	}
	r->uninterpreted = false;
	return r;
}

/**
 * Main interpretation.
 */
RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpSet *iset) {
	rz_return_val_if_fail(iset &&
			iset->astate &&
			iset->il_cache_client &&
			iset->yield_rbufs[RZ_INTERP_YIELD_KIND_XREF] &&
			iset->yield_rbufs[RZ_INTERP_YIELD_KIND_CALL_CANDIDATE] &&
			iset->yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW] &&
			iset->run_state_sync &&
			iset->plugin &&
			iset->plugin->eval &&
			iset->plugin->successors &&
			iset->plugin->init_state &&
			iset->plugin->fini_state &&
			iset->plugin->hash_state,
		false);

	bool success = true;

	RZ_LOG_DEBUG("interpreter: Main: Hello.\n");
	RzInterpPlugin *plugin = iset->plugin;

	//
	// Start interpretation
	//

	if (iset->plugin->init) {
		iset->plugin->init(&iset->interp_priv);
	}
	if (!iset->plugin->init_state(iset->astate, iset->interp_priv)) {
		rz_warn_if_reached();
		return false;
	}

	// TODO: It is probably better to make the following stuff while-loops.
	// Because otherwise it doesn't make sense without the docs.
	// But while debugging and developing, I keep it this way to separate clearly
	// what the interpreter does in each state.

INIT: {
	// prepare state at the procedure entrypoint
	RZ_LOG_DEBUG("interpreter: Enter INIT\n");
	rz_interp_run_state_set(iset->run_state, RZ_INTERP_RUN_STATE_INIT);

	const RzAnalysisPlugin *cur = rz_analysis_plugin_current(iset->a);
	RzInterpAbstrState *estate = rz_interpreter_abstr_state_new(cur->arch, RZ_INTERP_ABSTRACTION_CONST, iset->il_ctx);

	rz_list_purge(iset->fcn_state.queue);
	ht_up_clear(iset->fcn_state.pc_states);

	ut64 entry_point;
	if (rz_th_ring_buf_take_blocking(iset->entry_points, &entry_point) != RZ_THREAD_RING_BUF_OK) {
		// No more entry points to interpret => Terminate.
		// OR.
		success = true;
		goto TERM;
	}

	if (iset->plugin->reset) {
		iset->plugin->reset(iset->interp_priv);
	}

	if (!iset->plugin->init_state(estate, iset->interp_priv) || !iset->plugin->reset_state(estate, entry_point, iset->interp_priv)) {
		rz_warn_if_reached();
		return false;
	}

	rz_interp_set_push(iset, estate);
	rz_interpreter_abstr_state_free(estate);
}

	while (true) {
		RZ_LOG_DEBUG("interpreter: Enter EMU\n");
		rz_interp_run_state_set(iset->run_state, RZ_INTERP_RUN_STATE_EMU);

		RzInterpAbstrState *next = rz_interp_set_pop(iset);
		if (!next) {
			// No uninterpreted states left, fixpoint reached.
			success = true;
			goto TERM;
		}
		iset->astate = rz_interpreter_abstr_state_clone(iset, next);

		const RzILCacheBlock *il_bb = rz_il_cache_client_lift_il_block(iset->il_cache_client, iset->astate->pc);
		if (!il_bb) {
			success = false;
			goto TERM;
		}

		RzStrBuf sb;
		rz_strbuf_init(&sb);
		const char *old_cmt = rz_meta_get_string(iset->a, RZ_META_TYPE_COMMENT, il_bb->addr);
		if (old_cmt) {
			rz_strbuf_appendf(&sb, "%s; ", old_cmt);
		}
		rz_strbuf_append(&sb, "ENTRY ");
		state_as_str_short(iset, &sb, iset->astate);
		// rz_meta_set_string(iset->a, RZ_META_TYPE_COMMENT, il_bb->addr, rz_strbuf_get(&sb));
		rz_strbuf_fini(&sb);

		iset->astate->bb_addr = il_bb->addr;
		iset->astate->bb_size = il_bb->size;
		// Evaluate the effect on the abstract state.
		if (!plugin->eval(iset, il_bb, iset->interp_priv)) {
			RZ_LOG_DEBUG("interpreter: Eval failed\n");
			goto CLEAN;
		}
	}

CLEAN: {
	RZ_LOG_DEBUG("interpreter: Enter CLEAN\n");
	rz_interp_run_state_set(iset->run_state, RZ_INTERP_RUN_STATE_CLEAN);

	// Wait until RzInquiry asks to start again.
	rz_th_sem_wait(iset->run_state_sync);

	// Clean can only transition to Init.
	goto INIT;
}

TERM: {
	RZ_LOG_DEBUG("interpreter: Enter TERM\n");
	rz_interp_run_state_set(iset->run_state, RZ_INTERP_RUN_STATE_TERM);
	iset->plugin->fini_state(iset->astate, iset->interp_priv);
	if (iset->plugin->fini && iset->interp_priv) {
		RZ_FREE_CUSTOM(iset->interp_priv, iset->plugin->fini);
	}

	if (iset->plugin->fini && iset->interp_priv) {
		RZ_FREE_CUSTOM(iset->interp_priv, iset->plugin->fini);
	}
	return success;
}
}
