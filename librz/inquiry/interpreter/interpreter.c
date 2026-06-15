// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include "rz_analysis.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_itv.h"
#include "rz_util/rz_log.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

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
	RZ_OWN RZ_NONNULL RzAnalysisILConfig *il_config,
	RZ_NULLABLE const RzILRegBinding *reg_bindings) {
	rz_return_val_if_fail(il_config && reg_bindings, NULL);
	RzInterpAbstrState *state = RZ_NEW0(RzInterpAbstrState);
	if (!state) {
		return NULL;
	}
	state->arch_name = arch_name;
	state->kinds = kinds;
	state->pc = RZ_NEW0(RzInterpAbstrVal);
	if (!state->pc) {
		return NULL;
	}
	// Initialize the register file with uninitialized abstract values.
	state->var_name_hashes = ht_up_new(NULL, free);
	state->globals = ht_up_new(NULL, free);
	for (size_t i = 0; i < reg_bindings->regs_count; i++) {
		const char *rname = reg_bindings->regs[i].name;
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
	state->il_config = il_config;
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
	if (state->pc) {
		free(state->pc);
	}
	if (state->il_config) {
		rz_analysis_il_config_free(state->il_config);
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
		RzInterpAbstrVal *val = iset->plugin->clone_val(ht_up_find(vars, *key, NULL), iset->intrpr_priv);
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
	r->pc = iset->plugin->clone_val(state->pc, iset->intrpr_priv);
	if (!state->pc) {
		free(r);
		return NULL;
	}
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
	r->il_config = state->il_config;
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
		rz_intp_run_state_free(iset->run_state);
	}
	if (iset->il_vm) {
		rz_analysis_il_vm_free(iset->il_vm);
	}
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
	*io_request_rbuf = rz_th_ring_buf_new(RZ_INTERP_IO_RBUF_SIZE, sizeof(RzInterpIORequest));
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
	RZ_NONNULL RZ_BORROW RzThreadRingBuf *il_request_rbuf,
	RZ_NONNULL RZ_BORROW RzThreadQueue *il_queue,
	RzInterpYieldRBuf *yield_rbufs[RZ_INTERP_YIELD_KIND_NUM],
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	rz_return_val_if_fail(plugin && ignored_code && analysis && il_request_rbuf && il_queue, NULL);

	if (abstraction != (plugin->supported_abstractions & abstraction)) {
		RZ_LOG_ERROR("Plugin does not support all required abstractions.\n");
		return NULL;
	}

	RzInterpSet *iset = RZ_NEW0(RzInterpSet);
	if (!iset) {
		return NULL;
	}

	// Perform the RzAnalysisILVM and abstract state setup procedure.
	// This prototype won't use the RzAnalysisILVM directly but its components.
	// That is because the prototypes doesn't handle the VM tasks (track PC, handle IO)
	// in one VM object, but in separated modules.
	// So analysis_vm->vm->vm_memorys is used for handling IO requests and
	// analysis_vm->reg_binding is used for the abstract state setup.
	//
	// TODO: Is it a good idea to separate these tasks into different modules?
	// It allows the IO handler to buffer reads in r-- sections for multiple interpreters.
	// Possibly allows to optimize the IO access, because there is only module accessing it (not every interpreter).
	// But is there any other advantage?
	RzAnalysisILVM *il_vm = rz_analysis_il_vm_new(analysis, rz_analysis_get_reg(analysis));
	if (!il_vm) {
		free(iset);
		RZ_LOG_ERROR("Failed during RzAnalysisILVM setup.\n");
		return NULL;
	}

	const RzAnalysisPlugin *cur = rz_analysis_plugin_current(analysis);
	RzAnalysisILConfig *config = cur->il_config(analysis);
	RzInterpAbstrState *state = rz_interpreter_abstr_state_new(
		cur->arch,
		abstraction,
		config,
		il_vm->reg_binding);
	if (!state) {
		free(iset);
		rz_analysis_il_vm_free(il_vm);
		rz_analysis_il_config_free(config);
		return NULL;
	}

	RzThreadRingBuf *io_request_rbuf = NULL;
	RzThreadRingBuf *io_result_rbuf = NULL;
	RzThreadRingBuf *entry_points = NULL;
	if (!setup_ipc_objects(&io_request_rbuf, &io_result_rbuf, &entry_points)) {
		free(iset);
		rz_analysis_il_vm_free(il_vm);
		rz_interpreter_abstr_state_free(state);
		return NULL;
	}

	iset->plugin = plugin;
	iset->astate = state;
	iset->run_state = rz_intp_run_state_new();
	iset->il_vm = il_vm;
	iset->il_queue = il_queue;
	iset->il_request_rbuf = il_request_rbuf;
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

static bool jumps_to_ignored_code(const RzVector *v, ut64 jump_target) {
	void *it;
	rz_vector_foreach (v, it) {
		RzInterval *itv = it;
		if (rz_itv_contain(*itv, jump_target)) {
			return true;
		}
	}
	return false;
}

typedef struct {
	RzInterpCtrlFlow ctrl_flow;
	ut64 in_state_hash;
} SuccessorState;

static bool choose_next_pc(RzInterpSet *iset,
	ut64 out_hash,
	RzVector *tmp_succ_addr,
	RzVector *succ_states,
	const RzILCacheBlock *il_bb) {
	// Debug printing whole state of VM.
	//
	// plugin->state_as_str(out_state, state_str, iset->intrpr_priv);
	// char *s = rz_strbuf_drain_nofree(state_str);
	// RZ_LOG_DEBUG("%s", s);
	// free(s);
	bool has_succsessor = true;

	// Determine successors and increase the reference counts for the current out state.
	if (!iset->plugin->successors(iset->astate, tmp_succ_addr, iset->intrpr_priv)) {
		rz_warn_if_reached();
		return false;
	}

	// It is possible that the successor function doesn't add successors.
	// E.g. because the PC is an abstract value.
	// In this case the state counts as invalid.
	has_succsessor = !rz_vector_empty(tmp_succ_addr);
	// Request the successor effects over the queue.
	while (!rz_vector_empty(tmp_succ_addr)) {
		RzInterpCtrlFlow cf = { 0 };
		rz_vector_pop_front(tmp_succ_addr, &cf);
		if (cf.target_addr == UT64_MAX || cf.target_addr == 0) {
			RZ_LOG_DEBUG("interpreter: Quit due to invalid PC.\n");
			// Obviously wrong address.
			return false;
		}
		cf.src_block_addr = il_bb->addr;
		if (jumps_to_ignored_code(iset->ignored_code, cf.target_addr) && !cf.alt_target) {
			RZ_LOG_DEBUG("interpreter: tried to jump to ignored code region at 0x%" PFMT64x "\n", cf.target_addr);
			// Ignored code is mostly dynamically linked functions.
			// Skip to the next following address after the jump.
			cf.alt_target = il_bb->addr + il_bb->size;
			cf.actual_target = cf.alt_target;
		}

		SuccessorState ss = {
			.ctrl_flow = cf,
			.in_state_hash = out_hash
		};
		// The successors are pushed in the same order into the succ_states
		// vector, as they are requested over the queue.
		rz_vector_push(succ_states, &ss);
		if (rz_th_ring_buf_put(iset->il_request_rbuf, &cf.actual_target) != RZ_THREAD_RING_BUF_OK) {
			return false;
		}
	}
	return has_succsessor;
}

/**
 * \brief Set entry point and reset (clean) the vectors and sets.
 */
static bool reset_intrpr_state(
	RzInterpSet *iset,
	ut64 entry_point,
	RzVector **tmp_succ_addr,
	RzSetU **reachable_states,
	RzVector **succ_states) {

	if (iset->plugin->reset) {
		iset->plugin->reset(iset->intrpr_priv);
	}

	if (!iset->plugin->reset_state(iset->astate, entry_point, iset->intrpr_priv)) {
		rz_warn_if_reached();
		return false;
	}

	*tmp_succ_addr = rz_vector_new(sizeof(RzInterpCtrlFlow), NULL, NULL);
	*succ_states = rz_vector_new(sizeof(SuccessorState), NULL, NULL);
	*reachable_states = rz_set_u_new();
	if (!*tmp_succ_addr || !*succ_states || !*reachable_states) {
		rz_warn_if_reached();
		return false;
	}
	return true;
}

/**
 * Main interpretation.
 */
RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpSet *iset) {
	rz_return_val_if_fail(iset &&
			iset->astate &&
			iset->il_request_rbuf &&
			iset->il_queue &&
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

	// A vector for the plugin to push the determined successors into.
	RzVector *tmp_succ_addr = NULL;
	// The set of reachable states.
	RzSetU *reachable_states = NULL;
	// The successor states to evaluate.
	// This vector must have the same order as the elements pushed into branch_queue.
	RzVector *succ_states = NULL;
	const RzILCacheBlock *il_bb = NULL;
	ut64 astate_hash = 0;

	if (iset->plugin->init) {
		iset->plugin->init(&iset->intrpr_priv);
	}
	if (!iset->plugin->init_state(iset->astate, iset->intrpr_priv)) {
		rz_warn_if_reached();
		return false;
	}

	// TODO: It is probably better to make the following stuff while-loops.
	// Because otherwise it doesn't make sense without the docs.
	// But while debugging and developing, I keep it this way to separate clearly
	// what the interpreter does in each state.

INIT: {
	RZ_LOG_DEBUG("interpreter: Enter INIT\n");
	rz_intp_run_state_set(iset->run_state, RZ_INTP_RUN_STATE_INIT);

	ut64 entry_point;
	if (rz_th_ring_buf_take_blocking(iset->entry_points, &entry_point) != RZ_THREAD_RING_BUF_OK ||
		rz_th_ring_buf_put(iset->il_request_rbuf, &entry_point) != RZ_THREAD_RING_BUF_OK) {
		// No more entry points to interpret => Terminate.
		// OR
		// Can't request IL block => Cache closed => Terminate.
		success = true;
		goto TERM;
	}

	// Initializes the current interpreter's private data and its state.
	if (!reset_intrpr_state(iset, entry_point, &tmp_succ_addr, &reachable_states, &succ_states)) {
		success = false;
		goto TERM;
	}

	if (!rz_th_queue_pop(iset->il_queue, false, (void **)&il_bb) ||
		il_bb == RZ_IL_CACHE_FAILED_LIFTING_PTR || !il_bb) {
		// No more BBs to interpret. Terminate.
		success = true;
		goto TERM;
	}

	goto EMU;
}

EMU: {
	RZ_LOG_DEBUG("interpreter: Enter EMU\n");
	rz_intp_run_state_set(iset->run_state, RZ_INTP_RUN_STATE_EMU);

	iset->astate->bb_addr = il_bb->addr;
	iset->astate->bb_size = il_bb->size;
	// Evaluate the effect on the abstract state.
	if (!plugin->eval(iset, il_bb, iset->intrpr_priv)) {
		RZ_LOG_DEBUG("interpreter: Eval failed\n");
		goto CLEAN;
	}
	astate_hash = plugin->hash_state(iset->astate, iset->intrpr_priv);

	// Add output state hash to the reachable states and
	// set a flag if it was a new state.
	size_t psize = rz_set_u_size(reachable_states);
	rz_set_u_add(reachable_states, astate_hash);
	bool new_state_reached = psize < rz_set_u_size(reachable_states);

	// Determine the successor effects to evaluate.
	// Only newly reached states are allowed to add successors.
	if (!(new_state_reached && choose_next_pc(iset, astate_hash, tmp_succ_addr, succ_states, il_bb))) {
		// No new state or address means we can stop interpreting.
		// Note, that we can't use the queues as cancel condition because they
		// are asynchronous and checking them would introduces race conditions.
		// TODO: This doesn't work if the interpreter can produce multiple out states.
		goto CLEAN;
	}

	// Set effect and state for next evaluation.
	il_bb = NULL;
	SuccessorState next = { 0 };
	rz_vector_pop_front(succ_states, &next);
	if (!rz_th_queue_pop(iset->il_queue, false, (void **)&il_bb) ||
		il_bb == RZ_IL_CACHE_FAILED_LIFTING_PTR || !il_bb) {
		RZ_LOG_DEBUG("interpreter: Getting il bb failed\n");
		// The il op lifting failed. Likely because the PC
		// pointed to an unmapped region.
		goto CLEAN;
	}
	// Now we know the size of the destination block.
	// Set it and report the control flow change.
	next.ctrl_flow.target_block_size = il_bb->size;
	RzThreadRingBuf *cf_rbuf = iset->yield_rbufs[RZ_INTERP_YIELD_KIND_CONTROL_FLOW]->rbuf;
	if (rz_th_ring_buf_put(cf_rbuf, &next.ctrl_flow) != RZ_THREAD_RING_BUF_OK) {
		return false;
	}

	RZ_LOG_DEBUG("interpreter: Received il_bb: 0x%" PFMT64x "\n", il_bb->addr);
	if (!plugin->set_pc(iset->astate, next.ctrl_flow.actual_target, iset->intrpr_priv)) {
		rz_warn_if_reached();
		goto CLEAN;
	}

	// Loop back. Interpret next block.
	goto EMU;
}

CLEAN: {
	RZ_LOG_DEBUG("interpreter: Enter CLEAN\n");
	rz_intp_run_state_set(iset->run_state, RZ_INTP_RUN_STATE_CLEAN);

	RZ_FREE_CUSTOM(tmp_succ_addr, rz_vector_free);
	RZ_FREE_CUSTOM(succ_states, rz_vector_free);
	RZ_FREE_CUSTOM(reachable_states, rz_set_u_free);

	// Wait until RzInquiry asks to start again.
	rz_th_sem_wait(iset->run_state_sync);

	// Clean can only transition to Init.
	goto INIT;
}

TERM: {
	RZ_LOG_DEBUG("interpreter: Enter TERM\n");
	rz_intp_run_state_set(iset->run_state, RZ_INTP_RUN_STATE_TERM);
	iset->plugin->fini_state(iset->astate, iset->intrpr_priv);
	if (iset->plugin->fini && iset->intrpr_priv) {
		RZ_FREE_CUSTOM(iset->intrpr_priv, iset->plugin->fini);
	}

	RZ_FREE_CUSTOM(tmp_succ_addr, rz_vector_free);
	RZ_FREE_CUSTOM(succ_states, rz_vector_free);
	RZ_FREE_CUSTOM(reachable_states, rz_set_u_free);
	if (iset->plugin->fini && iset->intrpr_priv) {
		RZ_FREE_CUSTOM(iset->intrpr_priv, iset->plugin->fini);
	}
	return success;
}
}
