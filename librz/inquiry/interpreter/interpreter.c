// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include "rz_util/rz_assert.h"
#include "rz_util/rz_itv.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

RZ_API void rz_interpreter_insn_pkt_free(RZ_NULLABLE RZ_OWN RzInterpreterInsnPkt *pkt) {
	if (!pkt) {
		return;
	}
	if (pkt->effect) {
		rz_il_op_effect_free(pkt->effect);
	}
	free(pkt);
}

RZ_API void rz_interpreter_il_bb_free(RZ_NULLABLE RZ_OWN RzInterpreterILBB *il_bb) {
	if (!il_bb) {
		return;
	}
	rz_pvector_free(il_bb->il_ops);
	free(il_bb);
}

RZ_API void rz_interpreter_yield_queue_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldQueue *yield_queue) {
	if (!yield_queue) {
		return;
	}
	if (yield_queue->yield_queue) {
		rz_th_queue_free(yield_queue->yield_queue);
	}
	if (yield_queue->filter_data && yield_queue->filter_data->io_boundaries) {
		rz_pvector_free(yield_queue->filter_data->io_boundaries);
	}
	free(yield_queue->filter_data);
	free(yield_queue);
}

RZ_API RZ_OWN RzInterpreterYieldQueue *rz_interpreter_yield_queue_new(RzInterpreterYieldKind kind,
	RzInterpreterYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data) {
	RzInterpreterYieldQueue *yield_queue = RZ_NEW0(RzInterpreterYieldQueue);
	if (!yield_queue) {
		return NULL;
	}
	RzThreadQueue *queue = NULL;
	switch (kind) {
	case RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE:
		queue = rz_th_queue_new(RZ_INTERPRETER_YIELD_QUEUE_SIZE, NULL);
		break;
	case RZ_INTERPRETER_YIELD_KIND_XREF:
		if (filter_data) {
			yield_queue->filter_data = RZ_NEW0(RzInterpreterYieldFilterData);
			yield_queue->filter_data->io_boundaries = filter_data;
		}
		queue = rz_th_queue_new(RZ_INTERPRETER_YIELD_QUEUE_SIZE, NULL);
		break;
	}
	if (!queue) {
		free(yield_queue);
		return NULL;
	}
	yield_queue->kind = kind;
	yield_queue->yield_queue = queue;
	yield_queue->filter = filter;
	return yield_queue;
}

/**
 * \brief Initializes an abstract state for specified abstract kinds. Optionally with a list of registers.
 * The register name list should always be given if the architecture has some.
 */
RZ_API RZ_OWN RzInterpreterAbstrState *rz_interpreter_abstr_state_new(
	const char *arch_name,
	RzInterpreterAbstraction kinds,
	RZ_OWN RZ_NONNULL RzAnalysisILConfig *il_config,
	RZ_NULLABLE const RzILRegBinding *reg_bindings) {
	rz_return_val_if_fail(il_config && reg_bindings, NULL);
	RzInterpreterAbstrState *state = RZ_NEW0(RzInterpreterAbstrState);
	if (!state) {
		return NULL;
	}
	state->arch_name = arch_name;
	state->kinds = kinds;
	state->pc = RZ_NEW0(RzInterpreterAbstrVal);
	if (!state->pc) {
		return NULL;
	}
	// Initialize the register file with uninitialized abstract values.
	state->var_name_hashes = ht_up_new(NULL, free);
	state->globals = ht_up_new(NULL, free);
	for (size_t i = 0; i < reg_bindings->regs_count; i++) {
		const char *rname = reg_bindings->regs[i].name;
		RzInterpreterAbstrVal *aval = RZ_NEW0(RzInterpreterAbstrVal);
		if (!aval) {
			ht_up_free(state->globals);
			ht_up_free(state->var_name_hashes);
			free(state);
			return NULL;
		}

		aval->kind = RZ_INTERPRETER_ABSTRACTION_UNDEF;
		ut64 djb2_reg_hash = rz_str_djb2_hash(rname);
		if (!ht_up_insert(state->globals, djb2_reg_hash, aval) ||
			!ht_up_insert(state->var_name_hashes, djb2_reg_hash, rz_str_dup(rname))) {
			RZ_LOG_ERROR("Failed to add %s to the global variable map. "
				     "DJB2 hash collision of the register name. DJB2 hash = 0x%" PFMT64x "\n",
				rname, djb2_reg_hash);
			return NULL;
		}
	}
	state->locals = ht_up_new(NULL, free);
	state->lets = ht_up_new(NULL, free);
	state->il_config = il_config;
	// TODO: Instance Id
	state->shared_obj = rz_interpreter_shared_objects_new(0);
	return state;
}

RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpreterAbstrState *state) {
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
	if (state->shared_obj) {
		rz_interpreter_shared_objects_free(state->shared_obj);
	}
	free(state);
}

RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpreterSet *iset) {
	if (!iset) {
		return;
	}
	if (iset->branch_queue) {
		rz_th_queue_free(iset->branch_queue);
	}
	if (iset->il_queue) {
		rz_th_queue_free(iset->il_queue);
	}
	if (iset->io_request) {
		rz_th_queue_free(iset->io_request);
	}
	if (iset->io_result) {
		rz_th_queue_free(iset->io_result);
	}
	if (iset->is_running_flag) {
		rz_atomic_bool_free(iset->is_running_flag);
	}
	if (iset->state) {
		rz_interpreter_abstr_state_free(iset->state);
	}
	if (iset->yield_queues) {
		ht_up_free(iset->yield_queues);
	}
	if (iset->entry_points) {
		rz_vector_free(iset->entry_points);
	}
	free(iset);
}


RZ_API RZ_OWN RzInterpreterSharedObjects *rz_interpreter_shared_objects_new(size_t instance_id) {
	RzInterpreterSharedObjects *so = RZ_NEW0(RzInterpreterSharedObjects);
	if (!so) {
		return NULL;
	}
	so->instance_id = instance_id;
	so->received = rz_th_lock_new(false);
	if (!so->received) {
		free(so);
		return NULL;
	}
	return so;
}

RZ_API void rz_interpreter_shared_objects_fini(RZ_NULLABLE RZ_BORROW RzInterpreterSharedObjects *so) {
	if (!so) {
		return;
	}
	rz_th_lock_free(so->received);
	size_t instance_id = so->instance_id;
	memset(so, 0, sizeof(RzInterpreterSharedObjects));
	so->instance_id = instance_id;
	so->received = rz_th_lock_new(false);
}

RZ_API void rz_interpreter_shared_objects_free(RZ_NULLABLE RZ_OWN RzInterpreterSharedObjects *so) {
	if (!so) {
		return;
	}
	rz_th_lock_free(so->received);
	free(so);
}


static bool setup_queues(
	RZ_OWN RzPVector /*<RzBinSection *>*/ *sections,
	RzInterpreterYieldFilter yield_filter,
	RZ_OUT RzThreadQueue **il_queue,
	RZ_OUT RzThreadQueue **io_request_q,
	RZ_OUT RzThreadQueue **io_result_q,
	RZ_OUT RzThreadQueue **branch_queue,
	RZ_OUT HtUP **yield_queues) {
	*il_queue = NULL;
	*io_request_q = NULL;
	*io_result_q = NULL;
	*branch_queue = NULL;
	*yield_queues = NULL;

	RzInterpreterYieldQueue *yield_queue = NULL;
	// The queue to pass the Effects to the interpreter.
	// This is only one queue for the prototype.
	// In practice it would be one for each interpreter.
	*il_queue = rz_th_queue_new(RZ_INTERPRETER_IL_QUEUE_SIZE, NULL);
	if (!il_queue) {
		goto error_free;
	}

	// Setup the IO queues. Each interpreter instance needs it's own queue at
	// for writing IO. Because the writing is done on the IO cache, and each
	// instance needs its own cache.
	*io_request_q = rz_th_queue_new(RZ_INTERPRETER_IO_QUEUE_SIZE, NULL);
	*io_result_q = rz_th_queue_new(RZ_INTERPRETER_IO_QUEUE_SIZE, NULL);
	if (!io_request_q || !io_result_q) {
		goto error_free;
	}

	// The address queue. It is the queue the interpreter can request new Effects.
	// Of course, currently there is only a single one for the prototype.
	// In practice there would be one for each interpreter instance.
	*branch_queue = rz_th_queue_new(RZ_INTERPRETER_ADDR_QUEUE_SIZE, NULL);
	if (!branch_queue) {
		goto error_free;
	}

	// Multiple yield queues can be used by a single interpreter.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	*yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queues) {
		goto error_free;
	}

	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.

	// Xref yield queue.
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		yield_filter,
		sections);
	if (!yield_queue) {
		goto error_free;
	}
	ht_up_insert(*yield_queues, yield_kind, yield_queue);

	yield_kind = RZ_INTERPRETER_YIELD_KIND_CALL_CANDIDATE;
	yield_queue = rz_interpreter_yield_queue_new(yield_kind, NULL, NULL);
	if (!yield_queue) {
		goto error_free;
	}
	ht_up_insert(*yield_queues, yield_kind, yield_queue);
	return true;

error_free:
	ht_up_free(*yield_queues);
	rz_th_queue_free(*il_queue);
	rz_th_queue_free(*io_request_q);
	rz_th_queue_free(*io_result_q);
	rz_th_queue_free(*branch_queue);
	return false;
}


/**
 * \brief Initializes a new RzInterpreterSet and returns it.
 * If it fails, all arguments are freed.
 */
RZ_API RZ_OWN RzInterpreterSet *rz_interpreter_set_new(
	RZ_NONNULL RZ_OWN RzInterpreterPlugin *plugin,
	RZ_NONNULL RZ_OWN RzInterpreterAbstrState *state,
	RZ_OWN RzPVector /*<RzBinSection *>*/ *sections,
	RzInterpreterYieldFilter yield_filter,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag,
	RZ_NONNULL RZ_OWN RzVector /*<ut64>*/ *entry_points,
	RZ_NONNULL const RzVector /*<RzInterval>*/ *ignored_code) {
	rz_return_val_if_fail(plugin && state && is_running_flag && entry_points && ignored_code, NULL);

	RzInterpreterSet *set = RZ_NEW0(RzInterpreterSet);
	if (!set) {
		return false;
	}
	RzThreadQueue *io_request_q = NULL;
	RzThreadQueue *io_result_q = NULL;
	RzThreadQueue *branch_queue = NULL;
	RzThreadQueue *il_queue = NULL;
	HtUP *yield_queues = NULL;
	if (!setup_queues(sections, yield_filter, &il_queue, &io_request_q, &io_result_q, &branch_queue, &yield_queues)) {
		return false;
	}

	set->plugin = plugin;
	set->state = state;
	set->il_queue = il_queue;
	set->branch_queue = branch_queue;
	set->yield_queues = yield_queues;
	set->io_request = io_request_q;
	set->io_result = io_result_q;
	set->is_running_flag = is_running_flag;
	set->entry_points = entry_points;
	set->ignored_code = ignored_code;
	if (state->kinds != (plugin->supported_abstractions & state->kinds)) {
		RZ_LOG_ERROR("Abstract state doesn't fit to interpreter.\n");
		rz_interpreter_set_free(set);
		return NULL;
	}
	return set;
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

RZ_API void rz_interpreter_set_add_entry_points(RZ_NONNULL RzInterpreterSet *iset, const RzVector /*<ut64>*/ *entry_points) {
	rz_return_if_fail(iset && entry_points);
	rz_vector_clear(iset->entry_points);
	rz_vector_clone_intof(iset->entry_points, entry_points, NULL);
}

typedef struct {
	ut64 addr;
	ut64 in_state_hash;
} SuccessorState;

static bool choose_next_pc(RzInterpreterSet *iset,
	ut64 out_hash,
	RzVector *tmp_succ_addr,
	RzVector *succ_states,
	const RzInterpreterILBB *il_bb,
	void *plugin_data) {
	// Debug printing whole state of VM.
	//
	// plugin->state_as_str(out_state, state_str, plugin_data);
	// char *s = rz_strbuf_drain_nofree(state_str);
	// RZ_LOG_DEBUG("%s", s);
	// free(s);

	rz_th_lock_enter(iset->state->shared_obj->received);
	RzInterpreterBranch *branch = &iset->state->shared_obj->branch;
	bool has_succsessor = true;

	// Determine successors and increase the reference counts for the current out state.
	if (!iset->plugin->successors(iset->state, tmp_succ_addr, plugin_data)) {
		rz_warn_if_reached();
		return false;
	}

	// It is possible that the successor function doesn't add successors.
	// E.g. because the PC is an abstract value.
	// In this case the state counts as invalid.
	has_succsessor = !rz_vector_empty(tmp_succ_addr);
	// Request the successor effects over the queue.
	while (!rz_vector_empty(tmp_succ_addr)) {
		rz_vector_pop_front(tmp_succ_addr, &branch->target_addr);
		if (branch->target_addr == UT64_MAX || branch->target_addr == 0) {
			RZ_LOG_DEBUG("interpreter: Quit due to invalid PC.\n");
			// Obviously wrong address.
			return false;
		}
		branch->branching_bb_addr = il_bb->bb_addr;
		if (jumps_to_ignored_code(iset->ignored_code, branch->target_addr)) {
			RZ_LOG_DEBUG("interpreter: tried to jump to ignored code region at 0x%" PFMT64x "\n", branch->target_addr);
			// Ignored code is mostly dynamically linked functions.
			// Skip to the next following address after the jump.
			branch->alt_target = il_bb->bb_addr + il_bb->size;
		}

		SuccessorState ss = {
			.addr = branch->alt_target ? branch->alt_target : branch->target_addr,
			.in_state_hash = out_hash
		};
		// The successors are pushed in the same order into the succ_states
		// vector, as they are requested over the branch queue.
		rz_vector_push(succ_states, &ss);
		rz_th_queue_push(iset->branch_queue, iset->state->shared_obj, true);
		// Don't leave collection lock. Consumer will unlock it after it collected.
	}
	return has_succsessor;
}

/**
 * Main interpretation.
 */
RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpreterSet *iset) {
	rz_goto_if_fail(iset &&
			iset->state &&
			iset->branch_queue &&
			iset->il_queue &&
			iset->yield_queues &&
			iset->is_running_flag &&
			iset->plugin &&
			iset->plugin->eval &&
			iset->plugin->successors &&
			iset->plugin->init_state &&
			iset->plugin->fini_state &&
			iset->plugin->hash_state,
		entry_assert_error);
	bool success = true;

	RZ_LOG_DEBUG("INTERPRETER Main: Hello.\n");
	RzInterpreterPlugin *plugin = iset->plugin;

	void *priv_ptr = NULL;
	if (iset->plugin->init) {
		iset->plugin->init(&priv_ptr);
	}
	void *plugin_data = priv_ptr ? priv_ptr : NULL;

	//
	// Start interpretation
	//

	RzStrBuf *state_str = rz_strbuf_new("");

	// A vector for the plugin to push the determined successors into.
	RzVector *tmp_succ_addr = NULL;
	// The set of reachable states.
	RzSetU *reachable_states = NULL;
	// The successor states to evaluate.
	// This vector must have the same order as the elements pushed into branch_queue.
	RzVector *succ_states = NULL;

	// TODO: Add support for multiple entry points by spawning an interpreter for each of them.
	// For now let's just ignore them.
	if (rz_vector_len(iset->entry_points) > 1) {
		RZ_LOG_ERROR("More than one entry point is not yet supported by the prototype.\n");
		goto pre_loop_error;
	}

	rz_th_lock_enter(iset->state->shared_obj->received);
	RzInterpreterBranch *branch = &iset->state->shared_obj->branch;
	rz_vector_pop_front(iset->entry_points, &branch->target_addr);
	if (!plugin->init_state(iset->state, branch->target_addr, plugin_data)) {
		rz_warn_if_reached();
		goto pre_loop_error;
	}
#if RZ_BUILD_DEBUG
	ut64 in_hash = plugin->hash_state(iset->state, plugin_data);
#endif
	ut64 out_hash = 0;

	rz_th_queue_push(iset->branch_queue, iset->state->shared_obj, true);
	// Don't leave collection lock. Consumer will unlock it after it collected.

	const RzInterpreterILBB *il_bb = NULL;
	if (!rz_th_queue_pop(iset->il_queue, false, (void **)&il_bb) || !il_bb) {
		goto pre_loop_error;
	}

	tmp_succ_addr = rz_vector_new(sizeof(ut64), NULL, NULL);
	succ_states = rz_vector_new(sizeof(SuccessorState), NULL, NULL);
	reachable_states = rz_set_u_new();
	if (!tmp_succ_addr || !succ_states || !il_bb || !reachable_states) {
		rz_warn_if_reached();
		goto pre_loop_error;
	}

	while (rz_atomic_bool_get(iset->is_running_flag)) {
		iset->state->bb_addr = il_bb->bb_addr;
		iset->state->bb_size = il_bb->size;
		// Evaluate the effect on the input state.
		if (!plugin->eval(iset, il_bb, plugin_data)) {
			RZ_LOG_DEBUG("Eval failed\n");
			goto in_loop_error;
		}
		out_hash = plugin->hash_state(iset->state, plugin_data);
#if RZ_BUILD_DEBUG
		RZ_LOG_DEBUG("in_hash = 0x%llx, out_hash = 0x%llx\n", in_hash, out_hash);
#endif

		// Add output state hash to the reachable states and
		// set a flag if it was a new state.
		size_t psize = rz_set_u_size(reachable_states);
		rz_set_u_add(reachable_states, out_hash);
		bool new_state_reached = psize < rz_set_u_size(reachable_states);

		// Determine the successor effects to evaluate.
		// Only newly reached states are allowed to add successors.
		if (!(new_state_reached && choose_next_pc(iset, out_hash, tmp_succ_addr, succ_states, il_bb, plugin_data))) {
			// No new state or address means we can stop interpreting.
			// Note, that we can't use the queues as cancel condition because they
			// are asynchronous and checking them would introduces race conditions.
			// TODO: This doesn't work if the interpreter can produce multiple out states.
			break;
		}

		// Set effect and state for next evaluation.
		SuccessorState next = { 0 };
		rz_vector_pop_front(succ_states, &next);
#if RZ_BUILD_DEBUG
		in_hash = next.in_state_hash;
#endif
		if (!rz_th_queue_pop(iset->il_queue, false, (void **)&il_bb) || !il_bb) {
			// The il op lifting failed. Likely because the PC
			// pointed to an unmapped region.
			goto in_loop_error;
		}
		if (!plugin->set_pc(iset->state, next.addr, plugin_data)) {
			rz_warn_if_reached();
			// Some error occurred lifting this basic block. Or updating the PC.
			// Abort execution.
			goto in_loop_error;
		}
	}

loop_cleanup:
	rz_strbuf_free(state_str);
	rz_vector_free(tmp_succ_addr);
	rz_vector_free(succ_states);
	rz_set_u_free(reachable_states);
	iset->plugin->fini_state(iset->state, plugin_data);
	if (iset->plugin->fini) {
		iset->plugin->fini(plugin_data);
	}
	rz_atomic_bool_set(iset->is_running_flag, false);
	return success;

in_loop_error:
	RZ_LOG_DEBUG("in_loop_error\n");
	success = false;
	goto loop_cleanup;

pre_loop_error:
	RZ_LOG_DEBUG("pre_loop_error\n");
	success = false;
	goto loop_cleanup;

entry_assert_error:
	rz_atomic_bool_set(iset->is_running_flag, false);
	return false;
}
