// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

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

RZ_API void rz_interpreter_il_bb_free(RZ_NULLABLE RZ_OWN RzInterpreterILBB *il_op) {
	if (!il_op) {
		return;
	}
	rz_pvector_free(il_op);
}

RZ_API void rz_interpreter_yield_queue_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldQueue *yield_queue) {
	if (!yield_queue) {
		return;
	}
	if (yield_queue->yield_queue) {
		rz_th_queue_free(yield_queue->yield_queue);
	}
	if (yield_queue->filter_data && yield_queue->filter_data->io_boundaries) {
		rz_list_free(yield_queue->filter_data->io_boundaries);
	}
	free(yield_queue->filter_data);
	free(yield_queue);
}

RZ_API RZ_OWN RzInterpreterYieldQueue *rz_interpreter_yield_queue_new(RzInterpreterYieldKind kind,
	RzInterpreterYieldFilter filter,
	RZ_OWN RZ_NULLABLE void *filter_data_io_boundaries) {
	RzInterpreterYieldQueue *yield_queue = RZ_NEW0(RzInterpreterYieldQueue);
	if (!yield_queue) {
		return NULL;
	}
	RzThreadQueue *queue = NULL;
	switch (kind) {
	case RZ_INTERPRETER_YIELD_KIND_XREF:
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
	yield_queue->filter_data = RZ_NEW0(RzInterpreterYieldFilterData);
	if (filter_data_io_boundaries) {
		yield_queue->filter_data->io_boundaries = filter_data_io_boundaries;
	}
	return yield_queue;
}

/**
 * \brief Initializes an abstract state for specified abstract kinds. Optionally with a list of registers.
 * The register name list should always be given if the architecture has some.
 */
RZ_API RZ_OWN RzInterpreterAbstrState *rz_interpreter_abstr_state_new(
	RzInterpreterAbstraction kinds,
	RZ_NULLABLE const RzPVector *reg_names,
	size_t addr_bits) {
	RzInterpreterAbstrState *state = RZ_NEW0(RzInterpreterAbstrState);
	if (!state) {
		return NULL;
	}
	state->kinds = kinds;
	if (!reg_names) {
		return state;
	}
	state->pc = RZ_NEW0(RzInterpreterAbstrVal);
	if (!state->pc) {
		return NULL;
	}
	// Initialize the register file with uninitialized abstract values.
	state->globals = ht_up_new(NULL, free);
	void **it;
	rz_pvector_foreach (reg_names, it) {
		const char *rname = *it;
		RzInterpreterAbstrVal *aval = RZ_NEW0(RzInterpreterAbstrVal);
		if (!aval) {
			ht_up_free(state->globals);
			free(state);
			return NULL;
		}

		aval->kind = RZ_INTERPRETER_ABSTRACTION_UNDEF;
		ut64 djb2_reg_hash = rz_str_djb2_hash(rname);
		if (!ht_up_insert(state->globals, djb2_reg_hash, aval)) {
			RZ_LOG_ERROR("Failed to add %s to the global variable map. "
				     "DJB2 hash collision of the register name. DJB2 hash = 0x%" PFMT64x "\n",
				rname, djb2_reg_hash);
			return NULL;
		}
	}
	state->locals = ht_up_new(NULL, free);
	state->lets = ht_up_new(NULL, free);
	state->addr_bits = addr_bits;
	return state;
}

RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpreterAbstrState *state) {
	if (!state) {
		return;
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
	free(state);
}

RZ_API void rz_interpreter_set_free(RZ_OWN RZ_NULLABLE RzInterpreterSet *iset) {
	if (!iset) {
		return;
	}
	if (iset->addr_queue) {
		rz_th_queue_free(iset->addr_queue);
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

/**
 * \brief Initializes a new RzInterpreterSet and returns it.
 * If it fails, all arguments are freed.
 *
 * \param plugin The interpreter plugin.
 * \param request_il The request queue.
 * \param receive_il The receive queue.
 * \param yield_queues The yield queues.
 */
RZ_API RZ_OWN RzInterpreterSet *rz_interpreter_set_new(
	RZ_NONNULL RZ_OWN RzInterpreterPlugin *plugin,
	RZ_NONNULL RZ_OWN RzInterpreterAbstrState *state,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const ut64>*/ *addr_queue,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue,
	RZ_NONNULL RZ_OWN HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzInterpreterIORequest *>*/ *io_request,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzInterpreterIOResult *>*/ *io_result,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag,
	RZ_NONNULL RZ_OWN RzVector /*<ut64>*/ *entry_points) {
	rz_return_val_if_fail(plugin && state && addr_queue && il_queue && yield_queues && io_request && io_result && is_running_flag, NULL);

	RzInterpreterSet *set = RZ_NEW0(RzInterpreterSet);
	if (!set) {
		return false;
	}
	set->plugin = plugin;
	set->state = state;
	set->il_queue = il_queue;
	set->addr_queue = addr_queue;
	set->yield_queues = yield_queues;
	set->io_request = io_request;
	set->io_result = io_result;
	set->is_running_flag = is_running_flag;
	set->entry_points = entry_points;
	if (state->kinds != (plugin->supported_abstractions & state->kinds)) {
		RZ_LOG_ERROR("Abstract state doesn't fit to interpreter.\n");
		rz_interpreter_set_free(set);
		return NULL;
	}
	return set;
}

typedef struct {
	ut64 addr;
	ut64 in_state_hash;
} SuccessorState;

/**
 * Main interpretation.
 */
RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_OWN RzInterpreterSet *iset) {
	rz_goto_if_fail(iset &&
			iset->state &&
			iset->addr_queue &&
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
	bool success = false;

	RZ_LOG_WARN("INTERPRETER Main: Hello.\n");
	RzInterpreterPlugin *plugin = iset->plugin;

	void **priv_ptr = NULL;
	if (iset->plugin->init) {
		iset->plugin->init(priv_ptr);
	}
	void *plugin_data = priv_ptr ? *priv_ptr : NULL;

	//
	// Start interpretation
	//

	// A vector for the plugin to push the determined successors into.
	RzVector *tmp_succ_addr = NULL;
	// The set of reachable states.
	RzSetU *reachable_states = NULL;
	// The successor states to evaluate.
	// This vector must have the same order as the elements pushed into addr_queue.
	RzVector *succ_states = NULL;

	ut64 entry_point;
	rz_vector_pop_front(iset->entry_points, &entry_point);
	if (!plugin->init_state(iset->state, entry_point, plugin_data)) {
		goto pre_loop_error;
	}
	RzInterpreterAbstrState *in_state = iset->state;
	ut64 in_hash = plugin->hash_state(in_state, plugin_data);
	RzInterpreterAbstrState *out_state = NULL;
	ut64 out_hash = 0;

	const RzInterpreterILBB *il_bb = rz_th_queue_pop(iset->il_queue, false);
	// TODO: Add support for multiple entry points by spawning an interpreter for each of them.
	// For now let's just drop them.
	RzList *additional_entries = rz_th_queue_pop_all(iset->il_queue);
	if (rz_list_length(additional_entries) > 0) {
		RZ_LOG_WARN("More than one entry point is not yet supported by the prototype.\n");
	}
	rz_list_free(additional_entries);

	tmp_succ_addr = rz_vector_new(sizeof(ut64), NULL, NULL);
	succ_states = rz_vector_new(sizeof(SuccessorState), NULL, NULL);
	reachable_states = rz_set_u_new();
	if (!tmp_succ_addr || !succ_states || !il_bb || !reachable_states) {
		goto pre_loop_error;
	}
	ut64 _addr = 0;
	ut64 *addr = &_addr;

	while (rz_atomic_bool_get(iset->is_running_flag)) {
		// Evaluate the effect on the input state.
		if (!plugin->eval(in_state, il_bb, iset->yield_queues, iset->io_request, iset->io_result, plugin_data)) {
			goto in_loop_error;
		}
		// The input state was (almost always) manipulated by eval(). Rename to clarify.
		out_state = in_state;
		out_hash = plugin->hash_state(out_state, plugin_data);
		printf("in_hash = 0x%llx, out_hash = 0x%llx\n", in_hash, out_hash);

		// Add out_state hash to the reachable states and
		// set a flag if it was a new state.
		size_t psize = rz_set_u_size(reachable_states);
		rz_set_u_add(reachable_states, out_hash);
		bool new_state_reached = psize < rz_set_u_size(reachable_states);

		// Determine the successor effects to evaluate.
		// Only newly reached states are allowed to add successors.
		if (new_state_reached) {
			// Determine successors and increase the reference counts for the current out state.
			if (!plugin->successors(out_state, tmp_succ_addr, plugin_data)) {
				goto in_loop_error;
			}
			// It is possible that the successor function doesn't add successors.
			// E.g. because the PC is an abstract value.
			// In this case the state counts as invalid.
			new_state_reached = !rz_vector_empty(tmp_succ_addr);
			// Request the successor effects over the queue.
			while (!rz_vector_empty(tmp_succ_addr)) {
				rz_vector_pop_front(tmp_succ_addr, addr);
				SuccessorState ss = { .addr = *addr, .in_state_hash = out_hash };
				// The successors are pushed in the same order into the succ_states
				// vector, as they are requested over the addr_queue.
				rz_vector_push(succ_states, &ss);
				rz_th_queue_push(iset->addr_queue, addr, true);
			}
		}

		if (!new_state_reached) {
			// No new state, means we can stop interpreting.
			// Note, that we can't use the queues as cancel condition because they
			// are asynchronous and checking them would introduces race conditions.
			// TODO: This doesn't work if the interpreter can produce multiple out states.
			break;
		}

		// Set effect and state for next evaluation.
		SuccessorState next = { 0 };
		rz_vector_pop_front(succ_states, &next);
		in_hash = next.in_state_hash;
		il_bb = rz_th_queue_wait_pop(iset->il_queue, false);
		if (!il_bb || !plugin->set_pc(in_state, next.addr, plugin_data)) {
			// Some error occurred lifting this basic block. Or updating the PC.
			// Abort execution.
			goto in_loop_error;
		}
	}

loop_cleanup:
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
	success = false;
	goto loop_cleanup;

pre_loop_error:
	success = false;
	goto loop_cleanup;

entry_assert_error:
	rz_atomic_bool_set(iset->is_running_flag, false);
	return false;
}
