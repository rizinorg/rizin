// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include "rz_util/ht_up.h"
#include "rz_util/rz_assert.h"
#include "rz_util/rz_set.h"
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_types.h>
#include <rz_vector.h>
#include <rz_util.h>

RZ_API void rz_interpreter_il_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<RzILOpEffect *>*/ *q) {
	if (!q) {
		return;
	}
	RzILOpEffect *eff = rz_th_queue_pop(q, false);
	while (eff) {
		rz_il_op_effect_free(eff);
		eff = rz_th_queue_pop(q, false);
	}
}

RZ_API void rz_interpreter_addr_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<ut64 *>*/ *q) {
	if (!q) {
		return;
	}
	ut64 *addr = rz_th_queue_pop(q, false);
	while (addr) {
		free(addr);
		addr = rz_th_queue_pop(q, false);
	}
}

static void const_yield_queue_free(RZ_OWN RZ_NULLABLE RzThreadQueue /*<RzInterpreterYield *>*/ *q) {
	if (!q) {
		return;
	}
	RzInterpreterYield *yield = rz_th_queue_pop(q, false);
	while (yield) {
		free(yield->abstr_const);
		yield = rz_th_queue_pop(q, false);
	}
}

RZ_API void rz_interpreter_yield_queue_free(RZ_OWN RZ_NULLABLE RzInterpreterYieldQueue *yield_queue) {
	if (!yield_queue) {
		return;
	}
	if (yield_queue->yield_queue) {
		rz_th_queue_free(yield_queue->yield_queue);
	}
	switch (yield_queue->kind) {
	default:
		break;
	case RZ_INTERPRETER_YIELD_KIND_XREF:
		// Free the RzIOMap list.
		rz_list_free(yield_queue->filter_data.io_boundaries);
		break;
	}
	free(yield_queue);
}

RZ_API RZ_OWN RzInterpreterYieldQueue *rz_interpreter_yield_queue_new(RzInterpreterYieldKind kind,
	const RzInterpreterYieldFilter *filter,
	RZ_OWN RZ_NULLABLE void *filter_data) {
	RzInterpreterYieldQueue *yield_queue = RZ_NEW0(RzInterpreterYieldQueue);
	if (!yield_queue) {
		return NULL;
	}
	RzThreadQueue *queue = NULL;
	switch (kind) {
	case RZ_INTERPRETER_YIELD_KIND_XREF:
		queue = rz_th_queue_new(RZ_INTERPRETER_YIELD_QUEUE_SIZE, (RzListFree)const_yield_queue_free);
		break;
	}
	if (!queue) {
		free(yield_queue);
		return NULL;
	}
	yield_queue->kind = kind;
	yield_queue->yield_queue = queue;
	yield_queue->filter = filter;
	// TODO Doesn't look good. Void pointers are not nice.
	switch (kind) {
	default:
		rz_return_val_if_fail(!filter_data, NULL);
		break;
	case RZ_INTERPRETER_YIELD_KIND_XREF:
		yield_queue->filter_data.io_boundaries = filter_data;
		break;
	}
	return yield_queue;
}

/**
 * \brief Initializes an abstract state for specified abstract kinds. Optionally with a list of registers.
 * The register name list should always be given if the architecture has some.
 */
RZ_API RZ_OWN RzInterpreterAbstrState *rz_interpreter_abstr_state_new(RzInterpreterAbstraction kinds, RZ_NULLABLE const RzPVector *reg_names) {
	RzInterpreterAbstrState *state = RZ_NEW0(RzInterpreterAbstrState);
	if (!state) {
		return NULL;
	}
	state->kinds = kinds;
	if (!reg_names) {
		return state;
	}
	// Initialize the register file with uninitialized abstract values.
	state->reg_file = ht_sp_new(HT_STR_DUP, NULL, free);
	void **it;
	rz_pvector_foreach (reg_names, it) {
		const char *rname = *it;
		RzInterpreterAbstrVal *aval = RZ_NEW0(RzInterpreterAbstrVal);
		if (!aval) {
			ht_sp_free(state->reg_file);
			free(state);
			return NULL;
		}

		aval->kind = RZ_INTERPRETER_ABSTRACTION_UNDEF;
		ht_sp_insert(state->reg_file, rname, aval);
	}
	return state;
}

RZ_API void rz_interpreter_abstr_state_free(RZ_OWN RZ_NULLABLE RzInterpreterAbstrState *state) {
	if (!state) {
		return;
	}
	if (state->reg_file) {
		ht_sp_free(state->reg_file);
	}
	free(state);
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
	RZ_NONNULL RZ_OWN RzThreadQueue /*<ut64>*/ *addr_queue,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue,
	RZ_NONNULL RZ_OWN HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag) {
	rz_return_val_if_fail(plugin && state && plugin && addr_queue && il_queue && yield_queues, NULL);

	RzInterpreterSet *set = RZ_NEW0(RzInterpreterSet);
	if (!set || (state->kinds != (plugin->supported_abstractions & state->kinds))) {
		if ((state->kinds != (plugin->supported_abstractions & state->kinds))) {
			RZ_LOG_ERROR("Abstract state doesn't fit to interpreter.\n");
		}
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running_flag);
		return NULL;
	}
	set->state = state;
	set->il_queue = il_queue;
	set->addr_queue = addr_queue;
	set->yield_queues = yield_queues;
	set->is_running_flag = is_running_flag;
	return set;
}

RZ_API void rz_interpreter_queue_set_free(RZ_NULLABLE RZ_OWN RzInterpreterSet *iset) {
	if (!iset) {
		return;
	}
	if (iset->state) {
		rz_interpreter_abstr_state_free(iset->state);
	}
	if (iset->addr_queue) {
		rz_th_queue_free(iset->addr_queue);
	}
	if (iset->il_queue) {
		rz_th_queue_free(iset->il_queue);
	}
	if (iset->yield_queues) {
		ht_up_free(iset->yield_queues);
	}
	if (iset->is_running_flag) {
		rz_atomic_bool_free(iset->is_running_flag);
	}
	free(iset);
}

/**
 * Main interpretation.
 */
RZ_API bool rz_interpreter_run(RZ_NONNULL RZ_BORROW RzInterpreterSet *iset) {
	rz_return_val_if_fail(iset &&
			iset->addr_queue &&
			iset->il_queue &&
			iset->yield_queues &&
			iset->is_running_flag &&
			iset->plugin &&
			iset->plugin->init_state &&
			iset->plugin->eval &&
			iset->plugin->hash_state,
		false);
	bool success = false;

	RZ_LOG_WARN("INTERPRETER Main: Hello.\n");
	RzInterpreterPlugin *plugin = iset->plugin;

	void **priv_ptr = NULL;
	if (iset->plugin->init) {
		iset->plugin->init(priv_ptr);
	}
	void *plugin_data = priv_ptr ? *priv_ptr : NULL;

	plugin->init_state(iset->state, plugin_data);

	HtUP *state_map = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_abstr_state_free);


	RzSetU *reachable_states = rz_set_u_new();
	if (!reachable_states) {
		rz_warn_if_reached();
		goto error;
	}
	ut64 n_states = 0;
	ut64 prev_n_states = 0;
	while (true) {
		const RzILOpEffect *eff = rz_th_queue_wait_pop(iset->il_queue, false);
		if (!eff) {
			rz_warn_if_reached();
			goto error;
		}

		RzInterpreterAbstrState *state = ht_up_find(state_map, plugin->hash_state(state, plugin_data), NULL);
		if (!state || !plugin->eval(state, eff, iset->yield_queues, plugin_data)) {
			RZ_LOG_ERROR("Interpreter failed to evaluate an effect or state was NULL. Abort.\n");
			RZ_LOG_ERROR("n_states = %" PFMT64d ".\n", n_states);
			goto error;
		}

		rz_set_u_add(reachable_states, plugin->hash_state(state, plugin_data));
		n_states = rz_set_u_size(reachable_states);
		bool reached_new_state = n_states > prev_n_states;
		prev_n_states = n_states;

		if (rz_th_queue_size(iset->il_queue) == 0) {
			// No effect left to evaluate.
			break;
		}
		if (reached_new_state) {
			// Only new states are allowed to add to the request queue.
			// Otherwise we might loop indefinitely.
			size_t prev_addr_size = rz_th_queue_size(iset->addr_queue);
			if (!plugin->successors(state, iset->addr_queue, plugin_data)) {
				RZ_LOG_ERROR("Error during PC concretization. Abort.\n");
				goto error;
			}
		}
	}
	// while true {
	//    get new PCs
	//    request effects
	//    push effects
	// }

error:
	rz_atomic_bool_set(iset->is_running_flag, false);
	if (iset->plugin->fini) {
		iset->plugin->fini(plugin_data);
	}
	return success;
}
