// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_vector.h>

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
	RZ_NONNULL RZ_OWN RzThreadQueue /*<ut64>*/ *addr_queue,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue,
	RZ_NONNULL RZ_OWN HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag) {
	RzInterpreterSet *set = RZ_NEW0(RzInterpreterSet);
	if (!set) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running_flag);
		return NULL;
	}
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
 * \brief Runs the interpretation with a single interpreter plugin.
 */
static bool perform_interpretation(RzInterpreterPlugin *plugin, RZ_BORROW RzInterpreterSet *iset) {
	RzThreadQueue *il_queue = iset->il_queue;
	RzThreadQueue *addr_queue = iset->addr_queue;

	// The effect is owned by the cache. So it is constant.
	const RzILOpEffect *effect = rz_th_queue_pop(il_queue, false);
	RZ_LOG_WARN("INTERPRETER Instance: Got IL op: %p\n", effect);
	if (effect) {
		// No entry point given.
		RZ_LOG_WARN("INTERPRETER Instance: No entry point.\n");
		return false;
	}
	return true;
}

/**
 * Main thread of the interpretation.
 */
RZ_API bool rz_interpreter_run(RZ_BORROW RzInterpreterSet *iset) {
	RZ_LOG_WARN("INTERPRETER Main: Hello.\n");
	// This can be the place to spawn multiple interpreters in threads.
	bool result = perform_interpretation(iset->plugin, iset);
	rz_atomic_bool_set(iset->is_running_flag, false);
	return result;
}
