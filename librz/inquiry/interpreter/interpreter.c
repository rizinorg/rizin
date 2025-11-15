// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

#include <rz_core.h>
#include <rz_il/rz_il_opcodes.h>
#include <rz_inquiry/rz_interpreter.h>
#include <rz_th.h>
#include <rz_vector.h>
#include <rz_inquiry.h>

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
 * \brief Initializes a new RzInterpreterQueueSet and returns it.
 * If it fails, all arguments are freed.
 *
 * \param request_il The request queue.
 * \param receive_il The receive queue.
 * \param yield_queues The yield queues.
 */
RZ_API RZ_OWN RzInterpreterQueueSet *rz_interpreter_queue_set_new(
	RZ_NONNULL RZ_OWN RzThreadQueue /*<ut64>*/ *addr_queue,
	RZ_NONNULL RZ_OWN RzThreadQueue /*<const RzILOpEffect *>*/ *il_queue,
	RZ_NONNULL RZ_OWN HtUP /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag) {
	RzInterpreterQueueSet *set = RZ_NEW0(RzInterpreterQueueSet);
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

RZ_API void rz_interpreter_queue_set_free(RZ_NULLABLE RZ_OWN RzInterpreterQueueSet *qset) {
	if (!qset) {
		return;
	}
	if (qset->addr_queue) {
		rz_th_queue_free(qset->addr_queue);
	}
	if (qset->il_queue) {
		rz_th_queue_free(qset->il_queue);
	}
	if (qset->yield_queues) {
		ht_up_free(qset->yield_queues);
	}
	if (qset->is_running_flag) {
		rz_atomic_bool_free(qset->is_running_flag);
	}
	free(qset);
}

/**
 * \brief Runs a set of interpreters to inquire the requested yield.
 * What interpreters are spawned depend on the queues in \p yield_queues.
 */
RZ_API bool rz_interpreter_run(RZ_OWN RzInterpreterQueueSet *qset) {
	RZ_LOG_WARN("INTERPRETER: Hello.\n");
	RzThreadQueue *il_queue = qset->il_queue;
	RzThreadQueue *addr_queue = qset->addr_queue;

	// The effect is owned by the cache. So it is constant.
	const RzILOpEffect *effect = rz_th_queue_pop(il_queue, false);
	RZ_LOG_WARN("INTERPRETER: Got IL op: %p\n", effect);

	ut64 *a = RZ_NEW(ut64);
	*a = 0x08000080ul;
	rz_th_queue_push(addr_queue, a, true);
	RZ_LOG_WARN("INTERPRETER: Requested: %" PRIx64 "\n", 0x08000080ul);

	effect = rz_th_queue_pop(il_queue, true);
	while (rz_atomic_bool_get(qset->is_running_flag) && !effect) {
		effect = rz_th_queue_pop(il_queue, true);
	}
	RZ_LOG_WARN("INTERPRETER: Got IL op: %p\n", effect);

	rz_atomic_bool_set(qset->is_running_flag, false);
	return true;
}

/**
 * A function to call the prototype interpreter.
 * Usually these tasks will be split between different caches and yield consumers.
 */
RZ_API bool rz_inquiry_interpreter(RzCore *core, int argc, const char **argv) {
	// The pseudo cache of IL effects.
	// This is only a vector so we can simulate the ownership separation
	// of the pointers.
	RzPVector *il_cache = rz_pvector_new((RzPVectorFree)rz_il_op_effect_free);
	// The queue to pass the Effects to the interpreter.
	// This is only one queue for the prototype.
	// In practice it would be one for each interpreter.
	RzThreadQueue *il_queue = rz_th_queue_new(RZ_INTERPRETER_IL_QUEUE_SIZE, NULL);
	if (!il_queue) {
		return false;
	}

	// Add the Effect for each entry point.
	RzILOpEffect *eff = NULL;
	if (argc == 1) {
		ut64 entry_point = rz_bin_get_first_entrypoint(core->bin->cur->o);
		eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
		if (!eff) {
			rz_th_queue_free(il_queue);
			RZ_LOG_WARN("Could not get entry point IL operation at 0x%" PFMT64x "\n", (ut64)entry_point);
			return false;
		}
		rz_th_queue_push(il_queue, eff, true);
		rz_pvector_push(il_cache, eff);
	} else {
		// Add all entry points given as arguments.
		for (size_t i = 1; i < argc; i++) {
			ut64 entry_point = rz_num_get(core->num, argv[i]);
			eff = rz_inquiry_gen_il_bb(core->analysis, core->io, entry_point);
			if (!eff) {
				rz_th_queue_free(il_queue);
				return false;
			}
		}
		rz_th_queue_push(il_queue, eff, true);
		rz_pvector_push(il_cache, eff);
	}

	// The address queue. It is the queue the interpreter can request new Effects.
	// Of course, currently there is only a single one for the prototype.
	// In practice there would be one for each interpreter instance.
	RzThreadQueue *addr_queue = rz_th_queue_new(RZ_INTERPRETER_ADDR_QUEUE_SIZE, (RzListFree)rz_interpreter_addr_queue_free);
	if (!addr_queue) {
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		return false;
	}

	// Here we build the filter for the yield queue.
	// The prototype generates constant xrefs.
	// So the filter checks the generated xrefs, if they are within the IO map
	// boundaries.
	RzInterval iv = { .addr = 0, .size = UT64_MAX };
	RzList *boundaries = rz_io_get_boundaries_all_io_maps(core->io, iv);
	if (!boundaries) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		return false;
	}

	// Now create a set of yield queue(s).
	// These yield queues can be shared between different interpreters.
	// So we have one yield queue for each yield type.
	RzInterpreterYieldKind yield_kind = RZ_INTERPRETER_YIELD_KIND_XREF;
	RzInterpreterYieldQueue *yield_queue = rz_interpreter_yield_queue_new(
		yield_kind,
		(RzInterpreterYieldFilter *)rz_inquiry_xref_interpreter_filter,
		boundaries);
	if (!yield_queue) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		return false;
	}

	// Multiple yield queus can be used by a single interpreter.
	// E.g. if the interpreter has a complex abstract memory model
	// for stack, heap and constant values.
	// Then it can produce three kind of yields.
	HtUP *yield_queues = ht_up_new(NULL, (HtUPFreeValue)rz_interpreter_yield_queue_free);
	if (!yield_queue || !yield_queues) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		rz_interpreter_yield_queue_free(yield_queue);
		ht_up_free(yield_queues);
		return false;
	}
	ht_up_insert(yield_queues, yield_kind, yield_queue);
	// Create the running flag.
	RzAtomicBool *is_running = rz_atomic_bool_new(true);

	// Bundle all the queues into one object to pass it to the thread.
	// Later we would pass a unique qset to each interpreter with
	// the required queues only.
	// But for the prototype we have only one qset with all queues.
	RzInterpreterQueueSet *qset = rz_interpreter_queue_set_new(addr_queue, il_queue, yield_queues, is_running);
	if (!qset) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(il_cache);
		rz_interpreter_yield_queue_free(yield_queue);
		ht_up_free(yield_queues);
		rz_atomic_bool_free(is_running);
		return false;
	}

	// Dispatch prototype interpreter into a thread.
	// This part plays the role of the cache now.
	// Waiting for new Effects to be requested and sending them.
	RZ_LOG_WARN("INQUIRY: Start thread.\n");
	RzThread *iterpr_th = rz_th_new((RzThreadFunction)rz_interpreter_run, qset);
	RZ_LOG_WARN("INQUIRY: Start loop.\n");
	while (rz_atomic_bool_get(is_running)) {
		ut64 *addr = rz_th_queue_pop(addr_queue, false);
		if (!addr) {
			// Some artifical lag for testing.
			rz_sys_sleep(1);
			RZ_LOG_WARN("INQUIRY: Sleep over.\n");
			continue;
		}
		RZ_LOG_WARN("INQUIRY: Received %" PFMT64x ".\n", (*addr));
		RzILOpEffect *bb = rz_inquiry_gen_il_bb(core->analysis, core->io, *addr);
		free(addr);
		if (!bb) {
			// Stop interpreter.
			rz_atomic_bool_set(is_running, false);
			continue;
		}
		RZ_LOG_WARN("INQUIRY: Send %p.\n", bb);
		rz_pvector_push(il_cache, bb);
		rz_th_queue_push(il_queue, bb, true);
	}
	// Wait for thread to finish before cleaning.
	rz_th_wait(iterpr_th);
	rz_th_free(iterpr_th);
	rz_interpreter_queue_set_free(qset);
	// Empty pseudo-cache.
	rz_pvector_free(il_cache);

	return true;
}
