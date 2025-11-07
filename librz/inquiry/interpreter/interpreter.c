// SPDX-FileCopyrightText: 2025 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file The API implementation for all analysis interpreters.
 */

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
	RZ_NONNULL RZ_OWN RzThreadQueue /*<RzInquiryILQueueElement *>*/ *il_queue,
	RZ_NONNULL RZ_OWN RzPVector /*<RzInterpreterYieldQueue *>*/ *yield_queues,
	RZ_NONNULL RZ_OWN RzAtomicBool *is_running_flag) {
	RzInterpreterQueueSet *set = RZ_NEW0(RzInterpreterQueueSet);
	if (!set) {
		rz_th_queue_free(addr_queue);
		rz_th_queue_free(il_queue);
		rz_pvector_free(yield_queues);
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
		rz_pvector_free(qset->yield_queues);
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

	RzILOpEffect *effect = rz_th_queue_pop(il_queue, false);
	RZ_LOG_WARN("INTERPRETER: Got IL op: %p\n", effect);
	rz_il_op_effect_free(effect);

	ut64 *a = RZ_NEW(ut64);
	*a = 0x08000080ul;
	rz_th_queue_push(addr_queue, a, true);
	RZ_LOG_WARN("INTERPRETER: Requested: %" PRIx64 "\n", 0x08000080ul);

	effect = rz_th_queue_pop(il_queue, true);
	while (rz_atomic_bool_get(qset->is_running_flag) && !effect) {
		effect = rz_th_queue_pop(il_queue, true);
	}
	RZ_LOG_WARN("INTERPRETER: Got IL op: %p\n", effect);
	rz_il_op_effect_free(effect);

	rz_atomic_bool_set(qset->is_running_flag, false);
	return true;
}
