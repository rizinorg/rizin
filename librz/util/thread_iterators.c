// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file thread_iterators.c
 * These are threaded iterators, which allows to iterate
 * all the elements of a list/pvector/etc..
 */

#include <rz_th.h>
#include <rz_util.h>

static bool th_run_iterator(RzThreadFunction th_cb, void *context, size_t max_threads) {
	RzThreadPool *pool = rz_th_pool_new(max_threads);
	if (!pool) {
		RZ_LOG_ERROR("th: failed to allocate thread pool\n");
		return false;
	}

	ut32 pool_size = rz_th_pool_size(pool);
	RZ_LOG_VERBOSE("th: using %u threads for threaded iteration\n", pool_size);
	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_new(th_cb, context);
		rz_th_pool_add_thread(pool, th);
	}

	rz_th_pool_wait(pool);
	rz_th_pool_free(pool);
	return true;
}

typedef struct th_list_ctx_s {
	RzThreadLock *lock;
	RzListIter /*<void *>*/ *head;
	void *user;
	RzThreadIterator iterator;
} th_list_ctx_t;

static void *thread_iterate_list_cb(th_list_ctx_t *context) {
	void *element = NULL;
	void *user = context->user;
	RzThreadIterator iterator = context->iterator;
	RzThreadLock *lock = context->lock;

	do {
		rz_th_lock_enter(lock);
		if (!context->head) {
			rz_th_lock_leave(lock);
			break;
		}
		element = rz_list_iter_get_data(context->head);
		context->head = rz_list_iter_get_next(context->head);
		rz_th_lock_leave(lock);

		if (element) {
			iterator(element, user);
		}
	} while (true);
	return NULL;
}

/**
 * \brief      This helper iterates over a list in parallel.
 * This iterator is useful for tasks where you need to modify each entry
 *
 * \param[in]  list         The list to iterate
 * \param[in]  iterator     The iterator to use
 * \param[in]  max_threads  The maximum number of threads
 * \param      user         A user pointer
 *
 * \return     On error returns false, otherwise true.
 */
RZ_API bool rz_th_iterate_list(RZ_NONNULL const RzList /*<void *>*/ *list, RZ_NONNULL RzThreadIterator iterator, size_t max_threads, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(list && iterator, false);
	if (rz_list_length(list) < 1) {
		// nothing to do, but return true
		return true;
	}

	th_list_ctx_t context = {
		.lock = rz_th_lock_new(true),
		.head = list->head,
		.iterator = iterator,
		.user = user,
	};

	if (!context.lock) {
		RZ_LOG_ERROR("th: failed to allocate list lock\n");
		return false;
	}

	bool retval = th_run_iterator((RzThreadFunction)thread_iterate_list_cb, &context, max_threads);
	rz_th_lock_free(context.lock);
	return retval;
}

typedef struct th_vec_ctx_s {
	RzThreadLock *lock;
	size_t index;
	const RzPVector /*<void *>*/ *pvec;
	void *user;
	RzThreadIterator iterator;
} th_vec_ctx_t;

static void *thread_iterate_pvec_cb(th_vec_ctx_t *context) {
	void *element = NULL;
	void *user = context->user;
	RzThreadIterator iterator = context->iterator;
	RzThreadLock *lock = context->lock;
	const RzPVector *pvec = context->pvec;
	size_t length = rz_pvector_len(pvec);

	do {
		rz_th_lock_enter(lock);
		if (context->index >= length) {
			rz_th_lock_leave(lock);
			break;
		}
		element = rz_pvector_at(pvec, context->index);
		context->index++;
		rz_th_lock_leave(lock);

		if (element) {
			iterator(element, user);
		}
	} while (true);
	return NULL;
}

/**
 * \brief      This helper iterates over a PVector in parallel.
 * This iterator is useful for tasks where you need to modify each entry
 *
 * \param[in]  pvec         The vector to iterate
 * \param[in]  iterator     The iterator to use
 * \param[in]  max_threads  The maximum number of threads
 * \param      user         A user pointer
 *
 * \return     On error returns false, otherwise true.
 */
RZ_API bool rz_th_iterate_pvector(RZ_NONNULL const RzPVector /*<void *>*/ *pvec, RZ_NONNULL RzThreadIterator iterator, size_t max_threads, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(pvec && iterator, false);
	if (rz_pvector_len(pvec) < 1) {
		// nothing to do, but return true
		return true;
	}

	th_vec_ctx_t context = {
		.lock = rz_th_lock_new(true),
		.index = 0,
		.pvec = pvec,
		.iterator = iterator,
		.user = user,
	};

	if (!context.lock) {
		RZ_LOG_ERROR("th: failed to allocate vector lock\n");
		return false;
	}

	bool retval = th_run_iterator((RzThreadFunction)thread_iterate_pvec_cb, &context, max_threads);
	rz_th_lock_free(context.lock);
	return retval;
}
