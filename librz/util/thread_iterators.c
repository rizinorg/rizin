// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file thread_iterators.c
 * These are threaded iterators, which allows to iterate
 * all the elements of a list/pvector/etc..
 */

#include <rz_th.h>
#include <rz_util.h>

typedef struct th_list {
	RzThreadQueue *queue;
	const void *user;
	RzThreadIterator iterator;
} th_list_t;

static void *thread_iterate_list_cb(th_list_t *shared) {
	void *element = NULL;
	const void *user = shared->user;
	RzThreadQueue *queue = shared->queue;
	RzThreadIterator iterator = shared->iterator;

	while ((element = rz_th_queue_pop(queue, false))) {
		iterator(element, user);
	}
	return NULL;
}

static bool th_run_iterator(RzThreadQueue *queue, RzThreadIterator iterator, size_t max_threads, const void *user) {
	if (rz_th_queue_is_empty(queue)) {
		// nothing to do, but return true
		return true;
	}

	RzThreadPool *pool = rz_th_pool_new(max_threads);
	if (!pool) {
		RZ_LOG_ERROR("th: failed to allocate memory for threaded iteration\n");
		return false;
	}

	th_list_t shared = {
		.user = user,
		.queue = queue,
		.iterator = iterator,
	};

	ut32 pool_size = rz_th_pool_size(pool);
	RZ_LOG_VERBOSE("th: using %u threads for threaded iteration\n", pool_size);
	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_new((RzThreadFunction)thread_iterate_list_cb, &shared);
		rz_th_pool_add_thread(pool, th);
	}

	rz_th_pool_wait(pool);
	rz_th_pool_free(pool);
	return true;
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
RZ_API bool rz_th_iterate_list(RZ_NONNULL const RzList /*<void *>*/ *list, RZ_NONNULL RzThreadIterator iterator, size_t max_threads, RZ_NULLABLE const void *user) {
	rz_return_val_if_fail(list && iterator, false);
	if (rz_list_length(list) < 1) {
		// nothing to do, but return true
		return true;
	}

	RzThreadQueue *queue = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	if (!queue) {
		RZ_LOG_ERROR("th: failed to allocate memory for threaded iteration\n");
		return false;
	}

	void *ptr = NULL;
	RzListIter *it = NULL;
	rz_list_foreach (list, it, ptr) {
		if (!ptr) {
			continue;
		}
		rz_th_queue_push(queue, ptr, true);
	}

	bool retval = th_run_iterator(queue, iterator, max_threads, user);
	rz_th_queue_free(queue);
	return retval;
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
RZ_API bool rz_th_iterate_pvector(RZ_NONNULL const RzPVector *pvec, RZ_NONNULL RzThreadIterator iterator, size_t max_threads, RZ_NULLABLE const void *user) {
	rz_return_val_if_fail(pvec && iterator, false);
	if (rz_pvector_len(pvec) < 1) {
		// nothing to do, but return true
		return true;
	}

	RzThreadQueue *queue = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	if (!queue) {
		RZ_LOG_ERROR("th: failed to allocate memory for threaded iteration\n");
		return false;
	}

	void **it = NULL;
	rz_pvector_foreach (pvec, it) {
		if (!*it) {
			continue;
		}
		rz_th_queue_push(queue, *it, true);
	}

	bool retval = th_run_iterator(queue, iterator, max_threads, user);
	rz_th_queue_free(queue);
	return retval;
}
