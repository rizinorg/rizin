// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

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
RZ_API bool rz_th_iterate_list(RZ_NONNULL const RzList *list, RZ_NONNULL RzThreadIterator iterator, size_t max_threads, RZ_NULLABLE const void *user) {
	rz_return_val_if_fail(list && iterator, false);

	bool retval = true;
	void *ptr = NULL;
	RzListIter *it = NULL;
	RzThreadPool *pool = NULL;
	RzThreadQueue *queue = NULL;

	pool = rz_th_pool_new(max_threads);
	queue = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	if (!queue || !pool) {
		RZ_LOG_ERROR("th: failed to allocate memory for threaded iteration\n");
		retval = false;
		goto fail;
	}

	rz_list_foreach (list, it, ptr) {
		if (!ptr) {
			continue;
		}
		rz_th_queue_push(queue, ptr, true);
	}

	if (rz_th_queue_is_empty(queue)) {
		// nothing to do, but return true
		goto fail;
	}

	ut32 pool_size = rz_th_pool_size(pool);
	RZ_LOG_VERBOSE("th: using %u threads for threaded iteration\n", pool_size);

	th_list_t shared = {
		.user = user,
		.queue = queue,
		.iterator = iterator,
	};
	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_new((RzThreadFunction)thread_iterate_list_cb, &shared);
		if (th) {
			rz_th_pool_add_thread(pool, th);
		}
	}

	rz_th_pool_wait(pool);

fail:
	rz_th_queue_free(queue);
	rz_th_pool_free(pool);
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

	bool retval = true;
	void **it = NULL;
	RzThreadPool *pool = NULL;
	RzThreadQueue *queue = NULL;

	pool = rz_th_pool_new(max_threads);
	queue = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, NULL);
	if (!queue || !pool) {
		RZ_LOG_ERROR("th: failed to allocate memory for threaded iteration\n");
		retval = false;
		goto fail;
	}

	rz_pvector_foreach (pvec, it) {
		if (!*it) {
			continue;
		}
		rz_th_queue_push(queue, *it, true);
	}

	if (rz_th_queue_is_empty(queue)) {
		// nothing to do, but return true
		goto fail;
	}

	ut32 pool_size = rz_th_pool_size(pool);
	RZ_LOG_VERBOSE("th: using %u threads for threaded iteration\n", pool_size);

	th_list_t shared = {
		.user = user,
		.queue = queue,
		.iterator = iterator,
	};
	for (ut32 i = 0; i < pool_size; ++i) {
		RzThread *th = rz_th_new((RzThreadFunction)thread_iterate_list_cb, &shared);
		if (th) {
			rz_th_pool_add_thread(pool, th);
		}
	}

	rz_th_pool_wait(pool);

fail:
	rz_th_queue_free(queue);
	rz_th_pool_free(pool);
	return retval;
}
