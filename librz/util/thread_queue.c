// SPDX-FileCopyrightText: 2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include "thread.h"

/**
 * \brief RzThreadQueue is a thread-safe queue that can be listened on from multiple threads.
 *
 * This Queue is thread-safe and allows to perform LIFO/FIFO operations.
 * rz_th_queue_new      Allocates a RzThreadQueue structure and allows to limit the size of the queue.
 * rz_th_queue_push     Pushes an element to the queue unless the limit is reached.
 * rz_th_queue_pop      Pops an element from the queue, but returns NULL when is empty.
 * rz_th_queue_wait_pop Pops an element from the queue, but awaits for new elements when is empty.
 * rz_th_queue_free     Frees a RzThreadQueue structure, if the queue is not empty, it frees the elements with the provided qfree function.
 */
struct rz_th_queue_t {
	RzThreadLock *lock;
	RzThreadCond *cond;
	RzThreadQueueSize max_size;
	RzList /*<void *>*/ *list;
};

/**
 * \brief  Allocates and initializes a new fifo queue
 *
 * \param  max_size  The maximum size of the queue, use RZ_THREAD_QUEUE_UNLIMITED for an unlimited size
 * \param  qfree     Pointer to a custom free function to free the queue if not empty.
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_new(RzThreadQueueSize max_size, RZ_NULLABLE RzListFree qfree) {
	RzThreadQueue *queue = RZ_NEW0(RzThreadQueue);
	if (!queue) {
		return NULL;
	}

	queue->max_size = max_size;
	queue->list = rz_list_newf(qfree);
	queue->lock = rz_th_lock_new(false);
	queue->cond = rz_th_cond_new();
	if (!queue->list || !queue->lock || !queue->cond) {
		rz_th_queue_free(queue);
		return NULL;
	}

	return queue;
}

/**
 * \brief  Allocates and initializes a new fifo queue using a user-defined list
 *
 * \param  list  Pointer to the list that will be used to initialize the queue.
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_from_list(RZ_NONNULL RZ_BORROW RzList /*<void *>*/ *list, RZ_NULLABLE RzListFree qfree) {
	rz_return_val_if_fail(list, NULL);
	RzThreadQueue *queue = RZ_NEW0(RzThreadQueue);
	if (!queue) {
		return NULL;
	}

	queue->list = rz_list_clone(list);
	if (!queue->list) {
		free(queue);
		return NULL;
	}

	queue->list->free = qfree;
	queue->max_size = rz_list_length(list);
	queue->lock = rz_th_lock_new(false);
	queue->cond = rz_th_cond_new();
	if (!queue->list || !queue->lock || !queue->cond) {
		rz_th_queue_free(queue);
		return NULL;
	}

	return queue;
}

/**
 * \brief  Allocates and initializes a new fifo queue using a user-defined vector
 *
 * \param  vector  Pointer to the vector that will be used to initialize the queue.
 * \param  qfree   Pointer to a custom free function to free the queue if not empty.
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_from_pvector(RZ_NONNULL RZ_BORROW RzPVector /*<void *>*/ *vector, RZ_NULLABLE RzListFree qfree) {
	rz_return_val_if_fail(vector, NULL);
	RzThreadQueue *queue = rz_th_queue_new(rz_pvector_len(vector), qfree);
	if (!queue) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (vector, it) {
		void *value = *it;
		if (!value) {
			continue;
		}
		if (!rz_list_append(queue->list, value)) {
			rz_th_queue_free(queue);
			return NULL;
		}
	}

	return queue;
}

/**
 * \brief  Frees a RzThreadQueue structure
 *
 * \param  queue The RzThreadQueue to free
 */
RZ_API void rz_th_queue_free(RZ_NULLABLE RzThreadQueue *queue) {
	if (!queue) {
		return;
	}

	rz_list_free(queue->list);
	rz_th_lock_free(queue->lock);
	rz_th_cond_free(queue->cond);
	free(queue);
}

/**
 * \brief  Pushes a new element into the queue
 *
 * \param  queue The RzThreadQueue to push to
 * \param  user  The non-null pointer to push to the queue
 * \param  tail  When true, appends the element to the tail, otherwise to the head
 *
 * \return On success returns true, otherwise false
 */
RZ_API bool rz_th_queue_push(RZ_NONNULL RzThreadQueue *queue, RZ_NONNULL void *user, bool tail) {
	rz_return_val_if_fail(queue && user, false);

	bool added = false;
	rz_th_lock_enter(queue->lock);
	if (!queue->max_size || rz_list_length(queue->list) < queue->max_size) {
		if (tail) {
			added = rz_list_append(queue->list, user) != NULL;
		} else {
			added = rz_list_prepend(queue->list, user) != NULL;
		}
	}
	if (added) {
		rz_th_cond_signal(queue->cond);
	}
	rz_th_lock_leave(queue->lock);
	return added;
}

/**
 * \brief  Removes an element from the queue, but does not awaits when empty.
 *
 * \param  queue The RzThreadQueue to pop from
 * \param  tail  When true, pops the element from the tail, otherwise from the head
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN void *rz_th_queue_pop(RZ_NONNULL RzThreadQueue *queue, bool tail) {
	rz_return_val_if_fail(queue, NULL);

	void *user = NULL;
	rz_th_lock_enter(queue->lock);
	if (tail) {
		user = rz_list_pop(queue->list);
	} else {
		user = rz_list_pop_head(queue->list);
	}
	rz_th_lock_leave(queue->lock);
	return user;
}

/**
 * \brief  Removes an element from the queue, but yields the thread till not empty.
 *
 * \param  queue The RzThreadQueue to push to
 * \param  tail  When true, pops the element from the tail, otherwise from the head
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN void *rz_th_queue_wait_pop(RZ_NONNULL RzThreadQueue *queue, bool tail) {
	rz_return_val_if_fail(queue, NULL);

	void *user = NULL;
	rz_th_lock_enter(queue->lock);
	if (rz_list_empty(queue->list)) {
		rz_th_cond_wait(queue->cond, queue->lock);
	}
	if (tail) {
		user = rz_list_pop(queue->list);
	} else {
		user = rz_list_pop_head(queue->list);
	}
	rz_th_lock_leave(queue->lock);
	return user;
}

/**
 * \brief  Returns true if the queue is empty (thread-safe)
 *
 * \param  queue The RzThreadQueue to check
 *
 * \return When empty returns true, otherwise false
 */
RZ_API bool rz_th_queue_is_empty(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_val_if_fail(queue, false);

	rz_th_lock_enter(queue->lock);
	bool is_empty = rz_list_empty(queue->list);
	rz_th_lock_leave(queue->lock);
	return is_empty;
}

/**
 * \brief  Returns true if the queue is full and when the size is not RZ_THREAD_QUEUE_UNLIMITED (thread-safe)
 *
 * \param  queue The RzThreadQueue to check
 *
 * \return When full returns true, otherwise false
 */
RZ_API bool rz_th_queue_is_full(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_val_if_fail(queue, false);

	rz_th_lock_enter(queue->lock);
	bool is_full = queue->max_size != RZ_THREAD_QUEUE_UNLIMITED && rz_list_length(queue->list) >= queue->max_size;
	rz_th_lock_leave(queue->lock);
	return is_full;
}

/**
 * \brief  Returns the total number of element in the queue (thread-safe)
 *
 * \param  queue The RzThreadQueue to use
 *
 * \return Returns the total number of element in the queue
 */
RZ_API size_t rz_th_queue_size(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_val_if_fail(queue, false);

	rz_th_lock_enter(queue->lock);
	size_t size = rz_list_length(queue->list);
	rz_th_lock_leave(queue->lock);
	return size;
}

/**
 * \brief  Removes all elements from the queue, but does not awaits when empty.
 *
 * \param  queue The RzThreadQueue to pop from
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzList /*<void *>*/ *rz_th_queue_pop_all(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_val_if_fail(queue, false);

	RzList *list = rz_list_newf(queue->list->free);
	if (!list) {
		return NULL;
	}

	rz_th_lock_enter(queue->lock);
	RzList *res = queue->list;
	queue->list = list;
	rz_th_lock_leave(queue->lock);
	return res;
}
