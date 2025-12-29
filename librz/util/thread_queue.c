// SPDX-FileCopyrightText: 2022-2025 deroad <deroad@kumo.xn--q9jyb4c>
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
	RzThreadLock *reader_lock; ///< Lock for readers
	RzThreadCond *reader_cond; ///< Cond for readers
	size_t reader_awaiting; ///< Number of readers awaiting to read

	RzThreadCond *empty_cond; ///< Cond any thread waiting for an empty queue

	RzThreadLock *data_lock; ///< Lock used to modify the RzThreadQueue data
	RzThreadQueueSize max_size; ///< Max queue size or unlimited
	RzList /*<void *>*/ *list; ///< Stored data
	bool closed; ///< Defines if the queue is closed (i.e. reads or writes cannot be performed).
};

static RZ_OWN RzThreadQueue *th_queue_new(RzThreadQueueSize max_size, RzList /*<void *>*/ *list) {
	RzThreadQueue *queue = RZ_NEW0(RzThreadQueue);
	if (!queue) {
		return NULL;
	}

	queue->max_size = max_size;
	queue->list = list;
	queue->data_lock = rz_th_lock_new(false);
	queue->reader_lock = rz_th_lock_new(false);
	queue->reader_cond = rz_th_cond_new();
	queue->empty_cond = rz_th_cond_new();
	if (!queue->list ||
		!queue->data_lock ||
		!queue->reader_lock ||
		!queue->reader_cond ||
		!queue->empty_cond) {
		rz_th_queue_free(queue);
		return NULL;
	}

	return queue;
}

/**
 * \brief  Allocates and initializes a new fifo queue
 *
 * \param  max_size  The maximum size of the queue, use RZ_THREAD_QUEUE_UNLIMITED for an unlimited size
 * \param  qfree     Pointer to a custom free function to free the queue if not empty.
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzThreadQueue *rz_th_queue_new(RzThreadQueueSize max_size, RZ_NULLABLE RzListFree qfree) {
	RzList *list = rz_list_newf(qfree);
	if (!list) {
		return NULL;
	}

	return th_queue_new(max_size, list);
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

	size_t max_size = rz_list_length(list);
	RzList *copy = rz_list_clone(list);
	if (!copy) {
		return NULL;
	}

	copy->free = qfree;
	return th_queue_new(max_size, copy);
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

	size_t max_size = rz_pvector_len(vector);
	RzList *list = rz_list_newf(qfree);
	if (!list) {
		return NULL;
	}

	void **it;
	rz_pvector_foreach (vector, it) {
		void *value = *it;
		if (!value) {
			continue;
		}
		if (!rz_list_append(list, value)) {
			rz_list_free(list);
			return NULL;
		}
	}

	return th_queue_new(max_size, list);
}

/**
 * \brief  Closes a RzThreadQueue but only when empty (once closed you cannot read/write data).
 *
 * \param  queue The RzThreadQueue to close
 */
RZ_API void rz_th_queue_close_when_empty(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_if_fail(queue);

	rz_th_lock_enter(queue->data_lock);
	if (queue->closed) {
		// already closed.
		rz_th_lock_leave(queue->data_lock);
		return;
	}

	while (!rz_list_empty(queue->list)) {
		// the list is not empty, so we wait for it to be empty.
		rz_th_cond_timed_wait(queue->empty_cond, queue->data_lock, 100);
	}

	// we finally close the queue & notify all awating readers
	queue->closed = true;
	rz_th_cond_signal_all(queue->reader_cond);

	rz_th_lock_leave(queue->data_lock);
}

/**
 * \brief  Closes a RzThreadQueue (once closed you cannot read/write data).
 *
 * \param  queue The RzThreadQueue to close
 */
RZ_API void rz_th_queue_close(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_if_fail(queue);

	rz_th_lock_enter(queue->data_lock);
	if (!queue->closed) {
		queue->closed = true;
		rz_th_cond_signal_all(queue->reader_cond);
	}
	rz_th_lock_leave(queue->data_lock);
}

/**
 * \brief  Returns true if a given RzThreadQueue is closed.
 *
 * \param  queue The RzThreadQueue to check if is closed or not.
 */
RZ_API bool rz_th_queue_is_closed(RZ_NONNULL RzThreadQueue *queue) {
	rz_return_val_if_fail(queue, false);
	rz_th_lock_enter(queue->data_lock);
	bool closed = queue->closed;
	rz_th_lock_leave(queue->data_lock);
	return closed;
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

	// always close before freeing it.
	rz_th_queue_close(queue);

	rz_list_free(queue->list);
	rz_th_cond_free(queue->empty_cond);
	rz_th_lock_free(queue->reader_lock);
	rz_th_cond_free(queue->reader_cond);
	rz_th_lock_free(queue->data_lock);
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
	rz_th_lock_enter(queue->data_lock);

	if (queue->closed) {
		// never write to a closed queue
		goto end;
	}

	if (!queue->max_size || rz_list_length(queue->list) < queue->max_size) {
		if (tail) {
			added = rz_list_append(queue->list, user) != NULL;
		} else {
			added = rz_list_prepend(queue->list, user) != NULL;
		}
	}

	if (!added) {
		// we failed to add an element to the queue, so we return.
		goto end;
	}

	// we notify a reader that there is new data
	if (queue->reader_awaiting > 0) {
		// we notify a reader that there is now data.
		rz_th_cond_signal(queue->reader_cond);
	}

end:
	rz_th_lock_leave(queue->data_lock);
	return added;
}

/**
 * \brief  Removes an element from the queue. It blocks until it can read or the queue is closed.
 *
 * \param  queue The RzThreadQueue to pop from
 * \param  tail  When true, pops the element from the tail, otherwise from the head
 * \param  data  The data removed from the queue
 *
 * \return On success returns a valid pointer, otherwise NULL
 */
RZ_API bool rz_th_queue_pop(RZ_NONNULL RzThreadQueue *queue, bool tail, RZ_NONNULL RZ_OUT void **data) {
	rz_return_val_if_fail(queue && data, NULL);

	bool ret = false;
	rz_th_lock_enter(queue->reader_lock);
	rz_th_lock_enter(queue->data_lock);

	while (!queue->closed && rz_list_empty(queue->list)) {
		// the queue is not closed and we need to wait till there is new data
		queue->reader_awaiting++;
		rz_th_cond_wait(queue->reader_cond, queue->data_lock);
		queue->reader_awaiting--;
	}

	if (queue->closed) {
		// the queue is closed, nothing to do.
		goto end;
	}

	if (tail) {
		*data = rz_list_pop(queue->list);
	} else {
		*data = rz_list_pop_head(queue->list);
	}
	ret = true;

end:
	rz_th_lock_leave(queue->data_lock);
	rz_th_lock_leave(queue->reader_lock);
	return ret;
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

	rz_th_lock_enter(queue->data_lock);
	bool is_empty = rz_list_empty(queue->list);
	rz_th_lock_leave(queue->data_lock);
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

	rz_th_lock_enter(queue->data_lock);
	bool is_full = queue->max_size != RZ_THREAD_QUEUE_UNLIMITED && rz_list_length(queue->list) >= queue->max_size;
	rz_th_lock_leave(queue->data_lock);
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

	rz_th_lock_enter(queue->data_lock);
	size_t size = rz_list_length(queue->list);
	rz_th_lock_leave(queue->data_lock);
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

	rz_th_lock_enter(queue->data_lock);
	RzList *res = queue->list;
	queue->list = list;
	rz_th_lock_leave(queue->data_lock);
	return res;
}
