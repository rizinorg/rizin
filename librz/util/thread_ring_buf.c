// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_sys.h>

/**
 * \file A ring buffer implementation.
 *
 * Functionally it is equivalent to a fixed size queue, except that it
 * copies the data into the buffer.
 *
 * Suitable if you need to pass data between threads, but don't want to
 * think about pointer ownership or lifetime.
 */

#define LEAVE_RBUF() \
	rz_th_lock_enter(rbuf->counter_lock); \
	rbuf->threads_awaiting--; \
	rz_th_lock_leave(rbuf->counter_lock); \
	rz_th_lock_leave(rbuf->lock);

#define ENTER_RBUF() \
	rz_th_lock_enter(rbuf->counter_lock); \
	rbuf->threads_awaiting++; \
	rz_th_lock_leave(rbuf->counter_lock); \
	rz_th_lock_enter(rbuf->lock); \
	if (RZ_UNLIKELY(rbuf->closed)) { \
		LEAVE_RBUF(); \
		return RZ_THREAD_RING_BUF_CLOSED; \
	}

#define RBUF_CLOSE_ITERVAL_US 10000

/**
 * \brief RzThreadQueue is a thread-safe FIFO ring buffer that can be used from multiple threads.
 */
struct rz_th_ring_buf_t {
	RzThreadCond *writer_wait_cond; ///< The condition for writing threads to signal them they write.
	size_t writers_waiting; ///< Number of writers waiting.

	RzThreadCond *reader_wait_cond; ///< The condition for reading threads to signal them they read.
	size_t readers_waiting; ///< Number of readers waiting.

	RzThreadLock *lock; ///< Lock for buffer access.

	size_t threads_awaiting; ///< Number of threads awaiting to read/write
	RzThreadLock *counter_lock; ///< Lock for threads_awaiting counter.

	void *buf; ///< Stored data
	size_t elem_size; ///< Size of one element in the buffer.
	size_t n; ///< Number of elements the buffer can hold.

	size_t w; ///< Write index.
	size_t r; ///< Read index.

	bool closed; ///< Set if ring buffer is closed (no reads/writes allowed).

	/**
	 * \brief Number of elements written but not yet read.
	 * Only used of mode == RZ_THREAD_RING_BUF_OVERFLOW.
	 * It MUST be <= n
	 */
	size_t to_read;
};

/**
 * \brief Creates a new ring buffer.
 *
 * \param n The number of elements the buffer can hold.
 * \param elem_size Number of bytes each element has.
 *
 * \return The new rung buffer or NULL in case of failure.
 */
RZ_API RZ_OWN RzThreadRingBuf *rz_th_ring_buf_new(size_t n, size_t elem_size) {
	rz_return_val_if_fail(n > 1 && elem_size > 0, NULL);
	RzThreadRingBuf *rbuf = RZ_NEW0(RzThreadRingBuf);
	if (!rbuf) {
		rz_warn_if_reached();
		return NULL;
	}
	rbuf->buf = RZ_NEWS(ut8, n * elem_size);
	if (!rbuf->buf) {
		goto err_free;
	}
	rbuf->n = n;
	rbuf->elem_size = elem_size;
	rbuf->w = 0;
	rbuf->r = 0;

	rbuf->lock = rz_th_lock_new(false);
	rbuf->counter_lock = rz_th_lock_new(false);
	rbuf->writer_wait_cond = rz_th_cond_new();
	rbuf->reader_wait_cond = rz_th_cond_new();
	if (!rbuf->lock || !rbuf->counter_lock || !rbuf->writer_wait_cond || !rbuf->reader_wait_cond) {
		goto err_free;
	}

	return rbuf;

err_free:
	rz_warn_if_reached();
	rz_th_cond_free(rbuf->reader_wait_cond);
	rz_th_cond_free(rbuf->writer_wait_cond);
	rz_th_lock_free(rbuf->counter_lock);
	rz_th_lock_free(rbuf->lock);
	free(rbuf->buf);
	return NULL;
}

RZ_API void rz_th_ring_buf_free(RZ_OWN RZ_NULLABLE RzThreadRingBuf *rbuf) {
	if (!rbuf) {
		return;
	}
	rz_th_ring_buf_close(rbuf);

	free(rbuf->buf);
	rz_th_lock_free(rbuf->lock);
	rz_th_lock_free(rbuf->counter_lock);
	rz_th_cond_free(rbuf->writer_wait_cond);
	rz_th_cond_free(rbuf->reader_wait_cond);
	free(rbuf);
}

/**
 * \brief Closes the ring buffer.
 * If this is the first closing call for the given ring buffer,
 * it blocks until all waiting threads have left.
 *
 * \param rbuf The ring buffer to close.
 *
 * \return RZ_THREAD_RING_BUF_OK If the closing succeeded.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer is currently closed by another thread.
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_close(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);
	ENTER_RBUF();
	rbuf->closed = true;
	rz_th_cond_signal_all(rbuf->writer_wait_cond);
	rz_th_cond_signal_all(rbuf->reader_wait_cond);
	LEAVE_RBUF();

	while (rbuf->threads_awaiting) {
		rz_sys_usleep(RBUF_CLOSE_ITERVAL_US);
	}
	return RZ_THREAD_RING_BUF_OK;
}

static void reset_buf(RzThreadRingBuf *rbuf) {
	rbuf->w = 0;
	rbuf->r = 0;
	rbuf->to_read = 0;
}

/**
 * \brief Clears the ring buffer and opens it again.
 *
 * \param rbuf The ring buffer to close.
 *
 * \return RZ_THREAD_RING_BUF_OK If the ring buffer was opened.
 * \return RZ_THREAD_RING_BUF_FAIL If the ring buffer was already open.
 * \return RZ_THREAD_RING_BUF_CLOSED If there was an error condition. The buffer should not be used.
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_open(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);

	rz_th_lock_enter(rbuf->counter_lock);
	rbuf->threads_awaiting++;
	rz_th_lock_leave(rbuf->counter_lock);

	rz_th_lock_enter(rbuf->lock);

	if (!rbuf->closed) {
		LEAVE_RBUF();
		return RZ_THREAD_RING_BUF_FAIL;
	}
	reset_buf(rbuf);
	rbuf->closed = false;

	LEAVE_RBUF();
	return RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Clear all elements from the ring buffer.
 *
 * \param rbuf The ring buffer to clear.
 *
 * \return RZ_THREAD_RING_BUF_OK If all elements were cleared.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_clear(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);
	ENTER_RBUF()
	reset_buf(rbuf);
	if (rbuf->writers_waiting) {
		for (size_t i = 0; i < RZ_MIN(rbuf->writers_waiting, rbuf->n); ++i) {
			rz_th_cond_signal(rbuf->writer_wait_cond);
		}
	}
	LEAVE_RBUF()
	return RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Places the given element into the ring buffer.
 *
 * \param rbuf The ring buffer to write into.
 * \param elem The element to copy.
 *
 * \return RZ_THREAD_RING_BUF_OK If the write succeeded.
 * \return RZ_THREAD_RING_BUF_FAIL If the buffer was full.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_put(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf, void *elem) {
	rz_return_val_if_fail(rbuf && elem, RZ_THREAD_RING_BUF_CLOSED);

	ENTER_RBUF();
	while (rbuf->to_read == rbuf->n) {
		// Wait until data was read.
		rbuf->writers_waiting++;
		rz_th_cond_wait(rbuf->writer_wait_cond, rbuf->lock);
		rbuf->writers_waiting--;

		if (rbuf->closed) {
			LEAVE_RBUF();
			return RZ_THREAD_RING_BUF_CLOSED;
		}
	}
	memcpy((ut8 *)rbuf->buf + (rbuf->w * rbuf->elem_size), elem, rbuf->elem_size);
	rbuf->w = (rbuf->w + 1) % rbuf->n;
	rbuf->to_read++;
	if (rbuf->readers_waiting) {
		rz_th_cond_signal(rbuf->reader_wait_cond);
	}

	LEAVE_RBUF();
	return RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Takes the next element from the ring buffer.
 *
 * \param rbuf The ring buffer to read from.
 * \param elem Location to copy the element data into.
 *
 * \return RZ_THREAD_RING_BUF_OK If the read succeeded.
 * \return RZ_THREAD_RING_BUF_FAIL If the ring buffer was empty.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_take(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf, RZ_NONNULL RZ_OUT void *elem) {
	rz_return_val_if_fail(rbuf && elem, RZ_THREAD_RING_BUF_CLOSED);

	ENTER_RBUF();
	if (rbuf->to_read == 0) {
		LEAVE_RBUF();
		return RZ_THREAD_RING_BUF_FAIL;
	}
	memcpy(elem, (ut8 *)rbuf->buf + (rbuf->r * rbuf->elem_size), rbuf->elem_size);
	rbuf->r = (rbuf->r + 1) % rbuf->n;
	rbuf->to_read--;
	if (rbuf->writers_waiting) {
		rz_th_cond_signal(rbuf->writer_wait_cond);
	}
	LEAVE_RBUF();
	return RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Takes the next element from the ring buffer.
 * If the ring buffer is empty, it blocks until data was written or it was closed.
 *
 * \param rbuf The ring buffer to read from.
 * \param elem Location to copy the element data into.
 *
 * \return RZ_THREAD_RING_BUF_OK If the read succeeded.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_take_blocking(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf, RZ_NONNULL RZ_OUT void *elem) {
	rz_return_val_if_fail(rbuf && elem, RZ_THREAD_RING_BUF_CLOSED);

	ENTER_RBUF();
	while (rbuf->to_read == 0) {
		// Wait until data was written.
		rbuf->readers_waiting++;
		rz_th_cond_wait(rbuf->reader_wait_cond, rbuf->lock);
		rbuf->readers_waiting--;

		if (rbuf->closed) {
			LEAVE_RBUF();
			return RZ_THREAD_RING_BUF_CLOSED;
		}
	}
	memcpy(elem, (ut8 *)rbuf->buf + (rbuf->r * rbuf->elem_size), rbuf->elem_size);
	rbuf->r = (rbuf->r + 1) % rbuf->n;
	rbuf->to_read--;
	if (rbuf->writers_waiting) {
		rz_th_cond_signal(rbuf->writer_wait_cond);
	}
	LEAVE_RBUF();
	return RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Checks if the ring buffer is open.
 *
 * \return True If the ring buffer is open.
 * \return False The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API bool rz_th_ring_buf_is_open(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, false);
	rz_th_lock_enter(rbuf->counter_lock);
	rbuf->threads_awaiting++;
	rz_th_lock_leave(rbuf->counter_lock);

	rz_th_lock_enter(rbuf->lock);

	bool closed = rbuf->closed;

	rz_th_lock_leave(rbuf->lock);
	rbuf->threads_awaiting--;

	return !closed;
}

/**
 * \brief Checks if the buffer is empty.
 *
 * \return RZ_THREAD_RING_BUF_OK If the ring buffer was empty.
 * \return RZ_THREAD_RING_BUF_FAIL If the ring buffer was not empty.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_is_empty(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);
	ENTER_RBUF();
	bool empty = rbuf->to_read == 0;
	LEAVE_RBUF();
	return empty ? RZ_THREAD_RING_BUF_OK : RZ_THREAD_RING_BUF_FAIL;
}

/**
 * \brief Checks if the buffer is full.
 *
 * \return RZ_THREAD_RING_BUF_OK If the ring buffer was full.
 * \return RZ_THREAD_RING_BUF_FAIL If the ring buffer was not full.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_is_full(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);
	ENTER_RBUF();
	bool full = rbuf->n == rbuf->to_read;
	LEAVE_RBUF();
	return full ? RZ_THREAD_RING_BUF_OK : RZ_THREAD_RING_BUF_FAIL;
}

/**
 * \brief Checks if the buffer is empty.
 * This function is not thread safe!
 *
 * \return True If the buffer was empty.
 * \return False If the buffer was not empty.
 */
RZ_API bool rz_th_ring_buf_is_empty_unsafe(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, true);
	return rbuf->to_read == 0;
}

#undef ENTER_RBUF
#undef LEAVE_RBUF
