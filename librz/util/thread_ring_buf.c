// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_th.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_sys.h>

#define LEAVE_RBUF() \
	rz_th_lock_leave(rbuf->lock); \
	rbuf->threads_awaiting--;

#define ENTER_RBUF() \
	rbuf->threads_awaiting++; \
	rz_th_lock_enter(rbuf->lock); \
	if (rbuf->closed) { \
		LEAVE_RBUF(); \
		return RZ_THREAD_RING_BUF_CLOSED; \
	}

#define RBUF_CLOSE_ITERVAL_US 10000

/**
 * \brief RzThreadQueue is a thread-safe FIFO ring buffer that can be used from multiple threads.
 */
struct rz_th_ring_buf_t {
	RzThreadRingBufMode mode;

	RzThreadLock *lock; ///< Lock for buffer access.
	size_t threads_awaiting; ///< Number of threads awaiting to read/write

	void *buf; ///< Stored data
	size_t elem_size; ///< Size of one element in the buffer.
	size_t n; ///< Number of elements the buffer can hold.

	void *w; ///< Write location pointer.
	void *r; ///< Read location pointer.

	bool closed; ///< Set if ring buffer is closed (no reads/writes allowed).

	/**
	 * \brief Number of elements written but not yet read.
	 * Only used of mode == RZ_THREAD_RING_BUF_OVERFLOW.
	 * It MUST be <= n
	 */
	size_t to_read;
};

RZ_API RZ_OWN RzThreadRingBuf *rz_th_ring_buf_new(size_t n, size_t elem_size, RzThreadRingBufMode mode) {
	rz_return_val_if_fail(n > 1, NULL);
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
	rbuf->w = rbuf->buf;
	rbuf->r = NULL;

	rbuf->lock = rz_th_lock_new(false);
	if (!rbuf->lock) {
		goto err_free;
	}

	return rbuf;

err_free:
	rz_warn_if_reached();
	free(rbuf->buf);
	rz_th_lock_free(rbuf->lock);
	return NULL;
}

RZ_API void rz_th_ring_buf_free(RZ_OWN RZ_NULLABLE RzThreadRingBuf *rbuf) {
	rz_return_if_fail(rbuf);
	rz_th_ring_buf_close(rbuf);
	free(rbuf->buf);
	rz_th_lock_free(rbuf->lock);
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
	LEAVE_RBUF();

	while (rbuf->threads_awaiting) {
		rz_sys_usleep(RBUF_CLOSE_ITERVAL_US);
	}
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
	rbuf->w = rbuf->buf;
	rbuf->r = NULL;
	rbuf->to_read = 0;
	LEAVE_RBUF()
	return RZ_THREAD_RING_BUF_OK;
}

RZ_API RzThreadRingBufResult rz_th_ring_buf_put(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf, void *elem) {
	rz_return_val_if_fail(rbuf && elem, RZ_THREAD_RING_BUF_CLOSED);
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
	return RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Checks if the ring buffer is open.
 *
 * \return RZ_THREAD_RING_BUF_OK If the ring buffer is open.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_is_open(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);
	ENTER_RBUF()
	bool closed = rbuf->closed;
	LEAVE_RBUF();
	return closed ? RZ_THREAD_RING_BUF_CLOSED : RZ_THREAD_RING_BUF_OK;
}

/**
 * \brief Checks if the buffer is empty.
 *
 * \return RZ_THREAD_RING_BUF_OK If the ring buffer was empty.
 * \return RZ_THREAD_RING_BUF_FAIL If the ring buffer was not empty.
 * \return RZ_THREAD_RING_BUF_CLOSED The ring buffer was closed. Any subsequent operations on it are undefined!
 */
RZ_API RzThreadRingBufResult rz_th_ring_buf_empty(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
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
RZ_API RzThreadRingBufResult rz_th_ring_buf_full(RZ_BORROW RZ_NONNULL RzThreadRingBuf *rbuf) {
	rz_return_val_if_fail(rbuf, RZ_THREAD_RING_BUF_CLOSED);
	ENTER_RBUF();
	bool full = rbuf->n == rbuf->to_read;
	LEAVE_RBUF();
	return full ? RZ_THREAD_RING_BUF_OK : RZ_THREAD_RING_BUF_FAIL;
}

#undef ENTER_RBUF
#undef LEAVE_RBUF
