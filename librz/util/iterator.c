// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_iterator.h>
#include <rz_util/rz_assert.h>

/**
 * \brief Initialize a new RzIterator
 *
 * This function fills \p iterator with a new iterator and assigns function
 * pointers for iteration control and cleanup.
 * If \p next or \p u are NULL, the function logs a warning and returns false.
 *
 * \param next A pointer to the function that defines the 'next' behavior of the iterator.
 * \param free A pointer to the function that is used to free the inner object.
 * \param free_u A pointer to the function that is used to free the user object `u`.
 * \param clone_u A pointer to the function that duplicates the user object \p u, or NULL
 *                if the iterator does not support cloning (see rz_iterator_clone()).
 * \param u A generic pointer to user data.
 * \param iterator Output parameter, filled with the constructed iterator on success.
 *
 * \return True on success, false on failure.
 */
RZ_API bool rz_iterator_init(
	RZ_NONNULL rz_iterator_next_cb next,
	RZ_NULLABLE rz_iterator_free_cb free,
	RZ_NULLABLE rz_iterator_free_cb free_u,
	RZ_NULLABLE rz_iterator_clone_cb clone_u,
	RZ_NONNULL RZ_OWN void *u,
	RZ_OUT RZ_NONNULL RzIterator *iterator) {
	if (!(next && u)) {
		rz_warn_if_reached();
		if (free_u) {
			free_u(u);
		}
		return false;
	}

	iterator->next = next;
	iterator->u = u;
	iterator->free = free;
	iterator->free_u = free_u;
	iterator->clone_u = clone_u;
	return true;
}

/**
 * \brief Fetches the next element with the RzIterator
 *
 * This function retrieves the next element in the sequence for a given RzIterator.
 * Before fetching the next element, it frees the current element using the
 * RzIterator's `free` function if it's not NULL.
 *
 * \param it A pointer to the RzIterator object.
 *
 * \return void* Pointer to the element gotten as the next object in the sequence or NULL if operation failed.
 */
RZ_API RZ_BORROW void *rz_iterator_next(RZ_NONNULL RZ_BORROW RzIterator *it) {
	rz_return_val_if_fail(it && it->next, NULL);
	if (it->free) {
		it->free(it->cur);
	}
	it->cur = it->next(it);
	return it->cur;
}

RZ_API void rz_iterator_fini(RzIterator *it) {
	if (!it) {
		return;
	}
	if (it->free) {
		it->free(it->cur);
	}
	if (it->free_u) {
		it->free_u(it->u);
	}
}

/**
 * \brief Clone \p iter into \p iter_clone, at the state \p iter is in at the moment of cloning.
 *
 * The clone and the original are independent of each other, i.e. advancing or
 * finalizing one of them does not affect the other. Both continue to yield
 * the same elements from their current position on.
 *
 * If \p iter does not support cloning,
 * false is returned and \p iter_clone is set to an uninitialized iterator.
 *
 * \param iter The iterator to clone.
 * \param iter_clone Filled with the cloned iterator on success.
 *
 * \return True on success, false on failure or if the iterator does not support cloning.
 */
RZ_API bool rz_iterator_clone(const RzIterator *iter, RZ_OUT RzIterator *iter_clone) {
	rz_return_val_if_fail(iter_clone, false);
	*iter_clone = (RzIterator){ 0 };
	if (rz_iterator_is_uninit(iter)) {
		return false;
	}
	if (!iter->clone_u) {
		// This iterator does not have a clone callback,
		// so its state cannot be duplicated (see rz_iterator_init())
		return false;
	}
	void *u_clone = iter->clone_u(iter->u);
	if (!u_clone) {
		return false;
	}
	if (!rz_iterator_init(iter->next, iter->free, iter->free_u, iter->clone_u, u_clone, iter_clone)) {
		return false;
	}
	iter_clone->cur = iter->cur;
	return true;
}
