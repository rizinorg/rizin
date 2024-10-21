// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_iterator.h>
#include <rz_util/rz_assert.h>

/**
 * \brief Initialize a new RzIterator
 *
 * This function creates a new `RzIterator` object and assigns function pointers for
 * iteration control and cleanup. The created iterator is returned to the caller.
 * If `next` or `u` are NULL, the function logs a warning and return NULL.
 *
 * \param next A pointer to the function that defines the 'next' behavior of the iterator.
 * \param free A pointer to the function that is used to free the inner object.
 * \param free_u A pointer to the function that is used to free the user object `u`.
 * \param u A generic pointer to user data.
 *
 * \return RzIterator* A pointer to the newly created `RzIterator` or NULL if the operation failed.
 */
RZ_API RZ_OWN RzIterator *rz_iterator_new(
	RZ_NONNULL rz_iterator_next_cb next,
	RZ_NULLABLE rz_iterator_free_cb free,
	RZ_NULLABLE rz_iterator_free_cb free_u,
	RZ_NONNULL RZ_OWN void *u) {
	if (!(next && u)) {
		rz_warn_if_reached();
		goto cleanup;
	}
	RzIterator *it = RZ_NEW0(RzIterator);
	if (!it) {
		goto cleanup;
	}

	it->next = next;
	it->u = u;
	it->free = free;
	it->free_u = free_u;
	return it;
cleanup:
	if (free_u) {
		free_u(u);
	}
	return NULL;
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

RZ_API void rz_iterator_free(RzIterator *it) {
	if (!it) {
		return;
	}
	if (it->free) {
		it->free(it->cur);
	}
	if (it->free_u) {
		it->free_u(it->u);
	}
	free(it);
}
