// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "search_internal.h"

/**
 * \brief      Initialize a new RzSearchCollection
 *
 * \param[in]  find      The find callback to set
 * \param[in]  is_empty  The callback to use to check if collection is empty
 * \param[in]  free      The callback to use to free the context
 * \param      user      The additional context needed.
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new(RZ_NONNULL RzSearchFindCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(find && is_empty, NULL);
	RzSearchCollection *sc = RZ_NEW0(RzSearchCollection);
	if (!sc) {
		RZ_LOG_ERROR("search: failed to allocate RzSearchCollection\n");
		return NULL;
	}
	sc->find = find;
	sc->is_empty = is_empty;
	sc->free = free;
	sc->user = user;
	return sc;
}

/**
 * \brief      Frees a RzSearchCollection structure
 *
 * \param[in]  sc  The RzSearchCollection pointer to free
 */
RZ_API void rz_search_collection_free(RZ_NULLABLE RzSearchCollection *sc) {
	if (!sc) {
		return;
	}
	if (sc->free) {
		sc->free(sc->user);
	}
	free(sc);
}

/**
 * \brief      Checks if a given RzSearchCollection has an expected find callback
 *
 * \param      col       The RzSearchCollection to test
 * \param[in]  expected  The expected find callback
 *
 * \return     Returns true when the RzSearchCollection callback matches the expected one.
 */
RZ_IPI bool rz_search_collection_has_find_callback(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RzSearchFindCallback expected) {
	rz_return_val_if_fail(col && expected, false);
	return col->find == expected;
}

/**
 * \brief      Checks if a given RzSearchCollection is empty
 *
 * \param      col       The RzSearchCollection to test
 *
 * \return     Returns true when the RzSearchCollection is empty.
 */
RZ_IPI bool rz_search_collection_is_empty(RZ_NONNULL RzSearchCollection *col) {
	rz_return_val_if_fail(col && col->is_empty, false);
	return col->is_empty(col->user);
}

/**
 * \brief      Search collection over buffer
 *
 * \param      sc      The RzSearchCollection to use
 * \param[in]  buffer  The buffer to match in
 * \param[in]  length  The length of the buffer
 *
 * \return     Returns true when something matched, otherwise false.
 */
RZ_API bool rz_search_collection_match_any(RZ_NULLABLE RzSearchCollection *sc, RZ_NONNULL const ut8 *buffer, size_t length) {
	rz_return_val_if_fail(sc && buffer, false);

	if (length < 1 || rz_search_collection_is_empty(sc)) {
		return false;
	}

	RzThreadQueue *hits = rz_th_queue_new(RZ_THREAD_QUEUE_UNLIMITED, (RzListFree)rz_search_hit_free);
	if (!hits) {
		RZ_LOG_ERROR("search: cannot allocate RzSearchHit queue.\n");
		return false;
	}

	if (!sc->find(sc->user, 0, buffer, length, hits)) {
		RZ_LOG_ERROR("search: failed to run search over collection\n");
		return false;
	}

	size_t size = rz_th_queue_size(hits);
	rz_th_queue_free(hits);
	return size > 0;
}