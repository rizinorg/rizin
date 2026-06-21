// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "search_internal.h"

static RZ_OWN RzSearchCollection *rz_search_collection_new(RzSearchSpace space, RZ_NONNULL void *find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free_user, RZ_OWN RZ_NULLABLE void *user) {
	rz_return_val_if_fail(find && is_empty, NULL);
	RzSearchCollection *sc = RZ_NEW0(RzSearchCollection);
	if (!sc) {
		if (free_user && user) {
			free_user(user);
		}
		RZ_LOG_ERROR("search: failed to allocate RzSearchCollection\n");
		return NULL;
	}
	sc->space = space;
	sc->find = find;
	sc->is_empty = is_empty;
	sc->free = free_user;
	sc->user = user;
	return sc;
}

/**
 * \brief      Initialize a new RzSearchCollection over a graph.
 *
 * \param[in]  find      The find callback to set
 * \param[in]  is_empty  The callback to use to check if collection is empty
 * \param[in]  free      The callback to use to free the context
 * \param      user      The additional context needed.
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new_graph_space(RZ_NONNULL RzSearchFindGraphCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free_user, RZ_OWN RZ_NULLABLE void *user) {
	rz_return_val_if_fail(find && is_empty, NULL);
	return rz_search_collection_new(RZ_SEARCH_SPACE_GRAPH, find, is_empty, free_user, user);
}

/**
 * \brief      Initialize a new RzSearchCollection over bytes.
 *
 * \param[in]  find      The find callback to set
 * \param[in]  is_empty  The callback to use to check if collection is empty
 * \param[in]  free      The callback to use to free the context
 * \param      user      The additional context needed.
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new_bytes_space(RZ_NONNULL RzSearchFindBytesCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free_user, RZ_OWN RZ_NULLABLE void *user) {
	rz_return_val_if_fail(find && is_empty, NULL);
	return rz_search_collection_new(RZ_SEARCH_SPACE_BYTES, find, is_empty, free_user, user);
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
RZ_IPI bool rz_search_collection_has_find_callback(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL void *expected) {
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
