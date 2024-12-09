// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SEARCH_INTERNAL_H
#define RZ_SEARCH_INTERNAL_H

#include <rz_search.h>
#include <rz_list.h>
#include <rz_th.h>

#define RZ_SEARCH_AES_LENGTH         40
#define RZ_SEARCH_PRIVATE_KEY_LENGTH 11
#define RZ_SEARCH_MAX_HEX_PATTERN    UT16_MAX

typedef void (*RzSearchFreeCallback)(void *user);
typedef bool (*RzSearchIsEmptyCallback)(void *user);
typedef bool (*RzSearchFindCallback)(void *user, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits);

struct rz_search_collection_t {
	void *user; ///< Context defined by the various collections
	RzSearchFindCallback find; ///< Callback used for finding the data requested by the user
	RzSearchIsEmptyCallback is_empty; ///< Callback used to check if the collection is empty.
	RzSearchFreeCallback free; ///< Callback used to free the collection.
};

struct rz_search_opt_t {
	bool inverse_match;
	size_t buffer_size;
	size_t max_hits;
	RzThreadNCores max_threads;

	// cancel callback
	void *cancel_usr;
	RzSearchCancelCallback cancel_cb;
};

RZ_IPI RZ_OWN RzSearchHit *rz_search_hit_new(const char *metadata, ut64 address, size_t size);

RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new(RZ_NONNULL RzSearchFindCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free, RZ_NULLABLE void *user);
RZ_IPI bool rz_search_collection_has_find_callback(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RzSearchFindCallback expected);
RZ_IPI bool rz_search_collection_is_empty(RZ_NONNULL RzSearchCollection *col);

#endif /* RZ_SEARCH_INTERNAL_H */
