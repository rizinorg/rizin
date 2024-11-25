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
#define RZ_SEARCH_MIN_BUFFER_SIZE    512u
#define RZ_SEARCH_MAX_HEX_PATTERN    UT16_MAX

typedef void (*RzSearchFiniCallback)(void *user);
typedef bool (*RzSearchOverCallback)(RzPVector /*<void *>*/ *collection, ut64 address, const ut8 *buffer, size_t size, RzThreadQueue *hits);

struct rz_search_collection_t {
	RzPVector /*<void *>*/ *collection; ///< Collection of elements to search in a buffer
	RzSearchOverCallback search_over; ///< Collection search over the collection callback
};

struct rz_search_opt_t {
	bool backwards;
	bool allow_overlaps;
	bool inverse_match;
	size_t buffer_size;
	size_t max_threads;

	// cancel callback
	void *cancel_usr;
	RzSearchCancelCallback cancel_cb;
};

RZ_IPI RZ_OWN RzSearchHit *rz_search_hit_new(const char *metadata, ut64 address, size_t size);

RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new(RZ_NONNULL RzSearchOverCallback search_over, RZ_NULLABLE RzPVectorFree free);
RZ_IPI bool rz_search_collection_has_callback(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RzSearchOverCallback expected);
RZ_IPI bool rz_search_collection_is_empty(RZ_NONNULL RzSearchCollection *col);

#endif /* RZ_SEARCH_INTERNAL_H */
