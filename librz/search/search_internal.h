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

/**
 * \brief The callback to free the private user data in the RzSearchCollection.
 *
 * \param user The private user data to free.
 */
typedef void (*RzSearchFreeCallback)(void *user);

/**
 * \brief The callback to check if the search collection is considered empty.
 *
 * \param user The private user data.
 */
typedef bool (*RzSearchIsEmptyCallback)(void *user);

/**
 * \brief A callback checking a chunk of bytes if it matches the search criteria.
 *
 * \param user The private user data.
 * \param address The address associated with the given bytes.
 * \param buffer The bytes buffer.
 * \param size The buffer size in bytes.
 * \param The queue to push new hits onto.
 *
 * \return True, if a match was found.
 * \return False otherwise.
 */
typedef bool (*RzSearchFindBytesCallback)(void *user, ut64 address, const ut8 *buffer, size_t size, RZ_OUT RzThreadQueue *hits);

/**
 * \brief A callback to search a graph for a pattern.
 *
 * \param user The private user data.
 * \param graph The graph to search in.
 * \param The queue to push new hits onto.
 *
 * \return True, if a match was found.
 * \return False otherwise.
 */
typedef bool (*RzSearchFindGraphCallback)(void *user, const RzGraph *graph, RZ_OUT RzThreadQueue *hits);

typedef enum {
	RZ_SEARCH_SPACE_BYTES = 0, ///< The search is performed on bytes.
	RZ_SEARCH_SPACE_GRAPH, ///< The search is performed on a graph.
	RZ_SEARCH_SPACE_KB, ///< The search is performed on the knowledge base.
} RzSearchSpace;

struct rz_search_collection_t {
	void *user; ///< Context defined by the various collections
	RzSearchSpace space; ///< The search space of this collection.
	void *find; ///< Callback to do the search in a given chunk. The callback type depends on \ref rz_search_collection_t.space.
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

RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new_bytes(RZ_NONNULL RzSearchFindBytesCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free, RZ_NULLABLE void *user);
RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new_graph(RZ_NONNULL RzSearchFindGraphCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free, RZ_NULLABLE void *user);
RZ_IPI bool rz_search_collection_has_find_callback(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL void *expected);
RZ_IPI bool rz_search_collection_is_empty(RZ_NONNULL RzSearchCollection *col);
RZ_IPI static inline bool rz_search_collection_on_bytes_space(RZ_NONNULL RzSearchCollection *col) { return col->space == RZ_SEARCH_SPACE_BYTES; };
RZ_IPI static inline bool rz_search_collection_on_graph_space(RZ_NONNULL RzSearchCollection *col) { return col->space == RZ_SEARCH_SPACE_GRAPH; };

#endif /* RZ_SEARCH_INTERNAL_H */
