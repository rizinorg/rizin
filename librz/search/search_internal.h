// SPDX-FileCopyrightText: 2024 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_SEARCH_INTERNAL_H
#define RZ_SEARCH_INTERNAL_H

#include <rz_search.h>
#include <rz_list.h>
#include <rz_th.h>

#define RZ_SEARCH_MAX_HEX_PATTERN UT16_MAX

/**
 * \brief The number of elements per search chunk.
 * Note, the actual buffer, passed to the find() callback,
 * will be bigger by sizeof(element) - 1.
 * To also find elements crossing chunk boundaries.
 *
 * ATTENTION: If you change this value, update the test
 * in cmd_search_x::"search over boundary"
 */
#define RZ_SEARCH_MIN_ELEMENTS_PER_CHUNK 64u

/**
 * \brief Minimal buffer size for each find() thread in bytes.
 *
 * ATTENTION: This value must be aligned to at least 4bytes.
 * Otherwise the string search breaks.
 */
#define RZ_SEARCH_MIN_CHUNK_SIZE 32ull

/**
 * \brief Default buffer size for each find() thread in bytes.
 * Size: 4096
 *
 * ATTENTION: If you change this value, update the test
 * in cmd_search_x::"search over boundary"
 *
 * ATTENTION: This value must be aligned to at least 4bytes.
 * Otherwise the string search breaks.
 */
#define RZ_SEARCH_DEFAULT_CHUNK_SIZE 0x1000ull

/**
 * \brief Maximum buffer size to check in each find() thread in bytes.
 * Size: 4G
 */
#define RZ_SEARCH_MAX_CHUNK_SIZE             0x100000000ull
#define RZ_SEARCH_CANCEL_CHECK_INTERVAL_USEC 100 * 1000

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
 * \param fopt The find() search options.
 * \param user The private user data.
 * \param address The address associated with the given bytes.
 * \param buffer The bytes buffer.
 * \param hits The queue to push new hits onto.
 * \param n_hits The variable to store the number of new hits.
 *
 * \return True, if a match was found.
 * \return False otherwise.
 */
typedef bool (*RzSearchFindBytesCallback)(RzSearchFindOpt *fopt, void *user, ut64 address, const RzBuffer *buffer,
	RZ_OUT RzThreadQueue *hits, RZ_OUT size_t *n_hits);

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
typedef bool (*RzSearchFindGraphCallback)(RzSearchFindOpt *fopt, void *user, const RzGraph *graph, RZ_OUT RzThreadQueue *hits);

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

struct rz_search_bytes_pattern_t {
	const char *pattern_desc; ///< Pattern description string.
	ut8 *bytes; ///< Pattern bytes.
	ut8 *mask; ///< Pattern mask (when NULL full match)
	RzRegex *regex; ///< Regex patterns of the bytes. Is optional.
	size_t length; ///< Pattern & mask length
};

struct rz_search_opt_t {
	RzSearchFindOpt *find_opts;
	size_t max_hits;
	ut64 chunk_size;
	ut64 element_size;
	RzThreadNCores max_threads;
	RzSearchProgress show_progress;

	// cancel callback
	void *cancel_usr;
	RzSearchCancelCallback cancel_cb;
};

struct rz_search_find_opt_t {
	bool match_overlap; ///< Set if hits can overlap.
	size_t alignment; ///< The address alignment to start the search from. If >1, only `buffer + (alignment * x)` is searched.
};

struct rz_search_interval_t {
	RzInterval interval;
	size_t n_hits;
};

struct rz_search_hit_detail_t {
	RzSearchHitDetailType type;
	union {
		char *string;
		ut64 u64;
		st64 s64;
		double f64;
		ut8 *bytes;
	};
	size_t length;
};

RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_string_new(const char *string);
RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_unsigned_new(const ut64 u64);
RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_signed_new(const st64 s64);
RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_double_new(const double f64);
RZ_IPI RZ_OWN RzSearchHitDetail *rz_search_hit_detail_bytes_new(const ut8 *bytes, size_t length);

RZ_IPI void rz_search_hit_detail_free(RZ_NULLABLE RzSearchHitDetail *detail);

/**
 * \brief Checks of \p fopst->alignment is aligned.
 * If not, it increases \p offset by the required patting to align address + offset again and continues.
 */
#define RAW_BUF_ITER_ALIGN(fopts, address, offset) \
	if (fopts->alignment > 1 && rz_mem_align_padding(address + offset, fopts->alignment) != 0) { \
		/* Match has not the correct alignment in memory. */ \
		offset += rz_mem_align_padding(address + offset, fopts->alignment); \
		continue; \
	}

RZ_IPI RZ_OWN RzSearchHit *rz_search_hit_new(RZ_NULLABLE const char *hit_desc, ut64 address, size_t size, RZ_NULLABLE RZ_OWN RzSearchHitDetail *hit_detail);
RZ_IPI void rz_search_hit_free(RZ_NULLABLE RzSearchHit *hit);
RZ_IPI int rz_search_hit_cmp(RZ_NULLABLE RzSearchHit *a, RZ_NULLABLE RzSearchHit *b, void *user);

RZ_IPI RZ_OWN RzSearchInterval *rz_search_interval_new(RzInterval interval, size_t n_hits);
RZ_IPI void rz_search_interval_free(RZ_NULLABLE RzSearchInterval *interval);

RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new_bytes_space(RZ_NONNULL RzSearchFindBytesCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free_user, RZ_OWN RZ_NULLABLE void *user);
RZ_IPI RZ_OWN RzSearchCollection *rz_search_collection_new_graph_space(RZ_NONNULL RzSearchFindGraphCallback find, RZ_NONNULL RzSearchIsEmptyCallback is_empty, RZ_NULLABLE RzSearchFreeCallback free_user, RZ_OWN RZ_NULLABLE void *user);
RZ_IPI bool rz_search_collection_has_find_callback(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL void *expected);
RZ_IPI bool rz_search_collection_is_empty(RZ_NONNULL RzSearchCollection *col);
RZ_IPI static inline bool rz_search_collection_on_bytes_space(RZ_NONNULL RzSearchCollection *col) {
	return col->space == RZ_SEARCH_SPACE_BYTES;
};
RZ_IPI static inline bool rz_search_collection_on_graph_space(RZ_NONNULL RzSearchCollection *col) {
	return col->space == RZ_SEARCH_SPACE_GRAPH;
};

#endif /* RZ_SEARCH_INTERNAL_H */
