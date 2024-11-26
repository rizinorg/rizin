#ifndef RZ_SEARCH_H
#define RZ_SEARCH_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_io.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_search);

typedef struct rz_search_opt_t RzSearchOpt;

typedef struct rz_search_collection_t RzSearchCollection;

typedef struct rz_search_hit_t {
	char *metadata; ///< Metadata for extra details (can be NULL)
	ut64 address; ///< Address the matched data
	size_t size; ///< Size of the matched data (can be 0)
} RzSearchHit;

typedef bool (*RzSearchCancelCallback)(void *user, size_t n_hits);

RZ_API bool rz_search_opt_set_backwards(RZ_NONNULL RzSearchOpt *opt, bool backwards);
RZ_API bool rz_search_opt_set_allow_overlaps(RZ_NONNULL RzSearchOpt *opt, bool allow_overlaps);
RZ_API bool rz_search_opt_set_inverse_match(RZ_NONNULL RzSearchOpt *opt, bool inverse_match);
RZ_API bool rz_search_opt_set_buffer_size(RZ_NONNULL RzSearchOpt *opt, size_t buffer_size);
RZ_API bool rz_search_opt_set_max_threads(RZ_NONNULL RzSearchOpt *opt, size_t max_threads);
RZ_API bool rz_search_opt_set_cancel_cb(RZ_NONNULL RzSearchOpt *opt, RzSearchCancelCallback callback, void *user);

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_aes_keys();

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_private_keys();

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_regex();
RZ_API bool rz_search_collection_regex_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *regex, bool caseless);

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_bytes();
RZ_API bool rz_search_collection_bytes_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *metadata, RZ_NONNULL const ut8 *bytes, RZ_NULLABLE const ut8 *mask, size_t length);
RZ_API bool rz_search_collection_bytes_add_pattern(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *hex_pattern);

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_strings(RZ_NONNULL RzUtilStrScanOptions *opts, RzStrEnc expected, bool caseless);
RZ_API bool rz_search_collection_string_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *string);

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_magic(RZ_NONNULL const char *magic_dir);

RZ_API bool rz_search_collection_match_any(RZ_NULLABLE RzSearchCollection *sc, RZ_NONNULL const ut8 *buffer, size_t length);
RZ_API void rz_search_collection_free(RZ_NULLABLE RzSearchCollection *sc);
RZ_API void rz_search_hit_free(RZ_NULLABLE RzSearchHit *hit);

RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_search_run(RZ_NONNULL RzSearchOpt *opt, RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RzIO *io, RZ_NONNULL RzList /*<RzIOMap *>*/ *search_in);

#ifdef __cplusplus
}
#endif

#endif
