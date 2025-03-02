#ifndef RZ_SEARCH_H
#define RZ_SEARCH_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_io.h>
#include <rz_th.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_search);

enum {
	RZ_SEARCH_ESIL,
	RZ_SEARCH_KEYWORD,
	RZ_SEARCH_REGEXP,
	RZ_SEARCH_PATTERN,
	RZ_SEARCH_STRING,
	RZ_SEARCH_XREFS,
	RZ_SEARCH_AES,
	RZ_SEARCH_PRIV_KEY,
	RZ_SEARCH_DELTAKEY,
	RZ_SEARCH_MAGIC,
	RZ_SEARCH_LAST
};

#define RZ_SEARCH_DISTANCE_MAX 10

#define RZ_SEARCH_KEYWORD_TYPE_BINARY 'i'
#define RZ_SEARCH_KEYWORD_TYPE_STRING 's'

typedef struct rz_search_keyword_t {
	ut8 *bin_keyword;
	ut8 *bin_binmask;
	ut32 keyword_length;
	ut32 binmask_length;
	void *data;
	int count;
	int kwidx;
	int icase; // ignore case
	int type;
	ut64 last; // last hit hint
} RzSearchKeyword;

typedef struct {
	RzSearchKeyword *kw;
	ut64 addr;
} RzSearchLegacyHit;

typedef int (*RzSearchCallback)(RzSearchKeyword *kw, void *user, ut64 where);

typedef struct rz_search_t {
	int n_kws; // hit${n_kws}_${count}
	int mode;
	ut32 pattern_size;
	ut32 string_min; // max length of strings for RZ_SEARCH_STRING
	ut32 string_max; // min length of strings for RZ_SEARCH_STRING
	void *data; // data used by search algorithm
	void *user; // user data passed to callback
	RzSearchCallback callback;
	ut64 nhits;
	ut64 maxhits; // search.maxhits
	RzList /*<RzSearchHit *>*/ *hits;
	int distance;
	int inverse;
	bool overlap; // whether two matches can overlap
	int contiguous;
	int align;
	int (*update)(struct rz_search_t *s, ut64 from, const ut8 *buf, int len);
	RzList /*<RzSearchKeyword *>*/ *kws; // TODO: Use rz_search_kw_new ()
	RzIOBind iob;
	char bckwrds;
} RzSearch;

#ifdef RZ_API

#define RZ_SEARCH_AES_BOX_SIZE 31

RZ_API RzSearch *rz_search_new(int mode);
RZ_API int rz_search_set_mode(RzSearch *s, int mode);
RZ_API RzSearch *rz_search_free(RzSearch *s);

/* keyword management */
RZ_API RzList /*<RzSearchHit *>*/ *rz_search_find(RzSearch *s, ut64 addr, const ut8 *buf, int len);
RZ_API int rz_search_update(RzSearch *s, ut64 from, const ut8 *buf, long len);
RZ_API int rz_search_update_i(RzSearch *s, ut64 from, const ut8 *buf, long len);

RZ_API void rz_search_keyword_free(RzSearchKeyword *kw);
RZ_API RZ_OWN RzSearchKeyword *rz_search_keyword_new(const ut8 *kw_buf, int kw_len, RZ_NULLABLE const ut8 *bm_buf, int bm_buf_len, RZ_NULLABLE const char *data);
RZ_API RzSearchKeyword *rz_search_keyword_new_str(const char *kw, const char *bm, const char *data, int icase);
RZ_API RzSearchKeyword *rz_search_keyword_new_wide(const char *kw, const char *bm, const char *data, int icase);
RZ_API RzSearchKeyword *rz_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data);
RZ_API RzSearchKeyword *rz_search_keyword_new_hexmask(const char *kwstr, const char *data);
RZ_API RzSearchKeyword *rz_search_keyword_new_regexp(const char *str, const char *data);

RZ_API int rz_search_kw_add(RzSearch *s, RzSearchKeyword *kw);
RZ_API void rz_search_reset(RzSearch *s, int mode);
RZ_API void rz_search_kw_reset(RzSearch *s);
RZ_API void rz_search_string_prepare_backward(RzSearch *s);

// TODO: is this an internal API?
RZ_API int rz_search_mybinparse_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_aes_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_privkey_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_magic_update(RzSearch *_s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_deltakey_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_strings_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_regexp_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
RZ_API int rz_search_legacy_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr);
RZ_API void rz_search_set_distance(RzSearch *s, int dist);
RZ_API int rz_search_set_string_limits(RzSearch *s, ut32 min, ut32 max); // dup again?
// RZ_API int rz_search_set_callback(RzSearch *s, int (*callback)(struct rz_search_kw_t *, void *, ut64), void *user);
RZ_API void rz_search_set_callback(RzSearch *s, RzSearchCallback(callback), void *user);
RZ_API int rz_search_begin(RzSearch *s);

/* pattern search */
RZ_API void rz_search_pattern_size(RzSearch *s, int size);
RZ_API int rz_search_pattern(RzSearch *s, ut64 from, ut64 to);

#endif // RZ_API

//
// New search.
// Everything above is only there to not break the build.
//

RZ_LIB_VERSION_HEADER(rz_search);

/**
 * \brief Private search options for the search module. Use the rz_search_opt_*() functions to edit it.
 */
typedef struct rz_search_opt_t RzSearchOpt;

/**
 * \brief Options for the find() callback of the different searches.
 */
typedef struct rz_search_find_opt_t RzSearchFindOpt;

typedef struct rz_search_collection_t RzSearchCollection;

typedef struct rz_search_hit_t {
	char *hit_desc; ///< Hit description (can be NULL)
	ut64 address; ///< Address/offset of the matched data.
	size_t size; ///< Size of the matched data (can be 0), in bytes.
} RzSearchHit;

typedef enum {
	RZ_SEARCH_CANCEL_REGULAR_CHECK, ///< Regular cancel check. Repeated every RZ_SEARCH_CANCEL_CHECK_INTERVAL_USEC microseconds.
	RZ_SEARCH_CANCEL_SIGINT, ///< Interrupt signal (likely ctrl + c).
} RzSearchCancelReason;

typedef struct rz_search_bytes_pattern_t RzSearchBytesPattern;

RZ_API RZ_OWN char *rz_search_hit_flag_name(RZ_NONNULL const RzSearchHit *hit, size_t hit_id, RZ_NULLABLE const char *prefix);

RZ_API void rz_search_bytes_pattern_free(RZ_NULLABLE RZ_OWN RzSearchBytesPattern *hp);
RZ_API RZ_OWN RzSearchBytesPattern *rz_search_bytes_pattern_copy(RZ_NONNULL RZ_BORROW RzSearchBytesPattern *hp);
RZ_API RZ_OWN RzSearchBytesPattern *rz_search_bytes_pattern_new(RZ_OWN ut8 *bytes, RZ_NULLABLE RZ_OWN ut8 *mask, size_t length, RZ_NULLABLE const char *pattern_desc, bool compile_regex);
RZ_API RZ_OWN RzSearchBytesPattern *rz_search_parse_byte_pattern(const char *byte_pattern, RZ_NULLABLE const char *pattern_desc);
RZ_API size_t rz_search_bytes_pattern_len(RZ_NONNULL const RzSearchBytesPattern *hp);
RZ_API const char *rz_search_bytes_pattern_desc(RZ_NONNULL const RzSearchBytesPattern *bp);

/**
 * \brief The cancel callback. It is invoked to check, if the search should be stopped.
 *
 * \param user The private user data.
 * \param n_hits Number of hits already found during the search.
 * \param invoe_reason The reason it is called.
 *
 * \return True, if the search should be canceled.
 * \return False, if the search should continue.
 */
typedef bool (*RzSearchCancelCallback)(void *user, size_t n_hits, RzSearchCancelReason invoke_reason);

RZ_API RZ_OWN RzSearchOpt *rz_search_opt_new();
RZ_API void rz_search_opt_free(RZ_NULLABLE RzSearchOpt *opt);
RZ_API bool rz_search_opt_set_max_hits(RZ_NONNULL RzSearchOpt *opt, size_t max_hits);
RZ_API bool rz_search_opt_set_elemet_size(RZ_NONNULL RzSearchOpt *opt, ut64 chunk_size);
RZ_API bool rz_search_opt_set_max_threads(RZ_NONNULL RzSearchOpt *opt, RzThreadNCores max_threads);
RZ_API bool rz_search_opt_set_cancel_cb(RZ_NONNULL RzSearchOpt *opt, RzSearchCancelCallback callback, void *user);
RZ_API bool rz_search_opt_set_find_options(RZ_NONNULL RzSearchOpt *opt, RZ_OWN RzSearchFindOpt *find_opts);

RZ_API RZ_OWN RzSearchFindOpt *rz_search_find_opt_new();
RZ_API void rz_search_find_opt_free(RZ_NULLABLE RzSearchFindOpt *opt);
RZ_API bool rz_search_find_opt_set_inverse_match(RZ_NONNULL RzSearchFindOpt *opt, bool inverse_match);
RZ_API bool rz_search_find_opt_set_overlap_match(RZ_NONNULL RzSearchFindOpt *opt, bool overlap_match);
RZ_API bool rz_search_find_opt_set_alignment(RZ_NONNULL RzSearchFindOpt *opt, size_t alignment);

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_aes_keys();

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_private_keys();

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_bytes();
RZ_API bool rz_search_collection_bytes_add(RZ_NONNULL RzSearchCollection *col, RZ_NULLABLE const char *pattern_desc, RZ_NONNULL const ut8 *bytes, RZ_NULLABLE const ut8 *mask, size_t length);
RZ_API bool rz_search_collection_bytes_add_pattern(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL RZ_OWN RzSearchBytesPattern *bytes_pattern);

RZ_API RZ_OWN RzSearchCollection *rz_search_collection_strings(RZ_NONNULL RzUtilStrScanOptions *opts, RzStrEnc expected, RzRegexFlags re_flags);
RZ_API bool rz_search_collection_string_add(RZ_NONNULL RzSearchCollection *col, RZ_NONNULL const char *regex_pattern, RzRegexFlags re_flags);

RZ_API bool rz_search_collection_match_any(RZ_NULLABLE RzSearchCollection *sc, RZ_NONNULL const ut8 *buffer, size_t length);
RZ_API void rz_search_collection_free(RZ_NULLABLE RzSearchCollection *sc);

RZ_API RZ_OWN RzList /*<RzSearchHit *>*/ *rz_search_on_io(RZ_BORROW RZ_NONNULL RzSearchOpt *opt, RZ_BORROW RZ_NONNULL RzSearchCollection *col, RZ_BORROW RZ_NONNULL RzIO *io, RZ_BORROW RZ_NONNULL RzList /*<RzIOMap *>*/ *search_in);

#ifdef __cplusplus
}
#endif

#endif
