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

typedef enum {
	RZ_SEARCH_MODE_PATTERN = 0,
	RZ_SEARCH_MODE_KEYWORD,
	RZ_SEARCH_MODE_REGEXP,
	RZ_SEARCH_MODE_STRING,
	RZ_SEARCH_MODE_XREFS,
	RZ_SEARCH_MODE_AES,
	RZ_SEARCH_MODE_PRIV_KEY,
	RZ_SEARCH_MODE_DELTAKEY,
	RZ_SEARCH_MODE_MAGIC,
	RZ_SEARCH_MODE_ESIL,
	/* enum size */
	RZ_SEARCH_MODE_LAST
} rz_search_mode;

#define RZ_SEARCH_DISTANCE_MAX       10
#define RZ_SEARCH_DEFAULT_STRING_MAX 255
#define RZ_SEARCH_DEFAULT_STRING_MIN 3

#define RZ_SEARCH_AES_LENGTH         40
#define RZ_SEARCH_PRIVATE_KEY_LENGTH 11

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

typedef struct rz_search_hit_t {
	RzSearchKeyword *kw;
	ut64 addr;
} RzSearchHit;

typedef bool (*RzSearchCallback)(RzSearchKeyword *kw, void *user, ut64 where);

typedef struct rz_search_t {
	// internal data structures.
	RzIOBind iob; ///< RzIO bindings
	void *data; ///< Pointer to data owned by search algorithm
	int (*update)(struct rz_search_t *s, ut64 from, const ut8 *buf, int len);

	// User defined functions.
	void *user; ///< Pointer to user data passed to callback
	RzSearchCallback callback; ///< Callback called on hit

	// variables
	int n_kws; ///< Counter used to define the number of keywords in list hit${n_kws}_${nhits}
	RzList /*<RzSearchKeyword *>*/ *kws; ///< List of keywords matched.
	ut64 nhits; ///< Number of hits from last search.
	RzList /*<RzSearchHit *>*/ *hits; ///< List of matches.
	int prelude_counter; ///< Prelude counter

	// options
	rz_search_mode mode; ///< Search mode
	ut32 string_min; ///< Max length of strings for RZ_SEARCH_MODE_STRING
	ut32 string_max; ///< Min length of strings for RZ_SEARCH_MODE_STRING
	ut64 maxhits; ///< Maximum number of hits (0: no limit)
	ut32 distance; ///< Max distance between matches.
	bool overlap; ///< When true, looks for overlapped search hits.
	bool contiguous; ///< When true, accepts contiguous/adjacent search hits.
	ut64 align; ///< Address alignment required to perform the search.
	bool backwards; ///< When true, preforms the search backwards.
	ut64 from_addr; ///< Begin search address
	ut64 to_addr; ///< End search address
	char *prefix; ///< Name prefix to use on new flags on hit
	char *command; ///< Command to execute on hit
	bool show; ///< When true, shows all the matches details.

	// unknown
	ut32 pattern_size; ///< ?????
	bool inverse; ///< ?????
	bool flags; ///< ?????
} RzSearch;

#ifdef RZ_API

#define RZ_SEARCH_AES_BOX_SIZE 31

RZ_API bool rz_search_init(RZ_NONNULL RzSearch *s);
RZ_API void rz_search_fini(RZ_NONNULL RzSearch *s);
RZ_API RZ_OWN RzSearch *rz_search_new(rz_search_mode mode);
RZ_API void rz_search_free(RZ_NULLABLE RzSearch *s);

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
RZ_API void rz_search_reset(RZ_NONNULL RzSearch *s, rz_search_mode mode);
RZ_API void rz_search_kw_reset(RZ_NONNULL RzSearch *s);
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
RZ_API int rz_search_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr);

RZ_API bool rz_search_set_mode(RZ_NONNULL RzSearch *s, rz_search_mode mode);
RZ_API bool rz_search_set_pattern_size(RZ_NONNULL RzSearch *s, ut32 pattern_size);
RZ_API bool rz_search_set_string_limits(RZ_NONNULL RzSearch *s, ut32 min, ut32 max);
RZ_API bool rz_search_set_maxhits(RZ_NONNULL RzSearch *s, ut64 maxhits);
RZ_API bool rz_search_set_distance(RZ_NONNULL RzSearch *s, ut32 distance);
RZ_API bool rz_search_set_inverse(RZ_NONNULL RzSearch *s, bool inverse);
RZ_API bool rz_search_set_overlap(RZ_NONNULL RzSearch *s, bool overlap);
RZ_API bool rz_search_set_contiguous(RZ_NONNULL RzSearch *s, bool contiguous);
RZ_API bool rz_search_set_align(RZ_NONNULL RzSearch *s, ut64 align);
RZ_API bool rz_search_set_backwards(RZ_NONNULL RzSearch *s, bool backwards);
RZ_API bool rz_search_set_flags(RZ_NONNULL RzSearch *s, bool flags);
RZ_API bool rz_search_set_show(RZ_NONNULL RzSearch *s, bool show);
RZ_API bool rz_search_set_from_addr(RZ_NONNULL RzSearch *s, ut64 from_addr);
RZ_API bool rz_search_set_to_addr(RZ_NONNULL RzSearch *s, ut64 to_addr);
RZ_API bool rz_search_set_prefix(RZ_NONNULL RzSearch *s, RZ_NULLABLE const char *prefix);
RZ_API bool rz_search_set_command(RZ_NONNULL RzSearch *s, RZ_NULLABLE const char *command);
RZ_API bool rz_search_set_callback(RZ_NONNULL RzSearch *s, RZ_NULLABLE RzSearchCallback(callback), RZ_NULLABLE void *user);

RZ_API int rz_search_begin(RzSearch *s);

/* pattern search */
RZ_API int rz_search_pattern(RzSearch *s, ut64 from, ut64 to);

#ifdef __cplusplus
}
#endif

#endif
#endif
