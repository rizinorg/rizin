#ifndef R2_SIGN_H
#define R2_SIGN_H

#include <rz_types.h>
#include <rz_anal.h>
#include <rz_search.h>

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(rz_sign);

// XXX those limits should go away
#define R_SIGN_KEY_MAXSZ 1024
#define R_SIGN_VAL_MAXSZ 10240

#define ZIGN_HASH "sha256"
#define R_ZIGN_HASH R_HASH_SHA256

typedef enum {
	R_SIGN_BYTES     = 'b', // bytes pattern
	R_SIGN_BYTES_MASK= 'm', // bytes pattern
	R_SIGN_BYTES_SIZE= 's', // bytes pattern
	R_SIGN_ANAL      = 'a', // bytes pattern (anal mask) // wtf ?
	R_SIGN_COMMENT   = 'c', // comment
	R_SIGN_GRAPH     = 'g', // graph metrics
	R_SIGN_OFFSET    = 'o', // addr
	R_SIGN_NAME      = 'n', // real name
	R_SIGN_REFS      = 'r', // references
	R_SIGN_XREFS     = 'x', // xrefs
	R_SIGN_VARS      = 'v', // variables
	R_SIGN_TYPES     = 't', // types
	R_SIGN_BBHASH    = 'h', // basic block hash
} RzSignType;

typedef struct rz_sign_graph_t {
	int cc;
	int nbbs;
	int edges;
	int ebbs;
	int bbsum;
} RzSignGraph;

typedef struct rz_sign_bytes_t {
	int size;
	ut8 *bytes;
	ut8 *mask;
} RzSignBytes;

typedef struct rz_sign_hash_t {
	char *bbhash;
} RzSignHash;

typedef struct rz_sign_item_t {
	char *name;
	char *realname;
	char *comment;
	const RSpace *space;

	RzSignBytes *bytes;
	RzSignGraph *graph;
	ut64 addr;
	RzList *refs;
	RzList *xrefs;
	RzList *vars;
	RzList *types;
	RzSignHash *hash;
} RzSignItem;

typedef int (*RzSignForeachCallback)(RzSignItem *it, void *user);
typedef int (*RzSignSearchCallback)(RzSignItem *it, RzSearchKeyword *kw, ut64 addr, void *user);
typedef int (*RzSignGraphMatchCallback)(RzSignItem *it, RzAnalFunction *fcn, void *user);
typedef int (*RzSignOffsetMatchCallback)(RzSignItem *it, RzAnalFunction *fcn, void *user);
typedef int (*RzSignHashMatchCallback)(RzSignItem *it, RzAnalFunction *fcn, void *user);
typedef int (*RzSignRefsMatchCallback)(RzSignItem *it, RzAnalFunction *fcn, void *user);
typedef int (*RzSignVarsMatchCallback)(RzSignItem *it, RzAnalFunction *fcn, void *user);

typedef struct rz_sign_search_t {
	RzSearch *search;
	RzList *items;
	RzSignSearchCallback cb;
	void *user;
} RzSignSearch;

typedef struct rz_sign_options_t {
	double bytes_diff_threshold;
	double graph_diff_threshold;
} RzSignOptions;

typedef struct {
	double score;
	double bscore;
	double gscore;
	RzSignItem *item;
} RzSignCloseMatch;

#ifdef RZ_API
RZ_API bool rz_sign_add_bytes(RzAnal *a, const char *name, ut64 size, const ut8 *bytes, const ut8 *mask);
RZ_API bool rz_sign_add_anal(RzAnal *a, const char *name, ut64 size, const ut8 *bytes, ut64 at);
RZ_API bool rz_sign_add_graph(RzAnal *a, const char *name, RzSignGraph graph);
RZ_API bool rz_sign_addto_item(RzAnal *a, RzSignItem *it, RzAnalFunction *fcn, RzSignType type);
RZ_API bool rz_sign_add_addr(RzAnal *a, const char *name, ut64 addr);
RZ_API bool rz_sign_add_name(RzAnal *a, const char *name, const char *realname);
RZ_API bool rz_sign_add_comment(RzAnal *a, const char *name, const char *comment);
RZ_API bool rz_sign_add_refs(RzAnal *a, const char *name, RzList *refs);
RZ_API bool rz_sign_add_xrefs(RzAnal *a, const char *name, RzList *xrefs);
RZ_API bool rz_sign_add_vars(RzAnal *a, const char *name, RzList *vars);
RZ_API bool rz_sign_add_types(RzAnal *a, const char *name, RzList *vars);
RZ_API bool rz_sign_delete(RzAnal *a, const char *name);
RZ_API void rz_sign_list(RzAnal *a, int format);
RZ_API RzList *rz_sign_get_list(RzAnal *a);
RZ_API bool rz_sign_add_hash(RzAnal *a, const char *name, int type, const char *val, int len);
RZ_API bool rz_sign_add_bb_hash(RzAnal *a, RzAnalFunction *fcn, const char *name);
RZ_API char *rz_sign_calc_bbhash(RzAnal *a, RzAnalFunction *fcn);
RZ_API bool rz_sign_deserialize(RzAnal *a, RzSignItem *it, const char *k, const char *v);
RZ_API RzSignItem *rz_sign_get_item(RzAnal *a, const char *name);
RZ_API bool rz_sign_add_item(RzAnal *a, RzSignItem *it);

RZ_API bool rz_sign_foreach(RzAnal *a, RzSignForeachCallback cb, void *user);

RZ_API RzSignSearch *rz_sign_search_new(void);
RZ_API void rz_sign_search_free(RzSignSearch *ss);
RZ_API void rz_sign_search_init(RzAnal *a, RzSignSearch *ss, int minsz, RzSignSearchCallback cb, void *user);
RZ_API int rz_sign_search_update(RzAnal *a, RzSignSearch *ss, ut64 *at, const ut8 *buf, int len);
RZ_API bool rz_sign_match_graph(RzAnal *a, RzAnalFunction *fcn, int mincc, RzSignGraphMatchCallback cb, void *user);
RZ_API bool rz_sign_match_addr(RzAnal *a, RzAnalFunction *fcn, RzSignOffsetMatchCallback cb, void *user);
RZ_API bool rz_sign_match_hash(RzAnal *a, RzAnalFunction *fcn, RzSignHashMatchCallback cb, void *user);
RZ_API bool rz_sign_match_refs(RzAnal *a, RzAnalFunction *fcn, RzSignRefsMatchCallback cb, void *user);
RZ_API bool rz_sign_match_vars(RzAnal *a, RzAnalFunction *fcn, RzSignRefsMatchCallback cb, void *user);
RZ_API bool rz_sign_match_types(RzAnal *a, RzAnalFunction *fcn, RzSignRefsMatchCallback cb, void *user);

RZ_API bool rz_sign_load(RzAnal *a, const char *file);
RZ_API bool rz_sign_load_gz(RzAnal *a, const char *filename);
RZ_API char *rz_sign_path(RzAnal *a, const char *file);
RZ_API bool rz_sign_save(RzAnal *a, const char *file);

RZ_API RzSignItem *rz_sign_item_new(void);
RZ_API void rz_sign_item_free(RzSignItem *item);
RZ_API void rz_sign_graph_free(RzSignGraph *graph);
RZ_API void rz_sign_bytes_free(RzSignBytes *bytes);

RZ_API RzList *rz_sign_fcn_refs(RzAnal *a, RzAnalFunction *fcn);
RZ_API RzList *rz_sign_fcn_xrefs(RzAnal *a, RzAnalFunction *fcn);
RZ_API RzList *rz_sign_fcn_vars(RzAnal *a, RzAnalFunction *fcn);
RZ_API RzList *rz_sign_fcn_types(RzAnal *a, RzAnalFunction *fcn);

RZ_API int rz_sign_is_flirt(RBuffer *buf);
RZ_API void rz_sign_flirt_dump(const RzAnal *anal, const char *flirt_file);
RZ_API void rz_sign_flirt_scan(RzAnal *anal, const char *flirt_file);

RZ_API RzList *rz_sign_find_closest_sig(RzAnal *a, RzSignItem *it, int count, double score_threshold);
RZ_API RzList *rz_sign_find_closest_fcn(RzAnal *a, RzSignItem *it, int count, double score_threshold);
RZ_API void rz_sign_close_match_free(RzSignCloseMatch *match);
RZ_API bool rz_sign_diff(RzAnal *a, RzSignOptions *options, const char *other_space_name);
RZ_API bool rz_sign_diff_by_name(RzAnal *a, RzSignOptions *options, const char *other_space_name, bool not_matching);

RZ_API RzSignOptions *rz_sign_options_new(const char *bytes_thresh, const char *graph_thresh);
RZ_API void rz_sign_options_free(RzSignOptions *options);
#endif

#ifdef __cplusplus
}
#endif

#endif
