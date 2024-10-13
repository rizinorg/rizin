#ifndef RZ_CONFIG_H
#define RZ_CONFIG_H

#include "rz_types.h"
#include "rz_util.h"
#include "rz_util/rz_serialize.h"

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_config);

#define CN_BOOL 0x000001
#define CN_INT  0x000002
// NOTE: removed because this is redundant and it does not add any value
//       compared to CN_INT. Use that instead for consistency
// #define CN_OFFT  0x000004
#define CN_STR 0x000008
#define CN_RO  0x000010
#define CN_RW  0x000020

#define NODECB(w, x, y)    rz_config_set_cb(cfg, w, x, y)
#define NODEICB(w, x, y)   rz_config_set_i_cb(cfg, w, x, y)
#define SETDESC(x, y)      rz_config_node_desc(x, y)
#define SETOPTIONS(x, ...) set_options(x, __VA_ARGS__)
#define SETI(x, y, z)      SETDESC(rz_config_set_i(cfg, x, y), z)
#define SETB(x, y, z)      SETDESC(rz_config_set_b(cfg, x, y), z)
#define SETICB(w, x, y, z) SETDESC(NODEICB(w, x, y), z)
#define SETPREF(x, y, z)   SETDESC(rz_config_set(cfg, x, y), z)
#define SETCB(w, x, y, z)  SETDESC(NODECB(w, x, y), z)
#define SETBPREF(x, y, z)  SETDESC(NODECB(x, y, boolify_var_cb), z)

typedef bool (*RzConfigCallback)(void *user, void *data);

typedef struct rz_config_node_t {
	char *name;
	int flags;
	char *value;
	ut64 i_value;
	ut64 *cb_ptr_q;
	int *cb_ptr_i;
	char **cb_ptr_s;
	RzConfigCallback getter;
	RzConfigCallback setter;
	char *desc;
	RzList /*<char *>*/ *options;
} RzConfigNode;

RZ_API const char *rz_config_node_type(RzConfigNode *node);

typedef struct rz_config_t {
	int lock;
	void *user;
	RzNum *num;
	RzList /*<RzConfigNode *>*/ *nodes;
	HtSP *ht;
} RzConfig;

typedef struct rz_config_hold_num_t {
	char *key;
	ut64 value;
} RzConfigHoldNum;

typedef struct rz_config_hold_char_t {
	char *key;
	char *value;
} RzConfigHoldChar;

typedef struct rz_config_hold_t {
	RzConfig *cfg;
	RzList /*<RzConfigHoldNum *>*/ *list_num; // holds numeric values
	RzList /*<RzConfigHoldChar *>*/ *list_char; // holds char values
} RzConfigHold;

#ifdef RZ_API
RZ_API RzConfigHold *rz_config_hold_new(RzConfig *cfg);
RZ_API void rz_config_hold_free(RzConfigHold *h);

RZ_API bool rz_config_hold_i(RzConfigHold *h, ...);
RZ_API bool rz_config_hold_s(RzConfigHold *h, ...);

RZ_API void rz_config_hold_restore(RzConfigHold *h);

RZ_API RZ_OWN RzConfig *rz_config_new(RZ_BORROW void *user);
RZ_API RZ_OWN RzConfig *rz_config_clone(RZ_BORROW RzConfig *cfg);
RZ_API void rz_config_free(RZ_OWN RzConfig *cfg);
RZ_API void rz_config_lock(RZ_BORROW RzConfig *cfg, int l);
RZ_API void rz_config_bump(RZ_BORROW RzConfig *cfg, const char *key);
RZ_API RZ_BORROW RzConfigNode *rz_config_set_i(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, const ut64 i);
RZ_API RZ_BORROW RzConfigNode *rz_config_set_b(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, bool value);
RZ_API RZ_BORROW RzConfigNode *rz_config_set_cb(RZ_BORROW RzConfig *cfg, const char *name, const char *value, bool (*callback)(void *user, void *data));
RZ_API RZ_BORROW RzConfigNode *rz_config_set_i_cb(RZ_BORROW RzConfig *cfg, const char *name, int ivalue, bool (*callback)(void *user, void *data));
RZ_API RZ_BORROW RzConfigNode *rz_config_set(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, const char *value);
RZ_API bool rz_config_add_node(RZ_BORROW RzConfig *cfg, RZ_OWN RzConfigNode *node);
RZ_API bool rz_config_rm(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API ut64 rz_config_get_i(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API bool rz_config_get_b(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API RZ_BORROW const char *rz_config_get(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API const char *rz_config_desc(RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc);
RZ_API const char *rz_config_node_desc(RzConfigNode *node, RZ_NULLABLE const char *desc);
RZ_API RZ_BORROW RzConfigNode *rz_config_node_get(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API RZ_OWN RzConfigNode *rz_config_node_new(RZ_NONNULL const char *name, RZ_NONNULL const char *value);
RZ_API RZ_OWN RzConfigNode *rz_config_node_clone(RZ_BORROW RzConfigNode *n);
RZ_API void rz_config_node_free(RZ_NULLABLE void *n);
RZ_API void rz_config_node_value_format_i(RZ_OUT char *buf, size_t buf_size, const ut64 i, RZ_NULLABLE RzConfigNode *node);
RZ_API bool rz_config_toggle(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API bool rz_config_readonly(RZ_BORROW RzConfig *cfg, const char *key);
RZ_API bool rz_config_eval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *str);

RZ_API bool rz_config_set_setter(RzConfig *cfg, const char *key, RzConfigCallback cb);
RZ_API bool rz_config_set_getter(RzConfig *cfg, const char *key, RzConfigCallback cb);

RZ_API void rz_config_serialize(RZ_NONNULL RzConfig *config, RZ_NONNULL Sdb *db);
RZ_API bool rz_config_unserialize(RZ_NONNULL RzConfig *config, RZ_NONNULL Sdb *db, RZ_NULLABLE char **err);

static inline bool rz_config_node_is_bool(RzConfigNode *node) {
	return node->flags & CN_BOOL;
}
static inline bool rz_config_node_is_int(RzConfigNode *node) {
	return node->flags & CN_INT;
}
static inline bool rz_config_node_is_ro(RzConfigNode *node) {
	return node->flags & CN_RO;
}
static inline bool rz_config_node_is_str(RzConfigNode *node) {
	return node->flags & CN_STR;
}

/* serialize */

RZ_API void rz_serialize_config_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config);
RZ_API bool rz_serialize_config_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config,
	RZ_NULLABLE const char *const *exclude, RZ_NULLABLE RzSerializeResultInfo *res);
#endif

#ifdef __cplusplus
}
#endif

#endif
