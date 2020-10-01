#ifndef R2_CONFIG_H
#define R2_CONFIG_H

#include "rz_types.h"
#include "rz_util.h"

#ifdef __cplusplus
extern "C" {
#endif

R_LIB_VERSION_HEADER(rz_config);

#define CN_BOOL  0x000001
#define CN_INT   0x000002
// NOTE: removed because this is redundant and it does not add any value
//       compared to CN_INT. Use that instead for consistency
// #define CN_OFFT  0x000004
#define CN_STR   0x000008
#define CN_RO    0x000010
#define CN_RW    0x000020

typedef bool (*RConfigCallback)(void *user, void *data);

typedef struct rz_config_node_t {
	char *name;
	int flags;
	char *value;
	ut64 i_value;
	ut64 *cb_ptr_q;
	int *cb_ptr_i;
	char **cb_ptr_s;
	RConfigCallback getter;
	RConfigCallback setter;
	char *desc;
	RzList *options;
} RConfigNode;

RZ_API const char *rz_config_node_type(RConfigNode *node);

typedef struct rz_config_t {
	int lock;
	void *user;
	RNum *num;
	PrintfCallback cb_printf;
	RzList *nodes;
	HtPP *ht;
} RConfig;

typedef struct rz_config_hold_num_t {
	char *key;
	ut64 value;
} RConfigHoldNum;

typedef struct rz_config_hold_char_t {
	char *key;
	char *value;
} RConfigHoldChar;

typedef struct rz_config_hold_t { 
	RConfig *cfg;
	RzList *list_num; //list of RConfigHoldNum to hold numeric values 
	RzList *list_char; //list of RConfigHoldChar to hold char values
} RConfigHold;

#ifdef RZ_API
RZ_API RConfigHold* rz_config_hold_new(RConfig *cfg);
RZ_API void rz_config_hold_free(RConfigHold *h);

RZ_API bool rz_config_hold_i(RConfigHold *h, ...);
RZ_API bool rz_config_hold_s(RConfigHold *h, ...);

RZ_API void rz_config_hold_restore(RConfigHold *h);

RZ_API RConfig *rz_config_new(void *user);
RZ_API RConfig *rz_config_clone (RConfig *cfg);
RZ_API void rz_config_free(RConfig *cfg);
RZ_API void rz_config_lock(RConfig *cfg, int l);
RZ_API bool rz_config_eval(RConfig *cfg, const char *str, bool many);
RZ_API void rz_config_bump(RConfig *cfg, const char *key);
RZ_API RConfigNode *rz_config_set_i(RConfig *cfg, const char *name, const ut64 i);
RZ_API RConfigNode *rz_config_set_cb(RConfig *cfg, const char *name, const char *value, bool (*callback)(void *user, void *data));
RZ_API RConfigNode *rz_config_set_i_cb(RConfig *cfg, const char *name, int ivalue, bool (*callback)(void *user, void *data));
RZ_API RConfigNode *rz_config_set(RConfig *cfg, const char *name, const char *value);
RZ_API bool rz_config_rm(RConfig *cfg, const char *name);
RZ_API ut64 rz_config_get_i(RConfig *cfg, const char *name);
RZ_API const char *rz_config_get(RConfig *cfg, const char *name);
RZ_API const char *rz_config_desc(RConfig *cfg, const char *name, const char *desc);
RZ_API const char *rz_config_node_desc(RConfigNode *node, const char *desc);
RZ_API void rz_config_list(RConfig *cfg, const char *str, int rad);
RZ_API RConfigNode *rz_config_node_get(RConfig *cfg, const char *name);
RZ_API RConfigNode *rz_config_node_new(const char *name, const char *value);
RZ_API void rz_config_node_free(void *n);
RZ_API void rz_config_node_value_format_i(char *buf, size_t buf_size, const ut64 i, R_NULLABLE RConfigNode *node);
RZ_API bool rz_config_toggle(RConfig *cfg, const char *name);
RZ_API bool rz_config_readonly (RConfig *cfg, const char *key);

RZ_API void rz_config_set_sort_column (char *column);
RZ_API bool rz_config_set_setter (RConfig *cfg, const char *key, RConfigCallback cb);
RZ_API bool rz_config_set_getter (RConfig *cfg, const char *key, RConfigCallback cb);

RZ_API void rz_config_serialize(R_NONNULL RConfig *config, R_NONNULL Sdb *db);
RZ_API bool rz_config_unserialize(R_NONNULL RConfig *config, R_NONNULL Sdb *db, R_NULLABLE char **err);

static inline bool rz_config_node_is_bool(RConfigNode *node) {
	return node->flags & CN_BOOL;
}
static inline bool rz_config_node_is_int(RConfigNode *node) {
	return node->flags & CN_INT;
}
static inline bool rz_config_node_is_ro(RConfigNode *node) {
	return node->flags & CN_RO;
}
static inline bool rz_config_node_is_str(RConfigNode *node) {
	return node->flags & CN_STR;
}
#endif

#ifdef __cplusplus
}
#endif

#endif
