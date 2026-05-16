// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-FileCopyrightText: 2006-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

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
#define CN_STR  0x000008
#define CN_RO   0x000010

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
	RzConfigCallback setter;
	char *desc;
	RzList /*<char *>*/ *options;
} RzConfigNode;

typedef enum {
	RZ_CONFIG_VAR_TYPE_NONE = 0,
	// these are types
	RZ_CONFIG_VAR_TYPE_BOOL = 1,
	RZ_CONFIG_VAR_TYPE_INT = 2,
	RZ_CONFIG_VAR_TYPE_STR = 3,
	RZ_CONFIG_VAR_TYPE_LIST = 4,
	RZ_CONFIG_VAR_TYPE_ITV = 5,
	// these are flags
	RZ_CONFIG_VAR_FLAG_BIND = 0x40000000,
	RZ_CONFIG_VAR_FLAG_WRITABLE = 0x80000000,
} RzConfigVarFlags;

#define RZ_CONFIG_VAR_TYPE_MASK  0x0000ffff
#define RZ_CONFIG_VAR_FLAGS_MASK 0xffff0000

#define RZ_CONFIG_VAR_IS_TYPE(flags, expected)  (((flags) & RZ_CONFIG_VAR_TYPE_MASK) == (expected))
#define RZ_CONFIG_VAR_HAS_FLAG(flags, expected) (((flags) & RZ_CONFIG_VAR_FLAGS_MASK) & (expected))

typedef bool (*RzConfigBindGet)(void *user, void *value);
typedef bool (*RzConfigBindSet)(void *user, const void *value);
typedef bool (*RzConfigBindOpts)(void *user, RzList /*<char *>*/ **options);

typedef struct rz_config_owned_t {
	union {
		bool boolean; ///< Owned boolean
		ut64 integer; ///< Owned unsigned integer
		char *string; ///< Owned zero-terminated string (can be NULL)
		RzList /*<char *>*/ *list; ///< Owned list of zero-terminated string (can be NULL)
		RzInterval interval; ///< Owned interval
	};
	RzConfigBindSet validator; ///< Validator callback
	void *validator_user; ///< Validator callback user pointer
} RzConfigOwned;

typedef struct rz_config_bind_t {
	void *user;
	RzConfigBindGet get_value;
	RzConfigBindSet set_value;
	RzConfigBindOpts get_options;
} RzConfigBind;

typedef struct rz_config_var_t {
	char *name; ///< Variable name
	char *desc; ///< Description of the variable
	RzList /*<char *>*/ *options; ///< Variable possible values
	ut32 flags; ///< Define the type of the data via RzConfigVar (see RzConfigVarFlags)
	union {
		RzConfigOwned value; ///< owned value
		RzConfigBind bind; ///< bind value
	};
} RzConfigVar;

typedef struct rz_config_entry_t {
	bool is_variable;
	union {
		RzConfigVar var;
		RzConfigNode node;
	};
} RzConfigEntry;

typedef struct rz_config_t {
	void *user; ///< DEPRECATED
	RzVector /*<RzConfigEntry>*/ sorted_vars; ///< Sorted owned variables
} RzConfig;

typedef struct rz_config_hold_t RzConfigHold;
typedef bool (*RzConfigIterator)(const RzConfigEntry *entry, void *user);

#ifdef RZ_API

RZ_API bool rz_config_hold_var(RZ_NONNULL RzConfigHold *hold, ...);
RZ_API RzConfigHold *rz_config_hold_new(RZ_NONNULL RzConfig *cfg);
RZ_API RzConfigHold *rz_config_hold_new2(RZ_NONNULL RzConfig *cfg, ...);
RZ_API void rz_config_hold_restore(RZ_NULLABLE RzConfigHold *hold);
RZ_API void rz_config_hold_free(RZ_NULLABLE RzConfigHold *h);
RZ_API void rz_config_hold_restore_and_free(RZ_NULLABLE RzConfigHold *hold);

RZ_API RZ_OWN RzConfig *rz_config_new(RZ_DEPRECATE RZ_BORROW void *user);
RZ_API void rz_config_free(RZ_NULLABLE RzConfig *cfg);

RZ_API bool rz_config_set_readonly(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, bool read_only);
RZ_API bool rz_config_is_readonly(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API void rz_config_iterate_over(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL RzConfigIterator iterator, RZ_NULLABLE void *user);

RZ_API bool rz_config_add_bool(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, bool value);
RZ_API bool rz_config_add_integer(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ut64 value);
RZ_API bool rz_config_add_string(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, RZ_NULLABLE const char *value);
RZ_API bool rz_config_add_options(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ...);
RZ_API bool rz_config_add_list(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ...);
RZ_API bool rz_config_add_interval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ut64 from, ut64 to);

RZ_API bool rz_config_add_bind(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ut32 type, RZ_NONNULL RzConfigBindGet get, RZ_NULLABLE RzConfigBindSet set, RZ_NULLABLE RzConfigBindOpts opts, RZ_NULLABLE void *user);
#define rz_config_add_bool_bind(cfg, name, desc, get, set, opts, user)     rz_config_add_bind(cfg, name, desc, RZ_CONFIG_VAR_TYPE_BOOL, get, set, opts, user)
#define rz_config_add_integer_bind(cfg, name, desc, get, set, opts, user)  rz_config_add_bind(cfg, name, desc, RZ_CONFIG_VAR_TYPE_INT, get, set, opts, user)
#define rz_config_add_string_bind(cfg, name, desc, get, set, opts, user)   rz_config_add_bind(cfg, name, desc, RZ_CONFIG_VAR_TYPE_STR, get, set, opts, user)
#define rz_config_add_list_bind(cfg, name, desc, get, set, opts, user)     rz_config_add_bind(cfg, name, desc, RZ_CONFIG_VAR_TYPE_LIST, get, set, opts, user)
#define rz_config_add_interval_bind(cfg, name, desc, get, set, opts, user) rz_config_add_bind(cfg, name, desc, RZ_CONFIG_VAR_TYPE_ITV, get, set, opts, user)

RZ_API bool rz_config_set_string(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *value);
RZ_API bool rz_config_set_integer(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ut64 value);
RZ_API bool rz_config_set_bool(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, bool value);
RZ_API bool rz_config_toggle_bool(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API bool rz_config_set_list(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const RzList /*<const char *>*/ *value);
RZ_API bool rz_config_set_list2(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ...);
RZ_API bool rz_config_set_list3(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *comma_list);
RZ_API bool rz_config_set_interval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RzInterval value);
RZ_API bool rz_config_set_interval2(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ut64 from, ut64 to);
RZ_API bool rz_config_set_interval3(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *comma_itv);
RZ_API bool rz_config_set_any(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *value);
RZ_API bool rz_config_set_options(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE RZ_OWN RzList /*<char *>*/ *options);
RZ_API bool rz_config_set_options2(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ...);
RZ_API bool rz_config_set_validator(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE RzConfigBindSet validator, RZ_NULLABLE void *user);

RZ_API bool rz_config_get_bool(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API ut64 rz_config_get_integer(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API const char *rz_config_get_string(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API RZ_OWN RzList /*<const char *>*/ *rz_config_get_list(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API RzInterval rz_config_get_interval(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);

RZ_API RZ_OWN char *rz_config_get_as_string(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API const RzList /*<char *>*/ *rz_config_get_options(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API ut32 rz_config_get_flags(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name);

RZ_API bool rz_config_var_as_json(RZ_NONNULL const RzConfigVar *var, RZ_NONNULL PJ *pj, RZ_NONNULL const char *key);
RZ_API RZ_OWN char *rz_config_var_as_string(RZ_NONNULL const RzConfigVar *var);
RZ_API bool rz_config_var_is_readonly(RZ_NONNULL const RzConfigVar *var);
RZ_API bool rz_config_var_get_bool(RZ_NONNULL const RzConfigVar *var);
RZ_API ut64 rz_config_var_get_integer(RZ_NONNULL const RzConfigVar *var);
RZ_API const char *rz_config_var_get_string(RZ_NONNULL const RzConfigVar *var);
RZ_API RZ_OWN RzList /*<const char *>*/ *rz_config_var_get_list(RZ_NONNULL const RzConfigVar *var);
RZ_API RzInterval rz_config_var_get_interval(RZ_NONNULL const RzConfigVar *var);
RZ_API bool rz_config_var_has_type(RZ_NONNULL const RzConfigVar *var, ut32 etype);
RZ_API bool rz_config_var_has_flags(RZ_NONNULL const RzConfigVar *var, ut32 eflags);
RZ_API RZ_OWN char *rz_config_var_flags_as_string(ut32 flags);
RZ_API ut32 rz_config_var_get_flags(RZ_NONNULL const RzConfigVar *var);
RZ_API const char *rz_config_var_get_name(RZ_NONNULL const RzConfigVar *var);
RZ_API const char *rz_config_var_get_desc(RZ_NONNULL const RzConfigVar *var);
RZ_API const RzList /*<char *>*/ *rz_config_var_get_options(RZ_NONNULL const RzConfigVar *var);

/* to deprecate */
RZ_API const char *rz_config_entry_get_name(RZ_NONNULL const RzConfigEntry *entry);
RZ_API const char *rz_config_entry_get_desc(RZ_NONNULL const RzConfigEntry *entry);

RZ_API ut64 rz_config_entry_get_integer(RZ_NONNULL const RzConfigEntry *entry);
RZ_API bool rz_config_entry_get_bool(RZ_NONNULL const RzConfigEntry *entry);
RZ_API const char *rz_config_entry_get_string(RZ_NONNULL const RzConfigEntry *entry);
RZ_API RZ_OWN char *rz_config_entry_get_as_string(RZ_NONNULL const RzConfigEntry *entry);

/* old apis, deprecated */

RZ_API const char *rz_config_node_type(RzConfigNode *node);
RZ_DEPRECATE RZ_API void rz_config_lock(RZ_BORROW RzConfig *cfg, int l);
RZ_API RZ_BORROW RzConfigNode *rz_config_set_i(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, const ut64 i);
RZ_API RZ_BORROW RzConfigNode *rz_config_set_b(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, bool value);
RZ_API RZ_BORROW RzConfigNode *rz_config_set_cb(RZ_BORROW RzConfig *cfg, const char *name, const char *value, bool (*callback)(void *user, void *data));
RZ_API RZ_BORROW RzConfigNode *rz_config_set_i_cb(RZ_BORROW RzConfig *cfg, const char *name, st64 ivalue, bool (*callback)(void *user, void *data));
RZ_API RZ_BORROW RzConfigNode *rz_config_set(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name, const char *value);
RZ_API ut64 rz_config_get_i(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API bool rz_config_get_b(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API RZ_BORROW const char *rz_config_get(RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API const char *rz_config_desc(RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc);
RZ_API const char *rz_config_node_desc(RzConfigNode *node, RZ_NULLABLE const char *desc);
RZ_API RZ_BORROW RzConfigNode *rz_config_node_get(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API void rz_config_node_value_format_i(RZ_OUT char *buf, size_t buf_size, const ut64 i, RZ_NULLABLE RzConfigNode *node);
RZ_API bool rz_config_toggle(RZ_BORROW RzConfig *cfg, RZ_NONNULL const char *name);
RZ_API bool rz_config_eval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *str);
RZ_API ut32 rz_config_node_get_var_flags(RZ_NONNULL const RzConfigNode *node);

static inline bool rz_config_node_is_bool(const RzConfigNode *node) {
	return node->flags & CN_BOOL;
}

static inline bool rz_config_node_is_int(const RzConfigNode *node) {
	return node->flags & CN_INT;
}

static inline bool rz_config_node_is_ro(const RzConfigNode *node) {
	return node->flags & CN_RO;
}

static inline bool rz_config_node_is_str(const RzConfigNode *node) {
	return node->flags & CN_STR;
}

/* serialize */

RZ_API void rz_serialize_config_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config);
RZ_API bool rz_serialize_config_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzConfig *config, RZ_NULLABLE const char **exclude);
#endif

#ifdef __cplusplus
}
#endif

#endif
