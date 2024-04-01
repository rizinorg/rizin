#ifndef RZ_FLAGS_H
#define RZ_FLAGS_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_skiplist.h>
#include <rz_util/rz_serialize.h>

#ifdef __cplusplus
extern "C" {
#endif

// TODO: rename to rz_flag_XXX api
RZ_LIB_VERSION_HEADER(rz_flag);

#define RZ_FLAG_NAME_SIZE 512

/* zones.c */

typedef struct rz_flag_zone_item_t {
	ut64 from;
	ut64 to;
	char *name;
} RzFlagZoneItem;

/* flag.c */

typedef struct rz_flags_at_offset_t {
	ut64 off;
	RzList /*<RzFlagItem *>*/ *flags; /* list of RzFlagItem at offset */
} RzFlagsAtOffset;

typedef struct rz_flag_item_t {
	char *name; /* unique name, escaped to avoid issues with rizin shell */
	char *realname; /* real name, without any escaping */
	bool demangled; /* real name from demangling? */
	ut64 offset; /* offset flagged by this item */
	ut64 size; /* size of the flag item */
	RzSpace *space; /* flag space this item belongs to */
	char *color; /* item color */
	char *comment; /* item comment */
	char *alias; /* used to define a flag based on a math expression (e.g. foo + 3) */
} RzFlagItem;

typedef struct rz_flag_t {
	RzSpaces spaces; /* handle flag spaces */
	bool realnames;
	Sdb *tags;
	RzNum *num;
	RzSkipList *by_off; /* flags sorted by offset, value=RzFlagsAtOffset */
	HtPP *ht_name; /* hashmap key=item name, value=RzFlagItem * */
	RzList /*<RzFlagZoneItem *>*/ *zones;
} RzFlag;

/* compile time dependency */

typedef bool (*RzFlagExistAt)(RzFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off);
typedef RzFlagItem *(*RzFlagGet)(RzFlag *f, const char *name);
typedef RzFlagItem *(*RzFlagGetAtAddr)(RzFlag *f, ut64);
typedef RzFlagItem *(*RzFlagGetAt)(RzFlag *f, ut64 addr, bool closest);
typedef RzFlagItem *(*RzFlagGetAtBySpaces)(RzFlag *f, ut64 off, ...);
typedef const RzList /*<RzFlagItem *>*/ *(*RzFlagGetList)(RzFlag *f, ut64 addr);
typedef RzFlagItem *(*RzFlagSet)(RzFlag *f, const char *name, ut64 addr, ut32 size);
typedef bool (*RzFlagUnset)(RzFlag *f, RzFlagItem *item);
typedef bool (*RzFlagUnsetName)(RzFlag *f, const char *name);
typedef bool (*RzFlagUnsetOff)(RzFlag *f, ut64 addr);
typedef RzSpace *(*RzFlagSetSpace)(RzFlag *f, const char *name);
typedef bool (*RzFlagPopSpace)(RzFlag *f);
typedef bool (*RzFlagPushSpace)(RzFlag *f, const char *name);
typedef int (*RzFlagRename)(RzFlag *f, RzFlagItem *item, const char *name);

typedef bool (*RzFlagItemCb)(RzFlagItem *fi, void *user);

typedef struct rz_flag_bind_t {
	int init;
	RzFlag *f;
	RzFlagExistAt exist_at;
	RzFlagGet get;
	RzFlagGetAt get_at;
	RzFlagGetAtBySpaces get_at_by_spaces;
	RzFlagGetList get_list;
	RzFlagSet set;
	RzFlagUnset unset;
	RzFlagUnsetName unset_name;
	RzFlagUnsetOff unset_off;
	RzFlagSetSpace set_fs;
	RzFlagPushSpace push_fs;
	RzFlagPopSpace pop_fs;
	RzFlagRename rename;
} RzFlagBind;

#define rz_flag_bind_init(x) memset(&x, 0, sizeof(x))
RZ_API void rz_flag_bind(RzFlag *io, RzFlagBind *bnd);

#ifdef RZ_API
RZ_API RzFlag *rz_flag_new(void);
RZ_API RzFlag *rz_flag_free(RzFlag *f);
RZ_API bool rz_flag_exist_at(RzFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off);
RZ_API RzFlagItem *rz_flag_get(RzFlag *f, const char *name);
RZ_API RzFlagItem *rz_flag_get_i(RzFlag *f, ut64 off);
RZ_API RzFlagItem *rz_flag_get_by_spaces(RzFlag *f, ut64 off, ...);
RZ_API RzFlagItem *rz_flag_get_at(RzFlag *f, ut64 off, bool closest);
RZ_API RZ_BORROW RzFlagItem *rz_flag_get_at_by_spaces(RZ_NONNULL RzFlag *f, bool closest, ut64 off, ...);
RZ_API RzList /*<RzFlagItem *>*/ *rz_flag_all_list(RzFlag *f, bool by_space);
RZ_API const RzList /*<RzFlagItem *>*/ *rz_flag_get_list(RzFlag *f, ut64 off);
RZ_API char *rz_flag_get_liststr(RzFlag *f, ut64 off);
RZ_API bool rz_flag_unset(RzFlag *f, RzFlagItem *item);
RZ_API bool rz_flag_unset_name(RzFlag *f, const char *name);
RZ_API bool rz_flag_unset_off(RzFlag *f, ut64 addr);
RZ_API bool rz_flag_unset_all_off(RzFlag *f, ut64 off);
RZ_API void rz_flag_unset_all(RzFlag *f);
RZ_API void rz_flag_unset_all_in_space(RzFlag *f, const char *space_name);
RZ_API RzFlagItem *rz_flag_set(RzFlag *fo, const char *name, ut64 addr, ut32 size);
RZ_API RzFlagItem *rz_flag_set_next(RzFlag *fo, const char *name, ut64 addr, ut32 size);
RZ_API void rz_flag_item_set_alias(RzFlagItem *item, const char *alias);
RZ_API void rz_flag_item_free(RzFlagItem *item);
RZ_API void rz_flag_item_set_comment(RzFlagItem *item, const char *comment);
RZ_API void rz_flag_item_set_realname(RzFlagItem *item, const char *realname);
RZ_API const char *rz_flag_item_set_color(RzFlagItem *item, const char *color);
RZ_API RzFlagItem *rz_flag_item_clone(RzFlagItem *item);
RZ_API int rz_flag_unset_glob(RzFlag *f, const char *name);
RZ_API int rz_flag_rename(RzFlag *f, RzFlagItem *item, const char *name);
RZ_API int rz_flag_relocate(RzFlag *f, ut64 off, ut64 off_mask, ut64 to);
RZ_API bool rz_flag_move(RzFlag *f, ut64 at, ut64 to);
RZ_API int rz_flag_count(RzFlag *f, const char *glob);
RZ_API void rz_flag_foreach(RzFlag *f, RzFlagItemCb cb, void *user);
RZ_API void rz_flag_foreach_prefix(RzFlag *f, const char *pfx, int pfx_len, RzFlagItemCb cb, void *user);
RZ_API void rz_flag_foreach_range(RZ_NONNULL RzFlag *f, ut64 from, ut64 to, RzFlagItemCb cb, void *user);
RZ_API void rz_flag_foreach_glob(RzFlag *f, const char *glob, RzFlagItemCb cb, void *user);
RZ_API void rz_flag_foreach_space(RzFlag *f, const RzSpace *space, RzFlagItemCb cb, void *user);
RZ_API void rz_flag_foreach_space_glob(RzFlag *f, const char *glob, const RzSpace *space, RzFlagItemCb cb, void *user);

/* spaces */
static inline RzSpace *rz_flag_space_get(RzFlag *f, const char *name) {
	return rz_spaces_get(&f->spaces, name);
}

static inline RzSpace *rz_flag_space_cur(RzFlag *f) {
	return rz_spaces_current(&f->spaces);
}

static inline const char *rz_flag_space_cur_name(RzFlag *f) {
	return rz_spaces_current_name(&f->spaces);
}

static inline RzSpace *rz_flag_space_set(RzFlag *f, const char *name) {
	return rz_spaces_set(&f->spaces, name);
}

static inline bool rz_flag_space_unset(RzFlag *f, const char *name) {
	return rz_spaces_unset(&f->spaces, name);
}

static inline bool rz_flag_space_rename(RzFlag *f, const char *oname, const char *nname) {
	return rz_spaces_rename(&f->spaces, oname, nname);
}

static inline bool rz_flag_space_push(RzFlag *f, const char *name) {
	return rz_spaces_push(&f->spaces, name);
}

static inline bool rz_flag_space_pop(RzFlag *f) {
	return rz_spaces_pop(&f->spaces);
}

static inline int rz_flag_space_count(RzFlag *f, const char *name) {
	return rz_spaces_count(&f->spaces, name);
}

static inline bool rz_flag_space_is_empty(RzFlag *f) {
	return rz_spaces_is_empty(&f->spaces);
}

#define rz_flag_space_foreach(f, it, s) rz_spaces_foreach(&(f)->spaces, (it), (s))

/* tags */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_flag_tags_list(RzFlag *f);
RZ_API void rz_flag_tags_set(RzFlag *f, const char *name, const char *words);
RZ_API void rz_flag_tags_reset(RzFlag *f, const char *name);
RZ_API RzList /*<RzFlagItem *>*/ *rz_flag_tags_get(RzFlag *f, const char *name);

/* zones */

RZ_API void rz_flag_zone_item_free(void *a);
RZ_API bool rz_flag_zone_add(RzFlag *fz, const char *name, ut64 addr);
RZ_API bool rz_flag_zone_del(RzFlag *fz, const char *name);
RZ_API bool rz_flag_zone_around(RzFlag *fz, ut64 addr, const char **prev, const char **next);
RZ_API bool rz_flag_zone_reset(RzFlag *f);
RZ_API RzList /*<char *>*/ *rz_flag_zone_barlist(RzFlag *f, ut64 from, ut64 bsize, int rows);

/* serialize */

RZ_API void rz_serialize_flag_zones_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzList /*<RzFlagZoneItem *>*/ *zones);
RZ_API bool rz_serialize_flag_zones_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzList /*<RzFlagZoneItem *>*/ *zones, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_flag_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzFlag *flag);
RZ_API bool rz_serialize_flag_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzFlag *flag, RZ_NULLABLE RzSerializeResultInfo *res);

#endif

#ifdef __cplusplus
}
#endif

#endif
