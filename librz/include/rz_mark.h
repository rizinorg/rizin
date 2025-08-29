#ifndef RZ_MARK_H
#define RZ_MARK_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_skiplist.h>
#include <rz_util/ht_sp.h>
#include <rz_util/rz_serialize.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

// NOTE: Marks are currently used for the Hex Widget only
// but the API is kept generic in case of future reuse

RZ_LIB_VERSION_HEADER(rz_mark);

#define RZ_MARK_NAME_SIZE 512

typedef struct rz_mark_item_t {
	ut64 from; /* inclusive starting address of mark */
	ut64 to; /* inclusive ending address of mark */
	char *name; /* unique name for each mark, escaped to avoid issues with rizin shell */
	char *realname; /* real name, without any escaping */
	char *comment; /* item comment */
	char *color; /* item color */
} RzMarkItem;

typedef struct rz_marks_at_offset_t {
	ut64 off;
	RzList /*<RzMarkItem *>*/ *marks;
} RzMarksAtOffset;

typedef struct rz_mark_t {
	HtSP *ht_name; ///< name -> RzBookmarkItem*
	RzList /*<RzBookmarkItem *>*/ *items; ///< All bookmarks
	RzSkipList *by_off; ///< offset -> RzBookmarksAtOffset*
} RzMark;

typedef bool (*RzMarkItemCb)(RzMarkItem *item, void *user);

typedef enum {
	RZ_MARK_MATCH_CONTAINS,
	RZ_MARK_MATCH_START,
	RZ_MARK_MATCH_END
} RzMarkMatchMode;

#ifdef RZ_API
RZ_API RZ_OWN RzMark *rz_mark_new(void);
RZ_API void rz_mark_free(RZ_OWN RzMark *b);
RZ_API RZ_OWN RzMarkItem *rz_mark_set(RZ_BORROW RzMark *b, RZ_BORROW const char *name, ut64 from, ut64 to);
RZ_API RZ_BORROW RzMarkItem *rz_mark_get(RZ_BORROW RzMark *b, RZ_BORROW const char *name);
RZ_API RZ_BORROW RzMarkItem *rz_mark_get_start(RZ_BORROW RzMark *b, ut64 off);
RZ_API RZ_BORROW RzMarkItem *rz_mark_get_end(RZ_BORROW RzMark *b, ut64 off);
RZ_API RZ_BORROW RzMarkItem *rz_mark_get_at(RZ_BORROW RzMark *b, ut64 off);
RZ_API RZ_OWN RzList /*<RzMarkItem *>*/ *rz_mark_get_all_off(RZ_BORROW RzMark *b, ut64 off);
RZ_API RZ_OWN RzList /*<RzMarkItem *>*/ *rz_mark_all_list(RZ_BORROW RzMark *b);
RZ_API RZ_BORROW const RzList /*<RzMarkItem *>*/ *rz_mark_get_list(RZ_BORROW RzMark *b, ut64 off);
RZ_API void rz_mark_item_free(RZ_OWN RzMarkItem *item);
RZ_API RZ_OWN RzMarkItem *rz_mark_set(RZ_BORROW RzMark *b, RZ_BORROW const char *name, ut64 from, ut64 to);
RZ_API void rz_mark_item_set_comment(RZ_BORROW RzMarkItem *item, RZ_BORROW const char *comment);
RZ_API const char *rz_mark_item_set_color(RZ_BORROW RzMarkItem *item, RZ_BORROW const char *color);
RZ_API void rz_mark_item_set_realname(RZ_BORROW RzMarkItem *item, RZ_BORROW const char *realname);
RZ_API int rz_mark_rename(RZ_BORROW RzMark *b, RZ_BORROW RzMarkItem *item, RZ_BORROW const char *name);
RZ_API bool rz_mark_starts_or_ends(RZ_BORROW RzMark *b, ut64 from, ut64 to);
RZ_API bool rz_mark_unset(RZ_BORROW RzMark *b, RZ_BORROW RzMarkItem *item);
RZ_API bool rz_mark_unset_all_off(RZ_BORROW RzMark *b, ut64 off);
RZ_API void rz_mark_unset_all(RZ_BORROW RzMark *b);
RZ_API int rz_mark_unset_glob(RZ_BORROW RzMark *b, RZ_BORROW const char *glob);
RZ_API int rz_mark_count(RZ_BORROW RzMark *b, RZ_BORROW const char *glob);
RZ_API void rz_mark_foreach(RZ_BORROW RzMark *b, RzMarkItemCb cb, void *user);
RZ_API void rz_mark_foreach_glob(RZ_BORROW RzMark *b, RZ_BORROW const char *glob, RzMarkItemCb cb, void *user);

/* serialize */

RZ_API void rz_serialize_mark_save(RZ_NONNULL Sdb *db, RZ_BORROW RzMark *bm);
RZ_API bool rz_serialize_mark_load(RZ_NONNULL Sdb *db, RZ_BORROW RzMark *bm, RZ_NULLABLE RzSerializeResultInfo *res);

#endif // RZ_API

#ifdef __cplusplus
}
#endif

#endif // RZ_MARK_H
