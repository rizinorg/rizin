#ifndef RZ_BOOKMARK_H
#define RZ_BOOKMARK_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_skiplist.h>
#include <rz_util/ht_sp.h>
#include <rz_util/rz_serialize.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

// NOTE: Bookmarks are currently used for the Hex Widget only
// but the API is kept generic in case of future reuse

RZ_LIB_VERSION_HEADER(rz_bookmark);

#define RZ_BOOKMARK_NAME_SIZE 512

typedef struct rz_bookmark_item_t {
	ut64 from; /* starting address of bookmark */
	ut64 to; /* ending address of bookmark */
	char *name; /* unique name for each bookmark, escaped to avoid issues with rizin shell */
	char *realname; /* real name, without any escaping */
	char *comment; /* item comment */
	char *color; /* item color */
} RzBookmarkItem;

typedef struct rz_bookmarks_at_offset_t {
	ut64 off;
	RzList /*<RzBookmarkItem *>*/ *bookmarks;
} RzBookmarksAtOffset;

typedef struct rz_bookmark_t {
	HtSP *ht_name; // name -> RzBookmarkItem*
	RzList /*<RzBookmarkItem *>*/ *items; // All bookmarks
	RzSkipList *by_off; // offset -> RzBookmarksAtOffset*
} RzBookmark;

typedef bool (*RzBookmarkItemCb)(RzBookmarkItem *item, void *user);

typedef enum {
	RZ_BMARK_MATCH_CONTAINS,
	RZ_BMARK_MATCH_START,
	RZ_BMARK_MATCH_END
} RzBookmarkMatchMode;

#ifdef RZ_API
RZ_API RzBookmark *rz_bookmark_new(void);
RZ_API RzBookmark *rz_bookmark_free(RzBookmark *b);
RZ_API RzBookmarkItem *rz_bookmark_set(RzBookmark *b, const char *name, ut64 from, ut64 to);
RZ_API RzBookmarkItem *rz_bookmark_get(RzBookmark *b, const char *name);
RZ_API RzBookmarkItem *rz_bookmark_get_start(RzBookmark *b, ut64 off);
RZ_API RzBookmarkItem *rz_bookmark_get_end(RzBookmark *b, ut64 off);
RZ_API RzBookmarkItem *rz_bookmark_get_at(RzBookmark *b, ut64 addr);
RZ_API void rz_bookmark_item_free(RzBookmarkItem *item);
RZ_API RzBookmarkItem *rz_bookmark_set(RzBookmark *b, const char *name, ut64 from, ut64 to);
RZ_API void rz_bookmark_item_set_comment(RzBookmarkItem *item, const char *comment);
RZ_API const char *rz_bookmark_item_set_color(RzBookmarkItem *item, const char *color);
RZ_API void rz_bookmark_item_set_realname(RzBookmarkItem *item, const char *realname);
RZ_API int rz_bookmark_rename(RzBookmark *b, RzBookmarkItem *item, const char *name);
RZ_API bool rz_bookmark_unset(RzBookmark *b, RzBookmarkItem *item);
RZ_API bool rz_bookmark_unset_all_off(RzBookmark *b, ut64 off);
RZ_API void rz_bookmark_unset_all(RzBookmark *b);
RZ_API int rz_bookmark_unset_glob(RzBookmark *b, const char *glob);
RZ_API int rz_bookmark_count(RzBookmark *b, const char *glob);
RZ_API void rz_bookmark_foreach(RzBookmark *b, RzBookmarkItemCb cb, void *user);
RZ_API void rz_bookmark_foreach_glob(RzBookmark *b, const char *glob, RzBookmarkItemCb cb, void *user);

/* serialize */

RZ_API void rz_serialize_bookmark_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzBookmark *bm);
RZ_API bool rz_serialize_bookmark_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzBookmark *bm, RZ_NULLABLE RzSerializeResultInfo *res);

#endif // RZ_API

#ifdef __cplusplus
}
#endif

#endif // RZ_BOOKMARK_H
