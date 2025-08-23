// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_bookmark.h"
#include <rz_bookmark.h>
#include <rz_util.h>
#include <rz_cons.h>

RZ_LIB_VERSION(rz_bookmark);

#define STRDUP_OR_NULL(s) (!RZ_STR_ISEMPTY(s) ? strdup(s) : NULL)

static void bookmark_skiplist_free(void *data) {
	RzBookmarksAtOffset *item = (RzBookmarksAtOffset *)data;
	rz_list_free(item->bookmarks);
	free(data);
}

static int bookmark_skiplist_cmp(const void *va, const void *vb, void *user) {
	const RzBookmarksAtOffset *a = (RzBookmarksAtOffset *)va, *b = (RzBookmarksAtOffset *)vb;
	if (a->off == b->off) {
		return 0;
	}
	return a->off < b->off ? -1 : 1;
}

static void free_item_name(RzBookmarkItem *item) {
	if (item->name != item->realname) {
		free(item->name);
	}
}

static void free_item_realname(RzBookmarkItem *item) {
	if (item->name != item->realname) {
		free(item->realname);
	}
}

static void set_name(RzBookmarkItem *item, char *name) {
	free_item_name(item);
	item->name = name;
	free_item_realname(item);
	item->realname = item->name;
}

/* return the list of bookmarks at the nearest position.
   dir == -1 -> result <= off
   dir == 0 ->  result == off
   dir == 1 ->  result >= off*/
static RzBookmarksAtOffset *rz_bookmark_get_nearest_list(RzBookmark *b, ut64 off, int dir) {
	RzBookmarksAtOffset key = { .off = off };
	RzBookmarksAtOffset *bookmarks = (dir >= 0)
		? rz_skiplist_get_geq(b->by_off, &key)
		: rz_skiplist_get_leq(b->by_off, &key);
	return (dir == 0 && bookmarks && bookmarks->off != off) ? NULL : bookmarks;
}

RZ_API RzBookmark *rz_bookmark_new(void) {
	RzBookmark *b = RZ_NEW0(RzBookmark);
	if (!b) {
		return NULL;
	}
	b->ht_name = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_bookmark_item_free);
	b->by_off = rz_skiplist_new(bookmark_skiplist_free, bookmark_skiplist_cmp);
	return b;
}

static char *filter_item_name(const char *name) {
	char *res = rz_str_dup(name);
	if (!res) {
		return NULL;
	}

	rz_str_trim(res);
	rz_name_filter(res, 0, true);
	return res;
}

static void remove_offsetmap(RzBookmark *b, RzBookmarkItem *item) {
	rz_return_if_fail(b && item);
	RzBookmarksAtOffset *bookmarks = rz_bookmark_get_nearest_list(b, item->from, 0);
	if (bookmarks) {
		rz_list_delete_data(bookmarks->bookmarks, item);
		if (rz_list_empty(bookmarks->bookmarks)) {
			rz_skiplist_delete(b->by_off, bookmarks);
		}
	}
}

static RzBookmarksAtOffset *bookmarks_at_offset(RzBookmark *b, ut64 off) {
	RzBookmarksAtOffset *res = rz_bookmark_get_nearest_list(b, off, 0);
	if (res) {
		return res;
	}

	res = RZ_NEW(RzBookmarksAtOffset);
	if (!res) {
		return NULL;
	}

	res->bookmarks = rz_list_new();
	if (!res->bookmarks) {
		free(res);
		return NULL;
	}

	res->off = off;
	rz_skiplist_insert(b->by_off, res);
	return res;
}

static bool update_bookmark_item_range(RzBookmark *b, RzBookmarkItem *item, ut64 new_from, ut64 new_to,
	bool is_new, bool force) {
	rz_return_val_if_fail(b && item, false);

	if (item->from != new_from || item->to != new_to || force) {
		if (!is_new) {
			remove_offsetmap(b, item);
		}

		item->from = new_from;
		item->to = new_to;

		RzBookmarksAtOffset *bookmarksAtOffset = bookmarks_at_offset(b, new_from);
		if (!bookmarksAtOffset) {
			return false;
		}

		rz_list_append(bookmarksAtOffset->bookmarks, item);
		return true;
	}
	return false;
}

static bool update_bookmark_item_name(RzBookmark *b, RzBookmarkItem *item, const char *newname, bool force) {
	if (!b || !item || !newname) {
		return false;
	}
	if (!force && (item->name == newname || (item->name && !strcmp(item->name, newname)))) {
		return false;
	}
	char *fname = filter_item_name(newname);
	if (!fname) {
		return false;
	}
	bool res = (item->name)
		? ht_sp_update_key(b->ht_name, item->name, fname)
		: ht_sp_insert(b->ht_name, fname, item);
	if (res) {
		set_name(item, fname);
		return true;
	}
	free(fname);
	return false;
}

static RzBookmarkItem *bookmark_match(RzBookmark *b, ut64 off, RzBookmarkMatchMode mode) {
	rz_return_val_if_fail(b, NULL);

	RzBookmarksAtOffset *cur = rz_bookmark_get_nearest_list(b, off, -1);
	while (cur) {
		RzListIter *it;
		RzBookmarkItem *bi;

		rz_list_foreach (cur->bookmarks, it, bi) {
			bool match = false;
			switch (mode) {
			case RZ_BMARK_MATCH_CONTAINS:
				match = (off >= bi->from && off <= bi->to);
				break;
			case RZ_BMARK_MATCH_START:
				match = (off == bi->from);
				break;
			case RZ_BMARK_MATCH_END:
				match = (off == bi->to);
				break;
			}
			if (match) {
				return bi;
			}
		}
		if (cur->off == 0) {
			break;
		}
		cur = rz_bookmark_get_nearest_list(b, cur->off - 1, -1);
	}
	return NULL;
}

/* returns the last bookmark item that contains the given offset.
 * NULL is returned if such a item is not found. */

RZ_API RzBookmarkItem *rz_bookmark_get_at(RzBookmark *b, ut64 off) {
	return bookmark_match(b, off, RZ_BMARK_MATCH_CONTAINS);
}

/* returns the bookmark item that starts at the given offset.
 * NULL is returned if such an item is not found. */
RZ_API RzBookmarkItem *rz_bookmark_get_start(RzBookmark *b, ut64 off) {
	return bookmark_match(b, off, RZ_BMARK_MATCH_START);
}

/* returns the bookmark item that ends at the given offset.
 * NULL is returned if such an item is not found. */
RZ_API RzBookmarkItem *rz_bookmark_get_end(RzBookmark *b, ut64 off) {
	return bookmark_match(b, off, RZ_BMARK_MATCH_END);
}

/* return the bookmark item with name "name" in the RzBookmark "b", if it exists.
 * Otherwise, NULL is returned. */
RZ_API RzBookmarkItem *rz_bookmark_get(RzBookmark *b, const char *name) {
	rz_return_val_if_fail(b, NULL);
	RzBookmarkItem *r = ht_sp_find(b->ht_name, name, NULL);
	return r;
}

/* return the list of bookmark items that are associated with a given offset */
RZ_API const RzList /*<RzBookmarkItem *>*/ *rz_bookmark_get_list(RzBookmark *b, ut64 off) {
	const RzBookmarksAtOffset *item = rz_bookmark_get_nearest_list(b, off, 0);
	return item ? item->bookmarks : NULL;
}

/* create or modify an existing bookmark item with the given name and parameters.
 * The realname of the item will be the same as the name.
 * NULL is returned in case of any errors during the process. */
RZ_API RzBookmarkItem *rz_bookmark_set(RzBookmark *b, const char *name, ut64 from, ut64 to) {
	rz_return_val_if_fail(b && name && *name, NULL);

	bool is_new = false;
	char *itemname = filter_item_name(name);
	if (!itemname) {
		return NULL;
	}

	RzBookmarkItem *item = rz_bookmark_get(b, itemname);
	free(itemname);
	if (item && item->from == from && item->to == to) {
		return item;
	}

	if (!item) {
		item = RZ_NEW0(RzBookmarkItem);
		if (!item) {
			goto err;
		}
		is_new = true;
	}

	update_bookmark_item_range(b, item, from, to, is_new, true);
	update_bookmark_item_name(b, item, name, true);
	return item;
err:
	rz_bookmark_item_free(item);
	return NULL;
}

RZ_API RzBookmark *rz_bookmark_free(RzBookmark *b) {
	rz_return_val_if_fail(b, NULL);
	rz_skiplist_free(b->by_off);
	ht_sp_free(b->ht_name);
	free(b);
	return NULL;
}

RZ_API void rz_bookmark_item_free(RzBookmarkItem *item) {
	if (!item) {
		return;
	}
	free(item->color);
	free(item->comment);

	free_item_name(item);
	free(item->realname);
	free(item);
}

#define FOREACH_BODY(condition) \
	RzSkipListNode *it, *tmp; \
	RzBookmarksAtOffset *bookmarks_at; \
	RzListIter *it2, *tmp2; \
	RzBookmarkItem *bi; \
	rz_skiplist_foreach_safe(b->by_off, it, tmp, bookmarks_at) { \
		if (bookmarks_at) { \
			rz_list_foreach_safe (bookmarks_at->bookmarks, it2, tmp2, bi) { \
				if (condition) { \
					if (!cb(bi, user)) { \
						return; \
					} \
				} \
			} \
		} \
	}

RZ_API void rz_bookmark_foreach(RzBookmark *b, RzBookmarkItemCb cb, void *user) {
	FOREACH_BODY(true);
}

RZ_API void rz_bookmark_foreach_glob(RzBookmark *b, const char *glob, RzBookmarkItemCb cb, void *user) {
	FOREACH_BODY(!glob || rz_str_glob(bi->name, glob));
}

struct unset_off_foreach_t {
	RzBookmark *b;
	ut64 offset;
};

/* \brief unset the given bookmark \p item.
 *
 * return true if the item is successfully unset, false otherwise.
 * NOTE: the item is freed.
 */
RZ_API bool rz_bookmark_unset(RzBookmark *b, RzBookmarkItem *item) {
	rz_return_val_if_fail(b && item, false);
	remove_offsetmap(b, item);
	ht_sp_delete(b->ht_name, item->name);
	return true;
}

static bool unset_off_foreach(void *user, const char *k, const void *v) {
	struct unset_off_foreach_t *u = (struct unset_off_foreach_t *)user;
	RzBookmarkItem *bi = (RzBookmarkItem *)v;

	// check if any bookmarked range contains the current offset
	if (u->offset >= bi->from && u->offset <= bi->to) {
		rz_bookmark_unset(u->b, bi);
	}
	return true;
}

/* \brief unset all bookmark items found at offset \p off.
 *
 * return true if at least one bookmark is found and unset, false otherwise.
 */
RZ_API bool rz_bookmark_unset_all_off(RzBookmark *b, ut64 off) {
	rz_return_val_if_fail(b, false);
	struct unset_off_foreach_t u = { b, off };
	ht_sp_foreach(b->ht_name, unset_off_foreach, &u);
	return true;
}

struct unset_foreach_t {
	RzBookmark *b;
	int n;
};

static bool unset_foreach(RzBookmarkItem *bi, void *user) {
	struct unset_foreach_t *u = (struct unset_foreach_t *)user;
	rz_bookmark_unset(u->b, bi);
	u->n++;
	return true;
}

/* unset all the bookmark items that satisfy the given glob.
 * return the number of unset items. -1 on error */
RZ_API int rz_bookmark_unset_glob(RzBookmark *b, const char *glob) {
	rz_return_val_if_fail(b, -1);
	struct unset_foreach_t u = { .b = b, .n = 0 };
	rz_bookmark_foreach_glob(b, glob, unset_foreach, &u);
	return u.n;
}

/* unset all bookmark items in the RzBookmark b */
RZ_API void rz_bookmark_unset_all(RzBookmark *b) {
	rz_return_if_fail(b);
	ht_sp_free(b->ht_name);
	b->ht_name = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_bookmark_item_free);
	rz_skiplist_purge(b->by_off);
}

/* add/replace/remove the color of a bookmark item */
RZ_API const char *rz_bookmark_item_set_color(RzBookmarkItem *item, const char *color) {
	rz_return_val_if_fail(item, NULL);
	free(item->color);
	item->color = STRDUP_OR_NULL(color);
	return item->color;
}

/* add/replace/remove the comment of a flag item */
RZ_API void rz_bookmark_item_set_comment(RzBookmarkItem *item, const char *comment) {
	rz_return_if_fail(item);
	free(item->comment);
	item->comment = RZ_STR_ISEMPTY(comment) ? NULL : rz_str_dup(comment);
}

/* change the name of a bookmark item, if the new name is available.
 * true is returned if everything works well, false otherwise */
RZ_API int rz_bookmark_rename(RzBookmark *b, RzBookmarkItem *item, const char *name) {
	rz_return_val_if_fail(b && item && name && *name, false);
	return update_bookmark_item_name(b, item, name, false);
}

/* add/replace/remove the realname of a bookmark item */
RZ_API void rz_bookmark_item_set_realname(RzBookmarkItem *item, const char *realname) {
	rz_return_if_fail(item);
	free_item_realname(item);
	item->realname = RZ_STR_ISEMPTY(realname) ? NULL : rz_str_dup(realname);
}

static bool bookmark_count_foreach(RzBookmarkItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

RZ_API int rz_bookmark_count(RzBookmark *b, const char *glob) {
	int count = 0;
	rz_return_val_if_fail(b, -1);
	rz_bookmark_foreach_glob(b, glob, bookmark_count_foreach, &count);
	return count;
}
