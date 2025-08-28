// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_mark.h>
#include <rz_util.h>
#include <rz_cons.h>

RZ_LIB_VERSION(rz_mark);

#define STRDUP_OR_NULL(s) (!RZ_STR_ISEMPTY(s) ? strdup(s) : NULL)

static void mark_skiplist_free(void *data) {
	RzMarksAtOffset *item = (RzMarksAtOffset *)data;
	rz_list_free(item->marks);
	free(data);
}

static int mark_skiplist_cmp(const void *va, const void *vb, void *user) {
	const RzMarksAtOffset *a = (RzMarksAtOffset *)va, *b = (RzMarksAtOffset *)vb;
	if (a->off == b->off) {
		return 0;
	}
	return a->off < b->off ? -1 : 1;
}

static void free_item_name(RzMarkItem *item) {
	if (item->name != item->realname) {
		free(item->name);
	}
}

static void free_item_realname(RzMarkItem *item) {
	if (item->name != item->realname) {
		free(item->realname);
	}
}

static void set_name(RzMarkItem *item, char *name) {
	free_item_name(item);
	item->name = name;
	free_item_realname(item);
	item->realname = item->name;
}

/* return the list of marks at the nearest position.
   dir == -1 -> result <= off
   dir == 0 ->  result == off
   dir == 1 ->  result >= off*/
static RzMarksAtOffset *rz_mark_get_nearest_list(RzMark *b, ut64 off, int dir) {
	RzMarksAtOffset key = { .off = off };
	RzMarksAtOffset *marks = (dir >= 0)
		? rz_skiplist_get_geq(b->by_off, &key)
		: rz_skiplist_get_leq(b->by_off, &key);
	return (dir == 0 && marks && marks->off != off) ? NULL : marks;
}

RZ_API RzMark *rz_mark_new(void) {
	RzMark *b = RZ_NEW0(RzMark);
	if (!b) {
		return NULL;
	}
	b->ht_name = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_mark_item_free);
	b->by_off = rz_skiplist_new(mark_skiplist_free, mark_skiplist_cmp);
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

static void remove_offsetmap(RzMark *b, RzMarkItem *item) {
	rz_return_if_fail(b && item);
	RzMarksAtOffset *marks = rz_mark_get_nearest_list(b, item->from, 0);
	if (marks) {
		rz_list_delete_data(marks->marks, item);
		if (rz_list_empty(marks->marks)) {
			rz_skiplist_delete(b->by_off, marks);
		}
	}
}

static RzMarksAtOffset *marks_at_offset(RzMark *b, ut64 off) {
	RzMarksAtOffset *res = rz_mark_get_nearest_list(b, off, 0);
	if (res) {
		return res;
	}

	res = RZ_NEW(RzMarksAtOffset);
	if (!res) {
		return NULL;
	}

	res->marks = rz_list_new();
	if (!res->marks) {
		free(res);
		return NULL;
	}

	res->off = off;
	rz_skiplist_insert(b->by_off, res);
	return res;
}

static bool update_mark_item_range(RzMark *b, RzMarkItem *item, ut64 new_from, ut64 new_to,
	bool is_new, bool force) {
	rz_return_val_if_fail(b && item, false);

	if (item->from != new_from || item->to != new_to || force) {
		if (!is_new) {
			remove_offsetmap(b, item);
		}

		item->from = new_from;
		item->to = new_to;

		RzMarksAtOffset *marksAtOffset = marks_at_offset(b, new_from);
		if (!marksAtOffset) {
			return false;
		}

		rz_list_append(marksAtOffset->marks, item);
		return true;
	}
	return false;
}

static bool update_mark_item_name(RzMark *b, RzMarkItem *item, const char *newname, bool force) {
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

static bool mark_item_matches(RzMarkItem *bi, ut64 off, RzMarkMatchMode mode) {
	switch (mode) {
	case RZ_MARK_MATCH_CONTAINS:
		return (off >= bi->from && off <= bi->to);
	case RZ_MARK_MATCH_START:
		return (off == bi->from);
	case RZ_MARK_MATCH_END:
		return (off == bi->to);
	}
	return false;
}

static void mark_iterate_matches(RzMark *b, ut64 off, RzMarkMatchMode mode,
	bool stop_on_first, RzList *out) {
	RzMarksAtOffset *cur = rz_mark_get_nearest_list(b, off, -1);
	while (cur) {
		RzListIter *it;
		RzMarkItem *bi;

		rz_list_foreach (cur->marks, it, bi) {
			if (mark_item_matches(bi, off, mode)) {
				rz_list_append(out, bi);
				if (stop_on_first) {
					return;
				}
			}
		}
		if (cur->off == 0) {
			break;
		}
		cur = rz_mark_get_nearest_list(b, cur->off - 1, -1);
	}
}

static RzMarkItem *mark_match(RzMark *b, ut64 off, RzMarkMatchMode mode) {
	rz_return_val_if_fail(b, NULL);

	RzList *results = rz_list_newf(NULL);
	mark_iterate_matches(b, off, mode, true, results);
	RzMarkItem *ret = results->length ? rz_list_get_n(results, 0) : NULL;
	rz_list_free(results);
	return ret;
}

static RzList *mark_match_all(RzMark *b, ut64 off, RzMarkMatchMode mode) {
	rz_return_val_if_fail(b, NULL);

	RzList *results = rz_list_newf(NULL);
	mark_iterate_matches(b, off, mode, false, results);
	return results;
}

static bool mark_starts_or_ends(RzMark *b, ut64 from, ut64 to) {
	if (!b || from > to) {
		return false;
	}

	RzList *all = rz_mark_all_list(b);
	if (!all) {
		return false;
	}

	RzListIter *it;
	RzMarkItem *bi;
	rz_list_foreach (all, it, bi) {
		if ((bi->from >= from && bi->from <= to) ||
			(bi->to >= from && bi->to <= to)) {
			rz_list_free(all);
			return true;
		}
	}

	rz_list_free(all);
	return false;
}

static bool append_bi(RzMarkItem *item, void *user) {
	rz_list_append((RzList *)user, item);
	return true;
}

/* returns all defined marks in a list */
RZ_API RzList /*<RzMarkItem *>*/ *rz_mark_all_list(RzMark *b) {
	RzList *ret = rz_list_new();
	if (!b || !ret) {
		return ret;
	}

	rz_mark_foreach(b, append_bi, ret);
	return ret;
}

/* checks whether any mark starts or ends in the given range.
 * false is returned if such a item is not found. */
RZ_API bool rz_mark_starts_or_ends(RzMark *b, ut64 from, ut64 to) {
	return mark_starts_or_ends(b, from, to);
}

/* returns all mark items that contains the given offset.
 * NULL is returned if such a item is not found. */
RZ_API RzList /*<RzMarkItem *>*/ *rz_mark_get_all_off(RzMark *b, ut64 off) {
	return mark_match_all(b, off, RZ_MARK_MATCH_CONTAINS);
}

/* returns the last mark item that contains the given offset.
 * NULL is returned if such a item is not found. */
RZ_API RzMarkItem *rz_mark_get_at(RzMark *b, ut64 off) {
	return mark_match(b, off, RZ_MARK_MATCH_CONTAINS);
}

/* returns the mark item that starts at the given offset.
 * NULL is returned if such an item is not found. */
RZ_API RzMarkItem *rz_mark_get_start(RzMark *b, ut64 off) {
	return mark_match(b, off, RZ_MARK_MATCH_START);
}

/* returns the mark item that ends at the given offset.
 * NULL is returned if such an item is not found. */
RZ_API RzMarkItem *rz_mark_get_end(RzMark *b, ut64 off) {
	return mark_match(b, off, RZ_MARK_MATCH_END);
}

/* return the mark item with name "name" in the RzMark "b", if it exists.
 * Otherwise, NULL is returned. */
RZ_API RzMarkItem *rz_mark_get(RzMark *b, const char *name) {
	rz_return_val_if_fail(b, NULL);
	RzMarkItem *r = ht_sp_find(b->ht_name, name, NULL);
	return r;
}

/* return the list of mark items that are associated with a given offset */
RZ_API const RzList /*<RzMarkItem *>*/ *rz_mark_get_list(RzMark *b, ut64 off) {
	const RzMarksAtOffset *item = rz_mark_get_nearest_list(b, off, 0);
	return item ? item->marks : NULL;
}

/* create or modify an existing mark item with the given name and parameters.
 * The realname of the item will be the same as the name.
 * NULL is returned in case of any errors during the process. */
RZ_API RzMarkItem *rz_mark_set(RzMark *b, const char *name, ut64 from, ut64 to) {
	rz_return_val_if_fail(b && name && *name, NULL);

	bool is_new = false;
	char *itemname = filter_item_name(name);
	if (!itemname) {
		return NULL;
	}

	RzMarkItem *item = rz_mark_get(b, itemname);
	free(itemname);
	if (item && item->from == from && item->to == to) {
		return item;
	}

	if (!item) {
		item = RZ_NEW0(RzMarkItem);
		if (!item) {
			goto err;
		}
		is_new = true;
	}

	update_mark_item_range(b, item, from, to, is_new, true);
	update_mark_item_name(b, item, name, true);
	return item;
err:
	rz_mark_item_free(item);
	return NULL;
}

RZ_API RzMark *rz_mark_free(RzMark *b) {
	rz_return_val_if_fail(b, NULL);
	rz_skiplist_free(b->by_off);
	ht_sp_free(b->ht_name);
	free(b);
	return NULL;
}

RZ_API void rz_mark_item_free(RzMarkItem *item) {
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
	RzMarksAtOffset *marks_at; \
	RzListIter *it2, *tmp2; \
	RzMarkItem *bi; \
	rz_skiplist_foreach_safe(b->by_off, it, tmp, marks_at) { \
		if (marks_at) { \
			rz_list_foreach_safe (marks_at->marks, it2, tmp2, bi) { \
				if (condition) { \
					if (!cb(bi, user)) { \
						return; \
					} \
				} \
			} \
		} \
	}

RZ_API void rz_mark_foreach(RzMark *b, RzMarkItemCb cb, void *user) {
	FOREACH_BODY(true);
}

RZ_API void rz_mark_foreach_glob(RzMark *b, const char *glob, RzMarkItemCb cb, void *user) {
	FOREACH_BODY(!glob || rz_str_glob(bi->name, glob));
}

struct unset_off_foreach_t {
	RzMark *b;
	ut64 offset;
};

/* \brief unset the given mark \p item.
 *
 * return true if the item is successfully unset, false otherwise.
 * NOTE: the item is freed.
 */
RZ_API bool rz_mark_unset(RzMark *b, RzMarkItem *item) {
	rz_return_val_if_fail(b && item, false);
	remove_offsetmap(b, item);
	ht_sp_delete(b->ht_name, item->name);
	return true;
}

static bool unset_off_foreach(void *user, const char *k, const void *v) {
	struct unset_off_foreach_t *u = (struct unset_off_foreach_t *)user;
	RzMarkItem *bi = (RzMarkItem *)v;

	// check if any marked range contains the current offset
	if (u->offset >= bi->from && u->offset <= bi->to) {
		rz_mark_unset(u->b, bi);
	}
	return true;
}

/* \brief unset all mark items found at offset \p off.
 *
 * return true if at least one mark is found and unset, false otherwise.
 */
RZ_API bool rz_mark_unset_all_off(RzMark *b, ut64 off) {
	rz_return_val_if_fail(b, false);
	struct unset_off_foreach_t u = { b, off };
	ht_sp_foreach(b->ht_name, unset_off_foreach, &u);
	return true;
}

struct unset_foreach_t {
	RzMark *b;
	int n;
};

static bool unset_foreach(RzMarkItem *bi, void *user) {
	struct unset_foreach_t *u = (struct unset_foreach_t *)user;
	rz_mark_unset(u->b, bi);
	u->n++;
	return true;
}

/* unset all the mark items that satisfy the given glob.
 * return the number of unset items. -1 on error */
RZ_API int rz_mark_unset_glob(RzMark *b, const char *glob) {
	rz_return_val_if_fail(b, -1);
	struct unset_foreach_t u = { .b = b, .n = 0 };
	rz_mark_foreach_glob(b, glob, unset_foreach, &u);
	return u.n;
}

/* unset all mark items in the RzMark b */
RZ_API void rz_mark_unset_all(RzMark *b) {
	rz_return_if_fail(b);
	ht_sp_free(b->ht_name);
	b->ht_name = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_mark_item_free);
	rz_skiplist_purge(b->by_off);
}

/* add/replace/remove the color of a mark item */
RZ_API const char *rz_mark_item_set_color(RzMarkItem *item, const char *color) {
	rz_return_val_if_fail(item, NULL);
	free(item->color);
	item->color = STRDUP_OR_NULL(color);
	return item->color;
}

/* add/replace/remove the comment of a flag item */
RZ_API void rz_mark_item_set_comment(RzMarkItem *item, const char *comment) {
	rz_return_if_fail(item);
	free(item->comment);
	item->comment = RZ_STR_ISEMPTY(comment) ? NULL : rz_str_dup(comment);
}

/* change the name of a mark item, if the new name is available.
 * true is returned if everything works well, false otherwise */
RZ_API int rz_mark_rename(RzMark *b, RzMarkItem *item, const char *name) {
	rz_return_val_if_fail(b && item && name && *name, false);
	return update_mark_item_name(b, item, name, false);
}

/* add/replace/remove the realname of a mark item */
RZ_API void rz_mark_item_set_realname(RzMarkItem *item, const char *realname) {
	rz_return_if_fail(item);
	free_item_realname(item);
	item->realname = RZ_STR_ISEMPTY(realname) ? NULL : rz_str_dup(realname);
}

static bool mark_count_foreach(RzMarkItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

RZ_API int rz_mark_count(RzMark *b, const char *glob) {
	int count = 0;
	rz_return_val_if_fail(b, -1);
	rz_mark_foreach_glob(b, glob, mark_count_foreach, &count);
	return count;
}
