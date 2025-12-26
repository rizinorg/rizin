// SPDX-FileCopyrightText: 2025 PremadeS <emadsohail001@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types_base.h>
#include <rz_util/rz_assert.h>
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

RZ_API RZ_OWN RzMark *rz_mark_new(void) {
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
		rz_list_delete_val(marks->marks, item);
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
	if (!force && (item->name == newname || (RZ_STR_EQ(item->name, newname)))) {
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
		return RZ_BETWEEN(bi->from, off, bi->to);
	case RZ_MARK_MATCH_START:
		return (off == bi->from);
	case RZ_MARK_MATCH_END:
		return (off == bi->to);
	}
	return false;
}

static void mark_iterate_matches(RzMark *b, ut64 off, RzMarkMatchMode mode,
	bool stop_on_first, RzList /*<RzMarkItem *>*/ *out) {
	RzMarksAtOffset *cur = rz_mark_get_nearest_list(b, off, -1);
	while (cur) {
		RzListIter *it;
		RzMarkItem *bi;

		rz_list_foreach (cur->marks, it, bi) {
			if (!mark_item_matches(bi, off, mode)) {
				continue;
			}
			rz_list_append(out, bi);
			if (stop_on_first) {
				return;
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

static RzList /*<RzMarkItem *>*/ *mark_match_all(RzMark *b, ut64 off, RzMarkMatchMode mode) {
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
		if (RZ_BETWEEN(from, bi->from, to) ||
			RZ_BETWEEN(from, bi->to, to)) {
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

/**
 * \brief Get all defined marks as a list.
 *
 * \param b The mark container.
 * \return A newly allocated list of all mark items (\p RzMarkItem*).
 */
RZ_API RZ_OWN RzList /*<RzMarkItem *>*/ *rz_mark_all_list(RZ_NONNULL RzMark *b) {
	RzList *ret = rz_list_new();
	if (!b || !ret) {
		return ret;
	}

	rz_mark_foreach(b, append_bi, ret);
	return ret;
}

/**
 * \brief Check whether any mark starts or ends in the given range.
 *
 * \param b The mark container.
 * \param from Start of the range.
 * \param to End of the range.
 * \return True if a mark starts or ends in the given range, False otherwise.
 */
RZ_API bool rz_mark_starts_or_ends(RZ_NONNULL RzMark *b, ut64 from, ut64 to) {
	return mark_starts_or_ends(b, from, to);
}

/**
 * \brief Get all mark items that contain a given offset.
 *
 * \param b The mark container.
 * \param off The offset to query.
 * \return A list of all matching mark items. NULL if none are found.
 */
RZ_API RZ_OWN RzList /*<RzMarkItem *>*/ *rz_mark_get_all_off(RZ_NONNULL RzMark *b, ut64 off) {
	return mark_match_all(b, off, RZ_MARK_MATCH_CONTAINS);
}

/**
 * \brief Get the last mark item that contains the given offset.
 *
 * \param b The mark container.
 * \param off The offset to query.
 * \return The matching mark item. NULL if none is found.
 */
RZ_API RZ_BORROW RzMarkItem *rz_mark_get_at(RZ_NONNULL RzMark *b, ut64 off) {
	return mark_match(b, off, RZ_MARK_MATCH_CONTAINS);
}

/**
 * \brief Get the mark item that starts at a given offset.
 *
 * \param b The mark container.
 * \param off The offset to query.
 * \return The mark item starting at \p off. NULL if none is found.
 */
RZ_API RZ_BORROW RzMarkItem *rz_mark_get_start(RZ_NONNULL RzMark *b, ut64 off) {
	return mark_match(b, off, RZ_MARK_MATCH_START);
}

/**
 * \brief Get the mark item that ends at a given offset.
 *
 * \param b The mark container.
 * \param off The offset to query.
 * \return The mark item ending at \p off. NULL if none is found.
 */
RZ_API RZ_BORROW RzMarkItem *rz_mark_get_end(RZ_NONNULL RzMark *b, ut64 off) {
	return mark_match(b, off, RZ_MARK_MATCH_END);
}

/**
 * \brief Get the mark item with the given name.
 *
 * \param b The mark container.
 * \param name The name of the mark to retrieve.
 * \return The matching mark item. NULL if not found.
 */
RZ_API RZ_BORROW RzMarkItem *rz_mark_get(RZ_NONNULL RzMark *b, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(b, NULL);
	RzMarkItem *r = ht_sp_find(b->ht_name, name, NULL);
	return r;
}

/**
 * \brief Get all mark items containing with a given offset.
 *
 * \param b The mark container.
 * \param off The offset to query.
 * \return A list of mark items. NULL if none are found.
 */
RZ_API RZ_BORROW const RzList /*<RzMarkItem *>*/ *rz_mark_get_list(RZ_NONNULL RzMark *b, ut64 off) {
	const RzMarksAtOffset *item = rz_mark_get_nearest_list(b, off, 0);
	return item ? item->marks : NULL;
}

/**
 * \brief Create or update a mark item.
 *
 * If a mark with the given \p name already exists, it is updated.
 * Otherwise, a new one is created.
 *
 * \param b The mark container.
 * \param name The name of the mark.
 * \param from Start offset.
 * \param to End offset.
 * \return The created or updated mark item. NULL on error.
 */
RZ_API RZ_OWN RzMarkItem *rz_mark_set(RZ_NONNULL RzMark *b, RZ_NONNULL const char *name, ut64 from, ut64 to) {
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

/**
 * \brief Free a mark container and all its associated data.
 *
 * \param b The mark container to free.
 */
RZ_API void rz_mark_free(RZ_OWN RzMark *b) {
	rz_warn_if_fail(b);
	rz_skiplist_free(b->by_off);
	ht_sp_free(b->ht_name);
	free(b);
}

/**
 * \brief Free a mark item.
 *
 * \param item The mark item to free.
 */
RZ_API void rz_mark_item_free(RZ_OWN RzMarkItem *item) {
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

/**
 * \brief Iterate through all mark items.
 *
 * \param b The mark container.
 * \param cb Callback function to invoke for each mark item.
 * \param user User-provided data passed to the callback.
 */
RZ_API void rz_mark_foreach(RZ_NONNULL RzMark *b, RZ_NONNULL RzMarkItemCb cb, RZ_NULLABLE void *user) {
	FOREACH_BODY(true);
}

/**
 * \brief Iterate through all mark items matching a regex pattern.
 *
 * \param b The mark container.
 * \param regex Regex pattern to filter mark names.
 * \param cb Callback function to invoke for each matching mark item.
 * \param user User-provided data passed to the callback.
 */
RZ_API void rz_mark_foreach_regex(RZ_NONNULL RzMark *b, RZ_NONNULL const char *regex, RZ_NONNULL RzMarkItemCb cb, RZ_NULLABLE void *user) {
	FOREACH_BODY(!regex || rz_str_glob(bi->name, regex));
}

struct unset_off_foreach_t {
	RzMark *b;
	ut64 offset;
};

/**
 * \brief Unset (remove) a specific mark item.
 *
 * The item is freed.
 *
 * \param b The mark container.
 * \param item The mark item to unset.
 * \return True if successfully unset. False otherwise.
 */
RZ_API bool rz_mark_unset(RZ_NONNULL RzMark *b, RZ_NONNULL RzMarkItem *item) {
	rz_return_val_if_fail(b && item, false);
	remove_offsetmap(b, item);
	ht_sp_delete(b->ht_name, item->name);
	return true;
}

static bool unset_off_foreach(void *user, const char *k, const void *v) {
	struct unset_off_foreach_t *u = (struct unset_off_foreach_t *)user;
	RzMarkItem *bi = (RzMarkItem *)v;

	// check if any marked range contains the current offset
	if (RZ_BETWEEN(bi->from, u->offset, bi->to)) {
		rz_mark_unset(u->b, bi);
	}
	return true;
}

/**
 * \brief Unset all marks found at a specific offset.
 *
 * \param b The mark container.
 * \param off The offset to clear marks from.
 * \return True if at least one mark was unset. False otherwise.
 */
RZ_API bool rz_mark_unset_all_off(RZ_NONNULL RzMark *b, ut64 off) {
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

/**
 * \brief Unset all marks matching a glob pattern.
 *
 * \param b The mark container.
 * \param glob Glob/Regex pattern to filter mark names.
 * \return The number of marks unset. -1 on error.
 */
RZ_API int rz_mark_unset_glob(RZ_NONNULL RzMark *b, RZ_NONNULL const char *glob) {
	rz_return_val_if_fail(b, -1);
	struct unset_foreach_t u = { .b = b, .n = 0 };
	rz_mark_foreach_regex(b, glob, unset_foreach, &u);
	return u.n;
}

/**
 * \brief Unset all marks in the container.
 *
 * \param b The mark container.
 */
RZ_API void rz_mark_unset_all(RZ_NONNULL RzMark *b) {
	rz_return_if_fail(b);
	ht_sp_free(b->ht_name);
	b->ht_name = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_mark_item_free);
	rz_skiplist_purge(b->by_off);
}

/**
 * \brief Set or remove the color of a mark item.
 *
 * \param item The mark item.
 * \param color The new color string, or NULL to remove.
 * \return The updated color string. NULL if unset.
 */
RZ_API RZ_NULLABLE const char *rz_mark_item_set_color(RZ_NONNULL RzMarkItem *item, RZ_NONNULL const char *color) {
	rz_return_val_if_fail(item, NULL);
	free(item->color);
	item->color = STRDUP_OR_NULL(color);
	return item->color;
}

/**
 * \brief Set or remove the comment of a mark item.
 *
 * \param item The mark item.
 * \param comment The new comment string.
 */
RZ_API void rz_mark_item_set_comment(RZ_NONNULL RzMarkItem *item, RZ_NULLABLE const char *comment) {
	rz_return_if_fail(item);
	free(item->comment);
	item->comment = RZ_STR_ISEMPTY(comment) ? NULL : rz_str_dup(comment);
}

/**
 * \brief Rename a mark item.
 *
 * \param b The mark container.
 * \param item The mark item to rename.
 * \param name The new name.
 * \return True if renamed successfully. False otherwise.
 */
RZ_API int rz_mark_rename(RZ_NONNULL RzMark *b, RZ_NONNULL RzMarkItem *item, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(b && item && name && *name, false);
	return update_mark_item_name(b, item, name, false);
}

/**
 * \brief Set or remove the real name of a mark item.
 *
 * \param item The mark item.
 * \param realname The new real name.
 */
RZ_API void rz_mark_item_set_realname(RZ_NONNULL RzMarkItem *item, RZ_NONNULL const char *realname) {
	rz_return_if_fail(item);
	free_item_realname(item);
	item->realname = RZ_STR_ISEMPTY(realname) ? NULL : rz_str_dup(realname);
}

static bool mark_count_foreach(RzMarkItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

/**
 * \brief Count mark items matching a glob pattern.
 *
 * \param b The mark container.
 * \param glob Glob/Regex pattern to filter mark names.
 * \return The number of matching marks. -1 on error.
 */
RZ_API int rz_mark_count(RZ_NONNULL RzMark *b, RZ_NONNULL const char *glob) {
	int count = 0;
	rz_return_val_if_fail(b, -1);
	rz_mark_foreach_regex(b, glob, mark_count_foreach, &count);
	return count;
}
