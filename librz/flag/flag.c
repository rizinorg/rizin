// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2007-2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>
#include <rz_util.h>
#include <rz_cons.h>
#include <stdio.h>

RZ_LIB_VERSION(rz_flag);

#define IS_FI_NOTIN_SPACE(f, i) (rz_flag_space_cur(f) && (i)->space != rz_flag_space_cur(f))
#define IS_FI_IN_SPACE(fi, sp)  (!(sp) || (fi)->space == (sp))
#define STRDUP_OR_NULL(s)       (!RZ_STR_ISEMPTY(s) ? strdup(s) : NULL)

static const char *str_callback(RzNum *user, ut64 off, int *ok) {
	RzFlag *f = (RzFlag *)user;
	if (ok) {
		*ok = 0;
	}
	if (f) {
		const RzList *list = rz_flag_get_list(f, off);
		RzFlagItem *item = rz_list_get_top(list);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

static void flag_skiplist_free(void *data) {
	RzFlagsAtOffset *item = (RzFlagsAtOffset *)data;
	rz_list_free(item->flags);
	free(data);
}

static int flag_skiplist_cmp(const void *va, const void *vb) {
	const RzFlagsAtOffset *a = (RzFlagsAtOffset *)va, *b = (RzFlagsAtOffset *)vb;
	if (a->off == b->off) {
		return 0;
	}
	return a->off < b->off ? -1 : 1;
}

static ut64 num_callback(RzNum *user, const char *name, int *ok) {
	RzFlag *f = (RzFlag *)user;
	if (ok) {
		*ok = 0;
	}
	RzFlagItem *item = ht_pp_find(f->ht_name, name, NULL);
	if (item) {
		// NOTE: to avoid warning infinite loop here we avoid recursivity
		if (item->alias) {
			return 0LL;
		}
		if (ok) {
			*ok = 1;
		}
		return item->offset;
	}
	return 0LL;
}

static void free_item_realname(RzFlagItem *item) {
	if (item->name != item->realname) {
		free(item->realname);
	}
}

static void free_item_name(RzFlagItem *item) {
	if (item->name != item->realname) {
		free(item->name);
	}
}

/* return the list of flag at the nearest position.
   dir == -1 -> result <= off
   dir == 0 ->  result == off
   dir == 1 ->  result >= off*/
static RzFlagsAtOffset *rz_flag_get_nearest_list(RzFlag *f, ut64 off, int dir) {
	RzFlagsAtOffset key = { .off = off };
	RzFlagsAtOffset *flags = (dir >= 0)
		? rz_skiplist_get_geq(f->by_off, &key)
		: rz_skiplist_get_leq(f->by_off, &key);
	return (dir == 0 && flags && flags->off != off) ? NULL : flags;
}

static void remove_offsetmap(RzFlag *f, RzFlagItem *item) {
	rz_return_if_fail(f && item);
	RzFlagsAtOffset *flags = rz_flag_get_nearest_list(f, item->offset, 0);
	if (flags) {
		rz_list_delete_data(flags->flags, item);
		if (rz_list_empty(flags->flags)) {
			rz_skiplist_delete(f->by_off, flags);
		}
	}
}

static RzFlagsAtOffset *flags_at_offset(RzFlag *f, ut64 off) {
	RzFlagsAtOffset *res = rz_flag_get_nearest_list(f, off, 0);
	if (res) {
		return res;
	}

	// there is no existing flagsAtOffset, we create one now
	res = RZ_NEW(RzFlagsAtOffset);
	if (!res) {
		return NULL;
	}

	res->flags = rz_list_new();
	if (!res->flags) {
		free(res);
		return NULL;
	}

	res->off = off;
	rz_skiplist_insert(f->by_off, res);
	return res;
}

static char *filter_item_name(const char *name) {
	char *res = strdup(name);
	if (!res) {
		return NULL;
	}

	rz_str_trim(res);
	rz_name_filter(res, 0, true);
	return res;
}

static void set_name(RzFlagItem *item, char *name) {
	free_item_name(item);
	item->name = name;
	free_item_realname(item);
	item->realname = item->name;
}

static bool update_flag_item_offset(RzFlag *f, RzFlagItem *item, ut64 newoff, bool is_new, bool force) {
	if (item->offset != newoff || force) {
		if (!is_new) {
			remove_offsetmap(f, item);
		}
		item->offset = newoff;

		RzFlagsAtOffset *flagsAtOffset = flags_at_offset(f, newoff);
		if (!flagsAtOffset) {
			return false;
		}

		rz_list_append(flagsAtOffset->flags, item);
		return true;
	}

	return false;
}

static bool update_flag_item_name(RzFlag *f, RzFlagItem *item, const char *newname, bool force) {
	if (!f || !item || !newname) {
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
		? ht_pp_update_key(f->ht_name, item->name, fname)
		: ht_pp_insert(f->ht_name, fname, item);
	if (res) {
		set_name(item, fname);
		return true;
	}
	free(fname);
	return false;
}

static void ht_free_flag(HtPPKv *kv) {
	free(kv->key);
	rz_flag_item_free(kv->value);
}

static bool count_flags(RzFlagItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

static bool unset_flags_space(RzFlagItem *fi, void *user) {
	fi->space = NULL;
	return true;
}

static void count_flags_in_space(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *sp = (RzSpaces *)ev->user;
	RzFlag *f = container_of(sp, RzFlag, spaces);
	RzSpaceEvent *spe = (RzSpaceEvent *)data;
	rz_flag_foreach_space(f, spe->data.count.space, count_flags, &spe->res);
}

static void unset_flagspace(RzEvent *ev, int type, void *user, void *data) {
	RzSpaces *sp = (RzSpaces *)ev->user;
	RzFlag *f = container_of(sp, RzFlag, spaces);
	const RzSpaceEvent *spe = (const RzSpaceEvent *)data;
	rz_flag_foreach_space(f, spe->data.unset.space, unset_flags_space, NULL);
}

static void new_spaces(RzFlag *f) {
	rz_spaces_init(&f->spaces, "fs");
	rz_event_hook(f->spaces.event, RZ_SPACE_EVENT_COUNT, count_flags_in_space, NULL);
	rz_event_hook(f->spaces.event, RZ_SPACE_EVENT_UNSET, unset_flagspace, NULL);
}

RZ_API RzFlag *rz_flag_new(void) {
	RzFlag *f = RZ_NEW0(RzFlag);
	if (!f) {
		return NULL;
	}
	f->num = rz_num_new(&num_callback, &str_callback, f);
	if (!f->num) {
		rz_flag_free(f);
		return NULL;
	}
	f->base = 0;
	f->cb_printf = (PrintfCallback)printf;
	f->zones = NULL;
	f->tags = sdb_new0();
	f->ht_name = ht_pp_new(NULL, ht_free_flag, NULL);
	f->by_off = rz_skiplist_new(flag_skiplist_free, flag_skiplist_cmp);
	rz_list_free(f->zones);
	new_spaces(f);
	return f;
}

RZ_API RzFlagItem *rz_flag_item_clone(RzFlagItem *item) {
	rz_return_val_if_fail(item, NULL);

	RzFlagItem *n = RZ_NEW0(RzFlagItem);
	if (!n) {
		return NULL;
	}
	n->color = STRDUP_OR_NULL(item->color);
	n->comment = STRDUP_OR_NULL(item->comment);
	n->alias = STRDUP_OR_NULL(item->alias);
	n->name = STRDUP_OR_NULL(item->name);
	n->realname = STRDUP_OR_NULL(item->realname);
	n->offset = item->offset;
	n->size = item->size;
	n->space = item->space;
	return n;
}

RZ_API void rz_flag_item_free(RzFlagItem *item) {
	if (!item) {
		return;
	}
	free(item->color);
	free(item->comment);
	free(item->alias);
	/* release only one of the two pointers if they are the same */
	free_item_name(item);
	free(item->realname);
	free(item);
}

RZ_API RzFlag *rz_flag_free(RzFlag *f) {
	rz_return_val_if_fail(f, NULL);
	rz_skiplist_free(f->by_off);
	ht_pp_free(f->ht_name);
	sdb_free(f->tags);
	rz_spaces_fini(&f->spaces);
	rz_num_free(f->num);
	rz_list_free(f->zones);
	free(f);
	return NULL;
}

static bool print_flag_name(RzFlagItem *fi, void *user) {
	RzFlag *flag = (RzFlag *)user;
	flag->cb_printf("%s\n", fi->name);
	return true;
}

struct print_flag_t {
	RzFlag *f;
	PJ *pj;
	bool in_range;
	ut64 range_from;
	ut64 range_to;
	RzSpace *fs;
	bool real;
};

static bool print_flag_json(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	pj_o(u->pj);
	pj_ks(u->pj, "name", flag->name);
	if (flag->name != flag->realname) {
		pj_ks(u->pj, "realname", flag->realname);
	}
	pj_ki(u->pj, "size", flag->size);
	if (flag->alias) {
		pj_ks(u->pj, "alias", flag->alias);
	} else {
		pj_kn(u->pj, "offset", flag->offset);
	}
	if (flag->comment) {
		pj_ks(u->pj, "comment", flag->comment);
	}
	pj_end(u->pj);
	return true;
}

static bool print_flag_rad(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	char *comment_b64 = NULL, *tmp = NULL;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	if (!u->fs || flag->space != u->fs) {
		u->fs = flag->space;
		u->f->cb_printf("fs %s\n", u->fs ? u->fs->name : "*");
	}
	if (flag->comment && *flag->comment) {
		comment_b64 = rz_base64_encode_dyn((const ut8 *)flag->comment, strlen(flag->comment));
		// prefix the armored string with "base64:"
		if (comment_b64) {
			tmp = rz_str_newf("base64:%s", comment_b64);
			free(comment_b64);
			comment_b64 = tmp;
		}
	}
	if (flag->alias) {
		u->f->cb_printf("fa %s %s\n", flag->name, flag->alias);
		if (comment_b64) {
			u->f->cb_printf("\"fC %s %s\"\n",
				flag->name, comment_b64 ? comment_b64 : "");
		}
	} else {
		u->f->cb_printf("f %s %" PFMT64d " 0x%08" PFMT64x " %s\n",
			flag->name, flag->size, flag->offset,
			comment_b64 ? comment_b64 : "");
	}

	free(comment_b64);
	return true;
}

static bool print_flag_orig_name(RzFlagItem *flag, void *user) {
	struct print_flag_t *u = (struct print_flag_t *)user;
	if (u->in_range && (flag->offset < u->range_from || flag->offset >= u->range_to)) {
		return true;
	}
	if (flag->alias) {
		const char *n = u->real ? flag->realname : flag->name;
		u->f->cb_printf("%s %" PFMT64d " %s\n", flag->alias, flag->size, n);
	} else {
		const char *n = u->real ? flag->realname : (u->f->realnames ? flag->realname : flag->name);
		u->f->cb_printf("0x%08" PFMT64x " %" PFMT64d " %s\n", flag->offset, flag->size, n);
	}
	return true;
}

/* print with rz_cons the flag items in the flag f, given as a parameter */
RZ_API void rz_flag_list(RzFlag *f, int rad, const char *pfx) {
	rz_return_if_fail(f);
	bool in_range = false;
	ut64 range_from = UT64_MAX;
	ut64 range_to = UT64_MAX;
	if (rad == 'i') {
		char *sp, *arg = strdup(pfx + 1);
		sp = strchr(arg, ' ');
		if (sp) {
			*sp++ = 0;
			range_from = rz_num_math(f->num, arg);
			range_to = rz_num_math(f->num, sp);
		} else {
			const int bsize = 4096;
			range_from = rz_num_math(f->num, arg);
			range_to = range_from + bsize;
		}
		in_range = true;
		free(arg);
		rad = pfx[0];
		pfx = NULL;
	}

	if (pfx && !*pfx) {
		pfx = NULL;
	}

	switch (rad) {
	case 'q':
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_name, f);
		break;
	case 'j': {
		PJ *pj = pj_new();
		struct print_flag_t u = {
			.f = f,
			.pj = pj,
			.in_range = in_range,
			.range_from = range_from,
			.range_to = range_to,
			.real = false
		};
		pj_a(pj);
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_json, &u);
		pj_end(pj);
		f->cb_printf("%s\n", pj_string(pj));
		pj_free(pj);
		break;
	}
	case 1:
	case '*': {
		struct print_flag_t u = {
			.f = f,
			.in_range = in_range,
			.range_from = range_from,
			.range_to = range_to,
			.fs = NULL,
		};
		rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_rad, &u);
		break;
	}
	default:
	case 'n': {
		if (!pfx || pfx[0] != 'j') { // show original name
			struct print_flag_t u = {
				.f = f,
				.in_range = in_range,
				.range_from = range_from,
				.range_to = range_to,
				.real = (rad == 'n')
			};
			rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_orig_name, &u);
		} else {
			PJ *pj = pj_new();
			struct print_flag_t u = {
				.f = f,
				.pj = pj,
				.in_range = in_range,
				.range_from = range_from,
				.range_to = range_to,
				.real = true
			};
			pj_a(pj);
			rz_flag_foreach_space(f, rz_flag_space_cur(f), print_flag_json, &u);
			pj_end(pj);
			f->cb_printf("%s\n", pj_string(pj));
			pj_free(pj);
		}
		break;
	}
	}
}

static RzFlagItem *evalFlag(RzFlag *f, RzFlagItem *item) {
	rz_return_val_if_fail(f && item, NULL);
	if (item->alias) {
		item->offset = rz_num_math(f->num, item->alias);
	}
	return item;
}

/* return true if flag.* exist at offset. Otherwise, false is returned.
 * For example (f, "sym", 3, 0x1000)*/
RZ_API bool rz_flag_exist_at(RzFlag *f, const char *flag_prefix, ut16 fp_size, ut64 off) {
	rz_return_val_if_fail(f && flag_prefix, false);
	RzListIter *iter = NULL;
	RzFlagItem *item = NULL;
	const RzList *list = rz_flag_get_list(f, off);
	if (list) {
		rz_list_foreach (list, iter, item) {
			if (item->name && !strncmp(item->name, flag_prefix, fp_size)) {
				return true;
			}
		}
	}
	return false;
}

/* return the flag item with name "name" in the RzFlag "f", if it exists.
 * Otherwise, NULL is returned. */
RZ_API RzFlagItem *rz_flag_get(RzFlag *f, const char *name) {
	rz_return_val_if_fail(f, NULL);
	RzFlagItem *r = ht_pp_find(f->ht_name, name, NULL);
	return r ? evalFlag(f, r) : NULL;
}

/* return the first flag item that can be found at offset "off", or NULL otherwise */
RZ_API RzFlagItem *rz_flag_get_i(RzFlag *f, ut64 off) {
	rz_return_val_if_fail(f, NULL);
	const RzList *list = rz_flag_get_list(f, off);
	return list ? evalFlag(f, rz_list_get_top(list)) : NULL;
}

/* return the first flag that matches an offset ordered by the order of
 * operands to the function.
 * Pass in the name of each space, in order, followed by a NULL */
RZ_API RzFlagItem *rz_flag_get_by_spaces(RzFlag *f, ut64 off, ...) {
	rz_return_val_if_fail(f, NULL);

	const RzList *list = rz_flag_get_list(f, off);
	RzFlagItem *ret = NULL;
	const char *spacename;
	RzSpace **spaces;
	RzListIter *iter;
	RzFlagItem *flg;
	va_list ap, aq;
	size_t n_spaces = 0, i;

	va_start(ap, off);
	// some quick checks for common cases
	if (rz_list_empty(list)) {
		goto beach;
	}
	if (rz_list_length(list) == 1) {
		ret = rz_list_get_top(list);
		goto beach;
	}

	// count spaces in the vaarg
	va_copy(aq, ap);
	spacename = va_arg(aq, const char *);
	while (spacename) {
		n_spaces++;
		spacename = va_arg(aq, const char *);
	}
	va_end(aq);

	// get RzSpaces from the names
	i = 0;
	spaces = RZ_NEWS(RzSpace *, n_spaces);
	spacename = va_arg(ap, const char *);
	while (spacename) {
		RzSpace *space = rz_flag_space_get(f, spacename);
		if (space) {
			spaces[i++] = space;
		}
		spacename = va_arg(ap, const char *);
	}
	n_spaces = i;

	ut64 min_space_i = n_spaces + 1;
	rz_list_foreach (list, iter, flg) {
		// get the "priority" of the flag flagspace and
		// check if better than what we found so far
		for (i = 0; i < n_spaces; i++) {
			if (flg->space == spaces[i]) {
				break;
			}
			if (i >= min_space_i) {
				break;
			}
		}

		if (i < min_space_i) {
			min_space_i = i;
			ret = flg;
		}
		if (!min_space_i) {
			// this is the best flag we can find, let's stop immediately
			break;
		}
	}
	free(spaces);
beach:
	va_end(ap);
	return ret ? evalFlag(f, ret) : NULL;
}

static bool isFunctionFlag(const char *n) {
	return (!strncmp(n, "sym.func.", 9) || !strncmp(n, "method.", 7) || !strncmp(n, "sym.", 4) || !strncmp(n, "func.", 5) || !strncmp(n, "fcn.0", 5));
}

/* returns the last flag item defined before or at the given offset.
 * NULL is returned if such a item is not found. */
RZ_API RzFlagItem *rz_flag_get_at(RzFlag *f, ut64 off, bool closest) {
	rz_return_val_if_fail(f, NULL);

	RzFlagItem *nice = NULL;
	RzListIter *iter;
	const RzFlagsAtOffset *flags_at = rz_flag_get_nearest_list(f, off, -1);
	if (!flags_at) {
		return NULL;
	}
	if (flags_at->off == off) {
		RzFlagItem *item;
		rz_list_foreach (flags_at->flags, iter, item) {
			if (IS_FI_NOTIN_SPACE(f, item)) {
				continue;
			}
			if (nice) {
				if (isFunctionFlag(nice->name)) {
					nice = item;
				}
			} else {
				nice = item;
			}
		}
		if (nice) {
			return evalFlag(f, nice);
		}
	}

	if (!closest) {
		return NULL;
	}
	while (!nice && flags_at) {
		RzFlagItem *item;
		rz_list_foreach (flags_at->flags, iter, item) {
			if (IS_FI_NOTIN_SPACE(f, item)) {
				continue;
			}
			if (item->offset == off) {
				eprintf("XXX Should never happend\n");
				return evalFlag(f, item);
			}
			nice = item;
			break;
		}
		if (!nice && flags_at->off) {
			flags_at = rz_flag_get_nearest_list(f, flags_at->off - 1, -1);
		} else {
			flags_at = NULL;
		}
	}
	return nice ? evalFlag(f, nice) : NULL;
}

static bool append_to_list(RzFlagItem *fi, void *user) {
	RzList *ret = (RzList *)user;
	rz_list_append(ret, fi);
	return true;
}

RZ_API RzList *rz_flag_all_list(RzFlag *f, bool by_space) {
	RzList *ret = rz_list_new();
	if (!ret) {
		return NULL;
	}

	RzSpace *cur = by_space ? rz_flag_space_cur(f) : NULL;
	rz_flag_foreach_space(f, cur, append_to_list, ret);
	return ret;
}

/* return the list of flag items that are associated with a given offset */
RZ_API const RzList * /*<RzFlagItem*>*/ rz_flag_get_list(RzFlag *f, ut64 off) {
	const RzFlagsAtOffset *item = rz_flag_get_nearest_list(f, off, 0);
	return item ? item->flags : NULL;
}

RZ_API char *rz_flag_get_liststr(RzFlag *f, ut64 off) {
	RzFlagItem *fi;
	RzListIter *iter;
	const RzList *list = rz_flag_get_list(f, off);
	char *p = NULL;
	rz_list_foreach (list, iter, fi) {
		p = rz_str_appendf(p, "%s%s",
			fi->realname, iter->n ? "," : "");
	}
	return p;
}

// Set a new flag named `name` at offset `off`. If there's already a flag with
// the same name, slightly change the name by appending ".%d" as suffix
RZ_API RzFlagItem *rz_flag_set_next(RzFlag *f, const char *name, ut64 off, ut32 size) {
	rz_return_val_if_fail(f && name, NULL);
	if (!rz_flag_get(f, name)) {
		return rz_flag_set(f, name, off, size);
	}
	int i, newNameSize = strlen(name);
	char *newName = malloc(newNameSize + 16);
	if (!newName) {
		return NULL;
	}
	strcpy(newName, name);
	for (i = 0;; i++) {
		snprintf(newName + newNameSize, 15, ".%d", i);
		if (!rz_flag_get(f, newName)) {
			RzFlagItem *fi = rz_flag_set(f, newName, off, size);
			if (fi) {
				free(newName);
				return fi;
			}
		}
	}
	return NULL;
}

/* create or modify an existing flag item with the given name and parameters.
 * The realname of the item will be the same as the name.
 * NULL is returned in case of any errors during the process. */
RZ_API RzFlagItem *rz_flag_set(RzFlag *f, const char *name, ut64 off, ut32 size) {
	rz_return_val_if_fail(f && name && *name, NULL);

	bool is_new = false;
	char *itemname = filter_item_name(name);
	if (!itemname) {
		return NULL;
	}

	RzFlagItem *item = rz_flag_get(f, itemname);
	free(itemname);
	if (item && item->offset == off) {
		item->size = size;
		return item;
	}

	if (!item) {
		item = RZ_NEW0(RzFlagItem);
		if (!item) {
			goto err;
		}
		is_new = true;
	}

	item->space = rz_flag_space_cur(f);
	item->size = size;

	update_flag_item_offset(f, item, off + f->base, is_new, true);
	update_flag_item_name(f, item, name, true);
	return item;
err:
	rz_flag_item_free(item);
	return NULL;
}

/* add/replace/remove the alias of a flag item */
RZ_API void rz_flag_item_set_alias(RzFlagItem *item, const char *alias) {
	rz_return_if_fail(item);
	free(item->alias);
	item->alias = RZ_STR_ISEMPTY(alias) ? NULL : strdup(alias);
}

/* add/replace/remove the comment of a flag item */
RZ_API void rz_flag_item_set_comment(RzFlagItem *item, const char *comment) {
	rz_return_if_fail(item);
	free(item->comment);
	item->comment = RZ_STR_ISEMPTY(comment) ? NULL : strdup(comment);
}

/* add/replace/remove the realname of a flag item */
RZ_API void rz_flag_item_set_realname(RzFlagItem *item, const char *realname) {
	rz_return_if_fail(item);
	free_item_realname(item);
	item->realname = RZ_STR_ISEMPTY(realname) ? NULL : strdup(realname);
}

/* add/replace/remove the color of a flag item */
RZ_API const char *rz_flag_item_set_color(RzFlagItem *item, const char *color) {
	rz_return_val_if_fail(item, NULL);
	free(item->color);
	item->color = (color && *color) ? strdup(color) : NULL;
	return item->color;
}

/* change the name of a flag item, if the new name is available.
 * true is returned if everything works well, false otherwise */
RZ_API int rz_flag_rename(RzFlag *f, RzFlagItem *item, const char *name) {
	rz_return_val_if_fail(f && item && name && *name, false);
	return update_flag_item_name(f, item, name, false);
}

/* unset the given flag item.
 * returns true if the item is successfully unset, false otherwise.
 *
 * NOTE: the item is freed. */
RZ_API bool rz_flag_unset(RzFlag *f, RzFlagItem *item) {
	rz_return_val_if_fail(f && item, false);
	remove_offsetmap(f, item);
	ht_pp_delete(f->ht_name, item->name);
	return true;
}

/* unset the first flag item found at offset off.
 * return true if such a flag is found and unset, false otherwise. */
RZ_API bool rz_flag_unset_off(RzFlag *f, ut64 off) {
	rz_return_val_if_fail(f, false);
	RzFlagItem *item = rz_flag_get_i(f, off);
	if (item && rz_flag_unset(f, item)) {
		return true;
	}
	return false;
}

struct unset_foreach_t {
	RzFlag *f;
	int n;
};

static bool unset_foreach(RzFlagItem *fi, void *user) {
	struct unset_foreach_t *u = (struct unset_foreach_t *)user;
	if (IS_FI_NOTIN_SPACE(u->f, fi)) {
		return true;
	}
	rz_flag_unset(u->f, fi);
	u->n++;
	return true;
}

/* unset all the flag items that satisfy the given glob.
 * return the number of unset items. -1 on error */
// XXX This is O(n^n) because unset_globa iterates all flags and unset too.
RZ_API int rz_flag_unset_glob(RzFlag *f, const char *glob) {
	rz_return_val_if_fail(f, -1);

	struct unset_foreach_t u = { .f = f, .n = 0 };
	rz_flag_foreach_glob(f, glob, unset_foreach, &u);
	return u.n;
}

/* unset the flag item with the given name.
 * returns true if the item is found and unset, false otherwise. */
RZ_API bool rz_flag_unset_name(RzFlag *f, const char *name) {
	rz_return_val_if_fail(f, false);
	RzFlagItem *item = ht_pp_find(f->ht_name, name, NULL);
	return item && rz_flag_unset(f, item);
}

/* unset all flag items in the RzFlag f */
RZ_API void rz_flag_unset_all(RzFlag *f) {
	rz_return_if_fail(f);
	ht_pp_free(f->ht_name);
	f->ht_name = ht_pp_new(NULL, ht_free_flag, NULL);
	rz_skiplist_purge(f->by_off);
	rz_spaces_fini(&f->spaces);
	new_spaces(f);
}

/**
 * \brief Unset all flag items in the space with the given name
 *
 * \param f an RzFlag
 * \param space_name name of the space
 */
RZ_API void rz_flag_unset_all_in_space(RzFlag *f, const char *space_name) {
	rz_flag_space_push(f, space_name);
	RzList *flags = rz_flag_all_list(f, true);
	RzFlagItem *flag;
	RzListIter *iter;
	rz_list_foreach (flags, iter, flag) {
		rz_flag_unset(f, flag);
	}
	rz_flag_space_pop(f);
	free(flags);
}

struct flag_relocate_t {
	RzFlag *f;
	ut64 off;
	ut64 off_mask;
	ut64 neg_mask;
	ut64 to;
	int n;
};

static bool flag_relocate_foreach(RzFlagItem *fi, void *user) {
	struct flag_relocate_t *u = (struct flag_relocate_t *)user;
	ut64 fn = fi->offset & u->neg_mask;
	ut64 on = u->off & u->neg_mask;
	if (fn == on) {
		ut64 fm = fi->offset & u->off_mask;
		ut64 om = u->to & u->off_mask;
		update_flag_item_offset(u->f, fi, (u->to & u->neg_mask) + fm + om, false, false);
		u->n++;
	}
	return true;
}

RZ_API int rz_flag_relocate(RzFlag *f, ut64 off, ut64 off_mask, ut64 to) {
	rz_return_val_if_fail(f, -1);
	struct flag_relocate_t u = {
		.f = f,
		.off = off,
		.off_mask = off_mask,
		.neg_mask = ~(off_mask),
		.to = to,
		.n = 0
	};

	rz_flag_foreach(f, flag_relocate_foreach, &u);
	return u.n;
}

RZ_API bool rz_flag_move(RzFlag *f, ut64 at, ut64 to) {
	rz_return_val_if_fail(f, false);
	RzFlagItem *item = rz_flag_get_i(f, at);
	if (item) {
		rz_flag_set(f, item->name, to, item->size);
		return true;
	}
	return false;
}

// BIND
RZ_API void rz_flag_bind(RzFlag *f, RzFlagBind *fb) {
	rz_return_if_fail(f && fb);
	fb->f = f;
	fb->exist_at = rz_flag_exist_at;
	fb->get = rz_flag_get;
	fb->get_at = rz_flag_get_at;
	fb->get_list = rz_flag_get_list;
	fb->set = rz_flag_set;
	fb->unset = rz_flag_unset;
	fb->unset_name = rz_flag_unset_name;
	fb->unset_off = rz_flag_unset_off;
	fb->set_fs = rz_flag_space_set;
	fb->push_fs = rz_flag_space_push;
	fb->pop_fs = rz_flag_space_pop;
}

static bool flag_count_foreach(RzFlagItem *fi, void *user) {
	int *count = (int *)user;
	(*count)++;
	return true;
}

RZ_API int rz_flag_count(RzFlag *f, const char *glob) {
	int count = 0;
	rz_return_val_if_fail(f, -1);
	rz_flag_foreach_glob(f, glob, flag_count_foreach, &count);
	return count;
}

#define FOREACH_BODY(condition) \
	RzSkipListNode *it, *tmp; \
	RzFlagsAtOffset *flags_at; \
	RzListIter *it2, *tmp2; \
	RzFlagItem *fi; \
	rz_skiplist_foreach_safe(f->by_off, it, tmp, flags_at) { \
		if (flags_at) { \
			rz_list_foreach_safe (flags_at->flags, it2, tmp2, fi) { \
				if (condition) { \
					if (!cb(fi, user)) { \
						return; \
					} \
				} \
			} \
		} \
	}

RZ_API void rz_flag_foreach(RzFlag *f, RzFlagItemCb cb, void *user) {
	FOREACH_BODY(true);
}

RZ_API void rz_flag_foreach_prefix(RzFlag *f, const char *pfx, int pfx_len, RzFlagItemCb cb, void *user) {
	pfx_len = pfx_len < 0 ? strlen(pfx) : pfx_len;
	FOREACH_BODY(!strncmp(fi->name, pfx, pfx_len));
}

RZ_API void rz_flag_foreach_range(RzFlag *f, ut64 from, ut64 to, RzFlagItemCb cb, void *user) {
	FOREACH_BODY(fi->offset >= from && fi->offset < to);
}

RZ_API void rz_flag_foreach_glob(RzFlag *f, const char *glob, RzFlagItemCb cb, void *user) {
	FOREACH_BODY(!glob || rz_str_glob(fi->name, glob));
}

RZ_API void rz_flag_foreach_space_glob(RzFlag *f, const char *glob, const RzSpace *space, RzFlagItemCb cb, void *user) {
	FOREACH_BODY(IS_FI_IN_SPACE(fi, space) && (!glob || rz_str_glob(fi->name, glob)));
}

RZ_API void rz_flag_foreach_space(RzFlag *f, const RzSpace *space, RzFlagItemCb cb, void *user) {
	FOREACH_BODY(IS_FI_IN_SPACE(fi, space));
}
