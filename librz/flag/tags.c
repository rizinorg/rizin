// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>

RZ_API RzList *rz_flag_tags_set(RzFlag *f, const char *name, const char *words) {
	rz_return_val_if_fail(f && name && words, NULL);
	const char *k = sdb_fmt("tag.%s", name);
	sdb_set(f->tags, k, words, -1);
	return NULL;
}

RZ_API RzList *rz_flag_tags_list(RzFlag *f, const char *name) {
	rz_return_val_if_fail(f, NULL);
	if (name) {
		const char *k = sdb_fmt("tag.%s", name);
		char *words = sdb_get(f->tags, k, NULL);
		return rz_str_split_list(words, " ", 0);
	}
	RzList *res = rz_list_newf(free);
	SdbList *o = sdb_foreach_list(f->tags, false);
	SdbListIter *iter;
	SdbKv *kv;
	ls_foreach (o, iter, kv) {
		const char *tag = sdbkv_key(kv);
		if (strlen(tag) < 5) {
			continue;
		}
		rz_list_append(res, (void *)strdup(tag + 4));
	}
	ls_free(o);
	return res;
}

RZ_API void rz_flag_tags_reset(RzFlag *f, const char *name) {
	// TODO: use name
	rz_return_if_fail(f);
	sdb_reset(f->tags);
}

struct iter_glob_flag_t {
	RzList *res;
	RzList *words;
};

static bool iter_glob_flag(RzFlagItem *fi, void *user) {
	struct iter_glob_flag_t *u = (struct iter_glob_flag_t *)user;
	RzListIter *iter;
	const char *word;

	rz_list_foreach (u->words, iter, word) {
		if (rz_str_glob(fi->name, word)) {
			rz_list_append(u->res, fi);
		}
	}
	return true;
}

RZ_API RzList *rz_flag_tags_get(RzFlag *f, const char *name) {
	rz_return_val_if_fail(f && name, NULL);
	const char *k = sdb_fmt("tag.%s", name);
	RzList *res = rz_list_newf(NULL);
	char *words = sdb_get(f->tags, k, NULL);
	if (words) {
		RzList *list = rz_str_split_list(words, " ", 0);
		struct iter_glob_flag_t u = { .res = res, .words = list };
		rz_flag_foreach(f, iter_glob_flag, &u);
		rz_list_free(list);
		free(words);
	}
	return res;
}
