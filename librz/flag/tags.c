// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>

RZ_API void rz_flag_tags_set(RzFlag *f, const char *name, const char *words) {
	rz_return_if_fail(f && name && words);
	char tmpbuf[256];
	sdb_set(f->tags, rz_strf(tmpbuf, "tag.%s", name), words, -1);
}

RZ_API RZ_OWN RzList /*<char *>*/ *rz_flag_tags_list(RzFlag *f) {
	rz_return_val_if_fail(f, NULL);
	RzList *res = rz_list_newf(free);
	RzList *o = sdb_get_kv_list(f->tags, false);
	RzListIter *iter;
	SdbKv *kv;
	rz_list_foreach (o, iter, kv) {
		const char *tag = sdbkv_key(kv);
		if (strlen(tag) < 5) {
			continue;
		}
		rz_list_append(res, (void *)strdup(tag + 4));
	}
	rz_list_free(o);
	return res;
}

RZ_API void rz_flag_tags_reset(RzFlag *f, const char *name) {
	// TODO: use name
	rz_return_if_fail(f);
	sdb_reset(f->tags);
}

struct iter_glob_flag_t {
	RzList /*<RzFlagItem *>*/ *res;
	RzList /*<char *>*/ *words;
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

RZ_API RzList /*<RzFlagItem *>*/ *rz_flag_tags_get(RzFlag *f, const char *name) {
	rz_return_val_if_fail(f && name, NULL);
	char tmpbuf[256];
	RzList *res = rz_list_newf(NULL);
	char *words = sdb_get(f->tags, rz_strf(tmpbuf, "tag.%s", name), NULL);
	if (words) {
		RzList *list = rz_str_split_list(words, " ", 0);
		struct iter_glob_flag_t u = { .res = res, .words = list };
		rz_flag_foreach(f, iter_glob_flag, &u);
		rz_list_free(list);
		free(words);
	}
	return res;
}
