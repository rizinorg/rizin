// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2019 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_spaces.h"

RZ_API RzSpaces *rz_spaces_new(const char *name) {
	RzSpaces *sp = RZ_NEW0(RzSpaces);
	if (!sp || !rz_spaces_init(sp, name)) {
		free(sp);
		return NULL;
	}
	return sp;
}

RZ_API bool rz_spaces_init(RzSpaces *sp, const char *name) {
	rz_return_val_if_fail(sp && name, false);
	sp->name = rz_str_dup(name);
	if (!sp->name) {
		goto fail;
	}

	sp->spaces = NULL;
	sp->current = NULL;
	sp->spacestack = rz_list_new();
	if (!sp->spacestack) {
		goto fail;
	}

	sp->event = rz_event_new(sp);
	if (!sp->event) {
		goto fail;
	}

	return true;

fail:
	rz_spaces_fini(sp);
	return false;
}

RZ_API void rz_spaces_free(RzSpaces *sp) {
	rz_spaces_fini(sp);
	free(sp);
}

static inline void space_free(RzSpace *s) {
	if (s) {
		free(s->name);
		free(s);
	}
}

static void space_node_free(RBNode *n, void *user) {
	RzSpace *s = container_of(n, RzSpace, rb);
	space_free(s);
}

RZ_API void rz_spaces_fini(RzSpaces *sp) {
	rz_list_free(sp->spacestack);
	sp->spacestack = NULL;
	rz_rbtree_free(sp->spaces, space_node_free, NULL);
	sp->spaces = NULL;
	rz_event_free(sp->event);
	sp->event = NULL;
	sp->current = NULL;
	RZ_FREE(sp->name);
}

RZ_API void rz_spaces_purge(RzSpaces *sp) {
	sp->current = NULL;
	rz_list_purge(sp->spacestack);
	rz_rbtree_free(sp->spaces, space_node_free, NULL);
	sp->spaces = NULL;
}

static int name_space_cmp(const void *incoming, const RBNode *rb, void *user) {
	const RzSpace *s = container_of(rb, const RzSpace, rb);
	return strcmp(incoming, s->name);
}

RZ_API RzSpace *rz_spaces_get(RzSpaces *sp, const char *name) {
	if (!name) {
		return NULL;
	}
	RBNode *n = rz_rbtree_find(sp->spaces, (void *)name, name_space_cmp, NULL);
	return n ? container_of(n, RzSpace, rb) : NULL;
}

static int space_cmp(const void *incoming, const RBNode *rb, void *user) {
	const RzSpace *a = (const RzSpace *)incoming;
	const RzSpace *b = container_of(rb, const RzSpace, rb);
	return strcmp(a->name, b->name);
}

RZ_API RzSpace *rz_spaces_add(RzSpaces *sp, const char *name) {
	rz_return_val_if_fail(sp, NULL);
	if (!name || !*name || *name == '*') {
		return NULL;
	}

	RzSpace *s = rz_spaces_get(sp, name);
	if (s) {
		return s;
	}

	s = RZ_NEW0(RzSpace);
	if (!s) {
		return NULL;
	}

	s->name = rz_str_dup(name);
	if (!s->name) {
		free(s);
		return NULL;
	}

	rz_rbtree_insert(&sp->spaces, s, &s->rb, space_cmp, NULL);
	return s;
}

RZ_API RzSpace *rz_spaces_set(RzSpaces *sp, const char *name) {
	sp->current = rz_spaces_add(sp, name);
	return sp->current;
}

static inline bool spaces_unset_single(RzSpaces *sp, const char *name) {
	RzSpace *space = rz_spaces_get(sp, name);
	if (!space) {
		return false;
	}

	RzSpaceEvent ev = { .data.unset.space = space };
	rz_event_send(sp->event, RZ_SPACE_EVENT_UNSET, &ev);
	if (sp->current == space) {
		sp->current = NULL;
	}
	return rz_rbtree_delete(&sp->spaces, (void *)name, name_space_cmp, NULL, space_node_free, NULL);
}

RZ_API bool rz_spaces_unset(RzSpaces *sp, const char *name) {
	if (name) {
		return spaces_unset_single(sp, name);
	}

	RzList *names = rz_list_newf((RzListFree)free);
	if (!names) {
		return false;
	}

	RBIter it;
	RzSpace *s;
	rz_spaces_foreach(sp, it, s) {
		rz_list_append(names, rz_str_dup(s->name));
	}

	RzListIter *lit;
	const char *n;
	bool res = false;
	rz_list_foreach (names, lit, n) {
		res |= spaces_unset_single(sp, n);
	}
	rz_list_free(names);
	return res;
}

RZ_API int rz_spaces_count(RzSpaces *sp, const char *name) {
	RzSpace *s = rz_spaces_get(sp, name);
	if (!s) {
		return 0;
	}
	RzSpaceEvent ev = { .data.count.space = s, .res = 0 };
	rz_event_send(sp->event, RZ_SPACE_EVENT_COUNT, &ev);
	return ev.res;
}

RZ_API bool rz_spaces_push(RzSpaces *sp, const char *name) {
	rz_return_val_if_fail(sp, false);

	rz_list_push(sp->spacestack, sp->current ? sp->current->name : "*");
	rz_spaces_set(sp, name);
	return true;
}

RZ_API bool rz_spaces_pop(RzSpaces *sp) {
	char *name = rz_list_pop(sp->spacestack);
	if (!name) {
		return false;
	}

	RzSpace *s = rz_spaces_get(sp, name);
	rz_spaces_set(sp, s ? s->name : NULL);
	return true;
}

RZ_API bool rz_spaces_rename(RzSpaces *sp, const char *oname, const char *nname) {
	if (!oname && !sp->current) {
		return false;
	}

	RzSpace *s;
	if (oname) {
		s = rz_spaces_get(sp, oname);
		if (!s) {
			return false;
		}
	} else {
		s = sp->current;
	}

	RzSpace *sn = rz_spaces_get(sp, nname);
	if (sn) {
		return false;
	}

	RzSpaceEvent ev = {
		.data.rename.oldname = s->name,
		.data.rename.newname = nname,
		.data.rename.space = s
	};
	rz_event_send(sp->event, RZ_SPACE_EVENT_RENAME, &ev);

	rz_rbtree_delete(&sp->spaces, (void *)s->name, name_space_cmp, NULL, NULL, NULL);
	free(s->name);
	s->name = rz_str_dup(nname);
	rz_rbtree_insert(&sp->spaces, s, &s->rb, space_cmp, NULL);

	return true;
}
