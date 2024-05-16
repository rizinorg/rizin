// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "sdb.h"

RZ_API void sdb_ns_lock(Sdb *s, int lock, int depth) {
	SdbNs *ns;
	RzListIter *it;
	s->ns_lock = lock;
	if (depth) { // handles -1 as infinite
		rz_list_foreach (s->ns, it, ns) {
			sdb_ns_lock(ns->sdb, lock, depth - 1);
		}
	}
}

static void ns_free_exc_list(Sdb *s, RzList /*<void *>*/*list) {
	if (!list || !s) {
		return;
	}
	if (rz_list_contains(list, s)) {
		return;
	}
	rz_list_append(list, s);
	SdbNs *ns;
	RzListIter *it, *it2;
	rz_list_foreach_safe (s->ns, it, it2, ns) {
		bool deleted = false;
		if (!rz_list_contains(list, ns)) {
			rz_list_delete(s->ns, it); // free (it)
			free(ns->name);
			ns->name = NULL;
			deleted = true;
			if (ns->sdb) {
				if (sdb_free(ns->sdb)) {
					ns->sdb = NULL;
					free(ns->name);
					ns->name = NULL;
				}
			}
			rz_list_append(list, ns);
			rz_list_append(list, ns->sdb);
			ns_free_exc_list(ns->sdb, list);
			sdb_free(ns->sdb);
		}
		if (!deleted) {
			sdb_free(ns->sdb);
			s->ns->free = NULL;
			rz_list_delete(s->ns, it); // free (it)
		}
		free(ns);
	}
	rz_list_free(s->ns);
	s->ns = NULL;
}

RZ_API void sdb_ns_free_all(Sdb *s) {
	if (!s) {
		return;
	}
	RzList *list = rz_list_new();
	ns_free_exc_list(s, list);
	rz_list_free(list);
	rz_list_free(s->ns);
	s->ns = NULL;
}

static SdbNs *sdb_ns_new(Sdb *s, const char *name, ut32 hash) {
	char dir[SDB_MAX_PATH];
	SdbNs *ns;
	if (s->dir && *s->dir && name && *name) {
		int dir_len = strlen(s->dir);
		int name_len = strlen(name);
		if ((dir_len + name_len + 3) > SDB_MAX_PATH) {
			return NULL;
		}
		memcpy(dir, s->dir, dir_len);
		memcpy(dir + dir_len, ".", 1);
		memcpy(dir + dir_len + 1, name, name_len + 1);
	} else {
		dir[0] = 0;
	}
	ns = malloc(sizeof(SdbNs));
	if (!ns) {
		return NULL;
	}
	ns->hash = hash;
	ns->name = name ? strdup(name) : NULL;
	// ns->sdb = sdb_new (dir, ns->name, 0);
	ns->sdb = sdb_new0();
	// TODO: generate path

	if (ns->sdb) {
		free(ns->sdb->path);
		ns->sdb->path = NULL;
		if (*dir) {
			ns->sdb->path = strdup(dir);
		}
		free(ns->sdb->name);
		if (name && *name) {
			ns->sdb->name = strdup(name);
		}
	} else {
		free(ns->name);
		free(ns);
		ns = NULL;
	}
	return ns;
}

static void sdb_ns_free(SdbNs *ns) {
	sdb_free(ns->sdb);
	free(ns->name);
	free(ns);
}

RZ_API bool sdb_ns_unset(Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	RzListIter *it;
	if (s && (name || r)) {
		rz_list_foreach (s->ns, it, ns) {
			if (name && (!strcmp(name, ns->name))) {
				sdb_ns_free(ns);
				rz_list_delete(s->ns, it);
				return true;
			}
			if (r && ns->sdb == r) {
				sdb_ns_free(ns);
				rz_list_delete(s->ns, it);
				return true;
			}
		}
	}
	return false;
}

RZ_API int sdb_ns_set(Sdb *s, const char *name, Sdb *r) {
	SdbNs *ns;
	RzListIter *it;
	ut32 hash = sdb_hash(name);
	if (!s || !r || !name) {
		return 0;
	}
	rz_list_foreach (s->ns, it, ns) {
		if (ns->hash == hash) {
			if (ns->sdb == r) {
				return 0;
			}
			sdb_free(ns->sdb);
			r->refs++; // sdb_ref / sdb_unref //
			ns->sdb = r;
			return 1;
		}
	}
	if (s->ns_lock) {
		return 0;
	}
	ns = RZ_NEW(SdbNs);
	ns->name = strdup(name);
	ns->hash = hash;
	ns->sdb = r;
	r->refs++;
	rz_list_append(s->ns, ns);
	return 1;
}

RZ_API Sdb *sdb_ns(Sdb *s, const char *name, int create) {
	RzListIter *it;
	SdbNs *ns;
	ut32 hash;
	if (!s || !name || !*name) {
		return NULL;
	}
	hash = sdb_hash(name);
	rz_list_foreach (s->ns, it, ns) {
		if (ns->hash == hash) {
			return ns->sdb;
		}
	}
	if (!create) {
		return NULL;
	}
	if (s->ns_lock) {
		return NULL;
	}
	ns = sdb_ns_new(s, name, hash);
	if (!ns) {
		return NULL;
	}
	rz_list_append(s->ns, ns);
	return ns->sdb;
}

RZ_API Sdb *sdb_ns_path(Sdb *s, const char *path, int create) {
	char *ptr, *str;
	char *slash;

	if (!s || !path || !*path)
		return s;
	ptr = str = strdup(path);
	do {
		slash = strchr(ptr, '/');
		if (slash)
			*slash = 0;
		s = sdb_ns(s, ptr, create);
		if (!s)
			break;
		if (slash)
			ptr = slash + 1;
	} while (slash);
	free(str);
	return s;
}

static void ns_sync(Sdb *s, RzList /*<SdbNs *>*/ *list) {
	SdbNs *ns;
	RzListIter *it;
	rz_list_foreach (s->ns, it, ns) {
		if (rz_list_contains(list, ns)) {
			continue;
		}
		rz_list_append(list, ns);
		ns_sync(ns->sdb, list);
		sdb_sync(ns->sdb);
	}
	sdb_sync(s);
}

RZ_API void sdb_ns_sync(Sdb *s) {
	RzList *list = rz_list_new();
	ns_sync(s, list);
	rz_list_free(list);
}
