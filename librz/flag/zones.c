/* radare - LGPL - Copyright 2016-2020 - pancake */

#include <rz_flag.h>
#include <rz_util.h>

#define DB f->zones

#if !RZ_FLAG_ZONE_USE_SDB

static RzFlagZoneItem *rz_flag_zone_get (RzFlag *f, const char *name) {
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (DB, iter, zi) {
		if (!strcmp (name, zi->name)) {
			return zi;
		}
	}
	return NULL;
}
#endif

static RzFlagZoneItem *rz_flag_zone_get_inrange (RzFlag *f, ut64 from, ut64 to) {
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (DB, iter, zi) {
		if (RZ_BETWEEN (from, zi->from, to)) {
			return zi;
		}
	}
	return NULL;
}

RZ_API bool rz_flag_zone_add(RzFlag *f, const char *name, ut64 addr) {
	rz_return_val_if_fail (f && name && *name, false);
#if RZ_FLAG_ZONE_USE_SDB
	RzFlagZoneItem zi = { 0, 0, (const char *)name };
	if (!DB) {
		return false;
	}
	const char *bound = sdb_const_get (DB, name, NULL);
	if (bound) {
		sdb_fmt_tobin (bound, "qq", &zi);
		if (addr < zi.from) {
			zi.from = addr;
		}
		if (addr > zi.to) {
			zi.to = addr;
		}
		char *newBounds = sdb_fmt_tostr (&zi, "qq");
		sdb_set (DB, name, newBounds, 0);
		free (newBounds);
	} else {
		sdb_set (DB, name, sdb_fmt ("%"PFMT64d",%"PFMT64d, addr, addr), 0);
	}
#else
	RzFlagZoneItem *zi = rz_flag_zone_get (f, name);
	if (zi) {
		if (addr < zi->from) {
			zi->from = addr;
		}
		if (addr > zi->to) {
			zi->to = addr;
		}
	} else {
		if (!DB) {
			rz_flag_zone_reset (f);
		}
		zi = RZ_NEW0 (RzFlagZoneItem);
		zi->name = strdup (name);
		zi->from = zi->to = addr;
		rz_list_append (DB, zi);
	}
#endif
	return true;
}

RZ_API bool rz_flag_zone_reset(RzFlag *f) {
#if RZ_FLAG_ZONE_USE_SDB
	return sdb_reset (DB);
#else
	rz_list_free (f->zones);
	f->zones = rz_list_newf (rz_flag_zone_item_free);
	return true;
#endif
}

RZ_API bool rz_flag_zone_del(RzFlag *f, const char *name) {
#if RZ_FLAG_ZONE_USE_SDB
	return sdb_unset (DB, name, 0);
#else
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (DB, iter, zi) {
		if (!strcmp (name, zi->name)) {
			rz_list_delete (DB, iter);
			return true;
		}
	}
	return false;
#endif
}

#if RZ_FLAG_ZONE_USE_SDB

typedef struct rz_flag_zone_context_t {
	RzFlag *f;
	ut64 addr;
	ut64 l, h; // lower, higher closest offsets
	const char **prev;
	const char **next;
} RzFlagZoneContext;

static bool cb(void *user, const char *name, const char *from_to) {
	RzFlagZoneContext *zc = (RzFlagZoneContext*)user;
	RzFlagZoneItem zi = { 0, 0, name };
	sdb_fmt_tobin (from_to, "qq", &zi);
	if (zi.from > zc->addr) {
		if (zc->h == UT64_MAX) {
			zc->h = zi.from;
			*zc->next = name;
		} else {
			if (zi.from < zc->h) {
				zc->h = zi.from;
				*zc->next = name;
			}
		}
	}
	if (zi.from < zc->addr) {
		if (zc->l == UT64_MAX) {
			zc->l = zi.from;
			*zc->prev = name;
		} else {
			if (zi.from >= zc->l) {
				zc->l = zi.from;
				*zc->prev = name;
			}
		}
	}
	if (zi.to <= zc->addr) {
		if (zc->l == UT64_MAX) {
			zc->l = zi.to;
			*zc->prev = name;
		} else {
			if (zi.to >= zc->l) {
				zc->l = zi.to;
				*zc->prev = name;
			}
		}
	}
	if (zi.to > zc->addr) {
		if (zc->h == UT64_MAX) {
			zc->h = zi.to;
			*zc->next = name;
		} else {
			if (zi.to < zc->h) {
				zc->h = zi.to;
				*zc->next = name;
			}
		}
	}
	return true;
}

RZ_API bool rz_flag_zone_around(RzFlag *f, ut64 addr, const char **prev, const char **next) {
	RzFlagZoneContext ctx = { f, addr, 0, UT64_MAX, prev, next };
	*prev = *next = NULL;
	sdb_foreach (DB, cb, &ctx);
	return true;
}

static bool cb_list(void *user, const char *name, const char *from_to) {
	eprintf ("%s%s  %s\n", name, rz_str_pad (' ', 10 - strlen (name)), from_to);
	return true;
}

RZ_API bool rz_flag_zone_list(RzFlag *f, int mode) {
	sdb_foreach (DB, cb_list, NULL);
	return true;
}

#else

RZ_API void rz_flag_zone_item_free(void *a) {
	RzFlagZoneItem *zi = a;
	free (zi->name);
	free (zi);
}

RZ_API bool rz_flag_zone_around(RzFlag *f, ut64 addr, const char **prev, const char **next) {
	RzListIter *iter;
	RzFlagZoneItem *zi;
	*prev = *next = NULL;
	ut64 h = UT64_MAX, l = 0LL;

	rz_list_foreach (DB, iter, zi) {
		if (zi->from > addr) {
			if (h == UT64_MAX) {
				h = zi->from;
				*next = zi->name;
			} else {
				if (zi->from < h) {
					h = zi->from;
					*next = zi->name;
				}
			}
		}
		if (zi->from < addr) {
			if (l == UT64_MAX) {
				l = zi->from;
				*prev = zi->name;
			} else {
				if (zi->from >= l) {
					l = zi->from;
					*prev = zi->name;
				}
			}
		}
		if (zi->to <= addr) {
			if (l == UT64_MAX) {
				l = zi->to;
				*prev = zi->name;
			} else {
				if (zi->to >= l) {
					l = zi->to;
					*prev = zi->name;
				}
			}
		}
		if (zi->to > addr) {
			if (h == UT64_MAX) {
				h = zi->to;
				*next = zi->name;
			} else {
				if (zi->to < h) {
					h = zi->to;
					*next = zi->name;
				}
			}
		}
	}
	return true;
}

RZ_API RzList *rz_flag_zone_barlist(RzFlag *f, ut64 from, ut64 bsize, int rows) {
	RzList *list = rz_list_newf (NULL);
	int i;
	for (i = 0; i < rows; i++) {
		RzFlagZoneItem *zi = rz_flag_zone_get_inrange (f, from, from + bsize);
		if (zi) {
			rz_list_append (list, zi->name);
		} else {
			rz_list_append (list, "");
		}
		from += bsize;
	}
	return list;
}

RZ_API bool rz_flag_zone_list(RzFlag *f, int mode) {
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (DB, iter, zi) {
		if (mode == '*') {
			f->cb_printf ("fz %s @ 0x08%"PFMT64x"\n", zi->name, zi->from);
			f->cb_printf ("f %s %d 0x08%"PFMT64x"\n", zi->name,
				zi->to - zi->from, zi->from);
		} else {
			f->cb_printf ("0x08%"PFMT64x"  0x%08"PFMT64x"  %s\n",
					zi->from, zi->to, zi->name);
		}
	}
	return true;
}
#endif

// #define __MAIN__ 1
#if __MAIN__
#define FZ(x) rz_flag_zone_##x

int main() {
	const char *a, *b;
	RzFlagZone *fz = rz_flag_zone_new ();

	FZ(add)(fz, "main", 0x80000);
	FZ(add)(fz, "network", 0x85000);
	FZ(add)(fz, "libc", 0x90000);

	FZ(add)(fz, "network", 0x000);

	FZ(around)(fz, 0x83000, &a, &b);
	printf ("%s %s\n", a, b);

	FZ(around)(fz, 0x50000, &a, &b);
	printf ("%s %s\n", a, b);

	FZ(around)(fz, 0x500000, &a, &b);
	printf ("%s %s\n", a, b);

	FZ(list)(fz);

	rz_flag_zone_free (fz);
	return 0;
}
#endif
