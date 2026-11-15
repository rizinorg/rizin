// SPDX-FileCopyrightText: 2016-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>
#include <rz_util.h>

/**
 * \brief Find a named zone without transferring ownership.
 * \return A zone borrowed from \p f, or NULL if no zone matches.
 */
static RZ_BORROW RzFlagZoneItem *rz_flag_zone_get(RZ_BORROW RZ_NONNULL RzFlag *f, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(f && name, NULL);
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (f->zones, iter, zi) {
		if (!strcmp(name, zi->name)) {
			return zi;
		}
	}
	return NULL;
}

/**
 * \brief Find a zone starting in the range without transferring ownership.
 * \return A zone borrowed from \p f, or NULL if no zone matches.
 */
static RZ_BORROW RzFlagZoneItem *rz_flag_zone_get_inrange(RZ_BORROW RZ_NONNULL RzFlag *f, ut64 from, ut64 to) {
	rz_return_val_if_fail(f, NULL);
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (f->zones, iter, zi) {
		if (RZ_BETWEEN(from, zi->from, to)) {
			return zi;
		}
	}
	return NULL;
}

RZ_API bool rz_flag_zone_add(RZ_NONNULL RzFlag *f, RZ_NONNULL const char *name, ut64 addr) {
	rz_return_val_if_fail(f && name && *name, false);
	RzFlagZoneItem *zi = rz_flag_zone_get(f, name);
	if (zi) {
		if (addr < zi->from) {
			zi->from = addr;
		}
		if (addr > zi->to) {
			zi->to = addr;
		}
	} else {
		if (!f->zones) {
			rz_flag_zone_reset(f);
		}
		zi = RZ_NEW0(RzFlagZoneItem);
		zi->name = rz_str_dup(name);
		zi->from = zi->to = addr;
		rz_list_append(f->zones, zi);
	}
	return true;
}

RZ_API bool rz_flag_zone_reset(RzFlag *f) {
	rz_list_free(f->zones);
	f->zones = rz_list_newf(rz_flag_zone_item_free);
	return true;
}

RZ_API bool rz_flag_zone_del(RzFlag *f, const char *name) {
	RzListIter *iter;
	RzFlagZoneItem *zi;
	rz_list_foreach (f->zones, iter, zi) {
		if (!strcmp(name, zi->name)) {
			rz_list_delete(f->zones, iter);
			return true;
		}
	}
	return false;
}

RZ_API void rz_flag_zone_item_free(void *a) {
	RzFlagZoneItem *zi = a;
	free(zi->name);
	free(zi);
}

RZ_API bool rz_flag_zone_around(RzFlag *f, ut64 addr, const char **prev, const char **next) {
	RzListIter *iter;
	RzFlagZoneItem *zi;
	*prev = *next = NULL;
	ut64 h = UT64_MAX, l = 0LL;

	rz_list_foreach (f->zones, iter, zi) {
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

/**
 * \brief Collect zone labels for a bar display.
 * \return A list to free with rz_list_free(), or NULL on allocation failure.
 * Entries borrow zone names from \p f or refer to the static empty string.
 * Do not free or modify the strings. Removing zones can invalidate their names.
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_flag_zone_barlist(RZ_BORROW RZ_NONNULL RzFlag *f, ut64 from, ut64 bsize, int rows) {
	rz_return_val_if_fail(f, NULL);
	RzList *list = rz_list_newf(NULL);
	int i;
	for (i = 0; i < rows; i++) {
		RzFlagZoneItem *zi = rz_flag_zone_get_inrange(f, from, from + bsize);
		if (zi) {
			rz_list_append(list, zi->name);
		} else {
			rz_list_append(list, "");
		}
		from += bsize;
	}
	return list;
}
