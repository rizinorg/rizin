// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

#include "type_internal.h"

// XXX 12 is the maxstructsizedelta
#define TYPE_RANGE_BASE(x) ((x) >> 16)

static RzList *types_range_list(Sdb *db, ut64 addr) {
	RzList *list = NULL;
	ut64 base = TYPE_RANGE_BASE(addr);
	char *s = rz_str_newf("range.%" PFMT64x, base);
	if (s) {
		char *r = sdb_get(db, s, 0);
		if (r) {
			list = rz_str_split_list(r, " ", -1);
		}
		free(s);
	}
	return list;
}

static void types_range_del(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE(addr);
	const char *k = sdb_fmt("range.%" PFMT64x, base);
	char valstr[SDB_NUM_BUFSZ];
	const char *v = sdb_itoa(addr, valstr, SDB_NUM_BASE);
	sdb_array_remove(db, k, v, 0);
}

static void types_range_add(Sdb *db, ut64 addr) {
	ut64 base = TYPE_RANGE_BASE(addr);
	const char *k = sdb_fmt("range.%" PFMT64x, base);
	(void)sdb_array_add_num(db, k, addr, 0);
}

RZ_API char *rz_type_link_at(RzTypeDB *typedb, ut64 addr) {
	rz_return_val_if_fail(typedb, NULL);
	Sdb *TDB = typedb->sdb_types;
	if (addr == UT64_MAX) {
		return NULL;
	}
	const char *query = sdb_fmt("link.%08" PFMT64x, addr);
	char *res = sdb_get(TDB, query, 0);
	if (!res) { // resolve struct memb if possible for given addr
		RzList *list = types_range_list(TDB, addr);
		RzListIter *iter;
		const char *s;
		rz_list_foreach (list, iter, s) {
			ut64 laddr = rz_num_get(NULL, s);
			if (addr > laddr) {
				int delta = addr - laddr;
				const char *lk = sdb_fmt("link.%08" PFMT64x, laddr);
				char *k = sdb_get(TDB, lk, 0);
				res = rz_type_get_struct_memb(typedb, k, delta);
				if (res) {
					break;
				}
				free(k);
			}
		}
	}
	return res;
}

RZ_API bool rz_type_set_link(RzTypeDB *typedb, const char *type, ut64 addr) {
	rz_return_val_if_fail(typedb, false);
	Sdb *TDB = typedb->sdb_types;
	if (sdb_const_get(TDB, type, 0)) {
		char *laddr = rz_str_newf("link.%08" PFMT64x, addr);
		sdb_set(TDB, laddr, type, 0);
		types_range_add(TDB, addr);
		free(laddr);
		return true;
	}
	return false;
}

RZ_API bool rz_type_link_offset(RzTypeDB *typedb, const char *type, ut64 addr) {
	rz_return_val_if_fail(typedb, false);
	Sdb *TDB = typedb->sdb_types;
	if (sdb_const_get(TDB, type, 0)) {
		char *laddr = rz_str_newf("offset.%08" PFMT64x, addr);
		sdb_set(TDB, laddr, type, 0);
		free(laddr);
		return true;
	}
	return false;
}

RZ_API bool rz_type_unlink(RzTypeDB *typedb, ut64 addr) {
	rz_return_val_if_fail(typedb, false);
	Sdb *TDB = typedb->sdb_types;
	char *laddr = sdb_fmt("link.%08" PFMT64x, addr);
	sdb_unset(TDB, laddr, 0);
	types_range_del(TDB, addr);
	return true;
}

static bool sdbdeletelink(void *p, const char *k, const char *v) {
	//Sdb *TDB = (Sdb *)p;
	if (!strncmp(k, "link.", strlen("link."))) {
		//rz_type_del(TDB, k);
		//FIXME
	}
	return true;
}

RZ_API bool rz_type_unlink_all(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, false);
	Sdb *TDB = typedb->sdb_types;
	sdb_foreach(TDB, sdbdeletelink, TDB);
	return true;
}
