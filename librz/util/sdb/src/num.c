// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "sdb.h"
#include <rz_types.h>

// check if key exists and if it's a number.. rename?
RZ_API bool sdb_num_exists(Sdb *s, const char *key) {
	const char *o = sdb_const_get(s, key);
	return o ? (*o >= '0' && *o <= '9') : false;
}

RZ_API ut64 sdb_num_get(Sdb *s, const char *key) {
	const char *v = sdb_const_get(s, key);
	return (!v || *v == '-') ? 0LL : sdb_atoi(v);
}

RZ_API bool sdb_num_add(Sdb *s, const char *key, ut64 v) {
	char *val, b[SDB_NUM_BUFSZ];
	int numbase = sdb_num_base(sdb_const_get(s, key));
	val = sdb_itoa(v, b, numbase);
	return sdb_add(s, key, val);
}

RZ_API bool sdb_num_set(Sdb *s, const char *key, ut64 v) {
	char *val, b[SDB_NUM_BUFSZ];
	int numbase = sdb_num_base(sdb_const_get(s, key));
	val = sdb_itoa(v, b, numbase);
	return sdb_set(s, key, val);
}

RZ_API ut64 sdb_num_inc(Sdb *s, const char *key, ut64 n2) {
	ut64 n = sdb_num_get(s, key);
	ut64 res = n + n2;
	if (res < n) {
		return 0LL;
	}
	sdb_num_set(s, key, res);
	return res;
}

RZ_API ut64 sdb_num_dec(Sdb *s, const char *key, ut64 n2) {
	ut64 n = sdb_num_get(s, key);
	if (n2 > n) {
		sdb_set(s, key, "0");
		return 0LL; // XXX must be -1LL?
	}
	n -= n2;
	sdb_num_set(s, key, n);
	return n;
}

RZ_API int sdb_num_min(Sdb *db, const char *k, ut64 n) {
	const char *a = sdb_const_get(db, k);
	return (!a || n < sdb_atoi(a))
		? sdb_num_set(db, k, n)
		: 0;
}

RZ_API int sdb_num_max(Sdb *db, const char *k, ut64 n) {
	const char *a = sdb_const_get(db, k);
	return (!a || n > sdb_atoi(a))
		? sdb_num_set(db, k, n)
		: 0;
}

RZ_API bool sdb_bool_set(Sdb *db, const char *str, bool v) {
	return sdb_set(db, str, v ? "true" : "false");
}

RZ_API bool sdb_bool_get(Sdb *db, const char *str) {
	const char *b = sdb_const_get(db, str);
	return b && (!strcmp(b, "1") || !strcmp(b, "true"));
}

/* pointers */

RZ_API int sdb_ptr_set(Sdb *db, const char *key, void *p) {
	return sdb_num_set(db, key, (ut64)(size_t)p);
}

RZ_API void *sdb_ptr_get(Sdb *db, const char *key) {
	return (void *)(size_t)sdb_num_get(db, key);
}
