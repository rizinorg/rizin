// SPDX-FileCopyrightText: 2019 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_str_constpool.h"

RZ_API bool rz_str_constpool_init(RzStrConstPool *pool) {
	pool->ht = ht_sp_new(HT_STR_DUP, NULL, NULL);
	return pool->ht != NULL;
}

RZ_API void rz_str_constpool_fini(RzStrConstPool *pool) {
	ht_sp_free(pool->ht);
}

RZ_API const char *rz_str_constpool_get(RzStrConstPool *pool, const char *str) {
	if (!str) {
		return NULL;
	}
	HtSPKv *kv = ht_sp_find_kv(pool->ht, str, NULL);
	if (kv) {
		return kv->key;
	}
	ht_sp_insert(pool->ht, str, NULL);
	kv = ht_sp_find_kv(pool->ht, str, NULL);
	if (kv) {
		return kv->key;
	}
	return NULL;
}
