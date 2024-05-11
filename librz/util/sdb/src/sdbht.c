// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "sdbht.h"

RZ_API HtSS *sdb_ht_new(void) {
	HtSS *ht = ht_ss_new(HT_STR_DUP, HT_STR_DUP);
	if (ht) {
		ht->opt.elem_size = sizeof(SdbKv);
	}
	return ht;
}

static bool sdb_ht_internal_insert(HtSS *ht, const char *key, const char *value, bool update) {
	if (!ht || !key || !value) {
		return false;
	}
	SdbKv kvp = { { 0 } };
	kvp.base.key = strdup((void *)key);
	if (!kvp.base.key) {
		goto err;
	}
	kvp.base.value = strdup((void *)value);
	if (!kvp.base.value) {
		goto err;
	}
	kvp.base.key_len = strlen(kvp.base.key);
	kvp.base.value_len = strlen(kvp.base.value);
	return ht_ss_insert_kv(ht, (HtSSKv *)&kvp, update, NULL);

err:
	free(kvp.base.key);
	free(kvp.base.value);
	return false;
}

RZ_API bool sdb_ht_insert(HtSS *ht, const char *key, const char *value) {
	return sdb_ht_internal_insert(ht, key, value, false);
}

RZ_API bool sdb_ht_insert_kvp(HtSS *ht, SdbKv *kvp, bool update) {
	return ht_ss_insert_kv(ht, (HtSSKv *)kvp, update, NULL);
}

RZ_API bool sdb_ht_update(HtSS *ht, const char *key, const char *value) {
	return sdb_ht_internal_insert(ht, key, value, true);
}

RZ_API SdbKv *sdb_ht_find_kvp(HtSS *ht, const char *key, bool *found) {
	return (SdbKv *)ht_ss_find_kv(ht, key, found);
}

RZ_API char *sdb_ht_find(HtSS *ht, const char *key, bool *found) {
	return (char *)ht_ss_find(ht, key, found);
}

RZ_API void sdb_ht_free(HtSS *ht) {
	ht_ss_free(ht);
}

RZ_API bool sdb_ht_delete(HtSS *ht, const char *key) {
	return ht_ss_delete(ht, key);
}
