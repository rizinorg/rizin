// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include "sdbht.h"

/**
 * \brief A helper struct used for forwarding iteration (foreach) callbacks between `ht_` and the `sdb_` APIs.
 */
typedef struct {
	SdbHtForeachCallback cb;
	void *user;
} HtSSForeachKvCallbackRedirect;

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
	return ht_ss_insert_kv(ht, (HtSSKv *)&kvp, update);

err:
	free(kvp.base.key);
	free(kvp.base.value);
	return false;
}

RZ_API bool sdb_ht_insert(HtSS *ht, const char *key, const char *value) {
	return sdb_ht_internal_insert(ht, key, value, false);
}

RZ_API bool sdb_ht_insert_kvp(HtSS *ht, SdbKv *kvp, bool update) {
	return ht_ss_insert_kv(ht, (HtSSKv *)kvp, update);
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

static bool sdb_ht_foreach_kv_filter(void *user, const HtSSKv *kv) {
	SdbKv *sdb_kv = (SdbKv *)kv;
	if (sdbkv_key(sdb_kv) && sdbkv_value(sdb_kv) && *sdbkv_value(sdb_kv)) {
		HtSSForeachKvCallbackRedirect *redirect = user;
		return redirect->cb(redirect->user, (SdbKv *)kv);
	}
	return true;
}

/**
 * \brief Iterates all elements of a `HtSS` hash table.
 *
 * \param ht The hash table.
 * \param cb A callback to be invoked for each element.
 * \param user Pointer to user data to be passed to the callback for each element.
 * \return true if all elements were iterated, false if the iteration was cancelled by the user callback
 */
RZ_API bool sdb_ht_foreach_kv(RZ_NONNULL HtSS *ht, RZ_NONNULL SdbHtForeachCallback cb, RZ_NULLABLE void *user) {
	HtSSForeachKvCallbackRedirect redirect = {
		.cb = cb,
		.user = user
	};
	return ht_ss_foreach_kv(ht, sdb_ht_foreach_kv_filter, &redirect);
}