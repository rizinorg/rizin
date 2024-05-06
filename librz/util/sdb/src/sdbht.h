// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef __SDB_HT_H
#define __SDB_HT_H

#include <rz_util/ht_ss.h>

#ifdef __cplusplus
extern "C" {
#endif

/** keyvalue pair **/
typedef struct sdb_kv {
	// sub of HtSSKv so we can cast safely
	HtSSKv base;
	ut32 cas;
	ut64 expire;
} SdbKv;

static inline const char *sdbkv_key(const SdbKv *kv) {
	return kv->base.key;
}

static inline const char *sdbkv_value(const SdbKv *kv) {
	return kv->base.value;
}

static inline ut32 sdbkv_key_len(const SdbKv *kv) {
	return kv->base.key_len;
}

static inline ut32 sdbkv_value_len(const SdbKv *kv) {
	return kv->base.value_len;
}

RZ_API SdbKv *sdbkv_new2(const char *k, int kl, const char *v, int vl);
RZ_API SdbKv *sdbkv_new(const char *k, const char *v);
extern RZ_API void sdbkv_free(RZ_NULLABLE SdbKv *kv);

extern RZ_API ut32 sdb_hash(const char *key);

RZ_API HtSS *sdb_ht_new(void);
// Destroy a hashtable and all of its entries.
RZ_API void sdb_ht_free(HtSS *ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
RZ_API bool sdb_ht_insert(HtSS *ht, const char *key, const char *value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
RZ_API bool sdb_ht_insert_kvp(HtSS *ht, SdbKv *kvp, bool update);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
RZ_API bool sdb_ht_update(HtSS *ht, const char *key, const char *value);
// Delete a key from the hashtable.
RZ_API bool sdb_ht_delete(HtSS *ht, const char *key);
// Find the value corresponding to the matching key.
RZ_API char *sdb_ht_find(HtSS *ht, const char *key, bool *found);
// Find the KeyValuePair corresponding to the matching key.
RZ_API SdbKv *sdb_ht_find_kvp(HtSS *ht, const char *key, bool *found);

#ifdef __cplusplus
}
#endif

#endif // __SDB_HT_H
