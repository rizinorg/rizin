// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_util/rz_assert.h>

#define LOAD_FACTOR     1
#define S_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

// Sizes of the ht.
static const ut32 ht_primes_sizes[] = {
	3, 7, 11, 17, 23, 29, 37, 47, 59, 71, 89, 107, 131,
	163, 197, 239, 293, 353, 431, 521, 631, 761, 919,
	1103, 1327, 1597, 1931, 2333, 2801, 3371, 4049, 4861,
	5839, 7013, 8419, 10103, 12143, 14591, 17519, 21023,
	25229, 30293, 36353, 43627, 52361, 62851, 75431, 90523,
	108631, 130363, 156437, 187751, 225307, 270371, 324449,
	389357, 467237, 560689, 672827, 807403, 968897, 1162687,
	1395263, 1674319, 2009191, 2411033, 2893249, 3471899,
	4166287, 4999559, 5999471, 7199369
};

static inline ut32 hashfn(HtName_(Ht) * ht, const KEY_TYPE k) {
	return ht->opt.hashfn ? ht->opt.hashfn(k) : KEY_TO_HASH(k);
}

static inline ut32 bucketfn(HtName_(Ht) * ht, const KEY_TYPE k) {
	return hashfn(ht, k) % ht->size;
}

static inline KEY_TYPE dupkey(HtName_(Ht) * ht, const KEY_TYPE k) {
	return ht->opt.dupkey ? ht->opt.dupkey(k) : (KEY_TYPE)k;
}

static inline VALUE_TYPE dupval(HtName_(Ht) * ht, const VALUE_TYPE v) {
	return ht->opt.dupvalue ? ht->opt.dupvalue(v) : (VALUE_TYPE)v;
}

static inline ut32 calcsize_key(HtName_(Ht) * ht, const KEY_TYPE k) {
	return ht->opt.calcsizeK ? ht->opt.calcsizeK(k) : 0;
}

static inline ut32 calcsize_val(HtName_(Ht) * ht, const VALUE_TYPE v) {
	return ht->opt.calcsizeV ? ht->opt.calcsizeV(v) : 0;
}

static inline void fini_kv_pair(HtName_(Ht) * ht, HT_(Kv) * kv) {
	if (ht->opt.finiKV) {
		ht->opt.finiKV(kv, ht->opt.finiKV_user);
	}
}

static inline ut32 next_idx(ut32 idx) {
	if (idx != UT32_MAX && idx < S_ARRAY_SIZE(ht_primes_sizes) - 1) {
		return idx + 1;
	}
	return UT32_MAX;
}

static inline ut32 compute_size(ut32 idx, ut32 sz) {
	// when possible, use the precomputed prime numbers which help with
	// collisions, otherwise, at least make the number odd with |1
	return idx != UT32_MAX && idx < S_ARRAY_SIZE(ht_primes_sizes) ? ht_primes_sizes[idx] : (sz | 1);
}

static inline bool is_kv_equal(HtName_(Ht) * ht, const KEY_TYPE key, const ut32 key_len, const HT_(Kv) * kv) {
	if (key_len != kv->key_len) {
		return false;
	}

	bool res = key == kv->key;
	if (!res && ht->opt.cmp) {
		res = !ht->opt.cmp(key, kv->key);
	}
	return res;
}

static inline HT_(Kv) * kv_at(HtName_(Ht) * ht, HT_(Bucket) * bt, ut32 i) {
	return (HT_(Kv) *)((char *)bt->arr + i * ht->opt.elem_size);
}

static inline HT_(Kv) * next_kv(HtName_(Ht) * ht, HT_(Kv) * kv) {
	return (HT_(Kv) *)((char *)kv + ht->opt.elem_size);
}

#define BUCKET_FOREACH(ht, bt, j, kv) \
	if ((bt)->arr) \
		for ((j) = 0, (kv) = (bt)->arr; (j) < (bt)->count; (j)++, (kv) = next_kv(ht, kv))

#define BUCKET_FOREACH_SAFE(ht, bt, j, count, kv) \
	if ((bt)->arr) \
		for ((j) = 0, (kv) = (bt)->arr, (count) = (ht)->count; \
			(j) < (bt)->count; \
			(j) = (count) == (ht)->count ? j + 1 : j, (kv) = (count) == (ht)->count ? next_kv(ht, kv) : kv, (count) = (ht)->count)

// Create a new hashtable and return a pointer to it.
// size - number of buckets in the hashtable
static RZ_OWN HtName_(Ht) * internal_ht_new(ut32 size, ut32 prime_idx, HT_(Options) * opt) {
	HtName_(Ht) *ht = RZ_NEW0(HtName_(Ht));
	if (!ht) {
		return NULL;
	}
	ht->size = size;
	ht->count = 0;
	ht->prime_idx = prime_idx;
	ht->table = calloc(ht->size, sizeof(*ht->table));
	if (!ht->table) {
		free(ht);
		return NULL;
	}
	ht->opt = *opt;
	// if not provided, assume we are dealing with a regular HtName_(Ht), with
	// HT_(Kv) as elements
	if (ht->opt.elem_size == 0) {
		ht->opt.elem_size = sizeof(HT_(Kv));
	}
	return ht;
}

/**
 * \brief Create a new hashtable with options \p opt
 *
 * Options are copied to an inner field.
 */
RZ_API RZ_OWN HtName_(Ht) * Ht_(new_opt)(RZ_NONNULL HT_(Options) * opt) {
	rz_return_val_if_fail(opt, NULL);
	return internal_ht_new(ht_primes_sizes[0], 0, opt);
}

/**
 * \brief Create a new hashtable with options \p opt and
 *        preallocated buckets for \p initial_size entries.
 *
 * Options are copied to an inner field.
 */
RZ_API RZ_OWN HtName_(Ht) * Ht_(new_opt_size)(RZ_NONNULL HT_(Options) * opt, ut32 initial_size) {
	rz_return_val_if_fail(opt, NULL);
	ut32 idx = 0;
	while (idx < S_ARRAY_SIZE(ht_primes_sizes) &&
		ht_primes_sizes[idx] * LOAD_FACTOR < initial_size) {
		idx++;
	}
	if (idx == S_ARRAY_SIZE(ht_primes_sizes)) {
		idx = UT32_MAX;
	}
	ut32 sz = compute_size(idx, (ut32)(initial_size * (2 - LOAD_FACTOR)));
	return internal_ht_new(sz, idx, opt);
}

RZ_API void Ht_(free)(RZ_NULLABLE HtName_(Ht) * ht) {
	if (!ht) {
		return;
	}

	ut32 i;
	for (i = 0; i < ht->size; i++) {
		HT_(Bucket) *bt = &ht->table[i];
		HT_(Kv) * kv;
		ut32 j;

		if (ht->opt.finiKV) {
			BUCKET_FOREACH(ht, bt, j, kv) {
				ht->opt.finiKV(kv, ht->opt.finiKV_user);
			}
		}

		free(bt->arr);
	}
	free(ht->table);
	free(ht);
}

// Increases the size of the hashtable by 2.
static void internal_ht_grow(HtName_(Ht) * ht) {
	HtName_(Ht) * ht2;
	HtName_(Ht) swap;
	ut32 idx = next_idx(ht->prime_idx);
	ut32 sz = compute_size(idx, ht->size * 2);
	ut32 i;

	ht2 = internal_ht_new(sz, idx, &ht->opt);
	if (!ht2) {
		// we can't grow the ht anymore. Never mind, we'll be slower,
		// but everything can continue to work
		return;
	}

	for (i = 0; i < ht->size; i++) {
		HT_(Bucket) *bt = &ht->table[i];
		HT_(Kv) * kv;
		ut32 j;

		BUCKET_FOREACH(ht, bt, j, kv) {
			Ht_(insert_kv)(ht2, kv, false);
		}
	}
	// And now swap the internals.
	swap = *ht;
	*ht = *ht2;
	*ht2 = swap;

	ht2->opt.finiKV = NULL;
	Ht_(free)(ht2);
}

static void check_growing(HtName_(Ht) * ht) {
	if (ht->count >= LOAD_FACTOR * ht->size) {
		internal_ht_grow(ht);
	}
}

static HT_(Kv) * reserve_kv(HtName_(Ht) * ht, const KEY_TYPE key, const int key_len, bool update) {
	HT_(Bucket) *bt = &ht->table[bucketfn(ht, key)];
	HT_(Kv) * kvtmp;
	ut32 j;

	BUCKET_FOREACH(ht, bt, j, kvtmp) {
		if (is_kv_equal(ht, key, key_len, kvtmp)) {
			if (update) {
				fini_kv_pair(ht, kvtmp);
				return kvtmp;
			}
			return NULL;
		}
	}

	HT_(Kv) *newkvarr = realloc(bt->arr, (bt->count + 1) * ht->opt.elem_size);
	if (!newkvarr) {
		return NULL;
	}

	bt->arr = newkvarr;
	bt->count++;
	ht->count++;
	return kv_at(ht, bt, bt->count - 1);
}

RZ_API bool Ht_(insert_kv)(RZ_NONNULL HtName_(Ht) * ht, RZ_NONNULL HT_(Kv) * kv, bool update) {
	rz_return_val_if_fail(ht && kv, false);
	HT_(Kv) *kv_dst = reserve_kv(ht, kv->key, kv->key_len, update);
	if (!kv_dst) {
		return false;
	}

	memcpy(kv_dst, kv, ht->opt.elem_size);
	check_growing(ht);
	return true;
}

static bool insert_update(HtName_(Ht) * ht, const KEY_TYPE key, VALUE_TYPE value, bool update) {
	ut32 key_len = calcsize_key(ht, key);
	HT_(Kv) *kv_dst = reserve_kv(ht, key, key_len, update);
	if (!kv_dst) {
		return false;
	}

	kv_dst->key = dupkey(ht, key);
	kv_dst->key_len = key_len;
	kv_dst->value = dupval(ht, value);
	kv_dst->value_len = calcsize_val(ht, value);
	check_growing(ht);
	return true;
}

/**
 * Inserts the key value pair \p key, \p value into the hashtable \p ht.
 * Doesn't allow for "update" of the value.
 */
RZ_API bool Ht_(insert)(RZ_NONNULL HtName_(Ht) * ht, const KEY_TYPE key, VALUE_TYPE value) {
	rz_return_val_if_fail(ht, false);
	return insert_update(ht, key, value, false);
}

/**
 * Inserts the key value pair \p key, \p value into the hashtable \p ht.
 * Does allow for "update" of the value.
 */
RZ_API bool Ht_(update)(RZ_NONNULL HtName_(Ht) * ht, const KEY_TYPE key, VALUE_TYPE value) {
	rz_return_val_if_fail(ht, false);
	return insert_update(ht, key, value, true);
}

// Update the key of an element that has old_key as key and replace it with new_key
RZ_API bool Ht_(update_key)(RZ_NONNULL HtName_(Ht) * ht, const KEY_TYPE old_key, const KEY_TYPE new_key) {
	rz_return_val_if_fail(ht, false);
	// First look for the value associated with old_key
	bool found;
	VALUE_TYPE value = Ht_(find)(ht, old_key, &found);
	if (!found) {
		return false;
	}

	// Associate the existing value with new_key
	bool inserted = insert_update(ht, new_key, value, false);
	if (!inserted) {
		return false;
	}

	// Remove the old_key kv, paying attention to not double free the value
	HT_(Bucket) *bt = &ht->table[bucketfn(ht, old_key)];
	const int old_key_len = calcsize_key(ht, old_key);
	HT_(Kv) * kv;
	ut32 j;

	BUCKET_FOREACH(ht, bt, j, kv) {
		if (is_kv_equal(ht, old_key, old_key_len, kv)) {
			if (!ht->opt.dupvalue) {
				// do not free the value part if dupvalue is not
				// set, because the old value has been
				// associated with the new key and it should not
				// be freed
				kv->value = HT_NULL_VALUE;
				kv->value_len = 0;
			}
			fini_kv_pair(ht, kv);

			void *src = next_kv(ht, kv);
			memmove(kv, src, (bt->count - j - 1) * ht->opt.elem_size);
			bt->count--;
			ht->count--;
			return true;
		}
	}

	return false;
}

/**
 * Returns the corresponding Kv entry from \p key.
 * If \p found is not NULL, it will be set to true if the entry was found,
 * false otherwise.
 */
RZ_API RZ_BORROW HT_(Kv) * Ht_(find_kv)(RZ_NONNULL HtName_(Ht) * ht, const KEY_TYPE key, bool *found) {
	if (found) {
		*found = false;
	}
	rz_return_val_if_fail(ht, NULL);

	HT_(Bucket) *bt = &ht->table[bucketfn(ht, key)];
	ut32 key_len = calcsize_key(ht, key);
	HT_(Kv) * kv;
	ut32 j;

	BUCKET_FOREACH(ht, bt, j, kv) {
		if (is_kv_equal(ht, key, key_len, kv)) {
			if (found) {
				*found = true;
			}
			return kv;
		}
	}
	return NULL;
}

/**
 * Looks up the corresponding value from \p key.
 * If \p found is not NULL, it will be set to true if the entry was found,
 * false otherwise.
 */
RZ_API RZ_BORROW VALUE_TYPE Ht_(find)(RZ_NONNULL HtName_(Ht) * ht, const KEY_TYPE key, bool *found) {
	HT_(Kv) *res = Ht_(find_kv)(ht, key, found);
	return res ? res->value : HT_NULL_VALUE;
}

// Deletes a entry from the hash table from the key, if the pair exists.
RZ_API bool Ht_(delete)(RZ_NONNULL HtName_(Ht) * ht, const KEY_TYPE key) {
	rz_return_val_if_fail(ht, false);
	HT_(Bucket) *bt = &ht->table[bucketfn(ht, key)];
	ut32 key_len = calcsize_key(ht, key);
	HT_(Kv) * kv;
	ut32 j;

	BUCKET_FOREACH(ht, bt, j, kv) {
		if (is_kv_equal(ht, key, key_len, kv)) {
			fini_kv_pair(ht, kv);
			void *src = next_kv(ht, kv);
			memmove(kv, src, (bt->count - j - 1) * ht->opt.elem_size);
			bt->count--;
			ht->count--;
			return true;
		}
	}
	return false;
}

/**
 * \brief Apply \p cb for each KV pair in \p ht
 */
RZ_API void Ht_(foreach)(RZ_NONNULL HtName_(Ht) * ht, RZ_NONNULL HT_(ForeachCallback) cb, void *user) {
	rz_return_if_fail(ht && cb);
	ut32 i;

	for (i = 0; i < ht->size; ++i) {
		HT_(Bucket) *bt = &ht->table[i];
		HT_(Kv) * kv;
		ut32 j, count;

		BUCKET_FOREACH_SAFE(ht, bt, j, count, kv) {
			if (!cb(user, kv->key, kv->value)) {
				return;
			}
		}
	}
}
