// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_util/rz_assert.h>
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_str.h>

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

static inline ut32 hashfn(HtName_(Ht) *ht, const KEY_TYPE k) {
	return ht->opt.hashfn ? ht->opt.hashfn(k) : KEY_TO_HASH(k);
}

static inline ut32 bucketfn(HtName_(Ht) *ht, const KEY_TYPE k) {
	return hashfn(ht, k) % ht->size;
}

static inline KEY_TYPE dupkey(HtName_(Ht) *ht, const KEY_TYPE k) {
	return ht->opt.dupkey ? ht->opt.dupkey(k) : (KEY_TYPE)k;
}

static inline VALUE_TYPE dupval(HtName_(Ht) *ht, const VALUE_TYPE v) {
	return ht->opt.dupvalue ? ht->opt.dupvalue(v) : (VALUE_TYPE)v;
}

static inline ut32 calcsize_key(HtName_(Ht) *ht, const KEY_TYPE k) {
	return ht->opt.calcsizeK ? ht->opt.calcsizeK(k) : 0;
}

static inline ut32 calcsize_val(HtName_(Ht) *ht, const VALUE_TYPE v) {
	return ht->opt.calcsizeV ? ht->opt.calcsizeV(v) : 0;
}

static inline void fini_kv_pair(HtName_(Ht) *ht, HT_(Kv) *kv) {
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

static inline bool is_kv_equal(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, const HT_(Kv) *kv) {
	if (key_len != kv->key_len) {
		return false;
	}

	bool res = key == kv->key;
	if (!res && ht->opt.cmp) {
		res = !ht->opt.cmp(key, kv->key);
	}
	return res;
}

static inline HT_(Kv) *kv_at(HtName_(Ht) *ht, HT_(Bucket) *bt, ut32 i) {
	return (HT_(Kv) *)((char *)bt->arr + i * ht->opt.elem_size);
}

static inline HT_(Kv) *next_kv(HtName_(Ht) *ht, HT_(Kv) *kv) {
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
static RZ_OWN HtName_(Ht) *internal_ht_new(ut32 size, ut32 prime_idx, HT_(Options) *opt) {
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
 * \brief Create a new hashtable with options \p opt.
 *
 * Options are copied to an inner field.
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt)(RZ_NONNULL HT_(Options) *opt) {
	rz_return_val_if_fail(opt, NULL);
	return internal_ht_new(ht_primes_sizes[0], 0, opt);
}

/**
 * \brief Create a new hashtable with options \p opt and
 *        preallocated buckets for \p initial_size entries.
 *
 * Options are copied to an inner field.
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt_size)(RZ_NONNULL HT_(Options) *opt, ut32 initial_size) {
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

RZ_API void Ht_(free)(RZ_NULLABLE HtName_(Ht) *ht) {
	if (!ht) {
		return;
	}

	ut32 i;
	for (i = 0; i < ht->size; i++) {
		HT_(Bucket) *bt = &ht->table[i];
		HT_(Kv) *kv;
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

/**
 * Increases the size of the hashtable by 2.
 * Tracks change of KV \p tracked position.
 */
static HT_(Kv) *internal_ht_grow(HtName_(Ht) *ht, HT_(Kv) *tracked) {
	ut32 idx = next_idx(ht->prime_idx);
	ut32 sz = compute_size(idx, ht->size * 2);

	HtName_(Ht) *ht2 = internal_ht_new(sz, idx, &ht->opt);
	if (!ht2) {
		// we can't grow the ht anymore. Never mind, we'll be slower,
		// but everything can continue to work
		return tracked;
	}

	for (ut32 i = 0; i < ht->size; i++) {
		HT_(Bucket) *bt = &ht->table[i];
		HT_(Kv) *kv;
		ut32 j;

		BUCKET_FOREACH(ht, bt, j, kv) {
			if (kv == tracked) {
				continue;
			}
			if (Ht_(insert_kv_ex)(ht2, kv, false, NULL) < 0) {
				ht2->opt.finiKV = NULL;
				Ht_(free)(ht2);
				return tracked;
			}
		}
	}
	if (Ht_(insert_kv_ex)(ht2, tracked, false, &tracked) < 0) {
		ht2->opt.finiKV = NULL;
		Ht_(free)(ht2);
		return tracked;
	}

	// And now swap the internals.
	HtName_(Ht) swap = *ht;
	*ht = *ht2;
	*ht2 = swap;

	ht2->opt.finiKV = NULL;
	Ht_(free)(ht2);
	return tracked;
}

static HT_(Kv) *check_growing(HtName_(Ht) *ht, HT_(Kv) *tracked) {
	if (ht->count >= LOAD_FACTOR * ht->size) {
		return internal_ht_grow(ht, tracked);
	}
	return tracked;
}

/**
 * \brief Get an existing KV with key \p key or allocate a new KV otherwise
 */
static RZ_BORROW HT_(Kv) *reserve_kv(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, bool update, RZ_NONNULL HtRetCode *code) {
	HT_(Bucket) *bt = &ht->table[bucketfn(ht, key)];
	HT_(Kv) *kvtmp;
	ut32 j;

	BUCKET_FOREACH(ht, bt, j, kvtmp) {
		if (is_kv_equal(ht, key, key_len, kvtmp)) {
			if (update) {
				fini_kv_pair(ht, kvtmp);
				*code = HT_RC_UPDATED;
			} else {
				*code = HT_RC_EXISTING;
			}
			return kvtmp;
		}
	}

	HT_(Kv) *newkvarr = realloc(bt->arr, (bt->count + 1) * ht->opt.elem_size);
	if (!newkvarr) {
		*code = HT_RC_ERROR;
		return NULL;
	}

	bt->arr = newkvarr;
	bt->count++;
	ht->count++;
	*code = HT_RC_INSERTED;
	return kv_at(ht, bt, bt->count - 1);
}

/**
 * \brief Insert KV \p kv into hash table \p ht or replace an existing KV with \p kv,
 *        if hash table \p ht already contains a KV with the same key as \p kv
 * \param ht Hash table
 * \param kv KV; shallow copy is made when writing to the hash table
 * \param update Update flag; if set to true, replacement of existing KV is allowed
 * \return Returns true if insertion/replacement took place
 */
RZ_API bool Ht_(insert_kv)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update) {
	return Ht_(insert_kv_ex)(ht, kv, update, NULL) > 0;
}

/**
 * \brief Insert KV \p kv into hash table \p ht or replace an existing KV with \p kv,
 *        if hash table \p ht already contains a KV with the same key as \p kv
 * \param ht Hash table
 * \param kv KV; shallow copy is made when writing to the hash table
 * \param update Update flag; if set to true, replacement of existing KV is allowed
 * \param[out] out_kv Pointer to the inserted/updated KV
 *                    or pointer to the KV that prevented insertion (only if \p update set to false)
 *                    or NULL in case of error. Pointers are valid until the next modification of the hash table.
 * \return Returns HT_RC_INSERTED/HT_RC_UPDATED if KV was inserted/updated;
 *         returns HT_RC_EXISTING if key \p key already exists (only if \p update set to false);
 *         returns HT_RC_ERROR if out of memory.
 */
RZ_API HtRetCode Ht_(insert_kv_ex)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv) {
	rz_return_val_if_fail(ht && kv, HT_RC_ERROR);

	HtRetCode rc;
	HT_(Kv) *kv_dst = reserve_kv(ht, kv->key, kv->key_len, update, &rc);
	if (rc <= 0) {
		if (out_kv) {
			*out_kv = kv_dst;
		}
		return rc;
	}
	memcpy(kv_dst, kv, ht->opt.elem_size);
	kv_dst = check_growing(ht, kv_dst);
	if (out_kv) {
		*out_kv = kv_dst;
	}
	return rc;
}

static int insert_update(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value, bool update, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv) {
	ut32 key_len = calcsize_key(ht, key);
	HtRetCode rc;
	HT_(Kv) *kv_dst = reserve_kv(ht, key, key_len, update, &rc);
	if (rc <= 0) {
		if (out_kv) {
			*out_kv = kv_dst;
		}
		return rc;
	}
	kv_dst->key = dupkey(ht, key);
	kv_dst->key_len = key_len;
	kv_dst->value = dupval(ht, value);
	kv_dst->value_len = calcsize_val(ht, value);
	kv_dst = check_growing(ht, kv_dst);
	if (out_kv) {
		*out_kv = kv_dst;
	}
	return rc;
}

/**
 * \brief Insert the key value pair \p key, \p value into the hash table \p ht
 * \param ht Hash table
 * \param key KV key; copy is made according to the options of \p ht
 * \param value KV value; copy is made according to the options of \p ht
 * \return Returns true if insertion took place;
 *         returns false if out of memory or if key \p key already exists.
 */
RZ_API bool Ht_(insert)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value) {
	rz_return_val_if_fail(ht, false);
	return insert_update(ht, key, value, false, NULL) > 0;
}

/**
 * \brief Insert the key value pair \p key, \p value into the hash table \p ht
 * \param ht Hash table
 * \param key KV key; copy is made according to the options of \p ht
 * \param value KV value; copy is made according to the options of \p ht
 * \param[out] out_kv Pointer to the inserted KV
 *                    or pointer to the KV that prevented insertion
 *                    or NULL if out of memory. Pointers are valid until the next modification of the hash table.
 * \return Returns HT_RC_INSERTED if KV was inserted;
 *         returns HT_RC_EXISTING if key \p key already exists;
 *         returns HT_RC_ERROR if out of memory.
 */
RZ_API HtRetCode Ht_(insert_ex)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv) {
	rz_return_val_if_fail(ht, HT_RC_ERROR);
	return insert_update(ht, key, value, false, out_kv);
}

/**
 * \brief Insert the key value pair \p key, \p value into the hash table \p ht
 *        or update value of current KV if key \p key already exists
 * \param ht Hash table
 * \param key KV key; copy is made according to the options of \p ht
 * \param value KV value; copy is made according to the options of \p ht
 * \return Returns true if insertion/update took place;
 *         returns false if out of memory.
 */
RZ_API bool Ht_(update)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value) {
	rz_return_val_if_fail(ht, false);
	return insert_update(ht, key, value, true, NULL) > 0;
}

/**
 * \brief Insert the key value pair \p key, \p value into the hash table \p ht
 *        or update value of current KV if key \p key already exists
 * \param ht Hash table
 * \param key KV key; copy is made according to the options of \p ht
 * \param value KV value; copy is made according to the options of \p ht
 * \param[out] out_kv Pointer to the inserted/updated KV or NULL in case of error.
 *                    Pointers are valid until the next modification of the hash table.
 * \return Returns HT_RC_INSERTED/HT_RC_UPDATED if KV was inserted/updated;
 *         returns HT_RC_ERROR if out of memory.
 */
RZ_API HtRetCode Ht_(update_ex)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv) {
	rz_return_val_if_fail(ht, HT_RC_ERROR);
	return insert_update(ht, key, value, true, out_kv);
}

/**
 * Update the key of an element that has \p old_key as key and replace it with \p new_key
 */
RZ_API bool Ht_(update_key)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE old_key, const KEY_TYPE new_key) {
	rz_return_val_if_fail(ht, false);
	// First look for the value associated with old_key
	bool found;
	VALUE_TYPE value = Ht_(find)(ht, old_key, &found);
	if (!found) {
		return false;
	}

	// Associate the existing value with new_key
	bool inserted = insert_update(ht, new_key, value, false, NULL) > 0;
	if (!inserted) {
		return false;
	}

	// Remove the old_key kv, paying attention to not double free the value
	HT_(Bucket) *bt = &ht->table[bucketfn(ht, old_key)];
	const int old_key_len = calcsize_key(ht, old_key);
	HT_(Kv) *kv;
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
RZ_API RZ_BORROW HT_(Kv) *Ht_(find_kv)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	if (found) {
		*found = false;
	}
	rz_return_val_if_fail(ht, NULL);

	HT_(Bucket) *bt = &ht->table[bucketfn(ht, key)];
	ut32 key_len = calcsize_key(ht, key);
	HT_(Kv) *kv;
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
RZ_API VALUE_TYPE Ht_(find)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	HT_(Kv) *res = Ht_(find_kv)(ht, key, found);
	return res ? res->value : HT_NULL_VALUE;
}

/**
 * Deletes an entry from the hash table \p ht with key \p key, if the pair exists.
 */
RZ_API bool Ht_(delete)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key) {
	rz_return_val_if_fail(ht, false);
	HT_(Bucket) *bt = &ht->table[bucketfn(ht, key)];
	ut32 key_len = calcsize_key(ht, key);
	HT_(Kv) *kv;
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
 * Apply \p cb for each KV pair in \p ht.
 * If \p cb returns false, the iteration is stopped.
 */
RZ_API void Ht_(foreach)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(ForeachCallback) cb, RZ_NULLABLE void *user) {
	rz_return_if_fail(ht && cb);
	ut32 i;

	for (i = 0; i < ht->size; ++i) {
		HT_(Bucket) *bt = &ht->table[i];
		HT_(Kv) *kv;
		ut32 j, count;

		BUCKET_FOREACH_SAFE(ht, bt, j, count, kv) {
			if (!cb(user, kv->key, kv->value)) {
				return;
			}
		}
	}
}

/**
 * \brief Returns the number of elements stored in the hash map \p ht.
 *
 * \param ht The hash map.
 *
 * \return The number of elements saved in the hash map.
 */
RZ_API ut32 Ht_(size)(RZ_NONNULL HtName_(Ht) *ht) {
	return ht->count;
}

/**
 * \brief Advances an RzIterator with over a hashtable to the next value in
 * the hash table returns it.
 *
 * \param it The next mutable value or NULL if iteration terminated.
 */
RZ_API VALUE_TYPE *Ht_(iter_next_mut)(RzIterator *it) {
	rz_return_val_if_fail(it, NULL);

	HT_(IterMutState) *state = it->u;
	if (state->ti >= state->ht->size) {
		// Iteration is done. No elements left to select.
		return NULL;
	}
	// Iterate over tables until a table with an element is found.
	for (; state->ti < state->ht->size; state->ti++) {
		if (state->ht->table[state->ti].count == 0) {
			// Table has no elements. Check next table.
			continue;
		}
		if (state->bi < state->ht->table[state->ti].count) {
			// Table has elements, select the element.
			state->kv = &state->ht->table[state->ti].arr[state->bi];
			// For the next iteration, increment bucket index to the following element.
			state->bi++;
			return &state->kv->value;
		}
		// Reset bucket index to first bucket.
		state->bi = 0;
		// Go to next table
	}
	// Iteration is done. No elements left to select.
	return NULL;
}

/**
 * \brief Advances an RzIterator with over a hash table to the next value in
 * the hash table returns it as const.
 *
 * \param it The next value as immutable or NULL if iteration terminated.
 */
RZ_API const VALUE_TYPE *Ht_(iter_next)(RzIterator *it) {
	rz_return_val_if_fail(it, NULL);

	HT_(IterState) *state = it->u;
	if (state->ti >= state->ht->size) {
		// Iteration is done. No elements left to select.
		return NULL;
	}
	// Iterate over tables until a table with an element is found.
	for (; state->ti < state->ht->size; state->ti++) {
		if (state->ht->table[state->ti].count == 0) {
			// Table has no elements. Check next table.
			continue;
		}
		if (state->bi < state->ht->table[state->ti].count) {
			// Table has elements, select the element.
			state->kv = &state->ht->table[state->ti].arr[state->bi];
			// For the next iteration, increment bucket index to the following element.
			state->bi++;
			return (const VALUE_TYPE *)&state->kv->value;
		}
		// Reset bucket index to first bucket.
		state->bi = 0;
		// Go to next table
	}
	// Iteration is done. No elements left to select.
	return NULL;
}

/**
 * \brief Advances an RzIterator over a hash table to the next key in
 * the hash table returns it as const pointer.
 *
 * \param it The next key as immutable or NULL if iteration terminated.
 */
RZ_API const KEY_TYPE *Ht_(iter_next_key)(RzIterator *it) {
	rz_return_val_if_fail(it, NULL);

	HT_(IterState) *state = it->u;
	if (state->ti >= state->ht->size) {
		// Iteration is done. No elements left to select.
		return NULL;
	}
	// Iterate over tables until a table with an element is found.
	for (; state->ti < state->ht->size; state->ti++) {
		if (state->ht->table[state->ti].count == 0) {
			// Table has no elements. Check next table.
			continue;
		}
		if (state->bi < state->ht->table[state->ti].count) {
			// Table has elements, select the element.
			state->kv = &state->ht->table[state->ti].arr[state->bi];
			// For the next iteration, increment bucket index to the following element.
			state->bi++;
			return (const KEY_TYPE *)&state->kv->key;
		}
		// Reset bucket index to first bucket.
		state->bi = 0;
		// Go to next table
	}
	// Iteration is done. No elements left to select.
	return NULL;
}

RZ_API HT_(IterMutState) *Ht_(new_iter_mut_state)(RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterMutState) *state = RZ_NEW0(HT_(IterMutState));
	rz_return_val_if_fail(state, NULL);
	state->ht = ht;
	return state;
}

RZ_API HT_(IterState) *Ht_(new_iter_state)(const RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterState) *state = RZ_NEW0(HT_(IterState));
	rz_return_val_if_fail(state, NULL);
	state->ht = ht;
	return state;
}

RZ_API void Ht_(free_iter_mut_state)(HT_(IterMutState) *state) {
	if (state) {
		free(state);
	}
}

RZ_API void Ht_(free_iter_state)(HT_(IterState) *state) {
	if (state) {
		free(state);
	}
}

/**
 * \brief Returns an iterator over the hash table \p ht. The iterator yields mutable values.
 *
 * \param ht The hash table to create the iterator for.
 *
 * \return The iterator over the hash table values or NULL in case of failure.
 */
RZ_API RZ_OWN RzIterator *Ht_(as_iter_mut)(RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterMutState) *state = Ht_(new_iter_mut_state)(ht);
	rz_return_val_if_fail(state, NULL);

	RzIterator *iter = rz_iterator_new((rz_iterator_next_cb)Ht_(iter_next_mut), NULL, (rz_iterator_free_cb)Ht_(free_iter_mut_state), state);
	return iter;
}

/**
 * \brief Returns an iterator over the hash table \p ht. The iterator yields immutable values.
 *
 * \param ht The hash table to create the iterator for.
 *
 * \return The iterator over the hash table values or NULL in case of failure.
 */
RZ_API RZ_OWN RzIterator *Ht_(as_iter)(const RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterState) *state = Ht_(new_iter_state)(ht);
	rz_return_val_if_fail(state, NULL);

	RzIterator *iter = rz_iterator_new((rz_iterator_next_cb)Ht_(iter_next), NULL, (rz_iterator_free_cb)Ht_(free_iter_state), state);
	return iter;
}

/**
 * \brief Returns an iterator over the hash table \p ht. The iterator yields immutable keys.
 *
 * \param ht The hash table to create the iterator for.
 *
 * \return The iterator over the hash table keys or NULL in case of failure.
 */
RZ_API RZ_OWN RzIterator *Ht_(as_iter_keys)(const RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterState) *state = Ht_(new_iter_state)(ht);
	rz_return_val_if_fail(state, NULL);

	RzIterator *iter = rz_iterator_new((rz_iterator_next_cb)Ht_(iter_next_key), NULL, (rz_iterator_free_cb)Ht_(free_iter_state), state);
	return iter;
}
