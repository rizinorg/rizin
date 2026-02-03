// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_types.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_bits.h>

// Load factor thershold of 87.5% (after that the table grows)
#define LOAD_FACTOR_NUM 7
#define LOAD_FACTOR_DEN 8 /* should be power of 2; also GROUP_WIDTH should be multiple of LOAD_FACTOR_DEN */

// #define S_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0])) /*??*/
// #define QUICK_MIX(h) ((key) ^= (key) >> 16, (h) *= 0x9e3779b1u, (h) ^= (h) >> 15)
#define HASH_MIX(h) (h)

#define H1(HASH)                     (HASH >> 7)
#define H2_HASH_FRAGMENT(HASH)       (HASH & 0x7F)
#define H2_STATUS_DELETED            0b11111110
#define H2_STATUS_EMPTY              0b11111111
#define H2_IS_EMPTY_OR_DELETED(CTRL) (CTRL >> 7)
#define H2_IS_EMPTY(CTRL)            (CTRL == H2_STATUS_EMPTY)
#define H2_IS_DELETED(CTRL)          (CTRL == H2_STATUS_DELETED)
#define INDEX_TYPE                   ut32
#define INVALID_INDEX                UT32_MAX

// todo:
//	- [x] allocate first -> 0 bytes (update: actually MIN_CAPACITY)
// 	- [x] handle realloc / rehash -> capacity should be multiple of x^2-1; new_cap = (old_cap + 1 * 2) - 1 (update: capacity is actually x^2, and bitmask is capacity-1)
// 	- [x] should keep up to 87.5% load factor
// 	- [x] "rehash in place"
// 	- ensure SIMD alignment
//	- [x] clone first group at `ctrl` end
//	- [x] handle ctrl mirroring for sizes < GROUP_WIDTH
//	- the hash function should distribute entroy in both high and low bits to avoid H1 and H2 collisions

// todo: define likely/unlikely; OR remove it there is no impact
#define RZ_HOT_PATH
#define RZ_COLD_PATH

#define GROUP_WIDTH 8

/*
 * TODO:
 *	- add support for native 4-group parallel lookup on 32-bit environments
 *	- add support for ARM SIMD (NEON)
 */

#define MIN_CAPACITY (GROUP_WIDTH)

// static inline ut32 hashfn_quick_mix(ut32 h) {
//     ut32 x = (h ^ (h >> 16)) * 0x9e3779b1u;
//     return x ^ (x >> 15);
// }

static inline ut32 hashfn(HtName_(Ht) *ht, const KEY_TYPE k) { // todo: maybe use 64-bit hash
	return ht->opt.hashfn ? ht->opt.hashfn(k) : KEY_TO_HASH(k);
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

// static inline ut32 next_idx(ut32 idx) { // ??
// 	if (idx != UT32_MAX && idx < S_ARRAY_SIZE(ht_primes_sizes) - 1) {
// 		return idx + 1;
// 	}
// 	return UT32_MAX;
// }

// static inline ut32 compute_size(ut32 idx, ut32 sz) {
// 	// when possible, use the precomputed prime numbers which help with
// 	// collisions, otherwise, at least make the number odd with |1
// 	return idx != UT32_MAX && idx < S_ARRAY_SIZE(ht_primes_sizes) ? ht_primes_sizes[idx] : (sz | 1);
// }

static inline bool is_key_equal(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, const HT_(Kv) *kv) {
	if (key_len != kv->key_len) {
		return false;
	}

	if (key == kv->key) {
		return true;
	}

	return ht->opt.cmp && !ht->opt.cmp(key, kv->key);
}

// static inline HT_(Kv) *kv_at(HtName_(Ht) *ht, HT_(Bucket) *bt, ut32 i) {
// 	return (HT_(Kv) *)((char *)bt->arr + i * ht->opt.elem_size);
// }

// static inline HT_(Kv) *next_kv(HtName_(Ht) *ht, HT_(Kv) *kv) {
// 	return (HT_(Kv) *)((char *)kv + ht->opt.elem_size);
// }

// #define BUCKET_FOREACH(ht, bt, j, kv) \
// 	if ((bt)->arr) \
// 		for ((j) = 0, (kv) = (bt)->arr; (j) < (bt)->count; (j)++, (kv) = next_kv(ht, kv))

// #define BUCKET_FOREACH_SAFE(ht, bt, j, count, kv) \
// 	if ((bt)->arr) \
// 		for ((j) = 0, (kv) = (bt)->arr, (count) = (ht)->count; \
// 			(j) < (bt)->count; \
// 			(j) = (count) == (ht)->count ? j + 1 : j, (kv) = (count) == (ht)->count ? next_kv(ht, kv) : kv, (count) = (ht)->count)

// todo: avoid assigning past end
#define HT_FOREACH(ht, i, kv) \
	for ((i) = 0, (kv) = (void*)&(ht)->slots[(i)]; (i) < (ht)->capacity; (i)++) if (!H2_IS_EMPTY_OR_DELETED((ht)->ctrl[(i)]))

static void ctrl_table_set(HtName_(Ht) *ht, INDEX_TYPE idx, ut8 value) {
	ht->ctrl[idx] = value;

	// Copy to mirrored bytes
	if (idx < GROUP_WIDTH - 1) {
		ht->ctrl[ht->capacity + idx] = value;
	}
}

static ut32 next_power_of_two(ut32 n) {
	if (n <= 1) {
		return 1;
	}

	if ((n & (n - 1)) == 0) {
		return n;
	}

	return 1ul << (32 - rz_bits_leading_zeros(n));
}

// Create a new hashtable and return a pointer to it.
// size - number of buckets in the hashtable
/**
 * todo..
 */
static RZ_OWN HtName_(Ht) *internal_ht_new(ut32 requested_capacity, HT_(Options) *opt) {
	HtName_(Ht) *ht = RZ_NEW0(HtName_(Ht));
	if (!ht) {
		return NULL;
	}

	// Use minimum capacity of group size in order to avoid edge cases (related to ctrl byte mirroring and deletion slot placement)
	// No maximum capacity enforcement at the moment..
	ht->capacity = next_power_of_two(RZ_MAX(requested_capacity, 16));
	ht->size = 0;

	// Allocate additional space for the mirrored bytes at the end of the control array
	ut32 ctrl_size = (ht->capacity + GROUP_WIDTH) * sizeof(*ht->ctrl);
	ut32 slots_size = ht->capacity * sizeof(*ht->slots);

	// Allocate single heap block for both control and slot arrays
	if ((ht->data = calloc(ctrl_size + slots_size, sizeof(ut8))) == NULL) { // todo: use malloc
		return NULL;
	}

	ht->ctrl = ht->data;
	ht->slots = (HT_(Kv) *)(ht->data + ctrl_size);
	ht->opt = *opt;

	// Initialize all slots as empty
	memset(ht->ctrl, H2_STATUS_EMPTY, ctrl_size);

	// If not provided, assume we are dealing with a regular HtName_(Ht), with HT_(Kv) as elements
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
	return internal_ht_new(0, opt);
}

/**
 * \brief Create a new hashtable with options \p opt and
 *        preallocated buckets for \p initial_size entries.
 *
 * Options are copied to an inner field.
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt_size)(RZ_NONNULL HT_(Options) *opt, ut32 initial_size) {
	rz_return_val_if_fail(opt, NULL);
	return internal_ht_new(initial_size, opt);
}

/**
 * todo..
 */
RZ_API void Ht_(free)(RZ_NULLABLE HtName_(Ht) *ht) {
	if (!ht) {
		return;
	}

	if (ht->opt.finiKV) {
		for (INDEX_TYPE i = 0; i < ht->capacity; i++) {
			if (H2_IS_EMPTY_OR_DELETED(ht->ctrl[i])) { // todo: process all elements in group
				continue;
			}
			ht->opt.finiKV(&ht->slots[i], ht->opt.finiKV_user);
		}
	}

	free(ht->data);
	free(ht);
}

/**
 * Increases the capacity of the hashtable to `(x + 1) * 2 - 1` where `x` is the previous cpacity.
 * Tracks change of KV \p tracked position.
 */
// static HT_(Kv) *internal_ht_grow(HtName_(Ht) *ht, HT_(Kv) *tracked) {
// 	ut32 idx = next_idx(ht->prime_idx);
// 	// ut32 sz = compute_size(idx, ht->size * 2);
// 	ut32 cap = (ht->capacity + 1) * 2 - 1;

// 	HtName_(Ht) *ht2 = internal_ht_new(cp, idx, &ht->opt);
// 	if (!ht2) {
// 		// we can't grow the ht anymore. Never mind, we'll be slower,
// 		// but everything can continue to work
// 		return tracked;
// 	}

// 	// Iterate all slots
// 	for (ut32 i = 0; i < ht->capacity; i++) {
// 		if (ht->ctrl[i].empty) {
// 			continue;
// 		}
// 		if (kv == tracked) {
// 			continue;
// 		}
// 		if (Ht_(insert_kv_ex)(ht2, ht->slots[i], false, NULL) < 0) {
// 			ht2->opt.finiKV = NULL;
// 			Ht_(free)(ht2);
// 			return tracked; //?
// 		}
// 	}

// 	// Insert ???
// 	if (Ht_(insert_kv_ex)(ht2, tracked, false, &tracked) < 0) {
// 		ht2->opt.finiKV = NULL;
// 		Ht_(free)(ht2);
// 		return tracked;
// 	}

// 	// And now swap the internals.
// 	HtName_(Ht) swap = *ht;
// 	*ht = *ht2;
// 	*ht2 = swap;

// 	ht2->opt.finiKV = NULL;
// 	Ht_(free)(ht2);
// 	return tracked;
// }

/**
 * todo
 * \return true if either no growing is needed or there was a successfull growth; otherwise returns false on failed growth attempt
 */
static bool grow_if_needed(HtName_(Ht) *ht) {
	if (ht->size < (ht->capacity / LOAD_FACTOR_DEN) * LOAD_FACTOR_NUM) {
		return true;
	}

	// Create a new hash table
	HtName_(Ht) *ht2 = internal_ht_new(ht->capacity + 1, &ht->opt);
	if (!ht2) {
		// we can't grow the ht anymore. Never mind, we'll be slower,
		// but everything can continue to work
		return false;
	}

	// Iterate all slots and copy elements to `h2`
	for (ut32 i = 0; i < ht->capacity; i++) {
		if (H2_IS_EMPTY_OR_DELETED(ht->ctrl[i])) {
			continue;
		}

		if (Ht_(insert_kv_ex)(ht2, &ht->slots[i], false, NULL) < 0) {
			ht2->opt.finiKV = NULL;
			Ht_(free)(ht2);
			return false;
		}
	}

	// And now swap the internals.
	HtName_(Ht) swap = *ht;
	*ht = *ht2;
	*ht2 = swap;

	ht2->opt.finiKV = NULL;
	Ht_(free)(ht2);
	return true;
}

// static HT_(Kv) *check_growing(HtName_(Ht) *ht, HT_(Kv) *tracked) {
// 	if (ht->count >= LOAD_FACTOR * ht->capacity) {
// 		return internal_ht_grow(ht, tracked);
// 	}
// 	return tracked;
// }

/**
 * todo..
 * \return if the \p key is found this function will return it's slot ID, otherwise will return the ID of the next available slot for insertion purposes
 */
static INDEX_TYPE ctrl_table_lookup_or_reserve(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, bool *existing) {
	ut32 hash = hashfn(ht, key);
	hash = HASH_MIX(hash);

	ut32 hash_fragment = H2_HASH_FRAGMENT(hash);
	ut32 probe_step = GROUP_WIDTH;
	INDEX_TYPE index = H1(hash) & (ht->capacity - 1); // todo: rename to group_index_start, etc
	INDEX_TYPE first_deleted = INVALID_INDEX;

	while (true) {
		// TODO: Probe one group at a time
		for (INDEX_TYPE i = index; i < index + GROUP_WIDTH; i++) {
			INDEX_TYPE normalized_i = i & (ht->capacity - 1);
			ut8 *ctrl = &ht->ctrl[i];

			if (H2_IS_EMPTY(*ctrl)) {
				*existing = false;
				return first_deleted == INVALID_INDEX ? normalized_i : first_deleted;
			}

			if (H2_HASH_FRAGMENT(*ctrl) == H2_HASH_FRAGMENT(hash) && RZ_HOT_PATH(is_key_equal(ht, key, key_len, &ht->slots[normalized_i]))) {
				*existing = true;
				return normalized_i;
			}

			// If we visit a deleted slot, save it's index for potential later use
			if (H2_IS_DELETED(*ctrl) && first_deleted == INVALID_INDEX) {
				first_deleted = normalized_i;
			}
		}

		// Warn if we reach past the probing sequence (unexpected since we shouldn't get above load factor > 85.4%)
		if (RZ_COLD_PATH(probe_step >= ht->capacity)) {
			rz_warn_if_reached();
			*existing = false;
			return INVALID_INDEX;
		}

		// Triangular probing
		index = (index + probe_step) & (ht->capacity - 1);
		probe_step += GROUP_WIDTH;
	}
}

/**
 * todo..
 */
static INDEX_TYPE ctrl_table_lookup(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len) {
	ut32 hash = hashfn(ht, key);
	hash = HASH_MIX(hash);

	ut32 hash_fragment = H2_HASH_FRAGMENT(hash);
	ut32 probe_step = GROUP_WIDTH;
	INDEX_TYPE index = H1(hash) & (ht->capacity - 1);

	while (true) {
		// todo: Probe one group at a time
		for (ut32 i = index; i < index + GROUP_WIDTH; i++) {
			INDEX_TYPE normalized_i = i & (ht->capacity - 1);
			ut8 *ctrl = &ht->ctrl[i];

			if (H2_IS_EMPTY(*ctrl)) {
				return INVALID_INDEX;
			}

			if (H2_HASH_FRAGMENT(*ctrl) == hash_fragment && RZ_HOT_PATH(is_key_equal(ht, key, key_len, &ht->slots[normalized_i]))) {
				return normalized_i;
			}
		}

		// Warn if we reach past the probing sequence (unexpected)
		if (RZ_COLD_PATH(probe_step >= ht->capacity)) {
			rz_warn_if_reached();
			return INVALID_INDEX;
		}

		// Triangular probing
		index = (index + probe_step) & (ht->capacity - 1);
		probe_step += GROUP_WIDTH;
	}
}

/**
 * \brief Get an existing KV with key \p key or allocate a new KV otherwise
 */
static RZ_BORROW HT_(Kv) *reserve_kv(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, bool update, RZ_NONNULL HtRetCode *code) {
	if (RZ_COLD_PATH(!grow_if_needed(ht))) {
		*code = HT_RC_ERROR;
		return NULL;
	}

	bool existing = false;
	INDEX_TYPE idx = ctrl_table_lookup_or_reserve(ht, key, key_len, &existing);

	if (RZ_COLD_PATH(idx == INVALID_INDEX)) {
		*code = HT_RC_ERROR;
		return NULL;
	}

	if (existing) {
		if (update) {
			fini_kv_pair(ht, &ht->slots[idx]);
			*code = HT_RC_UPDATED;
		} else {
			*code = HT_RC_EXISTING;
		}
		return &ht->slots[idx];
	}

	// Writing over an empty or a deleted slot
	*code = HT_RC_INSERTED;

	ht->size++;
	ctrl_table_set(ht, idx, H2_HASH_FRAGMENT(hashfn(ht, key)));
	return &ht->slots[idx];
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
	// todo: check if we need to inline
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

	if (out_kv) {
		*out_kv = kv_dst;
	}

	return rc;
}

static HtRetCode insert_update(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value, bool update, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv) {
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
	INDEX_TYPE idx;

	// First look for the value associated with old_key
	if ((idx = ctrl_table_lookup(ht, old_key, calcsize_key(ht, old_key))) == INVALID_INDEX) {
		return false;
	}

	// Associate the new key with the existing value
	if (insert_update(ht, new_key, ht->slots[idx].value, false, NULL) <= 0) {
		return false;
	}

	// Remove the old_key kv, paying attention to not double free the value
	// TODO: use empty instead of delete where possible...
	ctrl_table_set(ht, idx, H2_STATUS_DELETED);

	// Do not free the value part if dupvalue is not set, because the old value will be
	// associated with the new key and it should not be freed
	if (!ht->opt.dupvalue) {
		ht->slots[idx].value = HT_NULL_VALUE;
		ht->slots[idx].value_len = 0;
	}
	fini_kv_pair(ht, &ht->slots[idx]);

	return true;
}

/**
 * Returns the corresponding Kv entry from \p key.
 * If \p found is not NULL, it will be set to true if the entry was found,
 * false otherwise.
 */
RZ_API RZ_BORROW HT_(Kv) *Ht_(find_kv)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	rz_return_val_if_fail(ht, NULL);
	INDEX_TYPE idx = ctrl_table_lookup(ht, key, calcsize_key(ht, key));

	if (idx == INVALID_INDEX) {
		if (found) {
			*found = false;
		}
		return NULL;
	}

	if (found) {
		*found = true;
	}

	return &ht->slots[idx];
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
	INDEX_TYPE idx = ctrl_table_lookup(ht, key, calcsize_key(ht, key));

	if (idx == INVALID_INDEX) {
		return false;
	}

	ht->size--;
	ctrl_table_set(ht, idx, H2_STATUS_DELETED); // todo: use empty where possible
	fini_kv_pair(ht, &ht->slots[idx]);

	return true;
}

/**
 * Apply \p cb for each KV pair in \p ht.
 * If \p cb returns false, the iteration is stopped.
 */
RZ_API void Ht_(foreach)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(ForeachCallback) cb, RZ_NULLABLE void *user) {
	rz_return_if_fail(ht && cb);

	// Iterate all slots and copy elements to `h2`
	for (INDEX_TYPE i = 0; i < ht->capacity; i++) {
		if (H2_IS_EMPTY_OR_DELETED(ht->ctrl[i])) { // todo: process all elements in group
			continue;
		}

		if (!cb(user, ht->slots[i].key, ht->slots[i].value)) {
			return;
		}
	}
}

/**
 * \brief Returns the number of elements stored in the hash map \p ht.
 *
 * \param ht The hash map.
 * \return The number of elements saved in the hash map.
 */
RZ_API ut32 Ht_(size)(const RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, 0);
	return ht->size;
}

/**
 * \brief Advances an RzIterator over a hashtable to the next value and returns it.
 *
 * \param it The next value or NULL if iteration terminated. The value is mutable.
 */
RZ_API RZ_BORROW VALUE_TYPE *Ht_(iter_next_mut)(RzIterator *it) {
	rz_return_val_if_fail(it, NULL);
	HT_(IterMutState) *state = it->u;

	// Iterate over tables until a table with an element is found.
	for (; state->ti < state->ht->capacity; state->ti++) {
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) { // todo: process all elements in group
			continue;
		}
		state->kv = &state->ht->slots[state->ti];
		state->ti++;
		return &state->kv->value;
	}

	// Iteration is done. No elements left to select.
	return NULL;
}

/**
 * \brief Advances an RzIterator over a hash table to the next value and returns it.
 *
 * \param it The next value as immutable or NULL if iteration terminated.
 */
RZ_API const VALUE_TYPE *Ht_(iter_next)(RzIterator *it) {
	rz_return_val_if_fail(it, NULL);
	HT_(IterState) *state = it->u;

	// Iterate over tables until a table with an element is found.
	for (; state->ti < state->ht->capacity; state->ti++) {
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) { // todo: process all elements in group
			continue;
		}
		state->kv = &state->ht->slots[state->ti];
		state->ti++;
		return (const VALUE_TYPE *)&state->kv->value;
	}

	// Iteration is done. No elements left to select.
	return NULL;
}

/**
 * \brief Advances an RzIterator over a hash table to the next key in
 * and returns it.
 *
 * \param it The next key as immutable or NULL if iteration terminated.
 */
RZ_API const KEY_TYPE *Ht_(iter_next_key)(RzIterator *it) {
	rz_return_val_if_fail(it, NULL);
	HT_(IterMutState) *state = it->u;

	// Iterate over tables until a table with an element is found.
	for (; state->ti < state->ht->capacity; state->ti++) {
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) { // todo: process all elements in group
			continue;
		}
		state->kv = &state->ht->slots[state->ti];
		state->ti++;
		return (const KEY_TYPE *)&state->kv->key;
	}

	// Iteration is done. No elements left to select.
	return NULL;
}

RZ_API RZ_OWN HT_(IterMutState) *Ht_(new_iter_mut_state)(RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterMutState) *state = RZ_NEW0(HT_(IterMutState));
	rz_return_val_if_fail(state, NULL);
	state->ht = ht;
	return state;
}

RZ_API RZ_OWN HT_(IterState) *Ht_(new_iter_state)(const RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterState) *state = RZ_NEW0(HT_(IterState));
	rz_return_val_if_fail(state, NULL);
	state->ht = ht;
	return state;
}

RZ_API void Ht_(free_iter_mut_state)(RZ_NULLABLE HT_(IterMutState) *state) {
	free(state);
}

RZ_API void Ht_(free_iter_state)(RZ_NULLABLE HT_(IterState) *state) {
	free(state);
}

/**
 * \brief Returns an iterator over the hash table \p ht. The iterator yields mutable values.
 *
 * \param ht The hash table to create the iterator for.
 *
 * \return The iterator over the hash table values or NULL in case of failure.
 */
RZ_API RZ_OWN RzIterator /* <HtName_(Ht)> */ *Ht_(as_iter_mut)(RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterMutState) *state = Ht_(new_iter_mut_state)(ht);
	if (!state) {
		RZ_LOG_ERROR("Could not allocate a new ht_iter state.\n");
		return NULL;
	}

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
RZ_API RZ_OWN RzIterator /* <HtName_(Ht)> */ *Ht_(as_iter)(const RZ_NONNULL HtName_(Ht) *ht) {
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
RZ_API RZ_OWN RzIterator /* <HtName_(Ht)> */ *Ht_(as_iter_keys)(const RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_val_if_fail(ht, NULL);
	HT_(IterState) *state = Ht_(new_iter_state)(ht);
	rz_return_val_if_fail(state, NULL);

	RzIterator *iter = rz_iterator_new((rz_iterator_next_cb)Ht_(iter_next_key), NULL, (rz_iterator_free_cb)Ht_(free_iter_state), state);
	return iter;
}
