// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_types.h>
#include <rz_endian.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_iterator.h>
#include <rz_util/rz_str.h>
#include <rz_util/rz_bits.h>

/**
 * \file ht_inc.c
 * \brief "SwissTable" hash table implementation.
 *
 * References:
 * 	- https://abseil.io/about/design/swisstables
 *  - https://en.wikipedia.org/wiki/Open_addressing
 */

// Load factor thershold of 87.5% (after that the table grows)
#define LOAD_FACTOR_NUM 7
#define LOAD_FACTOR_DEN 8 /* should be power of 2; also GROUP_WIDTH should be multiple of LOAD_FACTOR_DEN */

// Helper macros for H1/H2 hash components
#define H1(HASH)                     ((HASH) >> 7)
#define H2_HASH_FRAGMENT(HASH)       ((HASH) & 0x7F)
#define H2_STATUS_DELETED            0b11111110
#define H2_STATUS_EMPTY              0b11111111
#define H2_IS_EMPTY_OR_DELETED(CTRL) ((CTRL) >> 7)
#define H2_IS_EMPTY(CTRL)            ((CTRL) == H2_STATUS_EMPTY)
#define H2_IS_DELETED(CTRL)          ((CTRL) == H2_STATUS_DELETED)
#define INDEX_TYPE                   ut32
#define INVALID_INDEX                UT32_MAX

// Select lookup implementation
#if HAVE_SSE2
#include <emmintrin.h>
#define LOOKUP_METHOD_SSE2
#define GROUP_WIDTH 16
typedef ut16 group_mask_t;
typedef __m128i group_t;
#elif RZ_SYS_BITS == RZ_SYS_BITS_64
#define LOOKUP_METHOD_BITWISE_64
typedef ut64 group_t;
typedef ut64 group_mask_t;
#define GROUP_WIDTH sizeof(group_t)
#else
// Default lookup implementation
typedef ut64 group_t;
#define GROUP_WIDTH sizeof(group_t)
#endif

// Minimal capacity of a hash table
#define MIN_CAPACITY GROUP_WIDTH

// Slot addressing is different depending on whether custom elem_size is used
#ifdef HT_ENABLE_CUSTOM_ELEM_SIZE
#define HT_SLOT_AT(ht, index) \
	((HT_(Kv) *)((ut8 *)(ht->slots_) + index * ht->opt.elem_size))
#else
#define HT_SLOT_AT(ht, index) \
	(&(ht)->slots_[(index)])
#endif

// Helper macro for implementing an unrolled foreach loop
#define HT_FOREACH_UNROLL(ht, kv, idx, body) \
	if (!H2_IS_EMPTY_OR_DELETED((ht)->ctrl[idx])) { \
		HT_(Kv) *kv = HT_SLOT_AT((ht), (idx)); \
		body \
	}

// Helper function for the different lookup implementations
#if defined(LOOKUP_METHOD_SSE2)
static inline group_t group_load(const void *addr) {
	return _mm_loadu_si128((const __m128i *)addr);
}

static inline group_mask_t group_match_hash_fragment(group_t group, ut8 ctrl) {
	__m128i ctrl_vec = _mm_set1_epi8((char)ctrl);
	__m128i diff = _mm_cmpeq_epi8(group, ctrl_vec);
	return (group_mask_t)_mm_movemask_epi8(diff);
}

static inline group_mask_t group_match_empty(group_t group) {
	__m128i empty_vec = _mm_set1_epi8(H2_STATUS_EMPTY);
	__m128i diff = _mm_cmpeq_epi8(group, empty_vec);
	return (group_mask_t)_mm_movemask_epi8(diff);
}

static inline group_mask_t group_match_deleted(group_t group) {
	__m128i deleted_vec = _mm_set1_epi8(H2_STATUS_DELETED);
	__m128i diff = _mm_cmpeq_epi8(group, deleted_vec);
	return (group_mask_t)_mm_movemask_epi8(diff);
}

static inline ut8 group_lowest_bit(group_mask_t mask) {
	return rz_bits_trailing_zeros(mask);
}

#define HT_FOREACH(ht, kv, body) \
	for (INDEX_TYPE i = 0; i < (ht)->capacity; i += GROUP_WIDTH) { \
		RZ_PREFETCH(&(ht)->ctrl[i + GROUP_WIDTH]); \
		RZ_PREFETCH(HT_SLOT_AT((ht), i + GROUP_WIDTH)); \
		HT_FOREACH_UNROLL(ht, kv, i + 0, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 1, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 2, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 3, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 4, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 5, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 6, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 7, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 8, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 9, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 10, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 11, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 12, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 13, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 14, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 15, body); \
	}
#elif defined(LOOKUP_METHOD_BITWISE_64)
static inline group_t group_load(const void *addr) {
	return rz_read_le64(addr);
}

// Construct a ut64 by repeating a single byte (e.g. 0xF0 -> 0xF0F0F0F0F0F0F0F0)
static inline group_t group_repeat(ut8 byte) {
	return byte * 0x0101010101010101ull;
}

static inline group_t group_match_hash_fragment(group_t group, ut8 ctrl) {
	group_t diff = group ^ group_repeat(ctrl);
	return (diff - group_repeat(0x01)) & ~diff & group_repeat(0x80);
}

static inline group_mask_t group_match_empty(group_t group) {
	group_mask_t xor = group ^ group_repeat(0xFF);
	return (xor - group_repeat(0x01)) & ~xor & group_repeat(0x80);
}

static inline group_mask_t group_match_deleted(group_t group) {
	return group & ~(group << 1) & group_repeat(0x80);
}

static inline ut8 group_lowest_bit(group_mask_t mask) {
	return mask ? rz_bits_trailing_zeros(mask) / 8 : UT8_MAX;
}

#define HT_FOREACH(ht, kv, body) \
	for (INDEX_TYPE i = 0; i < (ht)->capacity; i += GROUP_WIDTH) { \
		RZ_PREFETCH(&(ht)->ctrl[i + GROUP_WIDTH]); \
		RZ_PREFETCH(HT_SLOT_AT((ht), i + GROUP_WIDTH)); \
		HT_FOREACH_UNROLL(ht, kv, i + 0, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 1, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 2, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 3, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 4, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 5, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 6, body); \
		HT_FOREACH_UNROLL(ht, kv, i + 7, body); \
	}
#else
// Default implementation
#define HT_FOREACH(ht, kv, body) \
	for (INDEX_TYPE i = 0; i < (ht)->capacity; i++) { \
		if (!H2_IS_EMPTY_OR_DELETED((ht)->ctrl[i])) { \
			HT_(Kv) *kv = HT_SLOT_AT((ht), i); \
			body \
		} \
	}
#endif

static inline ut32 kv_key_len(const HT_(Kv) *kv) {
#ifdef VARIABLE_KEY_LEN
	return kv->key_len;
#else
	return 0;
#endif
}

static inline ut32 hashfn(HtName_(Ht) *ht, const KEY_TYPE k, ut32 key_size) {
	return ht->opt.hashfn ? ht->opt.hashfn(k) : KEY_TO_HASH(k, key_size);
}

static inline KEY_TYPE dupkey(HtName_(Ht) *ht, const KEY_TYPE k) {
	return ht->opt.dupkey ? ht->opt.dupkey(k) : (KEY_TYPE)k;
}

static inline VALUE_TYPE dupval(HtName_(Ht) *ht, const VALUE_TYPE v) {
	return ht->opt.dupvalue ? ht->opt.dupvalue(v) : (VALUE_TYPE)v;
}

static inline ut32 calcsize_key(HtName_(Ht) *ht, const KEY_TYPE k) {
#ifdef VARIABLE_KEY_LEN
	return ht->opt.calcsizeK ? ht->opt.calcsizeK(k) : 0;
#else
	return 0;
#endif
}

static inline ut32 calcsize_val(HtName_(Ht) *ht, const VALUE_TYPE v) {
#ifdef VARIABLE_VALUE_LEN
	return ht->opt.calcsizeV ? ht->opt.calcsizeV(v) : 0;
#else
	return 0;
#endif
}

static inline void fini_kv_pair(HtName_(Ht) *ht, HT_(Kv) *kv) {
	if (ht->opt.finiKV) {
		ht->opt.finiKV(kv, ht->opt.finiKV_user);
	}
}

static inline bool is_key_equal(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, const HT_(Kv) *kv) {
#ifdef VARIABLE_KEY_LEN
	if (key_len != kv_key_len(kv)) {
		return false;
	}
#endif

	if (key == kv->key) {
		return true;
	}

	return ht->opt.cmp && !ht->opt.cmp(key, kv->key);
}

static void ctrl_table_set(HtName_(Ht) *ht, INDEX_TYPE idx, ut8 value) {
	// Branchless copy to mirrored bytes: if idx < GROUP_WIDTH the code below will set `mirror_idx`
	// to `ht->capacity + idx` and otherwise to `idx` (resulting in harmless duplicate write).
	ut32 mirror_idx = ((idx - (GROUP_WIDTH - 1)) & ht->capacity_mask) + ((GROUP_WIDTH - 1) & ht->capacity_mask);
	ht->ctrl[idx] = value;
	ht->ctrl[mirror_idx] = value;
}

static ut32 next_power_of_two(ut32 n) {
	if (n <= 1) {
		return 1;
	}

	if ((n & (n - 1)) == 0) {
		return n;
	}

	ut8 shift = 64 - rz_bits_leading_zeros(n);

	if (shift > 31) {
		// ut32 overflow
		rz_warn_if_reached();
		return 0x80000000;
	}

	return 1ul << shift;
}

/**
 * \brief Create a new hashtable and return a pointer to it.
 */
static RZ_OWN HtName_(Ht) *internal_ht_new(ut32 requested_capacity, HT_(Options) *opt) {
	HtName_(Ht) *ht = RZ_NEW0(HtName_(Ht));
	if (!ht) {
		return NULL;
	}

	// Use minimum capacity of group size in order to avoid edge cases (related to ctrl byte mirroring and deletion slot placement)
	// No maximum capacity enforcement at the moment..
	ht->capacity = next_power_of_two(RZ_MAX(requested_capacity, 16));
	ht->capacity_mask = ht->capacity - 1;
	ht->growth_left = (ht->capacity / LOAD_FACTOR_DEN) * LOAD_FACTOR_NUM;
	ht->size = 0;
	ht->opt = *opt;

	// If not provided, assume we are dealing with a regular HtName_(Ht), with HT_(Kv) as elements
	if (ht->opt.elem_size == 0) {
		ht->opt.elem_size = sizeof(HT_(Kv));
	}

	// Allocate additional space for the mirrored bytes at the end of the control array
	ut32 ctrl_size = (ht->capacity + GROUP_WIDTH) * sizeof(*ht->ctrl);
	ut32 slots_size = ht->capacity * ht->opt.elem_size;

#ifndef HT_ENABLE_CUSTOM_ELEM_SIZE
	if (ht->opt.elem_size != sizeof(HT_(Kv))) {
		// Custom elem_size support can be enabled by uncommenting the respective define
		rz_warn_if_reached();
		free(ht);
		return NULL;
	}
#endif

#ifndef VARIABLE_KEY_LEN
	if (ht->opt.calcsizeK) {
		// Key type is expected to be fixed sized (i.e. ut64)
		rz_warn_if_reached();
		free(ht);
		return NULL;
	}
#endif

#ifndef VARIABLE_VALUE_LEN
	if (ht->opt.calcsizeV) {
		// Value type is expected to be fixed sized (i.e. ut64)
		rz_warn_if_reached();
		free(ht);
		return NULL;
	}
#endif

	// Allocate single heap block for both control and slot arrays
	if ((ht->data = malloc(ctrl_size + slots_size)) == NULL) {
		free(ht);
		return NULL;
	}

	ht->ctrl = ht->data;
	ht->slots_ = (HT_(Kv) *)(ht->data + ctrl_size);

	// Initialize all slots as empty
	memset(ht->ctrl, H2_STATUS_EMPTY, ctrl_size);
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

RZ_API void Ht_(free)(RZ_NULLABLE HtName_(Ht) *ht) {
	if (!ht) {
		return;
	}

	if (ht->opt.finiKV) {
		HT_FOREACH(ht, kv, {
			fini_kv_pair(ht, kv);
		});
	}

	free(ht->data);
	free(ht);
}

/**
 * \brief Remove all entries in the hash table.
 *
 * \param ht The hash table to clear.
 */
RZ_API void Ht_(clear)(RZ_NONNULL HtName_(Ht) *ht) {
	rz_return_if_fail(ht);

	if (ht->opt.finiKV) {
		HT_FOREACH(ht, kv, {
			fini_kv_pair(ht, kv);
		});
	}

	// Reset control byte array
	memset(ht->ctrl, H2_STATUS_EMPTY, (ht->capacity + GROUP_WIDTH) * sizeof(*ht->ctrl));
	ht->growth_left = (ht->capacity / LOAD_FACTOR_DEN) * LOAD_FACTOR_NUM;
	ht->size = 0;
}

/**
 * \brief Creates a new hash table with requested size, copies existing elements and swaps with \p ht.
 */
static bool internal_ht_resize(HtName_(Ht) *ht, ut32 new_size) {
	// Create a new hash table
	HtName_(Ht) *ht2 = internal_ht_new(new_size, &ht->opt);
	if (!ht2) {
		// we can't grow the ht anymore. Never mind, we'll be slower,
		// but everything can continue to work
		return false;
	}

	HT_FOREACH(ht, kv, {
		if (Ht_(insert_kv_ex)(ht2, kv, false, NULL) < 0) {
			ht2->opt.finiKV = NULL;
			Ht_(free)(ht2);
			return false;
		}
	});

	// And now swap the internals.
	HtName_(Ht) swap = *ht;
	*ht = *ht2;
	*ht2 = swap;

	ht2->opt.finiKV = NULL;
	Ht_(free)(ht2);
	return true;
}

/**
 * \brief Checks if the hash table needs to grow (if load factor limit is reached) or rehash (if there are too many slots marked as "deleted")
 */
static bool internal_ht_rehash_if_needed(HtName_(Ht) *ht) {
	if (ht->growth_left) {
		return true;
	}

	ut32 capacity_used = (ht->capacity / LOAD_FACTOR_DEN) * LOAD_FACTOR_NUM - ht->growth_left;
	ut32 num_deleted = capacity_used - ht->size;

	if (num_deleted > ht->capacity / 4) {
		// 25% of the elements are deleted slots; rehash with the same size
		return internal_ht_resize(ht, ht->capacity);
	}

	// Grow
	return internal_ht_resize(ht, ht->capacity + 1);
}

/**
 * \brief Looks up an existing \p key, or reserves an unused slot otherwise.
 */
static INDEX_TYPE ctrl_table_lookup_or_reserve(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, ut32 hash, ut8 hash_fragment, ut8 *previous_ctrl, bool *existing) {
	ut32 probe_step = GROUP_WIDTH;
	INDEX_TYPE index = H1(hash) & ht->capacity_mask;
	INDEX_TYPE first_deleted = INVALID_INDEX;

	while (true) {
		// Probe one group at a time
#if defined(LOOKUP_METHOD_SSE2) || defined(LOOKUP_METHOD_BITWISE_64)
		group_mask_t deleted_match;
		group_mask_t empty_match;
		group_t group = group_load(&ht->ctrl[index]);

		// Match all control group bytes with the hash fragment of `key`
		for (group_mask_t ctrl_match = group_match_hash_fragment(group, hash_fragment); ctrl_match != 0; ctrl_match &= ctrl_match - 1) {
			INDEX_TYPE i = (index + group_lowest_bit(ctrl_match)) & ht->capacity_mask;

			if (is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, i))) {
				*existing = true;
				*previous_ctrl = 0; // not empty or deleted; we don't need the actual value
				return i;
			}
		}

		// If we reach a "deleted" slot, save it's index and return later
		if (first_deleted == INVALID_INDEX && (deleted_match = group_match_deleted(group))) {
			first_deleted = (index + group_lowest_bit(deleted_match)) & ht->capacity_mask;
		}

		// Check if there is at least 1 empty slot in the group
		if ((empty_match = group_match_empty(group))) {
			*existing = false;
			*previous_ctrl = first_deleted == INVALID_INDEX ? H2_STATUS_EMPTY : H2_STATUS_DELETED;
			return *previous_ctrl == H2_STATUS_EMPTY ? (index + group_lowest_bit(empty_match)) & ht->capacity_mask : first_deleted;
		}
#else
		INDEX_TYPE first_empty = INVALID_INDEX;

		for (INDEX_TYPE i = index; i < index + GROUP_WIDTH; i++) {
			INDEX_TYPE normalized_i = i & ht->capacity_mask;

			if (H2_IS_EMPTY(ht->ctrl[i])) {
				if (first_empty == INVALID_INDEX) {
					first_empty = normalized_i;
				}
				continue;
			}

			// If we visit a deleted slot, save it's index for potential later use
			if (H2_IS_DELETED(ht->ctrl[i])) {
				if (first_deleted == INVALID_INDEX) {
					first_deleted = normalized_i;
				}
				continue;
			}

			if (ht->ctrl[i] == hash_fragment && is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, normalized_i))) {
				*existing = true;
				*previous_ctrl = 0; // not empty; we don't need the value
				return normalized_i;
			}
		}

		if (first_empty != INVALID_INDEX) {
			*existing = false;
			*previous_ctrl = first_deleted == INVALID_INDEX ? H2_STATUS_EMPTY : H2_STATUS_DELETED;
			return *previous_ctrl == H2_STATUS_EMPTY ? first_empty : first_deleted;
		}
#endif

		// Warn if we reach past the probing sequence (unexpected since we shouldn't get above load factor > 85.4%)
		if (probe_step >= ht->capacity) {
			rz_warn_if_reached();
			*existing = false;
			return INVALID_INDEX;
		}

		// Triangular probing
		index = (index + probe_step) & ht->capacity_mask;
		probe_step += GROUP_WIDTH;
	}
}

/**
 * \brief Looks up a \p key and returns it's slot index.
 */
static INDEX_TYPE ctrl_table_lookup(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len) {
	ut32 probe_step = GROUP_WIDTH;
	ut32 hash = hashfn(ht, key, key_len);
	ut8 hash_fragment = H2_HASH_FRAGMENT(hash);
	INDEX_TYPE index = H1(hash) & ht->capacity_mask;

	RZ_PREFETCH(HT_SLOT_AT(ht, index));

	while (true) {
		// Probe one group at a time
#if defined(LOOKUP_METHOD_SSE2) || defined(LOOKUP_METHOD_BITWISE_64)
		group_t group = group_load(&ht->ctrl[index]);

		// Match all group control bytes with the H2 (hash fragment) of `key`
		for (group_mask_t ctrl_match = group_match_hash_fragment(group, hash_fragment); ctrl_match != 0; ctrl_match &= ctrl_match - 1) {
			INDEX_TYPE i = (index + group_lowest_bit(ctrl_match)) & ht->capacity_mask;

			if (is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, i))) {
				return i;
			}
		}

		// Check if there is at least 1 empty slot in the group
		if (group_match_empty(group)) {
			return INVALID_INDEX;
		}
#else
		bool empty_found = false;

		for (ut32 i = index; i < index + GROUP_WIDTH; i++) {
			INDEX_TYPE normalized_i = i & ht->capacity_mask;

			if (H2_IS_EMPTY(ht->ctrl[i])) {
				empty_found = true;
				continue;
			}

			if (ht->ctrl[i] == hash_fragment && is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, normalized_i))) {
				return normalized_i;
			}
		}

		if (empty_found) {
			return INVALID_INDEX;
		}
#endif

		// Warn if we reach past the probing sequence (unexpected)
		if (probe_step >= ht->capacity) {
			rz_warn_if_reached();
			return INVALID_INDEX;
		}

		// Triangular probing
		index = (index + probe_step) & ht->capacity_mask;
		probe_step += GROUP_WIDTH;
	}
}

/**
 * \brief Get an existing KV with key \p key or allocate a new KV otherwise.
 */
static RZ_BORROW HT_(Kv) *reserve_kv(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, bool update, RZ_NONNULL HtRetCode *code) {
	if (!internal_ht_rehash_if_needed(ht)) {
		*code = HT_RC_ERROR;
		return NULL;
	}

	ut32 hash = hashfn(ht, key, key_len);
	ut8 hash_fragment = H2_HASH_FRAGMENT(hash);
	ut8 previous_ctrl = 0;
	bool existing = false;
	INDEX_TYPE idx = ctrl_table_lookup_or_reserve(ht, key, key_len, hash, hash_fragment, &previous_ctrl, &existing);

	if (idx == INVALID_INDEX) {
		*code = HT_RC_ERROR;
		return NULL;
	}

	RZ_PREFETCH(HT_SLOT_AT(ht, idx));

	if (existing) {
		if (update) {
			fini_kv_pair(ht, HT_SLOT_AT(ht, idx));
			*code = HT_RC_UPDATED;
		} else {
			*code = HT_RC_EXISTING;
		}
		return HT_SLOT_AT(ht, idx);
	}

	// Writing over an empty or a deleted slot
	*code = HT_RC_INSERTED;

	// Decrease `growth_left` if writing over an empty slot
	if (previous_ctrl == H2_STATUS_EMPTY) {
		ht->growth_left--;
	}

	ht->size++;
	ctrl_table_set(ht, idx, hash_fragment);
	return HT_SLOT_AT(ht, idx);
}

//

static inline HtRetCode internal_insert_kv_ex(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv) {
	rz_return_val_if_fail(ht && kv, HT_RC_ERROR);

	HtRetCode rc;
	HT_(Kv) *kv_dst = reserve_kv(ht, kv->key, kv_key_len(kv), update, &rc);

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

/**
 * \brief Insert KV \p kv into hash table \p ht or replace an existing KV with \p kv,
 *        if hash table \p ht already contains a KV with the same key as \p kv
 * \param ht Hash table
 * \param kv KV; shallow copy is made when writing to the hash table
 * \param update Update flag; if set to true, replacement of existing KV is allowed
 * \return Returns true if insertion/replacement took place
 */
RZ_API bool Ht_(insert_kv)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update) {
	return internal_insert_kv_ex(ht, kv, update, NULL) > 0;
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
	return internal_insert_kv_ex(ht, kv, update, NULL);
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
	kv_dst->value = dupval(ht, value);

#ifdef VARIABLE_KEY_LEN
	kv_dst->key_len = key_len;
#endif
#ifdef VARIABLE_VALUE_LEN
	kv_dst->value_len = calcsize_val(ht, value);
#endif

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
 * \brief This function decides if a slot should be marked as "empty" or "deleted" based on a heuristic.
 *
 * If the distance between the previous and following empty slots is < GROUP_WIDTH it is safe to mark the slot
 * as "empty", otherwise we need to mark it as "deleted" (see references above for the difference between these two markers).
 */
static ut8 select_slot_type_for_deletion(RZ_NONNULL HtName_(Ht) *ht, INDEX_TYPE idx) {
	// Decide if we should mark the slot as empty or deleted
	INDEX_TYPE nearest_empty_before = 0;
	INDEX_TYPE nearest_empty_after = 0;

	// Check up to `GROUP_WIDTH` preceeding control bytes
	for (INDEX_TYPE i = 0; i < GROUP_WIDTH; i++) {
		if (ht->ctrl[(idx - i - 1) & ht->capacity_mask] == H2_STATUS_EMPTY) {
			break;
		}
		nearest_empty_before++;
	}

	// Check up to `GROUP_WIDTH` following control bytes
	for (INDEX_TYPE i = 0; i < GROUP_WIDTH; i++) {
		if (ht->ctrl[(idx + i) & ht->capacity_mask] == H2_STATUS_EMPTY) {
			break;
		}
		nearest_empty_after++;
	}

	return nearest_empty_before + nearest_empty_after < GROUP_WIDTH ? H2_STATUS_EMPTY : H2_STATUS_DELETED;
}

static bool internal_ht_delete(RZ_NONNULL HtName_(Ht) *ht, INDEX_TYPE idx) {
	ut8 ctrl = select_slot_type_for_deletion(ht, idx);

	ht->size--;
	ht->growth_left += ctrl == H2_STATUS_EMPTY ? 1 : 0;

	ctrl_table_set(ht, idx, ctrl);
	fini_kv_pair(ht, HT_SLOT_AT(ht, idx));
	return true;
}

/**
 * \brief Update the key of an element that has \p old_key as key and replace it with \p new_key
 * \param ht The hash table.
 * \param old_key The key to update.
 * \param new_key The new key.
 * \return true if \p old_key was found and update, false otherwise.
 */
RZ_API bool Ht_(update_key)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE old_key, const KEY_TYPE new_key) {
	rz_return_val_if_fail(ht, false);
	INDEX_TYPE idx;
	ut32 old_key_size = calcsize_key(ht, old_key);

	// First look for the value associated with old_key
	if ((idx = ctrl_table_lookup(ht, old_key, old_key_size)) == INVALID_INDEX) {
		return false;
	}

	// Associate the new key with the existing value
	if (insert_update(ht, new_key, HT_SLOT_AT(ht, idx)->value, false, NULL) <= 0) {
		return false;
	}

	// Second lookup of the element associated with `old_key`, since the previous index could be invalidated by a resize
	if ((idx = ctrl_table_lookup(ht, old_key, old_key_size)) == INVALID_INDEX) {
		return false;
	}

	// Do not free the value part if dupvalue is not set, because the old value will be
	// associated with the new key and it should not be freed
	if (!ht->opt.dupvalue) {
		HT_SLOT_AT(ht, idx)->value = HT_NULL_VALUE;
#ifdef VARIABLE_VALUE_LEN
		HT_SLOT_AT(ht, idx)->value_len = 0;
#endif
	}

	return internal_ht_delete(ht, idx);
}

static inline RZ_BORROW HT_(Kv) *internal_find_kv(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
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

	return HT_SLOT_AT(ht, idx);
}

/**
 * \brief Returns the corresponding KV entry from \p key.
 * \param ht The hash table.
 * \param key The key to look up.
 * \param[out] found Pointer to a bool, that would receive a value indicating if the key was found or not (optional).
 * \return If the key is found, the function will return a pointer to its KV entry, or `NULL` otherwise.
 * If \p found is not NULL, it will be set to true if the entry was found, false otherwise.
 */
RZ_API RZ_BORROW HT_(Kv) *Ht_(find_kv)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	rz_return_val_if_fail(ht, NULL);
	return internal_find_kv(ht, key, found);
}

/**
 * \brief Looks up the corresponding value from \p key.
 *
 * If \p found is not NULL, it will be set to true if the entry was found, false otherwise.
 *
 * \param ht The hash table.
 * \param key The key to look up.
 * \param[out] found Pointer to a bool, that would receive a value indicating if the key was found or not (optional).
 * \return If the key is found, the function will return the value associated with the key, or `HT_NULL_VALUE` otherwise.
 */
RZ_API VALUE_TYPE Ht_(find)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	rz_return_val_if_fail(ht, HT_NULL_VALUE);
	HT_(Kv) *res = internal_find_kv(ht, key, found);
	return res ? res->value : HT_NULL_VALUE;
}

/**
 * \brief Deletes an entry from the hash table \p ht with key \p key, if the pair exists.
 * \param ht The hash table.
 * \param key The key to delete.
 * \return true on success, false otherwise.
 */
RZ_API bool Ht_(delete)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key) {
	rz_return_val_if_fail(ht, false);
	INDEX_TYPE idx = ctrl_table_lookup(ht, key, calcsize_key(ht, key));

	if (idx == INVALID_INDEX) {
		return false;
	}

	return internal_ht_delete(ht, idx);
}

/**
 * \brief Apply \p cb for each KV pair in \p ht. If \p cb returns false, the iteration is stopped.
 * \param ht The hash table.
 * \param cb The callback function to invoke.
 * \param user Pointer to user data (passed through to the callback).
 */
RZ_API void Ht_(foreach)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(ForeachCallback) cb, RZ_NULLABLE void *user) {
	rz_return_if_fail(ht && cb);

	// Iterate all slots
	HT_FOREACH(ht, kv, {
		if (!cb(user, kv->key, kv->value)) {
			return;
		}
	});
}

/**
 * \brief Iterates all elements inside \p ht and invokes the callback function \p cb for each element.
 *
 * This function is similar to `Ht_(foreach)`, but the key/value are passed as pointer rather than by value.
 *
 * \param ht The hash table.
 * \param cb The callback function to invoke (returning `false` will cancel further iteration).
 * \param user Pointer to user data (passed through to the callback).
 * \return true if all elements were iterated, false if the iteration was cancelled by the user callback
 */
RZ_API bool Ht_(foreach_kv)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(ForeachKvCallback) cb, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(ht && cb, false);

	// Iterate all slots
	HT_FOREACH(ht, kv, {
		if (!cb(user, kv)) {
			return false;
		}
	});
	return true;
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
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) {
			continue;
		}
		state->kv = HT_SLOT_AT(state->ht, state->ti);
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
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) {
			continue;
		}
		state->kv = HT_SLOT_AT(state->ht, state->ti);
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
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) {
			continue;
		}
		state->kv = HT_SLOT_AT(state->ht, state->ti);
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
	if (!iter) {
		Ht_(free_iter_mut_state)(state);
	}
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
	if (!iter) {
		Ht_(free_iter_state)(state);
	}
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
	if (!iter) {
		Ht_(free_iter_state)(state);
	}
	return iter;
}
