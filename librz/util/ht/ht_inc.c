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
// #define HASH_MIX(h) (hashfn_quick_mix(h))
// #define HASH_MIX(h) (h)

// #define H1(HASH)                     (HASH >> 7)
// #define H2_HASH_FRAGMENT(HASH)       (HASH & 0x7F)
#define H1(HASH)                     (HASH)
#define H2_HASH_FRAGMENT(HASH)       ((HASH >> 19) & 0x7F)
#define H2_STATUS_DELETED            0b11111110
#define H2_STATUS_EMPTY              0b11111111
#define H2_IS_EMPTY_OR_DELETED(CTRL) ((CTRL) >> 7)
#define H2_IS_EMPTY(CTRL)            ((CTRL) == H2_STATUS_EMPTY)
#define H2_IS_DELETED(CTRL)          ((CTRL) == H2_STATUS_DELETED)
#define INDEX_TYPE                   ut32
#define INVALID_INDEX                UT32_MAX

// todo:
//	- [x] allocate first -> 0 bytes (update: actually MIN_CAPACITY)
// 	- [x] handle realloc / rehash -> capacity should be multiple of x^2-1; new_cap = (old_cap + 1 * 2) - 1 (update: capacity is actually x^2, and bitmask is capacity-1)
// 	- [x] should keep up to 87.5% load factor
// 	- [x] "rehash in place"
//	- [x] clone first group at `ctrl` end
//	- [x] handle ctrl mirroring for sizes < GROUP_WIDTH
//	- the hash function should distribute entroy in both high and low bits to avoid H1 and H2 collisions
//	- support custom element size
//	- support deletion slot trick (use empty slot where possible)
//	- allocate everything in one block
//  - adapt sdb.c

// todo: define likely/unlikely; OR remove it there is no impact
#define RZ_HOT_PATH
#define RZ_COLD_PATH

// todo: move to another header if going to be used
#if defined(_MSC_VER)
    #include <intrin.h>
    #define RZ_PREFETCH(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#elif defined(__GNUC__) || defined(__clang__)
    #define RZ_PREFETCH(addr) __builtin_prefetch((addr), 0, 3)
#else
    #define RZ_PREFETCH(addr) ((void)0)
#endif

#if defined(__SSE2__) || (defined(_MSC_VER) && (defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)))
    #define HAVE_SSE2
#endif

// #define GROUP_WIDTH 8

// TODO: add support for AMD NEON
// TODO: sse
// #if 0
#ifdef HAVE_SSE2
	// SSE2 is present x64/amd64 archs
	#include <emmintrin.h>
	#define LOOKUP_METHOD_SSE2
	#define GROUP_WIDTH  16
	typedef ut16 group_mask_t;
	typedef __m128i group_t;
#elif RZ_SYS_BITS == RZ_SYS_BITS_64
	#define LOOKUP_METHOD_DEFAULT_64
	typedef ut64 group_t;
	typedef ut64 group_mask_t;
	#define GROUP_WIDTH  sizeof(group_t)
#else
	// todo: for 32-bit use default implementation below
	#define LOOKUP_METHOD_DEFAULT_32
	typedef ut32 group_t;
	typedef ut32 group_mask_t;
	#define GROUP_WIDTH  sizeof(group_t)
	// TODO: portable implementation for big-endian
#endif

#define HT_SLOT_AT(ht, index) \
	(&(ht)->slots[(index)])
	// ((HT_(Kv) *)((ut8 *)(ht->slots) + index * ht->opt.elem_size))
	// (&(ht)->slots[(index)])

// Helper macro for implementing an unrolled foreach loop
#define HT_FOREACH_UNROLL(ht, kv, idx, body) \
		if (!H2_IS_EMPTY_OR_DELETED((ht)->ctrl[idx])) { \
			HT_(Kv) *kv = HT_SLOT_AT((ht), (idx)); \
			body \
		}

// Helper function for the different lookup implementations
#if defined(HAVE_SSE2)
	// todo
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

#elif defined(LOOKUP_METHOD_DEFAULT_64) || defined(LOOKUP_METHOD_DEFAULT_32)
// #if defined(LOOKUP_METHOD_DEFAULT_64) || defined(LOOKUP_METHOD_DEFAULT_32)
	// TODO: only little endian
	// Construct a ut64/ut32 by repeating a byte value (e.g. 0xF0 -> 0xF0F0F0F0F0F0F0F0)
	static inline group_t group_repeat(ut8 byte) {
	#if defined(LOOKUP_METHOD_DEFAULT_64)
		return byte * 0x0101010101010101ull;
	#elif defined(LOOKUP_METHOD_DEFAULT_32)
		return byte * 0x01010101ul;
	#else
		#error "Unsupported group width"
	#endif
	}

	// Match a hash fragment byte to 4/8 control bytes
	static inline group_t group_match_hash_fragment(group_t group, ut8 ctrl) {
		group_t diff = group ^ group_repeat(ctrl);
		return (diff - group_repeat(0x01)) & ~diff & group_repeat(0x80);
	}

	static inline group_mask_t group_match_empty(group_t group) {
		return group & (group << 1) & group_repeat(0x80);
	}

	static inline group_mask_t group_match_deleted(group_t group) {
		return group & ~(group << 1) & group_repeat(0x80);
	}

	// static inline group_mask_t group_match_empty_or_deleted(group_t group) {
	// 	return group & group_repeat(0x80);
	// }

	// static inline group_mask_t group_match_full(group_t group) {
	// 	return ~group & group_repeat(0x80);
	// }

	static inline ut8 group_lowest_bit(group_mask_t mask) {
		return mask ? rz_bits_trailing_zeros(mask) / 8 : UT8_MAX; // todo: maybe no need to check for 0
	}

	// #define HT_FOREACH_BEGIN(ht, kv) \
	// 	for (INDEX_TYPE gi = 0; gi < ht->capacity; gi += GROUP_WIDTH) { \
	// 		group_t ctrl_match = group_match_full(*((group_t *)&(ht)->ctrl[gi])); \
	// 		while (ctrl_match) { \
	// 			INDEX_TYPE ofs = group_lowest_bit(ctrl_match); \
	// 			HT_(Kv) *kv = &(ht)->slots[gi + ofs];

	// #define HT_FOREACH_END(ht) \
	// 			ctrl_match &= ~(0x80ULL << (ofs * 8)); \
	// 		} \
	// 	}
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
		for (INDEX_TYPE i = 0, i < (ht)->capacity; i++) { \
			if (!H2_IS_EMPTY_OR_DELETED((ht)->ctrl[i])) { \
				HT_(Kv) *kv = HT_SLOT_AT((ht), i); \
				body \
			} \
		}
#endif

#define MIN_CAPACITY (GROUP_WIDTH)

// static inline ut32 hashfn_quick_mix(ut64 h) {
//     // ut32 x = (h ^ ((h * 0xc2b2ae35) >> 16)) * 0x9e3779b1u;
//     // return x ^ (x >> 15);
// 	return _mm_crc32_u32(0, h);
// }

static inline ut32 hashfn(HtName_(Ht) *ht, const KEY_TYPE k) {
	ut32 result = ht->opt.hashfn ? ht->opt.hashfn(k) : KEY_TO_HASH(k); // todo: keep entropy for hashfn(k)

	if (ht->hash_shift) {
		result ^= result >> 16;
        result *= 0x85ebca6b;
        result ^= result >> ht->hash_shift;
        if (ht->hash_shift == 13) {
            result *= 0xc2b2ae35;
        }
	}

	return result;
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
	ht->opt = *opt;

	// If not provided, assume we are dealing with a regular HtName_(Ht), with HT_(Kv) as elements
	if (ht->opt.elem_size == 0) {
		ht->opt.elem_size = sizeof(HT_(Kv));
	}

	// Allocate additional space for the mirrored bytes at the end of the control array
	ut32 ctrl_size = (ht->capacity + GROUP_WIDTH) * sizeof(*ht->ctrl);
	ut32 slots_size = ht->capacity * ht->opt.elem_size; // todo: use elem_size

	// Allocate single heap block for both control and slot arrays
	if ((ht->data = calloc(ctrl_size + slots_size, sizeof(ut8))) == NULL) { // todo: use malloc
		return NULL;
	}

	ht->ctrl = ht->data;
	ht->slots = (HT_(Kv) *)(ht->data + ctrl_size);

	// Initialize all slots as empty
	memset(ht->ctrl, H2_STATUS_EMPTY, ctrl_size);

	if (ht->capacity < 8192) {
		// For smaller hashtables we do additional bit mixing
		ht->hash_shift = ht->capacity >= 512 ? 16 : 13;
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
		HT_FOREACH(ht, kv, {
			ht->opt.finiKV(kv, ht->opt.finiKV_user);
		});
		// for (INDEX_TYPE i = 0; i < ht->capacity; i++) {
		// 	if (H2_IS_EMPTY_OR_DELETED(ht->ctrl[i])) { // todo: process all elements in group
		// 		continue;
		// 	}
		// 	ht->opt.finiKV(&ht->slots[i], ht->opt.finiKV_user);
		// }
	}

	free(ht->data);
	free(ht);
}

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
	// for (ut32 i = 0; i < ht->capacity; i++) {
	// 	if (H2_IS_EMPTY_OR_DELETED(ht->ctrl[i])) {
	// 		continue;
	// 	}

	// 	if (Ht_(insert_kv_ex)(ht2, &ht->slots[i], false, NULL) < 0) {
	// 		ht2->opt.finiKV = NULL;
	// 		Ht_(free)(ht2);
	// 		return false;
	// 	}
	// }
	HT_FOREACH(ht, kv, {
		// if (Ht_(insert_kv_ex)(ht2, &ht->slots[i], false, NULL) < 0) {
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
static INDEX_TYPE ctrl_table_lookup_or_reserve(HtName_(Ht) *ht, const KEY_TYPE key, const ut32 key_len, ut32 hash, ut8 hash_fragment, bool *existing) {
	ut32 probe_step = GROUP_WIDTH;
	INDEX_TYPE index = H1(hash) & (ht->capacity - 1); // todo: rename to group_index_start, etc
	INDEX_TYPE first_deleted = INVALID_INDEX;

	while (true) {
		// Probe one group at a time
// #if 0
#ifdef LOOKUP_METHOD_SSE2
		group_t group;
		group_mask_t deleted_match;
		group_mask_t empty_match;

		// todo
		group = _mm_loadu_si128((const __m128i *)(&ht->ctrl[index]));

		// Match all control group bytes with the hash fragment of `key`
		for (group_mask_t ctrl_match = group_match_hash_fragment(group, hash_fragment); ctrl_match != 0; ctrl_match &= ctrl_match - 1) {
			INDEX_TYPE i = (index + group_lowest_bit(ctrl_match)) & (ht->capacity - 1);

			if (is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, i))) {
				*existing = true;
				return i;
			}
		}

		// If we reach a "deleted" slot, save it's index and return later
		if (first_deleted == INVALID_INDEX && (deleted_match = group_match_deleted(group))) {
			first_deleted = (index + group_lowest_bit(deleted_match)) & (ht->capacity - 1);
		}

		// Check if there is at least 1 empty slot in the group
		if ((empty_match = group_match_empty(group))) {
			*existing = false;
			return first_deleted == INVALID_INDEX ? (index + group_lowest_bit(empty_match)) & (ht->capacity - 1) : first_deleted;
		}

// #ifdef LOOKUP_METHOD_DEFAULT_64
#elif defined(LOOKUP_METHOD_DEFAULT_64)
		group_t group;
		group_t deleted_match;
		group_t empty_match;

		// Copy control group to a local variable, since the array offset has no alignment guarantees
		memcpy(&group, &ht->ctrl[index], sizeof(group)); // todo: read_le64

		// Match all control group bytes with the hash fragment of `key`
		for (group_mask_t ctrl_match = group_match_hash_fragment(group, hash_fragment); ctrl_match != 0; ctrl_match &= ctrl_match - 1) {
			INDEX_TYPE i = (index + group_lowest_bit(ctrl_match)) & (ht->capacity - 1);

			if (is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, i))) {
				*existing = true;
				return i;
			}
		}

		// If we reach a "deleted" slot, save it's index and return later
		if (first_deleted == INVALID_INDEX && (deleted_match = group_match_deleted(group))) {
			first_deleted = (index + group_lowest_bit(deleted_match)) & (ht->capacity - 1);
		}

		// Check if there is at least 1 empty slot in the group
		if ((empty_match = group_match_empty(group))) {
			*existing = false;
			return first_deleted == INVALID_INDEX ? (index + group_lowest_bit(empty_match)) & (ht->capacity - 1) : first_deleted;
		}
#else
		for (INDEX_TYPE i = index; i < index + GROUP_WIDTH; i++) {
			INDEX_TYPE normalized_i = i & (ht->capacity - 1);
			ut8 *ctrl = &ht->ctrl[i];

			if (H2_IS_EMPTY(*ctrl)) {
				*existing = false;
				return first_deleted == INVALID_INDEX ? normalized_i : first_deleted;
			}

			if (H2_HASH_FRAGMENT(*ctrl) == H2_HASH_FRAGMENT(hash) && RZ_HOT_PATH(is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, normalized_i)))) {
				*existing = true;
				return normalized_i;
			}

			// If we visit a deleted slot, save it's index for potential later use
			if (H2_IS_DELETED(*ctrl) && first_deleted == INVALID_INDEX) {
				first_deleted = normalized_i;
			}
		}
#endif

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
	ut8 hash_fragment = H2_HASH_FRAGMENT(hash);
	ut32 probe_step = GROUP_WIDTH;
	INDEX_TYPE index = H1(hash) & (ht->capacity - 1);

	while (true) {
		// Probe one group at a time
#ifdef LOOKUP_METHOD_SSE2
		// todo
		__m128i group = _mm_loadu_si128((const __m128i *)(&ht->ctrl[index]));

		// Match all group control bytes with the hash fragment of `key`
		for (group_mask_t ctrl_match = group_match_hash_fragment(group, hash_fragment); ctrl_match != 0; ctrl_match &= ctrl_match - 1) {
			INDEX_TYPE i = (index + group_lowest_bit(ctrl_match)) & (ht->capacity - 1);

			if (is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, i))) {
				return i;
			}
		}

		// Check if there is at least 1 empty slot in the group
		if (group_match_empty(group)) {
			return INVALID_INDEX;
		}

#elif defined(LOOKUP_METHOD_DEFAULT_64) || defined(LOOKUP_METHOD_DEFAULT_32)
// #if defined(LOOKUP_METHOD_DEFAULT_64) | defined(LOOKUP_METHOD_DEFAULT_32)
		group_t group;

		// Copy control group to a local variable, since the array offset has no alignment guarantees
		memcpy(&group, &ht->ctrl[index], sizeof(group));

		// Match all group control bytes with the hash fragment of `key`
		for (group_t ctrl_match = group_match_hash_fragment(group, hash_fragment); ctrl_match != 0; ctrl_match &= ctrl_match - 1) {
			INDEX_TYPE i = (index + group_lowest_bit(ctrl_match)) & (ht->capacity - 1);
			// todo: test if index is correct (combined with `ctrl_match &= ctrl_match - 1`)

			if (is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, i))) {
				return i;
			}
		}

		// Check if there is at least 1 empty slot in the group
		if (group_match_empty(group)) {
			return INVALID_INDEX;
		}
#else
		for (ut32 i = index; i < index + GROUP_WIDTH; i++) {
			INDEX_TYPE normalized_i = i & (ht->capacity - 1);
			ut8 *ctrl = &ht->ctrl[i];

			if (H2_IS_EMPTY(*ctrl)) {
				return INVALID_INDEX;
			}

			if (H2_HASH_FRAGMENT(*ctrl) == hash_fragment && RZ_HOT_PATH(is_key_equal(ht, key, key_len, HT_SLOT_AT(ht, normalized_i)))) {
				return normalized_i;
			}
		}
#endif

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

	ut32 hash = hashfn(ht, key);
	ut8 hash_fragment = H2_HASH_FRAGMENT(hash);
	bool existing = false;
	INDEX_TYPE idx = ctrl_table_lookup_or_reserve(ht, key, key_len, hash, hash_fragment, &existing);

	if (RZ_COLD_PATH(idx == INVALID_INDEX)) {
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

	ht->size++;
	ctrl_table_set(ht, idx, hash_fragment);
	return HT_SLOT_AT(ht, idx);
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
	return Ht_(insert_kv_ex)(ht, kv, update, NULL) > 0; // todo: move to static function
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
	if (insert_update(ht, new_key, HT_SLOT_AT(ht, idx)->value, false, NULL) <= 0) {
		return false;
	}

	// Remove the old_key kv, paying attention to not double free the value
	// TODO: use empty instead of delete where possible...
	ctrl_table_set(ht, idx, H2_STATUS_DELETED);

	// Do not free the value part if dupvalue is not set, because the old value will be
	// associated with the new key and it should not be freed
	if (!ht->opt.dupvalue) {
		HT_SLOT_AT(ht, idx)->value = HT_NULL_VALUE;
		HT_SLOT_AT(ht, idx)->value_len = 0;
	}
	fini_kv_pair(ht, HT_SLOT_AT(ht, idx));

	return true;
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
 * Returns the corresponding Kv entry from \p key.
 * If \p found is not NULL, it will be set to true if the entry was found,
 * false otherwise.
 */
RZ_API RZ_BORROW HT_(Kv) *Ht_(find_kv)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	rz_return_val_if_fail(ht, NULL);
	return internal_find_kv(ht, key, found);
}

/**
 * Looks up the corresponding value from \p key.
 * If \p found is not NULL, it will be set to true if the entry was found,
 * false otherwise.
 */
RZ_API VALUE_TYPE Ht_(find)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found) {
	rz_return_val_if_fail(ht, HT_NULL_VALUE);
	HT_(Kv) *res = internal_find_kv(ht, key, found);
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
	fini_kv_pair(ht, HT_SLOT_AT(ht, idx));

	return true;
}

/**
 * Apply \p cb for each KV pair in \p ht.
 * If \p cb returns false, the iteration is stopped.
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
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) { // todo: process all elements in group(?)
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
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) { // todo: process all elements in group (?)
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
		if (H2_IS_EMPTY_OR_DELETED(state->ht->ctrl[state->ti])) { // todo: process all elements in group (?)
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