// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-FileCopyrightText: 2026 Anton Angelov <anton.angelov@protonmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_util/rz_iterator.h>

#ifndef HT_TYPE
#error HT_TYPE should be defined before including this header
#endif

#undef HtName_
#undef Ht_
#undef HT_
#undef KEY_TYPE
#undef VALUE_TYPE
#undef KEY_TO_HASH
#undef HT_NULL_VALUE
#undef VARIABLE_KEY_LEN
#undef VARIABLE_VALUE_LEN

#if HT_TYPE == 1
// Hash table HtPP that has void* as key and void* as value
#define HtName_(name)              name##PP
#define Ht_(name)                  ht_pp_##name
#define HT_(name)                  HtPP##name
#define KEY_TYPE                   void *
#define VALUE_TYPE                 void *
#define KEY_TO_HASH(key, key_size) (ht_default_hash_ut64((uintptr_t)(key)))
#define HT_NULL_VALUE              NULL
#define VARIABLE_KEY_LEN
#define VARIABLE_VALUE_LEN
#elif HT_TYPE == 2
// Hash table HtUP that has void* as key and ut64 as value
#define HtName_(name)              name##UP
#define Ht_(name)                  ht_up_##name
#define HT_(name)                  HtUP##name
#define KEY_TYPE                   ut64
#define VALUE_TYPE                 void *
#define KEY_TO_HASH(key, key_size) (ht_default_hash_ut64((ut64)(key)))
#define HT_NULL_VALUE              0
#define VARIABLE_VALUE_LEN
#elif HT_TYPE == 3
// Hash table HtUU that has ut64 as key and ut64 as value
#define HtName_(name)              name##UU
#define Ht_(name)                  ht_uu_##name
#define HT_(name)                  HtUU##name
#define KEY_TYPE                   ut64
#define VALUE_TYPE                 ut64
#define KEY_TO_HASH(key, key_size) (ht_default_hash_ut64((ut64)(key)))
#define HT_NULL_VALUE              0
#elif HT_TYPE == 4
// Hash table HtPU that has void* as key and ut64 as value
#define HtName_(name)              name##PU
#define Ht_(name)                  ht_pu_##name
#define HT_(name)                  HtPU##name
#define KEY_TYPE                   void *
#define VALUE_TYPE                 ut64
#define KEY_TO_HASH(key, key_size) (ht_default_hash_ut64((uintptr_t)(key)))
#define HT_NULL_VALUE              0
#define VARIABLE_KEY_LEN
#elif HT_TYPE == 5
// Hash table HtSP that has C-string as key and void* as value
#define HtName_(name)              name##SP
#define Ht_(name)                  ht_sp_##name
#define HT_(name)                  HtSP##name
#define KEY_TYPE                   char *
#define VALUE_TYPE                 void *
#define KEY_TO_HASH(key, key_size) (ht_default_hash_string(key, key_size))
#define HT_NULL_VALUE              NULL
#define VARIABLE_KEY_LEN
#define VARIABLE_VALUE_LEN
#elif HT_TYPE == 6
// Hash table HtSS that has C-string as key and C-string as value
#define HtName_(name)              name##SS
#define Ht_(name)                  ht_ss_##name
#define HT_(name)                  HtSS##name
#define KEY_TYPE                   char *
#define VALUE_TYPE                 char *
#define KEY_TO_HASH(key, key_size) (ht_default_hash_string(key, key_size))
#define HT_NULL_VALUE              NULL
#define VARIABLE_KEY_LEN
#define VARIABLE_VALUE_LEN
#elif HT_TYPE == 7
// Hash table HtSU that has C-string as key and ut64 as value
#define HtName_(name)              name##SU
#define Ht_(name)                  ht_su_##name
#define HT_(name)                  HtSU##name
#define KEY_TYPE                   char *
#define VALUE_TYPE                 ut64
#define KEY_TO_HASH(key, key_size) (ht_default_hash_string(key, key_size))
#define HT_NULL_VALUE              0
#define VARIABLE_KEY_LEN
#endif

// Uncomment to enable support for custom element size (opt.elem_size != sizeof(VALUE_TYPE)). This could
// slow down lookup/insert/iteration with about 5-10%.
// #ifndef HT_ENABLE_CUSTOM_ELEM_SIZE
// #define HT_ENABLE_CUSTOM_ELEM_SIZE
// #endif

#ifndef HT_HASH_FUNCTIONS
#define HT_HASH_FUNCTIONS

/**
 * \brief A Murmur3-like hash function which reduces a 64-bit key to a 32-bit non-cryptographic hash.
 *
 * It's simpler than MurmurHash3 which makes it run faster at the cost of slightly worse hash distribution.
 * This hash function is used for HtPX and HtUX, if no custom hash function is specified.
 */
static inline ut32 ht_default_hash_ut64(ut64 key) {
	key ^= key >> 33;
	key *= 0xff51afd7ed558ccdULL;
	key ^= key >> 33;
	return (uint32_t)(key ^ (key >> 32));
}

/**
 * \brief Computes 32-bit hash for a byte buffer (string).
 *
 * The function uses Murmur3 mixing constants and tries to process the buffer in 16, 8 or 4-byte blocks when possible.
 * This hash function is used for HtSX, if no custom hash function is specified.
 */
static inline ut32 ht_default_hash_string(const char *key, ut32 len) {
	const uint64_t prime1 = 0xff51afd7ed558ccdULL; /* Murmur3 consts */
	const uint64_t prime2 = 0xc4ceb9fe1a85ec53ULL;
	ut64 result = 0xff51afd7ed558ccdULL;

	while (len >= 16) {
		ut128 block = rz_read_le128(key);
		result += (result << 5) ^ (block.Low * prime1);
		result += (result << 5) ^ (block.High * prime1);
		len -= 16;
		key += 16;
	}

	while (len >= 8) {
		ut64 block = rz_read_le64(key);
		result += (result << 5) ^ (block * prime1);
		len -= 8;
		key += 8;
	}

	while (len >= 4) {
		ut32 block = rz_read_le32(key);
		result += (result << 5) ^ (block * prime1);
		len -= 4;
		key += 4;
	}

	while (len > 0) {
		result += (result << 5) ^ (*key * prime1);
		len -= 1;
		key += 1;
	}

	// Finalize
	result ^= result >> 33;
	result *= prime2;

	// Fold the result
	return (ut32)(result ^ (result >> 32));
}
#endif

#ifndef HT_ENUM_DEFINED
#define HT_ENUM_DEFINED
/**
 * Return codes for insert/update methods
 * code < 0 <--> code == HT_RC_ERROR
 * code >= 0 <--> code != HT_RC_ERROR
 * code > 0 <--> code == HT_RC_INSERTED || code == HT_RC_UPDATED
 */
typedef enum {
	HT_RC_ERROR = -1, ///< Error (out of memory)
	HT_RC_EXISTING = 0, ///< Existing KV prevented an insertion
	HT_RC_INSERTED = 1, ///< New KV was inserted during insert/update operation
	HT_RC_UPDATED = 2, ///< Existing KV was updated during update operation
} HtRetCode;

typedef enum {
	HT_STR_DUP = 0, ///< String is copied when inserting into HT
	HT_STR_OWN, ///< String ownership is transferred when inserting into HT
	HT_STR_CONST ///< String is treated as constant and not copied when inserting into HT
} HtStrOption;
#endif

#include <rz_types.h>

/**
 * \brief Kv represents a single key/value element in the hashtable
 */
typedef struct Ht_(kv) {
	KEY_TYPE key;
	VALUE_TYPE value;
#ifdef VARIABLE_KEY_LEN
	ut32 key_len; ///< Size of the key. Used only for pointer or string keys.
#endif
#ifdef VARIABLE_VALUE_LEN
	ut32 value_len; ///< Size of the value. Used only for pointer or string values.
#endif
} HT_(Kv);

typedef void (*HT_(FiniKv))(HT_(Kv) *kv, void *user);
typedef KEY_TYPE (*HT_(DupKey))(const KEY_TYPE);
typedef VALUE_TYPE (*HT_(DupValue))(const VALUE_TYPE);
typedef void (*HT_(FreeValue))(VALUE_TYPE val);
typedef ut32 (*HT_(CalcSizeK))(const KEY_TYPE);
typedef ut32 (*HT_(CalcSizeV))(const VALUE_TYPE);
typedef ut32 (*HT_(HashFunction))(const KEY_TYPE);
typedef int (*HT_(Comparator))(const KEY_TYPE, const KEY_TYPE);
typedef bool (*HT_(ForeachCallback))(void *user, const KEY_TYPE, const VALUE_TYPE);
typedef bool (*HT_(ForeachKvCallback))(void *user, const HT_(Kv) *kv);

/**
 * Options contain all the settings of the hashtable.
 */
typedef struct Ht_(options_t) {
	size_t elem_size; ///< Size of each HtKv element (useful for subclassing like SdbKv).
			  ///< Zero value means to use default size of HtKv.
	HT_(Comparator) cmp; ///< RZ_NULLABLE. Function for comparing keys.
			     ///< Returns 0 if keys are equal.
	///< Function is invoked only if == operator applied to keys returns false.
	HT_(HashFunction) hashfn; ///< RZ_NULLABLE. Function for hashing items in the hash table.
				  ///< If NULL KEY_TO_HASH macro is used.
	HT_(CalcSizeK) calcsizeK; ///< RZ_NULLABLE. Function to determine the key's size.
				  ///< If NULL zero value is used as a size.
				  ///< Key sizes are checked on equality during keys comparsion as a pre-check.
	HT_(CalcSizeV) calcsizeV; ///< RZ_NULLABLE. Function to determine the value's size.
				  ///< If NULL zero value is used as a size.
				  ///< Not required for common scenarios. Could be used in subclasses.
	HT_(DupKey) dupkey; ///< RZ_NULLABLE. Function for making a copy of key.
			    ///< If NULL simple assignment operator is used.
	HT_(DupValue) dupvalue; ///< RZ_NULLABLE. Function for making a copy of value.
				///< If NULL simple assignment operator is used.
	HT_(FiniKv) finiKV; ///< RZ_NULLABLE. Function to clean up the key-value store.
	void *finiKV_user; ///< RZ_NULLABLE. User data which is passed into finiKV.
} HT_(Options);

/* Ht is the hashtable structure */
typedef struct Ht_(t) {
	ut32 capacity; ///< Capacity of the main array.
	ut32 capacity_mask; ///< Set to `capacity - 1` and used for bucket/index modulo.
	ut32 size; ///< Number of stored elements.
	ut32 growth_left; ///< Number of empty slots.
	RZ_BORROW ut8 *ctrl; ///< Control bytes (metadata) - point to the beginning of the `data` pointer.
	RZ_BORROW HT_(Kv) *slots_; ///< Main array (no buckets) - points to an offset after the `data` pointer.
	HT_(Options) opt; ///< Methods
	ut8 *data; ///< Single allocation for `ctrl` and `slots_` arrays.
} HtName_(Ht);

typedef struct Ht_(iter_mut_t) {
	HtName_(Ht) *ht; ///< The hash table to iterate over.
	ut32 ti; ///< Table index
	HT_(Kv) *kv; ///< Current Key-Value-pair.
} HT_(IterMutState);

typedef struct Ht_(iter_t) {
	const HtName_(Ht) *ht; ///< The hash table to iterate over.
	ut32 ti; ///< Table index
	ut32 bi; ///< Bucket index
	const HT_(Kv) *kv; ///< Current Key-Value-pair.
} HT_(IterState);

// Create a new Ht with the provided Options
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt)(RZ_NONNULL HT_(Options) *opt);
// Create a new Ht with the provided Options and initial size
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt_size)(RZ_NONNULL HT_(Options) *opt, ut32 initial_size);
// Destroy a hashtable and all of its entries.
RZ_API void Ht_(free)(RZ_NULLABLE HtName_(Ht) *ht);
RZ_API void Ht_(clear)(RZ_NONNULL HtName_(Ht) *ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
RZ_API bool Ht_(insert)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value);
RZ_API HtRetCode Ht_(insert_ex)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
RZ_API bool Ht_(update)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value);
RZ_API HtRetCode Ht_(update_ex)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv);
// Update the key of an element in the hashtable
RZ_API bool Ht_(update_key)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE old_key, const KEY_TYPE new_key);
// Delete a key from the hashtable.
RZ_API bool Ht_(delete)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key);
// Find the value corresponding to the matching key.
RZ_API VALUE_TYPE Ht_(find)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found);
// Iterates over all elements in the hashtable, calling the cb function on each Kv.
// If the cb returns false, the iteration is stopped.
// cb should not modify the hashtable.
// NOTE: cb can delete the current element, but it should be avoided
RZ_API void Ht_(foreach)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(ForeachCallback) cb, RZ_NULLABLE void *user);
RZ_API bool Ht_(foreach_kv)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(ForeachKvCallback) cb, RZ_NULLABLE void *user);

RZ_API ut32 Ht_(size)(const RZ_NONNULL HtName_(Ht) *ht);

RZ_API RZ_BORROW HT_(Kv) *Ht_(find_kv)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found);
RZ_API bool Ht_(insert_kv)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update);
RZ_API HtRetCode Ht_(insert_kv_ex)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update, RZ_OUT RZ_NULLABLE HT_(Kv) **out_kv);

RZ_API RZ_OWN HT_(IterMutState) *Ht_(new_iter_mut_state)(RZ_NONNULL HtName_(Ht) *ht);
RZ_API RZ_OWN HT_(IterState) *Ht_(new_iter_state)(const RZ_NONNULL HtName_(Ht) *ht);
RZ_API void Ht_(free_iter_mut_state)(RZ_NULLABLE HT_(IterMutState) *state);
RZ_API void Ht_(free_iter_state)(RZ_NULLABLE HT_(IterState) *state);

RZ_API RZ_BORROW VALUE_TYPE *Ht_(iter_next_mut)(RzIterator *it);
RZ_API const VALUE_TYPE *Ht_(iter_next)(RzIterator *it);
RZ_API const KEY_TYPE *Ht_(iter_next_key)(RzIterator *it);

RZ_API RZ_OWN RzIterator /* <HtName_(Ht)> */ *Ht_(as_iter_mut)(RZ_NONNULL HtName_(Ht) *ht);
RZ_API RZ_OWN RzIterator /* <HtName_(Ht)> */ *Ht_(as_iter)(const RZ_NONNULL HtName_(Ht) *ht);
RZ_API RZ_OWN RzIterator /* <HtName_(Ht)> */ *Ht_(as_iter_keys)(const RZ_NONNULL HtName_(Ht) *ht);
