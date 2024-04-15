// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

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

#if HT_TYPE == 1
#define HtName_(name)  name##PP
#define Ht_(name)      ht_pp_##name
#define HT_(name)      HtPP##name
#define KEY_TYPE       void *
#define VALUE_TYPE     void *
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE  NULL
#elif HT_TYPE == 2
#define HtName_(name)  name##UP
#define Ht_(name)      ht_up_##name
#define HT_(name)      HtUP##name
#define KEY_TYPE       ut64
#define VALUE_TYPE     void *
#define KEY_TO_HASH(x) ((ut32)(x))
#define HT_NULL_VALUE  0
#elif HT_TYPE == 3
#define HtName_(name)  name##UU
#define Ht_(name)      ht_uu_##name
#define HT_(name)      HtUU##name
#define KEY_TYPE       ut64
#define VALUE_TYPE     ut64
#define KEY_TO_HASH(x) ((ut32)(x))
#define HT_NULL_VALUE  0
#elif HT_TYPE == 4
#define HtName_(name)  name##PU
#define Ht_(name)      ht_pu_##name
#define HT_(name)      HtPU##name
#define KEY_TYPE       void *
#define VALUE_TYPE     ut64
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE  0
#elif HT_TYPE == 5
#define HtName_(name)  name##SP
#define Ht_(name)      ht_sp_##name
#define HT_(name)      HtSP##name
#define KEY_TYPE       char *
#define VALUE_TYPE     void *
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE  NULL
#elif HT_TYPE == 6
#define HtName_(name)  name##SS
#define Ht_(name)      ht_ss_##name
#define HT_(name)      HtSS##name
#define KEY_TYPE       char *
#define VALUE_TYPE     char *
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE  NULL
#elif HT_TYPE == 7
#define HtName_(name)  name##SU
#define Ht_(name)      ht_su_##name
#define HT_(name)      HtSU##name
#define KEY_TYPE       char *
#define VALUE_TYPE     ut64
#define KEY_TO_HASH(x) ((ut32)(uintptr_t)(x))
#define HT_NULL_VALUE  0
#endif

#ifndef HT_STR_OPTION_DEFINED
#define HT_STR_OPTION_DEFINED
typedef enum {
	HT_STR_DUP = 0, ///< String is copied when inserting into HT
	HT_STR_OWN, ///< String ownership is transferred when inserting into HT
	HT_STR_CONST ///< String is treated as constant and not copied when inserting into HT
} HtStrOption;
#endif

#include "ls.h"
#include <rz_types.h>

/* Kv represents a single key/value element in the hashtable */
typedef struct Ht_(kv) {
	KEY_TYPE key;
	VALUE_TYPE value;
	ut32 key_len;
	ut32 value_len;
}
HT_(Kv);

typedef void (*HT_(FiniKv))(HT_(Kv) *kv, void *user);
typedef KEY_TYPE (*HT_(DupKey))(const KEY_TYPE);
typedef VALUE_TYPE (*HT_(DupValue))(const VALUE_TYPE);
typedef void (*HT_(FreeValue))(VALUE_TYPE val);
typedef ut32 (*HT_(CalcSizeK))(const KEY_TYPE);
typedef ut32 (*HT_(CalcSizeV))(const VALUE_TYPE);
typedef ut32 (*HT_(HashFunction))(const KEY_TYPE);
typedef int (*HT_(ListComparator))(const KEY_TYPE, const KEY_TYPE);
typedef bool (*HT_(ForeachCallback))(void *user, const KEY_TYPE, const VALUE_TYPE);

typedef struct Ht_(bucket_t) {
	HT_(Kv) *arr;
	ut32 count;
}
HT_(Bucket);

/**
 * Options contain all the settings of the hashtable.
 */
typedef struct Ht_(options_t) {
	HT_(ListComparator) cmp; ///< RZ_NULLABLE. Function for comparing keys.
				 ///< Returns 0 if keys are equal.
	///< Function is invoked only if == operator applied to keys returns false.
	HT_(HashFunction) hashfn; ///< RZ_NULLABLE. Function for hashing items in the hash table.
				  ///< If NULL KEY_TO_HASH macro is used.
	HT_(DupKey) dupkey; ///< RZ_NULLABLE. Function for making a copy of key.
			    ///< If NULL simple assignment operator is used.
	HT_(DupValue) dupvalue; ///< RZ_NULLABLE. Function for making a copy of value.
				///< If NULL simple assignment operator is used.
	HT_(CalcSizeK) calcsizeK; ///< RZ_NULLABLE. Function to determine the key's size.
				  ///< If NULL zero value is used as a size.
				  ///< Key sizes are checked on equality during keys comparsion as a pre-check.
	HT_(CalcSizeV) calcsizeV; ///< RZ_NULLABLE. Function to determine the value's size.
				  ///< If NULL zero value is used as a size.
				  ///< Not required for common scenarios. Could be used in subclasses.
	HT_(FiniKv) finiKV; ///< RZ_NULLABLE. Function to clean up the key-value store.
	void *finiKV_user; ///< RZ_NULLABLE. User data which is passed into finiKV.
	size_t elem_size; ///< Size of each HtKv element (useful for subclassing like SdbKv).
			  ///< Zero value means to use default size of HtKv.
}
HT_(Options);

/* Ht is the hashtable structure */
typedef struct Ht_(t) {
	ut32 size; ///< Size of the hash table in buckets.
	ut32 count; ///< Number of stored elements.
	HT_(Bucket) *table; ///< Actual table.
	ut32 prime_idx;
	HT_(Options) opt;
}
HtName_(Ht);

// Create a new Ht with the provided Options
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt)(RZ_NONNULL HT_(Options) *opt);
// Create a new Ht with the provided Options and initial size
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_opt_size)(RZ_NONNULL HT_(Options) *opt, ut32 initial_size);
// Destroy a hashtable and all of its entries.
RZ_API void Ht_(free)(RZ_NULLABLE HtName_(Ht) *ht);
// Insert a new Key-Value pair into the hashtable. If the key already exists, returns false.
RZ_API bool Ht_(insert)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value);
// Insert a new Key-Value pair into the hashtable, or updates the value if the key already exists.
RZ_API bool Ht_(update)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, VALUE_TYPE value);
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

RZ_API RZ_BORROW HT_(Kv) *Ht_(find_kv)(RZ_NONNULL HtName_(Ht) *ht, const KEY_TYPE key, RZ_NULLABLE bool *found);
RZ_API bool Ht_(insert_kv)(RZ_NONNULL HtName_(Ht) *ht, RZ_NONNULL HT_(Kv) *kv, bool update);
