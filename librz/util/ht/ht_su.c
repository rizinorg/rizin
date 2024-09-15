// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#include "sdb.h"
#include <rz_util/ht_su.h>
#include "ht_inc.c"

static void fini_kv_key(HT_(Kv) *kv, RZ_UNUSED void *user) {
	free(kv->key);
}

/**
 * \brief Create a new hash table that has C-string as key and ut64 as value.
 * \param key_opt Defines how key is stored
 *
 * Keys are compared using strcmp function.
 * Size of keys is calculated using strlen function.
 * Copies of keys are made using rz_str_dup function if appropriate option is set.
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(HtStrOption key_opt) {
	HT_(Options) opt = {
		.cmp = (HT_(Comparator))strcmp,
		.hashfn = (HT_(HashFunction))sdb_hash,
		.dupkey = key_opt == HT_STR_DUP ? (HT_(DupKey))rz_str_dup : NULL,
		.dupvalue = NULL,
		.calcsizeK = (HT_(CalcSizeK))strlen,
		.calcsizeV = NULL,
		.finiKV = key_opt == HT_STR_CONST ? NULL : fini_kv_key,
		.finiKV_user = NULL,
		.elem_size = 0,
	};
	return internal_ht_new(ht_primes_sizes[0], 0, &opt);
}
