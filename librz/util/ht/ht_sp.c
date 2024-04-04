// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#include "sdb.h"
#include <rz_util/ht_sp.h>
#include "ht_inc.c"

static void fini_kv(HT_(Kv) *kv, void *user) {
	HT_(FreeValue) func = (HT_(FreeValue))user;
	free(kv->key);
	if (func) {
		func(kv->value);
	}
}

static void fini_kv_val(HT_(Kv) *kv, void *user) {
	HT_(FreeValue) func = (HT_(FreeValue))user;
	if (func) {
		func(kv->value);
	}
}

/**
 * \brief Create a new hashtable
 * \param key_opt Defines how key is stored
 * \param dup_val Function to making copy of a value when inserting
 * \param free_val Function to releasing a stored value
 */
RZ_API RZ_OWN HtName_(Ht) * Ht_(new)(HtStrOption key_opt, HT_(DupValue) dup_val, HT_(FreeValue) free_val) {
	HT_(Options) opt = {
		.cmp = (HT_(ListComparator))strcmp,
		.hashfn = (HT_(HashFunction))sdb_hash,
		.dupkey = key_opt == HT_STR_DUP ? (HT_(DupKey))strdup : NULL,
		.dupvalue = dup_val,
		.calcsizeK = (HT_(CalcSizeK))strlen,
		.calcsizeV = NULL,
		.finiKV = key_opt == HT_STR_CONST ? fini_kv_val : fini_kv,
		.finiKV_user = (void *)free_val,
		.elem_size = 0,
	};
	return internal_ht_new(ht_primes_sizes[0], 0, &opt);
}
