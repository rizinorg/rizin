// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#include "sdb.h"
#include <rz_util/ht_ss.h>
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
 * \param val_opt Defines how value is stored
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(HtStrOption key_opt, HtStrOption val_opt) {
	HT_(Options) opt = {
		.cmp = (HT_(ListComparator))strcmp,
		.hashfn = (HT_(HashFunction))sdb_hash,
		.dupkey = key_opt == HT_STR_DUP ? (HT_(DupKey))strdup : NULL,
		.dupvalue = val_opt == HT_STR_DUP ? (HT_(DupValue))strdup : NULL,
		.calcsizeK = (HT_(CalcSizeK))strlen,
		.calcsizeV = (HT_(CalcSizeV))strlen,
		.finiKV = key_opt == HT_STR_CONST ? fini_kv_val : fini_kv,
		.finiKV_user = val_opt == HT_STR_CONST ? NULL : (HT_(FreeValue))free,
		.elem_size = 0,
	};
	return internal_ht_new(ht_primes_sizes[0], 0, &opt);
}
