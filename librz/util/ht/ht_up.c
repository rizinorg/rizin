// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_util/ht_up.h>
#include "ht_inc.c"

static void fini_kv_val(HT_(Kv) *kv, void *user) {
	HT_(FreeValue) func = (HT_(FreeValue))user;
	if (func) {
		func(kv->value);
	}
}

static void init_options(HT_(Options) *opt, HT_(DupValue) valdup, HT_(FreeValue) valfree) {
	opt->cmp = NULL;
	opt->hashfn = NULL;
	opt->dupkey = NULL;
	opt->dupvalue = valdup;
	opt->calcsizeK = NULL;
	opt->calcsizeV = NULL;
	opt->finiKV = fini_kv_val;
	opt->finiKV_user = (void *)valfree;
	opt->elem_size = 0;
}

/**
 * \brief Create a new hashtable
 * \param valdup Function to making copy of a value when inserting
 * \param valfree Function to releasing a stored value
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(RZ_NULLABLE HT_(DupValue) valdup, RZ_NULLABLE HT_(FreeValue) valfree) {
	HT_(Options) opt;
	init_options(&opt, valdup, valfree);
	return internal_ht_new(ht_primes_sizes[0], 0, &opt);
}

/**
 * \brief Create a new hashtable with preallocated buckets for \p initial_size entries
 * \param valdup Function to making copy of a value when inserting
 * \param valfree Function to releasing a stored value
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_size)(ut32 initial_size, RZ_NULLABLE HT_(DupValue) valdup, RZ_NULLABLE HT_(FreeValue) valfree) {
	HT_(Options) opt;
	init_options(&opt, valdup, valfree);
	return Ht_(new_opt_size)(&opt, initial_size);
}
