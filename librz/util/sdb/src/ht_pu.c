// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "sdb.h"
#include "ht_pu.h"
#include "ht_inc.c"

static void free_kv_key(HT_(Kv) * kv) {
	free(kv->key);
}

// creates a default HtPU that has strings as keys
RZ_API HtName_(Ht) * Ht_(new0)(void) {
	HT_(Options)
	opt = {
		.cmp = (HT_(ListComparator))strcmp,
		.hashfn = (HT_(HashFunction))sdb_hash,
		.dupkey = (HT_(DupKey))strdup,
		.dupvalue = NULL,
		.calcsizeK = (HT_(CalcSizeK))strlen,
		.calcsizeV = NULL,
		.freefn = free_kv_key,
		.elem_size = sizeof(HT_(Kv)),
	};
	return Ht_(new_opt)(&opt);
}
