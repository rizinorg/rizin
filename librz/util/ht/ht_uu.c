// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include "ht_uu.h"

#include "ht_inc.c"

RZ_API HtName_(Ht) * Ht_(new0)(void) {
	HT_(Options)
	opt = {
		.cmp = NULL,
		.hashfn = NULL,
		.dupkey = NULL,
		.dupvalue = NULL,
		.calcsizeK = NULL,
		.calcsizeV = NULL,
		.freefn = NULL
	};
	return Ht_(new_opt)(&opt);
}
