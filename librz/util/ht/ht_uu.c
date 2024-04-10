// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#include <rz_util/ht_uu.h>

#include "ht_inc.c"

/**
 * \brief Create a new hashtable
 */
RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(void) {
	HT_(Options) opt = { 0 };
	return Ht_(new_opt)(&opt);
}
