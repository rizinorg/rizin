// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#ifndef HT_UP_H
#define HT_UP_H

#ifdef __cplusplus
extern "C" {
#endif

/** \file
 * This header provides an hash table HtUP that has ut64 as key and void* as value.
 * The API functions starts with "ht_up_" and the types starts with "HtUP".
 */
#define HT_TYPE 2
#include <rz_util/ht_inc.h>

RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(RZ_NULLABLE HT_(DupValue) valdup, RZ_NULLABLE HT_(FreeValue) valfree);
RZ_API RZ_OWN HtName_(Ht) *Ht_(new_size)(ut32 initial_size, RZ_NULLABLE HT_(DupValue) valdup, RZ_NULLABLE HT_(FreeValue) valfree);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif
