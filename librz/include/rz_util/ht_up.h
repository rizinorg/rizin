// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SDB_HT_UP_H
#define SDB_HT_UP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header provides an hashtable HtUP that has ut64 as key and void* as
 * value. The API functions starts with "ht_up_" and the types starts with "HtUP".
 */
#define HT_TYPE 2
#include "ht_inc.h"

RZ_API HtName_(Ht) * Ht_(new0)(void);
RZ_API HtName_(Ht) * Ht_(new)(HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) valueSize);
RZ_API HtName_(Ht) * Ht_(new_size)(ut32 initial_size, HT_(DupValue) valdup, HT_(KvFreeFunc) pair_free, HT_(CalcSizeV) valueSize);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif
