// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SDB_HT_PU_H
#define SDB_HT_PU_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header provides an hashtable HtPU that has void* as key and ut64 as
 * value. The API functions starts with "ht_pu_" and the types starts with "HtPU".
 */
#define HT_TYPE 4
#include "ht_inc.h"

RZ_API HtName_(Ht) * Ht_(new0)(void);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif
