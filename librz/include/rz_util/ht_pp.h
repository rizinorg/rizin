// SPDX-FileCopyrightText: 2016-2018 crowell
// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2016-2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef SDB_HT_PP_H
#define SDB_HT_PP_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header provides an hashtable HtPP that has void* as key and void* as
 * value. The API functions starts with "ht_pp_" and the types starts with "HtPP".
 */
#define HT_TYPE 1
#include <rz_util/ht_inc.h>
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif
