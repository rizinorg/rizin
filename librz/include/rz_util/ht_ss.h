// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#ifndef HT_SS_H
#define HT_SS_H

#ifdef __cplusplus
extern "C" {
#endif

/** \file
 * This header provides an hash table HtSS that has C-string as key and C-string as value.
 * The API functions starts with "ht_ss_" and the types starts with "HtSS".
 */
#define HT_TYPE 6
#include <rz_util/ht_inc.h>

RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(HtStrOption key_opt, HtStrOption val_opt);
#define ht_ss_foreach(ht, iter) ht_foreach(ss, ht, iter)
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif
