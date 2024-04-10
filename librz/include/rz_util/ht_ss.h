// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#ifndef HT_SS_H
#define HT_SS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header provides an hashtable HtSS that has char* as key and char* as
 * value. The API functions starts with "ht_ss_" and the types starts with "HtSS".
 */
#define HT_TYPE 6
#include <rz_util/ht_inc.h>

RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(HtStrOption key_opt, HtStrOption val_opt);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif