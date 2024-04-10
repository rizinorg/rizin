// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#ifndef HT_SU_H
#define HT_SU_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header provides an hashtable HtSU that has char* as key and ut64 as
 * value. The API functions starts with "ht_su_" and the types starts with "HtSU".
 */
#define HT_TYPE 7
#include <rz_util/ht_inc.h>

RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(HtStrOption key_opt);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif