// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: BSD-3-Clause

#ifndef HT_SP_H
#define HT_SP_H

#ifdef __cplusplus
extern "C" {
#endif

/** \file
 * This header provides an hash table HtSP that has char* as key and void* as
 * value. The API functions starts with "ht_sp_" and the types starts with "HtSP".
 */
#define HT_TYPE 5
#include <rz_util/ht_inc.h>

RZ_API RZ_OWN HtName_(Ht) *Ht_(new)(HtStrOption key_opt, RZ_NULLABLE HT_(DupValue) dup_val, RZ_NULLABLE HT_(FreeValue) free_val);
#undef HT_TYPE

#ifdef __cplusplus
}
#endif

#endif