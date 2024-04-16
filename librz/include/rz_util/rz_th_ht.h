// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TH_HASH_TABLE_H
#define RZ_TH_HASH_TABLE_H

#include <rz_th.h>
#include <rz_util/ht_pp.h>
#include <rz_util/ht_up.h>
#include <rz_util/ht_uu.h>
#include <rz_util/ht_pu.h>
#include <rz_util/ht_sp.h>
#include <rz_util/ht_ss.h>
#include <rz_util/ht_su.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef RZ_API

#define rz_th_ht_header(name, type, ktype, vtype) \
	typedef struct rz_th_##name##_t RzThread##type; \
	RZ_API void rz_th_##name##_free(RzThread##type *ht); \
	RZ_API RzThread##type *rz_th_##name##_new(type *table); \
	RZ_API bool rz_th_##name##_insert(RzThread##type *ht, const ktype key, vtype value); \
	RZ_API bool rz_th_##name##_update(RzThread##type *ht, const ktype key, vtype value); \
	RZ_API bool rz_th_##name##_delete(RzThread##type *ht, const ktype key); \
	RZ_API vtype rz_th_##name##_find(RzThread##type *ht, const ktype key, bool *found); \
	RZ_API type *rz_th_##name##_move(RzThread##type *ht); \
	RZ_API void rz_th_##name##_foreach(RzThread##type *ht, type##ForeachCallback cb, void *user)

rz_th_ht_header(ht_pp, HtPP, void *, void *);
rz_th_ht_header(ht_up, HtUP, ut64, void *);
rz_th_ht_header(ht_uu, HtUU, ut64, ut64);
rz_th_ht_header(ht_pu, HtPU, void *, ut64);
rz_th_ht_header(ht_sp, HtSP, char *, void *);
rz_th_ht_header(ht_ss, HtSS, char *, char *);
rz_th_ht_header(ht_su, HtSU, char *, ut64);

#endif /* RZ_API */

#ifdef __cplusplus
}
#endif

#endif /* RZ_TH_HASH_TABLE_H */
