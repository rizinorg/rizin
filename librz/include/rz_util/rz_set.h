// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: MIT

#ifndef RZ_SET_H
#define RZ_SET_H

#include <rz_util/ht_sp.h>
#include <rz_util/ht_up.h>
#include <rz_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HtSP RzSetS;

RZ_API RZ_OWN RzSetS *rz_set_s_new(HtStrOption opt);
RZ_API void rz_set_s_free(RZ_NULLABLE RzSetS *set);
RZ_API void rz_set_s_add(RZ_NONNULL RzSetS *set, const char *str);
RZ_API bool rz_set_s_contains(RZ_NONNULL RzSetS *set, const char *str);
RZ_API void rz_set_s_delete(RZ_NONNULL RzSetS *set, const char *str);
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_set_s_to_vector(RZ_NONNULL RzSetS *set);

typedef HtUP RzSetU;

RZ_API RZ_OWN RzSetU *rz_set_u_new(void);
RZ_API void rz_set_u_free(RZ_NULLABLE RzSetU *set);
RZ_API void rz_set_u_add(RZ_NONNULL RzSetU *set, ut64 u);
RZ_API bool rz_set_u_contains(RZ_NONNULL RzSetU *set, ut64 u);
RZ_API void rz_set_u_delete(RZ_NONNULL RzSetU *set, ut64 u);

#ifdef __cplusplus
}
#endif

#endif
