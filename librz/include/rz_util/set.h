// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: MIT

#ifndef SDB_SET_H
#define SDB_SET_H

#include <rz_util/ht_sp.h>
#include <rz_util/ht_up.h>
#include <rz_vector.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HtSP SetS;

RZ_API RZ_OWN SetS *set_s_new(HtStrOption opt);
RZ_API void set_s_add(RZ_NONNULL SetS *set, const char *str);
RZ_API bool set_s_contains(RZ_NONNULL SetS *set, const char *str);
RZ_API void set_s_delete(RZ_NONNULL SetS *set, const char *str);
RZ_API void set_s_free(RZ_NULLABLE SetS *set);
RZ_API RZ_OWN RzPVector /*<char *>*/ *set_s_to_vector(RZ_NONNULL SetS *set);

typedef HtUP SetU;

RZ_API RZ_OWN SetU *set_u_new(void);
RZ_API void set_u_add(RZ_NONNULL SetU *set, ut64 u);
RZ_API bool set_u_contains(RZ_NONNULL SetU *set, ut64 u);
RZ_API void set_u_delete(RZ_NONNULL SetU *set, ut64 u);
RZ_API void set_u_free(RZ_NULLABLE SetU *set);

#ifdef __cplusplus
}
#endif

#endif
