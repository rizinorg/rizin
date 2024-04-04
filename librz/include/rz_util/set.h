// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef SDB_SET_H
#define SDB_SET_H

#include <rz_util/ht_sp.h>
#include <rz_util/ht_up.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HtSP SetS;

RZ_API SetS *set_s_new(HtStrOption opt);
RZ_API void set_s_add(SetS *p, const char *str);
RZ_API bool set_s_contains(SetS *s, const char *str);
RZ_API void set_s_delete(SetS *s, const char *str);
RZ_API void set_s_free(SetS *s);

typedef HtUP SetU;

RZ_API SetU *set_u_new(void);
RZ_API void set_u_add(SetU *p, ut64 u);
RZ_API bool set_u_contains(SetU *s, ut64 u);
RZ_API void set_u_delete(SetU *s, ut64 u);
RZ_API void set_u_free(SetU *p);

#ifdef __cplusplus
}
#endif

#endif
