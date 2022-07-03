// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef SDB_SET_H
#define SDB_SET_H

#include "ht_pp.h"
#include "ht_up.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef HtPP SetP;

RZ_API SetP *set_p_new(void);
RZ_API void set_p_add(SetP *p, const void *u);
RZ_API bool set_p_contains(SetP *s, const void *u);
RZ_API void set_p_delete(SetP *s, const void *u);
RZ_API void set_p_free(SetP *p);

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
