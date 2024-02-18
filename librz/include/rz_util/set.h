// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#ifndef SDB_SET_H
#define SDB_SET_H

#include <rz_util/ht_pp.h>
#include <rz_util/ht_uu.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HtPP SetP;

RZ_API SetP *set_p_new(void);
RZ_API ut64 set_p_len(SetP *s);
RZ_API void set_p_add(SetP *p, const void *u);
RZ_API bool set_p_contains(SetP *s, const void *u);
RZ_API void set_p_delete(SetP *s, const void *u);
RZ_API void set_p_free(SetP *p);

typedef HtUU SetU;

RZ_API SetU *set_u_new(void);
RZ_API ut64 set_u_size(SetU *s);
RZ_API void set_u_add(SetU *p, ut64 u);
RZ_API bool set_u_contains(SetU *s, ut64 u);
RZ_API void set_u_delete(SetU *s, ut64 u);
RZ_API void set_u_free(SetU *p);

typedef struct {
	st64 ti; ///< Table index
	ut64 bi; ///< Bucket index
	ut64 v; ///< Current value of the iteration
} SetUIter;

typedef struct {
	st64 ti; // Table index
	size_t bi; // Bucket index
	void *v; ///< Current value of the iteration
} SetPIter;

RZ_API void advance_set_u_iter(SetU *s, SetUIter *it);
RZ_API void advance_set_p_iter(SetP *s, SetPIter *it);

#define set_u_iter_init(iter) SetUIter iter = { 0 }
#define set_u_iter_reset(iter) \
	do { \
		iter.ti = 0; \
		iter.bi = 0; \
		iter.v = 0; \
	} while (0)
/**
 * The adcvance_set_u_iter() sets iter.ti always to the entry of the next table to check.
 * So our condition checks if ti <= set->size.
 */
#define set_u_foreach(set, iter) \
	if (set) \
		for (advance_set_u_iter(set, &iter); iter.ti <= set->size && set_u_size(set) > 0; advance_set_u_iter(set, &iter))

#ifdef __cplusplus
}
#endif

#endif
