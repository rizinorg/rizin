// SPDX-FileCopyrightText: pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2024 pelijah
// SPDX-License-Identifier: MIT

#ifndef SDB_SET_H
#define SDB_SET_H

#include <rz_util/ht_sp.h>
#include <rz_util/ht_up.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HtSP SetS;

RZ_API RZ_OWN SetS *set_s_new(HtStrOption opt);
RZ_API void set_s_add(RZ_NONNULL SetS *set, const char *str);
RZ_API bool set_s_contains(RZ_NONNULL SetS *set, const char *str);
RZ_API void set_s_delete(RZ_NONNULL SetS *set, const char *str);
RZ_API void set_s_free(RZ_NULLABLE SetS *set);

typedef HtUP SetU;

RZ_API RZ_OWN SetU *set_u_new(void);
RZ_API void set_u_add(RZ_NONNULL SetU *set, ut64 u);
RZ_API ut64 set_u_size(SetU *s);
RZ_API bool set_u_contains(RZ_NONNULL SetU *set, ut64 u);
RZ_API void set_u_delete(RZ_NONNULL SetU *set, ut64 u);
RZ_API void set_u_free(RZ_NULLABLE SetU *set);

typedef struct {
	st64 ti; ///< Table index
	ut64 bi; ///< Bucket index
	ut64 v; ///< Current value of the iteration
} SetUIter;

RZ_API void advance_set_u_iter(SetU *s, SetUIter *it);

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
