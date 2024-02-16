// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ITERATOR_H
#define RZ_ITERATOR_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rz_iterator_t;
typedef void *(*rz_iterator_next_cb)(struct rz_iterator_t *);
typedef void (*rz_iterator_free_cb)(void *);

typedef struct rz_iterator_t {
	void *cur;
	void *u;
	rz_iterator_next_cb next;
	rz_iterator_free_cb free;
	rz_iterator_free_cb free_u;
} RzIterator;

#define rz_iterator_foreach(iter, val) \
	for ((val) = rz_iterator_next(iter); (val) != NULL; (val) = rz_iterator_next(iter))

RZ_API RZ_OWN RzIterator *rz_iterator_new(
	RZ_NONNULL rz_iterator_next_cb next,
	RZ_NULLABLE rz_iterator_free_cb free,
	RZ_NULLABLE rz_iterator_free_cb free_u,
	RZ_NONNULL RZ_OWN void *u);
RZ_API RZ_BORROW void *rz_iterator_next(RZ_NONNULL RZ_BORROW RzIterator *it);
RZ_API void rz_iterator_free(RzIterator *it);

#ifdef __cplusplus
}
#endif

#endif // RZ_ITERATOR_H
