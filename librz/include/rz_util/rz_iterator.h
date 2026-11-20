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
typedef void *(*rz_iterator_clone_cb)(const void *u);
typedef bool (*rz_iterator_reset_cb)(void *u);

typedef struct rz_iterator_t {
	void *cur;
	void *u;
	rz_iterator_next_cb next; ///< NULL means this iterator is uninitialized/invalid
	rz_iterator_free_cb free;
	rz_iterator_free_cb free_u;
	rz_iterator_clone_cb clone_u; ///< NULL means this iterator does not support cloning (see rz_iterator_clone())
	rz_iterator_reset_cb reset_u; ///< NULL means this iterator does not support resetting (see rz_iterator_reset())
} RzIterator;

#define rz_iterator_foreach(iter, val) \
	for ((val) = rz_iterator_next(iter); (val) != NULL; (val) = rz_iterator_next(iter))

RZ_API bool rz_iterator_init(
	RZ_NONNULL rz_iterator_next_cb next,
	RZ_NULLABLE rz_iterator_free_cb free,
	RZ_NULLABLE rz_iterator_free_cb free_u,
	RZ_NULLABLE rz_iterator_clone_cb clone_u,
	RZ_NULLABLE rz_iterator_reset_cb reset_u,
	RZ_NONNULL RZ_OWN void *u,
	RZ_OUT RZ_NONNULL RzIterator *iterator);
RZ_API RZ_BORROW void *rz_iterator_next(RZ_NONNULL RZ_BORROW RzIterator *it);
RZ_API void rz_iterator_fini(RzIterator *it);

RZ_API bool rz_iterator_reset(RZ_BORROW RZ_NONNULL RzIterator *iter);
RZ_API bool rz_iterator_clone(const RZ_NONNULL RzIterator *iter, RZ_OUT RZ_NONNULL RzIterator *iter_clone, bool reset);

static inline bool rz_iterator_is_uninit(RZ_NULLABLE const RzIterator *it) {
	return !it || !it->next;
}

#ifdef __cplusplus
}
#endif

#endif // RZ_ITERATOR_H
