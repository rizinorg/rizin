// SPDX-FileCopyrightText: 2010 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_FLIST_H
#define RZ_FLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <string.h>
//#include <rz_types.h>

#define rz_flist_t void **
#define RFList     void **

#ifdef RZ_API
RZ_API void **rz_flist_resize(void **it, int n);
#define rz_flist_rewind(it) \
	while (it != *it) \
		it--; \
	it++;
#define rz_flist_next(it) *it != 0
#define rz_flist_get(it)  *(it++)
#define rz_flist_unref(x) x

#define rz_flist_iterator(x) x
/*
static inline void **rz_flist_iterator(void **it) {
	rz_flist_iterator(it);
	return it;
}
*/

static inline void **rz_flist_init(void **it, int n) {
	*it = it;
	memset(++it, 0, (n + 1) * sizeof(void *));
	return it;
}

static inline void **rz_flist_new(int n) {
	void **it;
	if (((n + 2) * sizeof(void *)) < sizeof(void *))
		return NULL;
	if (!(it = (void **)calloc((n + 2), sizeof(void *)))) {
		return NULL;
	}
	return rz_flist_init(it, n);
}

static inline void **rz_flist_prev(void **it) {
	void **p = it--;
	return (it == *it) ? p : it;
}

static inline void rz_flist_set(void **it, int idx, void *data) {
	rz_flist_rewind(it);
	it[idx] = data;
}

static inline void rz_flist_delete(void **it, int idx) {
	rz_flist_rewind(it);
	free(it[idx]);
	for (it += idx; *it; it++)
		*it = *(it + 1);
}

#define rz_flist_foreach(it, pos) \
	rz_flist_rewind(it); \
	while (rz_flist_next(it) && (pos = rz_flist_get(it)))

static inline void rz_flist_free(void **it) {
	void *pos;
	rz_flist_foreach(it, pos)
		free(pos);
	rz_flist_rewind(it);
	free(--it);
}

static inline int rz_flist_length(void **it) {
	void *pos;
	int len = 0;
	rz_flist_foreach(it, pos)
		len++;
	return len;
}
#endif

#ifdef __cplusplus
}
#endif

#endif
