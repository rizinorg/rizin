// SPDX-FileCopyrightText: 2010-2013 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
// XXX. this is dupped inside the rz_flist.h for optimizations

int rz_flist_iterator(void **x) {
	return *x != 0;
}
void **rz_flist_next(void **x) {
	return x;
}
void **rz_flist_get(void **x) {
	return *(x++);
}
// XXX: forced free?? We need RFlist struct here
#include <rz_types.h>
//#include <rz_flist.h>
// NOTE: reimplemnetation of rz_flist in C (if no RZ_API defined)

#if 1
#define rz_flist_t void **
#define RFList     void **
#define rz_flist_rewind(it) \
	for (; (it) != *(it); (it)--) { \
	} \
	(it)++
#define rz_flist_next(it)    *(it) != 0
#define rz_flist_get(it)     *((it)++)
#define rz_flist_iterator(x) x
#define rz_flist_unref(x)    x
#endif

RZ_API void **rz_flist_new(int n) {
	void **it;
	if (!(it = (void **)calloc(n + 2, sizeof(void *)))) {
		return NULL;
	}
	*it = it;
	memset(++it, 0, (n + 1) * sizeof(void *));
	return it;
}

// XXX. this is wrong :?
RZ_API void **rz_flist_resize(void **it, int n) {
	rz_flist_rewind(it);
	it--;
	it = realloc(it, ((n + 2) * sizeof(void *)));
	*it = it;
	return it + 1;
}

RZ_API void **rz_flist_prev(void **it) {
	void **p = it--;
	return (it == *it) ? p : it;
}

RZ_API void rz_flist_set(void **it, int idx, void *data) {
	rz_flist_rewind(it);
	it[idx] = data;
}

RZ_API void rz_flist_delete(void **it, int idx) {
	rz_flist_rewind(it);
	free(it[idx]);
	it[idx] = NULL;
	for (it += idx; *it; it++) {
		*it = *(it + 1);
	}
}

#define rz_flist_foreach(it, pos) \
	rz_flist_rewind(it); \
	while (rz_flist_next(it) && ((pos) = rz_flist_get(it)))

RZ_API void rz_flist_free(void **it) {
	void *pos;
	rz_flist_foreach(it, pos) {
		free(pos);
	}
	rz_flist_rewind(it);
	free(--it);
}

RZ_API int rz_flist_length(void **it) {
	void *pos;
	int len = 0;
	rz_flist_foreach(it, pos) {
		len++;
	}
	return len;
}
