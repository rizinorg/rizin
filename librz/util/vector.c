// SPDX-FileCopyrightText: 2017-2020 maskray <i@maskray.me>
// SPDX-FileCopyrightText: 2017-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_vector.h"

// Optimize memory usage on glibc
#if __WORDSIZE == 32
// Chunk size 24, minus 4 (chunk header), minus 8 for capacity and len, 12 bytes remaining for 3 void *
#define INITIAL_VECTOR_LEN 3
#else
// For __WORDSIZE == 64
// Chunk size 48, minus 8 (chunk header), minus 8 for capacity and len, 32 bytes remaining for 4 void *
#define INITIAL_VECTOR_LEN 4
#endif

#define NEXT_VECTOR_CAPACITY (vec->capacity < INITIAL_VECTOR_LEN \
		? INITIAL_VECTOR_LEN \
		: vec->capacity <= 12 ? vec->capacity * 2 \
				      : vec->capacity + (vec->capacity >> 1))

#define RESIZE_OR_RETURN_NULL(next_capacity) \
	do { \
		size_t new_capacity = next_capacity; \
		void **new_a = realloc(vec->a, vec->elem_size * new_capacity); \
		if (!new_a) { \
			return NULL; \
		} \
		vec->a = new_a; \
		vec->capacity = new_capacity; \
	} while (0)

RZ_API void rz_vector_init(RzVector *vec, size_t elem_size, RzVectorFree free, void *free_user) {
	rz_return_if_fail(vec);
	vec->a = NULL;
	vec->capacity = vec->len = 0;
	vec->elem_size = elem_size;
	vec->free = free;
	vec->free_user = free_user;
}

RZ_API RzVector *rz_vector_new(size_t elem_size, RzVectorFree free, void *free_user) {
	RzVector *vec = RZ_NEW(RzVector);
	if (!vec) {
		return NULL;
	}
	rz_vector_init(vec, elem_size, free, free_user);
	return vec;
}

static void vector_free_elems(RzVector *vec) {
	if (vec->free) {
		while (vec->len > 0) {
			vec->free(rz_vector_index_ptr(vec, --vec->len), vec->free_user);
		}
	} else {
		vec->len = 0;
	}
}

RZ_API void rz_vector_fini(RzVector *vec) {
	rz_return_if_fail(vec);
	rz_vector_clear(vec);
	vec->free = NULL;
	vec->free_user = NULL;
}

RZ_API void rz_vector_clear(RzVector *vec) {
	rz_return_if_fail(vec);
	vector_free_elems(vec);
	RZ_FREE(vec->a);
	vec->capacity = 0;
}

RZ_API void rz_vector_free(RzVector *vec) {
	if (vec) {
		rz_vector_fini(vec);
		free(vec);
	}
}

static bool vector_clone(RzVector *dst, RzVector *src) {
	rz_return_val_if_fail(dst && src, false);
	dst->capacity = src->capacity;
	dst->len = src->len;
	dst->elem_size = src->elem_size;
	dst->free = src->free;
	dst->free_user = src->free_user;
	if (!dst->len) {
		dst->a = NULL;
	} else {
		dst->a = malloc(src->elem_size * src->capacity);
		if (!dst->a) {
			return false;
		}
		memcpy(dst->a, src->a, src->elem_size * src->len);
	}
	return true;
}

RZ_API RzVector *rz_vector_clone(RzVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	RzVector *ret = RZ_NEW(RzVector);
	if (!ret) {
		return NULL;
	}
	if (!vector_clone(ret, vec)) {
		free(ret);
		return NULL;
	}
	return ret;
}

RZ_API void rz_vector_assign(RzVector *vec, void *p, void *elem) {
	rz_return_if_fail(vec && p && elem);
	memcpy(p, elem, vec->elem_size);
}

RZ_API void *rz_vector_assign_at(RzVector *vec, size_t index, void *elem) {
	void *p = rz_vector_index_ptr(vec, index);
	if (elem) {
		rz_vector_assign(vec, p, elem);
	}
	return p;
}

RZ_API void rz_vector_remove_at(RzVector *vec, size_t index, void *into) {
	rz_return_if_fail(vec);
	void *p = rz_vector_index_ptr(vec, index);
	if (into) {
		rz_vector_assign(vec, into, p);
	}
	vec->len--;
	if (index < vec->len) {
		memmove(p, (char *)p + vec->elem_size, vec->elem_size * (vec->len - index));
	}
}

RZ_API void *rz_vector_insert(RzVector *vec, size_t index, void *x) {
	rz_return_val_if_fail(vec && index <= vec->len, NULL);
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL(NEXT_VECTOR_CAPACITY);
	}
	void *p = rz_vector_index_ptr(vec, index);
	if (index < vec->len) {
		memmove((char *)p + vec->elem_size, p, vec->elem_size * (vec->len - index));
	}
	vec->len++;
	if (x) {
		rz_vector_assign(vec, p, x);
	}
	return p;
}

RZ_API void *rz_vector_insert_range(RzVector *vec, size_t index, void *first, size_t count) {
	rz_return_val_if_fail(vec && index <= vec->len, NULL);
	if (vec->len + count > vec->capacity) {
		RESIZE_OR_RETURN_NULL(RZ_MAX(NEXT_VECTOR_CAPACITY, vec->len + count));
	}
	size_t sz = count * vec->elem_size;
	void *p = rz_vector_index_ptr(vec, index);
	if (index < vec->len) {
		memmove((char *)p + sz, p, vec->elem_size * (vec->len - index));
	}
	vec->len += count;
	if (first) {
		memcpy(p, first, sz);
	}
	return p;
}

RZ_API void rz_vector_pop(RzVector *vec, void *into) {
	rz_return_if_fail(vec);
	if (into) {
		rz_vector_assign(vec, into, rz_vector_index_ptr(vec, vec->len - 1));
	}
	vec->len--;
}

RZ_API void rz_vector_pop_front(RzVector *vec, void *into) {
	rz_return_if_fail(vec);
	rz_vector_remove_at(vec, 0, into);
}

RZ_API void *rz_vector_push(RzVector *vec, void *x) {
	rz_return_val_if_fail(vec, NULL);
	if (vec->len >= vec->capacity) {
		RESIZE_OR_RETURN_NULL(NEXT_VECTOR_CAPACITY);
	}
	void *p = rz_vector_index_ptr(vec, vec->len++);
	if (x) {
		rz_vector_assign(vec, p, x);
	}
	return p;
}

RZ_API void *rz_vector_push_front(RzVector *vec, void *x) {
	rz_return_val_if_fail(vec, NULL);
	return rz_vector_insert(vec, 0, x);
}

RZ_API void *rz_vector_reserve(RzVector *vec, size_t capacity) {
	rz_return_val_if_fail(vec, NULL);
	if (vec->capacity < capacity) {
		RESIZE_OR_RETURN_NULL(capacity);
	}
	return vec->a;
}

RZ_API void *rz_vector_shrink(RzVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	if (vec->len < vec->capacity) {
		RESIZE_OR_RETURN_NULL(vec->len);
	}
	return vec->a;
}

// pvector

static void pvector_free_elem(void *e, void *user) {
	void *p = *((void **)e);
	RzPVectorFree elem_free = (RzPVectorFree)user;
	elem_free(p);
}

RZ_API void rz_pvector_init(RzPVector *vec, RzPVectorFree free) {
	rz_vector_init(&vec->v, sizeof(void *), free ? pvector_free_elem : NULL, free);
}

RZ_API RzPVector *rz_pvector_new(RzPVectorFree free) {
	RzPVector *v = RZ_NEW(RzPVector);
	if (!v) {
		return NULL;
	}
	rz_pvector_init(v, free);
	return v;
}

RZ_API RzPVector *rz_pvector_new_with_len(RzPVectorFree free, size_t length) {
	RzPVector *v = rz_pvector_new(free);
	if (!v) {
		return NULL;
	}
	void **p = rz_pvector_reserve(v, length);
	if (!p) {
		rz_pvector_free(v);
		return NULL;
	}
	memset(p, 0, v->v.elem_size * v->v.capacity);
	v->v.len = length;
	return v;
}

RZ_API void rz_pvector_clear(RzPVector *vec) {
	rz_return_if_fail(vec);
	rz_vector_clear(&vec->v);
}

RZ_API void rz_pvector_fini(RzPVector *vec) {
	rz_return_if_fail(vec);
	rz_vector_fini(&vec->v);
}

RZ_API void rz_pvector_free(RzPVector *vec) {
	if (!vec) {
		return;
	}
	rz_vector_fini(&vec->v);
	free(vec);
}

RZ_API void **rz_pvector_contains(RzPVector *vec, void *x) {
	rz_return_val_if_fail(vec, NULL);
	size_t i;
	for (i = 0; i < vec->v.len; i++) {
		if (((void **)vec->v.a)[i] == x) {
			return &((void **)vec->v.a)[i];
		}
	}
	return NULL;
}

RZ_API void *rz_pvector_remove_at(RzPVector *vec, size_t index) {
	rz_return_val_if_fail(vec, NULL);
	void *r = rz_pvector_at(vec, index);
	rz_vector_remove_at(&vec->v, index, NULL);
	return r;
}

RZ_API void rz_pvector_remove_data(RzPVector *vec, void *x) {
	void **el = rz_pvector_contains(vec, x);
	if (!el) {
		return;
	}

	size_t index = el - (void **)vec->v.a;
	rz_vector_remove_at(&vec->v, index, NULL);
}

RZ_API void *rz_pvector_pop(RzPVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	void *r = rz_pvector_at(vec, vec->v.len - 1);
	rz_vector_pop(&vec->v, NULL);
	return r;
}

RZ_API void *rz_pvector_pop_front(RzPVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	void *r = rz_pvector_at(vec, 0);
	rz_vector_pop_front(&vec->v, NULL);
	return r;
}

// CLRS Quicksort. It is slow, but simple.
static void quick_sort(void **a, size_t n, RzPVectorComparator cmp) {
	if (n <= 1) {
		return;
	}
	size_t i = rand() % n, j = 0;
	void *t, *pivot = a[i];
	a[i] = a[n - 1];
	for (i = 0; i < n - 1; i++) {
		if (cmp(a[i], pivot) < 0) {
			t = a[i];
			a[i] = a[j];
			a[j] = t;
			j++;
		}
	}
	a[n - 1] = a[j];
	a[j] = pivot;
	quick_sort(a, j, cmp);
	quick_sort(a + j + 1, n - j - 1, cmp);
}

RZ_API void rz_pvector_sort(RzPVector *vec, RzPVectorComparator cmp) {
	rz_return_if_fail(vec && cmp);
	quick_sort(vec->v.a, vec->v.len, cmp);
}
