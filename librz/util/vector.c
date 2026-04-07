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

#define RESIZE_OR_RETURN_VAL(next_capacity, retval) \
	do { \
		size_t new_capacity = next_capacity; \
		void **new_a = realloc(vec->a, vec->elem_size * new_capacity); \
		if (!new_a && new_capacity) { \
			return retval; \
		} \
		vec->a = new_a; \
		vec->capacity = new_capacity; \
	} while (0)

#define RESIZE_OR_RETURN_NULL(next_capacity)  RESIZE_OR_RETURN_VAL(next_capacity, NULL)
#define RESIZE_OR_RETURN_FALSE(next_capacity) RESIZE_OR_RETURN_VAL(next_capacity, false)

RZ_API void rz_vector_init(RzVector *vec, size_t elem_size, RzVectorFree free, void *free_user) {
	rz_return_if_fail(vec);
	vec->a = NULL;
	vec->reverse_sorted = false;
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

/**
 * \brief Clone the contents of \p src into \p dst.
 * \param dst The vector to clone into.
 * \param src The vector to clone from.
 * \param item_cpy The function to copy every element of \p src into \p dst
 * \return true on success, false on failure.
 */
RZ_API bool rz_vector_clone_intof(
	RZ_NONNULL RZ_BORROW RZ_OUT RzVector *dst,
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *src,
	RZ_NULLABLE const RzVectorItemCpyFunc item_cpy) {
	rz_return_val_if_fail(dst && src, false);
	dst->capacity = src->capacity;
	dst->len = src->len;
	dst->elem_size = src->elem_size;
	dst->free = NULL;
	dst->free_user = NULL;
	if (!dst->len) {
		dst->a = NULL;
	} else {
		dst->a = malloc(src->elem_size * src->capacity);
		if (!dst->a) {
			return false;
		}
		const ut64 len = rz_vector_len(src);
		if (item_cpy) {
			for (ut64 i = 0; i < len; ++i) {
				item_cpy((ut8 *)(dst->a) + i * src->elem_size,
					(ut8 *)(src->a) + i * src->elem_size);
			}
		} else {
			memcpy(dst->a, src->a, src->elem_size * len);
		}
	}
	return true;
}

/**
 * Construct a new vector with the same contents and capacity as \p vec.
 * \param vec The source vector
 * \return The new vector
 */
RZ_API RZ_OWN RzVector *rz_vector_clonef(
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *vec,
	RZ_NULLABLE const RzVectorItemCpyFunc item_cpy) {
	rz_return_val_if_fail(vec, NULL);
	RzVector *dst = RZ_NEW(RzVector);
	if (!dst) {
		return NULL;
	}
	if (!rz_vector_clone_intof(dst, vec, item_cpy)) {
		free(dst);
		return NULL;
	}
	return dst;
}

/**
 * \brief Clone the contents of \p src into \p dst.
 * \param dst The vector to clone into.
 * \param src The vector to clone from.
 * \return true on success, false on failure.
 */
RZ_API bool rz_vector_clone_into(
	RZ_NONNULL RZ_BORROW RZ_OUT RzVector *dst,
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *src) {
	const bool ret = rz_vector_clone_intof(dst, src, NULL);
	dst->free = NULL;
	dst->free_user = NULL;
	return ret;
}

/**
 * \brief Construct a new vector with the same contents and capacity as \p vec.
 * The free function of the resulting vector will be NULL, so if elements are considered
 * to be owned and freed by \p vec, this will still be the case and the returned vector
 * only borrows them.
 *
 * \param vec The source vector
 * \return The new vector
 */
RZ_API RZ_OWN RzVector *rz_vector_clone(
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *vec) {
	RzVector *dst = rz_vector_clonef(vec, NULL);
	dst->free = NULL;
	dst->free_user = NULL;
	return dst;
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
	if (rz_vector_empty(vec)) {
		return;
	}
	void *p = rz_vector_index_ptr(vec, index);
	if (into) {
		rz_vector_assign(vec, into, p);
	}
	vec->len--;
	if (index < vec->len) {
		memmove(p, (char *)p + vec->elem_size, vec->elem_size * (vec->len - index));
	}
}

RZ_API void rz_vector_remove_range(RzVector *vec, size_t index, size_t count, void *into) {
	rz_return_if_fail(vec && index + count <= vec->len);
	void *p = rz_vector_index_ptr(vec, index);
	if (into) {
		memcpy(into, p, count * vec->elem_size);
	}
	vec->len -= count;
	if (index < vec->len) {
		memmove(p, (char *)p + vec->elem_size * count, vec->elem_size * (vec->len - index));
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

/**
 * \brief Inserts \p count elements from \p first in vector \p vec at index \p index, shifting elements if necessary.
 *
 * \param vec The vector to insert in.
 * \param index The index to insert the new elements. It can be equal to vector length which means insert-at-the-end.
 * \param first The array containing the new elements. If NULL, \p count empty elements will be inserted.
 * \param count The number of elements from \p first to be inserted, or number of empty elements if \p first is NULL.
 * \return A pointer to the inserted elements.
 */
RZ_API void *rz_vector_insert_range(RzVector *vec, size_t index, RZ_NULLABLE void *first, size_t count) {
	rz_return_val_if_fail(vec && index <= vec->len, NULL);
	if (count == 0) {
		return (char *)vec->a + vec->elem_size * index;
	}
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

/**
 * \brief Inserts an element into a sorted vector keeping the order.
 * NOTE: This function assumes the vector is already sorted!
 * If it isn't the final position of the element is undefined.
 *
 * \param vec A sorted vector to insert the element into.
 * \param elem Pointer to the element to insert into the vector.
 * \param cmp The comparator for the elements.
 * \param user The user data passed to the comparator.
 *
 * \return Pointer to the position in the vector where the element was placed.
 * Or NULL in case of failure.
 */
RZ_API void *rz_vector_insert_sorted(RZ_NONNULL RzVector *vec, RZ_NONNULL void *elem, RzVectorComparator cmp, void *user) {
	rz_return_val_if_fail(vec && elem, NULL);
	if (rz_vector_empty(vec)) {
		return rz_vector_push(vec, elem);
	}
	size_t i = vec->reverse_sorted ? rz_vector_len(vec) - 1 : 0;
	int inc = vec->reverse_sorted ? -1 : 1;

	do {
		void *velem = ((char *)vec->a) + (vec->elem_size * i);
		if (cmp(velem, elem, user) >= 0) {
			return rz_vector_insert(vec, vec->reverse_sorted ? i + 1 : i, elem);
		}
		if (i == 0 && inc == -1) {
			// Overflow is undefined. So lets not depend on it.
			break;
		}
		i += inc;
	} while (i >= 0 && i < rz_vector_len(vec));
	return vec->reverse_sorted ? rz_vector_push_front(vec, elem) : rz_vector_push(vec, elem);
}

RZ_API void rz_vector_pop(RzVector *vec, void *into) {
	if (rz_vector_empty(vec)) {
		return;
	}
	if (into) {
		rz_vector_assign(vec, into, rz_vector_index_ptr(vec, vec->len - 1));
	}
	vec->len--;
}

RZ_API void rz_vector_pop_front(RzVector *vec, void *into) {
	if (rz_vector_empty(vec)) {
		return;
	}
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

/**
 * \brief Checks if the given element is in the vector.
 *
 * \param vec The vector to search in.
 * \param elem Pointer to the element to search.
 *
 * \return True if the vector contains the element, false otherwise.
 */
RZ_API bool rz_vector_contains(const RZ_NONNULL RzVector *vec, const RZ_NONNULL void *elem) {
	rz_return_val_if_fail(vec && elem, false);
	for (size_t i = 0; i < vec->len; i++) {
		// Casts to make Windows happy.
		char *elem_v = ((char *)vec->a) + (vec->elem_size * i);
		if (memcmp(elem_v, (char *)elem, vec->elem_size) == 0) {
			return true;
		}
	}
	return false;
}

RZ_API bool rz_vector_swap(RzVector *vec, size_t index_a, size_t index_b) {
	rz_return_val_if_fail(vec && index_a < vec->len && index_b < vec->len, false);
	ut8 *tmp = malloc(vec->elem_size);
	if (!tmp) {
		return false;
	}
	void *elem_a = rz_vector_index_ptr(vec, index_a);
	void *elem_b = rz_vector_index_ptr(vec, index_b);
	memcpy(tmp, elem_a, vec->elem_size);
	memcpy(elem_a, elem_b, vec->elem_size);
	memcpy(elem_b, tmp, vec->elem_size);
	free(tmp);
	return true;
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

RZ_API void *rz_vector_flush(RzVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	rz_vector_shrink(vec);
	void *r = vec->a;
	vec->a = NULL;
	vec->capacity = vec->len = 0;
	return r;
}

// CLRS Quicksort. It is slow, but simple.
#define VEC_INDEX(a, i) (char *)a + elem_size *(i)
static void vector_quick_sort(void *a, size_t elem_size, size_t len, RzVectorComparator cmp, bool reverse, void *user) {
	rz_return_if_fail(a);
	if (len <= 1) {
		return;
	}
	size_t i = rand() % len, j = 0;
	void *t, *pivot;

	t = (void *)malloc(elem_size);
	pivot = (void *)malloc(elem_size);
	if (!t || !pivot) {
		free(t);
		free(pivot);
		RZ_LOG_ERROR("Failed to allocate memory\n");
		return;
	}

	memcpy(pivot, VEC_INDEX(a, i), elem_size);
	memcpy(VEC_INDEX(a, i), VEC_INDEX(a, len - 1), elem_size);
	for (i = 0; i < len - 1; i++) {
		if ((cmp(VEC_INDEX(a, i), pivot, user) < 0 && !reverse) ||
			(cmp(VEC_INDEX(a, i), pivot, user) > 0 && reverse)) {
			memcpy(t, VEC_INDEX(a, i), elem_size);
			memcpy(VEC_INDEX(a, i), VEC_INDEX(a, j), elem_size);
			memcpy(VEC_INDEX(a, j), t, elem_size);
			j++;
		}
	}
	memcpy(VEC_INDEX(a, len - 1), VEC_INDEX(a, j), elem_size);
	memcpy(VEC_INDEX(a, j), pivot, elem_size);
	RZ_FREE(t);
	RZ_FREE(pivot);
	vector_quick_sort(a, elem_size, j, cmp, reverse, user);
	vector_quick_sort(VEC_INDEX(a, j + 1), elem_size, len - j - 1, cmp, reverse, user);
}
#undef VEC_INDEX

/**
 * \brief Sort function for RzVector
 *
 * \param vec pointer to RzVector
 * \param cmp function used for comparing elements while sorting
 * \param reverse sort order, ascending order when reverse = False
 * \param user user pointer to extra data.
 */
RZ_API void rz_vector_sort(RzVector *vec, RzVectorComparator cmp, bool reverse, void *user) {
	rz_return_if_fail(vec && cmp);
	vec->reverse_sorted = reverse;
	if (rz_vector_empty(vec)) {
		return;
	}
	vector_quick_sort(vec->a, vec->elem_size, vec->len, cmp, reverse, user);
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

/**
 * \brief Checks if a the pointer \p x is in the vector.
 *
 * \param vec The vector to search in.
 * \param x The pointer to search.
 *
 * \return Returns the pointer to the \p x pointer in the vector if found. NULL otherwise.
 */
RZ_API void **rz_pvector_contains(RzPVector *vec, const void *x) {
	rz_return_val_if_fail(vec, NULL);
	size_t i;
	for (i = 0; i < vec->v.len; i++) {
		if (((void **)vec->v.a)[i] == x) {
			return &((void **)vec->v.a)[i];
		}
	}
	return NULL;
}

/**
 * \brief Find the \p element in the \p vec
 * \param vec the RzPVector to search in
 * \param value the value that elements in pvector compare against by \p cmp
 * \param cmp the comparator function
 * \return the iter of the element if found, NULL otherwise
 */
RZ_API RZ_BORROW void **rz_pvector_find(RZ_NONNULL const RzPVector *vec, RZ_NONNULL const void *value, RZ_NONNULL RzPVectorComparator cmp, void *user) {
	rz_return_val_if_fail(vec, NULL);

	void **iter;
	rz_pvector_foreach (vec, iter) {
		if (!cmp(value, *iter, user)) {
			return iter;
		}
	}
	return NULL;
}

/**
 * \brief Find the \p element in the \p vec.
 * \param vec the RzPVector to search in.
 * \param value the value that elements in pvector compare against by \p cmp.
 * \param cmp the comparator function.
 * \return Returns the index of the first matching element, SZT_MAX otherwise.
 */
RZ_API size_t rz_pvector_find_index(RZ_NONNULL const RzPVector *vec, RZ_NONNULL const void *value, RZ_NONNULL RzPVectorComparator cmp, void *user) {
	rz_return_val_if_fail(vec, SZT_MAX);

	void **iter = NULL;
	size_t i = 0;
	rz_pvector_enumerate (vec, iter, i) {
		if (!cmp(value, *iter, user)) {
			return i;
		}
	}
	return SZT_MAX;
}

/**
 * \brief Joins 2 pvector into one (pvec2 pointer needs to be freed by the user)
 *
 **/
RZ_API bool rz_pvector_join(RZ_NONNULL RzPVector *pvec1, RZ_NONNULL RzPVector *pvec2) {
	rz_return_val_if_fail(pvec1 && pvec2, 0);

	if (rz_pvector_empty(pvec2)) {
		return false;
	}

	if (pvec1->v.len + pvec2->v.len > pvec1->v.capacity) {
		RzVector *vec = &pvec1->v;
		RESIZE_OR_RETURN_NULL(RZ_MAX(NEXT_VECTOR_CAPACITY, pvec1->v.len + pvec2->v.len));
	}
	memmove((void **)pvec1->v.a + pvec1->v.len, pvec2->v.a, pvec2->v.elem_size * pvec2->v.len);
	pvec1->v.len += pvec2->v.len;

	// element in pvec2 is freed by pvec1
	pvec2->v.len = 0;

	return true;
}

/**
 * \brief Assign the pointer \p ptr at \p index in the pvector.
 *
 * \param vec The pvector to assign to.
 * \param index The index to assign the pointer to.
 * \param ptr The pointer to assign.
 *
 * \return The pointer stored at \p index before. Or NULL in case of failure.
 */
RZ_API void *rz_pvector_assign_at(RZ_BORROW RZ_NONNULL RzPVector *vec, size_t index, RZ_OWN RZ_NONNULL void *ptr) {
	rz_return_val_if_fail(vec && ptr, NULL);
	void **p = rz_vector_index_ptr(&vec->v, index);
	if (!p) {
		if (vec->v.free_user) {
			RzPVectorFree free_fn = (RzPVectorFree)vec->v.free_user;
			free_fn(ptr);
		}
		return NULL;
	}
	void *prev = *p;
	rz_vector_assign_at(&vec->v, index, ptr);
	return prev;
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

	size_t index = (el - (void **)vec->v.a) * sizeof(void **) / vec->v.elem_size;
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
static void quick_sort(void **a, size_t n, RzPVectorComparator cmp, void *user) {
	if (n <= 1) {
		return;
	}
	size_t i = rand() % n, j = 0;
	void *t, *pivot = a[i];
	a[i] = a[n - 1];
	for (i = 0; i < n - 1; i++) {
		if (cmp(a[i], pivot, user) < 0) {
			t = a[i];
			a[i] = a[j];
			a[j] = t;
			j++;
		}
	}
	a[n - 1] = a[j];
	a[j] = pivot;
	quick_sort(a, j, cmp, user);
	quick_sort(a + j + 1, n - j - 1, cmp, user);
}

RZ_API void rz_pvector_sort(RzPVector *vec, RzPVectorComparator cmp, void *user) {
	rz_return_if_fail(vec && cmp);
	if (rz_pvector_empty(vec)) {
		return;
	}
	quick_sort(vec->v.a, vec->v.len, cmp, user);
}

/**
 * \brief Find the unique values in the \p vec and push it in a new RzPVector.
 * \param vec the RzPVector to search in.
 * \param cmp the comparator function.
 * \param user the user data for \p cmp function.
 * \return Returns a new RzPVector which contains only unique values.
 */
RZ_API RZ_OWN RzPVector *rz_pvector_uniq(RZ_NONNULL const RzPVector *vec, RZ_NONNULL RzPVectorComparator cmp, void *user) {
	rz_return_val_if_fail(vec && cmp, NULL);

	RzPVector *npv = rz_pvector_new(NULL);
	if (!npv) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (vec, it) {
		bool found = false;
		void **it2;
		void *item = *it;
		rz_pvector_foreach (npv, it2) {
			void *item2 = *it2;
			if (cmp(item, item2, user) == 0) {
				found = true;
				break;
			}
		}
		if (!found) {
			rz_pvector_push(npv, item);
		}
	}
	return npv;
}
