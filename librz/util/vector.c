// SPDX-FileCopyrightText: 2017-2020 maskray <i@maskray.me>
// SPDX-FileCopyrightText: 2017-2020 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_assert.h"
#include "rz_vector.h"

// Optimize memory usage on glibc
#define INITIAL_VECTOR_LEN 8

#define NEXT_VECTOR_CAPACITY (vec->capacity < INITIAL_VECTOR_LEN \
		? INITIAL_VECTOR_LEN \
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
	if (vec->free && vec->len > 0) {
		while (vec->len > 0) {
			vec->free((char *)vec->a + vec->elem_size * (--vec->len), vec->free_user);
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

/**
 * \brief Removes all elements, frees the internal buffer, and
 * sets the vector's capacity to 0.
 *
 * Use rz_vector_purge() if the buffer's capacity should not change.
 */
RZ_API void rz_vector_clear(RZ_BORROW RzVector *vec) {
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

static RZ_INLINE void rz_vector_assign(RzVector *vec, void *p, const void *elem) {
	memcpy(p, elem, vec->elem_size);
}

/**
 * \brief Set element at \p index.
 * This is a simple memcpy. Vector length is not updated.
 * Use rz_vector_assign_at() if this is needed.
 *
 * \param vec The vector to update.
 * \param index Index where to write the element to.
 * \param elem Pointer to the element to copy.
 */
RZ_API void rz_vector_set(RZ_BORROW RzVector *vec, size_t index, const RZ_NONNULL void *elem) {
	rz_return_if_fail(vec && index < rz_vector_capacity(vec) && elem);
	void *p = rz_vector_index_ptr(vec, index);
	rz_return_if_fail(p);
	rz_vector_assign(vec, p, elem);
}

/**
 * \brief Set \p n elements, starting at element \p i to \p c.
 */
static void rz_vector_zeroize(RzVector *vec, size_t i, size_t n) {
	rz_return_if_fail(vec);
	memset((ut8 *)vec->a + (vec->elem_size * i), 0, vec->elem_size * n);
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
	if (item_cpy) {
		dst->free = src->free;
		dst->free_user = src->free_user;
	} else {
		dst->free = NULL;
		dst->free_user = NULL;
	}
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
	if (!dst) {
		return NULL;
	}
	dst->free = NULL;
	dst->free_user = NULL;
	return dst;
}

/**
 * \brief Assign the element \p elem at \p index in the vector.
 *
 * NOTE: This function can update the length of the vector. If the index
 * points after the last element, but not beyond the vector's capacity, it
 * sets the vector length to \p index + 1. Elements at [len, index) are set to zero.
 * Use rz_vector_set() if you need sideeffect-less manipulation of the vector slots.
 *
 * \param vec The vector to assign to.
 * \param index The index to assign the element to.
 * \param elem Pointer to the element to assign. If NULL, only the vector length is updated under the above condition.
 *
 * \return Pointer to the element at \p index. Or NULL in case of failure.
 */
RZ_API void *rz_vector_assign_at(RZ_BORROW RzVector *vec, size_t index, RZ_NULLABLE const void *elem) {
	rz_return_val_if_fail(vec && index < vec->capacity, NULL);
	void *p = rz_vector_index_ptr(vec, index);
	if (elem) {
		rz_vector_assign(vec, p, elem);
	}
	if (index >= rz_vector_len(vec)) {
		size_t len = rz_vector_len(vec);
		// Also zero the slot at index, if no element is assigned to it.
		size_t n = index - len + (!elem ? 1 : 0);
		rz_vector_zeroize(vec, len, n);
		vec->len = index + 1;
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

/**
 * \brief remove all elements in the given range and write the contents to into (must be appropriately large).
 * It is the caller's responsibility to free potential resources associated with the elements.
 */
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

/**
 * \brief Deletes all elements in the vector. The internal buffer is not freed
 * so the vector's capacity stays the same.
 *
 * Use rz_vector_clear() if the buffer should be freed.
 */
RZ_API void rz_vector_purge(RZ_BORROW RzVector *vec) {
	vector_free_elems(vec);
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

static bool bin_search_range(RZ_NONNULL RzVector *vec, RZ_NONNULL void *elem, RzVectorComparator cmp, void *user, RZ_OUT size_t *i) {
	size_t vlen = rz_vector_len(vec);
	if (vlen == 0) {
		*i = 0;
		return false;
	}

	size_t left = 0;
	size_t right = vlen;

	while (left < right) {
		size_t mid = left + (right - left) / 2;
		int cmp_res = cmp(elem, rz_vector_index_ptr(vec, mid), user);

		if (cmp_res == 0) {
			*i = mid;
			return true;
		}

		if (vec->reverse_sorted) {
			if (cmp_res > 0) {
				right = mid;
			} else {
				left = mid + 1;
			}
		} else {
			if (cmp_res > 0) {
				left = mid + 1;
			} else {
				right = mid;
			}
		}
	}

	*i = left;
	return false;
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

	size_t len = rz_vector_len(vec);
	if (len < 1) {
		return rz_vector_push(vec, elem);
	}

	size_t insert_index = 0;

	bin_search_range(vec, elem, cmp, user, &insert_index);

	return rz_vector_insert(vec, insert_index, elem);
}

/**
 * \brief Finds an element in the sorted vector via binary search.
 * NOTE: This function assumes the vector is already sorted!
 * If it isn't the result is undefined!
 *
 * \param vec A sorted vector to find the element in.
 * \param elem Pointer to the element to find in the vector.
 * \param cmp The comparator for the elements.
 * \param user The user data passed to the comparator.
 *
 * \return Index into the vector where the element is located.
 * Or SZT_MAX in case of failure or if no element was found.
 */
RZ_API size_t rz_vector_find_sorted(RZ_NONNULL RzVector *vec, RZ_NONNULL void *elem, RzVectorComparator cmp, void *user) {
	rz_return_val_if_fail(vec && elem, SZT_MAX);

	size_t i;
	if (!bin_search_range(vec, elem, cmp, user, &i)) {
		return SZT_MAX;
	}
	return i;
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
	if (RZ_UNLIKELY(!vec)) {
		return NULL;
	}
	if (RZ_LIKELY(vec->len < vec->capacity)) {
		void *p = (char *)vec->a + vec->elem_size * vec->len++;
		if (x) {
			memcpy(p, x, vec->elem_size);
		}
		return p;
	}
	RESIZE_OR_RETURN_NULL(NEXT_VECTOR_CAPACITY);
	void *p = (char *)vec->a + vec->elem_size * vec->len++;
	if (x) {
		memcpy(p, x, vec->elem_size);
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

/**
 * \brief Swap two elements of the vector
 * \param index_a index of the first element to swap
 * \param index_b index of the second element to swap
 * \return true if the swap succeeded
 **/
RZ_API bool rz_vector_swap(RzVector *vec, size_t index_a, size_t index_b) {
	rz_return_val_if_fail(vec && index_a < vec->len && index_b < vec->len, false);
	if (index_a == index_b) {
		return true;
	}
	ut8 stack_tmp[256];
	void *tmp = vec->elem_size <= sizeof(stack_tmp) ? stack_tmp : malloc(vec->elem_size);
	if (!tmp) {
		return false;
	}
	void *elem_a = rz_vector_index_ptr(vec, index_a);
	void *elem_b = rz_vector_index_ptr(vec, index_b);
	memcpy(tmp, elem_a, vec->elem_size);
	memcpy(elem_a, elem_b, vec->elem_size);
	memcpy(elem_b, tmp, vec->elem_size);
	if (tmp != stack_tmp) {
		free(tmp);
	}
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

/**
 * \brief Turn the vector into a fixed-size array.
 * This will clear the vector and return an array of its original contents whose
 * ownership is transferred to the caller.
 * This is useful when RzVector is used for its dynamically growing functionality as an
 * intermediate step to generate a fixed-size array in the end.
 */
RZ_API RZ_OWN void *rz_vector_take_array(RZ_BORROW RzVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	rz_vector_shrink(vec);
	void *r = vec->a;
	vec->a = NULL;
	vec->capacity = vec->len = 0;
	return r;
}

// CLRS Quicksort. It is slow, but simple.
#define VEC_INDEX(a, i) ((char *)(a) + elem_size * (i))

static void rz_vector_swap_elems(void *a, void *b, size_t elem_size, void *tmp) {
	memcpy(tmp, a, elem_size);
	memcpy(a, b, elem_size);
	memcpy(b, tmp, elem_size);
}

static inline int ilog2(size_t n) {
	int r = 0;
	while (n >>= 1) {
		r++;
	}
	return r;
}

static void insertion_sort(void *a, size_t elem_size, size_t len, RzVectorComparator cmp, bool reverse, void *user, void *tmp) {
	for (size_t i = 1; i < len; i++) {
		memcpy(tmp, VEC_INDEX(a, i), elem_size);
		size_t j = i;
		while (j > 0) {
			int c = cmp(VEC_INDEX(a, j - 1), tmp, user);
			if ((!reverse && c <= 0) || (reverse && c >= 0)) {
				break;
			}
			memcpy(VEC_INDEX(a, j), VEC_INDEX(a, j - 1), elem_size);
			j--;
		}
		memcpy(VEC_INDEX(a, j), tmp, elem_size);
	}
}

static void heap_sift_down(void *a, size_t elem_size, size_t start, size_t end, RzVectorComparator cmp, bool reverse, void *user, void *tmp) {
	size_t root = start;
	while (root * 2 + 1 <= end) {
		size_t child = root * 2 + 1;
		size_t swap = root;
		int c = cmp(VEC_INDEX(a, swap), VEC_INDEX(a, child), user);
		if ((!reverse && c < 0) || (reverse && c > 0)) {
			swap = child;
		}
		if (child + 1 <= end) {
			c = cmp(VEC_INDEX(a, swap), VEC_INDEX(a, child + 1), user);
			if ((!reverse && c < 0) || (reverse && c > 0)) {
				swap = child + 1;
			}
		}
		if (swap == root) {
			return;
		}
		memcpy(tmp, VEC_INDEX(a, root), elem_size);
		memcpy(VEC_INDEX(a, root), VEC_INDEX(a, swap), elem_size);
		memcpy(VEC_INDEX(a, swap), tmp, elem_size);
		root = swap;
	}
}

static void heap_sort(void *a, size_t elem_size, size_t len, RzVectorComparator cmp, bool reverse, void *user, void *tmp) {
	if (len <= 1) {
		return;
	}
	for (ssize_t start = (len - 2) / 2; start >= 0; start--) {
		heap_sift_down(a, elem_size, (size_t)start, len - 1, cmp, reverse, user, tmp);
	}
	for (size_t end = len - 1; end > 0; end--) {
		memcpy(tmp, VEC_INDEX(a, end), elem_size);
		memcpy(VEC_INDEX(a, end), VEC_INDEX(a, 0), elem_size);
		memcpy(VEC_INDEX(a, 0), tmp, elem_size);
		heap_sift_down(a, elem_size, 0, end - 1, cmp, reverse, user, tmp);
	}
}

static void introsort_impl(void *a, size_t elem_size, size_t len, RzVectorComparator cmp, bool reverse, void *user, int depth_limit, void *t, void *pivot) {
	while (len > 16) {
		if (depth_limit == 0) {
			heap_sort(a, elem_size, len, cmp, reverse, user, t);
			return;
		}
		depth_limit--;

		// Use median-of-three for pivot selection
		size_t mid = len / 2;
		if ((cmp(VEC_INDEX(a, 0), VEC_INDEX(a, mid), user) < 0) != reverse) {
			rz_vector_swap_elems(VEC_INDEX(a, 0), VEC_INDEX(a, mid), elem_size, t);
		}
		if ((cmp(VEC_INDEX(a, 0), VEC_INDEX(a, len - 1), user) < 0) != reverse) {
			rz_vector_swap_elems(VEC_INDEX(a, 0), VEC_INDEX(a, len - 1), elem_size, t);
		}
		if ((cmp(VEC_INDEX(a, mid), VEC_INDEX(a, len - 1), user) < 0) != reverse) {
			rz_vector_swap_elems(VEC_INDEX(a, mid), VEC_INDEX(a, len - 1), elem_size, t);
		}
		// Median is now at mid, use it as pivot
		memcpy(pivot, VEC_INDEX(a, mid), elem_size);

		// Partition
		size_t i = 0, j = len - 1;
		while (i <= j) {
			while ((cmp(VEC_INDEX(a, i), pivot, user) < 0) != reverse) {
				i++;
			}
			while ((cmp(pivot, VEC_INDEX(a, j), user) < 0) != reverse) {
				j--;
			}
			if (i <= j) {
				rz_vector_swap_elems(VEC_INDEX(a, i), VEC_INDEX(a, j), elem_size, t);
				i++;
				if (j > 0) {
					j--;
				} else {
					break;
				}
			}
		}

		if (i < len - i) {
			introsort_impl(a, elem_size, i, cmp, reverse, user, depth_limit, t, pivot);
			a = VEC_INDEX(a, i);
			len = len - i;
		} else {
			introsort_impl(VEC_INDEX(a, i), elem_size, len - i, cmp, reverse, user, depth_limit, t, pivot);
			len = i;
		}
	}
}

static void vector_introsort(void *a, size_t elem_size, size_t len, RzVectorComparator cmp, bool reverse, void *user) {
	if (len <= 1) {
		return;
	}
	ut8 stack_buf[512];
	void *t = elem_size <= 256 ? stack_buf : malloc(elem_size * 2);
	if (!t) {
		return;
	}
	void *pivot = (char *)t + elem_size;
	int depth = 2 * ilog2(len);
	introsort_impl(a, elem_size, len, cmp, reverse, user, depth, t, pivot);
	insertion_sort(a, elem_size, len, cmp, reverse, user, t);
	if (t != stack_buf) {
		free(t);
	}
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
	vector_introsort(vec->a, vec->elem_size, vec->len, cmp, reverse, user);
}

/**
 * \brief Remove all elements where pred returns true.
 * \param vec The vector to filter.
 * \param pred The predicate function.
 * \param user The user data passed to the predicate.
 */
RZ_API void rz_vector_remove_if(RzVector *vec, bool (*pred)(const void *elem, void *user), void *user) {
	rz_return_if_fail(vec && pred);
	size_t write = 0;
	for (size_t read = 0; read < vec->len; read++) {
		void *elem = (char *)vec->a + vec->elem_size * read;
		if (pred(elem, user)) {
			if (vec->free) {
				vec->free(elem, vec->free_user);
			}
		} else {
			if (write != read) {
				memcpy((char *)vec->a + vec->elem_size * write, elem, vec->elem_size);
			}
			write++;
		}
	}
	vec->len = write;
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
	rz_vector_zeroize(&v->v, 0, v->v.capacity);
	v->v.len = length;
	return v;
}

/**
 * \brief Removes all elements and frees the internal buffer.
 */
RZ_API void rz_pvector_clear(RZ_BORROW RzPVector *vec) {
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

	void **arr = (void **)vec->v.a;
	size_t len = vec->v.len;
	for (size_t i = 0; i < len; i++) {
		if (RZ_LIKELY(i + 32 < len)) {
			RZ_PREFETCH(&arr[i + 32]);
		}
		if (!cmp(value, arr[i], user)) {
			return &arr[i];
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

	void **arr = (void **)vec->v.a;
	size_t len = vec->v.len;
	for (size_t i = 0; i < len; i++) {
		if (RZ_LIKELY(i + 32 < len)) {
			RZ_PREFETCH(&arr[i + 32]);
		}
		if (!cmp(value, arr[i], user)) {
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
 * \brief Assign the pointer \p ptr at \p index into the pvector.
 *
 * NOTE: This function can update the length of the vector. If the index
 * points after the last element, but not beyond the vector's capacity, it
 * sets the vector length to \p index + 1. Elements at [len, index) are set to zero.
 * Use rz_pvector_set() if you need sideeffect-less manipulation of the vector slots.
 *
 * \param vec The pvector to assign to.
 * \param index The index to assign the pointer to.
 * \param ptr The pointer to assign.
 *
 * \return The pointer stored at \p index before. NULL if index >= vec->len or in case of failure.
 */
RZ_API void *rz_pvector_assign_at(RZ_BORROW RZ_NONNULL RzPVector *vec, size_t index, RZ_OWN RZ_NULLABLE void *ptr) {
	rz_return_val_if_fail(vec, NULL);
	if (index >= rz_pvector_capacity(vec)) {
		if (vec->v.free_user && ptr) {
			RzPVectorFree free_fn = (RzPVectorFree)vec->v.free_user;
			free_fn(ptr);
		}
		return NULL;
	}
	bool increased_len = index >= rz_pvector_len(vec);
	void **p = rz_vector_index_ptr(&vec->v, index);
	void *prev = !p || increased_len ? NULL : *p;
	rz_vector_assign_at(&vec->v, index, &ptr);
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

typedef struct {
	RzPVectorComparator cmp;
	void *user;
} PVectorSortCtx;

static int pvector_introsort_cmp(const void *a, const void *b, void *user) {
	PVectorSortCtx *ctx = user;
	return ctx->cmp(*(void *const *)a, *(void *const *)b, ctx->user);
}

RZ_API void rz_pvector_sort(RzPVector *vec, RzPVectorComparator cmp, void *user) {
	rz_return_if_fail(vec && cmp);
	if (rz_pvector_empty(vec)) {
		return;
	}
	PVectorSortCtx ctx = { cmp, user };
	rz_vector_sort(&vec->v, pvector_introsort_cmp, false, &ctx);
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
	if (rz_pvector_empty(vec)) {
		return rz_pvector_new(NULL);
	}

	RzPVector *sorted = rz_pvector_new(NULL);
	if (!sorted) {
		return NULL;
	}
	void **it;
	rz_pvector_foreach (vec, it) {
		rz_pvector_push(sorted, *it);
	}
	rz_pvector_sort(sorted, cmp, user);

	RzPVector *npv = rz_pvector_new(NULL);
	if (!npv) {
		rz_pvector_free(sorted);
		return NULL;
	}

	void **arr = (void **)sorted->v.a;
	rz_pvector_push(npv, arr[0]);
	for (size_t i = 1; i < sorted->v.len; i++) {
		if (cmp(arr[i - 1], arr[i], user) != 0) {
			rz_pvector_push(npv, arr[i]);
		}
	}
	rz_pvector_free(sorted);
	return npv;
}
