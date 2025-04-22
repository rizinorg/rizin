#ifndef RZ_VECTOR_H
#define RZ_VECTOR_H

#include <rz_types.h>
#include <rz_util/rz_assert.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * RzVector can contain arbitrarily sized elements.
 * RzPVector uses RzVector internally and always contains void *s
 *
 * Thus, for storing pointers it is highly encouraged to always use RzPVector
 * as it is specifically made for this purpose and is more consistent with RzList,
 * while RzVector can be used as, for example, a flat array of a struct.
 *
 * Notable differences between RzVector and RzPVector:
 * -------------------------------------------------
 * When RzVector expects an element to be inserted, for example in rz_vector_push(..., void *x),
 * this void * value is interpreted as a pointer to the actual data for the element.
 * => If you use RzVector as a dynamic replacement for (struct SomeStruct)[], you will
 * pass a struct SomeStruct * to these functions.
 *
 * Because RzPVector only handles pointers, the given void * is directly interpreted as the
 * actual pointer to be inserted.
 * => If you use RzPVector as a dynamic replacement for (SomeType *)[], you will pass
 * SomeType * directly to these functions.
 *
 * The same differentiation goes for the free functions:
 * - The element parameter in RzVectorFree is a pointer to the element inside the array.
 * - The element parameter in RzPVectorFree is the actual pointer stored in the array.
 *
 * General Hint:
 * -------------
 * remove/pop functions do not reduce the capacity.
 * Call rz_(p)vector_shrink explicitly if desired.
 */

// RzPVectorComparator should return negative, 0, positive to indicate "value < vec_data", "value == vec_data", "value > vec_data".
typedef int (*RzPVectorComparator)(const void *value, const void *vec_data, void *user);
typedef int (*RzVectorComparator)(const void *a, const void *b, void *user);
typedef void (*RzVectorFree)(void *e, void *user);
typedef void (*RzPVectorFree)(void *e);

typedef struct rz_vector_t {
	void *a;
	size_t len;
	size_t capacity;
	size_t elem_size;
	RzVectorFree free;
	void *free_user;
} RzVector;

// RzPVector directly wraps RzVector for type safety
typedef struct rz_pvector_t {
	RzVector v;
} RzPVector;

// RzVector

RZ_API void rz_vector_init(RzVector *vec, size_t elem_size, RzVectorFree free, void *free_user);

RZ_API RzVector *rz_vector_new(size_t elem_size, RzVectorFree free, void *free_user);

// clears the vector and calls vec->free on every element if set.
RZ_API void rz_vector_fini(RzVector *vec);

// frees the vector and calls vec->free on every element if set.
RZ_API void rz_vector_free(RzVector *vec);

typedef void (*RzVectorItemCpyFunc)(void *, void *);
typedef void (*RzPVectorItemCpyFunc)(void *, void *);

RZ_API bool rz_vector_clone_intof(
	RZ_NONNULL RZ_BORROW RZ_OUT RzVector *dst,
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *src,
	RZ_NULLABLE const RzVectorItemCpyFunc item_cpy);
RZ_API RZ_OWN RzVector *rz_vector_clonef(
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *vec,
	RZ_NULLABLE const RzVectorItemCpyFunc item_cpy);
RZ_API bool rz_vector_clone_into(
	RZ_NONNULL RZ_BORROW RZ_OUT RzVector *dst,
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *src);
RZ_API RZ_OWN RzVector *rz_vector_clone(
	RZ_NONNULL RZ_BORROW RZ_IN const RzVector *vec);

static inline bool rz_vector_empty(const RzVector *vec) {
	rz_return_val_if_fail(vec, false);
	return vec->len == 0;
}

RZ_API void rz_vector_clear(RzVector *vec);

// returns the length of the vector
static inline size_t rz_vector_len(const RzVector *vec) {
	rz_return_val_if_fail(vec, 0);
	return vec->len;
}

// returns a pointer to the offset inside the array where the element of the index lies.
static inline void *rz_vector_index_ptr(const RzVector *vec, size_t index) {
	rz_return_val_if_fail(vec && index < vec->capacity, NULL);
	return (char *)vec->a + vec->elem_size * index;
}

// returns a pointer to the first element of the vector
static inline void *rz_vector_head(const RzVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	return (void *)vec->a;
}

// returns a pointer to the last element of the vector
static inline void *rz_vector_tail(RzVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	if (vec->len < 1) {
		return NULL;
	}
	return (char *)vec->a + vec->elem_size * (vec->len - 1);
}

// helper function to assign an element of size vec->elem_size from elem to p.
// elem is a pointer to the actual data to assign!
RZ_API void rz_vector_assign(RzVector *vec, void *p, void *elem);

// assign the value of size vec->elem_size at elem to vec at the given index.
// elem is a pointer to the actual data to assign!
RZ_API void *rz_vector_assign_at(RzVector *vec, size_t index, void *elem);

// remove the element at the given index and write the content to into.
// It is the caller's responsibility to free potential resources associated with the element.
RZ_API void rz_vector_remove_at(RzVector *vec, size_t index, void *into);

/**
 * remove all elements in the given range and write the contents to into (must be appropriately large).
 * It is the caller's responsibility to free potential resources associated with the elements.
 */
RZ_API void rz_vector_remove_range(RzVector *vec, size_t index, size_t count, void *into);

// insert the value of size vec->elem_size at x at the given index.
// x is a pointer to the actual data to assign!
RZ_API void *rz_vector_insert(RzVector *vec, size_t index, void *x);

// insert count values of size vec->elem_size into vec starting at the given index.
RZ_API void *rz_vector_insert_range(RzVector *vec, size_t index, void *first, size_t count);

// like rz_vector_remove_at for the last element
RZ_API void rz_vector_pop(RzVector *vec, void *into);

// like rz_vector_remove_at for the first element
RZ_API void rz_vector_pop_front(RzVector *vec, void *into);

// like rz_vector_insert for the end of vec
RZ_API void *rz_vector_push(RzVector *vec, void *x);

// like rz_vector_insert for the beginning of vec
RZ_API void *rz_vector_push_front(RzVector *vec, void *x);

/**
 * \brief Swap two elements of the vector
 * \param index_a index of the first element to swap
 * \param index_b index of the second element to swap
 * \return true if the swap succeeded
 **/
RZ_API bool rz_vector_swap(RzVector *vec, size_t index_a, size_t index_b);

// make sure the capacity is at least capacity.
RZ_API void *rz_vector_reserve(RzVector *vec, size_t capacity);

// shrink capacity to len.
RZ_API void *rz_vector_shrink(RzVector *vec);

/**
 * \brief Turn the vector into a fixed-size array.
 * This will clear the vector and return an array of its original contents whose
 * ownership is transferred to the caller.
 * This is useful when RzVector is used for its dynamically growing functionality as an
 * intermediate step to generate a fixed-size array in the end.
 */
RZ_API void *rz_vector_flush(RzVector *vec);

// sort vector
RZ_API void rz_vector_sort(RzVector *vec, RzVectorComparator cmp, bool reverse, void *user);

/*
 * example:
 *
 * RzVector *v = ...; // <contains MyStruct>
 * MyStruct *it;
 * rz_vector_foreach (v, it) {
 *     // Do something with it
 * }
 */
#define rz_vector_foreach(vec, it) \
	if (!rz_vector_empty(vec)) \
		for (it = (void *)(vec)->a; (char *)it != (char *)(vec)->a + ((vec)->len * (vec)->elem_size); it = (void *)((char *)it + (vec)->elem_size))

#define rz_vector_foreach_prev(vec, it) \
	if (!rz_vector_empty(vec)) \
		for (it = (void *)((char *)(vec)->a + (((vec)->len - 1) * (vec)->elem_size)); (char *)it != (char *)(vec)->a - (vec)->elem_size; it = (void *)((char *)it - (vec)->elem_size))

#define rz_vector_enumerate(vec, it, i) \
	if (!rz_vector_empty(vec)) \
		for (it = (void *)(vec)->a, i = 0; i < (vec)->len; it = (void *)((char *)it + (vec)->elem_size), i++)

/*
 * example:
 *
 * RzVector *v = ...; // contains {(st64)0, (st64)2, (st64)4, (st64)6, (st64)8};
 * size_t l;
 * #define CMP(x, y) x - (*(st64 *)y)
 * rz_vector_lower_bound (v, 3, l, CMP);
 * // l == 2
 */
#define rz_vector_lower_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if ((cmp(x, ((char *)(vec)->a + (vec)->elem_size * m))) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0)

#define rz_vector_upper_bound(vec, x, i, cmp) \
	do { \
		size_t h = (vec)->len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if ((cmp(x, ((char *)(vec)->a + (vec)->elem_size * m))) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0)

// RzPVector

RZ_API void rz_pvector_init(RzPVector *vec, RzPVectorFree free);
RZ_API void rz_pvector_fini(RzPVector *vec);

RZ_API RzPVector *rz_pvector_new(RzPVectorFree free);

RZ_API RzPVector *rz_pvector_new_with_len(RzPVectorFree free, size_t length);

// clear the vector and call vec->v.free on every element.
RZ_API void rz_pvector_clear(RzPVector *vec);

// free the vector and call vec->v.free on every element.
RZ_API void rz_pvector_free(RzPVector *vec);

/// See rz_vector_clone() for detailed semantics
static inline RzPVector *rz_pvector_clone(RzPVector *vec) {
	return (RzPVector *)rz_vector_clone(&vec->v);
}

static inline RzPVector *rz_pvector_clonef(RzPVector *vec, RzPVectorItemCpyFunc item_cpy) {
	return (RzPVector *)rz_vector_clonef(&vec->v, item_cpy);
}

static inline size_t rz_pvector_len(const RzPVector *vec) {
	if (!vec) {
		return 0;
	}
	return vec->v.len;
}

static inline void *rz_pvector_at(const RzPVector *vec, size_t index) {
	rz_return_val_if_fail(vec, NULL);
	if (index >= vec->v.len) {
		return NULL;
	}
	return ((void **)vec->v.a)[index];
}

static inline void rz_pvector_set(RzPVector *vec, size_t index, void *e) {
	rz_return_if_fail(vec && index < vec->v.len);
	((void **)vec->v.a)[index] = e;
}

static inline bool rz_pvector_empty(const RzPVector *vec) {
	return rz_pvector_len(vec) == 0;
}

// same as rz_pvector_index_ptr(<vec>, 0)
static inline void **rz_pvector_data(RzPVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	return (void **)vec->v.a;
}

// returns the first element of the vector
static inline void *rz_pvector_head(RzPVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	if (vec->v.len < 1) {
		return NULL;
	}
	return ((void **)vec->v.a)[0];
}

// returns the last element of the vector
static inline void *rz_pvector_tail(RzPVector *vec) {
	rz_return_val_if_fail(vec, NULL);
	if (vec->v.len < 1) {
		return NULL;
	}
	return ((void **)vec->v.a)[vec->v.len - 1];
}

// returns the respective pointer inside the vector if x is found or NULL otherwise.
RZ_API void **rz_pvector_contains(RzPVector *vec, const void *x);

// find the element in the vec based on cmparator
RZ_API RZ_BORROW void **rz_pvector_find(RZ_NONNULL const RzPVector *vec, RZ_NONNULL const void *element, RZ_NONNULL RzPVectorComparator cmp, void *user);

// join two pvector into one, pvec1 should free the joined element in pvec2
RZ_API bool rz_pvector_join(RZ_NONNULL RzPVector *pvec1, RZ_NONNULL RzPVector *pvec2);

RZ_API void *rz_pvector_assign_at(RZ_BORROW RZ_NONNULL RzPVector *vec, size_t index, RZ_OWN RZ_NONNULL void *ptr);

// removes and returns the pointer at the given index. Does not call free.
RZ_API void *rz_pvector_remove_at(RzPVector *vec, size_t index);

// removes the element x, if present. Does not call free.
RZ_API void rz_pvector_remove_data(RzPVector *vec, void *x);

// like rz_vector_insert, but the pointer x is the actual data to be inserted.
static inline void **rz_pvector_insert(RzPVector *vec, size_t index, void *x) {
	return (void **)rz_vector_insert(&vec->v, index, &x);
}

// like rz_vector_insert_range.
static inline void **rz_pvector_insert_range(RzPVector *vec, size_t index, void **first, size_t count) {
	return (void **)rz_vector_insert_range(&vec->v, index, first, count);
}

// like rz_vector_pop, but returns the pointer directly.
RZ_API void *rz_pvector_pop(RzPVector *vec);

// like rz_vector_pop_front, but returns the pointer directly.
RZ_API void *rz_pvector_pop_front(RzPVector *vec);

// like rz_vector_push, but the pointer x is the actual data to be inserted.
static inline void **rz_pvector_push(RzPVector *vec, void *x) {
	return (void **)rz_vector_push(&vec->v, &x);
}

// like rz_vector_push_front, but the pointer x is the actual data to be inserted.
static inline void **rz_pvector_push_front(RzPVector *vec, void *x) {
	return (void **)rz_vector_push_front(&vec->v, &x);
}

// sort vec using quick sort.
RZ_API void rz_pvector_sort(RzPVector *vec, RzPVectorComparator cmp, void *user);

static inline void **rz_pvector_reserve(RzPVector *vec, size_t capacity) {
	return (void **)rz_vector_reserve(&vec->v, capacity);
}

static inline void **rz_pvector_shrink(RzPVector *vec) {
	return (void **)rz_vector_shrink(&vec->v);
}

static inline void **rz_pvector_flush(RzPVector *vec) {
	return (void **)rz_vector_flush(&vec->v);
}

/*
 * example:
 *
 * RzPVector *v = ...;
 * void **it;
 * rz_pvector_foreach (v, it) {
 *     void *p = *it;
 *     // Do something with p
 * }
 */
#define rz_pvector_foreach(vec, it) \
	if (!rz_pvector_empty(vec)) \
		for (it = (void **)(vec)->v.a; (vec)->v.len && it != (void **)(vec)->v.a + (vec)->v.len; it++)

// like rz_pvector_foreach() but inverse
#define rz_pvector_foreach_prev(vec, it) \
	if (!rz_pvector_empty(vec)) \
		for (it = ((vec)->v.len == 0 ? NULL : (void **)(vec)->v.a + (vec)->v.len - 1); it && it != (void **)(vec)->v.a - 1; it--)

/**
 * \brief Like rz_pvector_foreach() but with index
 */
#define rz_pvector_enumerate(vec, it, idx) \
	if (!rz_pvector_empty(vec)) \
		for (it = (void **)(vec)->v.a, idx = 0; idx < (vec)->v.len; it++, idx++)

/*
 * \brief Find the index of the least element greater than or equal to the lower bound x using binary search
 * example:
 *
 * st64 a[] = { 0, 2, 4, 6, 8 };
 * size_t index;
 * #define CMP(x, y) x - y
 * rz_pvector_lower_bound (v, 3, index, CMP);
 * // index == 2 (contains value 4)
 */
#define rz_array_lower_bound(array, len, x, i, cmp) \
	do { \
		size_t h = len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if (cmp((x), ((array)[m])) > 0) { \
				i = m + 1; \
			} else { \
				h = m; \
			} \
		} \
	} while (0)

/*
 * \brief Find the index of the least element greater than the upper bound x using binary search
 * example:
 *
 * st64 a[] = { 0, 2, 4, 6, 8 };
 * size_t index;
 * #define CMP(x, y) x - y
 * rz_pvector_lower_bound (v, 2, index, CMP);
 * // index == 2 (contains value 4)
 */
#define rz_array_upper_bound(array, len, x, i, cmp) \
	do { \
		size_t h = len, m; \
		for (i = 0; i < h;) { \
			m = i + ((h - i) >> 1); \
			if (cmp((x), ((array)[m])) < 0) { \
				h = m; \
			} else { \
				i = m + 1; \
			} \
		} \
	} while (0)

/**
 * \brief Find an element elem in the \p array,
 * lying within \p start and \p stop index such that \p cmp(x, elem) == 0
 * The index of the element elem is stored in \p itr
 * If \p itr == \p stop, then no such element was found
 */
#define rz_array_find(array, x, itr, start, stop, cmp) \
	do { \
		for (itr = start; itr < stop; itr++) { \
			if (cmp((array[itr]), x) == 0) { \
				break; \
			} \
		} \
		return itr; \
	} while (0)

/*
 * example:
 *
 * RzPVector *v = ...; // contains {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
 * size_t index;
 * #define CMP(x, y) x - y
 * rz_pvector_lower_bound (v, (void *)2, index, CMP);
 * // index == 1
 */
#define rz_pvector_lower_bound(vec, x, i, cmp) \
	rz_array_lower_bound((void **)(vec)->v.a, (vec)->v.len, x, i, cmp)

/*
 * example:
 *
 * RzPVector *v = ...; // contains {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
 * size_t index;
 * #define CMP(x, y) x - y
 * rz_pvector_upper_bound (v, (void *)2, index, CMP);
 * // index == 2
 */
#define rz_pvector_upper_bound(vec, x, i, cmp) \
	rz_array_upper_bound((void **)(vec)->v.a, (vec)->v.len, x, i, cmp)

#ifdef __cplusplus
}
#endif

#endif
