#ifndef RZ_QUEUE_H
#define RZ_QUEUE_H

#include <rz_types.h>
#include <rz_vector.h>

typedef RzPVector RzPQueue;
typedef RzPVectorFree RzPQueueFree;

static inline void rz_pqueue_init(RzPQueue *q, RzPQueueFree free) {
	rz_pvector_init(q, free);
}

static inline void rz_pqueue_fini(RzPQueue *q) {
	rz_pvector_fini(q);
}

static inline RzPQueue *rz_pqueue_new(RzPQueueFree free) {
	return rz_pvector_new(free);
}

// clear the vector and call vec->v.free on every element.
static inline void rz_pqueue_clear(RzPQueue *q) {
	rz_pvector_clear(q);
}

// free the vector and call vec->v.free on every element.
static inline void rz_pqueue_free(RzPQueue *q) {
	rz_pvector_free(q);
}

/// See rz_vector_clone() for detailed semantics
static inline RzPQueue *rz_pqueue_clone(RzPQueue *q) {
	return (RzPQueue *)rz_vector_clone(&q->v);
}

static inline size_t rz_pqueue_len(const RzPQueue *q) {
	rz_return_val_if_fail(q, 0);
	return q->v.len;
}

static inline void *rz_pqueue_at(const RzPQueue *q, size_t index) {
	rz_return_val_if_fail(q && index < q->v.len, NULL);
	return ((void **)q->v.a)[index];
}

static inline void rz_pqueue_set(RzPQueue *q, size_t index, void *e) {
	rz_return_if_fail(q && index < q->v.len);
	((void **)q->v.a)[index] = e;
}

static inline bool rz_pqueue_empty(RzPQueue *q) {
	return rz_pqueue_len(q) == 0;
}

// returns a pointer to the offset inside the array where the element of the index lies.
static inline void **rz_pqueue_index_ptr(RzPQueue *q, size_t index) {
	rz_return_val_if_fail(q && index < q->v.capacity, NULL);
	return ((void **)q->v.a) + index;
}

// same as rz_pqueue_index_ptr(<vec>, 0)
static inline void **rz_pqueue_data(RzPQueue *q) {
	rz_return_val_if_fail(q, NULL);
	return (void **)q->v.a;
}

// returns the first element of the vector
static inline void *rz_pqueue_head(RzPQueue *q) {
	rz_return_val_if_fail(q, NULL);
	return ((void **)q->v.a)[0];
}

// returns the last element of the vector
static inline void *rz_pqueue_tail(RzPQueue *q) {
	rz_return_val_if_fail(q, NULL);
	return ((void **)q->v.a)[q->v.len - 1];
}

// returns the respective pointer inside the vector if x is found or NULL otherwise.
static inline void **rz_pqueue_contains(RzPQueue *q, const void *x) {
	return rz_pvector_contains(q, x);
}

// like rz_vector_pop_front, but returns the pointer directly.
static inline void *rz_pqueue_dequeue(RzPQueue *q) {
	return rz_pvector_pop_front(q);
}

// like rz_vector_push, but the pointer x is the actual data to be inserted.
static inline void **rz_pqueue_enqueue(RzPQueue *q, void *x) {
	return (void **)rz_pvector_push(q, x);
}

static inline void **rz_pqueue_reserve(RzPQueue *q, size_t capacity) {
	return (void **)rz_pvector_reserve(q, capacity);
}

static inline void **rz_pqueue_shrink(RzPQueue *q) {
	return (void **)rz_pvector_shrink(q);
}

static inline void **rz_pqueue_flush(RzPQueue *q) {
	return (void **)rz_pvector_flush(q);
}

/*
 * example:
 *
 * RzPQueue *v = ...;
 * void **it;
 * rz_pqueue_foreach (v, it) {
 *     void *p = *it;
 *     // Do something with p
 * }
 */
#define rz_pqueue_foreach(q, it) \
	for (it = (void **)(q)->v.a; (q)->v.len && it != (void **)(q)->v.a + (q)->v.len; it++)

// like rz_pqueue_foreach() but inverse
#define rz_pqueue_foreach_prev(q, it) \
	for (it = ((q)->v.len == 0 ? NULL : (void **)(q)->v.a + (q)->v.len - 1); it && it != (void **)(q)->v.a - 1; it--)

/*
 * example:
 *
 * RzPQueue *v = ...; // contains {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
 * size_t index;
 * #define CMP(x, y) x - y
 * rz_pqueue_lower_bound (v, (void *)2, index, CMP);
 * // index == 1
 */
#define rz_pqueue_lower_bound(vec, x, i, cmp) \
	rz_array_lower_bound((void **)(vec)->v.a, (vec)->v.len, x, i, cmp)

/*
 * example:
 *
 * RzPQueue *v = ...; // contains {(void*)0, (void*)2, (void*)4, (void*)6, (void*)8};
 * size_t index;
 * #define CMP(x, y) x - y
 * rz_pqueue_upper_bound (v, (void *)2, index, CMP);
 * // index == 2
 */
#define rz_pqueue_upper_bound(vec, x, i, cmp) \
	rz_array_upper_bound((void **)(vec)->v.a, (vec)->v.len, x, i, cmp)

#endif // RZ_QUEUE_H
