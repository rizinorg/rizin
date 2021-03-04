// SPDX-FileCopyrightText: 2018 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_vector.h>
#include "minunit.h"

// allocates a vector of len ut32 values from 0 to len
// with capacity len + padding
static bool _init_test_vector(RzVector *v, size_t len, size_t padding, RzVectorFree free, void *free_user) {
	rz_vector_init(v, sizeof(ut32), free, free_user);
	rz_vector_reserve(v, len + padding);

	ut32 i;
	for (i = 0; i < len; i++) {
		rz_vector_push(v, &i);
	}

	return v->len == len && v->capacity == len + padding;
}

#define init_test_vector(v, len, padding, free, free_user) \
	{ \
		bool _r = _init_test_vector((v), (len), (padding), (free), (free_user)); \
		mu_assert("init_test_vector", _r); \
	}

// allocates a pvector of len pointers to ut32 values from 0 to len
// with capacity len + padding
static bool _init_test_pvector(RzPVector *v, size_t len, size_t padding) {
	rz_pvector_init(v, free);
	rz_pvector_reserve(v, len + padding);

	ut32 i;
	for (i = 0; i < len; i++) {
		ut32 *e = malloc(sizeof(ut32));
		*e = i;
		rz_pvector_push(v, e);
	}

	return v->v.len == len && v->v.capacity == len + padding;
}

#define init_test_pvector(v, len, padding) \
	{ \
		bool _r = _init_test_pvector((v), (len), (padding)); \
		mu_assert("init_test_pvector", _r); \
	}

// allocates a pvector of len pointers with values from 0 to len
// with capacity len + padding
static bool _init_test_pvector2(RzPVector *v, size_t len, size_t padding) {
	rz_pvector_init(v, NULL);
	rz_pvector_reserve(v, len + padding);

	int i;
	for (i = 0; (size_t)i < len; i++) {
		rz_pvector_push(v, (void *)((size_t)i));
	}

	return v->v.len == len && v->v.capacity == len + padding;
}

#define init_test_pvector2(v, len, padding) \
	{ \
		bool _r = _init_test_pvector2((v), (len), (padding)); \
		mu_assert("init_test_pvector2", _r); \
	}

static bool test_vector_fini(void) {
	RzVector v;
	rz_vector_init(&v, sizeof(void *), NULL, free);
	rz_vector_push(&v, &v);
	mu_assert_eq(v.elem_size, sizeof(void *), "init elem_size");
	mu_assert_eq(v.len, 1, "init len");
	mu_assert_notnull(v.a, "init a");
	mu_assert_null(v.free, "init free");
	mu_assert_eq(v.free_user, (void *)free, "init free_user");
	rz_vector_clear(&v);
	mu_assert_eq(v.elem_size, sizeof(void *), "init elem_size");
	mu_assert_eq(v.len, 0, "init len");
	mu_assert_null(v.a, "init a");
	mu_assert_eq(v.capacity, 0, "init capacity");
	mu_assert_null(v.free, "init free");
	mu_assert_eq(v.free_user, (void *)free, "init free_user");
	rz_vector_fini(&v);
	mu_assert_eq(v.elem_size, sizeof(void *), "init elem_size");
	mu_assert_eq(v.len, 0, "init len");
	mu_assert_null(v.a, "init a");
	mu_assert_eq(v.capacity, 0, "init capacity");
	mu_assert_null(v.free, "init free");
	mu_assert_null(v.free_user, "init free_user");
	mu_end;
}

static bool test_vector_init(void) {
	RzVector v;
	rz_vector_init(&v, 42, (void *)1337, (void *)42);
	mu_assert_eq(v.elem_size, 42UL, "init elem_size");
	mu_assert_eq(v.len, 0UL, "init len");
	mu_assert_null(v.a, "init a");
	mu_assert_eq(v.capacity, 0UL, "init capacity");
	mu_assert_eq(v.free, (void *)1337, "init free");
	mu_assert_eq(v.free_user, (void *)42, "init free_user");
	mu_end;
}

static bool test_vector_new(void) {
	RzVector *v = rz_vector_new(42, (void *)1337, (void *)42);
	mu_assert("new", v);
	mu_assert_eq(v->elem_size, 42UL, "new elem_size");
	mu_assert_eq(v->len, 0UL, "new len");
	mu_assert_null(v->a, "new a");
	mu_assert_eq(v->capacity, 0UL, "new capacity");
	mu_assert_eq(v->free, (void *)1337, "init free");
	mu_assert_eq(v->free_user, (void *)42, "init free_user");
	free(v);
	mu_end;
}

#define FREE_TEST_COUNT 10

static void elem_free_test(void *e, void *user) {
	ut32 e_val = *((ut32 *)e);
	int *acc = (int *)user;
	if (e_val > FREE_TEST_COUNT) {
		e_val = FREE_TEST_COUNT;
	}
	acc[e_val]++;
}

static bool test_vector_clear(void) {
	RzVector v;
	int acc[FREE_TEST_COUNT + 1] = { 0 };
	init_test_vector(&v, FREE_TEST_COUNT, 0, elem_free_test, acc);
	rz_vector_clear(&v);

	// see test_vector_free

	ut32 i;
	for (i = 0; i < FREE_TEST_COUNT; i++) {
		mu_assert_eq(acc[i], 1, "free individual elements");
	}

	mu_assert_eq(acc[FREE_TEST_COUNT], 0, "invalid free calls");
	mu_end;
}

static bool test_vector_free(void) {
	RzVector *v = rz_vector_new(4, NULL, NULL);
	int acc[FREE_TEST_COUNT + 1] = { 0 };
	init_test_vector(v, FREE_TEST_COUNT, 0, elem_free_test, acc);

	rz_vector_free(v);

	// elem_free_test does acc[i]++ for element value i
	// => acc[0] through acc[FREE_TEST_COUNT-1] == 1
	// acc[FREE_TEST_COUNT] is for potentially invalid calls of elem_free_test

	ut32 i;
	for (i = 0; i < FREE_TEST_COUNT; i++) {
		mu_assert_eq(acc[i], 1, "free individual elements");
	}

	mu_assert_eq(acc[FREE_TEST_COUNT], 0, "invalid free calls");
	mu_end;
}

static bool test_vector_clone(void) {
	RzVector v;
	init_test_vector(&v, 5, 0, NULL, NULL);
	RzVector *v1 = rz_vector_clone(&v);
	rz_vector_clear(&v);
	mu_assert("rz_vector_clone", v1);
	mu_assert_eq(v1->len, 5UL, "rz_vector_clone => len");
	mu_assert_eq(v1->capacity, 5UL, "rz_vector_clone => capacity");
	ut32 i;
	for (i = 0; i < 5; i++) {
		mu_assert_eq(*((ut32 *)rz_vector_index_ptr(v1, i)), i, "rz_vector_clone => content");
	}
	rz_vector_free(v1);

	init_test_vector(&v, 5, 5, NULL, NULL);
	v1 = rz_vector_clone(&v);
	rz_vector_clear(&v);
	mu_assert("rz_vector_clone (+capacity)", v1);
	mu_assert_eq(v1->len, 5UL, "rz_vector_clone (+capacity) => len");
	mu_assert_eq(v1->capacity, 10UL, "rz_vector_clone (+capacity) => capacity");
	for (i = 0; i < 5; i++) {
		mu_assert_eq(*((ut32 *)rz_vector_index_ptr(v1, i)), i, "rz_vector_clone => content");
	}
	// write over whole capacity to trigger potential errors with valgrind or asan
	for (i = 0; i < 10; i++) {
		*((ut32 *)rz_vector_index_ptr(v1, i)) = 1337;
	}
	rz_vector_free(v1);

	mu_end;
}

static bool test_vector_empty(void) {
	RzVector v;
	rz_vector_init(&v, 1, NULL, NULL);
	bool empty = rz_vector_empty(&v);
	mu_assert_eq(empty, true, "rz_vector_init => rz_vector_empty");
	uint8_t e = 0;
	rz_vector_push(&v, &e);
	empty = rz_vector_empty(&v);
	mu_assert_eq(empty, false, "rz_vector_push => !rz_vector_empty");
	rz_vector_pop(&v, &e);
	empty = rz_vector_empty(&v);
	mu_assert_eq(empty, true, "rz_vector_pop => rz_vector_empty");
	rz_vector_clear(&v);

	RzVector *vp = rz_vector_new(42, NULL, NULL);
	empty = rz_vector_empty(&v);
	mu_assert_eq(empty, true, "rz_vector_new => rz_vector_empty");
	rz_vector_free(vp);

	mu_end;
}

static bool test_vector_remove_at(void) {
	RzVector v;
	init_test_vector(&v, 5, 0, NULL, NULL);

	ut32 e;
	rz_vector_remove_at(&v, 2, &e);
	mu_assert_eq(e, 2, "rz_vector_remove_at => into");
	mu_assert_eq(v.len, 4UL, "rz_vector_remove_at => len");

	mu_assert_eq(((ut32 *)v.a)[0], 0, "rz_vector_remove_at => remaining elements");
	mu_assert_eq(((ut32 *)v.a)[1], 1, "rz_vector_remove_at => remaining elements");
	mu_assert_eq(((ut32 *)v.a)[2], 3, "rz_vector_remove_at => remaining elements");
	mu_assert_eq(((ut32 *)v.a)[3], 4, "rz_vector_remove_at => remaining elements");

	rz_vector_remove_at(&v, 3, &e);
	mu_assert_eq(e, 4, "rz_vector_remove_at (end) => into");
	mu_assert_eq(v.len, 3UL, "rz_vector_remove_at (end) => len");

	mu_assert_eq(((ut32 *)v.a)[0], 0, "rz_vector_remove_at (end) => remaining elements");
	mu_assert_eq(((ut32 *)v.a)[1], 1, "rz_vector_remove_at (end) => remaining elements");
	mu_assert_eq(((ut32 *)v.a)[2], 3, "rz_vector_remove_at (end) => remaining elements");

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_insert(void) {
	RzVector v;

	init_test_vector(&v, 4, 2, NULL, NULL);
	ut32 e = 1337;
	e = *((ut32 *)rz_vector_insert(&v, 1, &e));
	mu_assert_eq(v.len, 5UL, "rz_vector_insert => len");
	mu_assert_eq(e, 1337, "rz_vector_insert => content at returned ptr");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1337, "rz_vector_insert => content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 1, "rz_vector_insert => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 2, "rz_vector_insert => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 3, "rz_vector_insert => old content");
	rz_vector_clear(&v);

	init_test_vector(&v, 4, 2, NULL, NULL);
	ut32 *p = rz_vector_insert(&v, 1, NULL);
	*p = 1337;
	mu_assert_eq(v.len, 5UL, "rz_vector_insert (null) => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert (null) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1337, "rz_vector_insert (null) => content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 1, "rz_vector_insert (null) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 2, "rz_vector_insert (null) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 3, "rz_vector_insert (null) => old content");
	rz_vector_clear(&v);

	init_test_vector(&v, 4, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)rz_vector_insert(&v, 1, &e));
	mu_assert("rz_vector_insert (resize) => capacity", v.capacity >= 5);
	mu_assert_eq(v.len, 5UL, "rz_vector_insert => len");
	mu_assert_eq(e, 1337, "rz_vector_insert => content at returned ptr");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert (resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1337, "rz_vector_insert (resize) => content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 1, "rz_vector_insert (resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 2, "rz_vector_insert (resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 3, "rz_vector_insert (resize) => old content");
	rz_vector_clear(&v);

	init_test_vector(&v, 4, 2, NULL, NULL);
	e = 1337;
	e = *((ut32 *)rz_vector_insert(&v, 4, &e));
	mu_assert_eq(v.len, 5UL, "rz_vector_insert (end) => len");
	mu_assert_eq(e, 1337, "rz_vector_insert (end) => content at returned ptr");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_insert (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 2, "rz_vector_insert (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 3, "rz_vector_insert (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 1337, "rz_vector_insert (end) => content");
	rz_vector_clear(&v);

	init_test_vector(&v, 4, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)rz_vector_insert(&v, 4, &e));
	mu_assert("rz_vector_insert (resize) => capacity", v.capacity >= 5);
	mu_assert_eq(v.len, 5UL, "rz_vector_insert (end) => len");
	mu_assert_eq(e, 1337, "rz_vector_insert (end) => content at returned ptr");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 2, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 3, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 1337, "rz_vector_insert (end, resize) => content");
	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_insert_range(void) {
	RzVector v;
	ut32 range[] = { 0xC0, 0xFF, 0xEE };

	rz_vector_init(&v, 4, NULL, NULL);
	ut32 *p = (ut32 *)rz_vector_insert_range(&v, 0, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v, 0), "rz_vector_insert_range (empty) returned ptr");
	mu_assert_eq(v.len, 3UL, "rz_vector_insert_range (empty) => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0xC0, "rz_vector_insert_range (empty) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 0xFF, "rz_vector_insert_range (empty) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 0xEE, "rz_vector_insert_range (empty) => new content");
	rz_vector_clear(&v);

	init_test_vector(&v, 3, 3, NULL, NULL);
	p = (ut32 *)rz_vector_insert_range(&v, 2, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v, 2), "rz_vector_insert_range returned ptr");
	mu_assert_eq(v.len, 6UL, "rz_vector_insert_range => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert_range => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_insert_range => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 0xC0, "rz_vector_insert_range => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 0xFF, "rz_vector_insert_range => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 0xEE, "rz_vector_insert_range => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 5)), 2, "rz_vector_insert_range => old content");
	rz_vector_clear(&v);

	init_test_vector(&v, 3, 3, NULL, NULL);
	p = (ut32 *)rz_vector_insert_range(&v, 2, NULL, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v, 2), "rz_vector_insert_range (null) returned ptr");
	mu_assert_eq(v.len, 6UL, "rz_vector_insert_range (null) => len");
	p[0] = 0xC0;
	p[1] = 0xFF;
	p[2] = 0xEE;
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert_range (null) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_insert_range (null) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 0xC0, "rz_vector_insert_range (null) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 0xFF, "rz_vector_insert_range (null) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 0xEE, "rz_vector_insert_range (null) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 5)), 2, "rz_vector_insert_range (null) => old content");
	rz_vector_clear(&v);

	init_test_vector(&v, 3, 3, NULL, NULL);
	p = (ut32 *)rz_vector_insert_range(&v, 3, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v, 3), "rz_vector_insert_range (end) returned ptr");
	mu_assert_eq(v.len, 6UL, "rz_vector_insert_range (end) => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert_range (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_insert_range (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 2, "rz_vector_insert_range (end) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 0xC0, "rz_vector_insert_range (end) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 0xFF, "rz_vector_insert_range (end) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 5)), 0xEE, "rz_vector_insert_range (end) => new content");
	rz_vector_clear(&v);

	init_test_vector(&v, 3, 0, NULL, NULL);
	p = (ut32 *)rz_vector_insert_range(&v, 2, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v, 2), "rz_vector_insert_range (resize) returned ptr");
	mu_assert_eq(v.len, 6UL, "rz_vector_insert_range (resize) => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_insert_range (resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_insert_range (resize) => old content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 2)), 0xC0, "rz_vector_insert_range (resize) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 3)), 0xFF, "rz_vector_insert_range (resize) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 4)), 0xEE, "rz_vector_insert_range (resize) => new content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 5)), 2, "rz_vector_insert_range (resize) => old content");
	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_pop(void) {
	RzVector v;
	init_test_vector(&v, 3, 0, NULL, NULL);

	ut32 e;
	rz_vector_pop(&v, &e);
	mu_assert_eq(e, 2, "rz_vector_pop into");
	mu_assert_eq(v.len, 2UL, "rz_vector_pop => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_pop => remaining content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 1, "rz_vector_pop => remaining content");

	rz_vector_pop(&v, &e);
	mu_assert_eq(e, 1, "rz_vector_pop into");
	mu_assert_eq(v.len, 1UL, "rz_vector_pop => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 0, "rz_vector_pop => remaining content");

	rz_vector_pop(&v, &e);
	mu_assert_eq(e, 0, "rz_vector_pop (last) into");
	mu_assert_eq(v.len, 0UL, "rz_vector_pop (last) => len");

	rz_vector_pop(&v, &e);

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_pop_front(void) {
	RzVector v;
	init_test_vector(&v, 3, 0, NULL, NULL);

	ut32 e;
	rz_vector_pop_front(&v, &e);
	mu_assert_eq(e, 0, "rz_vector_pop_front into");
	mu_assert_eq(v.len, 2UL, "rz_vector_pop_front => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 1, "rz_vector_pop_front => remaining content");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 1)), 2, "rz_vector_pop_front => remaining content");

	rz_vector_pop_front(&v, &e);
	mu_assert_eq(e, 1, "rz_vector_pop_front into");
	mu_assert_eq(v.len, 1UL, "rz_vector_pop_front => len");
	mu_assert_eq(*((ut32 *)rz_vector_index_ptr(&v, 0)), 2, "rz_vector_pop_front => remaining content");

	rz_vector_pop_front(&v, &e);
	mu_assert_eq(e, 2, "rz_vector_pop_front (last) into");
	mu_assert_eq(v.len, 0UL, "rz_vector_pop_front (last) => len");

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_push(void) {
	RzVector v;
	rz_vector_init(&v, 4, NULL, NULL);

	ut32 *p = rz_vector_push(&v, NULL);
	*p = 1337;
	mu_assert_eq(v.len, 1UL, "rz_vector_push (null, empty, assign) => len == 1");
	ut32 e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push (null, empty, assign) => content");

	rz_vector_clear(&v);

	rz_vector_init(&v, 4, NULL, NULL);

	e = 1337;
	e = *((ut32 *)rz_vector_push(&v, &e));
	mu_assert_eq(v.len, 1UL, "rz_vector_push (empty) => len == 1");
	mu_assert_eq(e, 1337, "rz_vector_push (empty) => content at returned ptr");
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push (empty) => content");

	e = 0xDEAD;
	e = *((ut32 *)rz_vector_push(&v, &e));
	mu_assert_eq(v.len, 2UL, "rz_vector_push => len == 2");
	mu_assert_eq(e, 0xDEAD, "rz_vector_push (empty) => content at returned ptr");
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push => old content");
	e = *((ut32 *)rz_vector_index_ptr(&v, 1));
	mu_assert_eq(e, 0xDEAD, "rz_vector_push => content");

	e = 0xBEEF;
	e = *((ut32 *)rz_vector_push(&v, &e));
	mu_assert_eq(v.len, 3UL, "rz_vector_push => len == 3");
	mu_assert_eq(e, 0xBEEF, "rz_vector_push (empty) => content at returned ptr");
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push => old content");
	e = *((ut32 *)rz_vector_index_ptr(&v, 1));
	mu_assert_eq(e, 0xDEAD, "rz_vector_push => old content");
	e = *((ut32 *)rz_vector_index_ptr(&v, 2));
	mu_assert_eq(e, 0xBEEF, "rz_vector_push => content");

	rz_vector_clear(&v);

	init_test_vector(&v, 5, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)rz_vector_push(&v, &e));
	mu_assert("rz_vector_push (resize) => capacity", v.capacity >= 6);
	mu_assert_eq(v.len, 6UL, "rz_vector_push (resize) => len");
	mu_assert_eq(e, 1337, "rz_vector_push (empty) => content at returned ptr");

	size_t i;
	for (i = 0; i < v.len - 1; i++) {
		e = *((ut32 *)rz_vector_index_ptr(&v, i));
		mu_assert_eq(e, (ut32)i, "rz_vector_push (resize) => old content");
	}
	e = *((ut32 *)rz_vector_index_ptr(&v, 5));
	mu_assert_eq(e, 1337, "rz_vector_push (resize) => content");

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_push_front(void) {
	RzVector v;
	rz_vector_init(&v, 4, NULL, NULL);

	ut32 *p = rz_vector_push_front(&v, NULL);
	*p = 1337;
	mu_assert_eq(v.len, 1UL, "rz_vector_push_front (null, empty, assign) => len == 1");
	ut32 e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push_front (null, empty, assign) => content");

	rz_vector_clear(&v);

	rz_vector_init(&v, 4, NULL, NULL);

	e = 1337;
	e = *((ut32 *)rz_vector_push_front(&v, &e));
	mu_assert_eq(v.len, 1UL, "rz_vector_push_front (empty) => len == 1");
	mu_assert_eq(e, 1337, "rz_vector_push_front (empty) => content at returned ptr");
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push (empty) => content");

	e = 0xDEAD;
	e = *((ut32 *)rz_vector_push_front(&v, &e));
	mu_assert_eq(v.len, 2UL, "rz_vector_push_front => len == 2");
	mu_assert_eq(e, 0xDEAD, "rz_vector_push_front (empty) => content at returned ptr");
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 0xDEAD, "rz_vector_push_front => content");
	e = *((ut32 *)rz_vector_index_ptr(&v, 1));
	mu_assert_eq(e, 1337, "rz_vector_push_front => old content");

	e = 0xBEEF;
	e = *((ut32 *)rz_vector_push_front(&v, &e));
	mu_assert_eq(v.len, 3UL, "rz_vector_push_front => len == 3");
	mu_assert_eq(e, 0xBEEF, "rz_vector_push_front (empty) => content at returned ptr");
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 0xBEEF, "rz_vector_push_front => content");
	e = *((ut32 *)rz_vector_index_ptr(&v, 1));
	mu_assert_eq(e, 0xDEAD, "rz_vector_push_front => old content");
	e = *((ut32 *)rz_vector_index_ptr(&v, 2));
	mu_assert_eq(e, 1337, "rz_vector_push_front => old content");

	rz_vector_clear(&v);

	init_test_vector(&v, 5, 0, NULL, NULL);
	e = 1337;
	e = *((ut32 *)rz_vector_push_front(&v, &e));
	mu_assert("rz_vector_push_front (resize) => capacity", v.capacity >= 6);
	mu_assert_eq(v.len, 6UL, "rz_vector_push_front (resize) => len");
	mu_assert_eq(e, 1337, "rz_vector_push_front (empty) => content at returned ptr");

	size_t i;
	for (i = 1; i < v.len; i++) {
		e = *((ut32 *)rz_vector_index_ptr(&v, i));
		mu_assert_eq(e, (ut32)i - 1, "rz_vector_push (resize) => old content");
	}
	e = *((ut32 *)rz_vector_index_ptr(&v, 0));
	mu_assert_eq(e, 1337, "rz_vector_push (resize) => content");

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_reserve(void) {
	RzVector v;
	rz_vector_init(&v, 4, NULL, NULL);

	rz_vector_reserve(&v, 42);
	mu_assert_eq(v.capacity, 42UL, "rz_vector_reserve (empty) => capacity");
	mu_assert("rz_vector_reserve (empty) => a", v.a);
	size_t i;
	for (i = 0; i < v.capacity; i++) {
		*((ut32 *)rz_vector_index_ptr(&v, i)) = 1337;
	}
	v.len = 20;

	rz_vector_reserve(&v, 100);
	mu_assert_eq(v.capacity, 100UL, "rz_vector_reserve => capacity");
	mu_assert("rz_vector_reserve => a", v.a);
	for (i = 0; i < v.capacity; i++) {
		*((ut32 *)rz_vector_index_ptr(&v, i)) = 1337;
	}

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_shrink(void) {
	RzVector v;
	init_test_vector(&v, 5, 5, NULL, NULL);
	void *a = rz_vector_shrink(&v);
	mu_assert_eq(a, v.a, "rz_vector_shrink ret");
	mu_assert_eq(v.len, 5UL, "rz_vector_shrink => len");
	mu_assert_eq(v.capacity, 5UL, "rz_vector_shrink => capacity");
	rz_vector_clear(&v);

	init_test_vector(&v, 5, 0, NULL, NULL);
	a = rz_vector_shrink(&v);
	mu_assert_eq(a, v.a, "rz_vector_shrink (already minimal) ret");
	mu_assert_eq(v.len, 5UL, "rz_vector_shrink (already minimal) => len");
	mu_assert_eq(v.capacity, 5UL, "rz_vector_shrink (already minimal) => capacity");
	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_foreach(void) {
	RzVector v;
	init_test_vector(&v, 5, 5, NULL, NULL);

	int i = 1;
	ut32 *it;
	int acc[5] = { 0 };
	rz_vector_foreach(&v, it) {
		mu_assert_eq(acc[*it], 0, "unset acc element");
		acc[*it] = i++;
	}

	for (i = 0; i < 5; i++) {
		mu_assert_eq(acc[i], i + 1, "acc");
	}

	int acc_prev[5] = { 0 };
	i = 5;
	rz_vector_foreach_prev(&v, it) {
		mu_assert_eq(acc_prev[*it], 0, "unset acc_prev element");
		acc_prev[*it] = i++;
	}

	for (i = 0; i < 5; i++) {
		mu_assert_eq(acc_prev[i], 10 - i - 1, "acc_prev");
	}

	rz_vector_clear(&v);

	mu_end;
}

static bool test_vector_lower_bound(void) {
	RzVector v;
	rz_vector_init(&v, sizeof(st64), NULL, NULL);
	st64 a[] = { 0, 2, 4, 6, 8 };
	rz_vector_insert_range(&v, 0, a, 5);

	size_t l;
#define CMP(x, y) x - (*(st64 *)y)
	rz_vector_lower_bound(&v, 3, l, CMP);
	mu_assert_eq(l, 2, "lower_bound");
	rz_vector_lower_bound(&v, -1, l, CMP);
	mu_assert_eq(l, 0, "lower_bound");
	rz_vector_lower_bound(&v, 0, l, CMP);
	mu_assert_eq(l, 0, "lower_bound");
	rz_vector_lower_bound(&v, 2, l, CMP);
	mu_assert_eq(l, 1, "lower_bound");
	rz_vector_lower_bound(&v, 42, l, CMP);
	mu_assert_eq(l, 5, "lower_bound");
#undef CMP
	rz_vector_clear(&v);
	mu_end;
}

static bool test_pvector_init(void) {
	RzPVector v;
	rz_pvector_init(&v, (void *)1337);
	mu_assert_eq(v.v.elem_size, sizeof(void *), "elem_size");
	mu_assert_eq(v.v.len, 0UL, "len");
	mu_assert_null(v.v.a, "a");
	mu_assert_eq(v.v.capacity, 0UL, "capacity");
	mu_assert_eq(v.v.free_user, (void *)1337, "free");
	mu_end;
}

static bool test_pvector_new(void) {
	RzPVector *v = rz_pvector_new((void *)1337);
	mu_assert_eq(v->v.elem_size, sizeof(void *), "elem_size");
	mu_assert_eq(v->v.len, 0UL, "len");
	mu_assert_null(v->v.a, "a");
	mu_assert_eq(v->v.capacity, 0UL, "capacity");
	mu_assert_eq(v->v.free_user, (void *)1337, "free");
	free(v);
	mu_end;
}

static bool test_pvector_clear(void) {
	// run with asan or valgrind
	RzPVector v;
	init_test_pvector(&v, 5, 5);
	mu_assert_eq(v.v.len, 5UL, "initial len");
	mu_assert("initial a", v.v.a);
	mu_assert_eq(v.v.capacity, 10UL, "initial capacity");
	rz_pvector_clear(&v);
	mu_assert_eq(v.v.len, 0UL, "len");
	mu_assert_null(v.v.a, "a");
	mu_assert_eq(v.v.capacity, 0UL, "capacity");
	mu_end;
}

static bool test_pvector_free(void) {
	// run with asan or valgrind
	RzPVector *v = RZ_NEW(RzPVector);
	init_test_pvector(v, 5, 5);
	mu_assert_eq(v->v.len, 5UL, "initial len");
	mu_assert("initial a", v->v.a);
	mu_assert_eq(v->v.capacity, 10UL, "initial capacity");
	rz_pvector_free(v);
	mu_end;
}

static bool test_pvector_at(void) {
	RzPVector v;
	init_test_pvector(&v, 5, 0);
	ut32 i;
	for (i = 0; i < 5; i++) {
		ut32 e = *((ut32 *)rz_pvector_at(&v, i));
		mu_assert_eq(e, i, "at");
	}
	rz_pvector_clear(&v);
	mu_end;
}

static bool test_pvector_set(void) {
	RzPVector v;
	init_test_pvector(&v, 5, 0);
	free(((void **)v.v.a)[3]);
	rz_pvector_set(&v, 3, (void *)1337);
	mu_assert_eq(((void **)v.v.a)[3], (void *)1337, "set");
	rz_pvector_set(&v, 3, NULL);
	mu_assert_null(((void **)v.v.a)[3], "set");
	rz_pvector_clear(&v);
	mu_end;
}

static bool test_pvector_contains(void) {
	RzPVector v;
	init_test_pvector(&v, 5, 0);
	void *e = ((void **)v.v.a)[3];
	void **p = rz_pvector_contains(&v, e);
	mu_assert_eq(p, (void **)v.v.a + 3, "contains");
	p = rz_pvector_contains(&v, 0);
	mu_assert_null(p, "!contains");
	rz_pvector_clear(&v);
	mu_end;
}

static bool test_pvector_remove_at(void) {
	RzPVector v;
	init_test_pvector(&v, 5, 0);
	ut32 *e = rz_pvector_remove_at(&v, 3);
	mu_assert_eq(*e, 3, "remove_at ret");
	free(e);
	mu_assert_eq(v.v.len, 4UL, "remove_at => len");
	mu_assert_eq(*((ut32 **)v.v.a)[0], 0, "remove_at => remaining content");
	mu_assert_eq(*((ut32 **)v.v.a)[1], 1, "remove_at => remaining content");
	mu_assert_eq(*((ut32 **)v.v.a)[2], 2, "remove_at => remaining content");
	mu_assert_eq(*((ut32 **)v.v.a)[3], 4, "remove_at => remaining content");
	rz_pvector_clear(&v);
	mu_end;
}

static bool test_pvector_insert(void) {
	RzPVector v;

	init_test_pvector2(&v, 4, 2);
	void *e = (void *)1337;
	e = *rz_pvector_insert(&v, 1, e);
	mu_assert_eq(v.v.len, 5UL, "insert => len");
	mu_assert_eq(e, (void *)1337, "insert => content at returned ptr");
	mu_assert_null(*((void **)rz_vector_index_ptr(&v.v, 0)), "insert => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1337, "insert => content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)1, "insert => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)2, "insert => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)3, "insert => old content");
	rz_pvector_clear(&v);

	init_test_pvector2(&v, 4, 0);
	e = (void *)1337;
	e = *rz_pvector_insert(&v, 1, e);
	mu_assert("insert (resize) => capacity", v.v.capacity >= 5);
	mu_assert_eq(v.v.len, 5UL, "insert (resize) => len");
	mu_assert_eq(e, (void *)1337, "insert (resize) => content at returned ptr");
	mu_assert_null(*((void **)rz_vector_index_ptr(&v.v, 0)), "insert (resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1337, "insert => content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)1, "insert => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)2, "insert => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)3, "insert => old content");
	rz_pvector_clear(&v);

	init_test_pvector2(&v, 4, 2);
	e = (void *)1337;
	e = *rz_pvector_insert(&v, 4, e);
	mu_assert_eq(v.v.len, 5UL, "insert (end) => len");
	mu_assert_eq(e, (void *)1337, "insert (end) => content at returned ptr");
	mu_assert_null(*((void **)rz_vector_index_ptr(&v.v, 0)), "insert (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1, "insert (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)2, "insert (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)3, "insert (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)1337, "insert (end) => content");
	rz_pvector_clear(&v);

	init_test_pvector2(&v, 4, 2);
	e = (void *)1337;
	e = *rz_pvector_insert(&v, 4, e);
	mu_assert("rz_vector_insert (resize, resize) => capacity", v.v.capacity >= 5);
	mu_assert_eq(v.v.len, 5UL, "rz_vector_insert (end, resize) => len");
	mu_assert_eq(e, (void *)1337, "rz_vector_insert (end, resize) => content at returned ptr");
	mu_assert_null(*((void **)rz_vector_index_ptr(&v.v, 0)), "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)2, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)3, "rz_vector_insert (end, resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)1337, "rz_vector_insert (end, resize) => content");
	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_insert_range(void) {
	RzPVector v;
	void *range[] = { (void *)0xC0, (void *)0xFF, (void *)0xEE };

	rz_pvector_init(&v, NULL);
	void **p = rz_pvector_insert_range(&v, 0, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v.v, 0), "insert_range (empty) returned ptr");
	mu_assert_eq(v.v.len, 3UL, "insert_range (empty) => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)0xC0, "insert_range (empty) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)0xFF, "insert_range (empty) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)0xEE, "insert_range (empty) => new content");
	rz_pvector_clear(&v);

	init_test_pvector2(&v, 3, 3);
	p = rz_pvector_insert_range(&v, 2, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v.v, 2), "insert_range returned ptr");
	mu_assert_eq(v.v.len, 6UL, "insert_range => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)0, "insert_range => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1, "insert_range => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)0xC0, "insert_range => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)0xFF, "insert_range => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)0xEE, "insert_range => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 5)), (void *)2, "insert_range => old content");
	rz_pvector_clear(&v);

	init_test_pvector2(&v, 3, 3);
	p = rz_pvector_insert_range(&v, 3, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v.v, 3), "insert_range (end) returned ptr");
	mu_assert_eq(v.v.len, 6UL, "insert_range (end) => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)0, "insert_range (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1, "insert_range (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)2, "insert_range (end) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)0xC0, "insert_range (end) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)0xFF, "insert_range (end) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 5)), (void *)0xEE, "insert_range (end) => new content");
	rz_pvector_clear(&v);

	init_test_pvector2(&v, 3, 0);
	p = rz_pvector_insert_range(&v, 2, range, 3);
	mu_assert_eq(p, rz_vector_index_ptr(&v.v, 2), "insert_range (resize) returned ptr");
	mu_assert_eq(v.v.len, 6UL, "insert_range (resize) => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)0, "insert_range (resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1, "insert_range (resize) => old content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 2)), (void *)0xC0, "insert_range (resize) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 3)), (void *)0xFF, "insert_range (resize) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 4)), (void *)0xEE, "insert_range (resize) => new content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 5)), (void *)2, "insert_range (resize) => old content");
	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_pop(void) {
	RzPVector v;
	init_test_pvector2(&v, 3, 0);

	void *e = rz_pvector_pop(&v);
	mu_assert_eq(e, (void *)2, "pop ret");
	mu_assert_eq(v.v.len, 2UL, "pop => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)0, "pop => remaining content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)1, "pop => remaining content");

	e = rz_pvector_pop(&v);
	mu_assert_eq(e, (void *)1, "pop ret");
	mu_assert_eq(v.v.len, 1UL, "pop => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)0, "pop => remaining content");

	e = rz_pvector_pop(&v);
	mu_assert_eq(e, (void *)0, "pop (last) into");
	mu_assert_eq(v.v.len, 0UL, "pop (last) => len");

	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_pop_front(void) {
	RzPVector v;
	init_test_pvector2(&v, 3, 0);

	void *e = rz_pvector_pop_front(&v);
	mu_assert_null(e, "pop_front into");
	mu_assert_eq(v.v.len, 2UL, "pop_front => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)1, "pop_front => remaining content");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 1)), (void *)2, "pop_front => remaining content");

	e = rz_pvector_pop_front(&v);
	mu_assert_eq(e, (void *)1, "rz_vector_pop_front into");
	mu_assert_eq(v.v.len, 1UL, "rz_vector_pop_front => len");
	mu_assert_eq(*((void **)rz_vector_index_ptr(&v.v, 0)), (void *)2, "pop_front => remaining content");

	e = rz_pvector_pop_front(&v);
	mu_assert_eq(e, (void *)2, "pop_front (last) into");
	mu_assert_eq(v.v.len, 0UL, "pop_front (last) => len");

	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_push(void) {
	RzPVector v;
	rz_pvector_init(&v, NULL);

	void *e = (void *)1337;
	e = *rz_pvector_push(&v, e);
	mu_assert_eq(v.v.len, 1UL, "push (empty) => len == 1");
	mu_assert_eq(e, (void *)1337, "push (empty) => content at returned ptr");
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)1337, "rz_vector_push (empty) => content");

	e = (void *)0xDEAD;
	e = *rz_pvector_push(&v, e);
	mu_assert_eq(v.v.len, 2UL, "push => len == 2");
	mu_assert_eq(e, (void *)0xDEAD, "push => content at returned ptr");
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)1337, "push => old content");
	e = *((void **)rz_vector_index_ptr(&v.v, 1));
	mu_assert_eq(e, (void *)0xDEAD, "push => content");

	e = (void *)0xBEEF;
	e = *rz_pvector_push(&v, e);
	mu_assert_eq(v.v.len, 3UL, "push => len == 3");
	mu_assert_eq(e, (void *)0xBEEF, "push => content at returned ptr");
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)1337, "rz_vector_push => old content");
	e = *((void **)rz_vector_index_ptr(&v.v, 1));
	mu_assert_eq(e, (void *)0xDEAD, "rz_vector_push => old content");
	e = *((void **)rz_vector_index_ptr(&v.v, 2));
	mu_assert_eq(e, (void *)0xBEEF, "rz_vector_push => content");

	rz_vector_clear(&v.v);

	init_test_pvector2(&v, 5, 0);
	e = (void *)1337;
	e = *rz_pvector_push(&v, e);
	mu_assert("push (resize) => capacity", v.v.capacity >= 6);
	mu_assert_eq(v.v.len, 6UL, "push (resize) => len");
	mu_assert_eq(e, (void *)1337, "push (empty) => content at returned ptr");

	size_t i;
	for (i = 0; i < v.v.len - 1; i++) {
		e = *((void **)rz_vector_index_ptr(&v.v, i));
		mu_assert_eq(e, (void *)i, "push (resize) => old content");
	}
	e = *((void **)rz_vector_index_ptr(&v.v, 5));
	mu_assert_eq(e, (void *)1337, "rz_vector_push (resize) => content");

	rz_vector_clear(&v.v);

	mu_end;
}

static bool test_pvector_push_front(void) {
	RzPVector v;
	rz_pvector_init(&v, NULL);

	void *e = (void *)1337;
	e = *rz_pvector_push_front(&v, e);
	mu_assert_eq(v.v.len, 1UL, "push_front (empty) => len == 1");
	mu_assert_eq(e, (void *)1337, "push_front (empty) => content at returned ptr");
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)1337, "push_front (empty) => content");

	e = (void *)0xDEAD;
	e = *rz_pvector_push_front(&v, e);
	mu_assert_eq(v.v.len, 2UL, "push_front => len == 2");
	mu_assert_eq(e, (void *)0xDEAD, "push_front (empty) => content at returned ptr");
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)0xDEAD, "push_front => content");
	e = *((void **)rz_vector_index_ptr(&v.v, 1));
	mu_assert_eq(e, (void *)1337, "push_front => old content");

	e = (void *)0xBEEF;
	e = *rz_pvector_push_front(&v, e);
	mu_assert_eq(v.v.len, 3UL, "push_front => len == 3");
	mu_assert_eq(e, (void *)0xBEEF, "push_front (empty) => content at returned ptr");
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)0xBEEF, "push_front => content");
	e = *((void **)rz_vector_index_ptr(&v.v, 1));
	mu_assert_eq(e, (void *)0xDEAD, "push_front => old content");
	e = *((void **)rz_vector_index_ptr(&v.v, 2));
	mu_assert_eq(e, (void *)1337, "push_front => old content");

	rz_pvector_clear(&v);

	init_test_pvector2(&v, 5, 0);
	e = (void *)1337;
	e = *rz_pvector_push_front(&v, e);
	mu_assert("push_front (resize) => capacity", v.v.capacity >= 6);
	mu_assert_eq(v.v.len, 6UL, "push_front (resize) => len");
	mu_assert_eq(e, (void *)1337, "push_front (empty) => content at returned ptr");

	size_t i;
	for (i = 1; i < v.v.len; i++) {
		e = *((void **)rz_vector_index_ptr(&v.v, i));
		mu_assert_eq(e, (void *)(i - 1), "push_front (resize) => old content");
	}
	e = *((void **)rz_vector_index_ptr(&v.v, 0));
	mu_assert_eq(e, (void *)1337, "push_front (resize) => content");

	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_sort(void) {
	RzPVector v;
	rz_pvector_init(&v, free);
	rz_pvector_push(&v, strdup("Charmander"));
	rz_pvector_push(&v, strdup("Squirtle"));
	rz_pvector_push(&v, strdup("Bulbasaur"));
	rz_pvector_push(&v, strdup("Meowth"));
	rz_pvector_push(&v, strdup("Caterpie"));
	rz_pvector_sort(&v, (RzPVectorComparator)strcmp);

	mu_assert_eq(v.v.len, 5UL, "sort len");
	mu_assert_streq((const char *)((void **)v.v.a)[0], "Bulbasaur", "sorted strings");
	mu_assert_streq((const char *)((void **)v.v.a)[1], "Caterpie", "sorted strings");
	mu_assert_streq((const char *)((void **)v.v.a)[2], "Charmander", "sorted strings");
	mu_assert_streq((const char *)((void **)v.v.a)[3], "Meowth", "sorted strings");
	mu_assert_streq((const char *)((void **)v.v.a)[4], "Squirtle", "sorted strings");
	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_foreach(void) {
	RzPVector v;
	init_test_pvector2(&v, 5, 5);

	int i = 1;
	void **it;
	int acc[5] = { 0 };
	rz_pvector_foreach (&v, it) {
		void *e = *it;
		int ev = (int)((size_t)e);
		mu_assert_eq(acc[ev], 0, "unset acc element");
		acc[ev] = i++;
	}

	for (i = 0; i < 5; i++) {
		mu_assert_eq(acc[i], i + 1, "acc");
	}

	int acc_prev[5] = { 0 };
	i = 5;
	rz_pvector_foreach_prev(&v, it) {
		void *e = *it;
		int ev = (int)((size_t)e);
		mu_assert_eq(acc_prev[ev], 0, "unset acc_prev element");
		acc_prev[ev] = i++;
	}

	for (i = 0; i < 5; i++) {
		mu_assert_eq(acc_prev[i], 10 - i - 1, "acc_prev");
	}

	rz_pvector_clear(&v);

	mu_end;
}

static bool test_pvector_lower_bound(void) {
	void *a[] = { (void *)0, (void *)2, (void *)4, (void *)6, (void *)8 };
	RzPVector s;
	rz_pvector_init(&s, NULL);
	s.v.a = malloc(sizeof(void *) * 5);
	s.v.capacity = 5;
	memcpy(s.v.a, a, sizeof(void *) * 5);
	s.v.len = 5;

	size_t l;
#define CMP(x, y) ((char *)(x) - (char *)(y))
	rz_pvector_lower_bound(&s, 4, l, CMP);
	mu_assert_ptreq(rz_pvector_at(&s, l), (void *)4, "lower_bound");
	rz_pvector_lower_bound(&s, 5, l, CMP);
	mu_assert_ptreq(rz_pvector_at(&s, l), (void *)6, "lower_bound 2");
	rz_pvector_lower_bound(&s, 6, l, CMP);
	mu_assert_ptreq(rz_pvector_at(&s, l), (void *)6, "lower_bound 3");
	rz_pvector_lower_bound(&s, 9, l, CMP);
	mu_assert_eq(l, s.v.len, "lower_bound 3");
#undef CMP

	rz_pvector_clear(&s);

	mu_end;
}

static int all_tests(void) {
	mu_run_test(test_vector_init);
	mu_run_test(test_vector_new);
	mu_run_test(test_vector_fini);
	mu_run_test(test_vector_clear);
	mu_run_test(test_vector_free);
	mu_run_test(test_vector_clone);
	mu_run_test(test_vector_empty);
	mu_run_test(test_vector_remove_at);
	mu_run_test(test_vector_insert);
	mu_run_test(test_vector_insert_range);
	mu_run_test(test_vector_pop);
	mu_run_test(test_vector_pop_front);
	mu_run_test(test_vector_push);
	mu_run_test(test_vector_push_front);
	mu_run_test(test_vector_reserve);
	mu_run_test(test_vector_shrink);
	mu_run_test(test_vector_foreach);
	mu_run_test(test_vector_lower_bound);

	mu_run_test(test_pvector_init);
	mu_run_test(test_pvector_new);
	mu_run_test(test_pvector_clear);
	mu_run_test(test_pvector_free);
	mu_run_test(test_pvector_at);
	mu_run_test(test_pvector_set);
	mu_run_test(test_pvector_contains);
	mu_run_test(test_pvector_remove_at);
	mu_run_test(test_pvector_insert);
	mu_run_test(test_pvector_insert_range);
	mu_run_test(test_pvector_pop);
	mu_run_test(test_pvector_pop_front);
	mu_run_test(test_pvector_push);
	mu_run_test(test_pvector_push_front);
	mu_run_test(test_pvector_sort);
	mu_run_test(test_pvector_foreach);
	mu_run_test(test_pvector_lower_bound);

	return tests_passed != tests_run;
}

mu_main(all_tests)