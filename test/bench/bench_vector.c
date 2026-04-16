// SPDX-FileCopyrightText: 2026 Abdallh <abdallhdawi3@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include "bench_utils.h"
#include <rz_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static int cmp_int(const void *a, const void *b, void *user) {
	int ai = *(int *)a;
	int bi = *(int *)b;
	(void)user;
	return ai - bi;
}

static double get_time_us(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000.0 + ts.tv_nsec / 1000.0;
}

static void populate_vector(RzVector *vec, size_t n) {
	for (size_t i = 0; i < n; i++) {
		int val = rand();
		rz_vector_push(vec, &val);
	}
}

static void populate_pvector(RzPVector *vec, size_t n) {
	for (size_t i = 0; i < n; i++) {
		int *val = malloc(sizeof(int));
		*val = rand();
		rz_pvector_push(vec, val);
	}
}

static bool is_even(const void *elem, void *user) {
	int val = *(int *)elem;
	(void)user;
	return val % 2 == 0;
}

static void bench_vector_sort(RzTable *t) {
	RzVector *vec = rz_vector_new(sizeof(int), NULL, NULL);

	RZ_BENCH_RUN("sort_1M", t, 1, {
		populate_vector(vec, 1000000);
		rz_vector_sort(vec, (RzVectorComparator)cmp_int, false, NULL);
	});
	rz_vector_free(vec);
}

static void bench_vector_swap(RzTable *t) {
	RzVector *vec = rz_vector_new(sizeof(int), NULL, NULL);
	populate_vector(vec, 100000);

	RZ_BENCH_RUN("swap_1M", t, 1, {
		for (int i = 0; i < 1000000; i++) {
			size_t a = rand() % vec->len;
			size_t b = rand() % vec->len;
			rz_vector_swap(vec, a, b);
		}
	});
	rz_vector_free(vec);
}

static void bench_pvector_uniq(RzTable *t) {
	RzPVector *vec = rz_pvector_new(NULL);
	for (int i = 0; i < 10000; i++) {
		int *val = malloc(sizeof(int));
		*val = i % 5000;
		rz_pvector_push(vec, val);
	}

	RZ_BENCH_RUN("uniq_10k", t, 10, {
		RzPVector *result = rz_pvector_uniq(vec, (RzPVectorComparator)cmp_int, NULL);
		if (result) {
			rz_pvector_free(result);
		}
	});

	void **it;
	rz_pvector_foreach (vec, it) {
		free(*it);
	}
	rz_pvector_free(vec);
}

static void bench_pvector_contains(RzTable *t) {
	RzPVector *vec = rz_pvector_new(NULL);
	populate_pvector(vec, 100000);
	void **arr = (void **)vec->v.a;
	int *target = (int *)arr[99999];

	RZ_BENCH_RUN("pvector_contains", t, 1, {
		for (int i = 0; i < 10000; i++) {
			rz_pvector_contains(vec, target);
		}
	});

	void **it;
	rz_pvector_foreach (vec, it) {
		free(*it);
	}
	rz_pvector_free(vec);
}

static void bench_remove_if_vs_naive(RzTable *t) {
	RZ_BENCH_RUN("remove_if_100k", t, 5, {
		RzVector *vec = rz_vector_new(sizeof(int), NULL, NULL);
		populate_vector(vec, 100000);
		rz_vector_remove_if(vec, is_even, NULL);
		rz_vector_free(vec);
	});

	RZ_BENCH_RUN("remove_naive_100k", t, 5, {
		RzVector *vec = rz_vector_new(sizeof(int), NULL, NULL);
		populate_vector(vec, 100000);
		size_t i = 0;
		while (i < vec->len) {
			int val = *(int *)rz_vector_index_ptr(vec, i);
			if (val % 2 == 0) {
				rz_vector_remove_at(vec, i, NULL);
			} else {
				i++;
			}
		}
		rz_vector_free(vec);
	});
}

static void bench_vector_push(RzTable *t) {
	RZ_BENCH_RUN("push_1M", t, 1, {
		RzVector *vec = rz_vector_new(sizeof(int), NULL, NULL);
		for (int i = 0; i < 1000000; i++) {
			int val = rand();
			rz_vector_push(vec, &val);
		}
		rz_vector_free(vec);
	});
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	bench_vector_sort(t);
	bench_vector_swap(t);
	bench_pvector_uniq(t);
	bench_pvector_contains(t);
	bench_remove_if_vs_naive(t);
	bench_vector_push(t);

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
