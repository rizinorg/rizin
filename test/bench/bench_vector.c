// SPDX-FileCopyrightText: 2026 Jules
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_vector.h>

/**
 * \file bench_vector.c
 * \brief Benchmarks for core RzVector and RzPVector operations.
 */

static int cmp_int(const void *a, const void *b, void *user) {
	int ia = *(int *)a;
	int ib = *(int *)b;
	return ia - ib;
}

static int cmp_ptr(const void *a, const void *b, void *user) {
	return (intptr_t)a - (intptr_t)b;
}

static void bench_vector_push(RzTable *t_out) {
	RZ_BENCH_RUN_I("[vector push] 100k", i, t_out, 100, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < 100000; j++) {
			rz_vector_push(v, &j);
		}
		rz_vector_free(v);
	});
	RZ_BENCH_RUN_I("[vector push] 1m", i, t_out, 10, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < 1000000; j++) {
			rz_vector_push(v, &j);
		}
		rz_vector_free(v);
	});
}

static void bench_pvector_push(RzTable *t_out) {
	RZ_BENCH_RUN_I("[pvector push] 100k", i, t_out, 100, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < 100000; j++) {
			rz_pvector_push(v, (void *)(intptr_t)j);
		}
		rz_pvector_free(v);
	});
	RZ_BENCH_RUN_I("[pvector push] 1m", i, t_out, 10, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < 1000000; j++) {
			rz_pvector_push(v, (void *)(intptr_t)j);
		}
		rz_pvector_free(v);
	});
}

static void bench_vector_sort(RzTable *t_out) {
	int count = 10000;
	RZ_BENCH_RUN_I("[vector sort] 10k", i, t_out, 100, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < count; j++) {
			int val = rand();
			rz_vector_push(v, &val);
		}
		rz_vector_sort(v, cmp_int, false, NULL);
		rz_vector_free(v);
	});
}

static void bench_pvector_sort(RzTable *t_out) {
	int count = 10000;
	RZ_BENCH_RUN_I("[pvector sort] 10k", i, t_out, 100, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < count; j++) {
			rz_pvector_push(v, (void *)(intptr_t)rand());
		}
		rz_pvector_sort(v, cmp_ptr, NULL);
		rz_pvector_free(v);
	});
}

int main(void) {
	RzTable *t_out = rz_table_new();
	RZ_BENCH_TABLE_INIT(t_out);

	bench_vector_push(t_out);
	bench_pvector_push(t_out);
	bench_vector_sort(t_out);
	bench_pvector_sort(t_out);

	RZ_BENCH_RUN_I("[vector contains] 10k", i, t_out, 100, {
		RzVector *v = rz_vector_new(sizeof(int), NULL, NULL);
		for (int j = 0; j < 10000; j++) {
			rz_vector_push(v, &j);
		}
		int val = 9999;
		RZ_DONT_OPTIMIZE(bool, rz_vector_contains(v, &val));
		rz_vector_free(v);
	});

	RZ_BENCH_RUN_I("[pvector contains] 10k", i, t_out, 100, {
		RzPVector *v = rz_pvector_new(NULL);
		for (int j = 0; j < 10000; j++) {
			rz_pvector_push(v, (void *)(intptr_t)j);
		}
		void *val = (void *)(intptr_t)9999;
		RZ_DONT_OPTIMIZE(void **, rz_pvector_contains(v, val));
		rz_pvector_free(v);
	});

	RZ_BENCH_TABLE_PRINT_AND_FREE(t_out);
	return 0;
}
