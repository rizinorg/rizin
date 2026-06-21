// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_table.h>
#include <rz_util/rz_graph.h>

#include "bench_utils.h"
#include "rz_util/rz_num.h"
#include "rz_vector.h"

/**
 * \file bench_vector.c
 * \brief Benchmark for graph functions
 */

#define ITERATION_COUNT 200000

static void bench_rz_vector_remove_at(RzTable *t_out) {
	RzVector *v = rz_vector_new(sizeof(ut64), NULL, NULL);

	for (size_t i = 0; i < ITERATION_COUNT; ++i) {
		rz_vector_push(v, &i);
	}

	{
		RZ_BENCH_RUN_I("[RzVector] rz_vector_remove_at_unsorted", i, t_out, ITERATION_COUNT, {
			size_t index = rz_num_rand32(ITERATION_COUNT - 1 - i);
			rz_vector_remove_at_unsorted(v, index, NULL);
		});
	}

	rz_vector_clear(v);
	for (size_t i = 0; i < ITERATION_COUNT; ++i) {
		rz_vector_push(v, &i);
	}

	{
		RZ_BENCH_RUN_I("[RzVector] rz_vector_remove_at", i, t_out, ITERATION_COUNT, {
			size_t index = rz_num_rand32(ITERATION_COUNT - 1 - i);
			rz_vector_remove_at(v, index, NULL);
		});
	}
	rz_vector_free(v);
}

static void bench_rz_vector_swap(RzTable *t_out) {
	RzVector *v = rz_vector_new(sizeof(ut64), NULL, NULL);

	for (size_t i = 0; i < ITERATION_COUNT; ++i) {
		rz_vector_push(v, &i);
	}

	{
		RZ_BENCH_RUN_I("[RzVector] rz_vector_swap", i, t_out, ITERATION_COUNT, {
			size_t index_a = rz_num_rand32(ITERATION_COUNT - 1);
			size_t index_b = rz_num_rand32(ITERATION_COUNT - 1);
			rz_vector_swap(v, index_a, index_b);
		});
	}

	rz_vector_free(v);
}

#define SORT_N 4096

static int bench_cmp_u64(const void *a, const void *b, void *user) {
	(void)user;
	ut64 x = *(const ut64 *)a, y = *(const ut64 *)b;
	return (x > y) - (x < y);
}

// A deliberately non-trivial comparator, representative of comparing real
// struct elements; makes the per-element comparator-call count matter.
static int bench_cmp_u64_expensive(const void *a, const void *b, void *user) {
	(void)user;
	volatile int acc = 0;
	for (int k = 0; k < 24; k++) {
		acc += k * (k ^ 5);
	}
	ut64 x = *(const ut64 *)a, y = *(const ut64 *)b;
	return ((x > y) - (x < y)) + (acc & 0);
}

static int bench_cmp_pvoid(const void *a, const void *b, void *user) {
	(void)user;
	return (a > b) - (a < b);
}

static void bench_rz_vector_sort(RzTable *t_out) {
	RzVector *v = rz_vector_new(sizeof(ut64), NULL, NULL);
	rz_vector_reserve(v, SORT_N);
	ut64 *master = malloc(sizeof(ut64) * SORT_N);
	for (size_t i = 0; i < SORT_N; i++) {
		master[i] = rz_num_rand32(UT32_MAX);
	}

	{
		RZ_BENCH_RUN("[RzVector] rz_vector_sort ut64 4k", t_out, 2000, {
			memcpy(v->a, master, sizeof(ut64) * SORT_N);
			v->len = SORT_N;
			v->reverse_sorted = false;
			rz_vector_sort(v, bench_cmp_u64, false, NULL);
		});
	}
	{
		RZ_BENCH_RUN("[RzVector] rz_vector_sort expensive cmp 4k", t_out, 500, {
			memcpy(v->a, master, sizeof(ut64) * SORT_N);
			v->len = SORT_N;
			v->reverse_sorted = false;
			rz_vector_sort(v, bench_cmp_u64_expensive, false, NULL);
		});
	}

	free(master);
	rz_vector_free(v);
}

static void bench_rz_pvector_sort(RzTable *t_out) {
	RzPVector *v = rz_pvector_new(NULL);
	rz_pvector_reserve(v, SORT_N);
	void **master = malloc(sizeof(void *) * SORT_N);
	for (size_t i = 0; i < SORT_N; i++) {
		master[i] = (void *)(size_t)(rz_num_rand32(UT32_MAX) + 1);
	}

	{
		RZ_BENCH_RUN("[RzPVector] rz_pvector_sort 4k", t_out, 2000, {
			memcpy(v->v.a, master, sizeof(void *) * SORT_N);
			v->v.len = SORT_N;
			rz_pvector_sort(v, bench_cmp_pvoid, NULL);
		});
	}

	free(master);
	rz_pvector_free(v);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_vector_remove_at(t);
	bench_rz_vector_swap(t);
	bench_rz_vector_sort(t);
	bench_rz_pvector_sort(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
