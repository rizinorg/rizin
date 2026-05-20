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

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_vector_remove_at(t);
	bench_rz_vector_swap(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
