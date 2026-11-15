// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_table.h>
#include <rz_util/rz_graph.h>

#include "bench_utils.h"

/**
 * \file bench_graph.c
 * \brief Benchmark for graph functions
 */

#define ITERATION_COUNT 2000000

static void bench_rz_graph_list(RzTable *t_out) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_LIST, NULL, NULL, NULL);

	{
		RZ_BENCH_RUN_I("[RzGraph (list)] add node (int data)", i, t_out, ITERATION_COUNT, {
			rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(i), NULL);
		});
		RZ_BENCH_RUN_I("[RzGraph (list)] add edge by id (no data)", i, t_out, ITERATION_COUNT, {
			// Last add in iteration will fail of course
			// because the node i+1 doesn't exist.
			rz_graph_add_edge_by_id(g, i, i + 1, NULL);
		});
		RZ_BENCH_RUN_I("[RzGraph (list)] delete edge (no data)", i, t_out, ITERATION_COUNT, {
			// Last delete in iteration will fail of course
			// because the node i+1 doesn't exist.
			rz_graph_del_edge_by_id(g, i, i + 1);
		});
	}
	rz_graph_free(g);
}

#define MAX_MATRIX_SIZE 300 * 1000 * 1000

static void bench_rz_graph_matrix_capcity_expansion(RzTable *t_out) {
	RzGraph *g = rz_graph_new(RZ_GRAPH_IMPL_MATRIX, NULL, NULL, NULL);
	size_t next_cap = RZ_GRAPH_MATRIX_DEFAULT_CAPACITY;

	ut64 i = 0;
	do {
		// Add nodes up to next_cap
		for (; i < next_cap; ++i) {
			rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(i), NULL);
		}
		// Measure the performance of adding a node which triggers matrix
		// capacity expansion.
		size_t x = next_cap + (next_cap / 4);
		char bench_name[256] = { 0 };
		rz_strf(bench_name, "[RzGraph (matrix)] capacity expansion 0x%" PFMT64x " -> 0x%" PFMT64x " bytes",
			rz_graph_mem_usage(g),
			x * x * sizeof(RzGraphEdge *));
		{
			RZ_BENCH_RUN_I(bench_name, dummy, t_out, 1, {
				rz_graph_add_node(g, RZ_GRAPH_INT_AS_DATA(i), NULL);
			});
		}
		i++;
		next_cap += next_cap / 4;
	} while (rz_graph_mem_usage(g) < MAX_MATRIX_SIZE);

	rz_graph_free(g);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_graph_list(t);
	bench_rz_graph_matrix_capcity_expansion(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
