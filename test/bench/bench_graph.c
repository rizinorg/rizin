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

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Micro benchmarks
	bench_rz_graph_list(t);

	// Print results
	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
