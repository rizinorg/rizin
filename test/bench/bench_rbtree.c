// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_util/rz_rbtree.h>

#define ITERATION_COUNT 1000000

static int cmp_u64( void *a,  void *b, void *user) {
	ut64 ua = (ut64)(uintptr_t)a;
	ut64 ub = (ut64)(uintptr_t)b;
	if (ua < ub) return -1;
	if (ua > ub) return 1;
	return 0;
}

static inline ut64 splitmix64(ut64 v) {
	uint64_t z = (v + 0x9E3779B97F4A7C15ULL);
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
	z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
	return z ^ (z >> 31);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	RContRBTree *tree = rz_rbtree_cont_new();

	// sequential insert
	RZ_BENCH_RUN_I("[RBTree] insert sequential", i, t, ITERATION_COUNT, {
		rz_rbtree_cont_insert(tree, (void *)(uintptr_t)i, cmp_u64, NULL);
	});

	RZ_BENCH_RUN_I("[RBTree] find sequential", i, t, ITERATION_COUNT, {
		rz_rbtree_cont_find(tree, (void *)(uintptr_t)i, cmp_u64, NULL);
	});

	rz_rbtree_cont_free(tree);
	tree = rz_rbtree_cont_new();

	// random insert
	RZ_BENCH_RUN_I("[RBTree] insert random", i, t, ITERATION_COUNT, {
		rz_rbtree_cont_insert(tree, (void *)(uintptr_t)splitmix64(i), cmp_u64, NULL);
	});

	RZ_BENCH_RUN_I("[RBTree] find random", i, t, ITERATION_COUNT, {
		rz_rbtree_cont_find(tree, (void *)(uintptr_t)splitmix64(i), cmp_u64, NULL);
	});

	RZ_BENCH_RUN_I("[RBTree] delete random", i, t, ITERATION_COUNT, {
		rz_rbtree_cont_delete(tree, (void *)(uintptr_t)splitmix64(i), cmp_u64, NULL);
	});

	rz_rbtree_cont_free(tree);

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
