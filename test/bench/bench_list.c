// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include "bench_utils.h"
#include <rz_util.h>

/**
 * \file bench_list.c
 * \brief Benchmarks for `RzList` functions - comparing rz_list_purge implementations
 */

// Helper to populate a list with n non-null elements
static void populate_list(RzList *list, ut32 n) {
	for (ut32 j = 0; j < n; ++j) {
		rz_list_append(list, (void *)(size_t)(j + 1));
	}
}

// Helper to populate a list with n heap-allocated elements (for free fn tests)
static void populate_list_alloc(RzList *list, ut32 n) {
	for (ut32 j = 0; j < n; ++j) {
		ut32 *val = malloc(sizeof(ut32));
		*val = j;
		rz_list_append(list, val);
	}
}

/**
 * v1: Uses rz_list_delete per node (original)
 * Has extra overhead: unlinks node, updates prev/next, decrements length
 */
static void purge_v1(RzList *list) {
	RzListIter *it = list->head;
	while (it) {
		RzListIter *next = it->next;
		rz_list_delete(list, it);
		it = next;
	}
	list->length = 0;
	list->head = list->tail = NULL;
}

/**
 * v2: Direct free loop (new)
 * Tight loop: calls free fn on val, then frees the iter node directly
 */
static void purge_v2(RzList *list) {
	RzListIter *it = list->head;
	RzListFree fn = list->free;
	while (it) {
		RzListIter *next = it->next;
		if (fn && it->val) {
			fn(it->val);
		}
		free(it);
		it = next;
	}
	list->length = 0;
	list->head = list->tail = NULL;
}

/**
 * v3: Hoisted free loop
 */
static void purge_v3(RzList *list) {
	RzListIter *it = list->head;
	RzListFree fn = list->free;
	if (fn) {
		while (it) {
			RzListIter *next = it->next;
			fn(it->val);
			free(it);
			it = next;
		}
	} else {
		while (it) {
			RzListIter *next = it->next;
			free(it);
			it = next;
		}
	}
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

static void purge_v4_with_free_cb(RzList *list) {
	RzListIter *it = list->head;
	RzListFree fn = list->free;
	while (it) {
		RzListIter *next = it->next;
		fn(it->val);
		free(it);
		it = next;
	}
}

static void purge_v4_no_free_cb(RzList *list) {
	RzListIter *it = list->head;
	while (it) {
		RzListIter *next = it->next;
		free(it);
		it = next;
	}
}

/**
 * v4: Direct free loop with hoisted free fn check (split into helpers)
 */
static void purge_v4(RzList *list) {
	if (list->free) {
		purge_v4_with_free_cb(list);
	} else {
		purge_v4_no_free_cb(list);
	}
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

// --- No free function (pointer-only lists) ---

static void bench_purge_v1_small_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v1_1k_no_free", t_out, 1000, {
		populate_list(list, 1000);
		purge_v1(list);
	});
	rz_list_free(list);
}

static void bench_purge_v2_small_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v2_1k_no_free", t_out, 1000, {
		populate_list(list, 1000);
		purge_v2(list);
	});
	rz_list_free(list);
}

static void bench_purge_v3_small_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v3_1k_no_free", t_out, 1000, {
		populate_list(list, 1000);
		purge_v3(list);
	});
	rz_list_free(list);
}

static void bench_purge_v4_small_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v4_1k_no_free", t_out, 1000, {
		populate_list(list, 1000);
		purge_v4(list);
	});
	rz_list_free(list);
}

static void bench_purge_v1_medium_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v1_100k_no_free", t_out, 100, {
		populate_list(list, 100000);
		purge_v1(list);
	});
	rz_list_free(list);
}

static void bench_purge_v2_medium_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v2_100k_no_free", t_out, 100, {
		populate_list(list, 100000);
		purge_v2(list);
	});
	rz_list_free(list);
}

static void bench_purge_v3_medium_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v3_100k_no_free", t_out, 100, {
		populate_list(list, 100000);
		purge_v3(list);
	});
	rz_list_free(list);
}

static void bench_purge_v4_medium_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v4_100k_no_free", t_out, 100, {
		populate_list(list, 100000);
		purge_v4(list);
	});
	rz_list_free(list);
}

static void bench_purge_v1_large_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v1_1m_no_free", t_out, 10, {
		populate_list(list, 1000000);
		purge_v1(list);
	});
	rz_list_free(list);
}

static void bench_purge_v2_large_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v2_1m_no_free", t_out, 10, {
		populate_list(list, 1000000);
		purge_v2(list);
	});
	rz_list_free(list);
}

static void bench_purge_v3_large_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v3_1m_no_free", t_out, 10, {
		populate_list(list, 1000000);
		purge_v3(list);
	});
	rz_list_free(list);
}

static void bench_purge_v4_large_no_free(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v4_1m_no_free", t_out, 10, {
		populate_list(list, 1000000);
		purge_v4(list);
	});
	rz_list_free(list);
}

static void bench_purge_v1_medium_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v1_100k_with_free", t_out, 100, {
		populate_list_alloc(list, 100000);
		purge_v1(list);
	});
	rz_list_free(list);
}

static void bench_purge_v2_medium_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v2_100k_with_free", t_out, 100, {
		populate_list_alloc(list, 100000);
		purge_v2(list);
	});
	rz_list_free(list);
}

static void bench_purge_v3_medium_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v3_100k_with_free", t_out, 100, {
		populate_list_alloc(list, 100000);
		purge_v3(list);
	});
	rz_list_free(list);
}

static void bench_purge_v4_medium_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v4_100k_with_free", t_out, 100, {
		populate_list_alloc(list, 100000);
		purge_v4(list);
	});
	rz_list_free(list);
}

static void bench_purge_v1_large_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v1_1m_with_free", t_out, 10, {
		populate_list_alloc(list, 1000000);
		purge_v1(list);
	});
	rz_list_free(list);
}

static void bench_purge_v2_large_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v2_1m_with_free", t_out, 10, {
		populate_list_alloc(list, 1000000);
		purge_v2(list);
	});
	rz_list_free(list);
}

static void bench_purge_v3_large_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v3_1m_with_free", t_out, 10, {
		populate_list_alloc(list, 1000000);
		purge_v3(list);
	});
	rz_list_free(list);
}

static void bench_purge_v4_large_with_free(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	RZ_BENCH_RUN("purge_v4_1m_with_free", t_out, 10, {
		populate_list_alloc(list, 1000000);
		purge_v4(list);
	});
	rz_list_free(list);
}

// --- Empty list (base overhead) ---

static void bench_purge_v1_empty(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v1_empty", t_out, 10000, {
		purge_v1(list);
	});
	rz_list_free(list);
}

static void bench_purge_v2_empty(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v2_empty", t_out, 10000, {
		purge_v2(list);
	});
	rz_list_free(list);
}

static void bench_purge_v3_empty(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v3_empty", t_out, 10000, {
		purge_v3(list);
	});
	rz_list_free(list);
}

static void bench_purge_v4_empty(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("purge_v4_empty", t_out, 10000, {
		purge_v4(list);
	});
	rz_list_free(list);
}

#define IDX_N 50000

// Build a list of n non-null elements once, for reuse across timed iterations.
static RzList *make_index_list(ut32 n) {
	RzList *list = rz_list_new();
	populate_list(list, n);
	return list;
}

// rz_list_prepend: per-element prepend throughput (allocation + linking).
static void bench_prepend_50k(RzTable *t_out) {
	RZ_BENCH_RUN("prepend_50k", t_out, 200, {
		RzList *list = rz_list_new();
		for (ut32 j = 0; j < IDX_N; j++) {
			rz_list_prepend(list, (void *)(size_t)(j + 1));
		}
		rz_list_free(list);
	});
}

// rz_list_get_n, tail-biased indices: new code walks backward from the tail.
static void bench_get_n_tail_50k(RzTable *t_out) {
	RzList *list = make_index_list(IDX_N);
	RZ_BENCH_RUN_I("get_n_tail_50k", i, t_out, 200000, {
		ut32 n = IDX_N - 1 - (ut32)(i & 7); // always within 8 of the tail
		RZ_DONT_OPTIMIZE(void *, rz_list_get_n(list, n));
	});
	rz_list_free(list);
}

// rz_list_get_n, uniform-random indices: new code averages len/4 vs len/2 steps.
static void bench_get_n_random_50k(RzTable *t_out) {
	RzList *list = make_index_list(IDX_N);
	RZ_BENCH_RUN_I("get_n_random_50k", i, t_out, 100000, {
		ut32 n = (ut32)((i * 2654435761u) % IDX_N); // Knuth multiplicative hash
		RZ_DONT_OPTIMIZE(void *, rz_list_get_n(list, n));
	});
	rz_list_free(list);
}

// rz_list_set_n, tail-biased indices.
static void bench_set_n_tail_50k(RzTable *t_out) {
	RzList *list = make_index_list(IDX_N);
	RZ_BENCH_RUN_I("set_n_tail_50k", i, t_out, 200000, {
		ut32 n = IDX_N - 1 - (ut32)(i & 7);
		RZ_DONT_OPTIMIZE(bool, rz_list_set_n(list, n, (void *)(size_t)(n + 1)));
	});
	rz_list_free(list);
}

// rz_list_del_n at a fixed interior position. The list is large and shrinks by
// only one element per iteration, so the walk length stays ~constant and the
// timing isolates the walk + unlink rather than list rebuild/teardown.
static void bench_del_n_interior(RzTable *t_out) {
	RzList *list = make_index_list(100000);
	RZ_BENCH_RUN("del_n_pos2000_of_100k", t_out, 2000, {
		rz_list_del_n(list, 2000);
	});
	rz_list_free(list);
}

int main() {
	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	// Empty list - base overhead
	bench_purge_v1_empty(t);
	bench_purge_v2_empty(t);
	bench_purge_v3_empty(t);
	bench_purge_v4_empty(t);

	// No free function - pointer-only lists
	bench_purge_v1_small_no_free(t);
	bench_purge_v2_small_no_free(t);
	bench_purge_v3_small_no_free(t);
	bench_purge_v4_small_no_free(t);

	bench_purge_v1_medium_no_free(t);
	bench_purge_v2_medium_no_free(t);
	bench_purge_v3_medium_no_free(t);
	bench_purge_v4_medium_no_free(t);

	bench_purge_v1_large_no_free(t);
	bench_purge_v2_large_no_free(t);
	bench_purge_v3_large_no_free(t);
	bench_purge_v4_large_no_free(t);

	// With free function - heap-allocated elements
	bench_purge_v1_medium_with_free(t);
	bench_purge_v2_medium_with_free(t);
	bench_purge_v3_medium_with_free(t);
	bench_purge_v4_medium_with_free(t);

	bench_purge_v1_large_with_free(t);
	bench_purge_v2_large_with_free(t);
	bench_purge_v3_large_with_free(t);
	bench_purge_v4_large_with_free(t);

	// Functions touched by the RzList traversal optimizations
	bench_prepend_50k(t);
	bench_get_n_tail_50k(t);
	bench_get_n_random_50k(t);
	bench_set_n_tail_50k(t);
	bench_del_n_interior(t);

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}
