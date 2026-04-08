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

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	return 0;
}