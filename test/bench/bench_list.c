// SPDX-FileCopyrightText: 2026 Farhan-25 <shadowfinder1799@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include "bench_utils.h"
#include <rz_util.h>
#include <rz_util/rz_num.h>

/**
 * \file bench_list.c
 * \brief Benchmarks for `RzList` operations and purge implementations.
 */

#define LIST_SORT_N  4096
#define LIST_SMALL_N 32
#define LIST_GETN_N  4096
#define LIST_TOSTR_N 512

static int list_cmp_ptr_as_u64(const void *a, const void *b, void *user) {
	(void)user;
	ut64 x = (ut64)(size_t)a, y = (ut64)(size_t)b;
	return (x > y) - (x < y);
}

/**
 * \brief Sort a descending list repeatedly, including the cost of reversal.
 */
static void bench_list_sort_large(RzTable *t_out) {
	RzList *list = rz_list_new();
	for (ut32 j = 0; j < LIST_SORT_N; ++j) {
		rz_list_append(list, (void *)(size_t)rz_num_rand32(UT32_MAX));
	}
	rz_list_sort(list, list_cmp_ptr_as_u64, NULL);
	RZ_BENCH_RUN("[RzList] reverse+sort 4k descending", t_out, 300, {
		rz_list_reverse(list);
		list->sorted = false;
		rz_list_sort(list, list_cmp_ptr_as_u64, NULL);
	});
	rz_list_free(list);
}

/**
 * \brief Sort a small list repeatedly through the insertion sort path.
 *
 * The "presorted" variant shows the best case behaviour of the sort.
 */
static void bench_list_sort_small(RzTable *t_out) {
	RzList *list = rz_list_new();
	for (ut32 j = 0; j < LIST_SMALL_N; ++j) {
		rz_list_append(list, (void *)(size_t)rz_num_rand32(UT32_MAX));
	}
	rz_list_sort(list, list_cmp_ptr_as_u64, NULL);
	RZ_BENCH_RUN("[RzList] reverse+sort 32 descending", t_out, 5000, {
		rz_list_reverse(list);
		list->sorted = false;
		rz_list_sort(list, list_cmp_ptr_as_u64, NULL);
	});
	// list is now sorted ascending
	RZ_BENCH_RUN("[RzList] rz_list_sort 32 presorted", t_out, 5000, {
		list->sorted = false; // force sorting although the list is sorted
		rz_list_sort(list, list_cmp_ptr_as_u64, NULL);
	});
	rz_list_free(list);
}

static void bench_list_get_n(RzTable *t_out) {
	RzList *list = rz_list_new();
	for (ut32 j = 0; j < LIST_GETN_N; ++j) {
		rz_list_append(list, (void *)(size_t)(j + 1));
	}
	RZ_BENCH_RUN("[RzList] rz_list_get_n random idx 4k", t_out, 20000, {
		ut32 n = rz_num_rand32(LIST_GETN_N - 1);
		RZ_DONT_OPTIMIZE(void *, rz_list_get_n(list, n));
	});
	rz_list_free(list);
}

static void bench_list_to_str(RzTable *t_out) {
	RzList *list = rz_list_newf(free);
	for (ut32 j = 0; j < LIST_TOSTR_N; ++j) {
		char buf[16];
		snprintf(buf, sizeof(buf), "item%03u", j);
		rz_list_append(list, rz_str_dup(buf));
	}
	RZ_BENCH_RUN("[RzList] rz_list_to_str 512 items", t_out, 2000, {
		char *s = rz_list_to_str(list, ',', false);
		free(s);
	});
	rz_list_free(list);
}

static void bench_list_append_pop(RzTable *t_out) {
	RzList *list = rz_list_new();
	RZ_BENCH_RUN("[RzList] append+pop 1k cycle", t_out, 3000, {
		for (ut32 j = 0; j < 1000; ++j) {
			rz_list_append(list, (void *)(size_t)(j + 1));
		}
		for (ut32 j = 0; j < 1000; ++j) {
			rz_list_pop(list);
		}
	});
	rz_list_free(list);
}

/**
 * \brief Repeat accessor calls to measure their aggregate cost.
 *
 * The trivial getters are called all over Rizin. Bench them amplified,
 * because the per-call costs are below the clock resolution of the framework.
 */
static void bench_list_accessors(RzTable *t_out) {
	RzList *list = rz_list_new();
	for (ut32 j = 0; j < 1024; ++j) {
		rz_list_append(list, (void *)(size_t)(j + 1));
	}
	RzListIter *mid = rz_list_head(list);
	for (ut32 j = 0; j < 512; ++j) {
		mid = rz_list_next(mid);
	}
	RZ_BENCH_RUN("[RzList] rz_list_length x1000", t_out, 20000, {
		for (ut32 k = 0; k < 1000; ++k) {
			RZ_DONT_OPTIMIZE(ut32, rz_list_length(list));
		}
	});
	RZ_BENCH_RUN("[RzList] rz_list_first_val x1000", t_out, 20000, {
		for (ut32 k = 0; k < 1000; ++k) {
			RZ_DONT_OPTIMIZE(void *, rz_list_first_val(list));
		}
	});
	RZ_BENCH_RUN("[RzList] rz_list_iter_get_next_data x1000", t_out, 20000, {
		for (ut32 k = 0; k < 1000; ++k) {
			RZ_DONT_OPTIMIZE(void *, rz_list_iter_get_next_data(mid));
		}
	});
	rz_list_free(list);
}

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

	// Hot-path benchmarks
	bench_list_sort_large(t);
	bench_list_sort_small(t);
	bench_list_get_n(t);
	bench_list_to_str(t);
	bench_list_append_pop(t);
	bench_list_accessors(t);

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
