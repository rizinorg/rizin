// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_heap_jemalloc.h>
#include "minunit.h"

/**
 * Unit tests for jemalloc 5.3.0 struct sizes.
 */

bool test_jemalloc_530_struct_sizes_64bit(void) {
	mu_assert_eq(sizeof(phn_link_t_530_64), 24, "phn_link_t_530_64");
	mu_assert_eq(sizeof(ph_t_530_64), 16, "ph_t_530_64");
	mu_assert_eq(sizeof(rtree_leaf_elm_t_530_64), 8, "rtree_leaf_elm_t_530_64");
	mu_assert_eq(sizeof(rtree_node_elm_t_530_64), 8, "rtree_node_elm_t_530_64");
	mu_assert_eq(sizeof(rtree_t_530_64), 2097272, "rtree_t_530_64");
	mu_assert_eq(sizeof(edata_t_530_64), 128, "edata_t_530_64");
	mu_assert_eq(sizeof(nstime_t_530_64), 8, "nstime_t_530_64");
	mu_assert_eq(sizeof(bitmap_info_t_530_64), 16, "bitmap_info_t_530_64");
	mu_assert_eq(sizeof(bin_info_t_530_64), 40, "bin_info_t_530_64");
	mu_assert_eq(sizeof(bin_t_530_64), 224, "bin_t_530_64");
	mu_assert_eq(sizeof(arena_t_530_64), 78952, "arena_t_530_64");
	mu_assert_eq(sizeof(malloc_mutex_t_530_64), 112, "malloc_mutex_t_530_64");
	mu_assert_eq(sizeof(slab_data_t_530_64), 64, "slab_data_t_530_64");
	mu_assert_eq(sizeof(e_prof_info_t_530_64), 32, "e_prof_info_t_530_64");
	mu_assert_eq(sizeof(bin_stats_t_530_64), 80, "bin_stats_t_530_64");
	mu_assert_eq(sizeof(arena_stats_t_530_64), 10368, "arena_stats_t_530_64");
	mu_assert_eq(sizeof(pa_shard_t_530_64), 68280, "pa_shard_t_530_64");
	mu_assert_eq(sizeof(tsdn_t_530_64), 2632, "tsdn_t_530_64");
	mu_end;
}

bool test_jemalloc_530_struct_sizes_32bit(void) {
	mu_assert_eq(sizeof(phn_link_t_530_32), 12, "phn_link_t_530_32");
	mu_assert_eq(sizeof(ph_t_530_32), 8, "ph_t_530_32");
	mu_assert_eq(sizeof(rtree_leaf_elm_t_530_32), 8, "rtree_leaf_elm_t_530_32");
	mu_assert_eq(sizeof(rtree_node_elm_t_530_32), 4, "rtree_node_elm_t_530_32");
	mu_assert_eq(sizeof(rtree_t_530_32), 4188, "rtree_t_530_32");
	mu_assert_eq(sizeof(edata_t_530_32), 108, "edata_t_530_32");
	mu_assert_eq(sizeof(nstime_t_530_32), 8, "nstime_t_530_32");
	mu_assert_eq(sizeof(bitmap_info_t_530_32), 32, "bitmap_info_t_530_32");
	mu_assert_eq(sizeof(bin_info_t_530_32), 48, "bin_info_t_530_32");
	mu_assert_eq(sizeof(bin_t_530_32), 172, "bin_t_530_32");
	mu_assert_eq(sizeof(arena_t_530_32), 22004, "arena_t_530_32");
	mu_assert_eq(sizeof(malloc_mutex_t_530_32), 88, "malloc_mutex_t_530_32");
	mu_assert_eq(sizeof(slab_data_t_530_32), 68, "slab_data_t_530_32");
	mu_assert_eq(sizeof(e_prof_info_t_530_32), 20, "e_prof_info_t_530_32");
	mu_assert_eq(sizeof(bin_stats_t_530_32), 68, "bin_stats_t_530_32");
	mu_assert_eq(sizeof(arena_stats_t_530_32), 3944, "arena_stats_t_530_32");
	mu_assert_eq(sizeof(pa_shard_t_530_32), 17836, "pa_shard_t_530_32");
	mu_assert_eq(sizeof(tsdn_t_530_32), 2064, "tsdn_t_530_32");
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_jemalloc_530_struct_sizes_64bit);
	mu_run_test(test_jemalloc_530_struct_sizes_32bit);
	return tests_passed != tests_run;
}

mu_main(all_tests)
