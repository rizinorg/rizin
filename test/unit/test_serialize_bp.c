// SPDX-FileCopyrightText: 2021 DMaroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_bp.h>
#include <rz_debug.h>
#include "minunit.h"

bool test_bp_save_load() {
	Sdb *bp_sdb = sdb_new0();
	mu_assert_notnull(bp_sdb, "failed to create sdb");
	RzDebug *debug_save = rz_debug_new(0);
	mu_assert_notnull(debug_save, "failed to create debug instance");

	RzBreakpointItem *item_save = rz_debug_bp_add(debug_save, 0x1337, 0, true, 0, "doom", 42);
	mu_assert_notnull(item_save, "failed to create bp item");
	item_save->bbytes = NULL;
	item_save->data = "somedata";
	item_save->enabled = 1;
	item_save->expr = "alpha+beta";
	item_save->module_delta = 0x41;
	item_save->internal = 0;
	item_save->hits = 7;
	item_save->name = "morpheus";
	item_save->obytes = NULL;
	for (int i = 0; i < RZ_BP_MAXPIDS; i++) {
		item_save->pids[i] = i;
	}
	item_save->perm = 0644;
	item_save->size = 0x101;
	item_save->swstep = false;
	item_save->togglehits = 10;
	item_save->trace = 0;

	rz_serialize_bp_save(bp_sdb, debug_save->bp);
	mu_assert_true(sdb_exists(bp_sdb, "0x1337"), "key does not exist");

	RzDebug *debug_load = rz_debug_new(0);
	mu_assert_notnull(debug_load, "failed to create debug instance");
	mu_assert_true(rz_serialize_bp_load(bp_sdb, debug_load->bp, NULL), "failed to load bp");
	mu_assert_eq(debug_load->bp->bps_idx_count, 1, "breakpoint count not matching");

	RzBreakpointItem *item_load = rz_bp_get_index(debug_load->bp, 0);
	mu_assert_eq(item_load->addr, item_save->addr, "addr different");
	mu_assert_eq(item_load->delta, item_save->delta, "delta different");
	mu_assert_eq(item_load->enabled, item_save->enabled, "enabled different");
	mu_assert_eq(item_load->hits, item_save->hits, "hits different"); // lol
	mu_assert_eq(item_load->hw, item_save->hw, "hw different");
	mu_assert_eq(item_load->internal, item_save->internal, "internal different");
	mu_assert_eq(item_load->module_delta, item_save->module_delta, "module_delta different");
	mu_assert_eq(item_load->perm, item_save->perm, "perm different");
	mu_assert_eq(item_load->size, item_save->size, "size different");
	mu_assert_eq(item_load->swstep, item_save->swstep, "swstep different");
	mu_assert_eq(item_load->togglehits, item_save->togglehits, "togglehits different");
	mu_assert_eq(item_load->trace, item_save->trace, "trace different");

	mu_assert_streq((char *)item_load->bbytes, (char *)item_save->bbytes, "bbytes different");
	mu_assert_streq((char *)item_load->obytes, (char *)item_save->obytes, "obytes different");
	mu_assert_streq(item_load->cond, item_save->cond, "cond different");
	mu_assert_streq(item_load->data, item_save->data, "data different");
	mu_assert_streq(item_load->expr, item_save->expr, "expr different");
	mu_assert_streq(item_load->module_name, item_save->module_name, "module_name different");
	mu_assert_streq(item_load->name, item_save->name, "name different");

	for (int i = 0; i < RZ_BP_MAXPIDS; i++) {
		mu_assert_eq(item_load->pids[i], item_save->pids[i], "pid different");
	}

	rz_debug_free(debug_save);
	rz_debug_free(debug_load);
	mu_assert_true(sdb_free(bp_sdb), "failed to free sdb");

	mu_end;
}

int all_tests() {
	mu_run_test(test_bp_save_load);
	return tests_passed != tests_run;
}

mu_main(all_tests);
