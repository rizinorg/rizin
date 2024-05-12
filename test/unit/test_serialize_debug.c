// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_debug.h>
#include <rz_core.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *get_ref_sdb() {
	Sdb *ref_sdb = sdb_new0();

	Sdb *bp_sdb = sdb_ns(ref_sdb, "breakpoints", true);
	sdb_set(bp_sdb, "0x1337", "{\"cond\":\"bp_cond\",\"data\":\"bp_data\",\"delta\":2,\"enabled\":3,"
				  "\"expr\":\"bp_expr\",\"hits\":4,\"hw\":0,\"internal\":5,\"module_delta\":42,"
				  "\"module_name\":\"hax\",\"name\":\"spectre\",\"perm\":3,\"pids\":[0,1,2,3,4,5,6,7,8,9],"
				  "\"size\":1,\"swstep\":false,\"togglehits\":11,\"trace\":2}");

	return ref_sdb;
}

bool test_debug_serialize_save() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core null");
	rz_core_file_open(core, "malloc://0x3000", RZ_PERM_R, 0);
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set(core->config, "asm.bits", "64");
	RzDebug *debug = core->dbg;
	mu_assert_notnull(debug, "debug null");

	RzBreakpointItem *bp_item = rz_debug_bp_add(debug, 0x1337, 0, false, false, 1, "hax", 42);
	mu_assert_notnull(bp_item, "bp_item null");
	bool set = rz_bp_item_set_cond(bp_item, "bp_cond");
	mu_assert_true(set, "failed to set cond");
	set = rz_bp_item_set_data(bp_item, "bp_data");
	mu_assert_true(set, "failed to set data");
	set = rz_bp_item_set_expr(bp_item, "bp_expr");
	mu_assert_true(set, "failed to set expr");
	set = rz_bp_item_set_name(bp_item, "spectre");
	mu_assert_true(set, "failed to set name");
	bp_item->delta = 2;
	bp_item->enabled = 3;
	bp_item->hits = 4;
	bp_item->internal = 5;
	bp_item->perm = 03;
	for (int i = 0; i < RZ_BP_MAXPIDS; i++) {
		bp_item->pids[i] = i;
	}
	bp_item->swstep = false;
	bp_item->togglehits = 11;
	bp_item->trace = 2;

	Sdb *save_sdb = sdb_new0();
	mu_assert_notnull(save_sdb, "sdb null");
	rz_serialize_debug_save(save_sdb, debug);
	Sdb *ref = get_ref_sdb();
	mu_assert_notnull(ref, "ref sdb null");
	assert_sdb_eq(save_sdb, ref, "saved sdb not same");

	rz_core_file_close(core->file);
	rz_core_free(core);
	sdb_free(save_sdb);
	sdb_free(ref);

	mu_end;
}

bool test_debug_serialize_load() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core null");
	rz_core_file_open(core, "malloc://0x3000", RZ_PERM_R, 0);
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set(core->config, "asm.bits", "64");
	RzDebug *debug = core->dbg;
	mu_assert_notnull(debug, "debug null");

	Sdb *ref = get_ref_sdb();
	Sdb *load_sdb = sdb_new0();
	rz_serialize_debug_load(ref, debug, NULL);
	mu_assert_eq(rz_list_length(debug->bp->bps), 1, "number of breakpoints don't match");
	RzBreakpointItem *bp_item = rz_bp_get_index(debug->bp, 0);

	mu_assert_streq(bp_item->cond, "bp_cond", "cond not equal");
	mu_assert_streq(bp_item->data, "bp_data", "data not equal");
	mu_assert_eq(bp_item->delta, 2, "delta not equal");
	mu_assert_eq(bp_item->enabled, 3, "enabled not equal");
	mu_assert_streq(bp_item->expr, "bp_expr", "bp_expr not equal");
	mu_assert_eq(bp_item->hits, 4, "hits not equal");
	mu_assert_eq(bp_item->internal, 5, "internal not equal");
	mu_assert_streq(bp_item->name, "spectre", "name not equal");
	mu_assert_eq(bp_item->perm, 03, "perm not equal");
	for (int i = 0; i < RZ_BP_MAXPIDS; i++) {
		mu_assert_eq(bp_item->pids[i], i, "pid not equal");
	}
	mu_assert_eq(bp_item->size, 1, "size not equal");
	mu_assert_eq(bp_item->swstep, false, "swstep not equal");
	mu_assert_eq(bp_item->togglehits, 11, "togglehits not equal");
	mu_assert_eq(bp_item->trace, 2, "trace not equal");

	rz_core_file_close(core->file);
	rz_core_free(core);
	sdb_free(load_sdb);
	sdb_free(ref);

	mu_end;
}

int all_tests() {
	mu_run_test(test_debug_serialize_save);
	mu_run_test(test_debug_serialize_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
