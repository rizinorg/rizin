// SPDX-FileCopyrightText: 2023 Quentin Minster <quentin@minster.io>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *get_ref_sdb() {
	Sdb *ref_sdb = sdb_new0();

	sdb_set(ref_sdb, "-1", "{\"offset\":16,\"cursor\":1,\"current\":false}");
	sdb_set(ref_sdb, "0", "{\"offset\":32,\"cursor\":2,\"current\":true}");
	sdb_set(ref_sdb, "1", "{\"offset\":48,\"cursor\":3,\"current\":false}");
	sdb_set(ref_sdb, "2", "{\"offset\":64,\"cursor\":4,\"current\":false}");

	return ref_sdb;
}

bool test_seek_serialize_save() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core null");
	rz_core_file_open(core, "malloc://0x3000", RZ_PERM_R, 0);

	bool sought = rz_core_seek(core, 0x10, false);
	rz_print_set_cursor(core->print, true, 0, 1);
	mu_assert_true(sought, "failed to seek 0x10");
	sought = rz_core_seek_and_save(core, 0x20, false);
	rz_print_set_cursor(core->print, true, 0, 2);
	mu_assert_true(sought, "failed to seek 0x20");
	sought = rz_core_seek_and_save(core, 0x30, false);
	rz_print_set_cursor(core->print, true, 0, 3);
	mu_assert_true(sought, "failed to seek 0x30");
	sought = rz_core_seek_and_save(core, 0x40, false);
	rz_print_set_cursor(core->print, true, 0, 4);
	mu_assert_true(sought, "failed to seek 0x40");
	sought = rz_core_seek_undo(core);
	mu_assert_true(sought, "failed first undo seek");
	sought = rz_core_seek_undo(core);
	mu_assert_true(sought, "failed second undo seek");

	Sdb *save_sdb = sdb_new0();
	mu_assert_notnull(save_sdb, "sdb null");
	rz_serialize_core_seek_save(save_sdb, core);
	Sdb *ref = get_ref_sdb();
	mu_assert_notnull(ref, "ref sdb null");
	assert_sdb_eq(save_sdb, ref, "saved sdb not same");

	rz_core_file_close(core->file);
	rz_core_free(core);
	sdb_free(save_sdb);
	sdb_free(ref);

	mu_end;
}

bool test_seek_serialize_load() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core null");
	rz_core_file_open(core, "malloc://0x3000", RZ_PERM_R, 0);

	// enable the cursor so we can check the deserialized value
	rz_print_set_cursor(core->print, true, 0, 0);

	Sdb *ref = get_ref_sdb();
	Sdb *load_sdb = sdb_new0();
	rz_serialize_core_seek_load(ref, core, NULL);

	mu_assert_eq(rz_vector_len(&core->seek_history.undos), 1, "bad number of undos");
	RzCoreSeekItem *item = rz_vector_index_ptr(&core->seek_history.undos, 0);
	mu_assert_eq(item->offset, 0x10, "bad undo offset");
	mu_assert_eq(item->cursor, 1, "bad undo cursor");

	mu_assert_eq(rz_vector_len(&core->seek_history.redos), 2, "bad number of redos");
	item = rz_vector_index_ptr(&core->seek_history.redos, 1);
	mu_assert_eq(item->offset, 0x30, "bad first redo offset");
	mu_assert_eq(item->cursor, 3, "bad first redo cursor");
	item = rz_vector_index_ptr(&core->seek_history.redos, 0);
	mu_assert_eq(item->offset, 0x40, "bad second redo offset");
	mu_assert_eq(item->cursor, 4, "bad second redo cursor");

	// core offset not restored from current seek history item, so not checked
	mu_assert_eq(rz_print_get_cursor(core->print), 2, "bad current cursor");

	rz_core_file_close(core->file);
	rz_core_free(core);
	sdb_free(load_sdb);
	sdb_free(ref);

	mu_end;
}

int all_tests() {
	mu_run_test(test_seek_serialize_save);
	mu_run_test(test_seek_serialize_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
