// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_io.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *empty_ref_db() {
	Sdb *db = sdb_new0();
	Sdb *files = sdb_ns(db, "files", true);
	sdb_ns(files, "pcache", true);
	return db;
}

bool test_io_empty_save() {
	RzIO *io = rz_io_new();
	Sdb *db = sdb_new0();
	rz_serialize_io_save(db, io);
	Sdb *expected = empty_ref_db();
	assert_sdb_eq(db, expected, "io save empty");
	sdb_free(db);
	sdb_free(expected);
	rz_io_free(io);
	mu_end;
}

bool test_io_empty_load() {
	Sdb *db = empty_ref_db();
	RzIO *io = rz_io_new();
	bool succ = rz_serialize_io_load(db, io, NULL);
	sdb_free(db);
	mu_assert_true(succ, "load success");
	mu_assert_eq(io->files->size, 0, "empty files");
	rz_io_free(io);
	mu_end;
}

int all_tests() {
	mu_run_test(test_io_empty_save);
	mu_run_test(test_io_empty_load);
	return tests_passed != tests_run;
}

mu_main(all_tests)
