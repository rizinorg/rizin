// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_config.h>
#include "minunit.h"
#include "test_sdb.h"

Sdb *ref_db() {
	Sdb *db = sdb_new0();
	sdb_set(db, "somestring", "somevalue");
	sdb_set(db, "someint", "42");
	sdb_set(db, "somebiggerint", "0x00001337");
	return db;
}

bool test_config_save() {
	RzConfig *config = rz_config_new(NULL);
	rz_config_set(config, "somestring", "somevalue");
	rz_config_set_i(config, "someint", 42);
	rz_config_set_i(config, "somebiggerint", 0x1337);
	rz_config_lock(config, true);

	Sdb *db = sdb_new0();
	rz_serialize_config_save(db, config);
	rz_config_free(config);

	Sdb *expected = ref_db();
	assert_sdb_eq(db, expected, "config save");
	sdb_free(db);
	sdb_free(expected);
	mu_end;
}

bool test_config_load() {
	RzConfig *config = rz_config_new(NULL);
	rz_config_set(config, "somestring", "someoldvalue");
	rz_config_set_i(config, "someint", 0);
	rz_config_set_i(config, "somebiggerint", 0);
	rz_config_lock(config, true);

	Sdb *db = ref_db();
	sdb_set(db, "sneaky", "not part of config");
	bool loaded = rz_serialize_config_load(db, config, NULL, NULL);
	sdb_free(db);
	mu_assert("load success", loaded);

	mu_assert_eq(rz_list_length(config->nodes), 3, "count after load");
	mu_assert_streq(rz_config_get(config, "somestring"), "somevalue", "loaded config string");
	mu_assert_eq_fmt(rz_config_get_i(config, "someint"), (ut64)42, "loaded config int", "%" PFMT64u);
	mu_assert_eq_fmt(rz_config_get_i(config, "somebiggerint"), (ut64)0x1337, "loaded config bigger int", "0x%" PFMT64x);
	rz_config_free(config);
	mu_end;
}

bool test_config_load_exclude() {
	static const char *const exclude[] = {
		"somestring",
		"someint",
		NULL
	};
	RzConfig *config = rz_config_new(NULL);
	rz_config_set(config, "somestring", "someoldvalue");
	rz_config_set_i(config, "someint", 123);
	rz_config_set_i(config, "somebiggerint", 0);
	rz_config_lock(config, true);

	Sdb *db = ref_db();
	bool loaded = rz_serialize_config_load(db, config, exclude, NULL);
	sdb_free(db);
	mu_assert("load success", loaded);

	mu_assert_eq(rz_list_length(config->nodes), 3, "count after load");
	mu_assert_streq(rz_config_get(config, "somestring"), "someoldvalue", "excluded config string");
	mu_assert_eq_fmt(rz_config_get_i(config, "someint"), (ut64)123, "excluded config int", "%" PFMT64u);
	mu_assert_eq_fmt(rz_config_get_i(config, "somebiggerint"), (ut64)0x1337, "loaded config bigger int", "0x%" PFMT64x);
	rz_config_free(config);
	mu_end;
}

int all_tests() {
	mu_run_test(test_config_save);
	mu_run_test(test_config_load);
	mu_run_test(test_config_load_exclude);
	return tests_passed != tests_run;
}

mu_main(all_tests)