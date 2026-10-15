// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_pdb.h>
#include "minunit.h"

// Regression cluster for the PDB TPI NULL-data crash.
//
// A malformed TPI type record whose leaf is a known aggregate (LF_STRUCTURE,
// LF_UNION, LF_ENUM, ...) but whose body is too short makes the per-leaf
// parser (class_parse / union_parse / enum_parse) fail and return NULL. Such a
// record used to be stored with its known kind and data == NULL, and the public
// accessors then dereferenced data by kind and crashed.
//
// These tests build exactly that degenerate record by hand and assert every
// public accessor handles it gracefully instead of dereferencing NULL.

static RzPdbTpiType make_null_data_type(RzPDBTpiKind kind, ut16 leaf) {
	RzPdbTpiType t = { 0 };
	t.index = 0x1000;
	t.leaf = leaf;
	t.kind = kind;
	t.data = NULL;
	return t;
}

bool test_pdb_is_fwdref_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505 /* LF_STRUCTURE */);
	RzPdbTpiType u = make_null_data_type(TpiKind_UNION, 0x1506 /* LF_UNION */);
	RzPdbTpiType e = make_null_data_type(TpiKind_ENUM, 0x1507 /* LF_ENUM */);
	mu_assert_false(rz_bin_pdb_type_is_fwdref(&c), "CLASS with NULL data must not be a fwdref");
	mu_assert_false(rz_bin_pdb_type_is_fwdref(&u), "UNION with NULL data must not be a fwdref");
	mu_assert_false(rz_bin_pdb_type_is_fwdref(&e), "ENUM with NULL data must not be a fwdref");
	mu_end;
}

bool test_pdb_get_type_members_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505);
	RzPdbTpiType u = make_null_data_type(TpiKind_UNION, 0x1506);
	RzPdbTpiType e = make_null_data_type(TpiKind_ENUM, 0x1507);
	mu_assert_null(rz_bin_pdb_get_type_members(NULL, &c), "CLASS with NULL data has no members");
	mu_assert_null(rz_bin_pdb_get_type_members(NULL, &u), "UNION with NULL data has no members");
	mu_assert_null(rz_bin_pdb_get_type_members(NULL, &e), "ENUM with NULL data has no members");
	mu_end;
}

bool test_pdb_get_type_val_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505);
	RzPdbTpiType u = make_null_data_type(TpiKind_UNION, 0x1506);
	// Must return the neutral value rather than dereferencing NULL data.
	mu_assert_eq(rz_bin_pdb_get_type_val(&c), 0, "CLASS with NULL data must yield 0");
	mu_assert_eq(rz_bin_pdb_get_type_val(&u), 0, "UNION with NULL data must yield 0");
	mu_end;
}

bool test_pdb_get_type_name_null_data(void) {
	RzPdbTpiType c = make_null_data_type(TpiKind_CLASS, 0x1505);
	mu_assert_null(rz_bin_pdb_get_type_name(&c), "CLASS with NULL data has no name");
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_pdb_is_fwdref_null_data);
	mu_run_test(test_pdb_get_type_members_null_data);
	mu_run_test(test_pdb_get_type_val_null_data);
	mu_run_test(test_pdb_get_type_name_null_data);
	return tests_passed != tests_run;
}

mu_main(all_tests)
