// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static Sdb *setup_sdb(void) {
	Sdb *res = sdb_new0();
	sdb_set(res, "ExitProcess", "func", 0);
	sdb_set(res, "ReadFile", "func", 0);
	sdb_set(res, "memcpy", "func", 0);
	sdb_set(res, "strchr", "func", 0);
	sdb_set(res, "__stack_chk_fail", "func", 0);
	sdb_set(res, "WSAStartup", "func", 0);
	return res;
}

bool test_dll_names(void) {
	Sdb *TDB = setup_sdb();
	char *s;

	s = rz_type_func_guess(TDB, "sub.KERNEL32.dll_ExitProcess");
	mu_assert_notnull(s, "dll_ should be ignored");
	mu_assert_streq(s, "ExitProcess", "dll_ should be ignored");
	free(s);

	s = rz_type_func_guess(TDB, "sub.dll_ExitProcess_32");
	mu_assert_notnull(s, "number should be ignored");
	mu_assert_streq(s, "ExitProcess", "number should be ignored");
	free(s);

	s = rz_type_func_guess(TDB, "sym.imp.KERNEL32.dll_ReadFile");
	mu_assert_notnull(s, "dll_ and number should be ignored case 1");
	mu_assert_streq(s, "ReadFile", "dll_ and number should be ignored case 1");
	free(s);

	s = rz_type_func_guess(TDB, "sub.VCRUNTIME14.dll_memcpy");
	mu_assert_notnull(s, "dll_ and number should be ignored case 2");
	mu_assert_streq(s, "memcpy", "dll_ and number should be ignored case 2");
	free(s);

	s = rz_type_func_guess(TDB, "sub.KERNEL32.dll_ExitProcess_32");
	mu_assert_notnull(s, "dll_ and number should be ignored case 3");
	mu_assert_streq(s, "ExitProcess", "dll_ and number should be ignored case 3");
	free(s);

	s = rz_type_func_guess(TDB, "WS2_32.dll_WSAStartup");
	mu_assert_notnull(s, "dll_ and number should be ignored case 4");
	mu_assert_streq(s, "WSAStartup", "dll_ and number should be ignored case 4");
	free(s);

	sdb_free(TDB);
	mu_end;
}

bool test_ignore_prefixes(void) {
	Sdb *TDB = setup_sdb();
	char *s;

	s = rz_type_func_guess(TDB, "fcn.KERNEL32.dll_ExitProcess_32");
	mu_assert_null(s, "fcn. names should be ignored");
	free(s);

	s = rz_type_func_guess(TDB, "loc.KERNEL32.dll_ExitProcess_32");
	mu_assert_null(s, "loc. names should be ignored");
	free(s);

	sdb_free(TDB);
	mu_end;
}

bool test_remove_rz_prefixes(void) {
	Sdb *TDB = setup_sdb();
	char *s;

	s = rz_type_func_guess(TDB, "sym.imp.ExitProcess");
	mu_assert_notnull(s, "sym.imp should be ignored");
	mu_assert_streq(s, "ExitProcess", "sym.imp should be ignored");
	free(s);

	s = rz_type_func_guess(TDB, "sym.imp.fcn.ExitProcess");
	mu_assert_notnull(s, "sym.imp.fcn should be ignored");
	mu_assert_streq(s, "ExitProcess", "sym.imp.fcn should be ignored");
	free(s);

	s = rz_type_func_guess(TDB, "longprefix.ExitProcess");
	mu_assert_null(s, "prefixes longer than 3 should not be ignored");
	free(s);

	sdb_free(TDB);
	mu_end;
}

bool test_autonames(void) {
	Sdb *TDB = setup_sdb();
	char *s;

	s = rz_type_func_guess(TDB, "sub.strchr_123");
	mu_assert_null(s, "function that calls common fcns shouldn't be identified as such");
	free(s);

	s = rz_type_func_guess(TDB, "sub.__strchr_123");
	mu_assert_null(s, "initial _ should not confuse the api");
	free(s);

	s = rz_type_func_guess(TDB, "sub.__stack_chk_fail_740");
	mu_assert_null(s, "initial _ should not confuse the api");
	free(s);

	s = rz_type_func_guess(TDB, "sym.imp.strchr");
	mu_assert_notnull(s, "sym.imp. should be ignored");
	mu_assert_streq(s, "strchr", "strchr should be identified");
	free(s);

	sdb_free(TDB);
	mu_end;
}

bool test_file_slurp(void) {

#ifdef __WINDOWS__
#define S_IRWXU _S_IREAD | _S_IWRITE
#endif

	const char *test_file = "./empty_file";
	size_t s;
	const char *some_words = "some words";

	int f = open(test_file, O_CREAT, S_IRWXU);
	mu_assert_neq(f, -1, "cannot create empty file");
	close(f);

	char *content = rz_file_slurp(test_file, &s);
	mu_assert_eq(s, 0, "size should be zero");
	mu_assert_eq(strlen(content), 0, "returned buffer should be empty");
	free(content);

	f = open(test_file, O_WRONLY, S_IRWXU);
	mu_assert_neq(f, -1, "cannot reopen empty file");
	rz_xwrite(f, some_words, strlen(some_words));
	close(f);

	content = rz_file_slurp(test_file, &s);
	mu_assert_eq(s, strlen(some_words), "size should be correct");
	mu_assert_eq(strlen(content), strlen(some_words), "size for the buffer should be correct");
	mu_assert_streq(content, some_words, "content should match");
	free(content);

	unlink(test_file);

	mu_end;
}

bool test_initial_underscore(void) {
	Sdb *TDB = setup_sdb();
	char *s;

	s = rz_type_func_guess(TDB, "sym._strchr");
	mu_assert_notnull(s, "sym._ should be ignored");
	mu_assert_streq(s, "strchr", "strchr should be identified");
	free(s);

	sdb_free(TDB);
	mu_end;
}

/* references */
typedef struct {
	const char *name;
	RZ_REF_TYPE;
} TypeTest;

static TypeTest *rz_type_test_new(const char *name) {
	TypeTest *tt = RZ_NEW0(TypeTest);
	if (tt) {
		rz_ref_init(tt);
		tt->name = name;
	}
	return tt;
}

static void rz_type_test_free(TypeTest *tt) {
	tt->name = "";
}

RZ_REF_FUNCTIONS(TypeTest, rz_type_test);

bool test_references(void) {
	TypeTest *tt = rz_type_test_new("foo");
	mu_assert_eq(tt->refcount, 1, "reference count issue");
	rz_type_test_ref(tt);
	mu_assert_eq(tt->refcount, 2, "reference count issue");
	rz_type_test_unref(tt);
	mu_assert_streq(tt->name, "foo", "typetest name should be foo");
	mu_assert_eq(tt->refcount, 1, "reference count issue");
	rz_type_test_unref(tt); // tt becomes invalid
	mu_assert_eq(tt->refcount, 0, "reference count issue");
	mu_assert_streq(tt->name, "", "typetest name should be foo");
	free(tt);
	mu_end;
}

int all_tests() {
	mu_run_test(test_ignore_prefixes);
	mu_run_test(test_remove_rz_prefixes);
	mu_run_test(test_dll_names);
	mu_run_test(test_references);
	mu_run_test(test_autonames);
	mu_run_test(test_file_slurp);
	mu_run_test(test_initial_underscore);
	return tests_passed != tests_run;
}

mu_main(all_tests)