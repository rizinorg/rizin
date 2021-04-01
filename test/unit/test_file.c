// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_flag.h>
#include "minunit.h"

struct {
	const char *base;
	const char *path;
	const char *expect;
} relpath_cases[] = {
	{ "that/loonks/heavy", "that/loonks/exponsive", "../exponsive" },
	{ "/that/loonks/heavy", "/that/loonks/exponsive", "../exponsive" },
	{ "do/you/////need/a/hand", "haha//no/thancs///", "../../../../../haha//no/thancs///" },
	{ "C:/attenshone/no/running/in", "C:/the/pool", "../../../../the/pool" },
	{ "/whomst/has/spillened/my", "/whomst/has/spillened/my/dryness", "dryness" },
};

#define RELPATH_CASES_COUNT (sizeof(relpath_cases) / sizeof(relpath_cases[0]))

bool test_rz_file_relpath(const char *base, const char *path, const char *expect) {
	char *base_local = rz_str_replace(strdup(base), "/", RZ_SYS_DIR, 1);
	char *path_local = rz_str_replace(strdup(path), "/", RZ_SYS_DIR, 1);
	char *expect_local = rz_str_replace(strdup(expect), "/", RZ_SYS_DIR, 1);
	char *rel = rz_file_relpath(base_local, path_local);
	mu_assert_streq(rel, expect_local, "relpath");
	free(base_local);
	free(path_local);
	free(expect_local);
	free(rel);
	mu_end;
}

bool test_rz_file_dirname(void) {
	char *s = rz_file_dirname(RZ_SYS_DIR "home" RZ_SYS_DIR "mememan" RZ_SYS_DIR "henlo.txt");
	mu_assert_notnull(s, "dirname not null");
	mu_assert_streq(s, RZ_SYS_DIR "home" RZ_SYS_DIR "mememan", "dirname");
	free(s);

	s = rz_file_dirname(RZ_SYS_DIR "home" RZ_SYS_DIR "mememan" RZ_SYS_DIR);
	mu_assert_notnull(s, "dirname not null");
	mu_assert_streq(s, RZ_SYS_DIR "home" RZ_SYS_DIR "mememan", "dirname");
	free(s);

	s = rz_file_dirname("orang");
	mu_assert_notnull(s, "dirname not null");
	mu_assert_streq(s, "", "dirname");
	free(s);

	s = rz_file_dirname(".");
	mu_assert_notnull(s, "dirname not null");
	mu_assert_streq(s, ".", "dirname");
	free(s);

	s = rz_file_dirname("..");
	mu_assert_notnull(s, "dirname not null");
	mu_assert_streq(s, "..", "dirname");
	free(s);

	mu_end;
}

bool test_rz_file_mmap(void) {
	char *filename = rz_file_temp(NULL);
	RzMmap *m = rz_file_mmap(filename, O_RDWR | O_CREAT, 0644, 0xdead0000);
	mu_assert_notnull(m, "filename should be created");
	mu_assert_streq(m->filename, filename, "filename of mmaped area should ok");
	mu_assert_eq(m->len, 0, "mmaped file should be empty");
	mu_assert_eq(m->base, 0xdead0000, "base address is right");
	mu_assert_eq(m->perm, O_RDWR | O_CREAT, "mmaped perm should be ok");
	rz_file_mmap_resize(m, 0x10);
	mu_assert_eq(m->len, 0x10, "mmaped file should be empty");
	mu_assert_eq(m->base, 0xdead0000, "base address is right");
	strcpy((char *)m->buf, "1234567890ABCDEF");
	rz_file_mmap_free(m);

	m = rz_file_mmap(filename, O_RDONLY, 0644, 0xdead0000);
	mu_assert_eq(m->len, 0x10, "mmaped file should be empty");
	mu_assert_eq(m->base, 0xdead0000, "base address is right");
	mu_assert_streq((char *)m->buf, "1234567890ABCDEF", "previous data has been written to file");
	rz_file_mmap_free(m);

	rz_file_rm(filename);
	free(filename);
	mu_end;
}

int all_tests() {
	size_t i;
	for (i = 0; i < RELPATH_CASES_COUNT; i++) {
		mu_run_test(test_rz_file_relpath, relpath_cases[i].base, relpath_cases[i].path, relpath_cases[i].expect);
	}
	mu_run_test(test_rz_file_dirname);
	mu_run_test(test_rz_file_mmap);
	return tests_passed != tests_run;
}

mu_main(all_tests)