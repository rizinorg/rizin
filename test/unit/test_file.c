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

bool test_rz_file_basename(void) {
	const char *s = rz_file_basename("./\\test/\\//\\abc//\\/123/\\o.txt");
	mu_assert_notnull(s, "basename not null");
#if __WINDOWS__
	mu_assert_streq(s, "o.txt", "basename is supposed to be o.txt");
#else
	mu_assert_streq(s, "\\o.txt", "basename is supposed to be \\o.txt");
#endif
	s = rz_file_basename("./\\test/\\//\\abc//\\/123\\/o.txt");
	mu_assert_notnull(s, "basename not null");
	mu_assert_streq(s, "o.txt", "basename is supposed to be o.txt");
	mu_end;
}

bool test_rz_file_dos_basename(void) {
	const char *s = rz_file_dos_basename("./\\test/\\//\\abc//\\/123/\\o.txt");
	mu_assert_notnull(s, "basename not null");
	mu_assert_streq(s, "o.txt", "basename is supposed to be o.txt");
	s = rz_file_basename("./\\test/\\//\\abc//\\/123\\/o.txt");
	mu_assert_notnull(s, "basename not null");
	mu_assert_streq(s, "o.txt", "basename is supposed to be o.txt");
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
	// Sometimes rz_file_mmap_resize() can free file, we should ensure it doesn't do that
	mu_assert_notnull(m, "mmaped file should not be freed after resize");
	mu_assert_eq(m->len, 0x10, "mmaped file should be empty");
	mu_assert_eq(m->base, 0xdead0000, "base address is right");
	memcpy(m->buf, "1234567890ABCDEF", 0x10);
	rz_file_mmap_resize(m, 0);
	mu_assert_eq(m->len, 0, "mmaped file should resize to 0");
	mu_assert_null(m->buf, "mmaped buf should be NULL after resize to 0");
	rz_file_mmap_free(m);

	m = rz_file_mmap(filename, O_RDWR, 0644, 0xdead0000);
	mu_assert_notnull(m, "reopen after zero resize");
	mu_assert_notnull(rz_file_mmap_resize(m, 0x10), "resize back from 0");
	memcpy(m->buf, "1234567890ABCDEF", 0x10);
	rz_file_mmap_free(m);

	m = rz_file_mmap(filename, O_RDONLY, 0644, 0xdead0000);
	mu_assert_eq(m->len, 0x10, "mmaped file should be empty");
	mu_assert_eq(m->base, 0xdead0000, "base address is right");
	mu_assert_memeq(m->buf, (const ut8 *)"1234567890ABCDEF", 0x10, "previous data has been written to file");
	rz_file_mmap_free(m);

	mu_assert_null(rz_file_mmap_resize(NULL, 0x10), "resize NULL mmap returns NULL");
	mu_assert_null(rz_file_mmap("/nonexistent_rz_mmap_dir/file", O_RDONLY, 0, 0), "mmap nonexistent fails");
#if __UNIX__
	mu_assert_null(rz_file_mmap("/", O_RDONLY, 0, 0), "mmap directory fails cleanly");
	m = rz_file_mmap(filename, O_RDWR, 0644, 0xdead0000);
	mu_assert_notnull(m, "open for open-failure resize test");
	m->perm = O_RDWR | O_CREAT | O_EXCL;
	mu_assert_null(rz_file_mmap_resize(m, 0x10), "resize fails cleanly when reopen fails");
	rz_file_mmap_free(m);

	RzBuffer *mb = rz_buf_new_mmap(filename, O_RDWR, 0644, NULL);
	mu_assert_notnull(mb, "buf_new_mmap");
	mu_assert_true(rz_buf_resize(mb, 0x20), "buf_mmap resize up");
	mu_assert_true(rz_buf_resize(mb, 0), "buf_mmap resize to 0");
	mu_assert_eq(rz_buf_write(mb, (const ut8 *)"x", 0), 0, "buf_mmap 0-byte write on 0-length buffer");
	mu_assert_eq(rz_buf_size(mb), 0, "buf_mmap size remains 0 after 0-byte write");
	mu_assert_true(rz_buf_resize(mb, 0x10), "buf_mmap resize from 0");
	mu_assert_true(rz_file_rm(filename), "remove temp file before failed resize");
	mu_assert_false(rz_buf_resize(mb, 0x20), "buf_mmap resize fails after file removal");
	mu_assert_false(rz_buf_resize(mb, 0), "buf_mmap resize to 0 fails after file removal");
	rz_buf_free(mb);
#else
	rz_file_rm(filename);
#endif

	free(filename);
	mu_end;
}

bool test_rz_file_slurp_hexpairs(void) {
	char *filename = rz_file_temp(NULL);
	mu_assert_notnull(filename, "temp file");

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"1", 1, false), "dump single digit");
	int sz = 0;
	ut8 *buf = rz_file_slurp_hexpairs(filename, &sz);
	mu_assert_notnull(buf, "single digit hexpair");
	mu_assert_eq(sz, 1, "single digit size");
	mu_assert_eq(buf[0], 0x01, "single digit value");
	free(buf);

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"# comment\n1 2 3 4 5\n", 20, false), "dump odd hexpairs");
	buf = rz_file_slurp_hexpairs(filename, &sz);
	mu_assert_notnull(buf, "multi single-digit hexpairs");
	mu_assert_eq(sz, 5, "five bytes");
	mu_assert_memeq(buf, (const ut8 *)"\x01\x02\x03\x04\x05", 5, "values match");
	free(buf);

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"zz", 2, false), "dump invalid hex");
	mu_assert_null(rz_file_slurp_hexpairs(filename, &sz), "invalid hex returns NULL");
	mu_assert_null(rz_file_slurp_hexpairs("/nonexistent_rz_hexpairs_test", &sz), "missing file returns NULL");

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"4142", 4, false), "dump valid hex for NULL usz");
	buf = rz_file_slurp_hexpairs(filename, NULL);
	mu_assert_notnull(buf, "slurp hexpairs with NULL usz");
	mu_assert_memeq(buf, (const ut8 *)"AB", 2, "values match with NULL usz");
	free(buf);

	rz_file_rm(filename);
	free(filename);
	mu_end;
}

bool test_rz_file_slurp_lines_from_bottom(void) {
	char *filename = rz_file_temp(NULL);
	mu_assert_notnull(filename, "temp file");

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"", 0, false), "dump empty");
	char *s = rz_file_slurp_lines_from_bottom(filename, 0);
	mu_assert_streq_free(s, "", "empty file 0 lines");
	s = rz_file_slurp_lines_from_bottom(filename, 1);
	mu_assert_streq_free(s, "", "empty file 1 line");

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"\n", 1, false), "dump newline");
	s = rz_file_slurp_lines_from_bottom(filename, 1);
	mu_assert_streq_free(s, "\n", "single newline 1 line");

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"\na\n", 3, false), "dump leading newline");
	s = rz_file_slurp_lines_from_bottom(filename, 2);
	mu_assert_streq_free(s, "\na\n", "leading newline 2 lines");

	mu_assert_true(rz_file_dump(filename, (const ut8 *)"a\nb\nc\n", 6, false), "dump 3 lines");
	s = rz_file_slurp_lines_from_bottom(filename, 1);
	mu_assert_streq_free(s, "c\n", "last line");
	s = rz_file_slurp_lines_from_bottom(filename, 0);
	mu_assert_streq_free(s, "", "0 lines");
	s = rz_file_slurp_lines_from_bottom(filename, -1);
	mu_assert_streq_free(s, "", "negative lines");

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
	mu_run_test(test_rz_file_basename);
	mu_run_test(test_rz_file_dos_basename);
	mu_run_test(test_rz_file_mmap);
	mu_run_test(test_rz_file_slurp_hexpairs);
	mu_run_test(test_rz_file_slurp_lines_from_bottom);
	return tests_passed != tests_run;
}

mu_main(all_tests)
