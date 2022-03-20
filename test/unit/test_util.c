// SPDX-FileCopyrightText: 2018 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

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
	mu_assert_notnull(content, "content should not be NULL");
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

bool test_endian(void) {
	ut8 buf[8];
	rz_write_be16(buf, 0x1122);
	mu_assert_memeq((ut8 *)"\x11\x22", buf, 2, "be16");
	rz_write_le16(buf, 0x1122);
	mu_assert_memeq((ut8 *)"\x22\x11", buf, 2, "le16");

	rz_write_be32(buf, 0x11223344);
	mu_assert_memeq((ut8 *)"\x11\x22\x33\x44", buf, 4, "be32");
	rz_write_le32(buf, 0x11223344);
	mu_assert_memeq((ut8 *)"\x44\x33\x22\x11", buf, 4, "le32");

	rz_write_ble(buf, 0x1122, true, 16);
	mu_assert_memeq((ut8 *)"\x11\x22", buf, 2, "ble 16 true");
	rz_write_ble(buf, 0x1122, false, 16);
	mu_assert_memeq((ut8 *)"\x22\x11", buf, 2, "ble 16 false");

	mu_end;
}

int all_tests() {
	mu_run_test(test_file_slurp);
	mu_run_test(test_endian);
	return tests_passed != tests_run;
}

mu_main(all_tests)
