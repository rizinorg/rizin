// SPDX-FileCopyrightText: 2017 kriw <kotarou777775@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

bool test_rz_hex_from_code() {
	const char *s;
	char *r;
	s = "char *s = \"ABCD\";";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"AB\" \"CD\";";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"\x41\x42\x43\x44\"";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"\x41\x42\" /* test */ \"\x43\x44\";";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"\n\r\033\"";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "0a0d1b", s);
	free(r);
	s = "uint8_t buffer[3] = {0x41, 0x42, 0x43, 0x44};";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "uint8_t buffer[3] = {0x41,\n0x42,\n0x43,\n0x44};";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "uint8_t buffer[3] = { 0x41 , \n 0x42, \n 0x43 , \n 0x44 } ;";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "uint8_t buffer[3] = {0x41, /* test */0x42, 0x43,/*test*/ 0x44};";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "buf = \"\x41\x42\x43\x44\"";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "buf = [0x41, 0x42, 0x43, 0x44]";
	r = rz_hex_from_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);

	mu_end;
}

bool test_rz_hex_from_c() {
	const char *s;
	char *r;
	s = "char *s = \"ABCD\";";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"AB\" \"CD\";";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"\x41\x42\x43\x44\"";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"\x41\x42\" /* test */ \"\x43\x44\";";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "char *s = \"\n\r\033\"";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "0a0d1b", s);
	free(r);
	s = "uint8_t buffer[3] = {0x41, 0x42, 0x43, 0x44};";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "uint8_t buffer[3] = {0x41,\n0x42,\n0x43,\n0x44};";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "uint8_t buffer[3] = { 0x41 , \n 0x42, \n 0x43 , \n 0x44 } ;";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "uint8_t buffer[3] = {0x41, /* test */0x42, 0x43,/*test*/ 0x44};";
	r = rz_hex_from_c(s);
	mu_assert_streq(r, "41424344", s);
	free(r);

	mu_end;
}

bool test_rz_hex_from_py() {
	const char *s;
	char *r;
	s = "s = \"ABCD\";";
	r = rz_hex_from_py(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "s = \"\x41\x42\x43\x44\"";
	r = rz_hex_from_py(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "s = \"\n\r\"";
	r = rz_hex_from_py(s);
	mu_assert_streq(r, "0a0d", s);
	free(r);
	s = "buffer = [0x41, 0x42, 0x43, 0x44]";
	r = rz_hex_from_py(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "buffer = [0x41,\n0x42,\n0x43,\n0x44]";
	r = rz_hex_from_py(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "buffer = [ 0x41 , \n 0x42, \n 0x43 , \n 0x44 ]";
	r = rz_hex_from_py(s);
	mu_assert_streq(r, "41424344", s);
	free(r);

	mu_end;
}

bool test_rz_hex_no_code() {
	const char *s;
	char *r;
	s = "\"ABCD\"";
	r = rz_hex_no_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "\"AB\" \"CD\"";
	r = rz_hex_no_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "\"AB\"\n\"CD\"\n";
	r = rz_hex_no_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "\"\x41\x42\x43\x44\"";
	r = rz_hex_no_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);
	s = "\"\x41\x42\"  \"\x43\x44\";";
	r = rz_hex_no_code(s);
	mu_assert_streq(r, "41424344", s);
	free(r);

	mu_end;
}

bool test_rz_str2bin(void) {
	ut8 *buf = malloc(100);
	mu_assert_eq(rz_hex_str2bin("41424344", buf), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "ABCD has been written");
	mu_assert_eq(rz_hex_str2bin("0x41424344", buf), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "ABCD has been written");
	mu_assert_eq(rz_hex_str2bin("616263646566", buf), 6, "6 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"abcdef", 6, "abcdef has been written");
	mu_assert_eq(rz_hex_str2bin("61626364656", buf), -6, "error should be returned");
	free(buf);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_hex_from_c);
	mu_run_test(test_rz_hex_from_py);
	mu_run_test(test_rz_hex_from_code);
	mu_run_test(test_rz_hex_no_code);
	mu_run_test(test_rz_str2bin);
	return tests_passed != tests_run;
}

mu_main(all_tests)
