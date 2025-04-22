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
	ut8 *buf = calloc(100, sizeof(ut8));
	mu_assert_eq(rz_hex_str2bin("", buf), 0, "0 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"", 0, "'0' has been written");

	mu_assert_eq(rz_hex_str2bin("41424344", buf), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "ABCD has been written");

	mu_assert_eq(rz_hex_str2bin("0x41424344", buf), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "ABCD has been written");

	mu_assert_eq(rz_hex_str2bin("616263646566", buf), 6, "6 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"abcdef", 6, "abcdef has been written");

	mu_assert_eq(rz_hex_str2bin("61626364656", buf), -6, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"abcde\x60", 6, "abcdef has been written");

	mu_assert_eq(rz_hex_str2bin("61", buf), 1, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"a", 1, "a has been written");
	free(buf);
	mu_end;
}

bool test_rz_str2bin_msb(void) {
	ut8 *buf = calloc(100, sizeof(ut8));
	mu_assert_eq(rz_hex_str2bin_msb("", buf), 0, "0 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"", 0, "'0' has been written");

	mu_assert_eq(rz_hex_str2bin_msb("61", buf), 1, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"a", 1, "a has been written");

	mu_assert_eq(rz_hex_str2bin_msb("41424344", buf), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "ABCD has been written");

	mu_assert_eq(rz_hex_str2bin_msb("0x41424344", buf), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "ABCD has been written");

	mu_assert_eq(rz_hex_str2bin_msb("616263646566", buf), 6, "6 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"abcdef", 6, "abcdef has been written");

	mu_assert_eq(rz_hex_str2bin_msb("61626364656", buf), -6, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x06\x16\x26\x36\x46\x56", 6, "abcdef has been written");

	mu_assert_eq(rz_hex_str2bin_msb("0x61626364656", buf), -6, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x06\x16\x26\x36\x46\x56", 6, "abcdef has been written");
	free(buf);
	mu_end;
}

bool test_rz_str2bin_mask(void) {
	ut8 *buf = calloc(100, sizeof(ut8));
	ut8 *mask = calloc(100, sizeof(ut8));
	mu_assert_eq(rz_hex_str2bin_mask("", buf, mask, false), 0, "0 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"", 0, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"", 0, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("41424344", buf, mask, false), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xff\xff\xff\xff", 4, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask(".14.", buf, mask, false), 2, "2 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"\x01\x40", 2, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\x0f\xf0", 2, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("0140", buf, mask, false), 2, "2 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"\x01\x40", 2, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xff\xff", 2, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("0x41424344", buf, mask, false), 4, "4 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"ABCD", 4, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xff\xff\xff\xff", 4, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("616263646566", buf, mask, false), 6, "6 bytes are written");
	mu_assert_memeq(buf, (ut8 *)"abcdef", 6, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xff\xff\xff\xff\xff\xff", 6, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("61626364656", buf, mask, true), 6, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"abcde\x60", 6, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xff\xff\xff\xff\xff\xf0", 6, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("61626364656", buf, mask, false), 6, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x06\x16\x26\x36\x46\x56", 6, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\x0f\xff\xff\xff\xff\xff", 6, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("6", buf, mask, true), 1, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x60", 1, "Mem mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xf0", 1, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("6", buf, mask, false), 1, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x06", 1, "Mem mismatch");
	mu_assert_memeq(mask, (ut8 *)"\x0f", 1, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("61", buf, mask, false), 1, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"a", 1, "Buffer mismatch");
	mu_assert_memeq(mask, (ut8 *)"\xff", 1, "Mask doesn't match");

	mu_assert_eq(rz_hex_str2bin_mask("ffffffffff", buf, NULL, false), 5, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\xff\xff\xff\xff\xff", 5, "Buffer mismatch");

	mu_assert_eq(rz_hex_str2bin_mask("fffffffff", buf, NULL, false), 5, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x0f\xff\xff\xff\xff", 5, "Buffer mismatch");

	mu_assert_eq(rz_hex_str2bin_mask("0xffffffffff", buf, NULL, false), 5, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\xff\xff\xff\xff\xff", 5, "Buffer mismatch");

	mu_assert_eq(rz_hex_str2bin_mask("0xfffffffff", buf, NULL, false), 5, "error should be returned");
	mu_assert_memeq(buf, (ut8 *)"\x0f\xff\xff\xff\xff", 5, "Buffer mismatch");
	free(mask);
	free(buf);
	mu_end;
}

bool test_rz_hex_nibble_to_byte(void) {
	mu_assert_eq(rz_hex_digit_to_byte('/'), UT8_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('0'), 0, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('1'), 1, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('8'), 8, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('9'), 9, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte(':'), UT8_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('@'), UT8_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('A'), 10, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('B'), 11, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('E'), 14, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('F'), 15, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('G'), UT8_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('`'), UT8_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('a'), 10, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('b'), 11, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('e'), 14, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('f'), 15, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('g'), UT8_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_to_byte('\0'), UT8_MAX, "Mismatch");
	mu_end;
}

bool test_rz_hex_nibble_pair_to_byte(void) {
	mu_assert_eq(rz_hex_digit_pair_to_byte("1"), 1, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("11"), 17, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("12"), 18, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("fe"), 254, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("ff01"), 255, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("ff"), 255, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("F@"), 15, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte("p1"), UT16_MAX, "Mismatch");
	mu_assert_eq(rz_hex_digit_pair_to_byte(""), UT16_MAX, "Mismatch");
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_hex_from_c);
	mu_run_test(test_rz_hex_from_py);
	mu_run_test(test_rz_hex_from_code);
	mu_run_test(test_rz_hex_no_code);
	mu_run_test(test_rz_hex_nibble_to_byte);
	mu_run_test(test_rz_hex_nibble_pair_to_byte);
	mu_run_test(test_rz_str2bin);
	mu_run_test(test_rz_str2bin_msb);
	mu_run_test(test_rz_str2bin_mask);
	return tests_passed != tests_run;
}

mu_main(all_tests)
