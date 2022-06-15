// SPDX-FileCopyrightText: 2021 borzacchiello <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static RzUtilStrScanOptions g_opt = {
	.buf_size = 2048,
	.max_uni_blocks = 4,
	.min_str_length = 4,
	.prefer_big_endian = false,
	.check_ascii_freq = true
};

bool test_rz_scan_strings_detect_ascii(void) {
	static const unsigned char str[] = "\xff\xff\xffI am an ASCII string\xff\xff";
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings ascii, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an ASCII string", "rz_scan_strings ascii, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings ascii, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_8BIT, "rz_scan_strings ascii, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_ibm037(void) {
	static const unsigned char str[] = "\xc9\x40\x81\x94\x40\x81\x95\x40\xc9\xc2\xd4\xf0\xf3\xf7\x40\xa2\xa3\x99\x89\x95\x87\x25";
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings ibm037, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an IBM037 string", "rz_scan_strings ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_IBM037, "rz_scan_strings ibm037, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	/**
	 * two strings:
	 * 1. "Ber. Who's there.?\x00"
	 * 2. "Fran. Nay, answer me. Stand and unfold yourself"
	 */
	static const unsigned char str2[] = "\xff\xff\xff\xC2\x85\x99\x4B\x40\xE6\x88\x96\x7D\xA2\x40\xA3\x88\x85\x99\x85\x4B\x6F\x00\xC6\x99\x81\x95\x4B\x40\xD5\x81\xA8\x6B\x40\x81\x95\xA2\xA6\x85\x99\x40\x94\x85\x4B\x40\xE2\xA3\x81\x95\x84\x40\x81\x95\x84\x40\xA4\x95\x86\x96\x93\x84\x40\xA8\x96\xA4\x99\xA2\x85\x93\x86";
	buf = rz_buf_new_with_bytes(str2, sizeof(str2));

	str_list = rz_list_new();
	n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 2, "rz_scan_strings ibm037, number of strings");

	s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "Ber. Who's there.?", "rz_scan_strings ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_IBM037, "rz_scan_strings ibm037, string type");
	rz_detected_string_free(s);

	s = rz_list_get_n(str_list, 1);
	mu_assert_streq(s->string, "Fran. Nay, answer me. Stand and unfold yourself", "rz_scan_strings ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_IBM037, "rz_scan_strings ibm037, string type");
	rz_detected_string_free(s);

	rz_list_free(str_list);
	rz_buf_free(buf);

	// UTF and EBCDIC strings in one memory
	static const unsigned char str3[] =
		"\xff\xff\xff\xc9\x40\x81\x94\x40\x81\x95\x40\xc9\xc2\xd4\xf0\xf3\xf7\x40\xa2\xa3\x99\x89\x95\x87\x25\xff\xff\xff"
		"\xff\xff\xff\xffI am a \xc3\x99TF-8 string\xff\xff\xff\xff";
	buf = rz_buf_new_with_bytes(str3, sizeof(str3));

	str_list = rz_list_new();
	n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 2, "rz_scan_strings mix utf8 and ibm037, number of strings");

	s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an IBM037 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_IBM037, "rz_scan_strings mix utf8 and ibm037, string type");
	rz_detected_string_free(s);

	s = rz_list_get_n(str_list, 1);
	mu_assert_streq(s->string, "I am a \xc3\x99TF-8 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF8, "rz_scan_strings mix utf8 and ibm037, string type");
	rz_detected_string_free(s);

	rz_list_free(str_list);
	rz_buf_free(buf);

	// one of the ending chars of UTF-8 is actually one of the starting chars of the EBCDIC string
	static const unsigned char str4[] =
		"\xff\xff\xff\xc9\x40\x81\x94\x40\x81\x95\x40\xc9\xc2\xd4\xf0\xf3\xf7\x40\xa2\xa3\x99\x89\x95\x87\x25"
		"I am a \xc3\x99TF-8 string\xff\xff\xff";
	buf = rz_buf_new_with_bytes(str4, sizeof(str4));

	str_list = rz_list_new();
	n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 2, "rz_scan_strings mix utf8 and ibm037, number of strings");

	s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an IBM037 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_IBM037, "rz_scan_strings mix utf8 and ibm037, string type");
	rz_detected_string_free(s);

	s = rz_list_get_n(str_list, 1);
	mu_assert_streq(s->string, "I am a \xc3\x99TF-8 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF8, "rz_scan_strings mix utf8 and ibm037, string type");
	rz_detected_string_free(s);

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf8(void) {
	static const unsigned char str[] = "\xff\xff\xff\xffI am a \xc3\x99TF-8 string\xff\xff\xff\xff";
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf8, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a \xc3\x99TF-8 string", "rz_scan_strings utf8, different string");
	mu_assert_eq(s->addr, 4, "rz_scan_strings utf8, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF8, "rz_scan_strings utf8, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf16_le(void) {
	static const unsigned char str[] =
		"\xff\xff\xff\x49\x00\x20\x00\x61\x00\x6d\x00\x20\x00\x61"
		"\x00\x20\x00\x55\x00\x54\x00\x46\x00\x2d\x00\x31\x00\x36"
		"\x00\x6c\x00\x65\x00\x20\x00\x73\x00\x74\x00\x72\x00\x69"
		"\x00\x6e\x00\x67\x00\x00\xff\xff";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	g_opt.prefer_big_endian = false;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-16le string", "rz_scan_strings utf16le, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings utf16le, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16LE, "rz_scan_strings utf16le, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf16_le_special_chars(void) {
	static const unsigned char str[] =
		"\x09\x00\x77\x00\x69\x00\x64\x00\x65\x00\x5c\x00"
		"\x65\x00\x73\x00\x63\x00\x3a\x00\x20\x00\x1b\x00"
		"\x5b\x00\x30\x00\x6d\x00\xa1\x00\x0d\x00\x0a\x00"
		"\x00\x00\x00\x00";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	g_opt.prefer_big_endian = false;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "\twide\\esc: \x1b[0m\xc2\xa1\r\n", "rz_scan_strings utf16le, different string");
	mu_assert_eq(s->addr, 0, "rz_scan_strings utf16le, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16LE, "rz_scan_strings utf16le, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf16_be(void) {
	static const unsigned char str[] =
		"\xff\xff\xff\x00\x49\x00\x20\x00\x61\x00\x6d\x00\x20\x00\x61"
		"\x00\x20\x00\x55\x00\x54\x00\x46\x00\x2d\x00\x31\x00\x36\x00"
		"\x62\x00\x65\x00\x20\x00\x73\x00\x74\x00\x72\x00\x69\x00\x6e"
		"\x00\x67\xff\xff\xff\xff";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	g_opt.prefer_big_endian = true;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-16be string", "rz_scan_strings utf16be, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings utf16be, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16BE, "rz_scan_strings utf16be, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf32_le(void) {
	static const unsigned char str[] =
		"\xff\xff\x49\x00\x00\x00\x20\x00\x00\x00\x61\x00\x00\x00\x6d"
		"\x00\x00\x00\x20\x00\x00\x00\x61\x00\x00\x00\x20\x00\x00\x00"
		"\x55\x00\x00\x00\x54\x00\x00\x00\x46\x00\x00\x00\x2d\x00\x00"
		"\x00\x33\x00\x00\x00\x32\x00\x00\x00\x6c\x00\x00\x00\x65\x00"
		"\x00\x00\x20\x00\x00\x00\x73\x00\x00\x00\x74\x00\x00\x00\x72"
		"\x00\x00\x00\x69\x00\x00\x00\x6e\x00\x00\x00\x67\x00\x00\x00"
		"\xff\xff\xff\xff\xff\xff\xff\xff";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	g_opt.prefer_big_endian = false;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf32le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-32le string", "rz_scan_strings utf32le, different string");
	mu_assert_eq(s->addr, 2, "rz_scan_strings utf32le, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF32LE, "rz_scan_strings utf32le, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf32_be(void) {
	static const unsigned char str[] =
		"\xff\xff\x00\x00\x00\x49\x00\x00\x00\x20\x00\x00\x00\x61\x00"
		"\x00\x00\x6d\x00\x00\x00\x20\x00\x00\x00\x61\x00\x00\x00\x20"
		"\x00\x00\x00\x55\x00\x00\x00\x54\x00\x00\x00\x46\x00\x00\x00"
		"\x2d\x00\x00\x00\x33\x00\x00\x00\x32\x00\x00\x00\x62\x00\x00"
		"\x00\x65\x00\x00\x00\x20\x00\x00\x00\x73\x00\x00\x00\x74\x00"
		"\x00\x00\x72\x00\x00\x00\x69\x00\x00\x00\x6e\x00\x00\x00\x67"
		"\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	g_opt.prefer_big_endian = true;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf32be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-32be string", "rz_scan_strings utf32be, different string");
	mu_assert_eq(s->addr, 2, "rz_scan_strings utf32be, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF32BE, "rz_scan_strings utf32be, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_utf16_be(void) {
	static const unsigned char str[] =
		"\xff\xfftorre, alfiere\xff\x00\x04\x41\x04\x3b\x04\x3e\x04\x3d\x00\x2c\x00\x20\x04\x3b\x04\x30\x04\x34\x04\x4c\x04\x4f";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	g_opt.prefer_big_endian = true;
	int n = rz_scan_strings(buf, str_list, &g_opt, 16, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_UTF16BE);
	mu_assert_eq(n, 1, "rz_scan_strings utf16be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);

	mu_assert_eq(s->addr, 18, "rz_scan_strings utf16be, address");
	mu_assert_streq(s->string, "\xd1\x81\xd0\xbb\xd0\xbe\xd0\xbd\x2c\x20\xd0\xbb\xd0\xb0\xd0\xb4\xd1\x8c\xd1\x8f",
		"rz_scan_strings utf16be, different string");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16BE, "rz_scan_strings utf16be, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_extended_ascii(void) {
	static const unsigned char str[] =
		"Immensità s'annega il pensier mio: E il naufragar m'è dolce in questo mare.\x00"
		"Ich sah, wie Doris bei Damöten stand, er nahm sie zärtlich bei der Hand.\00"
		"Dans l'éblouissante clarté de leur premier amour.\x00";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();

	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_UTF8);
	mu_assert_eq(n, 3, "rz_scan_strings extended_ascii, number of strings");

	RzDetectedString *s_it = rz_list_get_n(str_list, 0);
	RzDetectedString *s_de = rz_list_get_n(str_list, 1);
	RzDetectedString *s_fr = rz_list_get_n(str_list, 2);

	mu_assert_streq(s_it->string, "Immensità s'annega il pensier mio: E il naufragar m'è dolce in questo mare.",
		"rz_scan_strings extended_ascii, different strings IT");
	mu_assert_streq(s_de->string, "Ich sah, wie Doris bei Damöten stand, er nahm sie zärtlich bei der Hand.",
		"rz_scan_strings extended_ascii, different strings DE");
	mu_assert_streq(s_fr->string, "Dans l'éblouissante clarté de leur premier amour.",
		"rz_scan_strings extended_ascii, different strings FR");

	rz_detected_string_free(s_it);
	rz_detected_string_free(s_de);
	rz_detected_string_free(s_fr);

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_scan_strings_detect_ascii);
	mu_run_test(test_rz_scan_strings_detect_ibm037);
	mu_run_test(test_rz_scan_strings_detect_utf8);
	mu_run_test(test_rz_scan_strings_detect_utf16_le);
	mu_run_test(test_rz_scan_strings_detect_utf16_le_special_chars);
	mu_run_test(test_rz_scan_strings_detect_utf16_be);
	mu_run_test(test_rz_scan_strings_detect_utf32_le);
	mu_run_test(test_rz_scan_strings_detect_utf32_be);
	mu_run_test(test_rz_scan_strings_utf16_be);
	mu_run_test(test_rz_scan_strings_extended_ascii);

	return tests_passed != tests_run;
}

mu_main(all_tests)
