// SPDX-FileCopyrightText: 2021 borzacchiello <lucaborza@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_search.h>
#include "minunit.h"

static RzUtilStrScanOptions g_opt = {
	.max_str_length = 2048,
	.min_str_length = 4,
	.prefer_big_endian = false,
	.check_ascii_freq = true,
};

bool test_rz_scan_strings_detect_ascii(void) {
	static const unsigned char str[] = "\xff\xff\xffI am an ASCII string\xff\xff";
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings ascii, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an ASCII string", "rz_scan_strings ascii, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings ascii, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_8BIT, "rz_scan_strings ascii, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_ibm290(void) {
	static const unsigned char expected[] = "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x58\x5a\x5b\x5c\x5d\x5e\x5f\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9d\x9e\x9f\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xac\xad\xae\xaf\xba\xbb\xbc\xbd\xbe\xbf\xbf\x00";
	RzBuffer *buf = rz_buf_new_with_bytes(expected, sizeof(expected));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, rz_buf_size(buf) - 1, RZ_STRING_ENC_IBM290);
	mu_assert_eq(n, 1, "rz_scan_strings ibm290, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, " 。「」、・ヲァィゥ£.<(+|&ェォャュョッー!¥*);¬アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフ¯ヘホマミムメモヤユヨラリルレロワン゛゜゜", "rz_scan_strings ibm290, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_IBM290, "rz_scan_strings ibm290, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_ibm037(void) {
	static const unsigned char str[] = "\xc9\x40\x81\x94\x40\x81\x95\x40\xc9\xc2\xd4\xf0\xf3\xf7\x40\xa2\xa3\x99\x89\x95\x87\x25";
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings ibm037, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an IBM037 string", "rz_scan_strings ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_IBM037, "rz_scan_strings ibm037, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	/**
	 * two strings:
	 * 1. "Ber. Who's there.?\x00"
	 * 2. "Fran. Nay, answer me. Stand and unfold yourself"
	 */
	static const unsigned char str2[] = "\xff\xff\xff\xC2\x85\x99\x4B\x40\xE6\x88\x96\x7D\xA2\x40\xA3\x88\x85\x99\x85\x4B\x6F\x00\xC6\x99\x81\x95\x4B\x40\xD5\x81\xA8\x6B\x40\x81\x95\xA2\xA6\x85\x99\x40\x94\x85\x4B\x40\xE2\xA3\x81\x95\x84\x40\x81\x95\x84\x40\xA4\x95\x86\x96\x93\x84\x40\xA8\x96\xA4\x99\xA2\x85\x93\x86";
	buf = rz_buf_new_with_bytes(str2, sizeof(str2));

	str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 2, "rz_scan_strings ibm037, number of strings");

	s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "Ber. Who's there.?", "rz_scan_strings ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_IBM037, "rz_scan_strings ibm037, string type");

	s = rz_list_get_n(str_list, 1);
	mu_assert_streq(s->string, "Fran. Nay, answer me. Stand and unfold yourself", "rz_scan_strings ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_IBM037, "rz_scan_strings ibm037, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	// UTF and EBCDIC strings in one memory
	static const unsigned char str3[] =
		"\xff\xff\xff\xc9\x40\x81\x94\x40\x81\x95\x40\xc9\xc2\xd4\xf0\xf3\xf7\x40\xa2\xa3\x99\x89\x95\x87\x25\xff\xff\xff"
		"\xff\xff\xff\xffI am a \xc3\x99TF-8 string\xff\xff\xff\xff";
	buf = rz_buf_new_with_bytes(str3, sizeof(str3));

	str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 2, "rz_scan_strings mix utf8 and ibm037, number of strings");

	s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an IBM037 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_IBM037, "rz_scan_strings mix utf8 and ibm037, string type");

	s = rz_list_get_n(str_list, 1);
	mu_assert_streq(s->string, "I am a \xc3\x99TF-8 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF8, "rz_scan_strings mix utf8 and ibm037, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	// one of the ending chars of UTF-8 is actually one of the starting chars of the EBCDIC string
	static const unsigned char str4[] =
		"\xff\xff\xff\xc9\x40\x81\x94\x40\x81\x95\x40\xc9\xc2\xd4\xf0\xf3\xf7\x40\xa2\xa3\x99\x89\x95\x87\x25"
		"I am a \xc3\x99TF-8 string\xff\xff\xff";
	buf = rz_buf_new_with_bytes(str4, sizeof(str4));

	str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 2, "rz_scan_strings mix utf8 and ibm037, number of strings");

	s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an IBM037 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_IBM037, "rz_scan_strings mix utf8 and ibm037, string type");

	s = rz_list_get_n(str_list, 1);
	mu_assert_streq(s->string, "%I am a \xc3\x99TF-8 string", "rz_scan_strings mix utf8 and ibm037, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF8, "rz_scan_strings mix utf8 and ibm037, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_detect_utf8(void) {
	static const unsigned char str[] = "\xff\xff\xff\xffI am a \xc3\x99TF-8 string\xff\xff\xff\xff";
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf8, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a \xc3\x99TF-8 string", "rz_scan_strings utf8, different string");
	mu_assert_eq(s->addr, 4, "rz_scan_strings utf8, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF8, "rz_scan_strings utf8, string type");

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

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

	g_opt.prefer_big_endian = false;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-16le string", "rz_scan_strings utf16le, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings utf16le, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF16LE, "rz_scan_strings utf16le, string type");

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

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

	g_opt.prefer_big_endian = false;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "\twide\\esc: \x1b[0m\xc2\xa1\r\n", "rz_scan_strings utf16le, different string");
	mu_assert_eq(s->addr, 0, "rz_scan_strings utf16le, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF16LE, "rz_scan_strings utf16le, string type");

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_user_unprintable(void) {
	// ASCII/UTF-8 string: "hello\tworld\ntest\0"
	// With \t (0x09) and \n (0x0a) as user-defined non-printable,
	// the scanner should produce: "hello", "world", "test"
	static const unsigned char str[] = "hello\tworld\ntest";
	static RzCodePoint code_points[] = { 0x09, 0x0a };
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));
	RzUtilStrScanOptions opt = g_opt;
	RzVector *user_unprintable = rz_vector_new(sizeof(RzCodePoint), NULL, NULL);
	mu_assert_notnull(user_unprintable, "user_unprintable vector alloc");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(code_points); i++) {
		mu_assert_true(rz_vector_push(user_unprintable, &code_points[i]), "push user_unprintable");
	}
	opt.user_unprintable = user_unprintable;
	opt.min_str_length = 4;

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_8BIT);
	mu_assert_eq(n, 3, "rz_scan_strings user_unprintable, number of strings");

	RzDetectedString *s0 = rz_list_get_n(str_list, 0);
	RzDetectedString *s1 = rz_list_get_n(str_list, 1);
	RzDetectedString *s2 = rz_list_get_n(str_list, 2);
	mu_assert_streq(s0->string, "hello", "rz_scan_strings user_unprintable, first string");
	mu_assert_streq(s1->string, "world", "rz_scan_strings user_unprintable, second string");
	mu_assert_streq(s2->string, "test", "rz_scan_strings user_unprintable, third string");

	rz_list_free(str_list);
	rz_buf_free(buf);
	rz_vector_free(user_unprintable);

	mu_end;
}

bool test_rz_scan_strings_user_unprintable_utf8(void) {
	// UTF-8 bytes for U+00E9 (latin small letter e with acute) between "ab" and "cd".
	static const unsigned char str[] = { 'a', 'b', 0xC3, 0xA9, 'c', 'd', 0x00 };
	static RzCodePoint code_points[] = { 0x00e9 }; // U+00E9 (latin small letter e with acute)
	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));
	RzUtilStrScanOptions opt = g_opt;
	RzVector *user_unprintable = rz_vector_new(sizeof(RzCodePoint), NULL, NULL);
	mu_assert_notnull(user_unprintable, "user_unprintable vector alloc");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(code_points); i++) {
		mu_assert_true(rz_vector_push(user_unprintable, &code_points[i]), "push user_unprintable");
	}
	opt.user_unprintable = user_unprintable;
	opt.min_str_length = 2;
	opt.check_ascii_freq = false;

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_UTF8);
	mu_assert_eq(n, 2, "rz_scan_strings user_unprintable utf8, number of strings");

	RzDetectedString *s0 = rz_list_get_n(str_list, 0);
	RzDetectedString *s1 = rz_list_get_n(str_list, 1);
	mu_assert_streq(s0->string, "ab", "rz_scan_strings user_unprintable utf8, first string");
	mu_assert_streq(s1->string, "cd", "rz_scan_strings user_unprintable utf8, second string");

	rz_list_free(str_list);
	rz_buf_free(buf);
	rz_vector_free(user_unprintable);

	mu_end;
}

bool test_rz_scan_strings_detect_utf16_be(void) {
	static const unsigned char str[] =
		"\xff\xff\xff\x00\x49\x00\x20\x00\x61\x00\x6d\x00\x20\x00\x61"
		"\x00\x20\x00\x55\x00\x54\x00\x46\x00\x2d\x00\x31\x00\x36\x00"
		"\x62\x00\x65\x00\x20\x00\x73\x00\x74\x00\x72\x00\x69\x00\x6e"
		"\x00\x67\xff\xff\xff\xff";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

	g_opt.prefer_big_endian = true;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-16be string", "rz_scan_strings utf16be, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings utf16be, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF16BE, "rz_scan_strings utf16be, string type");

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

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

	g_opt.prefer_big_endian = false;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf32le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-32le string", "rz_scan_strings utf32le, different string");
	mu_assert_eq(s->addr, 2, "rz_scan_strings utf32le, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF32LE, "rz_scan_strings utf32le, string type");

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

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

	g_opt.prefer_big_endian = true;
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf32be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-32be stringÿ", "rz_scan_strings utf32be, different string");
	mu_assert_eq(s->addr, 2, "rz_scan_strings utf32be, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF32BE, "rz_scan_strings utf32be, string type");
	mu_assert_eq(s->size, 92, "rz_scan_strings utf32be, size"); // 92 bytes in size, no NUL byte.
	mu_assert_eq(s->length, 23, "rz_scan_strings utf32be, length"); // 23 characters in length.

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

bool test_rz_scan_strings_utf16_be(void) {
	static const unsigned char str[] =
		"\xff\xfftorre, alfiere\xff\x00\x04\x41\x04\x3b\x04\x3e\x04\x3d\x00\x2c\x00\x20\x04\x3b\x04\x30\x04\x34\x04\x4c\x04\x4f";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

	g_opt.prefer_big_endian = true;
	int n = rz_scan_strings(buf, str_list, &g_opt, 16, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_UTF16BE);
	mu_assert_eq(n, 1, "rz_scan_strings utf16be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);

	mu_assert_eq(s->addr, 18, "rz_scan_strings utf16be, address");
	// "слон, ладья" UTF-8 encoded:
	mu_assert_streq(s->string, "\xd1\x81\xd0\xbb\xd0\xbe\xd0\xbd\x2c\x20\xd0\xbb\xd0\xb0\xd0\xb4\xd1\x8c\xd1\x8f", // This is UTF-8 encoded.
		"rz_scan_strings utf16be, different string");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF16BE, "rz_scan_strings utf16be, string type");
	mu_assert_eq(s->size, 22, "rz_scan_strings utf16be, size"); // 22 bytes in size, no NUL byte.
	mu_assert_eq(s->length, 11, "rz_scan_strings utf16be, length"); // 11 characters in length.

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

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);

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

	rz_list_free(str_list);
	rz_buf_free(buf);

	mu_end;
}

/**
 * \brief NUL byte is counted in the RzDetectedString->size member but not in the length member.
 */
bool test_rz_scan_strings_detect_length_ascii(void) {
	static const unsigned char no_nul[] = "I am an ASCII string without NUL byte.\xff";
	RzBuffer *buf = rz_buf_new_with_bytes(no_nul, sizeof(no_nul));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf), RZ_STRING_ENC_8BIT);
	mu_assert_eq(n, 1, "rz_scan_strings ascii, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am an ASCII string without NUL byte.", "rz_scan_strings ascii, different string");
	mu_assert_eq(s->addr, 0, "rz_scan_strings ascii, address");
	mu_assert_eq(s->size, 38, "rz_scan_strings ascii, size (in bytes, no NUL byte)");
	mu_assert_eq(s->length, 38, "rz_scan_strings ascii, length (in characters without NUL byte)");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_8BIT, "rz_scan_strings ascii, type");
	rz_list_purge(str_list);

	// Extra space between "a" and "NUL" to get comparable string length.
	static const unsigned char nul[] = "I am an ASCII string with a  NUL byte.\0";
	RzBuffer *buf_nul = rz_buf_new_with_bytes(nul, sizeof(nul));
	n = rz_scan_strings(buf_nul, str_list, &g_opt, 0, buf_nul->methods->get_size(buf_nul), RZ_STRING_ENC_8BIT);
	s = rz_list_get_n(str_list, 0);
	mu_assert_eq(n, 1, "rz_scan_strings ascii, number of strings");
	mu_assert_streq(s->string, "I am an ASCII string with a  NUL byte.", "rz_scan_strings ascii, different string");
	mu_assert_eq(s->addr, 0, "rz_scan_strings ascii, address");
	// One byte larger in size than above, due to additional NUL byte.
	mu_assert_eq(s->size, 39, "rz_scan_strings ascii, size (in bytes, without NUL byte)");
	mu_assert_eq(s->length, 38, "rz_scan_strings ascii, length (in characters)");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_8BIT, "rz_scan_strings ascii, type");

	rz_list_free(str_list);
	rz_buf_free(buf);
	rz_buf_free(buf_nul);

	mu_end;
}

/**
 * \brief NUL byte is counted in the RzDetectedString->size member but not in the length member.
 */
bool test_rz_scan_strings_detect_length_utf8(void) {
	static const unsigned char no_nul[] = "⟨I am an UTF-8 string without NUL byte⟩.\xff";
	RzBuffer *buf = rz_buf_new_with_bytes(no_nul, sizeof(no_nul));

	RzList *str_list = rz_list_newf((RzListFree)rz_detected_string_free);
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf), RZ_STRING_ENC_UTF8);
	mu_assert_eq(n, 1, "rz_scan_strings ascii, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "⟨I am an UTF-8 string without NUL byte⟩.", "rz_scan_strings utf-8, different string");
	mu_assert_eq(s->addr, 0, "rz_scan_strings utf-8, address");
	mu_assert_eq(s->size, 44, "rz_scan_strings utf-8, size (in bytes, no NUL byte)");
	mu_assert_eq(s->length, 40, "rz_scan_strings utf-8, length (in characters without NUL byte)");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF8, "rz_scan_strings utf-8, type");
	rz_list_purge(str_list);

	// Extra space between "a" and "NUL" to get comparable string length.
	static const unsigned char nul[] = "⟨I am an UTF-8 string with a  NUL byte⟩.\0";
	RzBuffer *buf_nul = rz_buf_new_with_bytes(nul, sizeof(nul));
	n = rz_scan_strings(buf_nul, str_list, &g_opt, 0, buf_nul->methods->get_size(buf_nul), RZ_STRING_ENC_UTF8);
	s = rz_list_get_n(str_list, 0);
	mu_assert_eq(n, 1, "rz_scan_strings utf-8, number of strings");
	mu_assert_streq(s->string, "⟨I am an UTF-8 string with a  NUL byte⟩.", "rz_scan_strings utf-8, different string");
	mu_assert_eq(s->addr, 0, "rz_scan_strings utf-8, address");
	// One byte larger in size than above, due to additional NUL byte.
	mu_assert_eq(s->size, 45, "rz_scan_strings utf-8, size (in bytes, with NUL byte)");
	mu_assert_eq(s->length, 40, "rz_scan_strings utf-8, length (in characters)");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF8, "rz_scan_strings utf-8, type");

	rz_list_free(str_list);
	rz_buf_free(buf);
	rz_buf_free(buf_nul);

	mu_end;
}

/**
 * \brief Test that rz_search_collection_string_add() refuses to add a string if
 * the search requires string scanning, but no scan optoins were given.
 */
bool test_rz_scan_strings_scan_options_error(void) {
	RzSearchCollection *collection = rz_search_collection_strings(NULL, 4);
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_IBM037), "Should fail for this config");
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_IBM290), "Should fail for this config");
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_EBCDIC_UK), "Should fail for this config");
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_EBCDIC_US), "Should fail for this config");
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_EBCDIC_ES), "Should fail for this config");
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_GUESS), "Should fail for this config");
	mu_assert_false(rz_search_collection_string_add(collection, "", 0, 1, RZ_STRING_ENC_SETTINGS), "Should fail for this config");
	mu_assert_true(rz_search_collection_string_add(collection, "some_pattern", 0, 1, RZ_STRING_ENC_UTF16BE), "Should succeed for this config");
	mu_assert_true(rz_search_collection_string_add(collection, "some_pattern", 0, 1, RZ_STRING_ENC_UTF16LE), "Should succeed for this config");
	mu_assert_true(rz_search_collection_string_add(collection, "some_pattern", 0, 1, RZ_STRING_ENC_UTF32BE), "Should succeed for this config");
	mu_assert_true(rz_search_collection_string_add(collection, "some_pattern", 0, 1, RZ_STRING_ENC_UTF32LE), "Should succeed for this config");
	mu_assert_true(rz_search_collection_string_add(collection, "some_pattern", 0, 1, RZ_STRING_ENC_8BIT), "Should succeed for this config");
	mu_assert_true(rz_search_collection_string_add(collection, "some_pattern", 0, 1, RZ_STRING_ENC_UTF8), "Should succeed for this config");
	rz_search_collection_free(collection);
	mu_end;
}

bool test_rz_scan_strings_max_matches(void) {
	static const ut8 str[] = "\xff\xffI am the first string\xff\xffI am the second one\xff\xff"
				 "And I am the third\xff";
	RzUtilStrScanOptions opt = g_opt;
	RzList *list = rz_list_newf((RzListFree)rz_detected_string_free);
	mu_assert_eq(rz_scan_strings_raw(str, list, &opt, 0, sizeof(str), RZ_STRING_ENC_GUESS), 3, "no limit");
	rz_list_purge(list);

	opt.max_matches = 2;
	mu_assert_eq(rz_scan_strings_raw(str, list, &opt, 0, sizeof(str), RZ_STRING_ENC_GUESS), 2, "two strings");
	mu_assert_eq(rz_list_length(list), 2, "two strings");
	RzDetectedString *s = rz_list_get_n(list, 1);
	mu_assert_streq(s->string, "I am the second one", "two strings, last one");
	rz_list_purge(list);

	opt.max_matches = 1;
	mu_assert_eq(rz_scan_strings_raw(str, list, &opt, 0, sizeof(str), RZ_STRING_ENC_GUESS), 1, "first string only");
	mu_assert_eq(rz_list_length(list), 1, "first string only");
	s = rz_list_first_val(list);
	mu_assert_streq(s->string, "I am the first string", "first string only");
	mu_assert_eq(s->addr, 2, "first string only, address");
	rz_list_free(list);
	mu_end;
}

bool test_rz_scan_strings_single_at_start(void) {
	RzUtilStrScanOptions opt = g_opt;
	RzDetectedString *s = NULL;

	static const ut8 at_start[] = "I am an ASCII string\xff\xff";
	mu_assert_true(rz_scan_strings_single_at_start_raw(at_start, sizeof(at_start), &opt, RZ_STRING_ENC_GUESS, &s), "string at start");
	mu_assert_streq(s->string, "I am an ASCII string", "string at start");
	mu_assert_eq(s->addr, 0, "string at start, address");
	rz_detected_string_free(s);

	// rz_scan_strings_single_raw() finds this one, at 3
	static const ut8 later[] = "\xff\xff\xffI am an ASCII string";
	mu_assert_false(rz_scan_strings_single_at_start_raw(later, sizeof(later), &opt, RZ_STRING_ENC_GUESS, &s), "string after the start");
	mu_assert_null(s, "string after the start");

	static const ut8 bom[] = "\xff\xfeH\x00"
				 "e\x00l\x00l\x00o\x00\x00\x00";
	mu_assert_true(rz_scan_strings_single_at_start_raw(bom, sizeof(bom), &opt, RZ_STRING_ENC_GUESS, &s), "string after a byte order mark");
	mu_assert_streq(s->string, "Hello", "string after a byte order mark");
	mu_assert_eq(s->addr, 0, "string after a byte order mark, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF16LE, "string after a byte order mark, encoding");
	rz_detected_string_free(s);

	// the longest byte order marks, the string itself starts right at the limit
	static const ut8 bom32le[] = "\xff\xfe\x00\x00H\x00\x00\x00"
				     "e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00\x00\x00";
	mu_assert_true(rz_scan_strings_single_at_start_raw(bom32le, sizeof(bom32le), &opt, RZ_STRING_ENC_GUESS, &s), "string after a UTF-32LE byte order mark");
	mu_assert_streq(s->string, "Hello", "string after a UTF-32LE byte order mark");
	mu_assert_eq(s->addr, 0, "string after a UTF-32LE byte order mark, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF32LE, "string after a UTF-32LE byte order mark, encoding");
	rz_detected_string_free(s);

	static const ut8 bom32be[] = "\x00\x00\xfe\xff\x00\x00\x00H"
				     "\x00\x00\x00"
				     "e\x00\x00\x00l\x00\x00\x00l\x00\x00\x00o\x00\x00\x00\x00";
	mu_assert_true(rz_scan_strings_single_at_start_raw(bom32be, sizeof(bom32be), &opt, RZ_STRING_ENC_UTF32BE, &s), "string after a UTF-32BE byte order mark");
	mu_assert_streq(s->string, "Hello", "string after a UTF-32BE byte order mark");
	mu_assert_eq(s->addr, 0, "string after a UTF-32BE byte order mark, address");
	mu_assert_eq(s->encoding, RZ_STRING_ENC_UTF32BE, "string after a UTF-32BE byte order mark, encoding");
	rz_detected_string_free(s);

	mu_end;
}

static ut32 xorshift32(ut32 *state) {
	ut32 x = *state;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return *state = x;
}

/**
 * \brief Fills \p buf with the pieces strings are made of: text in several
 * encodings, byte order marks, terminators and noise.
 */
static size_t random_string_soup(ut8 *buf, size_t size, ut32 *seed) {
	static const ut8 boms[][4] = { { 0xff, 0xfe }, { 0xfe, 0xff }, { 0xff, 0xfe, 0, 0 }, { 0, 0, 0xfe, 0xff } };
	static const ut8 bom_sizes[] = { 2, 2, 4, 4 };
	static const char *utf8[] = { "\xc3\xa9", "\xe2\x82\xac", "\xf0\x9f\x98\x80" };
	size_t n = 0;
	while (n + 32 < size) {
		ut32 r = xorshift32(seed);
		ut32 count = 1 + (r >> 8) % 8;
		switch (r % 9) {
		case 0: // text in 1, 2 or 4 byte units, either endianness
		case 1:
		case 2: {
			static const ut32 widths[] = { 1, 2, 4 };
			ut32 width = widths[r % 3];
			bool big_endian = (r >> 16) & 1;
			for (ut32 i = 0; i < count; i++) {
				ut8 ch = 'a' + xorshift32(seed) % 26;
				for (ut32 j = 0; j < width; j++) {
					buf[n++] = (big_endian ? j == width - 1 : !j) ? ch : 0;
				}
			}
			break;
		}
		case 3: {
			ut32 i = (r >> 16) % RZ_ARRAY_SIZE(boms);
			memcpy(buf + n, boms[i], bom_sizes[i]);
			n += bom_sizes[i];
			break;
		}
		case 4:
			memset(buf + n, 0, count % 4 + 1);
			n += count % 4 + 1;
			break;
		case 5: {
			const char *ch = utf8[(r >> 16) % RZ_ARRAY_SIZE(utf8)];
			memcpy(buf + n, ch, strlen(ch));
			n += strlen(ch);
			break;
		}
		case 6: // IBM037 letters
			for (ut32 i = 0; i < count; i++) {
				buf[n++] = 0xc1 + xorshift32(seed) % 9;
			}
			break;
		default:
			for (ut32 i = 0; i < count % 4 + 1; i++) {
				buf[n++] = xorshift32(seed);
			}
			break;
		}
	}
	return n;
}

static bool same_string(const RzDetectedString *a, const RzDetectedString *b) {
	if (!a || !b) {
		return a == b;
	}
	return a->addr == b->addr && a->size == b->size && a->length == b->length &&
		a->encoding == b->encoding && !strcmp(a->string, b->string);
}

/**
 * \brief First string of a full scan, which neither stops at it nor skips
 * anything, as reference for the scans that stop early.
 */
static RzDetectedString *full_scan_first(const ut8 *buf, size_t size, const RzUtilStrScanOptions *opt, RzStrEnc enc) {
	RzList *list = rz_list_newf((RzListFree)rz_detected_string_free);
	RzDetectedString *first = rz_scan_strings_raw(buf, list, opt, 0, size, enc) > 0 ? rz_list_pop_head(list) : NULL;
	rz_list_free(list);
	return first;
}

/**
 * \brief rz_scan_strings_single_raw() returns the first string of a full
 * scan, rz_scan_strings_single_at_start_raw() the same when it starts the
 * buffer.
 */
bool test_rz_scan_strings_single_same_as_full_scan(void) {
	static const RzStrEnc encodings[] = {
		RZ_STRING_ENC_GUESS, RZ_STRING_ENC_8BIT, RZ_STRING_ENC_UTF8, RZ_STRING_ENC_MUTF8,
		RZ_STRING_ENC_UTF16LE, RZ_STRING_ENC_UTF16BE, RZ_STRING_ENC_UTF32LE, RZ_STRING_ENC_UTF32BE,
		RZ_STRING_ENC_IBM037, RZ_STRING_ENC_IBM290, RZ_STRING_ENC_EBCDIC_UK, RZ_STRING_ENC_EBCDIC_US,
		RZ_STRING_ENC_EBCDIC_ES
	};
	ut8 buf[96];
	ut32 seed = 0x5eed;
	size_t at_start = 0;
	size_t after_bom = 0;
	for (size_t i = 0; i < 4000; i++) {
		size_t size = random_string_soup(buf, sizeof(buf), &seed);
		RzUtilStrScanOptions opt = {
			.max_str_length = size,
			.min_str_length = 4,
			.prefer_big_endian = i & 1,
			.check_ascii_freq = i & 2,
		};
		for (size_t e = 0; e < RZ_ARRAY_SIZE(encodings); e++) {
			RzDetectedString *expected = full_scan_first(buf, size, &opt, encodings[e]);
			RzDetectedString *single = NULL;
			bool single_found = rz_scan_strings_single_raw(buf, size, &opt, encodings[e], &single);
			bool same_single = single_found == !!single && same_string(expected, single);
			rz_detected_string_free(single);
			if (expected && expected->addr) {
				rz_detected_string_free(expected);
				expected = NULL;
			}
			RzDetectedString *actual = NULL;
			bool found = rz_scan_strings_single_at_start_raw(buf, size, &opt, encodings[e], &actual);
			bool same = found == !!actual && same_string(expected, actual);
			if (actual) {
				at_start++;
				after_bom += (buf[0] == 0xff && buf[1] == 0xfe) || (buf[0] == 0xfe && buf[1] == 0xff) ||
					!memcmp(buf, "\0\0\xfe\xff", 4);
			}
			rz_detected_string_free(expected);
			rz_detected_string_free(actual);
			char msg[128];
			snprintf(msg, sizeof(msg), "buffer %" PFMTSZu ", encoding %s, single", i, rz_str_enc_as_string(encodings[e]));
			mu_assert_true(same_single, msg);
			snprintf(msg, sizeof(msg), "buffer %" PFMTSZu ", encoding %s, at start", i, rz_str_enc_as_string(encodings[e]));
			mu_assert_true(same, msg);
		}
	}
	// The soup must reach both the plain and the byte order mark cases
	mu_assert_true(at_start > 1000, "strings at the start");
	mu_assert_true(after_bom > 10, "strings after a byte order mark");
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_scan_strings_detect_ascii);
	mu_run_test(test_rz_scan_strings_detect_ibm037);
	mu_run_test(test_rz_scan_strings_detect_ibm290);
	mu_run_test(test_rz_scan_strings_detect_utf8);
	mu_run_test(test_rz_scan_strings_detect_utf16_le);
	mu_run_test(test_rz_scan_strings_detect_utf16_le_special_chars);
	mu_run_test(test_rz_scan_strings_user_unprintable);
	mu_run_test(test_rz_scan_strings_user_unprintable_utf8);
	mu_run_test(test_rz_scan_strings_detect_utf16_be);
	mu_run_test(test_rz_scan_strings_detect_utf32_le);
	mu_run_test(test_rz_scan_strings_detect_utf32_be);
	mu_run_test(test_rz_scan_strings_utf16_be);
	mu_run_test(test_rz_scan_strings_extended_ascii);
	mu_run_test(test_rz_scan_strings_detect_length_ascii);
	mu_run_test(test_rz_scan_strings_detect_length_utf8);
	mu_run_test(test_rz_scan_strings_scan_options_error);
	mu_run_test(test_rz_scan_strings_max_matches);
	mu_run_test(test_rz_scan_strings_single_at_start);
	mu_run_test(test_rz_scan_strings_single_same_as_full_scan);

	return tests_passed != tests_run;
}

mu_main(all_tests)
