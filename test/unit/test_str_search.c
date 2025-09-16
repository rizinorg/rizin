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

bool all_tests() {
	mu_run_test(test_rz_scan_strings_detect_ascii);
	mu_run_test(test_rz_scan_strings_detect_ibm037);
	mu_run_test(test_rz_scan_strings_detect_ibm290);
	mu_run_test(test_rz_scan_strings_detect_utf8);
	mu_run_test(test_rz_scan_strings_detect_utf16_le);
	mu_run_test(test_rz_scan_strings_detect_utf16_le_special_chars);
	mu_run_test(test_rz_scan_strings_detect_utf16_be);
	mu_run_test(test_rz_scan_strings_detect_utf32_le);
	mu_run_test(test_rz_scan_strings_detect_utf32_be);
	mu_run_test(test_rz_scan_strings_utf16_be);
	mu_run_test(test_rz_scan_strings_extended_ascii);
	mu_run_test(test_rz_scan_strings_detect_length_ascii);
	mu_run_test(test_rz_scan_strings_detect_length_utf8);
	mu_run_test(test_rz_scan_strings_scan_options_error);

	return tests_passed != tests_run;
}

mu_main(all_tests)
