
#include <rz_util.h>
#include "minunit.h"

static RzUtilStrScanOptions g_opt = {
	.buf_size = 2048,
	.max_uni_blocks = 4,
	.min_str_length = 4
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
	mu_assert_eq(s->type, RZ_STRING_ENC_LATIN1, "rz_scan_strings ascii, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);

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
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-16le string", "rz_scan_strings utf16le, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings utf16le, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16LE, "rz_scan_strings utf16le, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);

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
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf16be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-16be string", "rz_scan_strings utf16be, different string");
	mu_assert_eq(s->addr, 3, "rz_scan_strings utf16be, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16BE, "rz_scan_strings utf16be, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);

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
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf32le, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-32le string", "rz_scan_strings utf32le, different string");
	mu_assert_eq(s->addr, 2, "rz_scan_strings utf32le, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF32LE, "rz_scan_strings utf32le, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);

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
	int n = rz_scan_strings(buf, str_list, &g_opt, 0, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_GUESS);
	mu_assert_eq(n, 1, "rz_scan_strings utf32be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);
	mu_assert_streq(s->string, "I am a UTF-32be string", "rz_scan_strings utf32be, different string");
	mu_assert_eq(s->addr, 2, "rz_scan_strings utf32be, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF32BE, "rz_scan_strings utf32be, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);

	mu_end;
}

bool test_rz_scan_strings_utf16_be(void) {
	static const unsigned char str[] =
		"\xff\xfftorre, alfiere\xff\xff\x04\x41\x04\x3b\x04\x3e\x04\x3d\x00\x2c\x00\x20\x04\x3b\x04\x30\x04\x34\x04\x4c\x04\x4f";

	RzBuffer *buf = rz_buf_new_with_bytes(str, sizeof(str));

	RzList *str_list = rz_list_new();
	int n = rz_scan_strings(buf, str_list, &g_opt, 16, buf->methods->get_size(buf) - 1, RZ_STRING_ENC_UTF16BE);
	mu_assert_eq(n, 1, "rz_scan_strings utf16be, number of strings");

	RzDetectedString *s = rz_list_get_n(str_list, 0);

	mu_assert_streq(s->string, "\xd1\x81\xd0\xbb\xd0\xbe\xd0\xbd\x2c\x20\xd0\xbb\xd0\xb0\xd0\xb4\xd1\x8c\xd1\x8f",
		"rz_scan_strings utf16be, different string");
	mu_assert_eq(s->addr, 18, "rz_scan_strings utf16be, address");
	mu_assert_eq(s->type, RZ_STRING_ENC_UTF16BE, "rz_scan_strings utf16be, string type");

	rz_detected_string_free(s);
	rz_list_free(str_list);

	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_scan_strings_detect_ascii);
	mu_run_test(test_rz_scan_strings_detect_utf8);
	mu_run_test(test_rz_scan_strings_detect_utf16_le);
	mu_run_test(test_rz_scan_strings_detect_utf16_be);
	mu_run_test(test_rz_scan_strings_detect_utf32_le);
	mu_run_test(test_rz_scan_strings_detect_utf32_be);

	mu_run_test(test_rz_scan_strings_utf16_be);
	return tests_passed != tests_run;
}

mu_main(all_tests)
