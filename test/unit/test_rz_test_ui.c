// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "../../binrz/rz-test-ui/load.c"
#include "../../binrz/rz-test-ui/vscreen.c"
#include "../../binrz/rz-test-ui/worker.c"
#include "minunit.h"

static void feed(RzVScreen *screen, const char *text) {
	rz_vscreen_feed(screen, (const ut8 *)text, strlen(text));
}

static bool test_screen_wrap_erase(void) {
	RzVScreen *s = rz_vscreen_new(3, 2);
	feed(s, "abcdef\x1b[1J");
	mu_assert_streq(rz_vscreen_line(s, 0), "", "erase with pending wrap stays in bounds");
	mu_assert_streq(rz_vscreen_line(s, 1), "", "erase includes the last cell");
	feed(s, "\x1b[Habc\rZ");
	mu_assert_streq(rz_vscreen_line(s, 0), "Zbc", "CR cancels delayed wrap");
	feed(s, "\x1b[Habc\x1b[31mD");
	mu_assert_streq(rz_vscreen_line(s, 1), "D", "SGR preserves delayed wrap");
	rz_vscreen_free(s);
	mu_end;
}

static bool test_screen_scroll_region(void) {
	RzVScreen *s = rz_vscreen_new(4, 4);
	feed(s, "top\r\n111\r\n222\r\nend\x1b[2;3r\x1b[3;1H\n");
	mu_assert_streq(rz_vscreen_line(s, 0), "top", "top is outside region");
	mu_assert_streq(rz_vscreen_line(s, 1), "222", "region scrolls");
	mu_assert_streq(rz_vscreen_line(s, 2), "", "bottom cleared");
	mu_assert_streq(rz_vscreen_line(s, 3), "end", "bottom outside region");
	feed(s, "\x1b[2;1H\x1bM");
	mu_assert_streq(rz_vscreen_line(s, 1), "", "reverse index inserts blank");
	mu_assert_streq(rz_vscreen_line(s, 2), "222", "reverse index shifts down");
	rz_vscreen_free(s);
	mu_end;
}

static bool test_screen_resize_saved(void) {
	RzVScreen *s = rz_vscreen_new(20, 8);
	feed(s, "\x1b[8;20H\x1b"
		"7\x1b[?1049hALT");
	mu_assert_true(rz_vscreen_resize(s, 2, 1), "shrink both buffers");
	feed(s, "\x1b[?1049l\x1b"
		"8x\x1b[1J");
	mu_assert_true(rz_vscreen_valid(s), "saved cursors clamped");
	mu_assert_eq(rz_vscreen_cols(s), 2, "width");
	mu_assert_false(rz_vscreen_resize(s, UT32_MAX, 2), "huge allocation rejected");
	mu_assert_eq(rz_vscreen_cols(s), 2, "failed resize preserves state");
	rz_vscreen_free(s);
	mu_end;
}

static bool test_screen_chunking(void) {
	const char *stream = "one\x1b[2;3H\xe7\x95\x8c\xe2\x94\x82\x1b[1;999999999999999999999999999999H!\x1b]title\x1b\\\x1b[?1049hhello\x1b[?1049l";
	RzVScreen *whole = rz_vscreen_new(30, 4);
	RzVScreen *bytes = rz_vscreen_new(30, 4);
	feed(whole, stream);
	for (size_t i = 0; stream[i]; i++) {
		rz_vscreen_feed(bytes, (const ut8 *)stream + i, 1);
	}
	char *a = rz_vscreen_to_str(whole), *b = rz_vscreen_to_str(bytes);
	mu_assert_streq(a, b, "output independent of transport boundaries");
	mu_assert_true(rz_vscreen_valid(bytes), "complete stream");
	mu_assert_eq(rz_vscreen_cell(bytes, 1, 2), 0x754c, "wide glyph lead");
	mu_assert_eq(rz_vscreen_cell(bytes, 1, 3), 0, "wide glyph continuation");
	mu_assert_eq(rz_vscreen_cell(bytes, 1, 4), 0x2502, "glyph after wide character");
	free(a);
	free(b);
	rz_vscreen_free(whole);
	rz_vscreen_free(bytes);
	mu_end;
}

static bool test_screen_wide_erase(void) {
	RzVScreen *screen = rz_vscreen_new(4, 2);
	feed(screen, "\xe7\x95\x8c!\x1b[1;2H\x1b[X");
	mu_assert_streq(rz_vscreen_line(screen, 0), "  !", "erasing trailing half clears glyph");
	feed(screen, "\x1b[1;3H\xe7\x95\x8c");
	mu_assert_true(rz_vscreen_resize(screen, 3, 2), "clip wide glyph on resize");
	mu_assert_streq(rz_vscreen_line(screen, 0), "", "clipped glyph becomes padding");
	rz_vscreen_free(screen);
	mu_end;
}

static bool test_snapshot_normalization(void) {
	char *text = normalize_screen("  first  \n\n next \n\n");
	mu_assert_streq(text, "  first\n\n next", "interior blank rows and indentation matter");
	free(text);
	mu_end;
}

static bool test_screen_bounded_strings(void) {
	RzVScreen *s = rz_vscreen_new(4, 2);
	feed(s, "\x1b]title");
	for (size_t i = 0; i < 100000; i++) {
		feed(s, "xxxxxxxx");
	}
	mu_assert_false(rz_vscreen_valid(s), "unterminated OSC is not a valid checkpoint");
	feed(s, "\x1b\\ok");
	mu_assert_true(rz_vscreen_valid(s), "OSC resumes at ST");
	mu_assert_streq(rz_vscreen_line(s, 0), "ok", "OSC never paints content");
	rz_vscreen_free(s);
	mu_end;
}

static bool test_screen_editing(void) {
	RzVScreen *s = rz_vscreen_new(6, 2);
	feed(s, "abcde\x1b[1;2H\x1b[2P");
	mu_assert_streq(rz_vscreen_line(s, 0), "ade", "delete characters");
	feed(s, "\x1b[2@xy");
	mu_assert_streq(rz_vscreen_line(s, 0), "axyde", "insert characters");
	feed(s, "\x1b[2X");
	mu_assert_streq(rz_vscreen_line(s, 0), "axy", "erase characters");
	feed(s, "\x1b[?7l\x1b[1;6HAB");
	mu_assert_eq(rz_vscreen_cell(s, 0, 5), 'B', "disabled autowrap overwrites last cell");
	rz_vscreen_free(s);
	mu_end;
}

static bool test_loader_valid(void) {
	const char *text = "NAME=first\r\nCOLS=80\r\nSTEPS=<<E\r\nKEYS V<ENTER><F12>\r\nEXPECT_AT 0 -1 \" \"\r\nEXPECT_SCREEN <<S\r\n  spaced  \r\n\r\nS\r\nE\r\nRUN\r\nNAME=second\r\nSTEPS=<<T\r\nQUIT\r\nT";
	RzPVector *tests = rz_test_ui_load("test", text);
	mu_assert_notnull(tests, "CRLF file without final newline");
	mu_assert_eq(rz_pvector_len(tests), 2, "two records");
	RzTestUi *first = rz_pvector_at(tests, 0), *second = rz_pvector_at(tests, 1);
	mu_assert_eq(second->index, 1, "worker index");
	RzTestUiStep *screen = rz_pvector_at(&first->steps, 4);
	mu_assert_streq(screen->arg_s, "  spaced  \n\n", "snapshot whitespace preserved");
	mu_assert_eq(screen->line_begin, 7, "first snapshot content line");
	mu_assert_eq(screen->line_end, 8, "last snapshot content line");
	rz_pvector_free(tests);
	mu_end;
}

static bool test_loader_invalid(void) {
	const char *invalid[] = {
		"NAME=x\nCOLS=0\nSTEPS=<<E\nQUIT\nE\n",
		"NAME=x\nCOLS=18446744073709551616\nSTEPS=<<E\nQUIT\nE\n",
		"NAME=x\nCOLS=80junk\nSTEPS=<<E\nQUIT\nE\n",
		"NAME=x\nTIMEOUT=-1\nSTEPS=<<E\nQUIT\nE\n",
		"NAME=x\nUTF8=2\nSTEPS=<<E\nQUIT\nE\n",
		"NAME=x\nNAME=y\nSTEPS=<<E\nQUIT\nE\n",
		"NAME=x\nSTEPS=<<E\nEXPECT_LIEN 1 oops\nE\n",
		"NAME=x\nSTEPS=<<E\nEXPECT_NOREGEX [\nE\n",
		"NAME=x\nSTEPS=<<E\nEXPECT_LINE nope text\nE\n",
		"NAME=x\nSTEPS=<<E\nEXPECT_HLINE 1 9 2 -\nE\n",
		"NAME=x\nSTEPS=<<E\nEXPECT_CELL 0 0 ab\nE\n",
		"NAME=x\nSTEPS=<<E\nRESIZE 0x24\nE\n",
		"NAME=x\nSTEPS=<<E\nQUIT\nEXPECT_LINE 0 ignored\nE\n",
		"NAME=x\nSTEPS=<<E\nQUIT\n",
		"NAME=x\nSTEPS=<<E\nEXPECT_SCREEN <<S\nnot terminated\nE\n",
		"NAME=x\nSTEPS=<<E\nQUIT\nE\nRUN\nNAME=y\nBAD=1\n",
		"NAME=x\nSTEPS=<<\nQUIT\n",
		"NAME=x\nSTEPS=<<E\nE\n",
		"NAME=x\n",
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(invalid); i++) {
		RzPVector *tests = rz_test_ui_load("invalid", invalid[i]);
		mu_assert_null(tests, "malformed file must fail atomically");
	}
	mu_end;
}

static bool test_assertion_bounds(void) {
	RzVScreen *s = rz_vscreen_new(3, 2);
	RzTestUiResult result = { 0 };
	RzTestUiStep step = { .kind = RZ_UI_STEP_EXPECT_NOLINE, .arg_n = 2, .arg_s = "absent" };
	check_step(&result, s, &step);
	mu_assert_true(result.assertion_failed, "out-of-range negative assertion fails");
	free(result.fail_diag);
	memset(&result, 0, sizeof(result));
	step.kind = RZ_UI_STEP_EXPECT_AT;
	step.arg_n = 0;
	step.arg_col = 2;
	step.arg_s = "  ";
	check_step(&result, s, &step);
	mu_assert_true(result.assertion_failed, "spaces past right edge fail");
	free(result.fail_diag);
	rz_vscreen_free(s);
	mu_end;
}

static bool test_screen_random_stream(void) {
	RzVScreen *s = rz_vscreen_new(7, 3);
	ut32 state = 12345;
	for (size_t i = 0; i < 100000; i++) {
		state = state * 1664525 + 1013904223;
		ut8 c = state >> 24;
		rz_vscreen_feed(s, &c, 1);
		if (!(i % 997)) {
			mu_assert_true(rz_vscreen_resize(s, 1 + state % 19, 1 + state % 7), "resize amid escape stream");
		}
	}
	char *text = rz_vscreen_to_str(s);
	mu_assert_notnull(text, "arbitrary bytes do not corrupt screen storage");
	free(text);
	rz_vscreen_free(s);
	mu_end;
}

static bool test_text_read_limit(void) {
	char *path = NULL;
	int fd = rz_file_mkstemp("rz-test-ui-read", &path);
	mu_assert_true(fd >= 0 && path, "temporary fixture");
	close(fd);
	mu_assert_true(rz_file_dump(path, (const ut8 *)"abcd", 4, false), "write fixture");
	char *text = rz_test_ui_read_text(path, 4);
	mu_assert_streq(text, "abcd", "exact size is accepted and terminated");
	free(text);
	text = rz_test_ui_read_text(path, 3);
	mu_assert_null(text, "read limit is enforced while reading");
	mu_assert_true(rz_file_dump(path, (const ut8 *)"ab\0d", 4, false), "write NUL fixture");
	text = rz_test_ui_read_text(path, 4);
	mu_assert_null(text, "embedded NUL cannot hide trailing directives");
	rz_file_rm(path);
	free(path);
	mu_end;
}

static bool test_snapshot_capture_limit(void) {
	RzVScreen *screen = rz_vscreen_new(3, 1);
	feed(screen, "abc");
	RzTestUiResult result = { .capture_size = RZ_TEST_UI_MAX_FILE_SIZE - 2 };
	RzTestUiStep step = { .kind = RZ_UI_STEP_EXPECT_SCR, .arg_s = "abc" };
	check_snapshot(&result, screen, &step);
	mu_assert_true(result.run_failed, "capture exhaustion is an infrastructure failure");
	mu_assert_true(rz_pvector_empty(result.fixups), "oversized capture is not retained");
	rz_pvector_free(result.fixups);
	free(result.fail_diag);
	rz_vscreen_free(screen);
	mu_end;
}

static bool all_tests(void) {
	mu_run_test(test_screen_wrap_erase);
	mu_run_test(test_screen_scroll_region);
	mu_run_test(test_screen_resize_saved);
	mu_run_test(test_screen_chunking);
	mu_run_test(test_screen_wide_erase);
	mu_run_test(test_snapshot_normalization);
	mu_run_test(test_screen_bounded_strings);
	mu_run_test(test_screen_editing);
	mu_run_test(test_loader_valid);
	mu_run_test(test_loader_invalid);
	mu_run_test(test_assertion_bounds);
	mu_run_test(test_screen_random_stream);
	mu_run_test(test_text_read_limit);
	mu_run_test(test_snapshot_capture_limit);
	return tests_passed != tests_run;
}

mu_main(all_tests)
