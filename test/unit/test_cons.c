// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_rz_cons() {
	// NOTE: not initializing a value here results in UB
	ut8 r = 0, g = 0, b = 0, a = 0;

	rz_cons_rgb_init();

	// all these strdup are for asan/valgrind to have some exact bounds to work with

	char *foo = strdup("___"); // should crash in asan mode
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 0, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// old school
	foo = strdup("\x1b[32mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 127, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("[32mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 127, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("32mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 0, "red color");
	mu_assert_eq(g, 127, "green color");
	mu_assert_eq(b, 0, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// 256
	foo = strdup("\x1b[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 255, "red color");
	mu_assert_eq(g, 135, "green color");
	mu_assert_eq(b, 255, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("[38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 255, "red color");
	mu_assert_eq(g, 135, "green color");
	mu_assert_eq(b, 255, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("38;5;213mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 255, "red color");
	mu_assert_eq(g, 135, "green color");
	mu_assert_eq(b, 255, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// 24 bit
	foo = strdup("\x1b[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 42, "red color");
	mu_assert_eq(g, 13, "green color");
	mu_assert_eq(b, 37, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("[38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 42, "red color");
	mu_assert_eq(g, 13, "green color");
	mu_assert_eq(b, 37, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	foo = strdup("38;2;42;13;37mhello\x1b[0m");
	r = g = b = a = 0;
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);
	mu_assert_eq(r, 42, "red color");
	mu_assert_eq(g, 13, "green color");
	mu_assert_eq(b, 37, "blue color");
	mu_assert_eq(a, 0, "alpha color");

	// no over-read
	foo = strdup("38;2");
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	foo = strdup("38;5");
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	foo = strdup("3");
	rz_cons_rgb_parse(foo, &r, &g, &b, &a);
	free(foo);

	mu_end;
}

bool test_cons_justify(void) {
	RzCons *cons = rz_cons_new();
	rz_cons_reset(cons);
	rz_cons_strcat_justify(cons, "Line1\nLine2", 2, '|');
	const char *buf = rz_cons_get_buffer(cons);
	const char *expected = "  | Line1\nLine2";

	mu_assert_streq(buf, expected, "Justify multiple lines");

	rz_cons_reset(cons);
	rz_cons_strcat_justify(cons, "A", 2, '|');
	buf = rz_cons_get_buffer(cons);
	mu_assert_streq(buf, "A", "Justify single char");

	rz_cons_free(cons);
	mu_end;
}

bool test_cons_at(void) {
	RzCons *cons = rz_cons_new();
	rz_cons_reset(cons);
	rz_cons_strcat_at(cons, "Hello", 2, 0, 10, 1);
	const char *buf = rz_cons_get_buffer(cons);
	mu_assert_true(strstr(buf, "Hello") != NULL, "Buffer contains Hello");
	rz_cons_free(cons);
	mu_end;
}

bool test_cons_misc(void) {
	RzCons *cons = rz_cons_new();

	rz_interrupt_break_push(cons->intr, NULL, NULL);
	mu_assert_false(rz_interrupt_is_breaked(cons->intr), "Not breaked initially");
	rz_interrupt_break_pop(cons->intr);

#if __UNIX__
	// Test UTF-8 detection via environment
	const char *env_vars[] = { "LC_ALL", "LC_CTYPE", "LANG" };
	char *old_envs[3];
	for (int i = 0; i < 3; i++) {
		old_envs[i] = rz_sys_getenv(env_vars[i]);
		rz_sys_setenv(env_vars[i], NULL);
	}

	rz_sys_setenv("LANG", "en_US.UTF-8");
	mu_assert_true(rz_cons_is_utf8(), "UTF-8 detected with LANG=en_US.UTF-8");

	rz_sys_setenv("LANG", "C");
	mu_assert_false(rz_cons_is_utf8(), "UTF-8 NOT detected with LANG=C");

	for (int i = 0; i < 3; i++) {
		rz_sys_setenv(env_vars[i], old_envs[i]);
		free(old_envs[i]);
	}
#endif

	// Interactive check
	mu_assert_false(rz_cons_is_interactive(cons), "Unit tests should not be interactive by default");
	rz_cons_set_interactive(cons, true);
	mu_assert_true(rz_cons_is_interactive(cons), "Manually set interactive to true");
	rz_cons_set_interactive(cons, false);
	mu_assert_false(rz_cons_is_interactive(cons), "Manually set interactive to false");

	rz_cons_free(cons);
	mu_end;
}

bool test_cons_highlight(void) {
	RzCons *cons = rz_cons_new();

	rz_cons_reset(cons);
	rz_cons_strcat(cons, "foo bar");
	rz_cons_highlight(cons, "foo");
	mu_assert_streq(rz_cons_get_buffer(cons), "\x1b[7mfoo\x1b[27m bar", "highlight plain word");

	rz_cons_reset(cons);
	rz_cons_strcat(cons, "foo foo");
	rz_cons_highlight(cons, "foo");
	mu_assert_streq(rz_cons_get_buffer(cons), "\x1b[7mfoo\x1b[27m \x1b[7mfoo\x1b[27m", "highlight all occurrences");

	rz_cons_reset(cons);
	rz_cons_strcat(cons, "\x1b[32mfoo\x1b[0m bar");
	rz_cons_highlight(cons, "foo");
	mu_assert_streq(rz_cons_get_buffer(cons), "\x1b[32m\x1b[7mfoo\x1b[27m bar", "highlight word inside ansi");

	// A buffer with only ansi escapes has no visible text, but the word must
	// still be remembered, otherwise rz_cons_flush calls highlight nothing
	rz_cons_reset(cons);
	rz_cons_strcat(cons, "\x1b[32m\x1b[0m");
	rz_cons_highlight(cons, "bar");
	mu_assert_streq(cons->highlight, "bar", "word recorded for ansi-only buffer");
	mu_assert_streq(rz_cons_get_buffer(cons), "\x1b[32m\x1b[0m", "ansi-only buffer unchanged");

	rz_cons_reset(cons);
	rz_cons_strcat(cons, "foo bar");
	rz_cons_highlight(cons, "");
	mu_assert_streq(rz_cons_get_buffer(cons), "foo bar", "empty word does not change buffer");
	mu_assert_null(cons->highlight, "empty word clears highlight");

	rz_cons_reset(cons);
	rz_cons_highlight(cons, "foo");
	mu_assert_null(rz_cons_get_buffer(cons), "empty buffer stays empty");

	rz_cons_free(cons);
	mu_end;
}

static bool test_cons_last_filtered(void) {
	static const struct {
		const char *input;
		const char *filter;
		const char *expected;
	} cases[] = {
		{ "one keep\nzero drop\ntwo keep\n", "keep", "one keep\ntwo keep\n" },
		{ "one keep\nzero drop\ntwo keep\n", "[0]", "one\nzero\ntwo\n" },
		{ "one\ntwo\nthree\n", ":1", "two\n" },
		{ "{\"value\":42}\n", "{.value}", "42\n" },
		{ "one\ntwo\n", "missing", NULL },
	};
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "create console");
	FILE *sink = rz_sys_fopen(RZ_SYS_DEVNULL, "w");
	mu_assert_notnull(sink, "open output sink");
	cons->fdout = fileno(sink);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		rz_cons_println(cons, "previous");
		rz_cons_flush(cons);
		rz_cons_print(cons, cases[i].input);
		rz_cons_grep_process(cons, rz_str_dup(cases[i].filter));
		rz_cons_flush(cons);
		rz_cons_last(cons);
		mu_assert_streq(rz_cons_get_buffer(cons), cases[i].expected, "replay filtered output");
		rz_cons_reset(cons);
	}

	fclose(sink);
	rz_cons_free(cons);
	mu_end;
}

static bool test_cons_last_capture(void) {
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "create console");
	FILE *sink = rz_sys_fopen(RZ_SYS_DEVNULL, "w");
	mu_assert_notnull(sink, "open output sink");
	cons->fdout = fileno(sink);

	rz_cons_last(cons);
	mu_assert_null(rz_cons_get_buffer(cons), "no output to replay initially");
	rz_cons_println(cons, "one keep\nzero drop\ntwo keep");
	rz_cons_flush(cons);
	rz_cons_last(cons);
	rz_cons_grep_process(cons, rz_str_dup("keep"));
	rz_cons_flush(cons);
	rz_cons_last(cons);
	rz_cons_grep_process(cons, rz_str_dup("two"));
	rz_cons_flush(cons);
	rz_cons_last(cons);
	mu_assert_streq(rz_cons_get_buffer(cons), "two keep\n", "successive filters replace saved output");
	rz_cons_flush(cons);
	rz_cons_flush(cons);

	rz_cons_push(cons);
	rz_cons_last(cons);
	rz_cons_grep_process(cons, rz_str_dup("[0]"));
	rz_cons_flush(cons);
	mu_assert_streq(rz_cons_get_buffer(cons), "two keep\n", "nested flush is deferred");
	rz_cons_filter(cons);
	mu_assert_streq(rz_cons_get_buffer(cons), "two\n", "nested capture can filter saved output");
	rz_cons_pop(cons);
	rz_cons_last(cons);
	mu_assert_streq(rz_cons_get_buffer(cons), "two keep\n", "capture and empty flush preserve saved output");
	rz_cons_reset(cons);
	rz_cons_println(cons, "replacement");
	rz_cons_flush(cons);
	rz_cons_last(cons);
	mu_assert_streq(rz_cons_get_buffer(cons), "replacement\n", "capture does not suppress the next snapshot");
	rz_cons_reset(cons);

	cons->context->lastEnabled = false;
	rz_cons_println(cons, "not saved");
	rz_cons_flush(cons);
	rz_cons_last(cons);
	mu_assert_null(rz_cons_get_buffer(cons), "disabled cache cannot be replayed");
	cons->context->lastEnabled = true;
	rz_cons_last(cons);
	mu_assert_streq(rz_cons_get_buffer(cons), "replacement\n", "disabled cache preserves saved output");
	rz_cons_reset(cons);

	const char binary[] = { 'a', '\0', 'b', '\n' };
	rz_cons_memcat(cons, binary, sizeof(binary));
	rz_cons_flush(cons);
	rz_cons_last(cons);
	mu_assert_eq(rz_cons_get_buffer_len(cons), sizeof(binary), "replay preserves binary length");
	mu_assert_memeq((const ut8 *)rz_cons_get_buffer(cons), (const ut8 *)binary, sizeof(binary), "replay preserves binary output");

	fclose(sink);
	rz_cons_free(cons);
	mu_end;
}

static bool test_cons_last_sizes(void) {
	// Same, shorter and longer than the saved output, each checked by ASan
	static const char *outputs[] = { "abc\n", "xyz\n", "q\n", "longer\n" };
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "create console");
	FILE *sink = rz_sys_fopen(RZ_SYS_DEVNULL, "w");
	mu_assert_notnull(sink, "open output sink");
	cons->fdout = fileno(sink);

	for (size_t i = 0; i < RZ_ARRAY_SIZE(outputs); i++) {
		rz_cons_print(cons, outputs[i]);
		rz_cons_flush(cons);
		rz_cons_last(cons);
		mu_assert_eq(rz_cons_get_buffer_len(cons), strlen(outputs[i]), "replay has the length of the output");
		mu_assert_streq(rz_cons_get_buffer(cons), outputs[i], "replay has the output");
		rz_cons_reset(cons);
	}

	fclose(sink);
	rz_cons_free(cons);
	mu_end;
}

// A redraw starts with RZ_CONS_CLEAR_SCREEN, whose carriage return takes no
// column: a line as wide as the console stays whole, a wider one keeps as many
// columns as a line without it.
static bool test_cons_visual_write_carriage_return(void) {
#define CLEAR Color_RESET RZ_CONS_CLEAR_SCREEN "\x1b[0;0H"
	// The line that fits is written twice, as every line homing the cursor;
	// the wider one is cut after 10 columns, as the line without the clear.
	static const char expect[] = CLEAR "0123456789" CLEAR "0123456789"
					   "\n" CLEAR "0123456789" RZ_CONS_CLEAR_FROM_CURSOR_TO_END Color_RESET
					   "\nabcdefghij" RZ_CONS_CLEAR_FROM_CURSOR_TO_END Color_RESET;
	char screen[] = CLEAR "0123456789\n" CLEAR "0123456789AB\nabcdefghijXY\n";
#undef CLEAR
	char *name = NULL;
	int fd = rz_file_mkstemp("rzcons", &name);
	mu_assert_neq((ut64)fd, (ut64)-1, "temporary output");
	RzCons *cons = rz_cons_new();
	mu_assert_notnull(cons, "create console");
	cons->fdout = fd;
	cons->columns = 10;
	cons->rows = 3;
	cons->blankline = false;
	cons->break_lines = false;
	rz_cons_visual_write(cons, screen);
	cons->fdout = 1;
	close(fd);
	size_t size = 0;
	char *out = rz_file_slurp(name, &size);
	rz_file_rm(name);
	free(name);
	mu_assert_notnull(out, "read output");
	mu_assert_eq(size, sizeof(expect) - 1, "length of the output");
	mu_assert_memeq((const ut8 *)out, (const ut8 *)expect, size, "columns of the lines");
	free(out);
	rz_cons_free(cons);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_cons);
	mu_run_test(test_cons_justify);
	mu_run_test(test_cons_at);
	mu_run_test(test_cons_misc);
	mu_run_test(test_cons_highlight);
	mu_run_test(test_cons_last_filtered);
	mu_run_test(test_cons_last_capture);
	mu_run_test(test_cons_last_sizes);
	mu_run_test(test_cons_visual_write_carriage_return);
	return tests_passed != tests_run;
}

mu_main(all_tests)
