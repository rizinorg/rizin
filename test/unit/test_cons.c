// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
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

typedef struct {
	RzStrBuf output;
	ut32 timeout;
	unsigned reads;
} BackendTest;

static int backend_test_read(void *user, RzCons *cons, ut32 timeout) {
	BackendTest *state = user;
	state->reads++;
	state->timeout = timeout;
	return timeout ? -1 : 0xc3;
}

static void backend_test_write(void *user, const char *text, size_t len) {
	BackendTest *state = user;
	rz_strbuf_append_n(&state->output, text, len);
}

static bool backend_test_size(void *user, int *width, int *height) {
	*width = 37;
	*height = 11;
	return true;
}

static bool test_cons_backend(void) {
	RzCons *cons = rz_cons_new();
	BackendTest state = { 0 };
	rz_strbuf_init(&state.output);
	RzConsBackend backend = { backend_test_read, backend_test_write, backend_test_size };
	mu_assert_true(rz_cons_set_backend(cons, &backend, &state), "attach backend");
	int rows;
	mu_assert_eq(rz_cons_get_size(cons, &rows), 37, "backend dimensions");
	mu_assert_eq(rows, 11, "backend rows");
	rz_cons_strcat(cons, "pending");
	mu_assert_eq(rz_cons_readchar(cons), 0xc3, "unsigned UTF-8 byte");
	mu_assert_streq(rz_strbuf_get(&state.output), "pending", "output flushed before input");
	mu_assert_true(rz_cons_readpush(cons, "\xff", 1), "push byte");
	mu_assert_eq(rz_cons_readchar(cons), 255, "read buffer remains unsigned");
	mu_assert_eq(state.reads, 1, "buffer has priority");
	mu_assert_eq(rz_cons_readchar_timeout(cons, 50), -1, "timed backend read");
	mu_assert_eq(state.timeout, 50, "timeout forwarded without native wait");
	rz_cons_gotoxy(cons, 4, 2);
	rz_cons_flush(cons);
	mu_assert_true(strstr(rz_strbuf_get(&state.output), "\x1b[2;4H") != NULL, "portable cursor positioning");
	rz_cons_set_cup(cons, true);
	mu_assert_true(strstr(rz_strbuf_get(&state.output), "\x1b[?1049h") != NULL, "alternate screen routed");
	RzConsBackend incomplete = { 0 };
	mu_assert_false(rz_cons_set_backend(cons, &incomplete, NULL), "partial backend rejected");
	mu_assert_eq(rz_cons_get_size(cons, NULL), 37, "rejection preserves current backend");
	mu_assert_true(rz_cons_set_backend(cons, NULL, NULL), "detach backend");
	rz_cons_free(cons);
	rz_strbuf_fini(&state.output);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_cons);
	mu_run_test(test_cons_backend);
	mu_run_test(test_cons_justify);
	mu_run_test(test_cons_at);
	mu_run_test(test_cons_misc);
	mu_run_test(test_cons_highlight);
	return tests_passed != tests_run;
}

mu_main(all_tests)
