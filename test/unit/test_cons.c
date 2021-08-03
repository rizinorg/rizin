// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
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

static RzLineNSCompletionResult *nocompletion_run(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	return rz_line_ns_completion_result_new(0, 0, NULL);
}

bool test_line_nocompletion(void) {
	RzLine *line = rz_line_new();
	line->ns_completion.run = nocompletion_run;
	strcpy(line->buffer.data, "pd");
	line->buffer.length = strlen("pd");
	line->buffer.index = 2;
	rz_line_autocomplete();

	mu_assert_streq(line->buffer.data, "pd", "pd is still there");
	mu_assert_eq(line->buffer.length, 2, "length is still 2");
	mu_assert_eq(line->buffer.index, 2, "the user position is still the same");

	rz_line_free();
	mu_end;
}

static RzLineNSCompletionResult *onecompletion_run(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	RzLineNSCompletionResult *res = rz_line_ns_completion_result_new(0, 2, NULL);
	rz_line_ns_completion_result_add(res, "pdf");
	return res;
}

bool test_line_onecompletion(void) {
	RzLine *line = rz_line_new();
	line->ns_completion.run = onecompletion_run;

	strcpy(line->buffer.data, "pd");
	line->buffer.length = strlen("pd");
	line->buffer.index = 2;
	rz_line_autocomplete();

	mu_assert_eq(line->buffer.length, 4, "length is updated (space included)");
	mu_assert_eq(line->buffer.index, 4, "index after the space");
	mu_assert_streq(line->buffer.data, "pdf ", "pdf has been autocompleted and a space added");

	strcpy(line->buffer.data, "pd fcn");
	line->buffer.length = strlen("pd fcn");
	line->buffer.index = 2;
	rz_line_autocomplete();

	mu_assert_eq(line->buffer.index, 3, "should leave everythin else intact");
	mu_assert_eq(line->buffer.length, 7, "length is updated");
	mu_assert_streq(line->buffer.data, "pdf fcn", "pdf has been autocompleted and fcn kept intact");

	rz_line_free();
	mu_end;
}

static RzLineNSCompletionResult *multicompletion_run(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	RzLineNSCompletionResult *res = rz_line_ns_completion_result_new(0, 2, NULL);
	rz_line_ns_completion_result_add(res, "pdf");
	rz_line_ns_completion_result_add(res, "pdF");
	rz_line_ns_completion_result_add(res, "pdb");
	rz_line_ns_completion_result_add(res, "pdx");
	return res;
}

static RzLineNSCompletionResult *multicompletion_run2(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	RzLineNSCompletionResult *res = rz_line_ns_completion_result_new(0, 1, NULL);
	rz_line_ns_completion_result_add(res, "pdf");
	rz_line_ns_completion_result_add(res, "pdF");
	rz_line_ns_completion_result_add(res, "pdb");
	rz_line_ns_completion_result_add(res, "pdx");
	return res;
}

bool test_line_multicompletion(void) {
	RzCons *cons = rz_cons_new();
	// Make test reproducible everywhere
	cons->force_columns = 80;
	cons->force_rows = 23;
	rz_line_free();
	RzLine *line = rz_line_new();
	line->ns_completion.run = multicompletion_run;
	cons->line = line;

	strcpy(line->buffer.data, "pd");
	line->buffer.length = strlen("pd");
	line->buffer.index = 2;
	rz_line_autocomplete();

	mu_assert_eq(line->buffer.length, 2, "length is the same");
	mu_assert_eq(line->buffer.index, 2, "index is the same");
	mu_assert_streq(line->buffer.data, "pd", "pd is the same");

	const char *exp_buf = "> pd\n"
			      "pdf       pdF       pdb       pdx       \n";
	const char *buf = rz_cons_get_buffer();
	mu_assert_notnull(buf, "buf is not null");
	mu_assert_streq(buf, exp_buf, "options are shown correctly");
	rz_cons_reset();

	line->ns_completion.run = multicompletion_run2;
	strcpy(line->buffer.data, "p");
	line->buffer.length = strlen("p");
	line->buffer.index = 1;
	rz_line_autocomplete();

	mu_assert_eq(line->buffer.length, 2, "length was updated for 'pd'");
	mu_assert_eq(line->buffer.index, 2, "index is at the end of 'pd'");
	mu_assert_streq(line->buffer.data, "pd", "pd was written because max common prefx");

	exp_buf = "> pd\n"
		  "pdf       pdF       pdb       pdx       \n";
	buf = rz_cons_get_buffer();
	mu_assert_notnull(buf, "buf is not null");
	mu_assert_streq(buf, exp_buf, "options are shown correctly");

	rz_cons_free();
	mu_end;
}

bool test_line_kill_word(void) {
	RzCons *cons = rz_cons_new();
	// Make test reproducible everywhere
	cons->force_columns = 80;
	cons->force_rows = 23;
	rz_line_free();
	RzLine *line = rz_line_new();
	line->ns_completion.run = multicompletion_run;
	cons->line = line;

	// write the string, then do ^b two times to move the index to 10, then ^d to delete the word under the cursor
	const char instr[] = "pd 10@ hello\x1b\x62\x1b\x62\x1b\x64\n";
	rz_cons_readpush(instr, sizeof(instr));
	rz_line_readline();

	mu_assert_eq(line->buffer.index, 3, "index is after 'pd '");
	mu_assert_streq(line->buffer.data, "pd @ hello", "10 was deleted");

	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_rz_cons);
	mu_run_test(test_line_nocompletion);
	mu_run_test(test_line_onecompletion);
	mu_run_test(test_line_multicompletion);
	mu_run_test(test_line_kill_word);
	return tests_passed != tests_run;
}

mu_main(all_tests)
