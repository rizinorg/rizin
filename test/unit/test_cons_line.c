// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

static RzLineNSCompletionResult *nocompletion_run(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	(void)buf;
	(void)prompt_type;
	(void)user;
	return rz_line_ns_completion_result_new(0, 0, NULL);
}

bool test_line_nocompletion(void) {
	RzLine *line = rz_line_new();
	line->ns_completion.run = nocompletion_run;
	strcpy(line->buffer.data, "pd");
	line->buffer.length = strlen("pd");
	line->buffer.index = 2;
	rz_line_autocomplete(line);

	mu_assert_streq(line->buffer.data, "pd", "pd is still there");
	mu_assert_eq(line->buffer.length, 2, "length is still 2");
	mu_assert_eq(line->buffer.index, 2, "the user position is still the same");

	rz_line_free(line);
	mu_end;
}

static RzLineNSCompletionResult *onecompletion_run(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	(void)buf;
	(void)prompt_type;
	(void)user;
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
	rz_line_autocomplete(line);

	mu_assert_eq(line->buffer.length, 4, "length is updated (space included)");
	mu_assert_eq(line->buffer.index, 4, "index after the space");
	mu_assert_streq(line->buffer.data, "pdf ", "pdf has been autocompleted and a space added");

	strcpy(line->buffer.data, "pd fcn");
	line->buffer.length = strlen("pd fcn");
	line->buffer.index = 2;
	rz_line_autocomplete(line);

	mu_assert_eq(line->buffer.index, 3, "should leave everythin else intact");
	mu_assert_eq(line->buffer.length, 7, "length is updated");
	mu_assert_streq(line->buffer.data, "pdf fcn", "pdf has been autocompleted and fcn kept intact");

	rz_line_free(line);
	mu_end;
}

static RzLineNSCompletionResult *multicompletion_run(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	(void)buf;
	(void)prompt_type;
	(void)user;
	RzLineNSCompletionResult *res = rz_line_ns_completion_result_new(0, 2, NULL);
	rz_line_ns_completion_result_add(res, "pdf");
	rz_line_ns_completion_result_add(res, "pdF");
	rz_line_ns_completion_result_add(res, "pdb");
	rz_line_ns_completion_result_add(res, "pdx");
	return res;
}

static RzLineNSCompletionResult *multicompletion_run2(RzLineBuffer *buf, RzLinePromptType prompt_type, void *user) {
	(void)buf;
	(void)prompt_type;
	(void)user;
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
	RzLine *line = cons->line;
	line->ns_completion.run = multicompletion_run;

	strcpy(line->buffer.data, "pd");
	line->buffer.length = strlen("pd");
	line->buffer.index = 2;
	rz_line_autocomplete(line);

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
	rz_line_autocomplete(line);

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
	RzLine *line = cons->line;
	line->ns_completion.run = multicompletion_run;

	// write the string, then do ^b two times to move the index to 10, then ^d to delete the word under the cursor
	const char instr[] = "pd 10@ hello\x1b\x62\x1b\x62\x1b\x64\n";
	rz_cons_readpush(instr, sizeof(instr));
	rz_line_readline(line);

	mu_assert_eq(line->buffer.index, 3, "index is after 'pd '");
	mu_assert_streq(line->buffer.data, "pd @ hello", "10 was deleted");

	rz_cons_free();
	mu_end;
}

bool test_line_undo(void) {
	RzCons *cons = rz_cons_new();
	// Make test reproducible everywhere
	cons->force_columns = 80;
	cons->force_rows = 23;
	RzLine *line = cons->line;

	// write 20 chars and undo once
	char input_concat[] = "01234567890123456789\x1f\n";
	rz_cons_readpush(input_concat, sizeof(input_concat));
	rz_line_readline(line);
	mu_assert_eq(line->buffer.length, 0, "concatenated string should get cleared");
	mu_assert_eq(line->buffer.index, 0, "index is 0");

	// write a string, delete, then undo('\x1f') twice
	char input_undo[] = "0123\x17\x1f\x1f\n";
	rz_cons_readpush(input_undo, sizeof(input_undo));
	rz_line_readline(line);
	mu_assert_eq(line->buffer.index, 0, "index is at 0");
	mu_assert_eq(line->buffer.length, 0, "legth is 0");

	// write a string, undo('\x1f') and redo('\x1b\x3f')
	char input_redo[] = "pDF\x1f\x1b\x3f\n";
	rz_cons_readpush(input_redo, sizeof(input_redo));
	rz_line_readline(line);
	mu_assert_streq(line->buffer.data, "pDF", "redo not working");

	// run completion (example of replacing and continuous operation).
	line->ns_completion.run = onecompletion_run;
	// now "pd" has been confirmed to be completed to "pdf ". undo will turn it to previous state replacing the texts.
	const char input_undo_group[] = "pd\t\x1f\n";
	rz_cons_readpush(input_undo_group, sizeof(input_undo_group));
	rz_line_readline(line);
	mu_assert_streq(line->buffer.data, "pd", "undo group operations not working");

	rz_cons_free();
	mu_end;
}

bool test_line_misc(void) {
	RzLine *line = rz_line_new();
	mu_assert_notnull(line, "Line object should be created");
	rz_line_set_prompt(line, "test> ");
	char *prompt = rz_line_get_prompt(line);
	mu_assert_notnull(prompt, "Prompt should not be null");
	mu_assert_streq_free(prompt, "test> ", "Line prompt check");

	rz_line_clipboard_push(line, "item1");
	mu_assert_eq(rz_list_length(line->kill_ring), 1, "Kill ring size");

	rz_line_free(line);
	mu_end;
}

bool test_line_ns_completion(void) {
	RzLineNSCompletionResult *res = rz_line_ns_completion_result_new(0, 5, ".");
	mu_assert_notnull(res, "Completion result new");

	rz_line_ns_completion_result_add(res, "test1");
	rz_line_ns_completion_result_add(res, "test2");
	rz_line_ns_completion_result_add(res, "test1"); // Should be ignored

	mu_assert_eq(rz_pvector_len(&res->options), 2, "Two unique options");
	mu_assert_streq(rz_pvector_at(&res->options, 0), "test1", "Option 0 check");
	mu_assert_streq(rz_pvector_at(&res->options, 1), "test2", "Option 1 check");

	rz_line_ns_completion_result_propose(res, "hello", "he", 2);
	mu_assert_eq(rz_pvector_len(&res->options), 3, "Three options after propose");
	char *opt2 = rz_pvector_at(&res->options, 2);
	mu_assert_notnull(opt2, "Option 2 should not be null");
	mu_assert_streq(opt2, "hello", "Option 2 check");

	rz_line_ns_completion_result_free(res);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_line_nocompletion);
	mu_run_test(test_line_onecompletion);
	mu_run_test(test_line_multicompletion);
	mu_run_test(test_line_kill_word);
	mu_run_test(test_line_undo);
	mu_run_test(test_line_misc);
	mu_run_test(test_line_ns_completion);
	return tests_passed != tests_run;
}

mu_main(all_tests)
