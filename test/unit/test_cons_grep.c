// SPDX-FileCopyrightText: 2026 Maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include "minunit.h"

bool test_grep_parse_simple(void) {
	RzCons *cons = rz_cons_new();
	char *cmd = strdup("pd~mov");
	rz_cons_grep_parsecmd(cmd, "");

	RzConsGrep *grep = &cons->context->grep;
	mu_assert_eq(grep->nstrings, 1, "nstrings is 1");
	mu_assert_streq(grep->strings[0], "mov", "string is mov");
	mu_assert_streq(cmd, "pd", "cmd trimmed");

	free(cmd);
	rz_cons_free();
	mu_end;
}

bool test_grep_parse_multiple(void) {
	RzCons *cons = rz_cons_new();
	char *cmd = strdup("pd~mov,call");
	rz_cons_grep_parsecmd(cmd, "");

	RzConsGrep *grep = &cons->context->grep;
	mu_assert_eq(grep->nstrings, 2, "nstrings is 2");
	mu_assert_streq(grep->strings[0], "mov", "string 0 is mov");
	mu_assert_streq(grep->strings[1], "call", "string 1 is call");

	free(cmd);
	rz_cons_free();
	mu_end;
}

bool test_grep_parse_negation(void) {
	RzCons *cons = rz_cons_new();
	char *cmd = strdup("pd~!mov");
	rz_cons_grep_parsecmd(cmd, "");

	RzConsGrep *grep = &cons->context->grep;
	mu_assert_eq(grep->neg, 1, "negation is set");
	mu_assert_eq(grep->nstrings, 1, "nstrings is 1");
	mu_assert_streq(grep->strings[0], "mov", "string is mov");

	free(cmd);
	rz_cons_free();
	mu_end;
}

bool test_grep_parse_case_insensitive(void) {
	RzCons *cons = rz_cons_new();
	char *cmd = strdup("pd~+mov");
	rz_cons_grep_parsecmd(cmd, "");

	RzConsGrep *grep = &cons->context->grep;
	mu_assert_eq(grep->icase, 1, "icase is set");
	mu_assert_eq(grep->nstrings, 1, "nstrings is 1");
	mu_assert_streq(grep->strings[0], "mov", "string is mov");

	free(cmd);
	rz_cons_free();
	mu_end;
}

bool test_grep_parse_line(void) {
	RzCons *cons = rz_cons_new();
	char *cmd = strdup("pd~:5");
	rz_cons_grep_parsecmd(cmd, "");

	RzConsGrep *grep = &cons->context->grep;
	mu_assert_eq(grep->line, 5, "line is 5");

	free(cmd);
	rz_cons_free();
	mu_end;
}

bool test_grep_line(void) {
	rz_cons_new();
	rz_cons_grep("mov");
	char line[] = "mov eax, 1";
	int len = rz_cons_grep_line(line, strlen(line));
	mu_assert_eq(len, 10, "Grep line matches");

	char line2[] = "sub eax, 1";
	int len2 = rz_cons_grep_line(line2, strlen(line2));
	mu_assert_eq(len2, 0, "Grep line does not match");

	rz_cons_free();
	mu_end;
}

bool all_tests() {
	mu_run_test(test_grep_parse_simple);
	mu_run_test(test_grep_parse_multiple);
	mu_run_test(test_grep_parse_negation);
	mu_run_test(test_grep_parse_case_insensitive);
	mu_run_test(test_grep_parse_line);
	mu_run_test(test_grep_line);
	return tests_passed != tests_run;
}

mu_main(all_tests)
