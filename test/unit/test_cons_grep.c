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

bool test_grep_json_projection(void) {
	rz_cons_new();
	rz_cons_print("[{\"offset\":1,\"bytes\":\"aa\",\"opcode\":\"nop\",\"family\":\"cpu\",\"type\":\"nop\",\"jump\":2},{\"offset\":2,\"bytes\":\"bb\",\"opcode\":\"ret\",\"family\":\"cpu\",\"type\":\"ret\"}]");
	rz_cons_grep("{.[] | {offset, bytes, opcode, family, type, jump}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"offset\":1,\"bytes\":\"aa\",\"opcode\":\"nop\",\"family\":\"cpu\",\"type\":\"nop\",\"jump\":2},{\"offset\":2,\"bytes\":\"bb\",\"opcode\":\"ret\",\"family\":\"cpu\",\"type\":\"ret\"}]\n",
		"json array projection");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_escaped_pipe(void) {
	rz_cons_new();
	rz_cons_print("[{\"key1\":1,\"key2\":\"aa\",\"key3\":true}]");
	rz_cons_grep("{.[]\\|{key1, key2, key3}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"key1\":1,\"key2\":\"aa\",\"key3\":true}]\n",
		"json array projection with escaped pipe");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_whitespace_tokens(void) {
	rz_cons_new();
	rz_cons_print("[{\"k\":1}]");
	rz_cons_grep("{ . \t[ \t] \t| \t{ k } }");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"k\":1}]\n",
		"json array projection accepts whitespace between tokens");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_escaped_pipe_whitespace_tokens(void) {
	rz_cons_new();
	rz_cons_print("[{\"k\":1}]");
	rz_cons_grep("{ . [ ] \t\\| \t{ k } }");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"k\":1}]\n",
		"json array projection accepts whitespace around escaped pipe");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_allows_spaces_in_keys(void) {
	rz_cons_new();
	rz_cons_print("[{\"a b\":1},{\"a\":2}]");
	rz_cons_grep("{.[]\\|{a b}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"a b\":1},{}]\n",
		"json array projection allows spaces in object keys");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_skips_non_objects(void) {
	rz_cons_new();
	rz_cons_print("[{\"k\":1},7,\"x\",null,true,[],{\"z\":2},{\"k\":3}]");
	rz_cons_grep("{.[] | {k}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"k\":1},{},{\"k\":3}]\n",
		"json array projection skips non-object array items and keeps empty objects");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_partial_and_nested_values(void) {
	rz_cons_new();
	rz_cons_print("[{\"a\":1,\"nested\":{\"x\":1},\"arr\":[1,2],\"s\":\"hi\"},{\"b\":2},{\"z\":3}]");
	rz_cons_grep("{.[] | {a, b, nested, arr}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"a\":1,\"nested\":{\"x\":1},\"arr\":[1,2]},{\"b\":2},{}]\n",
		"json array projection keeps partial objects and nested values");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_preserves_null_array_values(void) {
	rz_cons_new();
	rz_cons_print("[{\"arr\":[null,1]}]");
	rz_cons_grep("{.[]\\|{arr}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{\"arr\":[null,1]}]\n",
		"json array projection preserves null elements in nested arrays");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_projection_matches_keys_exactly(void) {
	rz_cons_new();
	rz_cons_print("[{\"offset2\":5},{\"offset\":7,\"offset2\":8}]");
	rz_cons_grep("{.[] | {offset}}");
	mu_assert_streq(rz_cons_get_buffer(),
		"[{},{\"offset\":7}]\n",
		"json array projection matches object keys exactly");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_path_regression(void) {
	rz_cons_new();
	rz_cons_print("[{\"opcode\":\"nop\"}]");
	rz_cons_grep("{[0].opcode}");
	mu_assert_streq(rz_cons_get_buffer(), "nop\n", "json path still extracts one node");

	rz_cons_free();
	mu_end;
}

bool test_grep_json_path_preserves_literal_open_brace(void) {
	rz_cons_new();
	rz_cons_print("{\"a{b\":7}");
	rz_cons_grep("{.a{b}");
	mu_assert_streq(rz_cons_get_buffer(), "7\n", "json path preserves literal open brace in key");

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
	mu_run_test(test_grep_json_projection);
	mu_run_test(test_grep_json_projection_escaped_pipe);
	mu_run_test(test_grep_json_projection_whitespace_tokens);
	mu_run_test(test_grep_json_projection_escaped_pipe_whitespace_tokens);
	mu_run_test(test_grep_json_projection_allows_spaces_in_keys);
	mu_run_test(test_grep_json_projection_skips_non_objects);
	mu_run_test(test_grep_json_projection_partial_and_nested_values);
	mu_run_test(test_grep_json_projection_preserves_null_array_values);
	mu_run_test(test_grep_json_projection_matches_keys_exactly);
	mu_run_test(test_grep_json_path_regression);
	mu_run_test(test_grep_json_path_preserves_literal_open_brace);
	return tests_passed != tests_run;
}

mu_main(all_tests)
