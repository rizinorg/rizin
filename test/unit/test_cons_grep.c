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

bool test_grep_json_path(void) {
	static const struct {
		const char *json;
		const char *grep;
		const char *expected;
		const char *message;
	} cases[] = {
		{
			"[{\"offset\":1,\"bytes\":\"aa\",\"opcode\":\"nop\",\"family\":\"cpu\",\"type\":\"nop\",\"jump\":2},{\"offset\":2,\"bytes\":\"bb\",\"opcode\":\"ret\",\"family\":\"cpu\",\"type\":\"ret\"}]",
			"{.[] | {offset, bytes, opcode, family, type, jump}}",
			"[{\"offset\":1,\"bytes\":\"aa\",\"opcode\":\"nop\",\"family\":\"cpu\",\"type\":\"nop\",\"jump\":2},{\"offset\":2,\"bytes\":\"bb\",\"opcode\":\"ret\",\"family\":\"cpu\",\"type\":\"ret\"}]\n",
			"json path array projection",
		},
		{
			"[{\"s\":\"alpha\",\"n\":1,\"b\":true,\"nil\":null,\"obj\":{\"x\":1},\"arr\":[1,2]},{\"s\":\"beta\",\"n\":2,\"b\":false,\"obj\":{\"y\":\"z\"}},{\"s\":\"gamma\",\"arr\":[]}]",
			"{.[]\\|{s,n,b,nil,obj,arr,missing}}",
			"[{\"s\":\"alpha\",\"n\":1,\"b\":true,\"nil\":null,\"obj\":{\"x\":1},\"arr\":[1,2]},{\"s\":\"beta\",\"n\":2,\"b\":false,\"obj\":{\"y\":\"z\"}},{\"s\":\"gamma\",\"arr\":[]}]\n",
			"json path array projection keeps existing typed values",
		},
		{
			"[{\"key1\":1,\"key2\":\"aa\",\"key3\":true}]",
			"{.[]\\|{key1, key2, key3}}",
			"[{\"key1\":1,\"key2\":\"aa\",\"key3\":true}]\n",
			"json path array projection with escaped pipe",
		},
		{
			"[]",
			"{ .[] \\| { key1, key2 } }",
			"[]\n",
			"json path array projection handles empty arrays",
		},
		{
			"[{\"k\":1}]",
			"{ . \t[ \t] \t| \t{ k } }",
			"[{\"k\":1}]\n",
			"json path array projection accepts whitespace between tokens",
		},
		{
			"[{\"k\":1}]",
			"{ . [ ] \t\\| \t{ k } }",
			"[{\"k\":1}]\n",
			"json path array projection accepts whitespace around escaped pipe",
		},
		{
			"[{\"a b\":1},{\"a\":2}]",
			"{.[]\\|{a b}}",
			"[{\"a b\":1},{}]\n",
			"json path array projection allows spaces in object keys",
		},
		{
			"[{\"k\":1},7,\"x\",null,true,[],{\"z\":2},{\"k\":3}]",
			"{.[] | {k}}",
			"[{\"k\":1},{},{\"k\":3}]\n",
			"json path array projection skips non-object array items and keeps empty objects",
		},
		{
			"[{\"a\":1,\"nested\":{\"x\":1},\"arr\":[1,2],\"s\":\"hi\"},{\"b\":2},{\"z\":3}]",
			"{.[] | {a, b, nested, arr}}",
			"[{\"a\":1,\"nested\":{\"x\":1},\"arr\":[1,2]},{\"b\":2},{}]\n",
			"json path array projection keeps partial objects and nested values",
		},
		{
			"[{\"arr\":[null,1]}]",
			"{.[]\\|{arr}}",
			"[{\"arr\":[null,1]}]\n",
			"json path array projection preserves null elements in nested arrays",
		},
		{
			"[{\"z\":1},{\"z\":2}]",
			"{.[]\\|{key1,key2}}",
			"[{},{}]\n",
			"json path array projection emits empty objects for missing keys",
		},
		{
			"[{\"offset2\":5},{\"offset\":7,\"offset2\":8}]",
			"{.[] | {offset}}",
			"[{},{\"offset\":7}]\n",
			"json path array projection matches object keys exactly",
		},
		{
			"{\"key1\":1}",
			"{.[]\\|{key1}}",
			"[]\n",
			"json path array projection returns empty array for non-array input",
		},
		{
			"[{\"opcode\":\"nop\"}]",
			"{[0].opcode}",
			"nop\n",
			"json path still extracts one node",
		},
		{
			"{\"a{b\":7}",
			"{.a{b}",
			"7\n",
			"json path preserves literal open brace in key",
		},
	};

	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		rz_cons_new();
		rz_cons_print(cases[i].json);
		rz_cons_grep(cases[i].grep);
		mu_assert_streq(rz_cons_get_buffer(), cases[i].expected, cases[i].message);
		rz_cons_free();
	}
	mu_end;
}

bool all_tests() {
	mu_run_test(test_grep_parse_simple);
	mu_run_test(test_grep_parse_multiple);
	mu_run_test(test_grep_parse_negation);
	mu_run_test(test_grep_parse_case_insensitive);
	mu_run_test(test_grep_parse_line);
	mu_run_test(test_grep_line);
	mu_run_test(test_grep_json_path);
	return tests_passed != tests_run;
}

mu_main(all_tests)
