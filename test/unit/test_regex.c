// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_regex.h>
#include "minunit.h"

bool exec_regex(RzRegex *regex, const char *str, RzRegexMatch *out) {
	RzRegexMatch match[2];
	mu_assert_true(rz_regex_exec(regex, str, 1, &match[0], 0) == 0, "Regex match failed");
	mu_assert_true(rz_regex_exec(regex, str, 1, &match[1], RZ_REGEX_LARGE) == 0, "Regex match failed for large engine");
	mu_assert_memeq((ut8 *)&match[0], (ut8 *)&match[1], sizeof(RzRegexMatch), "Results from large engine match does not equal small engine match");
	*out = match[0];
	return true;
}

bool test_rz_reg_exec(void) {
	const char *p = "abc|123";
	RzRegex *reg = rz_regex_new(p, "e");
	mu_assert_notnull(reg, "Regex was NULL");
	RzRegexMatch match;
	mu_assert_true(exec_regex(reg, "abc", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 0, "Start of match is not 0");
	mu_assert_eq(match.rm_eo, 3, "Start of match is not 3");
	mu_assert_true(exec_regex(reg, "zabc", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 1, "Start of match is not 1");
	mu_assert_eq(match.rm_eo, 4, "Start of match is not 4");
	mu_assert_true(exec_regex(reg, "abcz", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 0, "Start of match is not 0");
	mu_assert_eq(match.rm_eo, 3, "Start of match is not 3");
	mu_assert_true(exec_regex(reg, "123", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 0, "Start of match is not 0");
	mu_assert_eq(match.rm_eo, 3, "Start of match is not 3");
	mu_assert_true(exec_regex(reg, "z123", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 1, "Start of match is not 1");
	mu_assert_eq(match.rm_eo, 4, "Start of match is not 4");
	mu_assert_true(exec_regex(reg, "123z", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 0, "Start of match is not 0");
	mu_assert_eq(match.rm_eo, 3, "Start of match is not 3");
	rz_regex_free(reg);
	const char *p_big = "\\d+(([abc]*d[efg])+|[123]4[567]+)*|[zyx]+(test)+[mnb]";
	reg = rz_regex_new(p_big, "e");
	mu_assert_true(exec_regex(reg, "z1abcde123z", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 1, "Start of match is not 1");
	mu_assert_eq(match.rm_eo, 7, "Start of match is not 7");
	mu_assert_true(exec_regex(reg, "ayztesttestb123z", &match), "Regex match failed");
	mu_assert_eq(match.rm_so, 1, "Start of match is not 1");
	mu_assert_eq(match.rm_eo, 12, "Start of match is not 11");
	rz_regex_free(reg);
	mu_end;
}

bool test_rz_regex_capture(void) {
	char *str = "abcd PrefixHello42s xyz";

	RzRegex *re = rz_regex_new("[a-zA-Z]*(H[a-z]+)([0-9]*)s", "e");
	mu_assert_notnull(re, "regex_new");

	RzRegexMatch groups[4];
	int r = rz_regex_exec(re, str, RZ_ARRAY_SIZE(groups), groups, 0);
	mu_assert_eq(r, 0, "regex_exec");

	mu_assert_eq(groups[0].rm_so, 5, "full match start");
	mu_assert_eq(groups[0].rm_eo, 19, "full match end");
	char *s = rz_regex_match_extract(str, &groups[0]);
	mu_assert_streq_free(s, "PrefixHello42s", "full match extract");

	mu_assert_eq(groups[1].rm_so, 11, "capture 1 start");
	mu_assert_eq(groups[1].rm_eo, 16, "capture 1 end");
	s = rz_regex_match_extract(str, &groups[1]);
	mu_assert_streq_free(s, "Hello", "capture 1 extract");

	mu_assert_eq(groups[2].rm_so, 16, "capture 2 start");
	mu_assert_eq(groups[2].rm_eo, 18, "capture 2 end");
	s = rz_regex_match_extract(str, &groups[2]);
	mu_assert_streq_free(s, "42", "capture 2 extract");

	mu_assert_eq(groups[3].rm_so, -1, "capture 3 start");
	mu_assert_eq(groups[3].rm_eo, -1, "capture 3 end");
	s = rz_regex_match_extract(str, &groups[3]);
	mu_assert_null(s, "capture 3 extract");

	rz_regex_free(re);
	mu_end;
}

int main() {
	mu_run_test(test_rz_reg_exec);
	mu_run_test(test_rz_regex_capture);
}
