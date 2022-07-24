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

int main() {
	mu_run_test(test_rz_reg_exec);
}
