// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2022 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "minunit.h"
#include <rz_util/rz_regex.h>
#include <rz_util/rz_strbuf.h>
#include <rz_util/rz_str.h>
#include <rz_vector.h>
#include <rz_platform.h>

bool exec_regex(RzRegex *regex, const char *str, RzRegexMatch **out) {
	RzPVector *matches = rz_regex_match_all_not_grouped(regex, str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	if (!matches || rz_pvector_empty(matches)) {
		return false;
	}
	*out = (RzRegexMatch *)rz_pvector_pop_front(matches);
	rz_pvector_free(matches);
	return true;
}

bool test_rz_regex_all_match(void) {
	RzRegex *reg = rz_regex_new("push", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(reg, "Regex was NULL");
	RzRegexMatch *match = NULL;
	mu_assert_true(exec_regex(reg, "push", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 0, "Start of match is not 0");
	mu_assert_eq(match->len, 4, "Len of match is not 4");
	free(match);
	rz_regex_free(reg);
	mu_end;
}

bool test_rz_regex_posix_blank(void) {
	RzRegex *reg = rz_regex_new("[[:blank:]]", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(reg, "Regex was NULL");
	RzRegexMatch *match = NULL;
	mu_assert_true(exec_regex(reg, "push\tpush", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 4, "Start of match is not 4");
	mu_assert_eq(match->len, 1, "Len of match is not 1");
	free(match);
	rz_regex_free(reg);
	mu_end;
}

bool test_rz_regex_extend_space(void) {
	RzRegex *reg = rz_regex_new("push esi", RZ_REGEX_DEFAULT, 0, NULL);
	mu_assert_notnull(reg, "Regex was NULL");
	RzRegexMatch *match = NULL;
	mu_assert_notnull(reg, "Regex was NULL");
	mu_assert_true(exec_regex(reg, "push esi", &match), "Regex match failed. Was ' ' replaced with \\s in the pattern?");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 0, "Start of match is not 0");
	mu_assert_eq(match->len, 8, "Len of match is not 8");
	free(match);
	rz_regex_free(reg);
	mu_end;
}

bool test_rz_regex_all_to_str(void) {
	RzRegex *reg = rz_regex_new("123", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(reg, "Regex was NULL");
	RzStrBuf *res = rz_regex_full_match_str("(123)", "123 123 123", RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT, "\n");
	char *str = rz_strbuf_drain(res);
	mu_assert_streq(str, "123\n123\n123", "String match failed.");
	free(str);

	res = rz_regex_full_match_str("(123)", "123", RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT, "\n");
	str = rz_strbuf_drain(res);
	mu_assert_streq(str, "123", "String match failed.");
	free(str);

	res = rz_regex_full_match_str("(123)", "", RZ_REGEX_ZERO_TERMINATED, RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT, "\n");
	str = rz_strbuf_drain(res);
	mu_assert_streq(str, "", "String match failed.");
	free(str);
	rz_regex_free(reg);
	mu_end;
}

bool test_rz_reg_exec(void) {
	const char *p = "abc|123";
	RzRegex *reg = rz_regex_new(p, RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(reg, "Regex was NULL");
	RzRegexMatch *match = NULL;
	mu_assert_true(exec_regex(reg, "abc", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 0, "Start of match is not 0");
	mu_assert_eq(match->len, 3, "Len of match is not 3");
	free(match);
	mu_assert_true(exec_regex(reg, "zabc", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 1, "Start of match is not 1");
	mu_assert_eq(match->len, 3, "Len of match is not 3");
	free(match);
	mu_assert_true(exec_regex(reg, "abcz", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 0, "Start of match is not 0");
	mu_assert_eq(match->len, 3, "Len of match is not 3");
	free(match);
	mu_assert_true(exec_regex(reg, "123", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 0, "Start of match is not 0");
	mu_assert_eq(match->len, 3, "Len of match is not 3");
	free(match);
	mu_assert_true(exec_regex(reg, "z123", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 1, "Start of match is not 1");
	mu_assert_eq(match->len, 3, "Len of match is not 3");
	free(match);
	mu_assert_true(exec_regex(reg, "123z", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 0, "Start of match is not 0");
	mu_assert_eq(match->len, 3, "Len of match is not 3");
	free(match);
	rz_regex_free(reg);
	const char *p_big = "\\d+(([abc]*d[efg])+|[123]4[567]+)*|[zyx]+(test)+[mnb]";
	reg = rz_regex_new(p_big, RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_true(exec_regex(reg, "z1abcde123z", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 1, "Start of match is not 1");
	mu_assert_eq(match->len, 6, "Len of match is not 6");
	free(match);
	mu_assert_true(exec_regex(reg, "ayztesttestb123z", &match), "Regex match failed");
	mu_assert_notnull(match, "match was not set");
	mu_assert_eq(match->start, 1, "Start of match is not 1");
	mu_assert_eq(match->len, 11, "Len of match is not 11");
	free(match);
	rz_regex_free(reg);
	mu_end;
}

bool test_rz_regex_capture(void) {
	char *str = "abcd PrefixHello42s xyz";

	RzRegex *re = rz_regex_new("[a-zA-Z]*(H[a-z]+)([0-9]*)s", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re, "regex_new");

	RzPVector *matches = rz_regex_match_all_not_grouped(re, str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_true(matches && !rz_pvector_empty(matches), "Regex match failed");
	mu_assert_eq(rz_pvector_len(matches), 3, "Regex match count failed.");

	RzRegexMatch *match = rz_pvector_at(matches, 0);
	mu_assert_eq(match->start, 5, "full match start");
	mu_assert_eq(match->len, 14, "full match len");
	char *s = rz_str_ndup(str + match->start, match->len);
	mu_assert_streq_free(s, "PrefixHello42s", "full match extract");

	match = rz_pvector_at(matches, 1);
	mu_assert_eq(match->start, 11, "capture 1 start");
	mu_assert_eq(match->len, 5, "capture 1 len");
	s = rz_str_ndup(str + match->start, match->len);
	mu_assert_streq_free(s, "Hello", "capture 1 extract");

	match = rz_pvector_at(matches, 2);
	mu_assert_eq(match->start, 16, "capture 2 start");
	mu_assert_eq(match->len, 2, "capture 2 len");
	s = rz_str_ndup(str + match->start, match->len);
	mu_assert_streq_free(s, "42", "capture 2 extract");

	rz_regex_free(re);
	rz_pvector_free(matches);
	mu_end;
}

bool test_rz_regex_find(void) {
	char *str = "\x1b[90m?\x1b[0m\x1b[37m   \x1b[0m\x1b[36mR0\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[90m##\x1b[0m\x1b[33m0x17\x1b[0m";

	RzRegexSize num_offset = rz_regex_find("(\\W|m)((0x[a-fA-F0-9]+)|\\d+)(\x1b|[^\\w;])", str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
	mu_assert_eq(num_offset, 78, "Wrong offset");

	num_offset = rz_regex_find("\\d+", str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
	mu_assert_eq(num_offset, 2, "Wrong offset");

	num_offset = rz_regex_find("0x111+", str, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT);
	mu_assert_eq(num_offset, SZT_MAX, "Wrong offset");

	mu_end;
}

bool test_rz_regex_named_matches(void) {
	RzRegex *reg = rz_regex_new("(?<proto>^\\w+)(:\\/\\/)(?<domain>\\w+)\\.(?<tdomain>\\w+)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(reg, "Regex was NULL");
	mu_assert_streq((char *)rz_regex_get_match_name(reg, 1), "proto", "proto name not set.");
	mu_assert_streq((char *)rz_regex_get_match_name(reg, 3), "domain", "domain name not set.");
	mu_assert_streq((char *)rz_regex_get_match_name(reg, 4), "tdomain", "tdomain name not set.");

	mu_assert_eq(rz_regex_get_group_idx_by_name(reg, "proto"), 1, "proto name not set.");
	mu_assert_eq(rz_regex_get_group_idx_by_name(reg, "domain"), 3, "domain name not set.");
	mu_assert_eq(rz_regex_get_group_idx_by_name(reg, "tdomain"), 4, "tdomain name not set.");
	mu_assert_eq(rz_regex_get_group_idx_by_name(reg, "nonexistent"), -1, "shouldn't exis");

	RzPVector *matches = rz_regex_match_all_not_grouped(reg, "https://rizin.re", RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_true(matches && !rz_pvector_empty(matches), "Regex match failed");
	mu_assert_eq(rz_pvector_len(matches), 5, "Regex match count failed.");

	RzRegexMatch *match = rz_pvector_at(matches, 0);
	mu_assert_streq((char *)rz_regex_get_match_name(reg, match->group_idx), "(null)", "(null) was not matched.");
	match = rz_pvector_at(matches, 1);
	mu_assert_streq((char *)rz_regex_get_match_name(reg, match->group_idx), "proto", "proto was not matched.");
	match = rz_pvector_at(matches, 2);
	mu_assert_streq((char *)rz_regex_get_match_name(reg, match->group_idx), "(null)", "(null) was not matched.");
	match = rz_pvector_at(matches, 3);
	mu_assert_streq((char *)rz_regex_get_match_name(reg, match->group_idx), "domain", "domain was not matched.");
	match = rz_pvector_at(matches, 4);
	mu_assert_streq((char *)rz_regex_get_match_name(reg, match->group_idx), "tdomain", "tdomain was not matched.");

	rz_regex_free(reg);
	rz_pvector_free(matches);
	mu_end;
}

bool test_rz_regex_match_all_native_utf8(void) {
	RzPVector *match_groups = NULL;
	RzRegexMatch *match = NULL;

	const char *utf8 = "A salat with 🍇🍉🍍 Extra 🍍🍍🍍现代汉语常用字表 please.";

	RzRegex *re = rz_regex_new("🍍..", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re, "Regex was NULL");
	RzPVector *matches = rz_regex_match_all(re, utf8, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "matches was not set");
	mu_assert_eq(rz_pvector_len(matches), 2, "matches len was wrong");

	match_groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 21, "match.start wrong");
	mu_assert_eq(match->len, 6, "match.len wrong");

	match_groups = rz_pvector_at(matches, 1);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 32, "match.start wrong");
	mu_assert_eq(match->len, 12, "match.len wrong");

	rz_pvector_free(matches);

	// Overlap
	matches = rz_regex_match_all_overlap(re, utf8, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "matches was not set");
	mu_assert_eq(rz_pvector_len(matches), 4, "matches len was wrong");

	match_groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 21, "match.start wrong");
	mu_assert_eq(match->len, 6, "match.len wrong");

	match_groups = rz_pvector_at(matches, 1);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 32, "match.start wrong");
	mu_assert_eq(match->len, 12, "match.len wrong");

	match_groups = rz_pvector_at(matches, 2);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 36, "match.start wrong");
	mu_assert_eq(match->len, 11, "match.len wrong");

	match_groups = rz_pvector_at(matches, 3);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 40, "match.start wrong");
	mu_assert_eq(match->len, 10, "match.len wrong");

	rz_pvector_free(matches);

	rz_regex_free(re);
	mu_end;
}

bool test_rz_regex_match_all_native_utf16(void) {
	RzPVector *match_groups = NULL;
	RzRegexMatch *match = NULL;

	const char *utf8 = "A salat with 🍇🍉🍍 Extra 🍍🍍🍍现代汉语常用字表 please.";
	// Encode to host endianess UTF-16/32
	ut16 *utf16_he = rz_str_utf8_to_utf16(utf8, RZ_HOST_IS_BIG_ENDIAN);

	RzRegex16 *re = rz_regex_new_16("🍍..", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re, "Regex was NULL");
	RzPVector *matches = rz_regex_match_all_16(re, utf16_he, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "matches was not set");
	mu_assert_eq(rz_pvector_len(matches), 2, "matches len was wrong");

	match_groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 17, "match.start wrong");
	mu_assert_eq(match->len, 4, "match.len wrong");

	match_groups = rz_pvector_at(matches, 1);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 26, "match.start wrong");
	mu_assert_eq(match->len, 6, "match.len wrong");

	rz_pvector_free(matches);

	// Overlap
	matches = rz_regex_match_all_overlap_16(re, utf16_he, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "matches was not set");
	mu_assert_eq(rz_pvector_len(matches), 4, "matches len was wrong");

	match_groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 17, "match.start wrong");
	mu_assert_eq(match->len, 4, "match.len wrong");

	match_groups = rz_pvector_at(matches, 1);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 26, "match.start wrong");
	mu_assert_eq(match->len, 6, "match.len wrong");

	match_groups = rz_pvector_at(matches, 2);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 28, "match.start wrong");
	mu_assert_eq(match->len, 5, "match.len wrong");

	match_groups = rz_pvector_at(matches, 3);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 30, "match.start wrong");
	mu_assert_eq(match->len, 4, "match.len wrong");

	rz_pvector_free(matches);

	rz_regex_free(re);
	mu_end;
}

bool test_rz_regex_match_all_native_utf32(void) {
	RzPVector *match_groups = NULL;
	RzRegexMatch *match = NULL;

	const char *utf8 = "A salat with 🍇🍉🍍 Extra 🍍🍍🍍现代汉语常用字表 please.";
	// Encode to host endianess UTF-32/32
	ut32 *utf32_he = rz_str_utf8_to_utf32(utf8, RZ_HOST_IS_BIG_ENDIAN);

	RzRegex32 *re = rz_regex_new_32("🍍..", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re, "Regex was NULL");
	RzPVector *matches = rz_regex_match_all_32(re, (ut32 *)utf32_he, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "matches was not set");
	mu_assert_eq(rz_pvector_len(matches), 2, "matches len was wrong");

	match_groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 15, "match.start wrong");
	mu_assert_eq(match->len, 3, "match.len wrong");

	match_groups = rz_pvector_at(matches, 1);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 23, "match.start wrong");
	mu_assert_eq(match->len, 3, "match.len wrong");

	rz_pvector_free(matches);

	// Overlap
	matches = rz_regex_match_all_overlap_32(re, utf32_he, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "matches was not set");
	mu_assert_eq(rz_pvector_len(matches), 4, "matches len was wrong");

	match_groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 15, "match.start wrong");
	mu_assert_eq(match->len, 3, "match.len wrong");

	match_groups = rz_pvector_at(matches, 1);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 23, "match.start wrong");
	mu_assert_eq(match->len, 3, "match.len wrong");

	match_groups = rz_pvector_at(matches, 2);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 24, "match.start wrong");
	mu_assert_eq(match->len, 3, "match.len wrong");

	match_groups = rz_pvector_at(matches, 3);
	mu_assert_eq(rz_pvector_len(match_groups), 1, "num of match groups was wrong");
	match = rz_pvector_at(match_groups, 0);
	mu_assert_eq(match->start, 25, "match.start wrong");
	mu_assert_eq(match->len, 3, "match.len wrong");

	rz_pvector_free(matches);

	rz_regex_free(re);
	mu_end;
}

int main() {
	mu_run_test(test_rz_regex_all_match);
	mu_run_test(test_rz_regex_extend_space);
	mu_run_test(test_rz_reg_exec);
	mu_run_test(test_rz_regex_capture);
	mu_run_test(test_rz_regex_all_to_str);
	mu_run_test(test_rz_regex_named_matches);
	mu_run_test(test_rz_regex_posix_blank);
	mu_run_test(test_rz_regex_find);
	mu_run_test(test_rz_regex_match_all_native_utf8);
	mu_run_test(test_rz_regex_match_all_native_utf16);
	mu_run_test(test_rz_regex_match_all_native_utf32);
}
