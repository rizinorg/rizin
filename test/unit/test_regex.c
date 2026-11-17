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

	rz_regex_free_16(re);
	free(utf16_he);
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

	rz_regex_free_32(re);
	free(utf32_he);
	mu_end;
}

bool test_rz_regex_match_iter_utf8_groups(void) {
	const char *text = "TextTextText";
	RzRegex *re = rz_regex_new("(Te(x)t)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re, "regex new");

	static const struct {
		RzRegexSize match_idx;
		RzRegexSize group_idx;
		RzRegexSize start;
		RzRegexSize len;
	} expected[9] = {
		{ 0, 0, 0, 4 },
		{ 0, 1, 0, 4 },
		{ 0, 2, 2, 1 },
		{ 1, 0, 4, 4 },
		{ 1, 1, 4, 4 },
		{ 1, 2, 6, 1 },
		{ 2, 0, 8, 4 },
		{ 2, 1, 8, 4 },
		{ 2, 2, 10, 1 },
	};

	RzIterator it;
	mu_assert_true(rz_regex_match_iter(re, text, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter init");

	size_t idx = 0;
	RzRegexMatch *m;
	rz_iterator_foreach(&it, m) {
		mu_assert_true(idx < RZ_ARRAY_SIZE(expected), "too many iter matches");
		mu_assert_eq(m->match_idx, expected[idx].match_idx, "iter match_idx");
		mu_assert_eq(m->group_idx, expected[idx].group_idx, "iter group_idx");
		mu_assert_eq(m->start, expected[idx].start, "iter start");
		mu_assert_eq(m->len, expected[idx].len, "iter len");
		idx++;
	}
	mu_assert_eq(idx, RZ_ARRAY_SIZE(expected), "iter count");
	rz_iterator_fini(&it);

	RzPVector *all = rz_regex_match_all(re, text, RZ_REGEX_ZERO_TERMINATED, 0,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(all, "match_all");
	mu_assert_eq(rz_pvector_len(all), 3, "match_all outer len");
	idx = 0;
	void **outer_it;
	rz_pvector_foreach (all, outer_it) {
		RzPVector *groups = *outer_it;
		mu_assert_eq(rz_pvector_len(groups), 3, "match_all group len");
		void **inner_it;
		rz_pvector_foreach (groups, inner_it) {
			RzRegexMatch *gm = *inner_it;
			mu_assert_eq(gm->match_idx, expected[idx].match_idx, "match_all match_idx");
			mu_assert_eq(gm->group_idx, expected[idx].group_idx, "match_all group_idx");
			mu_assert_eq(gm->start, expected[idx].start, "match_all start");
			mu_assert_eq(gm->len, expected[idx].len, "match_all len");
			idx++;
		}
	}
	rz_pvector_free(all);

	RzPVector *first = rz_regex_match_first(re, text, RZ_REGEX_ZERO_TERMINATED, 0,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(first, "match_first");
	mu_assert_eq(((RzRegexMatch *)rz_pvector_at(first, 0))->match_idx, 0, "first match_idx");
	RzRegexMatch *g2 = rz_pvector_at(first, 2);
	mu_assert_eq(g2->match_idx, 0, "first group match_idx");
	rz_pvector_free(first);

	rz_regex_free(re);
	mu_end;
}

bool test_rz_regex_match_iter_overlap_utf8(void) {
	RzRegex *re_aa = rz_regex_new("aa", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_aa, "regex aa");

	RzIterator it;
	mu_assert_true(rz_regex_match_iter_overlap(re_aa, "aaaa", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter overlap aa");
	size_t count = 0;
	RzRegexMatch *m;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "overlap match_idx");
		mu_assert_eq(m->group_idx, 0, "overlap group_idx");
		mu_assert_eq(m->start, count, "overlap start");
		mu_assert_eq(m->len, 2, "overlap len");
		count++;
	}
	mu_assert_eq(count, 3, "overlap aa count");
	rz_iterator_fini(&it);
	rz_regex_free(re_aa);

	const char *utf8 = "A salat with 🍇🍉🍍 Extra 🍍🍍🍍现代汉语常用字表 please.";
	RzRegex *re_u8 = rz_regex_new("🍍..", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_u8, "regex utf8");
	mu_assert_true(rz_regex_match_iter_overlap(re_u8, utf8, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter overlap utf8");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "utf8 overlap match_idx");
		count++;
	}
	mu_assert_eq(count, 4, "utf8 overlap count");
	rz_iterator_fini(&it);
	rz_regex_free(re_u8);
	mu_end;
}

bool test_rz_regex_match_iter_utf16_and_utf32(void) {
	const char *utf8 = "A salat with 🍇🍉🍍 Extra 🍍🍍🍍现代汉语常用字表 please.";
	ut16 *utf16_he = rz_str_utf8_to_utf16(utf8, RZ_HOST_IS_BIG_ENDIAN);
	mu_assert_notnull(utf16_he, "utf16 conv");
	size_t u16_units = 0;
	while (utf16_he[u16_units]) {
		u16_units++;
	}

	RzRegex16 *re16 = rz_regex_new_16("🍍..", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re16, "regex16");
	RzIterator it;
	mu_assert_true(rz_regex_match_iter_16(re16, utf16_he, u16_units, 0, RZ_REGEX_DEFAULT, &it),
		"iter16 init");
	RzRegexMatch *m;
	size_t count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "iter16 match_idx");
		mu_assert_eq(m->group_idx, 0, "iter16 group_idx");
		if (count == 0) {
			mu_assert_eq(m->start, 17, "iter16 match 0 start");
			mu_assert_eq(m->len, 4, "iter16 match 0 len");
		} else if (count == 1) {
			mu_assert_eq(m->start, 26, "iter16 match 1 start");
			mu_assert_eq(m->len, 6, "iter16 match 1 len");
		}
		count++;
	}
	mu_assert_eq(count, 2, "iter16 count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_overlap_16(re16, utf16_he, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter16 overlap init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "iter16 overlap match_idx");
		count++;
	}
	mu_assert_eq(count, 4, "iter16 overlap count");
	rz_iterator_fini(&it);
	rz_regex_free_16(re16);
	free(utf16_he);

	ut32 *utf32_he = rz_str_utf8_to_utf32(utf8, RZ_HOST_IS_BIG_ENDIAN);
	mu_assert_notnull(utf32_he, "utf32 conv");
	size_t u32_units = 0;
	while (utf32_he[u32_units]) {
		u32_units++;
	}

	RzRegex32 *re32 = rz_regex_new_32("🍍..", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re32, "regex32");
	mu_assert_true(rz_regex_match_iter_32(re32, utf32_he, u32_units, 0, RZ_REGEX_DEFAULT, &it),
		"iter32 init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "iter32 match_idx");
		if (count == 0) {
			mu_assert_eq(m->start, 15, "iter32 match 0 start");
			mu_assert_eq(m->len, 3, "iter32 match 0 len");
		} else if (count == 1) {
			mu_assert_eq(m->start, 23, "iter32 match 1 start");
			mu_assert_eq(m->len, 3, "iter32 match 1 len");
		}
		count++;
	}
	mu_assert_eq(count, 2, "iter32 count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_overlap_32(re32, utf32_he, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter32 overlap init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "iter32 overlap match_idx");
		count++;
	}
	mu_assert_eq(count, 4, "iter32 overlap count");
	rz_iterator_fini(&it);
	rz_regex_free_32(re32);
	free(utf32_he);
	mu_end;
}

bool test_rz_regex_match_iter_multi(void) {
	const char *utf8 = "🍍🍍🍍ab";
	size_t u8_bytes = strlen(utf8);
	ut16 *utf16_he = rz_str_utf8_to_utf16(utf8, RZ_HOST_IS_BIG_ENDIAN);
	ut32 *utf32_he = rz_str_utf8_to_utf32(utf8, RZ_HOST_IS_BIG_ENDIAN);
	mu_assert_notnull(utf16_he, "utf16 multi");
	mu_assert_notnull(utf32_he, "utf32 multi");

	size_t u16_units = 0;
	while (utf16_he[u16_units]) {
		u16_units++;
	}
	size_t u32_units = 0;
	while (utf32_he[u32_units]) {
		u32_units++;
	}

	RzRegexMulti *re8 = rz_regex_new_multi("🍍..", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF8);
	RzRegexMulti *re16 = rz_regex_new_multi("🍍..", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF16);
	RzRegexMulti *re32 = rz_regex_new_multi("🍍..", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF32);
	mu_assert_notnull(re8, "re8 multi");
	mu_assert_notnull(re16, "re16 multi");
	mu_assert_notnull(re32, "re32 multi");

	RzIterator it;
	RzRegexMatch *m;
	size_t count = 0;

	mu_assert_true(rz_regex_match_iter_multi(re8, (const ut8 *)utf8, u8_bytes, 0,
			       RZ_REGEX_DEFAULT, &it),
		"multi utf8");
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "multi utf8 match_idx");
		mu_assert_eq(m->start, 0, "multi utf8 start");
		mu_assert_eq(m->len, 12, "multi utf8 len");
		count++;
	}
	mu_assert_eq(count, 1, "multi utf8 non-overlap count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_overlap_multi(re8, (const ut8 *)utf8,
			       RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT, &it),
		"multi utf8 overlap");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "multi utf8 overlap idx");
		count++;
	}
	mu_assert_eq(count, 3, "multi utf8 overlap count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_overlap_multi(re16, (const ut8 *)utf16_he,
			       u16_units * RZ_UTF16_CODE_POINT_WIDTH, 0, RZ_REGEX_DEFAULT, &it),
		"multi utf16 overlap");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "multi utf16 overlap idx");
		count++;
	}
	mu_assert_eq(count, 3, "multi utf16 overlap count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_multi(re16, (const ut8 *)utf16_he,
			       RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT, &it),
		"multi utf16 zero-terminated");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "multi utf16 zt idx");
		mu_assert_eq(m->start, 0, "multi utf16 zt start");
		mu_assert_eq(m->len, 6, "multi utf16 zt len");
		count++;
	}
	mu_assert_eq(count, 1, "multi utf16 zt count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_multi(re32, (const ut8 *)utf32_he,
			       u32_units * RZ_UTF32_CODE_POINT_WIDTH,
			       RZ_UTF32_CODE_POINT_WIDTH, RZ_REGEX_DEFAULT, &it),
		"multi utf32 with offset");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "multi utf32 idx");
		mu_assert_eq(m->start, 1, "multi utf32 offset start");
		mu_assert_eq(m->len, 3, "multi utf32 len");
		count++;
	}
	mu_assert_eq(count, 1, "multi utf32 count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_overlap_multi(re32, (const ut8 *)utf32_he,
			       RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT, &it),
		"multi utf32 zero-terminated overlap");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, count, "multi utf32 zt overlap idx");
		mu_assert_eq(m->start, count, "multi utf32 zt overlap start");
		mu_assert_eq(m->len, 3, "multi utf32 zt overlap len");
		count++;
	}
	mu_assert_eq(count, 3, "multi utf32 zt overlap count");
	rz_iterator_fini(&it);

	rz_regex_free_multi(re8);
	rz_regex_free_multi(re16);
	rz_regex_free_multi(re32);
	free(utf16_he);
	free(utf32_he);
	mu_end;
}

bool test_rz_regex_match_all_multi(void) {
	const char *utf8 = "🍍🍍🍍ab";
	size_t u8_bytes = strlen(utf8);
	ut16 *utf16_he = rz_str_utf8_to_utf16(utf8, RZ_HOST_IS_BIG_ENDIAN);
	ut32 *utf32_he = rz_str_utf8_to_utf32(utf8, RZ_HOST_IS_BIG_ENDIAN);
	mu_assert_notnull(utf16_he, "utf16 all_multi");
	mu_assert_notnull(utf32_he, "utf32 all_multi");

	size_t u16_units = 0;
	while (utf16_he[u16_units]) {
		u16_units++;
	}
	size_t u32_units = 0;
	while (utf32_he[u32_units]) {
		u32_units++;
	}

	RzRegexMulti *re8 = rz_regex_new_multi("🍍(..)", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF8);
	RzRegexMulti *re16 = rz_regex_new_multi("🍍(..)", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF16);
	RzRegexMulti *re32 = rz_regex_new_multi("🍍(..)", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF32);
	mu_assert_notnull(re8, "re8 all_multi");
	mu_assert_notnull(re16, "re16 all_multi");
	mu_assert_notnull(re32, "re32 all_multi");

	// Non-overlapping UTF-8 (explicit byte size)
	RzPVector *matches = rz_regex_match_all_multi(re8, (const ut8 *)utf8, u8_bytes, 0,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_multi utf8");
	mu_assert_eq(rz_pvector_len(matches), 1, "all_multi utf8 count");
	RzPVector *groups = rz_pvector_at(matches, 0);
	mu_assert_eq(rz_pvector_len(groups), 2, "all_multi utf8 groups");
	RzRegexMatch *m = rz_pvector_at(groups, 0);
	mu_assert_eq(m->match_idx, 0, "all_multi utf8 m0 match_idx");
	mu_assert_eq(m->group_idx, 0, "all_multi utf8 m0 group_idx");
	mu_assert_eq(m->start, 0, "all_multi utf8 m0 start");
	mu_assert_eq(m->len, 12, "all_multi utf8 m0 len");
	m = rz_pvector_at(groups, 1);
	mu_assert_eq(m->group_idx, 1, "all_multi utf8 g1 group_idx");
	mu_assert_eq(m->start, 4, "all_multi utf8 g1 start");
	mu_assert_eq(m->len, 8, "all_multi utf8 g1 len");
	rz_pvector_free(matches);

	// Overlapping UTF-8 (RZ_REGEX_ZERO_TERMINATED)
	matches = rz_regex_match_all_overlap_multi(re8, (const ut8 *)utf8,
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_overlap_multi utf8");
	mu_assert_eq(rz_pvector_len(matches), 3, "all_overlap_multi utf8 count");
	m = rz_pvector_at(rz_pvector_at(matches, 2), 0);
	mu_assert_eq(m->match_idx, 2, "all_overlap_multi utf8 m2 idx");
	mu_assert_eq(m->start, 8, "all_overlap_multi utf8 m2 start");
	mu_assert_eq(m->len, 6, "all_overlap_multi utf8 m2 len");
	rz_pvector_free(matches);

	// Non-overlapping UTF-16 (explicit byte size + byte offset) and RZ_REGEX_ZERO_TERMINATED
	matches = rz_regex_match_all_multi(re16, (const ut8 *)utf16_he,
		u16_units * RZ_UTF16_CODE_POINT_WIDTH, 2 * RZ_UTF16_CODE_POINT_WIDTH,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_multi utf16 offset");
	mu_assert_eq(rz_pvector_len(matches), 1, "all_multi utf16 offset count");
	m = rz_pvector_at(rz_pvector_at(matches, 0), 0);
	mu_assert_eq(m->start, 2, "all_multi utf16 offset start");
	mu_assert_eq(m->len, 5, "all_multi utf16 offset len");
	rz_pvector_free(matches);

	matches = rz_regex_match_all_multi(re16, (const ut8 *)utf16_he,
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_multi utf16 zt");
	mu_assert_eq(rz_pvector_len(matches), 1, "all_multi utf16 zt count");
	m = rz_pvector_at(rz_pvector_at(matches, 0), 0);
	mu_assert_eq(m->start, 0, "all_multi utf16 zt start");
	mu_assert_eq(m->len, 6, "all_multi utf16 zt len");
	rz_pvector_free(matches);

	// Overlapping UTF-16 (RZ_REGEX_ZERO_TERMINATED)
	matches = rz_regex_match_all_overlap_multi(re16, (const ut8 *)utf16_he,
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_overlap_multi utf16 zt");
	mu_assert_eq(rz_pvector_len(matches), 3, "all_overlap_multi utf16 zt count");
	m = rz_pvector_at(rz_pvector_at(matches, 1), 0);
	mu_assert_eq(m->match_idx, 1, "all_overlap_multi utf16 m1 idx");
	mu_assert_eq(m->start, 2, "all_overlap_multi utf16 m1 start");
	mu_assert_eq(m->len, 5, "all_overlap_multi utf16 m1 len");
	rz_pvector_free(matches);

	// Non-overlapping UTF-32 (explicit byte size + byte offset) and RZ_REGEX_ZERO_TERMINATED
	matches = rz_regex_match_all_multi(re32, (const ut8 *)utf32_he,
		u32_units * RZ_UTF32_CODE_POINT_WIDTH, RZ_UTF32_CODE_POINT_WIDTH,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_multi utf32 offset");
	mu_assert_eq(rz_pvector_len(matches), 1, "all_multi utf32 offset count");
	m = rz_pvector_at(rz_pvector_at(matches, 0), 0);
	mu_assert_eq(m->start, 1, "all_multi utf32 offset start");
	mu_assert_eq(m->len, 3, "all_multi utf32 offset len");
	rz_pvector_free(matches);

	matches = rz_regex_match_all_multi(re32, (const ut8 *)utf32_he,
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_multi utf32 zt");
	mu_assert_eq(rz_pvector_len(matches), 1, "all_multi utf32 zt count");
	m = rz_pvector_at(rz_pvector_at(matches, 0), 0);
	mu_assert_eq(m->start, 0, "all_multi utf32 zt start");
	mu_assert_eq(m->len, 3, "all_multi utf32 zt len");
	rz_pvector_free(matches);

	// Overlapping UTF-32 (RZ_REGEX_ZERO_TERMINATED)
	matches = rz_regex_match_all_overlap_multi(re32, (const ut8 *)utf32_he,
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(matches, "all_overlap_multi utf32 zt");
	mu_assert_eq(rz_pvector_len(matches), 3, "all_overlap_multi utf32 zt count");
	m = rz_pvector_at(rz_pvector_at(matches, 2), 0);
	mu_assert_eq(m->match_idx, 2, "all_overlap_multi utf32 m2 idx");
	mu_assert_eq(m->start, 2, "all_overlap_multi utf32 m2 start");
	mu_assert_eq(m->len, 3, "all_overlap_multi utf32 m2 len");
	rz_pvector_free(matches);

	rz_regex_free_multi(re8);
	rz_regex_free_multi(re16);
	rz_regex_free_multi(re32);
	free(utf16_he);
	free(utf32_he);
	mu_end;
}

bool test_rz_regex_match_iter_zero_len_and_edge_cases(void) {
	// Zero-length pattern "a*" must terminate cleanly on "ab", "", and "b".
	RzRegex *re_astar = rz_regex_new("a*", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_astar, "regex a*");

	RzIterator it;
	mu_assert_true(rz_regex_match_iter(re_astar, "ab", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter a* ab");
	RzRegexMatch *m;
	size_t count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->start, 0, "a* start");
		mu_assert_eq(m->len, 1, "a* len");
		count++;
	}
	mu_assert_eq(count, 1, "a* on ab count");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter(re_astar, "", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter a* empty");
	count = 0;
	rz_iterator_foreach(&it, m) {
		count++;
	}
	mu_assert_eq(count, 0, "a* on empty count");
	rz_iterator_fini(&it);

	RzPVector *all_empty = rz_regex_match_all_not_grouped(re_astar, "ab",
		RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(all_empty, "not_grouped a*");
	mu_assert_eq(rz_pvector_len(all_empty), 1, "not_grouped a* on ab count");
	rz_pvector_free(all_empty);
	rz_regex_free(re_astar);

	// Zero-length recheck hitting a non-empty alternative ("a*|b" on "ab").
	RzRegex *re_alt = rz_regex_new("a*|b", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_alt, "regex a*|b");
	RzPVector *all_alt = rz_regex_match_all(re_alt, "ab", RZ_REGEX_ZERO_TERMINATED, 0,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(all_alt, "match_all a*|b");
	mu_assert_eq(rz_pvector_len(all_alt), 2, "match_all a*|b count");
	RzRegexMatch *m0 = rz_pvector_at(rz_pvector_at(all_alt, 0), 0);
	RzRegexMatch *m1 = rz_pvector_at(rz_pvector_at(all_alt, 1), 0);
	mu_assert_eq(m0->start, 0, "a*|b m0 start");
	mu_assert_eq(m0->len, 1, "a*|b m0 len");
	mu_assert_eq(m1->match_idx, 1, "a*|b m1 match_idx");
	mu_assert_eq(m1->start, 1, "a*|b m1 start");
	mu_assert_eq(m1->len, 1, "a*|b m1 len");
	rz_pvector_free(all_alt);
	rz_regex_free(re_alt);

	// UTF-16 & UTF-32 zero-len recheck regression test (was double-free/leak).
	ut16 u16_ab[] = { 'a', 'b', 0 };
	RzRegex16 *re16_alt = rz_regex_new_16("a*|b", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re16_alt, "regex16 a*|b");
	RzPVector *all16 = rz_regex_match_all_16(re16_alt, u16_ab, 2, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(all16, "all16 a*|b");
	mu_assert_eq(rz_pvector_len(all16), 2, "all16 a*|b count");
	rz_pvector_free(all16);
	rz_regex_free_16(re16_alt);

	ut32 u32_ab[] = { 'a', 'b', 0 };
	RzRegex32 *re32_alt = rz_regex_new_32("a*|b", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re32_alt, "regex32 a*|b");
	RzPVector *all32 = rz_regex_match_all_32(re32_alt, u32_ab, 2, 0, RZ_REGEX_DEFAULT);
	mu_assert_notnull(all32, "all32 a*|b");
	mu_assert_eq(rz_pvector_len(all32), 2, "all32 a*|b count");
	rz_pvector_free(all32);
	rz_regex_free_32(re32_alt);

	// \K producing a zero-length match during recheck must not be yielded inconsistently.
	RzRegex *re_bsk = rz_regex_new("a\\K", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_bsk, "regex a\\K");
	mu_assert_true(rz_regex_match_iter(re_bsk, "aaa", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter a\\K init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		count++;
	}
	mu_assert_eq(count, 0, "a\\K on aaa yields no zero-len matches");
	rz_iterator_fini(&it);
	rz_regex_free(re_bsk);

	RzRegex *re_bsk_alt = rz_regex_new("aa\\K|ab", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_bsk_alt, "regex aa\\K|ab");
	mu_assert_true(rz_regex_match_iter(re_bsk_alt, "aaaab", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter aa\\K|ab init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->start, 3, "aa\\K|ab start");
		mu_assert_eq(m->len, 2, "aa\\K|ab len");
		count++;
	}
	mu_assert_eq(count, 1, "aa\\K|ab count");
	rz_iterator_fini(&it);
	rz_regex_free(re_bsk_alt);

	// Optional unmatched capturing group: "(a)(b)?(c)" on "ac".
	RzRegex *re_opt = rz_regex_new("(a)(b)?(c)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re_opt, "regex optional group");
	mu_assert_true(rz_regex_match_iter(re_opt, "ac", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter opt init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->match_idx, 0, "opt match_idx");
		mu_assert_eq(m->group_idx, count, "opt group_idx");
		if (count == 2) {
			mu_assert_eq(m->start, RZ_REGEX_UNSET, "unmatched group unset");
			mu_assert_eq(m->len, 0, "unmatched group len 0");
		}
		count++;
	}
	mu_assert_eq(count, 4, "opt group count");
	rz_iterator_fini(&it);
	rz_regex_free(re_opt);

	// Early loop break + no-match + past-end offset.
	RzRegex *re_txt = rz_regex_new("(Te(x)t)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_true(rz_regex_match_iter(re_txt, "TextTextText", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"early break init");
	count = 0;
	rz_iterator_foreach(&it, m) {
		count++;
		break;
	}
	mu_assert_eq(count, 1, "early break yielded 1");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter(re_txt, "nomatch", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"no match init");
	mu_assert_null(rz_iterator_next(&it), "no match yields NULL");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter(re_txt, "Text", 4, 10, RZ_REGEX_DEFAULT, &it),
		"offset past end init");
	mu_assert_null(rz_iterator_next(&it), "offset past end yields NULL");
	mu_assert_null(rz_iterator_next(&it), "second next after exhaustion yields NULL");
	rz_iterator_fini(&it);

	rz_regex_free(re_txt);
	mu_end;
}

bool test_rz_regex_match_first_utf16_and_utf32(void) {
	const char *utf8 = "ab 🍍(42) cd";
	ut16 *utf16_he = rz_str_utf8_to_utf16(utf8, RZ_HOST_IS_BIG_ENDIAN);
	ut32 *utf32_he = rz_str_utf8_to_utf32(utf8, RZ_HOST_IS_BIG_ENDIAN);
	mu_assert_notnull(utf16_he, "utf16 conv");
	mu_assert_notnull(utf32_he, "utf32 conv");

	RzRegex16 *re16 = rz_regex_new_16("🍍\\((\\d+)\\)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re16, "regex16");
	RzPVector *m16 = rz_regex_match_first_16(re16, utf16_he, RZ_REGEX_ZERO_TERMINATED, 0,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(m16, "match_first_16");
	mu_assert_eq(rz_pvector_len(m16), 2, "match_first_16 group count");
	RzRegexMatch *g0 = rz_pvector_at(m16, 0);
	RzRegexMatch *g1 = rz_pvector_at(m16, 1);
	mu_assert_eq(g0->match_idx, 0, "m16 g0 match_idx");
	mu_assert_eq(g0->group_idx, 0, "m16 g0 group_idx");
	mu_assert_eq(g0->start, 3, "m16 g0 start");
	mu_assert_eq(g0->len, 6, "m16 g0 len");
	mu_assert_eq(g1->match_idx, 0, "m16 g1 match_idx");
	mu_assert_eq(g1->group_idx, 1, "m16 g1 group_idx");
	mu_assert_eq(g1->start, 6, "m16 g1 start");
	mu_assert_eq(g1->len, 2, "m16 g1 len");
	rz_pvector_free(m16);

	mu_assert_null(rz_regex_match_first_16(re16, utf16_he, RZ_REGEX_ZERO_TERMINATED, 5,
			       RZ_REGEX_DEFAULT),
		"match_first_16 past match returns NULL");
	rz_regex_free_16(re16);

	RzRegex32 *re32 = rz_regex_new_32("🍍\\((\\d+)\\)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re32, "regex32");
	RzPVector *m32 = rz_regex_match_first_32(re32, utf32_he, RZ_REGEX_ZERO_TERMINATED, 0,
		RZ_REGEX_DEFAULT);
	mu_assert_notnull(m32, "match_first_32");
	mu_assert_eq(rz_pvector_len(m32), 2, "match_first_32 group count");
	g0 = rz_pvector_at(m32, 0);
	g1 = rz_pvector_at(m32, 1);
	mu_assert_eq(g0->match_idx, 0, "m32 g0 match_idx");
	mu_assert_eq(g0->group_idx, 0, "m32 g0 group_idx");
	mu_assert_eq(g0->start, 3, "m32 g0 start");
	mu_assert_eq(g0->len, 5, "m32 g0 len");
	mu_assert_eq(g1->match_idx, 0, "m32 g1 match_idx");
	mu_assert_eq(g1->group_idx, 1, "m32 g1 group_idx");
	mu_assert_eq(g1->start, 5, "m32 g1 start");
	mu_assert_eq(g1->len, 2, "m32 g1 len");
	rz_pvector_free(m32);

	mu_assert_null(rz_regex_match_first_32(re32, utf32_he, RZ_REGEX_ZERO_TERMINATED, 5,
			       RZ_REGEX_DEFAULT),
		"match_first_32 past match returns NULL");
	rz_regex_free_32(re32);

	free(utf16_he);
	free(utf32_he);
	mu_end;
}

bool test_rz_regex_match_iter_errors_and_invalid_multi(void) {
	RzIterator it;

	// Partial match error (PCRE2_ERROR_PARTIAL < 0) on initial match step.
	RzRegex *re_abc = rz_regex_new("abc", RZ_REGEX_EXTENDED, RZ_REGEX_JIT_PARTIAL_HARD, NULL);
	mu_assert_notnull(re_abc, "regex abc");
	mu_assert_true(rz_regex_match_iter(re_abc, "ab", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_PARTIAL_HARD, &it),
		"iter partial init");
	mu_assert_null(rz_iterator_next(&it), "partial match error stops iteration");
	mu_assert_null(rz_iterator_next(&it), "exhausted after error");
	rz_iterator_fini(&it);

	// Invalid match flag triggers PCRE2_ERROR_BADOPTION (< 0) cleanly.
	mu_assert_true(rz_regex_match_iter(re_abc, "abc", RZ_REGEX_ZERO_TERMINATED, 0,
			       0xFFFFFFFFu, &it),
		"iter bad mflags init");
	mu_assert_null(rz_iterator_next(&it), "invalid mflags stops iteration");
	rz_iterator_fini(&it);
	rz_regex_free(re_abc);

	// Zero-length recheck hitting PCRE2_ERROR_PARTIAL (< 0): "a*" matches empty at 0 on "b",
	// then NOTEMPTY_ATSTART recheck hits partial match on "bc".
	RzRegex *re_recheck_err = rz_regex_new("a*|bc", RZ_REGEX_EXTENDED,
		RZ_REGEX_JIT_PARTIAL_HARD, NULL);
	mu_assert_notnull(re_recheck_err, "regex a*|bc");
	mu_assert_true(rz_regex_match_iter(re_recheck_err, "b", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_PARTIAL_HARD, &it),
		"iter recheck partial init");
	mu_assert_null(rz_iterator_next(&it), "recheck partial error stops iteration");
	rz_iterator_fini(&it);
	rz_regex_free(re_recheck_err);

	// Recursive \K inside lookahead returns PCRE2_ERROR_BAD_BACKSLASH_K (< 0) at runtime.
	RzRegex *re_rec_bsk = rz_regex_new("(?(DEFINE)(a\\K))(?=(?1))", RZ_REGEX_DEFAULT, 0, NULL);
	mu_assert_notnull(re_rec_bsk, "regex recursive \\K");
	mu_assert_true(rz_regex_match_iter(re_rec_bsk, "a", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter recursive \\K init");
	mu_assert_null(rz_iterator_next(&it), "recursive \\K in lookahead fails cleanly");
	rz_iterator_fini(&it);
	rz_regex_free(re_rec_bsk);

	// Invalid RzRegexMulti encoding type fails cleanly for iter and match_all APIs.
	RzRegexMulti bad_multi = { .re_type = (RzRegexType)99 };
	mu_assert_false(rz_regex_match_iter_multi(&bad_multi, (const ut8 *)"abc", 3, 0,
				RZ_REGEX_DEFAULT, &it),
		"invalid multi iter");
	mu_assert_true(rz_iterator_is_uninit(&it), "invalid multi leaves iterator uninit");
	mu_assert_false(rz_regex_match_iter_overlap_multi(&bad_multi, (const ut8 *)"abc", 3, 0,
				RZ_REGEX_DEFAULT, &it),
		"invalid multi iter overlap");
	mu_assert_null(rz_regex_match_all_multi(&bad_multi, (const ut8 *)"abc", 3, 0,
			       RZ_REGEX_DEFAULT),
		"invalid multi match_all");
	mu_assert_null(rz_regex_match_all_overlap_multi(&bad_multi, (const ut8 *)"abc", 3, 0,
			       RZ_REGEX_DEFAULT),
		"invalid multi match_all_overlap");

	// NULL free safety for multi regex helpers.
	rz_regex_free_multi(NULL);
	rz_regex_free_multi_clone(NULL);
	mu_end;
}

bool test_rz_regex_match_iter_multibyte_zero_width_and_unaligned(void) {
	RzIterator it;
	RzRegexMatch *m;
	size_t count;

	// Zero-width alternation advancing over 4-byte UTF-8 and 2-unit UTF-16 surrogate pairs.
	const char *mb_utf8 = "🍍b";
	RzRegex *re8 = rz_regex_new("a*|b", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re8, "re8 a*|b");
	mu_assert_true(rz_regex_match_iter(re8, mb_utf8, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter utf8 zero-width over 4-byte char");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->start, 4, "utf8 match after 4-byte emoji");
		mu_assert_eq(m->len, 1, "utf8 match len");
		count++;
	}
	mu_assert_eq(count, 1, "utf8 multibyte zero-width count");
	rz_iterator_fini(&it);

	// Zero-width anchors (^, $, (?=b)) and CRLF multiline input.
	RzRegex *re_crlf = rz_regex_new("^|a*|b", RZ_REGEX_MULTILINE, 0, NULL);
	mu_assert_notnull(re_crlf, "re crlf");
	mu_assert_true(rz_regex_match_iter(re_crlf, "a\r\nb\r\n", RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter crlf");
	count = 0;
	rz_iterator_foreach(&it, m) {
		if (count == 0) {
			mu_assert_eq(m->start, 0, "crlf m0 start");
			mu_assert_eq(m->len, 1, "crlf m0 len");
		} else if (count == 1) {
			mu_assert_eq(m->start, 3, "crlf m1 start");
			mu_assert_eq(m->len, 1, "crlf m1 len");
		}
		count++;
	}
	mu_assert_eq(count, 2, "crlf zero-width count");
	rz_iterator_fini(&it);
	rz_regex_free(re_crlf);
	rz_regex_free(re8);

	// UTF-16 surrogate pair zero-width advance + empty UTF-16/UTF-32 inputs.
	ut16 *mb_u16 = rz_str_utf8_to_utf16(mb_utf8, RZ_HOST_IS_BIG_ENDIAN);
	ut32 *mb_u32 = rz_str_utf8_to_utf32(mb_utf8, RZ_HOST_IS_BIG_ENDIAN);
	mu_assert_notnull(mb_u16, "mb_u16");
	mu_assert_notnull(mb_u32, "mb_u32");

	RzRegex16 *re16 = rz_regex_new_16("a*|(b)(c)?", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re16, "re16");
	mu_assert_true(rz_regex_match_iter_16(re16, mb_u16, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter16 surrogate zero-width");
	count = 0;
	rz_iterator_foreach(&it, m) {
		if (count == 0) {
			mu_assert_eq(m->start, 2, "u16 m0 start after surrogate");
			mu_assert_eq(m->len, 1, "u16 m0 len");
		} else if (count == 1) {
			mu_assert_eq(m->group_idx, 1, "u16 g1 idx");
			mu_assert_eq(m->start, 2, "u16 g1 start");
			mu_assert_eq(m->len, 1, "u16 g1 len");
		}
		count++;
	}
	mu_assert_eq(count, 2, "u16 surrogate count");
	rz_iterator_fini(&it);

	ut16 empty16[] = { 0 };
	mu_assert_true(rz_regex_match_iter_16(re16, empty16, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter16 empty zt");
	mu_assert_null(rz_iterator_next(&it), "iter16 empty zt yields NULL");
	rz_iterator_fini(&it);
	rz_regex_free_16(re16);

	RzRegex32 *re32 = rz_regex_new_32("a*|(b)", RZ_REGEX_EXTENDED, 0, NULL);
	mu_assert_notnull(re32, "re32");
	mu_assert_true(rz_regex_match_iter_32(re32, mb_u32, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter32 zero-width");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->start, 1, "u32 match start");
		mu_assert_eq(m->len, 1, "u32 match len");
		count++;
	}
	mu_assert_eq(count, 2, "u32 match + group count");
	rz_iterator_fini(&it);

	ut32 empty32[] = { 0 };
	mu_assert_true(rz_regex_match_iter_32(re32, empty32, RZ_REGEX_ZERO_TERMINATED, 0,
			       RZ_REGEX_DEFAULT, &it),
		"iter32 empty zt");
	mu_assert_null(rz_iterator_next(&it), "iter32 empty zt yields NULL");
	rz_iterator_fini(&it);
	rz_regex_free_32(re32);

	// Odd/unaligned byte lengths in RzRegexMulti truncate cleanly to whole code units.
	ut16 u16_abc[] = { 'a', 'b', 'c', 0 };
	RzRegexMulti *rm16 = rz_regex_new_multi("ab", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF16);
	mu_assert_notnull(rm16, "rm16");
	// 5 bytes -> 2 UTF-16 code units ("ab"), ignoring trailing partial byte.
	mu_assert_true(rz_regex_match_iter_multi(rm16, (const ut8 *)u16_abc, 5, 0,
			       RZ_REGEX_DEFAULT, &it),
		"rm16 odd byte len");
	count = 0;
	rz_iterator_foreach(&it, m) {
		mu_assert_eq(m->start, 0, "rm16 odd start");
		mu_assert_eq(m->len, 2, "rm16 odd len");
		count++;
	}
	mu_assert_eq(count, 1, "rm16 odd count");
	rz_iterator_fini(&it);

	// 3 bytes -> 1 UTF-16 code unit ("a"): "ab" must not match.
	mu_assert_true(rz_regex_match_iter_multi(rm16, (const ut8 *)u16_abc, 3, 0,
			       RZ_REGEX_DEFAULT, &it),
		"rm16 truncated byte len");
	mu_assert_null(rz_iterator_next(&it), "rm16 truncated no match");
	rz_iterator_fini(&it);

	// Cloned RzRegexMulti with JIT enabled works through iterator API.
	RzRegexMulti *rm16_clone = rz_regex_multi_clone(rm16, true);
	mu_assert_notnull(rm16_clone, "rm16 clone");
	mu_assert_true(rz_regex_match_iter_multi(rm16_clone, (const ut8 *)u16_abc, 6, 0,
			       RZ_REGEX_DEFAULT, &it),
		"rm16 clone iter");
	m = rz_iterator_next(&it);
	mu_assert_notnull(m, "rm16 clone match");
	mu_assert_eq(m->start, 0, "rm16 clone start");
	mu_assert_eq(m->len, 2, "rm16 clone len");
	rz_iterator_fini(&it);
	rz_regex_free_multi_clone(rm16_clone);
	rz_regex_free_multi(rm16);

	ut32 u32_abc[] = { 'a', 'b', 'c', 0 };
	RzRegexMulti *rm32 = rz_regex_new_multi("ab", RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT,
		RZ_REGEX_UTF32);
	mu_assert_notnull(rm32, "rm32");
	// 10 bytes -> 2 UTF-32 code units ("ab"); 7 bytes -> 1 unit ("a", no match).
	mu_assert_true(rz_regex_match_iter_multi(rm32, (const ut8 *)u32_abc, 10, 0,
			       RZ_REGEX_DEFAULT, &it),
		"rm32 unaligned 10 bytes");
	m = rz_iterator_next(&it);
	mu_assert_notnull(m, "rm32 10 bytes matches ab");
	mu_assert_eq(m->len, 2, "rm32 10 bytes len");
	rz_iterator_fini(&it);

	mu_assert_true(rz_regex_match_iter_multi(rm32, (const ut8 *)u32_abc, 7, 0,
			       RZ_REGEX_DEFAULT, &it),
		"rm32 unaligned 7 bytes");
	mu_assert_null(rz_iterator_next(&it), "rm32 7 bytes no match");
	rz_iterator_fini(&it);
	rz_regex_free_multi(rm32);

	free(mb_u16);
	free(mb_u32);
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
	mu_run_test(test_rz_regex_match_iter_utf8_groups);
	mu_run_test(test_rz_regex_match_iter_overlap_utf8);
	mu_run_test(test_rz_regex_match_iter_utf16_and_utf32);
	mu_run_test(test_rz_regex_match_iter_multi);
	mu_run_test(test_rz_regex_match_all_multi);
	mu_run_test(test_rz_regex_match_iter_zero_len_and_edge_cases);
	mu_run_test(test_rz_regex_match_first_utf16_and_utf32);
	mu_run_test(test_rz_regex_match_iter_errors_and_invalid_multi);
	mu_run_test(test_rz_regex_match_iter_multibyte_zero_width_and_unaligned);
	return tests_passed != tests_run;
}
