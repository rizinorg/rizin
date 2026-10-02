// SPDX-FileCopyrightText: 2026 MrQuantum1915 <darshanpatelgdh@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_search.h>
#include "minunit.h"

bool test_pattern_new_and_getter(void) {
	// with mask
	ut8 *bytes = RZ_NEWS(ut8, 4);
	ut8 *mask = RZ_NEWS(ut8, 4);
	ut8 sbytes[] = { 0x37, 0x42, 0xa7, 0x9e };
	ut8 smask[] = { 0xef, 0xaf, 0x7d, 0xe3 };
	rz_mem_copy(bytes, 4, sbytes, 4);
	rz_mem_copy(mask, 4, smask, 4);

	RzSearchBytesPattern *pat = rz_search_bytes_pattern_new(bytes, mask, sizeof(sbytes), "3742a79e:efaf7de3", false);
	mu_assert_notnull(pat, "pattern_new with mask should succeed");
	mu_assert_eq(rz_search_bytes_pattern_len(pat), sizeof(sbytes), "length should match");
	mu_assert_streq(rz_search_bytes_pattern_desc(pat), "3742a79e:efaf7de3", "desc should match");

	const ut8 *out_bytes = NULL;
	const ut8 *out_mask = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(pat, &out_bytes, &out_mask);
	mu_assert_memeq(out_bytes, sbytes, 4, "bytes content should match");
	mu_assert_memeq(out_mask, smask, 4, "mask content should match");

	const ut8 *only_bytes = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(pat, &only_bytes, NULL);
	mu_assert_notnull(only_bytes, "only_bytes query should work");

	const ut8 *only_mask = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(pat, NULL, &only_mask);
	mu_assert_notnull(only_mask, "only_mask query should work");

	rz_search_bytes_pattern_free(pat);

	// w/o mask
	ut8 *bytes2 = RZ_NEWS(ut8, 2);
	bytes2[0] = 0x42;
	bytes2[1] = 0x37;
	RzSearchBytesPattern *pat2 = rz_search_bytes_pattern_new(bytes2, NULL, 2, NULL, false);
	mu_assert_notnull(pat2, "pattern_new without mask should succeed");
	mu_assert_null(rz_search_bytes_pattern_desc(pat2), "NULL desc should remain NULL");
	mu_assert_eq(rz_search_bytes_pattern_len(pat2), 2, "length should be 2");
	const ut8 *m = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(pat2, NULL, &m);
	mu_assert_null(m, "mask should be NULL when not provided");

	rz_search_bytes_pattern_free(pat2);
	// should not crash
	rz_search_bytes_pattern_free(NULL);

	mu_end;
}

bool test_pattern_copy(void) {
	ut8 *bytes = RZ_NEWS(ut8, 4);
	ut8 *mask = RZ_NEWS(ut8, 4);
	ut8 sbytes[] = { 0x37, 0x42, 0xa7, 0x9e };
	ut8 smask[] = { 0xef, 0xaf, 0x7d, 0xe3 };
	rz_mem_copy(bytes, 4, sbytes, 4);
	rz_mem_copy(mask, 4, smask, 4);

	RzSearchBytesPattern *pat = rz_search_bytes_pattern_new(bytes, mask, 4, "masked", false);
	RzSearchBytesPattern *cpy = rz_search_bytes_pattern_copy(pat);
	mu_assert_notnull(cpy, "copy should succeed");
	mu_assert_eq(rz_search_bytes_pattern_len(cpy), 4, "copy length should match");
	mu_assert_streq(rz_search_bytes_pattern_desc(cpy), "masked", "copy desc should match");

	const ut8 *cpy_bytes = NULL, *cpy_mask = NULL;
	const ut8 *orig_bytes = NULL, *orig_mask = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(cpy, &cpy_bytes, &cpy_mask);
	rz_search_bytes_pattern_get_bytes_and_mask(pat, &orig_bytes, &orig_mask);
	mu_assert_memeq(cpy_bytes, sbytes, 4, "copy bytes should match original");
	mu_assert_memeq(cpy_mask, smask, 4, "copy mask should match original");
	mu_assert_ptrneq(cpy_bytes, orig_bytes, "copy bytes should be a distinct allocation");
	mu_assert_ptrneq(cpy_mask, orig_mask, "copy mask should be a distinct allocation");

	// freeing orig should not affect cpy.
	rz_search_bytes_pattern_free(pat);
	mu_assert_eq(rz_search_bytes_pattern_len(cpy), 4, "copy should survive original free");
	rz_search_bytes_pattern_free(cpy);

	// w/o mask
	ut8 *bytes2 = RZ_NEWS(ut8, 2);
	bytes2[0] = 0xab;
	bytes2[1] = 0xcd;
	RzSearchBytesPattern *pat2 = rz_search_bytes_pattern_new(bytes2, NULL, 2, "nomask", false);
	RzSearchBytesPattern *cpy2 = rz_search_bytes_pattern_copy(pat2);
	const ut8 *m = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(cpy2, NULL, &m);
	mu_assert_null(m, "copy of maskless pattern should have NULL mask");
	rz_search_bytes_pattern_free(pat2);
	rz_search_bytes_pattern_free(cpy2);

	mu_end;
}

bool test_parse_byte_pattern(void) {
	RzSearchBytesPattern *p1 = rz_search_parse_byte_pattern("a987", "exact");
	mu_assert_notnull(p1, "hex should be parsed");
	mu_assert_eq(rz_search_bytes_pattern_len(p1), 2, "exact hex length");
	const ut8 ex1[] = { 0xa9, 0x87 };
	const ut8 *b = NULL, *m = NULL;
	rz_search_bytes_pattern_get_bytes_and_mask(p1, &b, &m);
	mu_assert_memeq(b, ex1, 2, "bytes should match");
	mu_assert_null(m, "should have no mask");
	rz_search_bytes_pattern_free(p1);

	// wildcard nibble
	RzSearchBytesPattern *p2 = rz_search_parse_byte_pattern("a9.7", "wc");
	mu_assert_notnull(p2, "wildcard pattern should parse");
	rz_search_bytes_pattern_get_bytes_and_mask(p2, NULL, &m);
	ut8 exp_m[] = { 0xff, 0x0f };
	mu_assert_notnull(m, "wildcard pattern needs a mask");
	mu_assert_memeq(m, exp_m, 2, "wildcard equivalent mask");
	rz_search_bytes_pattern_free(p2);

	// custom mask
	RzSearchBytesPattern *p3 = rz_search_parse_byte_pattern("a907:ff0f", "cm");
	mu_assert_notnull(p3, "custom mask should parse");
	const ut8 exp_b[] = { 0xa9, 0x07 };
	rz_search_bytes_pattern_get_bytes_and_mask(p3, &b, &m);
	mu_assert_memeq(b, exp_b, 2, "custom mask bytes");
	mu_assert_memeq(m, exp_m, 2, "custom mask values");
	rz_search_bytes_pattern_free(p3);

	// 0x prefix
	RzSearchBytesPattern *p4 = rz_search_parse_byte_pattern("0xa907:0xff0f", "0x");
	mu_assert_notnull(p4, "0x-prefixed should parse");
	rz_search_bytes_pattern_get_bytes_and_mask(p4, &b, &m);
	mu_assert_memeq(b, exp_b, 2, "0x-prefixed bytes");
	mu_assert_memeq(m, exp_m, 2, "0x-prefixed mask");
	rz_search_bytes_pattern_free(p4);

	// odd nibbles: leftpadded, generate mask
	RzSearchBytesPattern *p5 = rz_search_parse_byte_pattern("abc", "odd");
	mu_assert_notnull(p5, "odd nibble should parse");
	mu_assert_eq(rz_search_bytes_pattern_len(p5), 2, "odd nibble pads to 2 bytes");
	rz_search_bytes_pattern_get_bytes_and_mask(p5, NULL, &m);
	mu_assert_notnull(m, "odd nibble should produce mask");
	exp_m[0] = 0x0f;
	exp_m[1] = 0xff;
	mu_assert_memeq(m, exp_m, 2, "autogenerated mask for left padding");
	rz_search_bytes_pattern_free(p5);

	// NULL desc
	RzSearchBytesPattern *p6 = rz_search_parse_byte_pattern("abc42", NULL);
	mu_assert_notnull(p6, "NULL desc should parse");
	mu_assert_null(rz_search_bytes_pattern_desc(p6), "desc should be null");
	rz_search_bytes_pattern_free(p6);

	mu_end;
}

bool test_parse_byte_pattern_invalid(void) {
	mu_assert_null(rz_search_parse_byte_pattern("aa:bb:cc", "bad"), "multiple colons should fail");
	mu_assert_null(rz_search_parse_byte_pattern("zz00", "bad"), "non-hex chars should fail");
	mu_assert_null(rz_search_parse_byte_pattern("aabb:ff", "bad"), "mask length mismatch should fail");
	mu_assert_null(rz_search_parse_byte_pattern("aa:f.", "bad"), "wildcard in mask should fail");
	mu_end;
}

bool all_tests() {
	mu_run_test(test_pattern_new_and_getter);
	mu_run_test(test_pattern_copy);
	mu_run_test(test_parse_byte_pattern);
	mu_run_test(test_parse_byte_pattern_invalid);

	return tests_passed != tests_run;
}

mu_main(all_tests)