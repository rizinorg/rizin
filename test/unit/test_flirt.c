// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <math.h>
#include <rz_flirt.h>
#include <rz_util.h>
#include "minunit.h"

#define test_flirt_pat_run(name) mu_run_test(test_flirt_pat_##name)
#define test_flirt_pat_def(name, n_childs, string) \
	bool test_flirt_pat_##name(void) { \
		RzFlirtNode *node = NULL; \
		RzBuffer *buffer = rz_buf_new_with_string(string); \
		mu_assert_notnull(buffer, "buffer is not null (" #name ")"); \
		node = rz_sign_flirt_parse_string_pattern_from_buffer(buffer, RZ_FLIRT_NODE_OPTIMIZE_NONE, NULL); \
		mu_assert_notnull(node, "node is not null (" #name ")"); \
		mu_assert_eq(rz_list_length(node->child_list), n_childs, "node contains one child (" #name ")"); \
		rz_sign_flirt_node_free(node); \
		rz_buf_free(buffer); \
		mu_end; \
	}

test_flirt_pat_def(parse_signature, 1,
	"31C04885D2741F488D4417FF4839C77610EB1D0F1F4400004883E8014839C777 13 9867 0033 :0000 Curl_memrchr \n"
	"---\n");

test_flirt_pat_def(parse_comment, 0,
	"#some comment here\n"
	"---\n");

test_flirt_pat_def(parse_trailer, 1,
	"4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E 07 FAEE 003B :0000 Curl_gethostname ^000E gethostname ^0027 strchr ........4885C07403C600004489E05B5D415CC3\n"
	"---\n");

test_flirt_pat_def(parse_large_function, 1,
	"3c14a918d430e77901b6ed5ffc95ba75102562772b73fb79c65537a5765f9018 ff 3041 2989a :0000 foo\n"
	"---\n");

test_flirt_pat_def(parse_large_offset, 1,
	"3c14a918d430e77901b6ed5ffc95ba75102562772b73fb79c65537a5765f9018 ff 3041 2989a :0000 ecp_nistz256_precomputed :25100 ecp_nistz256_mul_by_2 :251a0 ecp_nistz256_div_by_2 :25280 ecp_nistz256_mul_by_3 :25380 ecp_nistz256_add :25420 ecp_nistz256_sub :254c0 ecp_nistz256_neg :25560 ecp_nistz256_ord_mul_mont :258e0 ecp_nistz256_ord_sqr_mont :26300 ecp_nistz256_to_mont :26340 ecp_nistz256_mul_mont :26640 ecp_nistz256_sqr_mont :26ce0 ecp_nistz256_from_mont :26e00 ecp_nistz256_scatter_w5 :26e60 ecp_nistz256_gather_w5 :26fc0 ecp_nistz256_scatter_w7 :27000 ecp_nistz256_gather_w7 :272a0 ecp_nistz256_avx2_gather_w7 :27580 ecp_nistz256_point_double :278c0 ecp_nistz256_point_add :28020 ecp_nistz256_point_add_affine\n"
	"---\n");

test_flirt_pat_def(parse_multiline, 5,
	"31C083FF7F77114863FF488D05........0FB6043883E008C30F1F8000000000 0D 8C27 0149 :0000 Curl_isspace :0020 Curl_isdigit :0040 Curl_isalnum :0060 Curl_isxdigit :0080 Curl_isgraph :00B0 Curl_isprint :00D0 Curl_isalpha :00F0 Curl_isupper :0110 Curl_islower :0130 Curl_iscntrl ........0FB6043883E004C30F1F800000000031C083FF7F77114863FF488D05........0FB6043883E007C30F1F800000000031C083FF7F77114863FF488D05........0FB6043883E044C30F1F800000000083FF7F771B83FF2074164863FF488D05........0FB6043883E05FC30F1F400031C0C366662E0F1F840000000000669031C083FF7F77114863FF488D05........0FB6043883E05FC30F1F800000000031C083FF7F77114863FF488D05........0FB6043883E003C30F1F800000000031C083FF7F77114863FF488D05........0FB6043883E001C30F1F800000000031C083FF7F77114863FF488D05........0FB6043883E002C30F1F800000000031C083FF7F77114863FF488D05........0FB6043883E020C3\n"
	"0FB707C366662E0F1F840000000000908B07C366662E0F1F8400000000006690 08 DB34 0028 :0000 Curl_read16_le :0010 Curl_read32_le :0020 Curl_read16_be \n"
	"41564531F641554989FD41545589F5534889D30F1F4400004889DA89EE4C89EF 01 3E9B 006C :0000 Curl_get_line ^0021 fgets ^0031 strlen ........4989C44885C074334889C7E8........4885C0740841807C04FF0A740E41BE01000000EBCE660F1F4400004584F6740B4531F6EBBE660F1F4400005B4C89E05D415C415D415EC3\n"
	"4154554889FD534889F3C60700E8........C6441DFF004189C485C07515BE2E 07 FAEE 003B :0000 Curl_gethostname ^000E gethostname ^0027 strchr ........4885C07403C600004489E05B5D415CC3\n"
	"31C04885D2741F488D4417FF4839C77610EB1D0F1F4400004883E8014839C777 13 9867 0033 :0000 Curl_memrchr \n"
	"---\n");

int all_tests() {
	test_flirt_pat_run(parse_signature);
	test_flirt_pat_run(parse_comment);
	test_flirt_pat_run(parse_trailer);
	test_flirt_pat_run(parse_large_function);
	test_flirt_pat_run(parse_large_offset);
	test_flirt_pat_run(parse_multiline);
	return tests_passed != tests_run;
}

mu_main(all_tests)
