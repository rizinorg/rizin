// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <math.h>
#include <rz_core.h>
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

bool test_flirt_pat_unsorted_local_offsets_sig_roundtrip(void) {
	const char *pat =
		"554889E5909090909090909090909090909090909090909090909090909090C3 00 0000 0050 "
		":0000@ first_loc :0030@ late_loc :0020 pub_mid :0020 pub_mid_alias :0040 pub_end\n"
		"---\n";
	RzBuffer *pat_buf = rz_buf_new_with_string(pat);
	mu_assert_notnull(pat_buf, "pat_buf");
	RzFlirtNode *node = rz_sign_flirt_parse_string_pattern_from_buffer(pat_buf, RZ_FLIRT_NODE_OPTIMIZE_NONE, NULL);
	mu_assert_notnull(node, "parsed pat node");

	RzFlirtNode *child = rz_list_first_val(node->child_list);
	mu_assert_notnull(child, "child node");
	RzFlirtModule *mod = rz_list_first_val(child->module_list);
	mu_assert_notnull(mod, "module");
	mu_assert_eq(rz_list_length(mod->public_functions), 5, "5 symbols parsed");

	const ut32 expected_offsets[] = { 0x00, 0x20, 0x20, 0x30, 0x40 };
	RzListIter *it;
	RzFlirtFunction *fn;
	size_t idx = 0;
	rz_list_foreach (mod->public_functions, it, fn) {
		mu_assert_eq(fn->offset, expected_offsets[idx], "pat public_functions sorted ascending");
		idx++;
	}

	/* Convert .pat -> .sig and parse back: offsets must not underflow */
	RzBuffer *sig_buf = rz_buf_new_with_bytes(NULL, 0);
	mu_assert_notnull(sig_buf, "sig_buf");
	RzFlirtCompressedOptions opts = {
		.version = 10,
		.arch = RZ_FLIRT_SIG_ARCH_386,
		.file = RZ_FLIRT_SIG_FILE_ALL,
		.os = RZ_FLIRT_SIG_OS_ALL,
		.app = RZ_FLIRT_SIG_APP_ALL,
		.deflate = false,
		.libname = "test_unsorted",
	};
	mu_assert_true(rz_sign_flirt_write_compressed_pattern_to_buffer(node, sig_buf, &opts), "write sig");
	rz_buf_seek(sig_buf, 0, RZ_BUF_SET);

	RzFlirtNode *sig_node = rz_sign_flirt_parse_compressed_pattern_from_buffer(sig_buf, RZ_FLIRT_SIG_ARCH_386, NULL);
	mu_assert_notnull(sig_node, "parsed sig node");
	RzFlirtNode *sig_child = rz_list_first_val(sig_node->child_list);
	mu_assert_notnull(sig_child, "sig child");
	RzFlirtModule *sig_mod = rz_list_first_val(sig_child->module_list);
	mu_assert_notnull(sig_mod, "sig module");
	mu_assert_eq(rz_list_length(sig_mod->public_functions), 5, "5 symbols round-tripped");
	idx = 0;
	rz_list_foreach (sig_mod->public_functions, it, fn) {
		mu_assert_eq(fn->offset, expected_offsets[idx], "sig round-trip offset preserved");
		idx++;
	}

	rz_sign_flirt_node_free(sig_node);
	rz_buf_free(sig_buf);
	rz_sign_flirt_node_free(node);
	rz_buf_free(pat_buf);
	mu_end;
}

bool test_flirt_pat_unsorted_local_apply_no_delete(void) {
	/* 0x00..0x20: prelude + ret, 0x20: pub_mid, 0x30: late_loc, 0x40: pub_end, 0x50: boundary, 0x60: outside_fcn */
	ut8 code[0x80];
	memset(code, 0x90, sizeof(code));
	code[0] = 0x55;
	code[1] = 0x48;
	code[2] = 0x89;
	code[3] = 0xe5;
	code[0x1f] = 0xc3;
	code[0x2f] = 0xc3;
	code[0x3f] = 0xc3;
	code[0x4f] = 0xc3;
	code[0x5f] = 0xc3;
	code[0x6f] = 0xc3;

	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	RzCoreFile *cf = rz_core_file_open(core, "malloc://128", RZ_PERM_RWX, 0);
	mu_assert_notnull(cf, "open malloc://128");
	rz_core_bin_load(core, "malloc://128", 0);
	rz_config_set(core->config, "asm.arch", "x86");
	rz_config_set_i(core->config, "asm.bits", 64);
	mu_assert_true(rz_io_write_at(core->io, 0, code, sizeof(code)), "write code");

	const ut64 addrs[] = { 0x00, 0x20, 0x30, 0x40, 0x50, 0x60 };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(addrs); i++) {
		char name[32];
		snprintf(name, sizeof(name), "fcn.%08" PFMT64x, addrs[i]);
		RzAnalysisFunction *f = rz_analysis_create_function(core->analysis, name, addrs[i], RZ_ANALYSIS_FCN_TYPE_FCN);
		RzAnalysisBlock *bb = rz_analysis_create_block(core->analysis, addrs[i], i == 0 ? 0x20 : 0x10);
		mu_assert_notnull(f, "create function");
		mu_assert_notnull(bb, "create block");
		rz_analysis_function_add_block(f, bb);
		rz_analysis_block_unref(bb);
	}

	/* Includes unsorted local (:0030@ before :0020) and symbol at module->length (:0050) */
	const char *pat =
		"554889E5909090909090909090909090909090909090909090909090909090C3 00 0000 0050 "
		":0000@ first_loc :0030@ late_loc :0020 pub_mid :0040 pub_end :0050 at_end\n"
		"---\n";
	char *tmp = rz_file_temp("rz_test_flirt_unsorted");
	mu_assert_notnull(tmp, "rz_file_temp");
	char *pat_path = rz_str_newf("%s.pat", tmp);
	free(tmp);
	mu_assert_notnull(pat_path, "pat_path");
	mu_assert_true(rz_file_dump(pat_path, (const ut8 *)pat, (int)strlen(pat), false), "dump pat");

	mu_assert_true(rz_sign_flirt_apply(core->analysis, pat_path, RZ_FLIRT_SIG_ARCH_386), "rz_sign_flirt_apply");
	rz_file_rm(pat_path);
	free(pat_path);

	/* Outside function at 0x60 must NOT be swallowed/deleted by ut32 underflow */
	mu_assert_notnull(rz_analysis_get_function_at(core->analysis, 0x60), "function outside module preserved");
	RzAnalysisFunction *f0 = rz_analysis_get_function_at(core->analysis, 0x00);
	RzAnalysisFunction *f2 = rz_analysis_get_function_at(core->analysis, 0x20);
	RzAnalysisFunction *f4 = rz_analysis_get_function_at(core->analysis, 0x40);
	mu_assert_notnull(f0, "first_loc exists");
	mu_assert_streq(f0->name, "flirt.first_loc", "first_loc renamed");
	mu_assert_notnull(f2, "pub_mid exists");
	mu_assert_streq(f2->name, "flirt.pub_mid", "pub_mid renamed");
	mu_assert_notnull(f4, "pub_end exists");
	mu_assert_streq(f4->name, "flirt.pub_end", "pub_end renamed");

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	test_flirt_pat_run(parse_signature);
	test_flirt_pat_run(parse_comment);
	test_flirt_pat_run(parse_trailer);
	test_flirt_pat_run(parse_large_function);
	test_flirt_pat_run(parse_large_offset);
	test_flirt_pat_run(parse_multiline);
	mu_run_test(test_flirt_pat_unsorted_local_offsets_sig_roundtrip);
	mu_run_test(test_flirt_pat_unsorted_local_apply_no_delete);
	return tests_passed != tests_run;
}

mu_main(all_tests)
