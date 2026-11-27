// SPDX-FileCopyrightText: 2026 Rizin contributors
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_egg.h>
#include "minunit.h"

#if defined(__linux__) && defined(__x86_64__)
static bool mem_contains(const char *haystack, size_t hay_len, const char *needle) {
	size_t nlen = strlen(needle);
	return hay_len >= nlen &&
		rz_mem_mem((const ut8 *)haystack, hay_len, (const ut8 *)needle, nlen) != NULL;
}
#endif

bool test_egg_filter_c_assembly_strings(void) {
	const char *input =
		"\t.file\t\"test.c\"\n"
		"\t.data\n"
		"\t.section\t.rodata.str1.1,\"aMS\",@progbits,1\n"
		".LC0:\n"
		"\t.string\t\"size is 12345678\\n\"\n"
		".LC1:\n"
		"\t.asciz\t\"userdata\\n\"\n"
		".LC2:\n"
		"\t.asciz\t\"rodata_test\\n\"\n"
		".LC3:\n"
		"\t.string\t\"zeroing\\n\"\n"
		".LC4:\n"
		"\t.ascii\t\"escaped \\\"size\\\" cfi section .cstring ___main __alloca\"\n"
		".LC5:\n"
		"\t.asciz\t\"get_pc_thunk.bx\"\n"
		"lbl: .asciz \"size zero\"\n";

	char *out = rz_egg_filter_c_assembly(input);
	mu_assert_notnull(out, "filtered assembly must not be NULL");
	const char *expected =
		"\t.file\t\"test.c\"\n"
		"\t.data\n"
		"\t.text\n"
		".LC0:\n"
		"\t.string\t\"size is 12345678\\n\"\n"
		".LC1:\n"
		"\t.asciz\t\"userdata\\n\"\n"
		".LC2:\n"
		"\t.asciz\t\"rodata_test\\n\"\n"
		".LC3:\n"
		"\t.string\t\"zeroing\\n\"\n"
		".LC4:\n"
		"\t.ascii\t\"escaped \\\"size\\\" cfi section .cstring ___main __alloca\"\n"
		".LC5:\n"
		"\t.asciz\t\"get_pc_thunk.bx\"\n"
		"lbl: .asciz \"size zero\"\n";
	mu_assert_streq(out, expected, "string literals must be preserved without corruption");
	free(out);
	mu_end;
}

bool test_egg_filter_c_assembly_directives_and_stubs(void) {
	const char *input =
		"\t.text\n"
		"\t.cstring\n"
		"\t.rdata\n"
		"\t.rodata\n"
		"\t.section\t__TEXT,__cstring,cstring_literals\n"
		"\t.section\t__TEXT,__literal8,8byte_literals\n"
		"\t.section\t__TEXT,__text,regular,pure_instructions\n"
		"\t.section\t\".foo\\\\\",__cstring\n"
		"\t.section\t.rdata,\"dr\"\n"
		"\t.section\t\".note.GNU-stack\",\"\",@progbits\n"
		"\t.globl\tmain\n"
		"\t.type\tmain, @function\n"
		"main:\n"
		"\t.cfi_startproc\n"
		"\tcall\t___main\n"
		"\tcallq\t__alloca\n"
		"\tbl\t___main\n"
		"\tcall\tmy___main\n"
		"\tcall\t__alloca_custom\n"
		"\tcall\t__x86.get_pc_thunk.bx\n"
		"\tcall\tget_pc_thunk.bx\n"
		"\tcall\tmy_get_pc_thunk.bx\n"
		"\tleaq\tsize_buf(%rip), %rsi # cfi comment get_pc_thunk.bx\n"
		".zero_label:\n"
		"zeroing:\n"
		"\t.zero\t16\n"
		"\t.cfi_endproc\n"
		"\t.size\tmain, .-main\n";

	char *out = rz_egg_filter_c_assembly(input);
	mu_assert_notnull(out, "filtered assembly must not be NULL");
	const char *expected =
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.section\t\".foo\\\\\",__cstring\n"
		"\t.text\n"
		"\t.section\t\".note.GNU-stack\",\"\",@progbits\n"
		"\t.globl\tmain\n"
		"\t.type\tmain, @function\n"
		"main:\n"
		"\tcall\tmy___main\n"
		"\tcall\t__alloca_custom\n"
		"\tcall\t__x86.__getesp__\n"
		"\tcall\t__getesp__\n"
		"\tcall\tmy_get_pc_thunk.bx\n"
		"\tleaq\tsize_buf(%rip), %rsi # cfi comment get_pc_thunk.bx\n"
		".zero_label:\n"
		"zeroing:\n";
	mu_assert_streq(out, expected, "directives, stubs, and thunks filtered accurately");
	free(out);
	mu_end;
}

bool test_egg_filter_c_assembly_thunk_comdat_and_crlf(void) {
	const char *comdat_input =
		"\t.text\n"
		"main:\n"
		"\tcall\t__x86.get_pc_thunk.bx\n"
		"\tret\n"
		"\t.section\t.text.__x86.get_pc_thunk.bx,\"axG\",@progbits,"
		"__x86.get_pc_thunk.bx,comdat\n"
		"\t.globl\t__x86.get_pc_thunk.bx\n"
		"\t.hidden\t__x86.get_pc_thunk.bx\n"
		"\t.type\t__x86.get_pc_thunk.bx, @function\n"
		"__x86.get_pc_thunk.bx:\n"
		".LFB1:\n"
		"\t.cfi_startproc\n"
		"\tmovl\t(%esp), %ebx\n"
		"\tret\n"
		"\t.cfi_endproc\n"
		".LFE1:\n"
		"get_pc_thunk.bx: .byte 0xc3\n"
		"__x86.get_pc_thunk.bx: # get_pc_thunk.bx in comment\n";

	char *comdat_out = rz_egg_filter_c_assembly(comdat_input);
	mu_assert_notnull(comdat_out, "comdat filtered assembly must not be NULL");
	const char *comdat_expected =
		"\t.text\n"
		"main:\n"
		"\tcall\t__x86.__getesp__\n"
		"\tret\n"
		"\t.text\n"
		"\t.globl\t__x86.__getesp__\n"
		"\t.hidden\t__x86.__getesp__\n"
		"\t.type\t__x86.__getesp__, @function\n"
		"__x86.__getesp__:\n"
		".LFB1:\n"
		"\tmovl\t(%esp), %ebx\n"
		"\tret\n"
		".LFE1:\n"
		"__getesp__: .byte 0xc3\n"
		"__x86.__getesp__: # get_pc_thunk.bx in comment\n";
	mu_assert_streq(comdat_out, comdat_expected,
		"COMDAT thunk definition, label prefix, and call must stay consistent");
	free(comdat_out);

	const char *crlf_input =
		"\t.rodata\r\n"
		".LC0:\r\n"
		"\t.string\t\"hello\\r\\n\"\r\n"
		"__x86.get_pc_thunk.bx:\r\n"
		"\tcall\t__x86.get_pc_thunk.bx\r\n"
		"\t.size\tmain, .-main\r\n";

	char *crlf_out = rz_egg_filter_c_assembly(crlf_input);
	mu_assert_notnull(crlf_out, "crlf filtered assembly must not be NULL");
	const char *crlf_expected =
		"\t.text\n"
		".LC0:\n"
		"\t.string\t\"hello\\r\\n\"\n"
		"__x86.__getesp__:\n"
		"\tcall\t__x86.__getesp__\n";
	mu_assert_streq(crlf_out, crlf_expected,
		"CRLF line endings must normalize cleanly without breaking directives or labels");
	free(crlf_out);
	mu_end;
}

bool test_egg_filter_c_assembly_labels_and_sections(void) {
	const char *input =
		"buf: .zero 16\n"
		"l1: l2: .size main, .-main\n"
		"__x86.get_pc_thunk.bx: .cfi_startproc\n"
		"foo: .rodata\n"
		"bar: .section .rdata$zzz\n"
		"lbl: call ___main\n"
		"lbl2: call my_func\n"
		"\tcall\t___main@PLT\n"
		"\tbl\thelper @ calls ___main\n"
		"\tcall\tfoo # ___main\n"
		"\tcall\tfoo ; ___main\n"
		"\tcall\tfoo // ___main\n"
		"\tcall\tfoo, \"a\\\"___main\"\n"
		"\t.section\n"
		"\t.section # comment\n"
		"\t.section ,.rodata\n"
		"\t.section\t__TEXT,\"__cstring\"\n"
		"\t.section\t__TEXT,__cstring#comment\n"
		"\t.section\t__TEXT,__const;comment\n"
		"\t.section\t__TEXT,__text//comment\n"
		"\t.section\t__TEXT,__literal4\n"
		"\t.section\t__TEXT,__literal16\n"
		"\t.section\t__TEXT,__literal_foo\n"
		"\t.section\t__TEXT,__literal\n"
		"\t.section\t__literal8\n"
		"\t.section\t.rdata$zzz\n"
		"\t.section\t.text$foo\n"
		"\t.section\t\".rodata\"\n"
		"\t.ident\t\"a\\\"get_pc_thunk.bx\"\n"
		"\t.ident\t\"a\\\\\" get_pc_thunk.bx\n"
		"\tnop ; get_pc_thunk.bx\n"
		"\tnop // get_pc_thunk.bx\n"
		"lbl_ws:   \n"
		"\tcall   \n"
		"foo:bar\n"
		"\t.section   \n"
		"\t.section\t__TEXT , __cstring\n"
		"\t.section\t__TEXT\n"
		"\t.section\t__TEXT foo\n"
		"\t.section\tfoo/\n"
		"\t.section\tfoo/bar\n"
		"\t.section\t\".rodata\n"
		"\t.section\t\"\n"
		"\t.section\t.rodata_extra\n"
		"\tcall\tfoo/\n"
		"\tcall\tfoo/bar\n"
		"\tcall\t*___main\n"
		"\tnop\t/\n"
		"\tnop\ta/b\n"
		"\tcall\taget_pc_thunk.bx\n"
		"\tcall\tget_pc_thunk.bx2\n"
		"/\n"
		"/foo\n"
		"lbl_slash: /\n"
		"lbl_slash2: /foo\n"
		"\t.a\n"
		"\t.a,1\n"
		"\t.a#c\n"
		"\t.a;c\n";

	char *out = rz_egg_filter_c_assembly(input);
	mu_assert_notnull(out, "filtered assembly must not be NULL");
	const char *expected =
		"buf:\n"
		"l1: l2:\n"
		"__x86.__getesp__:\n"
		"foo:\n"
		"\t.text\n"
		"bar:\n"
		"\t.text\n"
		"lbl:\n"
		"lbl2: call my_func\n"
		"\tbl\thelper @ calls ___main\n"
		"\tcall\tfoo # ___main\n"
		"\tcall\tfoo ; ___main\n"
		"\tcall\tfoo // ___main\n"
		"\tcall\tfoo, \"a\\\"___main\"\n"
		"\t.section\n"
		"\t.section # comment\n"
		"\t.section ,.rodata\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.section\t__TEXT,__literal_foo\n"
		"\t.section\t__TEXT,__literal\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.text\n"
		"\t.ident\t\"a\\\"get_pc_thunk.bx\"\n"
		"\t.ident\t\"a\\\\\" __getesp__\n"
		"\tnop ; get_pc_thunk.bx\n"
		"\tnop // get_pc_thunk.bx\n"
		"lbl_ws:   \n"
		"\tcall   \n"
		"foo:bar\n"
		"\t.section   \n"
		"\t.text\n"
		"\t.section\t__TEXT\n"
		"\t.section\t__TEXT foo\n"
		"\t.section\tfoo/\n"
		"\t.section\tfoo/bar\n"
		"\t.section\t\".rodata\n"
		"\t.section\t\"\n"
		"\t.section\t.rodata_extra\n"
		"\tcall\tfoo/\n"
		"\tcall\tfoo/bar\n"
		"\tnop\t/\n"
		"\tnop\ta/b\n"
		"\tcall\taget_pc_thunk.bx\n"
		"\tcall\tget_pc_thunk.bx2\n"
		"/\n"
		"/foo\n"
		"lbl_slash: /\n"
		"lbl_slash2: /foo\n"
		"\t.a\n"
		"\t.a,1\n"
		"\t.a#c\n"
		"\t.a;c\n";
	mu_assert_streq(out, expected,
		"label-prefixed directives/stubs, sections, comments, and escapes must filter accurately");
	free(out);
	mu_end;
}

bool test_egg_filter_c_assembly_edge_lines(void) {
	char *empty_out = rz_egg_filter_c_assembly("");
	mu_assert_notnull(empty_out, "empty input must not return NULL");
	mu_assert_streq(empty_out, "", "empty input must stay empty");
	free(empty_out);

	const char *blanks_and_comments =
		"\n"
		"   \n"
		"\t\n"
		"# hash get_pc_thunk.bx\n"
		"; semi .zero 4\n"
		"@ arm call ___main\n"
		"// slash .rodata\n"
		"lbl_s: ; .zero 4\n"
		"lbl_a: @ call ___main\n"
		"lbl_c: // .rodata\n";
	char *bc_out = rz_egg_filter_c_assembly(blanks_and_comments);
	mu_assert_notnull(bc_out, "blanks and comments output must not be NULL");
	mu_assert_streq(bc_out, blanks_and_comments, "blank and comment-only lines must be preserved verbatim");
	free(bc_out);

	const char *cases[][2] = {
		{ "\t.rodata", "\t.text" },
		{ "buf: .zero 16", "buf:" },
		{ "foo: .rodata", "foo:\n\t.text" },
		{ "lbl: call ___main", "lbl:" },
		{ "\tcall\t__x86.get_pc_thunk.bx", "\tcall\t__x86.__getesp__" },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		char *no_nl_out = rz_egg_filter_c_assembly(cases[i][0]);
		mu_assert_notnull(no_nl_out, "no-trailing-newline output must not be NULL");
		mu_assert_streq(no_nl_out, cases[i][1], "input without trailing newline must filter cleanly");
		free(no_nl_out);
	}
	mu_end;
}

bool test_egg_compile_c_source_strings(void) {
#if defined(__linux__) && defined(__x86_64__)
	const char *rel_sflib = "../librz/include/sflib/linux-x86-64/sflib.h";
	if (!rz_file_exists(rel_sflib)) {
		mu_end;
	}
	char *abs_sflib = rz_file_abspath(rel_sflib);
	mu_assert_notnull(abs_sflib, "abspath sflib");

	char *prev_sflib = rz_sys_getenv("SFLIBPATH");
	rz_sys_setenv("SFLIBPATH", abs_sflib);

	char *tmp_base = rz_file_temp("egg_test");
	mu_assert_notnull(tmp_base, "temp base path");
	char *tmp_c = rz_str_newf("%s.c", tmp_base);
	mu_assert_notnull(tmp_c, "temp c path");
	const char *src =
		"int main() {\n"
		"  write(1, \"size is 12345678\\n\", 17);\n"
		"  write(1, \"userdata\\n\", 9);\n"
		"  write(1, \"zeroing\\n\", 8);\n"
		"  return 0;\n"
		"}\n";
	mu_assert_true(rz_file_dump(tmp_c, (const ut8 *)src, strlen(src), false), "write temp c");

	RzPath *sys_path = rz_path_new();
	mu_assert_notnull(sys_path, "sys_path");
	char *text_file = rz_egg_compile_c_source(tmp_c, "x86", "linux", 64, sys_path);
	rz_path_free(sys_path);

	rz_sys_setenv("SFLIBPATH", prev_sflib);
	free(prev_sflib);
	rz_file_rm(tmp_c);
	rz_file_rm(tmp_base);
	free(tmp_c);
	free(tmp_base);
	free(abs_sflib);

	mu_assert_notnull(text_file, "rz_egg_compile_c_source output");
	size_t out_len = 0;
	char *bin = rz_file_slurp(text_file, &out_len);
	rz_file_rm(text_file);
	free(text_file);

	mu_assert_notnull(bin, "slurp compiled text binary");
	mu_assert_true(out_len > 0, "compiled text must be non-empty");
	mu_assert_true(mem_contains(bin, out_len, "size is 12345678"), "preserve size string");
	mu_assert_true(mem_contains(bin, out_len, "userdata"), "preserve userdata string");
	mu_assert_true(mem_contains(bin, out_len, "zeroing"), "preserve zeroing string");
	mu_assert_false(mem_contains(bin, out_len, "usetext"), "no rdata/text string corruption");
	free(bin);

	// Compiler succeeding without producing assembly hits missing-tmp error path.
	char *true_exe = rz_file_path("true");
	if (true_exe && !RZ_STR_EQ(true_exe, "true")) {
		char *prev_cc = rz_sys_getenv("CC");
		rz_sys_setenv("CC", true_exe);
		char *fail_base = rz_file_temp("egg_fail");
		mu_assert_notnull(fail_base, "temp fail base path");
		char *fail_c = rz_str_newf("%s.c", fail_base);
		mu_assert_notnull(fail_c, "temp fail c path");
		mu_assert_true(rz_file_dump(fail_c, (const ut8 *)"int main(){return 0;}\n", 22, false), "write fail c");
		RzPath *fail_path = rz_path_new();
		mu_assert_notnull(fail_path, "fail sys_path");
		char *fail_out = rz_egg_compile_c_source(fail_c, "x86", "linux", 64, fail_path);
		mu_assert_null(fail_out, "missing compiler output must fail cleanly");
		rz_path_free(fail_path);
		rz_sys_setenv("CC", prev_cc);
		free(prev_cc);
		rz_file_rm(fail_c);
		rz_file_rm(fail_base);
		free(fail_c);
		free(fail_base);
	}
	free(true_exe);
#endif
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_egg_filter_c_assembly_strings);
	mu_run_test(test_egg_filter_c_assembly_directives_and_stubs);
	mu_run_test(test_egg_filter_c_assembly_thunk_comdat_and_crlf);
	mu_run_test(test_egg_filter_c_assembly_labels_and_sections);
	mu_run_test(test_egg_filter_c_assembly_edge_lines);
	mu_run_test(test_egg_compile_c_source_strings);
	return tests_passed != tests_run;
}

mu_main(all_tests)
