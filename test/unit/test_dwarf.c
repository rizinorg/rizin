// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_bin_dwarf.h>

#define check_abbrev_code(expected_code) \
	mu_assert_eq(da->decls[i].code, expected_code, "Wrong abbrev code");

#define check_abbrev_tag(expected_tag) \
	mu_assert_eq(da->decls[i].tag, expected_tag, "Incorrect abbreviation tag")

#define check_abbrev_count(expected_count) \
	mu_assert_eq(da->decls[i].count, expected_count, "Incorrect abbreviation count")

#define check_abbrev_children(expected_children) \
	mu_assert_eq(da->decls[i].has_children, expected_children, "Incorrect children flag")

#define check_abbrev_attr_name(expected_name) \
	mu_assert_eq(da->decls[i].defs[j].attr_name, expected_name, "Incorrect children flag");

#define check_abbrev_attr_form(expected_form) \
	mu_assert_eq(da->decls[i].defs[j].attr_form, expected_form, "Incorrect children flag");

static bool check_line_samples_eq(const RzBinSourceLineInfo *actual,
	size_t samples_count_expect, const RzBinSourceLineSample *samples_expect) {
	mu_assert_eq(actual->samples_count, samples_count_expect, "samples count");
	if (samples_expect) {
		mu_assert_notnull(actual->samples, "samples");
		for (size_t i = 0; i < samples_count_expect; i++) {
			mu_assert_eq(actual->samples[i].address, samples_expect[i].address, "sample addr");
			mu_assert_eq(actual->samples[i].line, samples_expect[i].line, "sample line");
			mu_assert_eq(actual->samples[i].column, samples_expect[i].column, "sample column");
			if (samples_expect[i].file) {
				mu_assert_notnull(actual->samples[i].file, "sample file");
				mu_assert_streq(actual->samples[i].file, samples_expect[i].file, "sample file");
			} else {
				mu_assert_null(actual->samples[i].file, "sample file");
			}
		}
	} else {
		mu_assert_null(actual->samples, "samples");
	}
	return true;
}

static void print_line_samples(size_t samples_count, const RzBinSourceLineSample *samples) {
	printf("{\n");
	for (size_t i = 0; i < samples_count; i++) {
		printf("\t{ 0x%" PFMT64x ", %" PFMT32u ", %" PFMT32u ", %s%s%s }%s\n",
			samples[i].address,
			samples[i].line,
			samples[i].column,
			samples[i].file ? "\"" : "",
			samples[i].file ? samples[i].file : "NULL",
			samples[i].file ? "\"" : "",
			i + 1 < samples_count ? "," : "");
	}
	printf("};\n");
}

#define assert_line_samples_eq(actual, count_expect, samples_expect) \
	do { \
		if (!check_line_samples_eq(actual, count_expect, samples_expect)) { \
			printf("---- EXPECTED:\n"); \
			print_line_samples(count_expect, samples_expect); \
			printf("---- GOT:\n"); \
			print_line_samples(actual->samples_count, actual->samples); \
			return false; \
		} \
	} while (0);

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C binary
 */
bool test_dwarf3_c_basic(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_eq(da->count, 7, "Incorrect number of abbreviation");

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	check_abbrev_tag(DW_TAG_compile_unit);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
		{
			int j = 0;
			check_abbrev_attr_name(DW_AT_producer);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_language);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_comp_dir);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_low_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_high_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_stmt_list);
			check_abbrev_attr_form(DW_FORM_data4);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_count(8);
		check_abbrev_children(false);
	}
	i++;
	check_abbrev_tag(DW_TAG_base_type);
	{
		check_abbrev_count(4);
		check_abbrev_children(false);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_count(12);
		check_abbrev_children(true);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_count(7);
		check_abbrev_children(false);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_count(10);
		check_abbrev_children(true);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_count(6);
		check_abbrev_children(false);
	}
	i++;

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x1129, 3, 1, ".//main.c" },
		{ 0x1131, 6, 1, ".//main.c" },
		{ 0x1134, 7, 12, ".//main.c" },
		{ 0x1140, 8, 2, ".//main.c" },
		{ 0x114a, 9, 6, ".//main.c" },
		{ 0x1151, 10, 9, ".//main.c" },
		{ 0x1154, 11, 1, ".//main.c" },
		{ 0x1156, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C++ binary
 * 
 * 
 * 
 * 
 */
bool test_dwarf3_cpp_basic(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_cpp.elf", &opt);
	mu_assert("couldn't open file", res);

	// this is probably ugly, but I didn't know how to
	// tell core  what bin to open so I did it myself

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert("Incorrect number of abbreviation", da->count == 32);

	// order matters
	// I nest scopes to make it more readable, (hopefully)
	int i = 0;
	check_abbrev_tag(DW_TAG_compile_unit);
	{
		check_abbrev_children(true);
		check_abbrev_count(9);
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			check_abbrev_attr_name(DW_AT_producer);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_language);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_comp_dir);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_ranges);
			check_abbrev_attr_form(DW_FORM_data4);
			j++;
			check_abbrev_attr_name(DW_AT_low_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_entry_pc);
			check_abbrev_attr_form(DW_FORM_addr);
			j++;
			check_abbrev_attr_name(DW_AT_stmt_list);
			check_abbrev_attr_form(DW_FORM_data4);

			// check_abbrev_attr_name (DW_AT value: 0);
			// check_abbrev_attr_form (DW_AT value: 0);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_structure_type);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
		{
			/**
			 *  Everything commented out is something that is missing from being printed by `id` Radare
			 */
			int j = 0;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_byte_size);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_file);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_line);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_column);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_containing_type);
			check_abbrev_attr_form(DW_FORM_ref4);
			j++;
			check_abbrev_attr_name(DW_AT_sibling);
			check_abbrev_attr_form(DW_FORM_ref4);

			// check_abbrev_attr_name (DW_AT value: 0);
			// check_abbrev_attr_form (DW_AT value: 0);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(2);
	}
	i++;
	check_abbrev_tag(DW_TAG_member);
	{
		check_abbrev_children(false);
		check_abbrev_count(5);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(10);
	}
	i++;

	// 8
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(12);
		{
			int j = 0;
			check_abbrev_attr_name(DW_AT_external);
			check_abbrev_attr_form(DW_FORM_flag);
			j++;
			check_abbrev_attr_name(DW_AT_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_decl_file);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_line);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_decl_column);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			// check_abbrev_attr_name (DW_AT_MIPS_linkage_name);
			check_abbrev_attr_form(DW_FORM_strp);
			j++;
			check_abbrev_attr_name(DW_AT_virtuality);
			check_abbrev_attr_form(DW_FORM_data1);
			j++;
			check_abbrev_attr_name(DW_AT_containing_type);
			check_abbrev_attr_form(DW_FORM_ref4);
			j++;
			check_abbrev_attr_name(DW_AT_declaration);
			check_abbrev_attr_form(DW_FORM_flag);
			j++;
			check_abbrev_attr_name(DW_AT_object_pointer);
			check_abbrev_attr_form(DW_FORM_ref4);
			j++;
			check_abbrev_attr_name(DW_AT_sibling);
			check_abbrev_attr_form(DW_FORM_ref4);
		}
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(13);
	}
	i++;
	check_abbrev_tag(DW_TAG_const_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(2);
	}
	i++;
	check_abbrev_tag(DW_TAG_pointer_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_reference_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_subroutine_type);
	{
		check_abbrev_children(true);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_unspecified_parameters);
	{
		check_abbrev_children(false);
		check_abbrev_count(1);
	}
	i++;
	check_abbrev_tag(DW_TAG_base_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(4);
	}
	i++;
	check_abbrev_tag(DW_TAG_pointer_type);
	{
		check_abbrev_children(false);
		check_abbrev_count(4);
	}
	i++;
	check_abbrev_tag(DW_TAG_structure_type);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_inheritance);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(10);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(13);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(12);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_children(false);
		check_abbrev_count(7);
	}
	i++;
	check_abbrev_tag(DW_TAG_variable);
	{
		check_abbrev_children(false);
		check_abbrev_count(7);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(5);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(5);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(4);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(9);
	}
	i++;
	check_abbrev_tag(DW_TAG_formal_parameter);
	{
		check_abbrev_children(false);
		check_abbrev_count(3);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(9);
	}
	i++;
	check_abbrev_tag(DW_TAG_subprogram);
	{
		check_abbrev_children(true);
		check_abbrev_count(8);
	}

	// rz_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// rz_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x1169, 19, 12, ".//main.cpp" },
		{ 0x1176, 22, 16, ".//main.cpp" },
		{ 0x118b, 22, 5, ".//main.cpp" },
		{ 0x118f, 23, 15, ".//main.cpp" },
		{ 0x11a4, 23, 5, ".//main.cpp" },
		{ 0x11a8, 24, 7, ".//main.cpp" },
		{ 0x11af, 25, 20, ".//main.cpp" },
		{ 0x11bd, 25, 19, ".//main.cpp" },
		{ 0x11c6, 25, 10, ".//main.cpp" },
		{ 0x11c9, 26, 21, ".//main.cpp" },
		{ 0x11d7, 26, 20, ".//main.cpp" },
		{ 0x11e0, 26, 10, ".//main.cpp" },
		{ 0x11e3, 27, 10, ".//main.cpp" },
		{ 0x11e6, 28, 1, ".//main.cpp" },
		{ 0x11ed, 0, 0, NULL },
		{ 0x11ee, 2, 3, ".//main.cpp" },
		{ 0x11fa, 2, 12, ".//main.cpp" },
		{ 0x1208, 2, 15, ".//main.cpp" },
		{ 0x120b, 0, 0, NULL },
		{ 0x120c, 3, 11, ".//main.cpp" },
		{ 0x1218, 3, 21, ".//main.cpp" },
		{ 0x1226, 3, 22, ".//main.cpp" },
		{ 0x1229, 0, 0, NULL },
		{ 0x122a, 3, 11, ".//main.cpp" },
		{ 0x123a, 3, 22, ".//main.cpp" },
		{ 0x1259, 0, 0, NULL },
		{ 0x125a, 4, 15, ".//main.cpp" },
		{ 0x1266, 4, 31, ".//main.cpp" },
		{ 0x126b, 4, 34, ".//main.cpp" },
		{ 0x126d, 0, 0, NULL },
		{ 0x126e, 8, 3, ".//main.cpp" },
		{ 0x127e, 8, 9, ".//main.cpp" },
		{ 0x1298, 8, 12, ".//main.cpp" },
		{ 0x129b, 0, 0, NULL },
		{ 0x129c, 9, 11, ".//main.cpp" },
		{ 0x12ac, 9, 18, ".//main.cpp" },
		{ 0x12c6, 9, 19, ".//main.cpp" },
		{ 0x12c9, 0, 0, NULL },
		{ 0x12ca, 9, 11, ".//main.cpp" },
		{ 0x12da, 9, 19, ".//main.cpp" },
		{ 0x12f9, 0, 0, NULL },
		{ 0x12fa, 10, 15, ".//main.cpp" },
		{ 0x1306, 10, 31, ".//main.cpp" },
		{ 0x130b, 10, 34, ".//main.cpp" },
		{ 0x130d, 0, 0, NULL },
		{ 0x130e, 14, 3, ".//main.cpp" },
		{ 0x131a, 14, 10, ".//main.cpp" },
		{ 0x1328, 14, 13, ".//main.cpp" },
		{ 0x132b, 0, 0, NULL },
		{ 0x132c, 15, 11, ".//main.cpp" },
		{ 0x1338, 15, 19, ".//main.cpp" },
		{ 0x1346, 15, 20, ".//main.cpp" },
		{ 0x1349, 0, 0, NULL },
		{ 0x134a, 15, 11, ".//main.cpp" },
		{ 0x135a, 15, 20, ".//main.cpp" },
		{ 0x1379, 0, 0, NULL },
		{ 0x137a, 16, 15, ".//main.cpp" },
		{ 0x1386, 16, 30, ".//main.cpp" },
		{ 0x138b, 16, 33, ".//main.cpp" },
		{ 0x138d, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf3_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_eq(da->count, 58, "Incorrect number of abbreviation");
	int i = 18;

	check_abbrev_tag(DW_TAG_formal_parameter);
	check_abbrev_count(5);
	check_abbrev_children(false);
	check_abbrev_code(19);
	i = 41;
	check_abbrev_tag(DW_TAG_inheritance);
	check_abbrev_count(3);
	check_abbrev_children(false);
	check_abbrev_code(18);

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x118a, 3, 3, ".//mammal.cpp" },
		{ 0x1196, 3, 19, ".//mammal.cpp" },
		{ 0x11a4, 3, 22, ".//mammal.cpp" },
		{ 0x11a8, 3, 3, ".//mammal.cpp" },
		{ 0x11b8, 3, 22, ".//mammal.cpp" },
		{ 0x11d8, 4, 22, ".//mammal.cpp" },
		{ 0x11e4, 4, 31, ".//mammal.cpp" },
		{ 0x11e9, 4, 34, ".//mammal.cpp" },
		{ 0x11eb, 10, 12, ".//mammal.cpp" },
		{ 0x11f7, 10, 12, ".//mammal.cpp" },
		{ 0x1206, 12, 23, ".//mammal.cpp" },
		{ 0x1212, 13, 1, ".//mammal.cpp" },
		{ 0x1228, 7, 6, ".//mammal.cpp" },
		{ 0x1234, 7, 26, ".//mammal.cpp" },
		{ 0x1239, 7, 28, ".//mammal.cpp" },
		{ 0x123b, 15, 12, ".//main.cpp" },
		{ 0x1248, 18, 16, ".//main.cpp" },
		{ 0x125d, 18, 5, ".//main.cpp" },
		{ 0x1261, 19, 15, ".//main.cpp" },
		{ 0x1276, 19, 5, ".//main.cpp" },
		{ 0x127a, 20, 7, ".//main.cpp" },
		{ 0x1281, 21, 20, ".//main.cpp" },
		{ 0x128f, 21, 19, ".//main.cpp" },
		{ 0x1298, 21, 10, ".//main.cpp" },
		{ 0x129b, 22, 21, ".//main.cpp" },
		{ 0x12a9, 22, 20, ".//main.cpp" },
		{ 0x12b2, 22, 10, ".//main.cpp" },
		{ 0x12b5, 23, 23, ".//main.cpp" },
		{ 0x12ba, 23, 24, ".//main.cpp" },
		{ 0x12bf, 24, 1, ".//main.cpp" },
		{ 0x12c6, 2, 3, ".//mammal.h" },
		{ 0x12d2, 2, 12, ".//mammal.h" },
		{ 0x12e0, 2, 15, ".//mammal.h" },
		{ 0x12e3, 0, 0, NULL },
		{ 0x12e4, 4, 3, ".//main.cpp" },
		{ 0x12f4, 4, 9, ".//main.cpp" },
		{ 0x130e, 4, 12, ".//main.cpp" },
		{ 0x1311, 0, 0, NULL },
		{ 0x1312, 5, 11, ".//main.cpp" },
		{ 0x1322, 5, 18, ".//main.cpp" },
		{ 0x133c, 5, 19, ".//main.cpp" },
		{ 0x133f, 0, 0, NULL },
		{ 0x1340, 5, 11, ".//main.cpp" },
		{ 0x1350, 5, 19, ".//main.cpp" },
		{ 0x136f, 0, 0, NULL },
		{ 0x1370, 6, 15, ".//main.cpp" },
		{ 0x137c, 6, 31, ".//main.cpp" },
		{ 0x1381, 6, 34, ".//main.cpp" },
		{ 0x1383, 0, 0, NULL },
		{ 0x1384, 10, 3, ".//main.cpp" },
		{ 0x1390, 10, 10, ".//main.cpp" },
		{ 0x139e, 10, 13, ".//main.cpp" },
		{ 0x13a1, 0, 0, NULL },
		{ 0x13a2, 11, 11, ".//main.cpp" },
		{ 0x13ae, 11, 19, ".//main.cpp" },
		{ 0x13bc, 11, 20, ".//main.cpp" },
		{ 0x13bf, 0, 0, NULL },
		{ 0x13c0, 11, 11, ".//main.cpp" },
		{ 0x13d0, 11, 20, ".//main.cpp" },
		{ 0x13ef, 0, 0, NULL },
		{ 0x13f0, 12, 15, ".//main.cpp" },
		{ 0x13fc, 12, 30, ".//main.cpp" },
		{ 0x1401, 12, 33, ".//main.cpp" },
		{ 0x1403, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf_cpp_empty_line_info(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/pe/hello_world_not_stripped.exe", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	// not ignoring null entries -> 755 abbrevs
	mu_assert_eq(da->count, 731, "Incorrect number of abbreviation");

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 16, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const ut64 test_addresses[] = {
		0x00401000,
		0x00401000,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401010,
		0x00401013,
		0x00401015,
		0x0040101e,
		0x00401028,
		0x00401028,
		0x00401032,
		0x00401032,
		0x0040103c,
		0x0040103c,
		0x00401046,
		0x00401046,
		0x00401046
	};
	mu_assert_eq(li->lines->samples_count, 1331, "samples count");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(test_addresses); i++) {
		mu_assert_eq(li->lines->samples[i].address, test_addresses[i], "line addr");
	}

	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_io_free(io);
	rz_bin_free(bin);
	mu_end;
}

bool test_dwarf2_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf2_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_eq(da->count, 58, "Incorrect number of abbreviation");

	int i = 18;

	check_abbrev_tag(DW_TAG_formal_parameter);
	check_abbrev_count(5);
	check_abbrev_children(false);
	check_abbrev_code(19);
	i = 41;
	check_abbrev_tag(DW_TAG_inheritance);
	check_abbrev_count(4);
	check_abbrev_children(false);
	check_abbrev_code(18);

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x118a, 3, 3, ".//mammal.cpp" },
		{ 0x1196, 3, 19, ".//mammal.cpp" },
		{ 0x11a4, 3, 22, ".//mammal.cpp" },
		{ 0x11a8, 3, 3, ".//mammal.cpp" },
		{ 0x11b8, 3, 22, ".//mammal.cpp" },
		{ 0x11d8, 4, 22, ".//mammal.cpp" },
		{ 0x11e4, 4, 31, ".//mammal.cpp" },
		{ 0x11e9, 4, 34, ".//mammal.cpp" },
		{ 0x11eb, 10, 12, ".//mammal.cpp" },
		{ 0x11f7, 10, 12, ".//mammal.cpp" },
		{ 0x1206, 12, 23, ".//mammal.cpp" },
		{ 0x1212, 13, 1, ".//mammal.cpp" },
		{ 0x1228, 7, 6, ".//mammal.cpp" },
		{ 0x1234, 7, 26, ".//mammal.cpp" },
		{ 0x1239, 7, 28, ".//mammal.cpp" },
		{ 0x123b, 15, 12, ".//main.cpp" },
		{ 0x1248, 18, 16, ".//main.cpp" },
		{ 0x125d, 18, 5, ".//main.cpp" },
		{ 0x1261, 19, 15, ".//main.cpp" },
		{ 0x1276, 19, 5, ".//main.cpp" },
		{ 0x127a, 20, 7, ".//main.cpp" },
		{ 0x1281, 21, 20, ".//main.cpp" },
		{ 0x128f, 21, 19, ".//main.cpp" },
		{ 0x1298, 21, 10, ".//main.cpp" },
		{ 0x129b, 22, 21, ".//main.cpp" },
		{ 0x12a9, 22, 20, ".//main.cpp" },
		{ 0x12b2, 22, 10, ".//main.cpp" },
		{ 0x12b5, 23, 23, ".//main.cpp" },
		{ 0x12ba, 23, 24, ".//main.cpp" },
		{ 0x12bf, 24, 1, ".//main.cpp" },
		{ 0x12c6, 2, 3, ".//mammal.h" },
		{ 0x12d2, 2, 12, ".//mammal.h" },
		{ 0x12e0, 2, 15, ".//mammal.h" },
		{ 0x12e3, 0, 0, NULL },
		{ 0x12e4, 4, 3, ".//main.cpp" },
		{ 0x12f4, 4, 9, ".//main.cpp" },
		{ 0x130e, 4, 12, ".//main.cpp" },
		{ 0x1311, 0, 0, NULL },
		{ 0x1312, 5, 11, ".//main.cpp" },
		{ 0x1322, 5, 18, ".//main.cpp" },
		{ 0x133c, 5, 19, ".//main.cpp" },
		{ 0x133f, 0, 0, NULL },
		{ 0x1340, 5, 11, ".//main.cpp" },
		{ 0x1350, 5, 19, ".//main.cpp" },
		{ 0x136f, 0, 0, NULL },
		{ 0x1370, 6, 15, ".//main.cpp" },
		{ 0x137c, 6, 31, ".//main.cpp" },
		{ 0x1381, 6, 34, ".//main.cpp" },
		{ 0x1383, 0, 0, NULL },
		{ 0x1384, 10, 3, ".//main.cpp" },
		{ 0x1390, 10, 10, ".//main.cpp" },
		{ 0x139e, 10, 13, ".//main.cpp" },
		{ 0x13a1, 0, 0, NULL },
		{ 0x13a2, 11, 11, ".//main.cpp" },
		{ 0x13ae, 11, 19, ".//main.cpp" },
		{ 0x13bc, 11, 20, ".//main.cpp" },
		{ 0x13bf, 0, 0, NULL },
		{ 0x13c0, 11, 11, ".//main.cpp" },
		{ 0x13d0, 11, 20, ".//main.cpp" },
		{ 0x13ef, 0, 0, NULL },
		{ 0x13f0, 12, 15, ".//main.cpp" },
		{ 0x13fc, 12, 30, ".//main.cpp" },
		{ 0x1401, 12, 33, ".//main.cpp" },
		{ 0x1403, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	// TODO add abbrev checks

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x401160, 15, 0, "../main.cpp" },
		{ 0x401174, 18, 7, "../main.cpp" },
		{ 0x40117f, 18, 11, "../main.cpp" },
		{ 0x401194, 0, 11, "../main.cpp" },
		{ 0x401198, 18, 5, "../main.cpp" },
		{ 0x4011a1, 19, 7, "../main.cpp" },
		{ 0x4011ac, 19, 11, "../main.cpp" },
		{ 0x4011c1, 0, 11, "../main.cpp" },
		{ 0x4011c5, 19, 5, "../main.cpp" },
		{ 0x4011c9, 20, 7, "../main.cpp" },
		{ 0x4011d0, 21, 13, "../main.cpp" },
		{ 0x4011d4, 21, 16, "../main.cpp" },
		{ 0x4011dd, 21, 10, "../main.cpp" },
		{ 0x4011e3, 22, 13, "../main.cpp" },
		{ 0x4011e7, 22, 16, "../main.cpp" },
		{ 0x4011f0, 22, 10, "../main.cpp" },
		{ 0x4011f6, 23, 10, "../main.cpp" },
		{ 0x4011fc, 23, 19, "../main.cpp" },
		{ 0x401204, 23, 17, "../main.cpp" },
		{ 0x401206, 23, 3, "../main.cpp" },
		{ 0x40120e, 24, 1, "../main.cpp" },
		{ 0x401219, 18, 7, "../main.cpp" },
		{ 0x401223, 24, 1, "../main.cpp" },
		{ 0x40122e, 19, 7, "../main.cpp" },
		{ 0x401233, 18, 7, "../main.cpp" },
		{ 0x40123c, 0, 0, NULL },
		{ 0x401240, 10, 0, "../main.cpp" },
		{ 0x40125c, 10, 10, "../main.cpp" },
		{ 0x40125f, 10, 13, "../main.cpp" },
		{ 0x401261, 0, 0, NULL },
		{ 0x401270, 4, 0, "../main.cpp" },
		{ 0x401280, 4, 9, "../main.cpp" },
		{ 0x401283, 4, 3, "../main.cpp" },
		{ 0x4012a3, 4, 9, "../main.cpp" },
		{ 0x4012a6, 4, 12, "../main.cpp" },
		{ 0x4012ac, 0, 0, NULL },
		{ 0x4012b0, 11, 0, "../main.cpp" },
		{ 0x4012b8, 11, 20, "../main.cpp" },
		{ 0x4012ba, 0, 0, NULL },
		{ 0x4012c0, 11, 0, "../main.cpp" },
		{ 0x4012d0, 11, 19, "../main.cpp" },
		{ 0x4012e8, 11, 20, "../main.cpp" },
		{ 0x4012ee, 0, 0, NULL },
		{ 0x4012f0, 12, 0, "../main.cpp" },
		{ 0x4012f8, 12, 23, "../main.cpp" },
		{ 0x4012ff, 0, 0, NULL },
		{ 0x401300, 2, 0, "../mammal.h" },
		{ 0x40131c, 2, 12, "../mammal.h" },
		{ 0x40131f, 2, 15, "../mammal.h" },
		{ 0x401321, 0, 0, NULL },
		{ 0x401330, 5, 0, "../main.cpp" },
		{ 0x401340, 5, 19, "../main.cpp" },
		{ 0x401348, 5, 19, "../main.cpp" },
		{ 0x40134e, 0, 0, NULL },
		{ 0x401350, 5, 0, "../main.cpp" },
		{ 0x401360, 5, 18, "../main.cpp" },
		{ 0x401378, 5, 19, "../main.cpp" },
		{ 0x40137e, 0, 0, NULL },
		{ 0x401380, 6, 0, "../main.cpp" },
		{ 0x401388, 6, 24, "../main.cpp" },
		{ 0x40138f, 0, 0, NULL },
		{ 0x401390, 3, 0, "../mammal.cpp" },
		{ 0x401398, 3, 22, "../mammal.cpp" },
		{ 0x4013a0, 3, 0, "../mammal.cpp" },
		{ 0x4013b0, 3, 21, "../mammal.cpp" },
		{ 0x4013c8, 3, 22, "../mammal.cpp" },
		{ 0x4013d0, 4, 0, "../mammal.cpp" },
		{ 0x4013d8, 4, 24, "../mammal.cpp" },
		{ 0x4013e0, 10, 0, "../mammal.cpp" },
		{ 0x4013e8, 12, 14, "../mammal.cpp" },
		{ 0x4013f1, 12, 2, "../mammal.cpp" },
		{ 0x4013f7, 0, 0, NULL },
		{ 0x401400, 7, 0, "../mammal.cpp" },
		{ 0x401408, 7, 19, "../mammal.cpp" },
		{ 0x40140f, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_multidir_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf4_multidir_comp_units", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfDebugAbbrev *da = rz_bin_dwarf_parse_abbrev(bin->cur);
	mu_assert_notnull(da, "abbrevs");
	mu_assert_eq(da->count, 8, "abbrevs count");

	RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info(bin->cur, da);
	mu_assert_notnull(info, "info");

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, info, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x1139, 6, 12, "/home/florian/dev/dwarf-comp-units/main.c" },
		{ 0x113d, 7, 2, "/home/florian/dev/dwarf-comp-units/main.c" },
		{ 0x115f, 8, 2, "/home/florian/dev/dwarf-comp-units/main.c" },
		{ 0x1181, 9, 9, "/home/florian/dev/dwarf-comp-units/main.c" },
		{ 0x1186, 10, 1, "/home/florian/dev/dwarf-comp-units/main.c" },
		{ 0x1188, 2, 31, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c" },
		{ 0x1192, 3, 11, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c" },
		{ 0x1198, 3, 20, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c" },
		{ 0x11a1, 3, 16, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c" },
		{ 0x11a3, 4, 1, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c" },
		{ 0x11a5, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_dwarf_debug_info_free(info);
	rz_bin_dwarf_debug_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_big_endian_dwarf2(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/ppc64_sudoku_dwarf", &opt);
	mu_assert("couldn't open file", res);

	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_LINES);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_list_length(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x10000ec4, 30, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f18, 31, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f18, 31, 11, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f28, 32, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f28, 32, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f2c, 31, 11, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f30, 32, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f34, 34, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f38, 53, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f44, 38, 54, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f44, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x10000f44, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000f5c, 572, 14, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000f60, 42, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f60, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x10000f60, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000f78, 53, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f78, 53, 18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f80, 53, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f90, 53, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000f98, 54, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fa0, 34, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fa0, 55, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fa4, 36, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fb4, 38, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fc0, 38, 35, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fcc, 39, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fcc, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x10000fcc, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000fe4, 40, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10000fe4, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x10000fe4, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10000ffc, 41, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001008, 41, 35, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001014, 41, 54, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001014, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x10001014, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x1000102c, 572, 14, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001030, 46, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000103c, 46, 35, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001048, 47, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001048, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x10001048, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001060, 48, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001060, 48, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001074, 49, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001080, 49, 35, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000108c, 50, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000108c, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x1000108c, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010a4, 572, 14, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010a8, 46, 54, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100010a8, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x100010a8, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010c0, 572, 14, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010c4, 49, 54, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100010c4, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x100010c4, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010dc, 572, 14, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010e0, 53, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100010e0, 335, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h" },
		{ 0x100010e0, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010f8, 572, 14, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100010fc, 54, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100010fc, 600, 19, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001108, 450, 30, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x10001114, 49, 7, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x1000111c, 874, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001128, 875, 4, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001128, 875, 51, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x1000112c, 600, 19, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x1000113c, 622, 25, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001144, 55, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001144, 55, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001154, 55, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000115c, 32, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000115c, 34, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001164, 32, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001178, 32, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001178, 34, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000117c, 34, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001180, 570, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100011ac, 50, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x100011b4, 876, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011b4, 876, 21, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011c0, 877, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011c0, 877, 27, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011c4, 877, 23, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011e0, 877, 27, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x100011e4, 55, 42, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100011e4, 600, 19, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x100011f0, 450, 30, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x100011fc, 49, 7, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x10001204, 874, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001210, 875, 4, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001210, 875, 51, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001214, 600, 19, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001224, 622, 25, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x1000122c, 600, 46, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream" },
		{ 0x10001230, 50, 18, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/basic_ios.h" },
		{ 0x10001238, 876, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001238, 876, 21, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001244, 877, 2, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001244, 877, 27, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001248, 877, 23, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001264, 877, 27, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/locale_facets.h" },
		{ 0x10001268, 58, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012bc, 61, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012bc, 62, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012bc, 62, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012c4, 66, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012c8, 64, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012d4, 66, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012d4, 66, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012d8, 64, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012d8, 64, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012e0, 62, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012e0, 62, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012ec, 69, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012ec, 69, 15, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012f4, 70, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012f4, 70, 15, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100012f8, 71, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001308, 74, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001314, 75, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001334, 84, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001334, 85, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001334, 85, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001338, 85, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001348, 87, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001350, 88, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001350, 88, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000136c, 75, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001374, 98, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001374, 99, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001374, 99, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001378, 99, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001388, 101, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001390, 102, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001390, 102, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013a8, 105, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013a8, 106, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013a8, 106, 18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013ac, 106, 18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013ac, 107, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013b4, 110, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013bc, 77, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013bc, 78, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013bc, 78, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013c0, 78, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013d0, 80, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013d8, 81, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013d8, 81, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013e8, 91, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013e8, 92, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013e8, 92, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013ec, 92, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100013fc, 94, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001404, 95, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001404, 95, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001420, 134, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001420, 135, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001420, 136, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001420, 137, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001420, 137, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001430, 136, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001440, 137, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001440, 137, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001444, 139, 6, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001450, 140, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000145c, 142, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000145c, 142, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000145c, 144, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001460, 145, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001474, 150, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001474, 151, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001474, 152, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001474, 153, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001474, 153, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001480, 152, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001490, 153, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001490, 153, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001498, 155, 2, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014a4, 155, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014b0, 157, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014b0, 157, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014b0, 159, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014b4, 160, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014c8, 165, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014cc, 166, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014cc, 167, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014cc, 168, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014cc, 168, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014d0, 168, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014d8, 170, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014d8, 170, 27, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014dc, 170, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014ec, 167, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100014f4, 176, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001500, 176, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000150c, 172, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000150c, 172, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000150c, 174, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000150c, 174, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001514, 174, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001514, 176, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001528, 174, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001528, 174, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001528, 176, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001534, 174, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001534, 174, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001534, 176, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001540, 176, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000154c, 180, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000154c, 180, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001550, 180, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001560, 167, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001568, 186, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001574, 186, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001580, 182, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001580, 182, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001580, 184, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001580, 184, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001588, 184, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001588, 186, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000159c, 184, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000159c, 184, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000159c, 186, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015a8, 184, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015a8, 184, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015a8, 186, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015b4, 186, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015c0, 190, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015c0, 190, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015c4, 268, 12, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015c8, 190, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015dc, 196, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015e8, 196, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015f4, 192, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015f4, 192, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015f4, 194, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015f4, 194, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015fc, 194, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100015fc, 196, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001610, 194, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001610, 194, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001610, 196, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000161c, 194, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000161c, 194, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000161c, 196, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001628, 196, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001634, 201, 10, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001634, 201, 28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001638, 201, 10, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001640, 203, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001640, 203, 27, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001644, 203, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001654, 167, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000165c, 209, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001668, 209, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001674, 205, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001674, 205, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001674, 207, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001674, 207, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000167c, 207, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000167c, 209, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001690, 207, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001690, 207, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001690, 209, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000169c, 207, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000169c, 207, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000169c, 209, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016a8, 209, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016b4, 213, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016b4, 213, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016b8, 213, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016c8, 167, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016d0, 219, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016dc, 219, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016e8, 215, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016e8, 215, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016e8, 217, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016e8, 217, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016f0, 217, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100016f0, 219, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001704, 217, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001704, 217, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001704, 219, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001710, 217, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001710, 217, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001710, 219, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000171c, 219, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001728, 223, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001728, 223, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000172c, 268, 12, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001730, 223, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001744, 229, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001750, 229, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000175c, 225, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000175c, 225, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000175c, 227, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000175c, 227, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001764, 227, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001764, 229, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001778, 227, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001778, 227, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001778, 229, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001784, 227, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001784, 227, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001784, 229, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001790, 229, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000179c, 234, 10, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000179c, 234, 28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017a0, 268, 12, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017a4, 234, 10, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017ac, 236, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017ac, 236, 27, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017b0, 236, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017c4, 242, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017d0, 242, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017dc, 238, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017dc, 238, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017dc, 240, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017dc, 240, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017e4, 240, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017e4, 242, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017f8, 240, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017f8, 240, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100017f8, 242, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001804, 240, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001804, 240, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001804, 242, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001810, 242, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000181c, 246, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000181c, 246, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001820, 246, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001830, 167, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001838, 252, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001844, 252, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001850, 248, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001850, 248, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001850, 250, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001850, 250, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001858, 250, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001858, 252, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000186c, 250, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000186c, 250, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000186c, 252, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001878, 250, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001878, 250, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001878, 252, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001884, 252, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001890, 256, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001890, 256, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001894, 268, 12, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001898, 256, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018ac, 262, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018b8, 262, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018c4, 258, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018c4, 258, 30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018c4, 260, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018c4, 260, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018cc, 260, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018cc, 262, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018e0, 260, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018e0, 260, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018e0, 262, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018ec, 260, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018ec, 260, 34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018ec, 262, 21, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100018f8, 262, 41, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001904, 267, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000190c, 269, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000190c, 270, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000191c, 113, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000194c, 115, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001954, 115, 15, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001954, 115, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000195c, 116, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000195c, 116, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001960, 116, 37, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001964, 116, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001974, 117, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001974, 117, 32, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001978, 119, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001978, 119, 18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001984, 119, 40, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x1000198c, 119, 36, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001998, 119, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019a0, 119, 54, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019ac, 119, 40, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019b4, 121, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019b4, 121, 36, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019c4, 122, 6, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019c4, 122, 11, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019cc, 128, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019cc, 129, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019f4, 126, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x100019f4, 126, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp" },
		{ 0x10001a0c, 10, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a0c, 11, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a0c, 11, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a10, 11, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a1c, 13, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a30, 16, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a30, 17, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a30, 17, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a34, 17, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a40, 19, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a54, 11, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a54, 11, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a54, 22, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a54, 23, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a58, 23, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a64, 25, 8, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a64, 25, 10, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a6c, 26, 8, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a6c, 29, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a7c, 17, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a7c, 17, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a7c, 31, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a7c, 32, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a80, 32, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a8c, 34, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a8c, 34, 11, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a94, 35, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001a94, 38, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001aa4, 41, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001aa4, 42, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001aa4, 42, 16, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001aa8, 42, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001ab4, 44, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001ac8, 16, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001ae4, 17, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001ae4, 18, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001ae4, 20, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001ae4, 20, 16, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001aec, 22, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001aec, 22, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001af8, 30, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001af8, 30, 26, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b04, 31, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b04, 31, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b10, 32, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b10, 32, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b28, 40, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b28, 40, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b3c, 42, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b44, 24, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b44, 26, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b44, 26, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b50, 26, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b54, 27, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b54, 27, 15, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b68, 17, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001b68, 17, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001b68, 28, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b6c, 28, 9, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b78, 34, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b78, 42, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001b78, 42, 16, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/alphanum.cpp" },
		{ 0x10001b7c, 34, 14, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b88, 36, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b88, 36, 23, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b94, 37, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001b94, 37, 24, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001ba0, 38, 13, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001ba0, 38, 22, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001bb4, 42, 17, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001bb8, 44, 5, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001bb8, 45, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001be0, 45, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001bf8, 74, 25, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/iostream" },
		{ 0x10001c28, 45, 1, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/play.cpp" },
		{ 0x10001c48, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_info_free(li);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf3_aranges(void) {
	// The file's arange version is actually 2 but the format is the same as 3
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open(bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert("couldn't open file", res);

	RzList *aranges = rz_bin_dwarf_parse_aranges(bin->cur);
	mu_assert_eq(rz_list_length(aranges), 2, "arange sets count");

	RzBinDwarfARangeSet *set = rz_list_get_n(aranges, 0);
	mu_assert_eq(set->unit_length, 60, "unit length");
	mu_assert_eq(set->version, 2, "version");
	mu_assert_eq(set->debug_info_offset, 0x0, "debug_info offset");
	mu_assert_eq(set->address_size, 8, "address size");
	mu_assert_eq(set->segment_size, 0, "segment size");
	mu_assert_eq(set->aranges_count, 3, "aranges count");
	RzBinDwarfARange ref_0[] = {
		{ 0x000000000000118a, 0x000000000000009e },
		{ 0x0000000000001228, 0x0000000000000013 },
		{ 0x0000000000000000, 0x0000000000000000 }
	};
	mu_assert_memeq((const ut8 *)set->aranges, (const ut8 *)&ref_0, sizeof(ref_0), "aranges contents");

	set = rz_list_get_n(aranges, 1);
	mu_assert_eq(set->unit_length, 188, "unit length");
	mu_assert_eq(set->version, 2, "version");
	mu_assert_eq(set->debug_info_offset, 0x22e, "debug_info offset");
	mu_assert_eq(set->address_size, 8, "address size");
	mu_assert_eq(set->segment_size, 0, "segment size");
	mu_assert_eq(set->aranges_count, 11, "aranges count");
	RzBinDwarfARange ref_1[] = {
		{ 0x000000000000123b, 0x000000000000008b },
		{ 0x00000000000012c6, 0x000000000000001d },
		{ 0x00000000000012e4, 0x000000000000002d },
		{ 0x0000000000001312, 0x000000000000002d },
		{ 0x0000000000001340, 0x000000000000002f },
		{ 0x0000000000001370, 0x0000000000000013 },
		{ 0x0000000000001384, 0x000000000000001d },
		{ 0x00000000000013a2, 0x000000000000001d },
		{ 0x00000000000013c0, 0x000000000000002f },
		{ 0x00000000000013f0, 0x0000000000000013 },
		{ 0x0000000000000000, 0x0000000000000000 }
	};
	mu_assert_memeq((const ut8 *)set->aranges, (const ut8 *)&ref_1, sizeof(ref_1), "aranges contents");

	rz_list_free(aranges);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool all_tests() {
	srand(time(0));
	mu_run_test(test_dwarf3_c_basic);
	mu_run_test(test_dwarf_cpp_empty_line_info);
	mu_run_test(test_dwarf2_cpp_many_comp_units);
	mu_run_test(test_dwarf3_cpp_basic);
	mu_run_test(test_dwarf3_cpp_many_comp_units);
	mu_run_test(test_dwarf4_cpp_many_comp_units);
	mu_run_test(test_dwarf4_multidir_comp_units);
	mu_run_test(test_big_endian_dwarf2);
	mu_run_test(test_dwarf3_aranges);
	return tests_passed != tests_run;
}

mu_main(all_tests)
