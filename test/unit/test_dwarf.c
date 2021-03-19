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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 1, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(li->rows), 8, "rows count");

	const RzBinSourceRow test_rows[] = {
		{ 0x1129, ".//main.c", 3, 1 },
		{ 0x1131, ".//main.c", 6, 1 },
		{ 0x1134, ".//main.c", 7, 12 },
		{ 0x1140, ".//main.c", 8, 2 },
		{ 0x114a, ".//main.c", 9, 6 },
		{ 0x1151, ".//main.c", 10, 9 },
		{ 0x1154, ".//main.c", 11, 1 },
		{ 0x1156, ".//main.c", 0, 0 }
	};
	i = 0;
	RzBinSourceRow *row;
	RzListIter *iter;
	rz_list_foreach (li->rows, iter, row) {
		const RzBinSourceRow *expect = &test_rows[i++];
		mu_assert_eq(row->address, expect->address, "Row addr");
		mu_assert_streq(row->file, expect->file, "Row file");
		mu_assert_eq(row->line, expect->line, "Row line");
		mu_assert_eq(row->column, expect->column, "Row column");
	}

	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 1, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(li->rows), 60, "rows count");

	int test_addresses[] = {
		0x11ee,
		0x11fa,
		0x1208,
		0x120b,
		0x120c,
		0x1218,
		0x1226,
		0x1229,
		0x122a,
		0x123a,
		0x1259,
		0x125a,
		0x1266,
		0x126b,
		0x126d,
		0x126e,
		0x127e,
		0x1298,
		0x129b,
		0x129c,
		0x12ac,
		0x12c6,
		0x12c9,
		0x12ca,
		0x12da,
		0x12f9,
		0x12fa,
		0x1306,
		0x130b,
		0x130d,
		0x130e,
		0x131a,
		0x1328,
		0x132b,
		0x132c,
		0x1338,
		0x1346,
		0x1349,
		0x134a,
		0x135a,
		0x1379,
		0x137a,
		0x1386,
		0x138b,
		0x138d,
		0x1169,
		0x1176,
		0x118b,
		0x118f,
		0x11a4,
		0x11a8,
		0x11af,
		0x11bd,
		0x11c6,
		0x11c9,
		0x11d7,
		0x11e0,
		0x11e3,
		0x11e6,
		0x11ed
	};
	i = 0;

	RzBinSourceRow *row;
	RzListIter *iter;
	rz_list_foreach (li->rows, iter, row) {
		mu_assert_eq(row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 2, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(li->rows), 17, "rows count");

	int test_addresses[] = {
		0x118a,
		0x1196,
		0x11a4,
		0x11a8,
		0x11b8,
		0x11d8,
		0x11e4,
		0x11e9,
		0x11eb,
		0x11f7,
		0x1206,
		0x1212,
		0x1228,
		0x1228,
		0x1234,
		0x1239,
		0x123b
	};
	i = 0;

	RzBinSourceRow *row;
	RzListIter *iter;
	rz_list_foreach (li->rows, iter, row) {
		mu_assert_eq(row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 16, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0))->rows), 271, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 1))->rows), 45, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 2))->rows), 41, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 3))->rows), 4, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 4))->rows), 4, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 5))->rows), 69, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 6))->rows), 46, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 7))->rows), 36, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 9))->rows), 4, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0xa))->rows), 220, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0xb))->rows), 72, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0xc))->rows), 155, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0xd))->rows), 331, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0xe))->rows), 16, "rows count");
	mu_assert_eq(rz_list_length(((RzBinDwarfLineInfo *)rz_list_get_n(line_list, 0xf))->rows), 13, "rows count");

	const int test_addresses[] = {
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

	int i = 0;

	RzBinSourceRow *row;
	RzListIter *iter;
	rz_list_foreach (li->rows, iter, row) {
		mu_assert_eq(row->address, test_addresses[i++], "row addr");
		if (i == 23)
			break;
	}

	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 2, "Amount of line information parse doesn't match");

	RzBinDwarfLineInfo *li = rz_list_get_n(line_list, 0);
	mu_assert_eq(rz_list_length(li->rows), 17, "rows count");
	const ut64 test_addresses0[] = {
		0x118a,
		0x1196,
		0x11a4,
		0x11a8,
		0x11b8,
		0x11d8,
		0x11e4,
		0x11e9,
		0x11eb,
		0x11f7,
		0x1206,
		0x1212,
		0x1228,
		0x1228,
		0x1234,
		0x1239,
		0x123b
	};
	RzBinSourceRow *row;
	RzListIter *iter;
	i = 0;
	rz_list_foreach (li->rows, iter, row) {
		mu_assert_eq(row->address, test_addresses0[i++], "row addr");
	}

	li = rz_list_get_n(line_list, 1);
	mu_assert_eq(rz_list_length(li->rows), 50, "rows count");
	const ut64 test_addresses1[] = {
		0x12c6,
		0x12d2,
		0x12e0,
		0x12e3,
		0x12e4,
		0x12f4,
		0x130e,
		0x1311,
		0x1312,
		0x1322,
		0x133c,
		0x133f,
		0x1340,
		0x1350,
		0x136f,
		0x1370,
		0x137c,
		0x1381,
		0x1383,
		0x1384,
		0x1390,
		0x139e,
		0x13a1,
		0x13a2,
		0x13ae,
		0x13bc,
		0x13bf,
		0x13c0,
		0x13d0,
		0x13ef,
		0x13f0,
		0x13fc,
		0x1401,
		0x1403,
		0x123b,
		0x1248,
		0x125d,
		0x1261,
		0x1276,
		0x127a,
		0x1281,
		0x128f,
		0x1298,
		0x129b,
		0x12a9,
		0x12b2,
		0x12b5,
		0x12ba,
		0x12bf,
		0x12c6
	};
	i = 0;
	rz_list_foreach (li->rows, iter, row) {
		mu_assert_eq(row->address, test_addresses1[i++], "row addr");
	}

	// add line information check
	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 2, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(li->rows), 61, "rows count");

	const int test_addresses[] = {
		0x00401160,
		0x00401174,
		0x0040117f,
		0x00401194,
		0x00401198,
		0x004011a1,
		0x004011ac,
		0x004011c1,
		0x004011c5,
		0x004011c9,
		0x004011d0,
		0x004011d4,
		0x004011dd,
		0x004011e3,
		0x004011e7,
		0x004011f0,
		0x004011f6,
		0x004011fc,
		0x00401204,
		0x00401206,
		0x0040120e,
		0x00401219,
		0x00401223,
		0x0040122e,
		0x00401233,
		0x0040123c,
		0x00401240,
		0x0040125c,
		0x0040125f,
		0x00401261,
		0x00401270,
		0x00401280,
		0x00401283,
		0x004012a3,
		0x004012a6,
		0x004012ac,
		0x004012b0,
		0x004012b8,
		0x004012ba,
		0x004012c0,
		0x004012d0,
		0x004012e8,
		0x004012ee,
		0x004012f0,
		0x004012f8,
		0x004012ff,
		0x00401300,
		0x0040131c,
		0x0040131f,
		0x00401321,
		0x00401330,
		0x00401340,
		0x00401348,
		0x0040134e,
		0x00401350,
		0x00401360,
		0x00401378,
		0x0040137e,
		0x00401380,
		0x00401388,
		0x0040138f,
		0x00401390,
		0x00401398,
		0x004013a0,
		0x004013b0,
		0x004013c8,
		0x004013d0,
		0x004013d8,
		0x004013e0,
		0x004013e8,
		0x004013f1,
		0x004013f7,
		0x00401400,
		0x00401408,
		0x0040140f,
	};

	RzBinSourceRow *row;
	RzListIter *iter;
	int i = 0;
	rz_list_foreach (li->rows, iter, row) {
		mu_assert_eq(row->address, test_addresses[i++], "Line number statement address doesn't match");
	}

	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, info, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 2, "line info count");

	const RzBinSourceRow test_rows0[] = {
		{ 0x1139, "/home/florian/dev/dwarf-comp-units/main.c", 6, 12 },
		{ 0x113d, "/home/florian/dev/dwarf-comp-units/main.c", 7, 2 },
		{ 0x115f, "/home/florian/dev/dwarf-comp-units/main.c", 8, 2 },
		{ 0x1181, "/home/florian/dev/dwarf-comp-units/main.c", 9, 9 },
		{ 0x1186, "/home/florian/dev/dwarf-comp-units/main.c", 10, 1 },
		{ 0x1188, "/home/florian/dev/dwarf-comp-units/main.c", 0, 0 }
	};

	const RzBinSourceRow test_rows1[] = {
		{ 0x1188, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c", 2, 31 },
		{ 0x1192, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c", 3, 11 },
		{ 0x1198, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c", 3, 20 },
		{ 0x11a1, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c", 3, 16 },
		{ 0x11a3, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c", 4, 1 },
		{ 0x11a5, "/home/florian/dev/dwarf-comp-units/some_subfolder/subfile.c", 0, 0 }
	};

	const RzBinSourceRow *test_rows[] = { test_rows0, test_rows1 };

	for (size_t i = 0; i < 2; i++) {
		RzBinDwarfLineInfo *li = rz_list_get_n(line_list, i);
		mu_assert_eq(rz_list_length(li->rows), i ? RZ_ARRAY_SIZE(test_rows1) : RZ_ARRAY_SIZE(test_rows0), "rows count");
		RzBinSourceRow *row;
		RzListIter *iter;
		size_t j = 0;
		rz_list_foreach (li->rows, iter, row) {
			const RzBinSourceRow *expect = &test_rows[i][j++];
			mu_assert_eq(row->address, expect->address, "Row addr");
			mu_assert_streq(row->file, expect->file, "Row file");
			mu_assert_eq(row->line, expect->line, "Row line");
			mu_assert_eq(row->column, expect->column, "Row column");
		}
	}

	rz_list_free(line_list);
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

	RzList *line_list = rz_bin_dwarf_parse_line(bin->cur, NULL, RZ_BIN_DWARF_LINE_INFO_MASK_OPS | RZ_BIN_DWARF_LINE_INFO_MASK_ROWS);
	mu_assert_eq(rz_list_length(line_list), 1, "Amount of line information parse doesn't match");
	RzBinDwarfLineInfo *li = rz_list_first(line_list);
	mu_assert_eq(rz_list_length(li->rows), 475, "rows count");

	const RzBinSourceRow test_rows[] = {
		{ 0x10000ec4, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 30, 1 },
		{ 0x10000f18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 31, 5 },
		{ 0x10000f18, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 31, 11 },
		{ 0x10000f28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 32, 5 },
		{ 0x10000f28, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 32, 22 },
		{ 0x10000f2c, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 31, 11 },
		{ 0x10000f30, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 32, 13 },
		{ 0x10000f34, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 34, 17 },
		{ 0x10000f38, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 53, 22 },
		{ 0x10000f44, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 38, 54 },
		{ 0x10000f44, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h", 335, 2 },
		{ 0x10000f44, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream", 570, 18 },
		{ 0x10000f5c, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream", 572, 14 },
		{ 0x10000f60, "/home/hound/Projects/r2test/dwarf/cpp/sudoku_cpp/grid.cpp", 42, 22 },
		{ 0x10000f60, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/bits/char_traits.h", 335, 2 },
		{ 0x10000f60, "/home/hound/Crosscompilation/powerpc64-linux-musl-cross/powerpc64-linux-musl/include/c++/9.3.0/ostream", 570, 18 }
	};

	RzBinSourceRow *row;
	RzListIter *iter;
	int i = 0;
	rz_list_foreach (li->rows, iter, row) {
		const RzBinSourceRow *expect = &test_rows[i++];
		mu_assert_eq(row->address, expect->address, "Row addr");
		mu_assert_streq(row->file, expect->file, "Row file");
		mu_assert_eq(row->line, expect->line, "Row line");
		mu_assert_eq(row->column, expect->column, "Row column");
		if (i == 0x10) {
			break;
		}
	}

	rz_list_free(line_list);
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
