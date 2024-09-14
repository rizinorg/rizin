// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_bin.h>
#include <rz_core.h>
#include <rz_bin_dwarf.h>
#include "../unit/minunit.h"

static bool check_line_samples_eq(
	const RzBinSourceLineInfo *actual,
	size_t samples_count_expect,
	const RzBinSourceLineSample *samples_expect) {
	mu_assert_eq(actual->samples_count, samples_count_expect, "samples count");
	if (samples_expect) {
		mu_assert_notnull(actual->samples, "samples");
		for (size_t i = 0; i < samples_count_expect; i++) {
			RzBinSourceLineSample *act = &actual->samples[i];
			const RzBinSourceLineSample *exp = &samples_expect[i];
			mu_assert_eq(act->address, exp->address, "sample addr");
			mu_assert_eq(act->line, exp->line, "sample line");
			mu_assert_eq(act->column, exp->column, "sample column");
			if (exp->file) {
				mu_assert_notnull(act->file, "sample file");
				mu_assert_streq(act->file, exp->file, "sample file");
			} else {
				mu_assert_null(act->file, "sample file");
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

#define TEST_ABBREV_DECL(_index, _offset, _tag, _has_children, _attr_count) \
	do { \
		abbrev = rz_vector_index_ptr(&tbl->abbrevs, _index); \
		mu_assert_notnull(abbrev, "abbrev"); \
		mu_assert_eq(abbrev->offset, _offset, "abbrev offset"); \
		mu_assert_eq(abbrev->tag, _tag, "abbrev tag"); \
		mu_assert_eq(abbrev->has_children, _has_children, "abbrev has children"); \
		mu_assert_eq(rz_vector_len(&abbrev->defs), _attr_count, "abbrev has children"); \
	} while (0)

#define TEST_ABBREV_ATTR(_index, _name, _form) \
	do { \
		def = rz_vector_index_ptr(&abbrev->defs, _index); \
		mu_assert_notnull(def, "abbrev attr"); \
		mu_assert_eq(def->at, _name, "abbrev attr name"); \
		mu_assert_eq(def->form, _form, "abbrev attr form"); \
	} while (0)

/**
 * @brief Tests correct parsing of abbreviations and line information of DWARF3 C binary
 */
bool test_dwarf3_c_basic(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf3_c.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDwarfAbbrev *da = NULL;
	da = rz_bin_dwarf_abbrev_from_file(bin->cur, false);
	mu_assert_eq(rz_bin_dwarf_abbrev_count(da), 7, "Incorrect number of abbreviation");

	RzBinDwarfAbbrevTable *tbl = ht_up_find(da->by_offset, 0x0, NULL);
	RzBinDwarfAbbrevDecl *abbrev = NULL;
	RzBinDwarfAttrSpec *def = NULL;

	TEST_ABBREV_DECL(0, 0x0, DW_TAG_compile_unit, true, 7);
	TEST_ABBREV_ATTR(0, DW_AT_producer, DW_FORM_strp);
	TEST_ABBREV_ATTR(1, DW_AT_language, DW_FORM_data1);
	TEST_ABBREV_ATTR(2, DW_AT_name, DW_FORM_strp);
	TEST_ABBREV_ATTR(3, DW_AT_comp_dir, DW_FORM_strp);
	TEST_ABBREV_ATTR(4, DW_AT_low_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(5, DW_AT_high_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(6, DW_AT_stmt_list, DW_FORM_data4);

	TEST_ABBREV_DECL(2, 0x26, DW_TAG_base_type, false, 3);
	TEST_ABBREV_ATTR(0, DW_AT_byte_size, DW_FORM_data1);
	TEST_ABBREV_ATTR(1, DW_AT_encoding, DW_FORM_data1);
	TEST_ABBREV_ATTR(2, DW_AT_name, DW_FORM_string);

	TEST_ABBREV_DECL(6, 0x76, DW_TAG_variable, false, 5);
	TEST_ABBREV_ATTR(0, DW_AT_name, DW_FORM_string);
	TEST_ABBREV_ATTR(1, DW_AT_decl_file, DW_FORM_data1);
	TEST_ABBREV_ATTR(2, DW_AT_decl_line, DW_FORM_data1);
	TEST_ABBREV_ATTR(3, DW_AT_decl_column, DW_FORM_data1);
	TEST_ABBREV_ATTR(4, DW_AT_type, DW_FORM_ref4);

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(
		bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x1129, 3, 1, "main.c" },
		{ 0x1131, 6, 1, "main.c" },
		{ 0x1134, 7, 12, "main.c" },
		{ 0x1140, 8, 2, "main.c" },
		{ 0x114a, 9, 6, "main.c" },
		{ 0x1151, 10, 9, "main.c" },
		{ 0x1154, 11, 1, "main.c" },
		{ 0x1156, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_free(li);

	rz_bin_dwarf_abbrev_free(da);
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
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf3_cpp.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	// this is probably ugly, but I didn't know how to
	// tell core  what bin to open so I did it myself

	RzBinDwarfAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_abbrev_from_file(bin->cur, false);
	mu_assert("Incorrect number of abbreviation", rz_bin_dwarf_abbrev_count(da) == 32);

	RzBinDwarfAbbrevTable *tbl = ht_up_find(da->by_offset, 0x0, NULL);
	RzBinDwarfAbbrevDecl *abbrev = NULL;
	RzBinDwarfAttrSpec *def = NULL;
	mu_assert_notnull(tbl, "abbrev table");
	mu_assert_eq(rz_vector_len(&tbl->abbrevs), 32, "abbrev decls count");
	mu_assert_eq(tbl->offset, 0x0, "abbrev table offset");

	TEST_ABBREV_DECL(0, 0x0, DW_TAG_compile_unit, true, 8);
	TEST_ABBREV_ATTR(0, DW_AT_producer, DW_FORM_strp);
	TEST_ABBREV_ATTR(1, DW_AT_language, DW_FORM_data1);
	TEST_ABBREV_ATTR(2, DW_AT_name, DW_FORM_strp);
	TEST_ABBREV_ATTR(3, DW_AT_comp_dir, DW_FORM_strp);
	TEST_ABBREV_ATTR(4, DW_AT_ranges, DW_FORM_data4);
	TEST_ABBREV_ATTR(5, DW_AT_low_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(6, DW_AT_entry_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(7, DW_AT_stmt_list, DW_FORM_data4);

	TEST_ABBREV_DECL(8, 0x8d, DW_TAG_subprogram, true, 12);
	TEST_ABBREV_ATTR(0, DW_AT_external, DW_FORM_flag);
	TEST_ABBREV_ATTR(1, DW_AT_name, DW_FORM_string);
	TEST_ABBREV_ATTR(2, DW_AT_decl_file, DW_FORM_data1);
	TEST_ABBREV_ATTR(3, DW_AT_decl_line, DW_FORM_data1);
	TEST_ABBREV_ATTR(4, DW_AT_decl_column, DW_FORM_data1);
	TEST_ABBREV_ATTR(5, DW_AT_MIPS_linkage_name, DW_FORM_strp);
	TEST_ABBREV_ATTR(6, DW_AT_type, DW_FORM_ref4);
	TEST_ABBREV_ATTR(7, DW_AT_virtuality, DW_FORM_data1);
	TEST_ABBREV_ATTR(8, DW_AT_vtable_elem_location, DW_FORM_block1);
	TEST_ABBREV_ATTR(9, DW_AT_containing_type, DW_FORM_ref4);
	TEST_ABBREV_ATTR(10, DW_AT_declaration, DW_FORM_flag);
	TEST_ABBREV_ATTR(11, DW_AT_object_pointer, DW_FORM_ref4);

	// rz_bin_dwarf_parse_info (da, core->bin, mode); Information not stored anywhere, not testable now?

	// rz_bin_dwarf_parse_aranges (core->bin, MODE); Information not stored anywhere, not testable now?

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(
		bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 1, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x1169, 19, 12, "main.cpp" },
		{ 0x1176, 22, 16, "main.cpp" },
		{ 0x118b, 22, 5, "main.cpp" },
		{ 0x118f, 23, 15, "main.cpp" },
		{ 0x11a4, 23, 5, "main.cpp" },
		{ 0x11a8, 24, 7, "main.cpp" },
		{ 0x11af, 25, 20, "main.cpp" },
		{ 0x11bd, 25, 19, "main.cpp" },
		{ 0x11c6, 25, 10, "main.cpp" },
		{ 0x11c9, 26, 21, "main.cpp" },
		{ 0x11d7, 26, 20, "main.cpp" },
		{ 0x11e0, 26, 10, "main.cpp" },
		{ 0x11e3, 27, 10, "main.cpp" },
		{ 0x11e6, 28, 1, "main.cpp" },
		{ 0x11ed, 0, 0, NULL },
		{ 0x11ee, 2, 3, "main.cpp" },
		{ 0x11fa, 2, 12, "main.cpp" },
		{ 0x1208, 2, 15, "main.cpp" },
		{ 0x120b, 0, 0, NULL },
		{ 0x120c, 3, 11, "main.cpp" },
		{ 0x1218, 3, 21, "main.cpp" },
		{ 0x1226, 3, 22, "main.cpp" },
		{ 0x1229, 0, 0, NULL },
		{ 0x122a, 3, 11, "main.cpp" },
		{ 0x123a, 3, 22, "main.cpp" },
		{ 0x1259, 0, 0, NULL },
		{ 0x125a, 4, 15, "main.cpp" },
		{ 0x1266, 4, 31, "main.cpp" },
		{ 0x126b, 4, 34, "main.cpp" },
		{ 0x126d, 0, 0, NULL },
		{ 0x126e, 8, 3, "main.cpp" },
		{ 0x127e, 8, 9, "main.cpp" },
		{ 0x1298, 8, 12, "main.cpp" },
		{ 0x129b, 0, 0, NULL },
		{ 0x129c, 9, 11, "main.cpp" },
		{ 0x12ac, 9, 18, "main.cpp" },
		{ 0x12c6, 9, 19, "main.cpp" },
		{ 0x12c9, 0, 0, NULL },
		{ 0x12ca, 9, 11, "main.cpp" },
		{ 0x12da, 9, 19, "main.cpp" },
		{ 0x12f9, 0, 0, NULL },
		{ 0x12fa, 10, 15, "main.cpp" },
		{ 0x1306, 10, 31, "main.cpp" },
		{ 0x130b, 10, 34, "main.cpp" },
		{ 0x130d, 0, 0, NULL },
		{ 0x130e, 14, 3, "main.cpp" },
		{ 0x131a, 14, 10, "main.cpp" },
		{ 0x1328, 14, 13, "main.cpp" },
		{ 0x132b, 0, 0, NULL },
		{ 0x132c, 15, 11, "main.cpp" },
		{ 0x1338, 15, 19, "main.cpp" },
		{ 0x1346, 15, 20, "main.cpp" },
		{ 0x1349, 0, 0, NULL },
		{ 0x134a, 15, 11, "main.cpp" },
		{ 0x135a, 15, 20, "main.cpp" },
		{ 0x1379, 0, 0, NULL },
		{ 0x137a, 16, 15, "main.cpp" },
		{ 0x1386, 16, 30, "main.cpp" },
		{ 0x138b, 16, 33, "main.cpp" },
		{ 0x138d, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_free(li);

	rz_bin_dwarf_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf3_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDwarfAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_abbrev_from_file(bin->cur, false);
	mu_assert_eq(rz_bin_dwarf_abbrev_count(da), 58, "Incorrect number of abbreviation");

	RzBinDwarfAbbrevTable *tbl = ht_up_find(da->by_offset, 0x0, NULL);
	RzBinDwarfAbbrevDecl *abbrev = NULL;
	RzBinDwarfAttrSpec *def = NULL;

	TEST_ABBREV_DECL(0, 0x0, DW_TAG_compile_unit, true, 8);
	TEST_ABBREV_ATTR(0, DW_AT_producer, DW_FORM_strp);
	TEST_ABBREV_ATTR(1, DW_AT_language, DW_FORM_data1);
	TEST_ABBREV_ATTR(2, DW_AT_name, DW_FORM_strp);
	TEST_ABBREV_ATTR(3, DW_AT_comp_dir, DW_FORM_strp);
	TEST_ABBREV_ATTR(4, DW_AT_ranges, DW_FORM_data4);
	TEST_ABBREV_ATTR(5, DW_AT_low_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(6, DW_AT_entry_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(7, DW_AT_stmt_list, DW_FORM_data4);

	TEST_ABBREV_DECL(17, 0x11d, DW_TAG_subprogram, true, 7);
	TEST_ABBREV_ATTR(0, DW_AT_specification, DW_FORM_ref4);
	TEST_ABBREV_ATTR(1, DW_AT_object_pointer, DW_FORM_ref4);
	TEST_ABBREV_ATTR(2, DW_AT_low_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(3, DW_AT_high_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(4, DW_AT_frame_base, DW_FORM_block1);
	TEST_ABBREV_ATTR(5, DW_AT_GNU_all_call_sites, DW_FORM_flag);
	TEST_ABBREV_ATTR(6, DW_AT_sibling, DW_FORM_ref4);

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(
		bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x118a, 3, 3, "mammal.cpp" },
		{ 0x1196, 3, 19, "mammal.cpp" },
		{ 0x11a4, 3, 22, "mammal.cpp" },
		{ 0x11a8, 3, 3, "mammal.cpp" },
		{ 0x11b8, 3, 22, "mammal.cpp" },
		{ 0x11d8, 4, 22, "mammal.cpp" },
		{ 0x11e4, 4, 31, "mammal.cpp" },
		{ 0x11e9, 4, 34, "mammal.cpp" },
		{ 0x11eb, 10, 12, "mammal.cpp" },
		{ 0x11f7, 10, 12, "mammal.cpp" },
		{ 0x1206, 12, 23, "mammal.cpp" },
		{ 0x1212, 13, 1, "mammal.cpp" },
		{ 0x1228, 7, 6, "mammal.cpp" },
		{ 0x1234, 7, 26, "mammal.cpp" },
		{ 0x1239, 7, 28, "mammal.cpp" },
		{ 0x123b, 15, 12, "main.cpp" },
		{ 0x1248, 18, 16, "main.cpp" },
		{ 0x125d, 18, 5, "main.cpp" },
		{ 0x1261, 19, 15, "main.cpp" },
		{ 0x1276, 19, 5, "main.cpp" },
		{ 0x127a, 20, 7, "main.cpp" },
		{ 0x1281, 21, 20, "main.cpp" },
		{ 0x128f, 21, 19, "main.cpp" },
		{ 0x1298, 21, 10, "main.cpp" },
		{ 0x129b, 22, 21, "main.cpp" },
		{ 0x12a9, 22, 20, "main.cpp" },
		{ 0x12b2, 22, 10, "main.cpp" },
		{ 0x12b5, 23, 23, "main.cpp" },
		{ 0x12ba, 23, 24, "main.cpp" },
		{ 0x12bf, 24, 1, "main.cpp" },
		{ 0x12c6, 2, 3, "mammal.h" },
		{ 0x12d2, 2, 12, "mammal.h" },
		{ 0x12e0, 2, 15, "mammal.h" },
		{ 0x12e3, 0, 0, NULL },
		{ 0x12e4, 4, 3, "main.cpp" },
		{ 0x12f4, 4, 9, "main.cpp" },
		{ 0x130e, 4, 12, "main.cpp" },
		{ 0x1311, 0, 0, NULL },
		{ 0x1312, 5, 11, "main.cpp" },
		{ 0x1322, 5, 18, "main.cpp" },
		{ 0x133c, 5, 19, "main.cpp" },
		{ 0x133f, 0, 0, NULL },
		{ 0x1340, 5, 11, "main.cpp" },
		{ 0x1350, 5, 19, "main.cpp" },
		{ 0x136f, 0, 0, NULL },
		{ 0x1370, 6, 15, "main.cpp" },
		{ 0x137c, 6, 31, "main.cpp" },
		{ 0x1381, 6, 34, "main.cpp" },
		{ 0x1383, 0, 0, NULL },
		{ 0x1384, 10, 3, "main.cpp" },
		{ 0x1390, 10, 10, "main.cpp" },
		{ 0x139e, 10, 13, "main.cpp" },
		{ 0x13a1, 0, 0, NULL },
		{ 0x13a2, 11, 11, "main.cpp" },
		{ 0x13ae, 11, 19, "main.cpp" },
		{ 0x13bc, 11, 20, "main.cpp" },
		{ 0x13bf, 0, 0, NULL },
		{ 0x13c0, 11, 11, "main.cpp" },
		{ 0x13d0, 11, 20, "main.cpp" },
		{ 0x13ef, 0, 0, NULL },
		{ 0x13f0, 12, 15, "main.cpp" },
		{ 0x13fc, 12, 30, "main.cpp" },
		{ 0x1401, 12, 33, "main.cpp" },
		{ 0x1403, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_free(li);

	rz_bin_dwarf_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

#define CHECK_LINEOP_FILE_ENTRY(index, dir, time, sz, path) \
	{ \
		RzBinDwarfFileEntry *f = rz_vector_index_ptr(&hdr->file_names, (index)); \
		mu_assert_eq(f->size, (sz), "file name table"); \
		mu_assert_eq(f->timestamp, (time), "file name time"); \
		mu_assert_eq(f->directory_index, (dir), "file name dir"); \
		mu_assert_streq(f->path_name, (path), "invalid_parameter_handler.c"); \
	}

#define CHECK_LINEOP_OPCODE(index, opc) \
	{ \
		RzBinDwarfLineOp *op = rz_vector_index_ptr(&lunit->ops, (index)); \
		mu_assert_eq(op->opcode, (opc), "lineop opcode"); \
	}
#define CHECK_LINEOP_TYPE(index, t) \
	{ \
		RzBinDwarfLineOp *op = rz_vector_index_ptr(&lunit->ops, (index)); \
		mu_assert_eq(op->type, (t), "lineop opcode"); \
	}

bool test_dwarf_cpp_empty_line_info(void) { // this should work for dwarf2 aswell
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/pe/hello_world_not_stripped.exe", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDwarfAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_abbrev_from_file(bin->cur, false);
	// not ignoring null entries -> 755 abbrevs
	mu_assert_eq(rz_bin_dwarf_abbrev_count(da), 731, "Incorrect number of abbreviation");

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(
		bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 25, "line units count");
	RzBinDwarfLineUnit *lunit = rz_pvector_tail(li->units);
	mu_assert_notnull(lunit, "line unit");

	RzBinDwarfLineUnitHdr *hdr = &lunit->hdr;
	mu_assert_eq(hdr->unit_length, 704, "");
	mu_assert_eq(hdr->encoding.version, 2, "");
	mu_assert_eq(hdr->min_inst_len, 1, "");
	mu_assert_eq(hdr->max_ops_per_inst, 1, "");
	mu_assert_eq(hdr->default_is_stmt, 1, "");
	mu_assert_eq(hdr->line_base, -5, "");
	mu_assert_eq(hdr->line_range, 14, "");
	mu_assert_eq(hdr->opcode_base, 13, "");

	ut8 opc[] = { 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1 };
	mu_assert_memeq(hdr->std_opcode_lengths, opc, hdr->opcode_base - 1, "opcodes");

	char *dir = NULL;
	dir = rz_pvector_at(&hdr->directories, 0);
	mu_assert_streq(dir, "../misc", "Directory table");
	dir = rz_pvector_at(&hdr->directories, 1);
	mu_assert_streq(dir, "/usr/local/Cellar/mingw-w64/5.0.4_1/toolchain-i686/i686-w64-mingw32/include", "Directory table");
	dir = rz_pvector_at(&hdr->directories, 2);
	mu_assert_streq(dir, "/usr/local/Cellar/mingw-w64/5.0.4_1/toolchain-i686/i686-w64-mingw32/include/psdk_inc", "Directory table");

	CHECK_LINEOP_FILE_ENTRY(0, 1, 0, 0, "invalid_parameter_handler.c");
	CHECK_LINEOP_FILE_ENTRY(1, 2, 0, 0, "interlockedapi.h");
	CHECK_LINEOP_FILE_ENTRY(2, 3, 0, 0, "intrin-impl.h");

	CHECK_LINEOP_FILE_ENTRY(14, 2, 0, 0, "wtypesbase.h");
	CHECK_LINEOP_FILE_ENTRY(15, 2, 0, 0, "unknwnbase.h");
	CHECK_LINEOP_FILE_ENTRY(16, 2, 0, 0, "objidlbase.h");

	CHECK_LINEOP_FILE_ENTRY(29, 2, 0, 0, "winsmcrd.h");
	CHECK_LINEOP_FILE_ENTRY(30, 2, 0, 0, "winscard.h");
	CHECK_LINEOP_FILE_ENTRY(31, 2, 0, 0, "commdlg.h");

	CHECK_LINEOP_OPCODE(0, DW_LNS_set_column);
	CHECK_LINEOP_OPCODE(1, DW_LNE_set_address);
	CHECK_LINEOP_OPCODE(2, DW_LNS_advance_line);

	CHECK_LINEOP_OPCODE(17, DW_LNS_copy);
	CHECK_LINEOP_OPCODE(18, DW_LNS_set_column);
	CHECK_LINEOP_TYPE(19, RZ_BIN_DWARF_LINE_OP_TYPE_SPEC);

	CHECK_LINEOP_OPCODE(33, DW_LNS_copy);
	CHECK_LINEOP_OPCODE(34, DW_LNS_advance_pc);
	CHECK_LINEOP_OPCODE(35, DW_LNE_end_sequence);

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

	rz_bin_dwarf_line_free(li);

	rz_bin_dwarf_abbrev_free(da);
	rz_io_free(io);
	rz_bin_free(bin);
	mu_end;
}

bool test_dwarf2_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf2_many_comp_units.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDwarfAbbrev *da = NULL;
	// mode = 0, calls
	// static void dump_r_bin_dwarf_debug_abbrev(FILE *f, RzBinDwarfDebugAbbrev *da)
	// which prints out all the abbreviation
	da = rz_bin_dwarf_abbrev_from_file(bin->cur, false);
	mu_assert_eq(rz_bin_dwarf_abbrev_count(da), 58, "Incorrect number of abbreviation");

	RzBinDwarfAbbrevTable *tbl = ht_up_find(da->by_offset, 0x0, NULL);
	RzBinDwarfAbbrevDecl *abbrev = NULL;
	RzBinDwarfAttrSpec *def = NULL;

	TEST_ABBREV_DECL(0, 0x0, DW_TAG_compile_unit, true, 8);
	TEST_ABBREV_ATTR(0, DW_AT_producer, DW_FORM_strp);
	TEST_ABBREV_ATTR(1, DW_AT_language, DW_FORM_data1);
	TEST_ABBREV_ATTR(2, DW_AT_name, DW_FORM_strp);
	TEST_ABBREV_ATTR(3, DW_AT_comp_dir, DW_FORM_strp);
	TEST_ABBREV_ATTR(4, DW_AT_ranges, DW_FORM_data4);
	TEST_ABBREV_ATTR(5, DW_AT_low_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(6, DW_AT_entry_pc, DW_FORM_addr);
	TEST_ABBREV_ATTR(7, DW_AT_stmt_list, DW_FORM_data4);

	TEST_ABBREV_DECL(18, 0x131, DW_TAG_formal_parameter, false, 4);
	TEST_ABBREV_ATTR(0, DW_AT_name, DW_FORM_strp);
	TEST_ABBREV_ATTR(1, DW_AT_type, DW_FORM_ref4);
	TEST_ABBREV_ATTR(2, DW_AT_artificial, DW_FORM_flag);
	TEST_ABBREV_ATTR(3, DW_AT_location, DW_FORM_block1);

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(
		bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 2, "line units count");
	mu_assert_notnull(li->lines, "line info");
	const RzBinSourceLineSample test_line_samples[] = {
		{ 0x118a, 3, 3, "mammal.cpp" },
		{ 0x1196, 3, 19, "mammal.cpp" },
		{ 0x11a4, 3, 22, "mammal.cpp" },
		{ 0x11a8, 3, 3, "mammal.cpp" },
		{ 0x11b8, 3, 22, "mammal.cpp" },
		{ 0x11d8, 4, 22, "mammal.cpp" },
		{ 0x11e4, 4, 31, "mammal.cpp" },
		{ 0x11e9, 4, 34, "mammal.cpp" },
		{ 0x11eb, 10, 12, "mammal.cpp" },
		{ 0x11f7, 10, 12, "mammal.cpp" },
		{ 0x1206, 12, 23, "mammal.cpp" },
		{ 0x1212, 13, 1, "mammal.cpp" },
		{ 0x1228, 7, 6, "mammal.cpp" },
		{ 0x1234, 7, 26, "mammal.cpp" },
		{ 0x1239, 7, 28, "mammal.cpp" },
		{ 0x123b, 15, 12, "main.cpp" },
		{ 0x1248, 18, 16, "main.cpp" },
		{ 0x125d, 18, 5, "main.cpp" },
		{ 0x1261, 19, 15, "main.cpp" },
		{ 0x1276, 19, 5, "main.cpp" },
		{ 0x127a, 20, 7, "main.cpp" },
		{ 0x1281, 21, 20, "main.cpp" },
		{ 0x128f, 21, 19, "main.cpp" },
		{ 0x1298, 21, 10, "main.cpp" },
		{ 0x129b, 22, 21, "main.cpp" },
		{ 0x12a9, 22, 20, "main.cpp" },
		{ 0x12b2, 22, 10, "main.cpp" },
		{ 0x12b5, 23, 23, "main.cpp" },
		{ 0x12ba, 23, 24, "main.cpp" },
		{ 0x12bf, 24, 1, "main.cpp" },
		{ 0x12c6, 2, 3, "mammal.h" },
		{ 0x12d2, 2, 12, "mammal.h" },
		{ 0x12e0, 2, 15, "mammal.h" },
		{ 0x12e3, 0, 0, NULL },
		{ 0x12e4, 4, 3, "main.cpp" },
		{ 0x12f4, 4, 9, "main.cpp" },
		{ 0x130e, 4, 12, "main.cpp" },
		{ 0x1311, 0, 0, NULL },
		{ 0x1312, 5, 11, "main.cpp" },
		{ 0x1322, 5, 18, "main.cpp" },
		{ 0x133c, 5, 19, "main.cpp" },
		{ 0x133f, 0, 0, NULL },
		{ 0x1340, 5, 11, "main.cpp" },
		{ 0x1350, 5, 19, "main.cpp" },
		{ 0x136f, 0, 0, NULL },
		{ 0x1370, 6, 15, "main.cpp" },
		{ 0x137c, 6, 31, "main.cpp" },
		{ 0x1381, 6, 34, "main.cpp" },
		{ 0x1383, 0, 0, NULL },
		{ 0x1384, 10, 3, "main.cpp" },
		{ 0x1390, 10, 10, "main.cpp" },
		{ 0x139e, 10, 13, "main.cpp" },
		{ 0x13a1, 0, 0, NULL },
		{ 0x13a2, 11, 11, "main.cpp" },
		{ 0x13ae, 11, 19, "main.cpp" },
		{ 0x13bc, 11, 20, "main.cpp" },
		{ 0x13bf, 0, 0, NULL },
		{ 0x13c0, 11, 11, "main.cpp" },
		{ 0x13d0, 11, 20, "main.cpp" },
		{ 0x13ef, 0, 0, NULL },
		{ 0x13f0, 12, 15, "main.cpp" },
		{ 0x13fc, 12, 30, "main.cpp" },
		{ 0x1401, 12, 33, "main.cpp" },
		{ 0x1403, 0, 0, NULL }
	};
	assert_line_samples_eq(li->lines, RZ_ARRAY_SIZE(test_line_samples), test_line_samples);
	rz_bin_dwarf_line_free(li);

	rz_bin_dwarf_abbrev_free(da);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_cpp_many_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	// TODO add abbrev checks

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(
		bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 2, "line units count");
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
	rz_bin_dwarf_line_free(li);

	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_multidir_comp_units(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf4_multidir_comp_units", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);
	mu_assert_notnull(dw, "DWARF");

	RzBinDwarfAbbrev *da = rz_bin_dwarf_abbrev_from_file(bin->cur, false);
	mu_assert_notnull(da, "abbrevs");
	mu_assert_eq(rz_bin_dwarf_abbrev_count(da), 8, "abbrevs count");

	RzBinDwarfInfo *info = dw->info;
	mu_assert_notnull(info, "info");

	RzBinDwarfLine *li = dw->line;
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 2, "line units count");
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

	rz_bin_dwarf_abbrev_free(da);
	rz_bin_dwarf_free(dw);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_big_endian_dwarf2(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/ppc64_sudoku_dwarf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDwarfLine *li = rz_bin_dwarf_line_from_file(bin->cur, NULL, false);
	mu_assert_notnull(li, "line info");
	mu_assert_eq(rz_pvector_len(li->units), 1, "line units count");
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
	rz_bin_dwarf_line_free(li);

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
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf3_many_comp_units.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDwarfARanges *aranges = rz_bin_dwarf_aranges_from_file(bin->cur);
	mu_assert_eq(rz_list_length(aranges->list), 2, "arange sets count");

	RzBinDwarfARangeSet *set = rz_list_get_n(aranges->list, 0);
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

	set = rz_list_get_n(aranges->list, 1);
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

	rz_bin_dwarf_aranges_free(aranges);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf5_loclists(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/float_ex1/float_ex1_arm", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);
	mu_assert_notnull(dw->loclists, ".debug_loclists");

	mu_assert_notnull(dw->info, ".debug_info");
	RzBinDwarfCompUnit *cu = rz_vector_head(&dw->info->units);
	mu_assert_notnull(cu, ".debug_info unit");
	RzBinDwarfLocList *loclist =
		rz_bin_dwarf_loclists_get(dw->loclists, dw->addr, cu, 0x00000012);
	mu_assert_notnull(loclist, "loclist");

	{
		RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 0);
		mu_assert_notnull(entry, "entry");
		mu_assert_eq(entry->range.begin, 0x4c0, "entry begin");
		mu_assert_eq(entry->range.end, 0x4de, "entry end");

		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
		mu_assert_notnull(loc, "location");
		mu_assert_eq(loc->kind, RzBinDwarfLocationKind_REGISTER, "piece kind");
		mu_assert_eq(loc->register_number, 0, "piece reg");
		rz_bin_dwarf_location_free(loc);
	}

	{
		RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 1);
		mu_assert_notnull(entry, "entry");
		mu_assert_eq(entry->range.begin, 0x4de, "entry begin");
		mu_assert_eq(entry->range.end, 0x4e1, "entry end");

		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
		mu_assert_notnull(loc, "location");
		mu_assert_eq(loc->kind, RzBinDwarfLocationKind_REGISTER_OFFSET, "piece kind");
		mu_assert_eq(loc->register_number, 2, "piece reg");
		mu_assert_eq(loc->offset, -4, "piece reg");
		rz_bin_dwarf_location_free(loc);
	}

	{
		RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 2);
		mu_assert_notnull(entry, "entry");
		mu_assert_eq(entry->range.begin, 0x4e1, "entry begin");
		mu_assert_eq(entry->range.end, 0x4f8, "entry end");

		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
		mu_assert_notnull(loc, "location");
		mu_assert_eq(loc->kind, RzBinDwarfLocationKind_EVALUATION_WAITING, "piece kind");
		mu_assert("eval waiting", loc->eval_waiting.eval && loc->eval_waiting.result);
		rz_bin_dwarf_location_free(loc);
	}

	rz_bin_dwarf_free(dw);
	rz_bin_free(bin);
	rz_io_free(io);
	mu_end;
}

bool test_dwarf4_loclists(void) {
	RzBin *bin = rz_bin_new();
	RzIO *io = rz_io_new();
	rz_io_bind(io, &bin->iob);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/pe/vista-glass.exe", &opt);
	mu_assert_notnull(bf, "couldn't open file");

	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);
	mu_assert_notnull(dw->loclists, ".debug_loc");
	mu_assert_notnull(dw->info, ".debug_info");

	RzBinDwarfCompUnit *cu = rz_vector_index_ptr(&dw->info->units, 0);
	RzBinDwarfLocList *loclist =
		rz_bin_dwarf_loclists_get(dw->loclists, dw->addr, cu, 0);
	mu_assert_notnull(loclist, "loclist");

	{
		RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 0);
		mu_assert_notnull(entry, "entry");
		mu_assert_eq(entry->range.begin, 0x4013b0, "entry begin");
		mu_assert_eq(entry->range.end, 0x4013b4, "entry end");

		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
		mu_assert_notnull(loc, "location");
		mu_assert_eq(loc->kind, RzBinDwarfLocationKind_REGISTER_OFFSET, "piece kind");
		mu_assert_eq(loc->register_number, 4, "piece reg");
		mu_assert_eq(loc->offset, 4, "piece reg offset");
		rz_bin_dwarf_location_free(loc);
	}

	{
		RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 1);
		mu_assert_notnull(entry, "entry");
		mu_assert_eq(entry->range.begin, 0x4013b4, "entry begin");
		mu_assert_eq(entry->range.end, 0x4013c0, "entry end");

		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
		mu_assert_notnull(loc, "location");
		mu_assert_eq(loc->kind, RzBinDwarfLocationKind_REGISTER, "piece kind");
		mu_assert_eq(loc->register_number, 1, "piece reg");
		rz_bin_dwarf_location_free(loc);
	}

	{
		RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 2);
		mu_assert_notnull(entry, "entry");
		mu_assert_eq(entry->range.begin, 0x4013c0, "entry begin");
		mu_assert_eq(entry->range.end, 0x401728, "entry end");

		RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
		mu_assert_notnull(loc, "location");
		mu_assert_eq(loc->kind, RzBinDwarfLocationKind_EVALUATION_WAITING, "piece kind");
		mu_assert("eval waiting", loc->eval_waiting.eval && loc->eval_waiting.result);
		rz_bin_dwarf_location_free(loc);
	}

	rz_bin_dwarf_free(dw);
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
	mu_run_test(test_dwarf5_loclists);
	mu_run_test(test_dwarf4_loclists);
	return tests_passed != tests_run;
}

mu_main(all_tests)
