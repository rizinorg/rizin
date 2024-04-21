// SPDX-FileCopyrightText: 2020 HoundThe <cgkajm@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_bin.h>
#include <rz_type.h>
#include <rz_util/rz_path.h>
#include "test_config.h"
#include "test_types.h"
#include "../unit/minunit.h"

#define check_fn(addr, name, sig) \
	{ \
		RzAnalysisDwarfFunction *f = ht_up_find(analysis->debug_info->function_by_addr, addr, NULL); \
		mu_assert_notnull(f, "No function at 0x401300"); \
		mu_assert_streq(f->prefer_name, name, "fn name"); \
		RzCallable *c = rz_type_func_get(analysis->typedb, f->prefer_name); \
		mu_assert_streq_free(rz_type_callable_as_string(analysis->typedb, c), sig, "fn sig"); \
	}

static bool test_parse_dwarf_types(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core->bin, "Couldn't create new RzBin");
	mu_assert_notnull(core->io, "Couldn't create new RzIO");
	mu_assert_notnull(core->analysis, "Couldn't create new RzAnalysis");
	RzAnalysis *analysis = core->analysis;
	RzBin *bin = core->bin;

	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_set_cpu(analysis, "x86");
	rz_analysis_set_bits(analysis, 32);
	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	rz_type_db_init(analysis->typedb, types_dir, "x86", 32, "linux");
	free(types_dir);

	RzBinOptions opt = { 0 };
	RzBinFile *bf = rz_bin_open(bin, "bins/pe/vista-glass.exe", &opt);
	mu_assert_notnull(bf, "couldn't open file");
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 32);
	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);

	mu_assert_notnull(dw->abbrev, "Couldn't parse Abbreviations");
	mu_assert_notnull(dw->info, "Couldn't parse debug_info section");
	mu_assert_notnull(dw->loclists, "Couldn't parse loc section");

	rz_analysis_dwarf_process_info(analysis, dw);

	// Check the enum presence and validity
	RzBaseType *cairo = rz_type_db_get_base_type(analysis->typedb, "_cairo_status");
	mu_assert_notnull(cairo, "Couldn't find _cairo_status");
	mu_assert_eq(cairo->kind, RZ_BASE_TYPE_KIND_ENUM, "_cairo_status is enum");
	mu_assert_true(has_enum_val(cairo, "CAIRO_STATUS_SUCCESS", 0), "CAIRO_STATUS_SUCCESS = 0x0");
	mu_assert_true(has_enum_val(cairo, "CAIRO_STATUS_INVALID_PATH_DATA", 0x9), "CAIRO_STATUS_INVALID_PATH_DATA = 0x9");
	mu_assert_true(has_enum_val(cairo, "CAIRO_STATUS_INVALID_WEIGHT", 0x1f), "CAIRO_STATUS_INVALID_WEIGHT = 0x1f");
	mu_assert_null(rz_type_db_enum_member_by_val(analysis->typedb, "_cairo_status", 0x20), "no 0x20 member");

	RzBaseType *cairo1 = rz_type_db_get_enum(analysis->typedb, "_cairo_status");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_SUCCESS"), "CAIRO_STATUS_SUCCESS");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_NO_MEMORY"), "CAIRO_STATUS_NO_MEMORY");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_RESTORE"), "CAIRO_STATUS_INVALID_RESTORE");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_POP_GROUP"), "CAIRO_STATUS_INVALID_POP_GROUP");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_NO_CURRENT_POINT"), "CAIRO_STATUS_NO_CURRENT_POINT");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_MATRIX"), "CAIRO_STATUS_INVALID_MATRIX");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_STATUS"), "CAIRO_STATUS_INVALID_STATUS");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_NULL_POINTER"), "CAIRO_STATUS_NULL_POINTER");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_STRING"), "CAIRO_STATUS_INVALID_STRING");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_PATH_DATA"), "CAIRO_STATUS_INVALID_PATH_DATA");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_READ_ERROR"), "CAIRO_STATUS_READ_ERROR");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_WRITE_ERROR"), "CAIRO_STATUS_WRITE_ERROR");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_SURFACE_FINISHED"), "CAIRO_STATUS_SURFACE_FINISHED");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_SURFACE_TYPE_MISMATCH"), "CAIRO_STATUS_SURFACE_TYPE_MISMATCH");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_PATTERN_TYPE_MISMATCH"), "CAIRO_STATUS_PATTERN_TYPE_MISMATCH");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_CONTENT"), "CAIRO_STATUS_INVALID_CONTENT");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_FORMAT"), "CAIRO_STATUS_INVALID_FORMAT");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_VISUAL"), "CAIRO_STATUS_INVALID_VISUAL");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_FILE_NOT_FOUND"), "CAIRO_STATUS_FILE_NOT_FOUND");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_DASH"), "CAIRO_STATUS_INVALID_DASH");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_DSC_COMMENT"), "CAIRO_STATUS_INVALID_DSC_COMMENT");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_INDEX"), "CAIRO_STATUS_INVALID_INDEX");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_CLIP_NOT_REPRESENTABLE"), "CAIRO_STATUS_CLIP_NOT_REPRESENTABLE");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_TEMP_FILE_ERROR"), "CAIRO_STATUS_TEMP_FILE_ERROR");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_STRIDE"), "CAIRO_STATUS_INVALID_STRIDE");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_FONT_TYPE_MISMATCH"), "CAIRO_STATUS_FONT_TYPE_MISMATCH");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_USER_FONT_IMMUTABLE"), "CAIRO_STATUS_USER_FONT_IMMUTABLE");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_USER_FONT_ERROR"), "CAIRO_STATUS_USER_FONT_ERROR");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_NEGATIVE_COUNT"), "CAIRO_STATUS_NEGATIVE_COUNT");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_CLUSTERS"), "CAIRO_STATUS_INVALID_CLUSTERS");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_SLANT"), "CAIRO_STATUS_INVALID_SLANT");
	mu_assert_true(has_enum_case(cairo1, "CAIRO_STATUS_INVALID_WEIGHT"), "CAIRO_STATUS_INVALID_WEIGHT");

	mu_assert_false(has_enum_case(cairo1, "CAIRO_NO_SUCH_CASE"), "no such enum case");

	// Check the structure presence and validity
	RzBaseType *margins = rz_type_db_get_base_type(analysis->typedb, "_MARGINS");
	mu_assert_eq(margins->kind, RZ_BASE_TYPE_KIND_STRUCT, "_MARGINS is struct");
	mu_assert_true(has_struct_member(margins, "cxLeftWidth"), "cxLeftWidth");
	mu_assert_true(has_struct_member(margins, "cxRightWidth"), "cxRightWidth");
	mu_assert_true(has_struct_member(margins, "cyTopHeight"), "cyTopHeight");
	mu_assert_true(has_struct_member(margins, "cyBottomHeight"), "cyBottomHeight");

	mu_assert_false(has_struct_member(margins, "noSuchMember"), "no such struct member");

	// Check the union presence and validity
	RzBaseType *unaligned = rz_type_db_get_base_type(analysis->typedb, "unaligned");
	mu_assert_notnull(unaligned, "unaligned exists");
	mu_assert_eq(unaligned->kind, RZ_BASE_TYPE_KIND_UNION, "unaligned is union");
	mu_assert_true(has_union_member(unaligned, "ptr"), "ptr");
	mu_assert_true(has_union_member(unaligned, "u2"), "u2");
	mu_assert_true(has_union_member(unaligned, "u4"), "u4");
	mu_assert_true(has_union_member(unaligned, "u8"), "u8");
	mu_assert_true(has_union_member(unaligned, "s2"), "s2");
	mu_assert_true(has_union_member(unaligned, "s4"), "s4");
	mu_assert_true(has_union_member(unaligned, "s8"), "s8");

	mu_assert_false(has_union_member(unaligned, "noSuchMember"), "no such union member");
	// TODO: Check also the exact types of the members
	// check_kv("union.unaligned.u2", "short unsigned int,0,0");
	// check_kv("union.unaligned.s8", "long long int,0,0");

	rz_bin_dwarf_free(dw);
	rz_core_free(core);
	mu_end;
}

static bool test_dwarf_function_parsing_cpp(void) {
#if WITH_GPL
	RzCore *core = rz_core_new();
	mu_assert_notnull(core->bin, "Couldn't create new RzBin");
	mu_assert_notnull(core->io, "Couldn't create new RzIO");
	mu_assert_notnull(core->analysis, "Couldn't create new RzAnalysis");
	RzAnalysis *analysis = core->analysis;
	RzBin *bin = core->bin;

	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_set_cpu(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	rz_type_db_init(analysis->typedb, TEST_BUILD_TYPES_DIR, "x86", 64, "linux");

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	mu_assert_notnull(bf, "couldn't open file");
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);
	mu_assert_notnull(dw->abbrev, "Couldn't parse Abbreviations");
	mu_assert_notnull(dw->info, "Couldn't parse debug_info section");

	rz_analysis_dwarf_process_info(analysis, dw);

	mu_assert_notnull(analysis->debug_info, "Couldn't get debug info");

	check_fn(0x401300, "Mammal::Mammal()", "void Mammal::Mammal()(struct Mammal *this)");
	check_fn(0x401380, "Dog::walk()", "int Dog::walk()(struct Dog *this)");
	check_fn(0x401390, "Mammal::~Mammal()", "void Mammal::~Mammal()(struct Mammal *this)");
	check_fn(0x401160, "main", "int main()");

	rz_bin_dwarf_free(dw);
	rz_core_free(core);
#endif
	mu_end;
}

static bool test_dwarf_function_parsing_go(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core->bin, "Couldn't create new RzBin");
	mu_assert_notnull(core->io, "Couldn't create new RzIO");
	mu_assert_notnull(core->analysis, "Couldn't create new RzAnalysis");
	RzAnalysis *analysis = core->analysis;
	RzBin *bin = core->bin;

	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_set_cpu(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf_go_tree", &opt);
	mu_assert_notnull(bf, "couldn't open file");
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);
	mu_assert_notnull(dw->abbrev, "Couldn't parse Abbreviations");
	mu_assert_notnull(dw->info, "Couldn't parse debug_info section");
	mu_assert_notnull(dw->loclists, "Couldn't parse loc section");

	rz_analysis_dwarf_process_info(analysis, dw);

	mu_assert_notnull(analysis->debug_info, "Couldn't get debug info");
	check_fn(0x491980, "main.main", "void main.main()");
	check_fn(0x491d90, "main.tree.iterInorder", "void main.tree.iterInorder(main.tree t, func(int) visit)");

	/* We do not parse variable information from .debug_frame that is this Go binary using, so
	   don't check variable information and add it in the future */

	rz_bin_dwarf_free(dw);
	rz_core_free(core);
	mu_end;
}

static bool test_dwarf_function_parsing_rust(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core->bin, "Couldn't create new RzBin");
	mu_assert_notnull(core->io, "Couldn't create new RzIO");
	mu_assert_notnull(core->analysis, "Couldn't create new RzAnalysis");
	RzAnalysis *analysis = core->analysis;
	RzBin *bin = core->bin;

	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_set_cpu(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	char *types_dir = rz_path_system(RZ_SDB_TYPES);
	rz_type_db_init(analysis->typedb, types_dir, "x86", 64, "linux");
	free(types_dir);

	RzBinOptions opt = { 0 };
	rz_bin_options_init(&opt, 0, 0, 0, false);
	RzBinFile *bf = rz_bin_open(bin, "bins/elf/dwarf_rust_bubble", &opt);
	mu_assert_notnull(bf, "couldn't open file");
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);
	RzBinDWARF *dw = rz_bin_dwarf_from_file(bf);

	mu_assert_notnull(dw->abbrev, "Couldn't parse Abbreviations");
	mu_assert_notnull(dw->info, "Couldn't parse debug_info section");
	mu_assert_notnull(dw->loclists, "Couldn't parse loc section");

	rz_analysis_dwarf_process_info(analysis, dw);

	mu_assert_notnull(analysis->debug_info, "Couldn't get debug info");
	check_fn(0x5750, "main", "void main()");
	check_fn(0x5270, "bubble_sort<i32>", "void bubble_sort<i32>(struct &mut [i32] values)");
	check_fn(0x8730, "lang_start_internal", "isize lang_start_internal(struct &Fn<()> main, isize argc, u8 **argv)");

	RzBinDwarfCompUnit *cu = ht_up_find(dw->info->unit_by_offset, 0x4151, NULL);
	mu_assert_notnull(cu, "Couldn't get compunit");
	RzBinDwarfLocList *loclist = rz_bin_dwarf_loclists_get(dw->loclists, dw->addr, cu, 0xd973);
	mu_assert_notnull(loclist, "Couldn't get loclist");
	RzBinDwarfLocListEntry *entry = rz_pvector_at(&loclist->entries, 0);
	mu_assert_notnull(entry, "Couldn't get entry");
	mu_assert_notnull(entry->expression, "Couldn't get entry expression");
	mu_assert_eq(entry->range.begin, 0x84e1, "Err entry begin");
	mu_assert_eq(entry->range.end, 0x84fc, "Err entry end");
	RzBinDwarfLocation *loc = rz_bin_dwarf_location_from_block(entry->expression, dw, cu, NULL);
	mu_assert_notnull(loc, "Couldn't get location");
	RzBinDWARFDumpOption dump_option = {
		.composite_sep = ", "
	};
	char *locstr = rz_bin_dwarf_location_to_string(loc, &dump_option);
	mu_assert_streq_free(locstr, "composite: [(.0, 64): stack+18, (.0, 64): stack+8]", "Error location string");
	rz_bin_dwarf_location_free(loc);

	rz_bin_dwarf_free(dw);
	rz_core_free(core);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_parse_dwarf_types);
	mu_run_test(test_dwarf_function_parsing_cpp);
	mu_run_test(test_dwarf_function_parsing_rust);
	mu_run_test(test_dwarf_function_parsing_go);
	return tests_passed != tests_run;
}

mu_main(all_tests)
