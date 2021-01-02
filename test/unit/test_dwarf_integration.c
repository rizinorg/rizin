#include <rz_analysis.h>
#include <rz_bin.h>
#include "minunit.h"

#define MODE 2

#define check_kv(k, v)                                                         \
	do {                                                                   \
		value = sdb_get (sdb, k, NULL);                    \
		mu_assert_nullable_streq (value, v, "Wrong key - value pair"); \
	} while (0)

static bool test_parse_dwarf_types(void) {
	RzBin *bin = rz_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RzBin");
	RzIO *io = rz_io_new ();
	mu_assert_notnull (io, "Couldn't create new RzIO");
	RzAnalysis *analysis = rz_analysis_new ();
	mu_assert_notnull (analysis, "Couldn't create new RzAnalysis");
	rz_io_bind (io, &bin->iob);
	analysis->binb.demangle = rz_bin_demangle;
	RzBinOptions opt = { 0 };
	bool res = rz_bin_open (bin, "bins/pe/vista-glass.exe", &opt);
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	analysis->cpu = strdup ("x86");
	analysis->bits = 32;
	mu_assert ("pe/vista-glass.exe binary could not be opened", res);
	mu_assert_notnull (analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");
	RzBinDwarfDebugAbbrev *abbrevs = rz_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");

	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc (bin, 4);
	RzAnalysisDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	rz_analysis_dwarf_process_info (analysis, &ctx);

	char * value = NULL;
	Sdb *sdb = analysis->sdb_types;
	check_kv ("_cairo_status", "enum");
	check_kv ("enum._cairo_status.0x0", "CAIRO_STATUS_SUCCESS");
	check_kv ("enum._cairo_status.CAIRO_STATUS_SUCCESS", "0x0");
	check_kv ("enum._cairo_status.0x9", "CAIRO_STATUS_INVALID_PATH_DATA");
	check_kv ("enum._cairo_status.CAIRO_STATUS_INVALID_PATH_DATA", "0x9");
	check_kv ("enum._cairo_status.0x1f", "CAIRO_STATUS_INVALID_WEIGHT");
	check_kv ("enum._cairo_status.CAIRO_STATUS_INVALID_WEIGHT", "0x1f");
	check_kv ("enum._cairo_status.0x20", NULL);
	check_kv ("enum._cairo_status", "CAIRO_STATUS_SUCCESS,CAIRO_STATUS_NO_MEMORY" 
	",CAIRO_STATUS_INVALID_RESTORE,CAIRO_STATUS_INVALID_POP_GROUP,CAIRO_STATUS_NO_CURRENT_POINT"
	",CAIRO_STATUS_INVALID_MATRIX,CAIRO_STATUS_INVALID_STATUS,CAIRO_STATUS_NULL_POINTER,"
	"CAIRO_STATUS_INVALID_STRING,CAIRO_STATUS_INVALID_PATH_DATA,CAIRO_STATUS_READ_ERROR,"
	"CAIRO_STATUS_WRITE_ERROR,CAIRO_STATUS_SURFACE_FINISHED,CAIRO_STATUS_SURFACE_TYPE_MISMATCH,"
	"CAIRO_STATUS_PATTERN_TYPE_MISMATCH,CAIRO_STATUS_INVALID_CONTENT,CAIRO_STATUS_INVALID_FORMAT,"
	"CAIRO_STATUS_INVALID_VISUAL,CAIRO_STATUS_FILE_NOT_FOUND,CAIRO_STATUS_INVALID_DASH,"
	"CAIRO_STATUS_INVALID_DSC_COMMENT,CAIRO_STATUS_INVALID_INDEX,CAIRO_STATUS_CLIP_NOT_REPRESENTABLE,"
	"CAIRO_STATUS_TEMP_FILE_ERROR,CAIRO_STATUS_INVALID_STRIDE,"
	"CAIRO_STATUS_FONT_TYPE_MISMATCH,CAIRO_STATUS_USER_FONT_IMMUTABLE,CAIRO_STATUS_USER_FONT_ERROR,"
	"CAIRO_STATUS_NEGATIVE_COUNT,CAIRO_STATUS_INVALID_CLUSTERS,"
	"CAIRO_STATUS_INVALID_SLANT,CAIRO_STATUS_INVALID_WEIGHT");

	check_kv ("_MARGINS", "struct");
	// TODO evaluate member_location operations in DWARF to get offset and test it
	check_kv ("struct._MARGINS", "cxLeftWidth,cxRightWidth,cyTopHeight,cyBottomHeight");

	check_kv ("unaligned", "union");
	check_kv ("union.unaligned", "ptr,u2,u4,u8,s2,s4,s8");
	check_kv ("union.unaligned.u2", "short unsigned int,0,0");
	check_kv ("union.unaligned.s8", "long long int,0,0");
	rz_bin_dwarf_free_debug_info (info);
	rz_bin_dwarf_free_debug_abbrev (abbrevs);
	rz_analysis_free (analysis);
	rz_bin_free (bin);
	rz_io_free (io);
	mu_end;
}

static bool test_dwarf_function_parsing_cpp(void) {
	RzBin *bin = rz_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RzBin");
	RzIO *io = rz_io_new ();
	mu_assert_notnull (io, "Couldn't create new RzIO");
	RzAnalysis *analysis = rz_analysis_new ();
	mu_assert_notnull (analysis, "Couldn't create new RzAnalysis");
	rz_io_bind (io, &bin->iob);
	analysis->binb.demangle = rz_bin_demangle;

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open (bin, "bins/elf/dwarf4_many_comp_units.elf", &opt);
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	analysis->cpu = strdup ("x86");
	analysis->bits = 64;
	mu_assert ("elf/dwarf4_many_comp_units.elf binary could not be opened", res);
	mu_assert_notnull (analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");
	RzBinDwarfDebugAbbrev *abbrevs = rz_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc (bin, 8);

	RzAnalysisDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	rz_analysis_dwarf_process_info (analysis, &ctx);

	Sdb *sdb = sdb_ns (analysis->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	char *value = NULL;
	check_kv ("Mammal", "fcn");
	check_kv ("fcn.Mammal.addr", "0x401300");
	check_kv ("fcn.Mammal.sig", "void Mammal(Mammal * this);");
	check_kv ("fcn.Dog::walk__.addr", "0x401380");
	check_kv ("fcn.Dog::walk__.sig", "int Dog::walk()(Dog * this);");
	check_kv ("fcn.Dog::walk__.name", "Dog::walk()");
	check_kv ("fcn.Mammal::walk__.vars", "this");
	check_kv ("fcn.Mammal::walk__.var.this", "b,-8,Mammal *");

	check_kv ("main", "fcn");
	check_kv ("fcn.main.addr", "0x401160");
	check_kv ("fcn.main.sig", "int main();");
	check_kv ("fcn.main.vars", "b,m,output");
	check_kv ("fcn.main.var.output", "b,-40,int");

	rz_bin_dwarf_free_debug_info (info);
	rz_bin_dwarf_free_debug_abbrev (abbrevs);
	rz_bin_dwarf_free_loc (loc_table);
	rz_analysis_free (analysis);
	rz_bin_free (bin);
	rz_io_free (io);
	mu_end;
}

static bool test_dwarf_function_parsing_go(void) {
	RzBin *bin = rz_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RzBin");
	RzIO *io = rz_io_new ();
	mu_assert_notnull (io, "Couldn't create new RzIO");
	RzAnalysis *analysis = rz_analysis_new ();
	mu_assert_notnull (analysis, "Couldn't create new RzAnalysis");
	rz_io_bind (io, &bin->iob);
	analysis->binb.demangle = rz_bin_demangle;

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open (bin, "bins/elf/dwarf_go_tree", &opt);
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	analysis->cpu = strdup ("x86");
	analysis->bits = 64;
	mu_assert ("bins/elf/dwarf_go_tree", res);
	mu_assert_notnull (analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");
	RzBinDwarfDebugAbbrev *abbrevs = rz_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc (bin, 8);

	RzAnalysisDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	rz_analysis_dwarf_process_info (analysis, &ctx);

	Sdb *sdb = sdb_ns (analysis->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	char *value = NULL;

	check_kv ("main_main", "fcn");
	check_kv ("fcn.main_main.name", "main.main");
	check_kv ("fcn.main_main.addr", "0x491980");

	check_kv ("main_tree_iterInorder", "fcn");
	check_kv ("fcn.main_tree_iterInorder.name", "main.tree.iterInorder");
	check_kv ("fcn.main_tree_iterInorder.addr", "0x491d90");
	check_kv ("fcn.main_tree_iterInorder.sig", "void main.tree.iterInorder(main.tree t,func(int) visit);");

	/* We do not parse variable information from .debug_frame that is this Go binary using, so
	   don't check variable information and add it in the future */

	rz_bin_dwarf_free_debug_info (info);
	rz_bin_dwarf_free_debug_abbrev (abbrevs);
	rz_bin_dwarf_free_loc (loc_table);
	rz_analysis_free (analysis);
	rz_bin_free (bin);
	rz_io_free (io);
	mu_end;
}

static bool test_dwarf_function_parsing_rust(void) {
	RzBin *bin = rz_bin_new ();
	mu_assert_notnull (bin, "Couldn't create new RzBin");
	RzIO *io = rz_io_new ();
	mu_assert_notnull (io, "Couldn't create new RzIO");
	RzAnalysis *analysis = rz_analysis_new ();
	mu_assert_notnull (analysis, "Couldn't create new RzAnalysis");
	rz_io_bind (io, &bin->iob);
	analysis->binb.demangle = rz_bin_demangle;

	RzBinOptions opt = { 0 };
	bool res = rz_bin_open (bin, "bins/elf/dwarf_rust_bubble", &opt);
	// TODO fix, how to correctly promote binary info to the RzAnalysis in unit tests?
	analysis->cpu = strdup ("x86");
	analysis->bits = 64;
	mu_assert ("bins/elf/dwarf_rust_bubble", res);
	mu_assert_notnull (analysis->sdb_types, "Couldn't create new RzAnalysis.sdb_types");
	RzBinDwarfDebugAbbrev *abbrevs = rz_bin_dwarf_parse_abbrev (bin, MODE);
	mu_assert_notnull (abbrevs, "Couldn't parse Abbreviations");
	RzBinDwarfDebugInfo *info = rz_bin_dwarf_parse_info (abbrevs, bin, MODE);
	mu_assert_notnull (info, "Couldn't parse debug_info section");
	HtUP /*<offset, List *<LocListEntry>*/ *loc_table = rz_bin_dwarf_parse_loc (bin, 8);

	RzAnalysisDwarfContext ctx = {
		.info = info,
		.loc = loc_table
	};
	rz_analysis_dwarf_process_info (analysis, &ctx);

	Sdb *sdb = sdb_ns (analysis->sdb, "dwarf", 0);
	mu_assert_notnull (sdb, "No dwarf function information in db");
	char *value = NULL;

	check_kv ("fcn.main.addr", "0x5750");
	check_kv ("fcn.main.name", "main");
	check_kv ("fcn.main.var.numbers", "s,128,i32[11]");
	check_kv ("fcn.main.var.strings", "s,312,&str[6]");
	// check_kv ("fcn.main.vars", "numbers,arg0,arg0,strings,arg0,arg0"); Fix these collision by unique renaming in future
	check_kv ("fcn.lang_start_internal.sig", "isize lang_start_internal(&Fn<()> main,isize argc,u8 ** argv);");

	check_kv ("bubble_sort__str_", "fcn");
	check_kv ("bubble_sort_i32_", "fcn");
	check_kv ("fcn.bubble_sort_i32_.vars", "values,n,swapped,iter,__next,val,i");
	check_kv ("fcn.bubble_sort_i32_.var.iter", "s,112,Range<usize>");
	check_kv ("fcn.bubble_sort_i32_.var.i", "s,176,usize");
	check_kv ("fcn.bubble_sort_i32_.name", "bubble_sort<i32>");
	check_kv ("fcn.bubble_sort_i32_.addr", "0x5270");

	rz_bin_dwarf_free_debug_info (info);
	rz_bin_dwarf_free_debug_abbrev (abbrevs);
	rz_bin_dwarf_free_loc (loc_table);
	rz_analysis_free (analysis);
	rz_bin_free (bin);
	rz_io_free (io);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_parse_dwarf_types);
	mu_run_test (test_dwarf_function_parsing_cpp);
	mu_run_test (test_dwarf_function_parsing_go);
	mu_run_test (test_dwarf_function_parsing_rust);
	return tests_passed != tests_run;
}

mu_main (all_tests)