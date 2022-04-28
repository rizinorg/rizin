// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_sign.h>

#include "../unit/minunit.h"

static bool test_analysis_sign_za_mips(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "Couldn't create new RzCore");
	ut64 loadaddr = 0;
	const char *fpath = "bins/elf/ld-uClibc-0.9.33.2.so";
	RzCoreFile *file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "open file");
	rz_core_bin_load(core, fpath, loadaddr);

	bool analyze_recursively = rz_config_get_i(core->config, "analysis.calls");
	bool is_added = rz_core_analysis_function_add(core, NULL, 0x2a1c, analyze_recursively);
	mu_assert_eq(is_added, true, "Couldn't add fcn");

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0x2a1c);
	mu_assert_notnull(fcn, "Couldn't get fcn");

	RzSignItem *it = rz_sign_item_new();
	mu_assert_notnull(it, "Couldn't create new RzSignItem");
	char *zigname = NULL;
	zigname = rz_str_new(fcn->name);
	it->name = zigname;
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_GRAPH);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_BYTES);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_XREFS);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_REFS);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_VARS);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_TYPES);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_BBHASH);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_OFFSET);
	rz_sign_addto_item(core->analysis, it, fcn, RZ_SIGN_NAME);
	is_added = rz_sign_add_item(core->analysis, it);
	mu_assert_eq(is_added, true, "Couldn't add RzSignItem");
	rz_sign_item_free(it);

	it = rz_sign_get_item(core->analysis, fcn->name);
	mu_assert_notnull(it, "Couldn't get RzSignItem");
	mu_assert_streq(it->name, fcn->name, "name");
	mu_assert_notnull(it->bytes, "bytes");
	mu_assert_eq(it->bytes->size, 76, "bytes size");
	// graph
	mu_assert_notnull(it->graph, "graph");
	mu_assert_eq(it->graph->bbsum, 396, "graph bbsum");
	mu_assert_eq(it->graph->cc, 8, "graph cc");
	mu_assert_eq(it->graph->ebbs, 2, "graph ebbs");
	mu_assert_eq(it->graph->edges, 16, "graph edges");
	mu_assert_eq(it->graph->nbbs, 12, "graph nbbs");
	mu_assert_eq(it->addr, 0x2a1c, "addr");
	// vars
	mu_assert_notnull(it->vars, "vars");
	mu_assert_eq(rz_list_length(it->vars), 17, "vars count");
	mu_assert_streq(rz_list_get_n(it->vars, 0), "b16", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 1), "s-4", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 2), "s-12", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 3), "s-16", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 4), "s-20", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 5), "s-8", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 6), "s-24", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 7), "s-32", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 8), "s-80", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 9), "s-76", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 10), "s-28", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 11), "s-36", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 12), "s-40", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 13), "r4", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 14), "r6", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 15), "r7", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 16), "r5", "var");
	// types
	mu_assert_notnull(it->types, "types");
	mu_assert_eq(rz_list_length(it->types), 6, "types count");
	mu_assert_streq(rz_list_get_n(it->types, 0), "func.sym._dl_malloc.args=5", "type");
	mu_assert_streq(rz_list_get_n(it->types, 1), "func.sym._dl_malloc.arg.0=\"int32_t,arg1\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 2), "func.sym._dl_malloc.arg.1=\"int32_t,arg2\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 3), "func.sym._dl_malloc.arg.2=\"int32_t,arg3\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 4), "func.sym._dl_malloc.arg.3=\"int32_t,arg4\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 5), "func.sym._dl_malloc.arg.4=\"int32_t,arg_10h\"", "type");
	// hash
	mu_assert_notnull(it->hash, "hash");
	mu_assert_streq(it->hash->bbhash, "ec986971438cf486e01f14e9bc442d9f4c457854207d30fe4aa9f1ffdf892911", "hash val");
	rz_sign_item_free(it);

	rz_core_file_close(file);
	rz_core_free(core);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_analysis_sign_za_mips);
	return tests_passed != tests_run;
}

mu_main(all_tests)
