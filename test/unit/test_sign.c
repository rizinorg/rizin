// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_sign.h>

#include "minunit.h"

static bool test_analysis_sign_get_set(void) {
	RzAnalysis *analysis = rz_analysis_new();

	RzSignItem *item = rz_sign_item_new();
	item->name = strdup("sym.mahboi");
	item->realname = strdup("sym.Mah.Boi");
	item->comment = strdup("This peace is what all true warriors strive for");

	item->bytes = RZ_NEW0(RzSignBytes);
	item->bytes->size = 4;
	item->bytes->bytes = (ut8 *)strdup("\xde\xad\xbe\xef");
	item->bytes->mask = (ut8 *)strdup("\xc0\xff\xee\x42");

	item->graph = RZ_NEW0(RzSignGraph);
	item->graph->bbsum = 42;
	item->graph->cc = 123;
	item->graph->ebbs = 13;
	item->graph->edges = 12;
	item->graph->nbbs = 11;

	item->addr = 0x1337;

	item->xrefs_from = rz_list_newf(free);
	rz_list_append(item->xrefs_from, strdup("gwonam"));
	rz_list_append(item->xrefs_from, strdup("link"));

	item->xrefs_to = rz_list_newf(free);
	rz_list_append(item->xrefs_to, strdup("king"));
	rz_list_append(item->xrefs_to, strdup("ganon"));

	item->vars = rz_list_newf(free);
	rz_list_append(item->vars, strdup("r16"));
	rz_list_append(item->vars, strdup("s42"));
	rz_list_append(item->vars, strdup("b13"));

	item->types = rz_list_newf(free);
	rz_list_append(item->types, strdup("func.sym.mahboi.ret=char *"));
	rz_list_append(item->types, strdup("func.sym.mahboi.args=2"));
	rz_list_append(item->types, strdup("func.sym.mahboi.arg.0=\"int,arg0\""));
	rz_list_append(item->types, strdup("func.sym.mahboi.arg.1=\"uint32_t,die\""));

	item->hash = RZ_NEW0(RzSignHash);
	item->hash->bbhash = strdup("7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851");

	rz_sign_add_item(analysis, item);
	rz_sign_item_free(item);

	rz_spaces_set(&analysis->zign_spaces, "koridai");
	rz_sign_add_comment(analysis, "sym.boring", "gee it sure is boring around here");

	// --

	rz_spaces_set(&analysis->zign_spaces, NULL);
	item = rz_sign_get_item(analysis, "sym.mahboi");
	mu_assert_notnull(item, "get item");

	mu_assert_streq(item->name, "sym.mahboi", "name");
	mu_assert_streq(item->realname, "sym.Mah.Boi", "realname");
	mu_assert_streq(item->comment, "This peace is what all true warriors strive for", "comment");
	mu_assert_notnull(item->bytes, "bytes");
	mu_assert_eq(item->bytes->size, 4, "bytes size");
	mu_assert_memeq(item->bytes->bytes, (ut8 *)"\xde\xad\xbe\xef", 4, "bytes bytes");
	mu_assert_memeq(item->bytes->mask, (ut8 *)"\xc0\xff\xee\x42", 4, "bytes mask");
	mu_assert_notnull(item->graph, "graph");
	mu_assert_eq(item->graph->bbsum, 42, "graph bbsum");
	mu_assert_eq(item->graph->cc, 123, "graph cc");
	mu_assert_eq(item->graph->ebbs, 13, "graph ebbs");
	mu_assert_eq(item->graph->edges, 12, "graph edges");
	mu_assert_eq(item->graph->nbbs, 11, "graph nbbs");
	mu_assert_eq(item->addr, 0x1337, "addr");
	mu_assert_notnull(item->xrefs_from, "xrefs_from");
	mu_assert_eq(rz_list_length(item->xrefs_from), 2, "xrefs_from count");
	mu_assert_streq(rz_list_get_n(item->xrefs_from, 0), "gwonam", "xrefs_from");
	mu_assert_streq(rz_list_get_n(item->xrefs_from, 1), "link", "xrefs_from");
	mu_assert_notnull(item->xrefs_to, "xrefs_to");
	mu_assert_eq(rz_list_length(item->xrefs_to), 2, "xrefs count");
	mu_assert_streq(rz_list_get_n(item->xrefs_to, 0), "king", "xrefs_to");
	mu_assert_streq(rz_list_get_n(item->xrefs_to, 1), "ganon", "xrefs_to");
	mu_assert_notnull(item->vars, "vars");
	mu_assert_eq(rz_list_length(item->vars), 3, "vars count");
	mu_assert_streq(rz_list_get_n(item->vars, 0), "r16", "var");
	mu_assert_streq(rz_list_get_n(item->vars, 1), "s42", "var");
	mu_assert_streq(rz_list_get_n(item->vars, 2), "b13", "var");
	mu_assert_notnull(item->types, "types");
	mu_assert_eq(rz_list_length(item->types), 4, "types count");
	mu_assert_streq(rz_list_get_n(item->types, 0), "func.sym.mahboi.ret=char *", "type");
	mu_assert_streq(rz_list_get_n(item->types, 1), "func.sym.mahboi.args=2", "type");
	mu_assert_streq(rz_list_get_n(item->types, 2), "func.sym.mahboi.arg.0=\"int,arg0\"", "type");
	mu_assert_streq(rz_list_get_n(item->types, 3), "func.sym.mahboi.arg.1=\"uint32_t,die\"", "type");
	mu_assert_notnull(item->hash, "hash");
	mu_assert_streq(item->hash->bbhash, "7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851", "hash val");
	rz_sign_item_free(item);

	rz_spaces_set(&analysis->zign_spaces, "koridai");
	item = rz_sign_get_item(analysis, "sym.boring");
	mu_assert_notnull(item, "get item in space");
	mu_assert_streq(item->comment, "gee it sure is boring around here", "item in space comment");
	rz_sign_item_free(item);

	rz_analysis_free(analysis);
	mu_end;
}

static bool test_analysis_sign_za_ppc(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "Couldn't create new RzCore");
	ut64 loadaddr = 0x10000000;
	const char *fpath = "bins/elf/busybox-powerpc";
	RzCoreFile *file = rz_core_file_open(core, fpath, RZ_PERM_R, loadaddr);
	mu_assert_notnull(file, "open file");
	rz_core_bin_load(core, fpath, loadaddr);

	bool analyze_recursively = rz_config_get_i(core->config, "analysis.calls");
	bool is_added = rz_core_analysis_function_add(core, NULL, 0x10002d70, analyze_recursively);
	mu_assert_eq(is_added, true, "Couldn't add fcn");

	RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, 0x10002d70);
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
	mu_assert_eq(it->bytes->size, 12, "bytes size");
	// graph
	mu_assert_notnull(it->graph, "graph");
	mu_assert_eq(it->graph->bbsum, 304, "graph bbsum");
	mu_assert_eq(it->graph->cc, 12, "graph cc");
	mu_assert_eq(it->graph->ebbs, 1, "graph ebbs");
	mu_assert_eq(it->graph->edges, 29, "graph edges");
	mu_assert_eq(it->graph->nbbs, 19, "graph nbbs");
	mu_assert_eq(it->addr, 0x10002d70, "addr");
	// vars
	mu_assert_notnull(it->vars, "vars");
	mu_assert_eq(rz_list_length(it->vars), 7, "vars count");
	mu_assert_streq(rz_list_get_n(it->vars, 0), "b-4096", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 1), "s4", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 2), "s-36", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 3), "s0", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 4), "s-4136", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 5), "r5", "var");
	mu_assert_streq(rz_list_get_n(it->vars, 6), "r6", "var");
	// types
	mu_assert_notnull(it->types, "types");
	mu_assert_eq(rz_list_length(it->types), 5, "types count");
	mu_assert_streq(rz_list_get_n(it->types, 0), "func.fcn.10002d70.args=4", "type");
	mu_assert_streq(rz_list_get_n(it->types, 1), "func.fcn.10002d70.arg.0=\"int32_t,arg1\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 2), "func.fcn.10002d70.arg.1=\"int32_t,arg2\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 3), "func.fcn.10002d70.arg.2=\"int32_t,arg_1034h\"", "type");
	mu_assert_streq(rz_list_get_n(it->types, 4), "func.fcn.10002d70.arg.3=\"int32_t,arg_1030h\"", "type");
	// hash
	mu_assert_notnull(it->hash, "hash");
	mu_assert_streq(it->hash->bbhash, "b73e65dc846183808d8e385076f9bbcd0b1dcdaa5652254fb55b3b159462a507", "hash val");
	rz_sign_item_free(it);

	rz_core_file_close(file);
	rz_core_free(core);
	mu_end;
}

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
	mu_run_test(test_analysis_sign_get_set);
	mu_run_test(test_analysis_sign_za_ppc);
	mu_run_test(test_analysis_sign_za_mips);
	return tests_passed != tests_run;
}

mu_main(all_tests)