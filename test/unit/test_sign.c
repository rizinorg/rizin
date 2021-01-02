#include <rz_analysis.h>
#include <rz_sign.h>

#include "minunit.h"

static bool test_analysis_sign_get_set(void) {
	RzAnalysis *analysis = rz_analysis_new ();

	RzSignItem *item = rz_sign_item_new ();
	item->name = strdup ("sym.mahboi");
	item->realname = strdup ("sym.Mah.Boi");
	item->comment = strdup ("This peace is what all true warriors strive for");

	item->bytes = RZ_NEW0 (RzSignBytes);
	item->bytes->size = 4;
	item->bytes->bytes = (ut8 *)strdup ("\xde\xad\xbe\xef");
	item->bytes->mask = (ut8 *)strdup ("\xc0\xff\xee\x42");

	item->graph = RZ_NEW0 (RzSignGraph);
	item->graph->bbsum = 42;
	item->graph->cc = 123;
	item->graph->ebbs = 13;
	item->graph->edges = 12;
	item->graph->nbbs = 11;

	item->addr = 0x1337;

	item->refs = rz_list_newf (free);
	rz_list_append (item->refs, strdup ("gwonam"));
	rz_list_append (item->refs, strdup ("link"));

	item->xrefs = rz_list_newf (free);
	rz_list_append (item->xrefs, strdup ("king"));
	rz_list_append (item->xrefs, strdup ("ganon"));

	item->vars = rz_list_newf (free);
	rz_list_append (item->vars, strdup ("r16"));
	rz_list_append (item->vars, strdup ("s42"));
	rz_list_append (item->vars, strdup ("b13"));

	item->types = rz_list_newf (free);
	rz_list_append (item->types, strdup ("func.sym.mahboi.ret=char *"));
	rz_list_append (item->types, strdup ("func.sym.mahboi.args=2"));
	rz_list_append (item->types, strdup ("func.sym.mahboi.arg.0=\"int,arg0\""));
	rz_list_append (item->types, strdup ("func.sym.mahboi.arg.1=\"uint32_t,die\""));

	item->hash = RZ_NEW0 (RzSignHash);
	item->hash->bbhash = strdup ("7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851");

	rz_sign_add_item (analysis, item);
	rz_sign_item_free (item);

	rz_spaces_set (&analysis->zign_spaces, "koridai");
	rz_sign_add_comment (analysis, "sym.boring", "gee it sure is boring around here");

	// --
	
	rz_spaces_set (&analysis->zign_spaces, NULL);
	item = rz_sign_get_item (analysis, "sym.mahboi");
	mu_assert_notnull (item, "get item");

	mu_assert_streq (item->name, "sym.mahboi", "name");
	mu_assert_streq (item->realname, "sym.Mah.Boi", "realname");
	mu_assert_streq (item->comment, "This peace is what all true warriors strive for", "comment");
	mu_assert_notnull (item->bytes, "bytes");
	mu_assert_eq (item->bytes->size, 4, "bytes size");
	mu_assert_memeq (item->bytes->bytes, (ut8 *)"\xde\xad\xbe\xef", 4, "bytes bytes");
	mu_assert_memeq (item->bytes->mask, (ut8 *)"\xc0\xff\xee\x42", 4, "bytes mask");
	mu_assert_notnull (item->graph, "graph");
	mu_assert_eq (item->graph->bbsum, 42, "graph bbsum");
	mu_assert_eq (item->graph->cc, 123, "graph cc");
	mu_assert_eq (item->graph->ebbs, 13, "graph ebbs");
	mu_assert_eq (item->graph->edges, 12, "graph edges");
	mu_assert_eq (item->graph->nbbs, 11, "graph nbbs");
	mu_assert_eq (item->addr, 0x1337, "addr");
	mu_assert_notnull (item->refs, "refs");
	mu_assert_eq (rz_list_length (item->refs), 2, "refs count");
	mu_assert_streq (rz_list_get_n (item->refs, 0), "gwonam", "ref");
	mu_assert_streq (rz_list_get_n (item->refs, 1), "link", "ref");
	mu_assert_notnull (item->xrefs, "xrefs");
	mu_assert_eq (rz_list_length (item->xrefs), 2, "xrefs count");
	mu_assert_streq (rz_list_get_n (item->xrefs, 0), "king", "xref");
	mu_assert_streq (rz_list_get_n (item->xrefs, 1), "ganon", "xref");
	mu_assert_notnull (item->vars, "vars");
	mu_assert_eq (rz_list_length (item->vars), 3, "vars count");
	mu_assert_streq (rz_list_get_n (item->vars, 0), "r16", "var");
	mu_assert_streq (rz_list_get_n (item->vars, 1), "s42", "var");
	mu_assert_streq (rz_list_get_n (item->vars, 2), "b13", "var");
	mu_assert_notnull (item->types, "types");
	mu_assert_eq (rz_list_length (item->types), 4, "types count");
	mu_assert_streq (rz_list_get_n (item->types, 0), "func.sym.mahboi.ret=char *", "type");
	mu_assert_streq (rz_list_get_n (item->types, 1), "func.sym.mahboi.args=2", "type");
	mu_assert_streq (rz_list_get_n (item->types, 2), "func.sym.mahboi.arg.0=\"int,arg0\"", "type");
	mu_assert_streq (rz_list_get_n (item->types, 3), "func.sym.mahboi.arg.1=\"uint32_t,die\"", "type");
	mu_assert_notnull (item->hash, "hash");
	mu_assert_streq (item->hash->bbhash, "7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851", "hash val");
	rz_sign_item_free (item);
	
	rz_spaces_set (&analysis->zign_spaces, "koridai");
	item = rz_sign_get_item (analysis, "sym.boring");
	mu_assert_notnull (item, "get item in space");
	mu_assert_streq (item->comment, "gee it sure is boring around here", "item in space comment");
	rz_sign_item_free (item);

	rz_analysis_free (analysis);
	mu_end;
}

int all_tests(void) {
	mu_run_test (test_analysis_sign_get_set);
	return tests_passed != tests_run;
}

mu_main (all_tests)