#include <rz_anal.h>
#include <rz_reg.h>
#include <rz_util.h>
#include "minunit.h"

bool test_filter_regs(void) {
	RzAnal *anal = rz_anal_new ();
	rz_anal_use (anal, "x86");
	rz_anal_set_bits (anal, 32);
	rz_anal_set_reg_profile (anal);
	RzAnalEsil *esil = rz_anal_esil_new (4096, 0, 1);
	esil->anal = anal;

	// create expected results
	rz_anal_esil_parse (esil, "0x9090,ax,:=,0xff,ah,:=");
	const ut64 ax = rz_reg_getv (anal->reg, "ax");
	const ut64 ah = rz_reg_getv (anal->reg, "ah");
	const ut64 al = rz_reg_getv (anal->reg, "al");
	rz_reg_setv (anal->reg, "eax", 0);

	RzAnalEsilDFG *dfg = rz_anal_esil_dfg_expr (anal, NULL, "0x9090,ax,:=,0xff,ah,:=");

	// filter for ax register
	RzStrBuf *filtered_expr = rz_anal_esil_dfg_filter (dfg, "ax");
	rz_anal_esil_parse (esil, rz_strbuf_get (filtered_expr));
	const ut64 filtered_ax = rz_reg_getv (anal->reg, "ax");
	rz_strbuf_free (filtered_expr);
	rz_reg_setv (anal->reg, "eax", 0);

	// filter for ah register
	filtered_expr = rz_anal_esil_dfg_filter (dfg, "ah");
	rz_anal_esil_parse (esil, rz_strbuf_get (filtered_expr));
	const ut64 filtered_ah = rz_reg_getv (anal->reg, "ah");
	rz_strbuf_free (filtered_expr);
	rz_reg_setv (anal->reg, "eax", 0);

	// filter for al register
	filtered_expr = rz_anal_esil_dfg_filter (dfg, "al");
	rz_anal_esil_parse (esil, rz_strbuf_get (filtered_expr));
	const ut64 filtered_al = rz_reg_getv (anal->reg, "al");
	rz_strbuf_free (filtered_expr);

	rz_anal_esil_dfg_free (dfg);
	rz_anal_esil_free (esil);
	rz_anal_free (anal);

	mu_assert ("filtering for ax failed", ax == filtered_ax);
	mu_assert ("filtering for ah failed", ah == filtered_ah);
	mu_assert ("filtering for al failed", al == filtered_al);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test (test_filter_regs);
	return tests_passed != tests_run;
}
