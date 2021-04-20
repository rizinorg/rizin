// SPDX-FileCopyrightText: 2020 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

static bool sanitize_instr_acc(void *user, const ut64 k, const void *v) {
	RzPVector *vec = (RzPVector *)v;
	void **it;
	rz_pvector_foreach (vec, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc;
		bool found = false;
		rz_vector_foreach(&var->accesses, acc) {
			if (acc->offset == (st64)k) {
				found = true;
				break;
			}
		}
		mu_assert("instr refs var, but var does not ref instr", found);
	}
	return true;
}

static bool sanitize(RzAnalysisFunction *fcn) {
	ht_up_foreach(fcn->inst_vars, sanitize_instr_acc, NULL);

	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		RzAnalysisVarAccess *acc;
		rz_vector_foreach(&var->accesses, acc) {
			RzPVector *iaccs = ht_up_find(fcn->inst_vars, acc->offset, NULL);
			mu_assert("var refs instr but instr does not ref var", rz_pvector_contains(iaccs, var));
		}
	}
	return true;
}

#define assert_sane(analysis) \
	do { \
		RzListIter *ass_it; \
		RzAnalysisFunction *ass_fcn; \
		rz_list_foreach ((analysis)->fcns, ass_it, ass_fcn) { \
			if (!sanitize(ass_fcn)) { \
				return false; \
			} \
		} \
	} while (0);

static RzAnalysisVar *set_var_str(RzAnalysisFunction *fcn, int delta, char kind, const char *type, int size, bool isarg, const char *name) {
	RzType *ttype = rz_type_parse(fcn->analysis->typedb->parser, type, NULL);
	if (!ttype) {
		return NULL;
	}
	return rz_analysis_function_set_var(fcn, delta, kind, ttype, size, isarg, name);
}

bool test_rz_analysis_var() {
	RzAnalysis *analysis = rz_analysis_new();
	rz_analysis_use(analysis, "x86");
	rz_analysis_set_bits(analysis, 64);

	RzAnalysisFunction *fcn = rz_analysis_create_function(analysis, "fcn", 0x100, RZ_ANALYSIS_FCN_TYPE_FCN, NULL);
	assert_sane(analysis);

	// creating variables and renaming

	RzAnalysisVar *a = set_var_str(fcn, -8, RZ_ANALYSIS_VAR_KIND_BPV, "char *", 8, false, "random_name");
	mu_assert_notnull(a, "create a var");
	mu_assert_streq(a->name, "random_name", "var name");
	bool succ = rz_analysis_var_rename(a, "var_a", false);
	mu_assert("rename success", succ);
	mu_assert_streq(a->name, "var_a", "var name after rename");

	RzAnalysisVar *b = set_var_str(fcn, -0x10, RZ_ANALYSIS_VAR_KIND_SPV, "char *", 8, false, "var_a");
	mu_assert_null(b, "create a var with the same name");
	b = set_var_str(fcn, -0x10, RZ_ANALYSIS_VAR_KIND_SPV, "char *", 8, false, "new_var");
	mu_assert_notnull(b, "create a var with another name");
	mu_assert_streq(b->name, "new_var", "var name");
	succ = rz_analysis_var_rename(b, "random_name", false);
	mu_assert("rename success", succ);
	mu_assert_streq(b->name, "random_name", "var name after rename");
	succ = rz_analysis_var_rename(b, "var_a", false);
	mu_assert("rename failed", !succ);
	mu_assert_streq(b->name, "random_name", "var name after failed rename");
	succ = rz_analysis_var_rename(b, "var_b", false);
	mu_assert("rename success", succ);
	mu_assert_streq(b->name, "var_b", "var name after rename");

	RzAnalysisVar *c = set_var_str(fcn, 0x30, RZ_ANALYSIS_VAR_KIND_REG, "int64_t", 8, true, "arg42");
	mu_assert_notnull(c, "create a var");

	// querying variables

	RzAnalysisVar *v = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_REG, 0x41);
	mu_assert_null(v, "get no var");
	v = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_REG, 0x30);
	mu_assert_ptreq(v, c, "get var (reg)");
	v = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_SPV, -0x10);
	mu_assert_ptreq(v, b, "get var (sp)");
	v = rz_analysis_function_get_var(fcn, RZ_ANALYSIS_VAR_KIND_BPV, -8);
	mu_assert_ptreq(v, a, "get var (bp)");

	v = rz_analysis_function_get_var_byname(fcn, "random_name");
	mu_assert_null(v, "nonsense name");
	v = rz_analysis_function_get_var_byname(fcn, "var_a");
	mu_assert_ptreq(v, a, "get var by name");

	// accesses

	rz_analysis_var_set_access(a, "rsp", 0x120, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 42);
	rz_analysis_var_set_access(a, "rbp", 0x130, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, 13);
	rz_analysis_var_set_access(b, "rsp", 0x120, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, 123);
	rz_analysis_var_set_access(b, "rbp", 0x10, RZ_ANALYSIS_VAR_ACCESS_TYPE_WRITE, -100);

	st64 stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -0x10, 0x12345);
	mu_assert_eq(stackptr, ST64_MAX, "unset stackptr");

	RzPVector *used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -8, 0x130);
	mu_assert_eq(stackptr, 13, "stackptr");
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, 123123, 0x130);
	mu_assert_eq(stackptr, ST64_MAX, "stackptr");
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 2, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	mu_assert("used vars", rz_pvector_contains(used_vars, b));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -0x10, 0x120);
	mu_assert_eq(stackptr, 123, "stackptr");
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -8, 0x120);
	mu_assert_eq(stackptr, 42, "stackptr");
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x10);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, b));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -0x10, 0x10);
	mu_assert_eq(stackptr, -100, "stackptr");

	assert_sane(analysis);

	// relocate function

	rz_analysis_function_relocate(fcn, 0xffffffffffff0100UL);
	assert_sane(analysis);

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL); // addresses should stay the same
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0xffffffffffff0130UL, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 42);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0x123, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 42);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 2, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	mu_assert("used vars", rz_pvector_contains(used_vars, b));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -0x10, 0x120);
	mu_assert_eq(stackptr, 123, "stackptr");
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -8, 0x120);
	mu_assert_eq(stackptr, 42, "stackptr");
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x10);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, b));

	rz_analysis_function_relocate(fcn, 0x8000000000000010);
	assert_sane(analysis);

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x8000000000000100);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0x8000000000000100, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 987321);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x8000000000000100);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -8, 0x8000000000000100);
	mu_assert_eq(stackptr, 987321, "stackptr");

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x7ffffffffffffe00);
	mu_assert("no used vars", !used_vars || rz_pvector_len(used_vars));
	rz_analysis_var_set_access(a, "rbp", 0x7ffffffffffffe00, RZ_ANALYSIS_VAR_ACCESS_TYPE_READ, 777);
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x7ffffffffffffe00);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -8, 0x7ffffffffffffe00);
	mu_assert_eq(stackptr, 777, "stackptr");

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 2, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, a));
	mu_assert("used vars", rz_pvector_contains(used_vars, b));
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -0x10, 0x120);
	mu_assert_eq(stackptr, 123, "stackptr");
	stackptr = rz_analysis_function_get_var_stackptr_at(fcn, -8, 0x120);
	mu_assert_eq(stackptr, 42, "stackptr");

	assert_sane(analysis);

	rz_analysis_var_delete(a);
	assert_sane(analysis);

	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0xffffffffffff0130UL);
	mu_assert("used vars count", !used_vars || !rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x123);
	mu_assert("used vars count", !used_vars || !rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x130);
	mu_assert("used vars count", !used_vars || !rz_pvector_len(used_vars));
	used_vars = rz_analysis_function_get_vars_used_at(fcn, 0x120);
	mu_assert_eq(rz_pvector_len(used_vars), 1, "used vars count");
	mu_assert("used vars", rz_pvector_contains(used_vars, b));

	rz_analysis_var_delete(b);
	rz_analysis_var_delete(c);

	rz_analysis_free(analysis);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_var);
	return tests_passed != tests_run;
}

mu_main(all_tests)
