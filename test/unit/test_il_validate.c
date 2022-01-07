// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_il_validate() {
	RzILOpPure *op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(63, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand sizes of add op do not agree: 63 vs. 64.", "report");

	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_validate);
	return tests_passed != tests_run;
}

mu_main(all_tests)
