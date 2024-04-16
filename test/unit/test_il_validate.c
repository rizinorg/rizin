// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

static bool test_il_validate_pure_bool() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_b0();
	RzILSortPure sort = rz_il_sort_pure_bv(0xffff);
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_b1();
	sort = rz_il_sort_pure_bv(0xffff);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_null() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(NULL, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	mu_assert_streq_free(report, "Encountered NULL for pure op.", "no report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_bitv_from_ut64(42, 123);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(42)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_ite() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_ite(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, 0), rz_il_op_new_bitv_from_ut64(32, 0));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(32)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_ite(rz_il_op_new_b0(), rz_il_op_new_b0(), rz_il_op_new_b1());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_ite(rz_il_op_new_bitv_from_ut64(12, 0), rz_il_op_new_bitv_from_ut64(32, 0), rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	mu_assert_streq_free(report, "Condition of ite op is not boolean.", "report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_ite(rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, 0), rz_il_op_new_bitv_from_ut64(31, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	mu_assert_streq_free(report, "Types of ite branches do not agree: bitvector:32 vs. bitvector:31.", "report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_let() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	// body type
	RzILOpPure *op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	// bound
	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	// shadowing
	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_let(
			"y", rz_il_op_new_bitv_from_ut64(32, 123),
			rz_il_op_new_let(
				"x", rz_il_op_new_bitv_from_ut64(42, 321),
				rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL_PURE))));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(42)), "sort");
	mu_assert_null(report, "no report");
	free(report);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_let(
			"y", rz_il_op_new_bitv_from_ut64(32, 123),
			rz_il_op_new_let(
				"x", rz_il_op_new_bitv_from_ut64(42, 321),
				rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL_PURE))));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(32)), "sort");
	mu_assert_null(report, "no report");
	free(report);
	rz_il_op_pure_free(op);

	// invalid cases
	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	free(report);
	rz_il_op_pure_free(op);

	op = rz_il_op_new_let(
		"x", rz_il_op_new_b0(),
		rz_il_op_new_var("x", RZ_IL_VAR_KIND_GLOBAL));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "valid");
	free(report);
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_var() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	rz_il_validate_global_context_add_var(ctx, "y", rz_il_sort_pure_bv(42));

	RzILOpPure *op = rz_il_op_new_var("y", RZ_IL_VAR_KIND_GLOBAL);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(42)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	RzILOpEffect *eop = rz_il_op_new_seq(
		rz_il_op_new_set("y", true, rz_il_op_new_bitv_from_ut64(24, 0x1234)),
		rz_il_op_new_jmp(rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL)));
	RzILTypeEffect t;
	val = rz_il_validate_effect(eop, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA | RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(eop);

	op = rz_il_op_new_var("x", RZ_IL_VAR_KIND_GLOBAL);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"x\" referenced by var op does not exist.", "report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Local variable \"x\" is not available at var op.", "report");
	rz_il_op_pure_free(op);

	eop = rz_il_op_new_seq(
		rz_il_op_new_set("y", true, rz_il_op_new_bitv_from_ut64(23, 0x1234)),
		rz_il_op_new_jmp(rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL)));
	val = rz_il_validate_effect(eop, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Length of dst operand (23) of jmp op is not equal to pc length 24.", "report");
	rz_il_op_effect_free(eop);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_inv() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_bool_inv(rz_il_op_new_b0());
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_bool_inv(rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand of boolean inv op is not boolean.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bool_binop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_bool_and(
		rz_il_op_new_b0(),
		rz_il_op_new_b1());
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_bool_and(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of and op is not bool.", "report");

	op = rz_il_op_new_bool_and(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of and op is not bool.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv_binop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(63, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand sizes of add op do not agree: 63 vs. 64.", "report");

	op = rz_il_op_new_add(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of add op is not a bitvector.", "report");

	op = rz_il_op_new_add(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of add op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv_bool_unop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_msb(rz_il_op_new_bitv_from_ut64(64, 123));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_msb(rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand of msb op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_bitv_unop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_log_not(rz_il_op_new_bitv_from_ut64(64, 123));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_log_not(rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand of lognot op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_shift() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 123), rz_il_op_new_bitv_from_ut64(32, 32));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_shiftl(rz_il_op_new_bitv_from_ut64(8, 0),
		rz_il_op_new_bitv_from_ut64(64, 123), rz_il_op_new_bitv_from_ut64(32, 32));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Fill operand of shiftl op is not bool.", "report");

	op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_b0(), rz_il_op_new_bitv_from_ut64(32, 32));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Value operand of shiftl op is not a bitvector.", "report");

	op = rz_il_op_new_shiftl(rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(32, 32), rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Distance operand of shiftl op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_cmp() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_eq(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_eq(
		rz_il_op_new_bitv_from_ut64(63, 123),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Operand sizes of eq op do not agree: 63 vs. 64.", "report");

	op = rz_il_op_new_eq(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of eq op is not a bitvector.", "report");

	op = rz_il_op_new_eq(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of eq op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_cast() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_cast(13,
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(13)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_cast(13,
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	op->op.cast.length = 0;
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of cast op is 0.", "report");

	op = rz_il_op_new_cast(13,
		rz_il_op_new_bitv_from_ut64(12, 0),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Fill operand of cast op is not bool.", "report");

	op = rz_il_op_new_cast(13,
		rz_il_op_new_b0(),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Value operand of cast op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_append() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_append(
		rz_il_op_new_bitv_from_ut64(64, 123),
		rz_il_op_new_bitv_from_ut64(41, 456));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64 + 41)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_append(
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(64, 456));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "High operand of append op is not a bitvector.", "report");

	op = rz_il_op_new_append(
		rz_il_op_new_bitv_from_ut64(64, 456),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Low operand of append op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_load() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	rz_il_validate_global_context_add_mem(ctx, 1, 16, 9);

	RzILOpPure *op = rz_il_op_new_load(1, rz_il_op_new_bitv_from_ut64(16, 123));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(9)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_load(1, rz_il_op_new_bitv_from_ut64(9, 123));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of key operand (9) of load op is not equal to key length 16 of mem 1.", "report");

	op = rz_il_op_new_load(0, rz_il_op_new_bitv_from_ut64(16, 123));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Mem 0 referenced by load op does not exist.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_loadw() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	rz_il_validate_global_context_add_mem(ctx, 1, 16, 9);

	RzILOpPure *op = rz_il_op_new_loadw(1, rz_il_op_new_bitv_from_ut64(16, 123), 32);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(32)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_loadw(1, rz_il_op_new_bitv_from_ut64(12, 123), 32);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of key operand (12) of loadw op is not equal to key length 16 of mem 1.", "report");

	op = rz_il_op_new_loadw(0, rz_il_op_new_bitv_from_ut64(16, 123), 32);
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Mem 0 referenced by loadw op does not exist.", "report");

	op = rz_il_op_new_loadw(1, rz_il_op_new_bitv_from_ut64(16, 123), 32);
	op->op.loadw.n_bits = 0;
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Length of loadw op is 0.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_null() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILValidateReport report;
	bool val = rz_il_validate_effect(NULL, ctx, NULL, NULL, &report);
	mu_assert_false(val, "valid");
	mu_assert_streq_free(report, "Encountered NULL for effect op.", "no report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_empty() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_empty();
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_NONE, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_nop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_nop();
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_NONE, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_store() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	rz_il_validate_global_context_add_mem(ctx, 1, 16, 9);

	RzILOpEffect *op = rz_il_op_new_store(1,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_bitv_from_ut64(9, 42));
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_store(0,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_bitv_from_ut64(9, 42));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Mem 0 referenced by store op does not exist.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_store(1,
		rz_il_op_new_bitv_from_ut64(12, 123),
		rz_il_op_new_bitv_from_ut64(9, 42));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Length of key operand (12) of store op is not equal to key length 16 of mem 1.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_store(1,
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(9, 42));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Key operand of store op is not a bitvector.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_store(1,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_bitv_from_ut64(8, 42));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Length of value operand (8) of store op is not equal to value length 9 of mem 1.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_store(1,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_b0());
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Value operand of store op is not a bitvector.", "report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_storew() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	rz_il_validate_global_context_add_mem(ctx, 1, 16, 9);

	RzILOpEffect *op = rz_il_op_new_storew(1,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_bitv_from_ut64(42, 42));
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_storew(0,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_bitv_from_ut64(9, 42));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Mem 0 referenced by storew op does not exist.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_storew(1,
		rz_il_op_new_bitv_from_ut64(12, 123),
		rz_il_op_new_bitv_from_ut64(9, 42));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Length of key operand (12) of storew op is not equal to key length 16 of mem 1.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_storew(1,
		rz_il_op_new_b0(),
		rz_il_op_new_bitv_from_ut64(9, 42));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Key operand of storew op is not a bitvector.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_storew(1,
		rz_il_op_new_bitv_from_ut64(16, 123),
		rz_il_op_new_b0());
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Value operand of storew op is not a bitvector.", "report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_set() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	rz_il_validate_global_context_add_var(ctx, "x", rz_il_sort_pure_bv(42));

	// global
	RzILOpEffect *op = rz_il_op_new_set("x", false, rz_il_op_new_bitv_from_ut64(42, 0));
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_set("y", false, rz_il_op_new_bitv_from_ut64(42, 0));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"y\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_set("x", false, rz_il_op_new_bitv_from_ut64(41, 0));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Types of global variable \"x\" and set op do not agree: bitvector:42 vs. bitvector:41.", "report");
	rz_il_op_effect_free(op);

	// local
	op = rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(20, 0));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(22, 0)),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(22, 42)));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(22, 0)),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(21, 42)));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Types of local variable \"x\" and set op do not agree: bitvector:22 vs. bitvector:21.", "report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_jmp() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x1000));
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(42, 0x1000));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Length of dst operand (42) of jmp op is not equal to pc length 24.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_jmp(rz_il_op_new_b0());
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Dst operand of jmp op is not a bitvector.", "report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_goto() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_goto("beach");
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_seq() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_seq(rz_il_op_new_nop(), rz_il_op_new_nop());
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_NONE, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_set("nexist", false, rz_il_op_new_b0()), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"nexist\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_nop(), rz_il_op_new_set("nexist", false, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"nexist\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	// effect type handling
	op = rz_il_op_new_seq(rz_il_op_new_set("x", true, rz_il_op_new_b0()), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_set("x", true, rz_il_op_new_b0()), rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA | RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)), rz_il_op_new_set("x", true, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Encountered further effects after a ctrl effect in seq op.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_nop(), rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seq(rz_il_op_new_nop(), rz_il_op_new_set("x", true, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_blk() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_blk(NULL, rz_il_op_new_nop(), rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x1000)));
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_blk(NULL,
		rz_il_op_new_set("nexist", false, rz_il_op_new_b0()),
		rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x1000)));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"nexist\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_blk(NULL,
		rz_il_op_new_nop(),
		rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(23, 0x1000)));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Length of dst operand (23) of jmp op is not equal to pc length 24.", "report");
	rz_il_op_effect_free(op);

	// effect type handling
	op = rz_il_op_new_blk(NULL,
		rz_il_op_new_set("x", true, rz_il_op_new_b0()),
		rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x1000)));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA | RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_blk(NULL,
		rz_il_op_new_set("x", true, rz_il_op_new_b0()),
		rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_blk(NULL,
		rz_il_op_new_nop(),
		rz_il_op_new_set("x", true, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Control effect operand of blk op does not only perform control effects.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_blk(NULL,
		rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x1000)),
		rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Data effect operand of blk op does not only perform data effects.", "report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_repeat() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_nop());
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_NONE, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_repeat(rz_il_op_new_bitv_from_ut64(16, 0), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Condition of repeat op is not boolean.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("nexist", false, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"nexist\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	//////////////////////////
	// local context handling

	// types remembered from the loop
	op = rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)));
	HtSP *local_var_sorts;
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 1, "local var sorts count");
	RzILSortPure *sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars available before are still available after
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("y", true, rz_il_op_new_ite(rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL), rz_il_op_new_b0(), rz_il_op_new_b1())));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 2, "local var sorts count");
	sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars available only inside the loop can be made available again if they have the same type
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 32)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 2, "local var sorts count");
	sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars defined inside the loop already can not be used again with another type
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(13, 32)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Types of local variable \"x\" and set op do not agree: bitvector:14 vs. bitvector:13.", "report");
	rz_il_op_effect_free(op);

	// vars available only inside the loop are not available after it anymore
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("x", true, rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Local variable \"x\" is not available at var op.", "report");
	rz_il_op_effect_free(op);

	//////////////////////////
	// effect type handling

	op = rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_repeat(rz_il_op_new_b0(), rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Body operand of repeat op does not only perform data effects.", "report");
	rz_il_op_effect_free(op);

	//////////////////////////
	// malformed effect handling

	op = rz_il_op_new_seqn(2,
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(32, 1)),
		rz_il_op_new_repeat(rz_il_op_new_non_zero(rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL)),
			rz_il_op_new_set("x", true, rz_il_op_new_sub(rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL), rz_il_op_new_b1()))));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Right operand of sub op is not a bitvector.", "report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_effect_branch() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpEffect *op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_nop());
	RzILValidateReport report;
	RzILTypeEffect t;
	bool val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_NONE, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_bitv_from_ut64(8, 0), rz_il_op_new_nop(), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Condition of branch op is not boolean.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_set("nexist", false, rz_il_op_new_b0()), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"nexist\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_set("nexist", false, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Global variable \"nexist\" referenced by set op does not exist.", "report");
	rz_il_op_effect_free(op);

	//////////////////////////
	// local context handling

	// types remembered from the branches
	op = rz_il_op_new_branch(rz_il_op_new_b0(),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)),
		rz_il_op_new_set("y", true, rz_il_op_new_b0()));
	HtSP *local_var_sorts;
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 2, "local var sorts count");
	RzILSortPure *sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars available before are still available after
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_nop()),
		rz_il_op_new_set("y", true, rz_il_op_new_ite(rz_il_op_new_var("y", RZ_IL_VAR_KIND_LOCAL), rz_il_op_new_b0(), rz_il_op_new_b1())));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 1, "local var sorts count");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars available only inside a branch can be made available again if they have the same type
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 32)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 2, "local var sorts count");
	sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)), rz_il_op_new_nop()),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 32)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 2, "local var sorts count");
	sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars defined in both branches are still available after it
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(),
			rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)),
			rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 42))),
		rz_il_op_new_set("x", true, rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_true(val, "valid");
	mu_assert_null(report, "no report");
	mu_assert_notnull(local_var_sorts, "local var sorts");
	mu_assert_eq(local_var_sorts->count, 2, "local var sorts count");
	sort = ht_sp_find(local_var_sorts, "x", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bv(14)), "local var sort");
	sort = ht_sp_find(local_var_sorts, "y", NULL);
	mu_assert_notnull(sort, "local var sort");
	mu_assert_true(rz_il_sort_pure_eq(*sort, rz_il_sort_pure_bool()), "local var sort");
	ht_sp_free(local_var_sorts);
	local_var_sorts = NULL;
	rz_il_op_effect_free(op);

	// vars defined already inside the branch can not be used again with another type
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(13, 32)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Types of local variable \"x\" and set op do not agree: bitvector:14 vs. bitvector:13.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)), rz_il_op_new_nop()),
		rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(13, 32)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Types of local variable \"x\" and set op do not agree: bitvector:14 vs. bitvector:13.", "report");
	rz_il_op_effect_free(op);

	// vars defined only inside one branch are not available after it anymore
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0))),
		rz_il_op_new_set("x", true, rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Local variable \"x\" is not available at var op.", "report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 0)), rz_il_op_new_nop()),
		rz_il_op_new_set("x", true, rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report, "Local variable \"x\" is not available at var op.", "report");
	rz_il_op_effect_free(op);

	// vars defined in both branches must agree in their types
	op = rz_il_op_new_seqn(3,
		rz_il_op_new_set("y", true, rz_il_op_new_b0()),
		rz_il_op_new_branch(rz_il_op_new_b0(),
			rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(13, 0)),
			rz_il_op_new_set("x", true, rz_il_op_new_bitv_from_ut64(14, 42))),
		rz_il_op_new_set("x", true, rz_il_op_new_var("x", RZ_IL_VAR_KIND_LOCAL)));
	val = rz_il_validate_effect(op, ctx, &local_var_sorts, NULL, &report);
	mu_assert_false(val, "invalid");
	mu_assert_streq_free(report,
		"Control flow paths from branch op do not agree on the type of local variable \"x\": bitvector:14 vs. bitvector:13.", "report");
	rz_il_op_effect_free(op);

	//////////////////////////
	// effect type handling

	op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_set("x", true, rz_il_op_new_b0()), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_set("x", true, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_nop(), rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_b0(), rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)), rz_il_op_new_nop());
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	op = rz_il_op_new_branch(rz_il_op_new_b0(),
		rz_il_op_new_jmp(rz_il_op_new_bitv_from_ut64(24, 0x100)),
		rz_il_op_new_set("x", true, rz_il_op_new_b0()));
	val = rz_il_validate_effect(op, ctx, NULL, &t, &report);
	mu_assert_true(val, "valid");
	mu_assert_eq(t, RZ_IL_TYPE_EFFECT_DATA | RZ_IL_TYPE_EFFECT_CTRL, "effect type");
	mu_assert_null(report, "no report");
	rz_il_op_effect_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	RzILOpPure *op = rz_il_op_new_float_from_f64(4.2);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float80() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	RzILOpPure *op = rz_il_op_new_float_from_f80(4.2L);
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_80)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_fbits() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fbits(rz_il_op_new_float_from_f64(12.345));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fbits(rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of fbits op is not a float.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float_bool_uop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_is_finite(rz_il_op_new_float_from_f64(12.345));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_is_finite(rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of is_finite op is not a float.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float_uop() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fneg(rz_il_op_new_float_from_f64(12.345));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fneg(rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of fneg op is not a float.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float_uop_with_round() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fround(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(12.345));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fround(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(32, 0));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of fround op is not a float.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_forder() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_forder(
		rz_il_op_new_float_from_f64(12.345),
		rz_il_op_new_float_from_f64(11.111));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);

	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bool()), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_forder(
		rz_il_op_new_bitv_from_ut64(32, 0),
		rz_il_op_new_float_from_f64(11.111));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of forder op is not a float.", "report");

	op = rz_il_op_new_forder(
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of forder op is not a float.", "report");

	op = rz_il_op_new_forder(
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_float_from_f32(2.12f));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Op forder formats of left operand (float:1) and right operand (float:0) do not agree.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float_binop_with_round() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fadd(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(12.345),
		rz_il_op_new_float_from_f64(11.111));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fadd(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(32, 0),
		rz_il_op_new_float_from_f64(11.111));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Left operand of fadd op is not a float.", "report");

	op = rz_il_op_new_fadd(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_b0());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Right operand of fadd op is not a float.", "report");

	op = rz_il_op_new_fadd(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_float_from_f32(2.12f));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "Op fadd formats of left operand (float:1) and right operand (float:0) do not agree.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float_terop_with_round() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fmad(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(12.345),
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_float_from_f64(3.14));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fmad(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(32, 0),
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_float_from_f64(3.14));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "1st operand of fmad op is not a float.", "report");

	op = rz_il_op_new_fmad(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_b0(),
		rz_il_op_new_float_from_f64(3.14));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "2nd operand of fmad op is not a float.", "report");

	op = rz_il_op_new_fmad(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_float_from_f64(3.14),
		rz_il_op_new_b1());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "3rd operand of fmad op is not a float.", "report");

	op = rz_il_op_new_fmad(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11.111),
		rz_il_op_new_float_from_f32(2.12f),
		rz_il_op_new_float_from_f32(3.14f));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "types of operand in op fmad do not agree: operand1 (float:1) operand2 (float:0) operand3 (float:0)", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_float_hybridop_with_round() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);
	RzILOpPure *op = rz_il_op_new_fcompound(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(0.28347),
		rz_il_op_new_bitv_from_ut64(64, 21333));
	RzILSortPure sort;
	RzILValidateReport report;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fcompound(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(64, 21333),
		rz_il_op_new_bitv_from_ut64(64, 89435));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "1st operand of fcompound op is not a float.", "report");

	op = rz_il_op_new_fcompound(
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(44.15),
		rz_il_op_new_b1());
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "2nd operand of fcompound op is not a bitv.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_fcast_to_int() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fcast_int(
		64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(12.345));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_bv(64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fcast_int(
		64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(64, 11));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of fcast_int op is not a float.", "report");

	op = rz_il_op_new_fcast_int(
		0,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11.11));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "length of casted bitvector should not be 0.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_icast_to_float() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fcast_float(
		RZ_FLOAT_IEEE754_BIN_64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(64, 12));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_64)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fcast_float(
		RZ_FLOAT_IEEE754_BIN_64,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(11));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of fcast_float op is not a bitvector.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

static bool test_il_validate_pure_fconvert() {
	RzILValidateGlobalContext *ctx = rz_il_validate_global_context_new_empty(24);

	RzILOpPure *op = rz_il_op_new_fconvert(
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_float_from_f64(15.678));
	RzILSortPure sort;
	RzILValidateReport report = NULL;
	bool val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_true(val, "valid");
	mu_assert_true(rz_il_sort_pure_eq(sort, rz_il_sort_pure_float(RZ_FLOAT_IEEE754_BIN_32)), "sort");
	mu_assert_null(report, "no report");
	rz_il_op_pure_free(op);

	op = rz_il_op_new_fconvert(
		RZ_FLOAT_IEEE754_BIN_32,
		RZ_FLOAT_RMODE_RNE,
		rz_il_op_new_bitv_from_ut64(64, 1201));
	val = rz_il_validate_pure(op, ctx, &sort, &report);
	mu_assert_false(val, "invalid");
	rz_il_op_pure_free(op);
	mu_assert_streq_free(report, "operand of fconvert op is not a float.", "report");

	rz_il_validate_global_context_free(ctx);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_validate_pure_null);
	mu_run_test(test_il_validate_pure_bitv);
	mu_run_test(test_il_validate_pure_bool);
	mu_run_test(test_il_validate_pure_ite);
	mu_run_test(test_il_validate_pure_let);
	mu_run_test(test_il_validate_pure_var);
	mu_run_test(test_il_validate_pure_inv);
	mu_run_test(test_il_validate_pure_bool_binop);
	mu_run_test(test_il_validate_pure_bitv_binop);
	mu_run_test(test_il_validate_pure_bitv_bool_unop);
	mu_run_test(test_il_validate_pure_bitv_unop);
	mu_run_test(test_il_validate_pure_shift);
	mu_run_test(test_il_validate_pure_cmp);
	mu_run_test(test_il_validate_pure_cast);
	mu_run_test(test_il_validate_pure_append);
	mu_run_test(test_il_validate_pure_load);
	mu_run_test(test_il_validate_pure_loadw);
	mu_run_test(test_il_validate_effect_null);
	mu_run_test(test_il_validate_effect_empty);
	mu_run_test(test_il_validate_effect_nop);
	mu_run_test(test_il_validate_effect_store);
	mu_run_test(test_il_validate_effect_storew);
	mu_run_test(test_il_validate_effect_set);
	mu_run_test(test_il_validate_effect_jmp);
	mu_run_test(test_il_validate_effect_goto);
	mu_run_test(test_il_validate_effect_seq);
	mu_run_test(test_il_validate_effect_blk);
	mu_run_test(test_il_validate_effect_repeat);
	mu_run_test(test_il_validate_effect_branch);
	mu_run_test(test_il_validate_pure_float);
	mu_run_test(test_il_validate_pure_float80);
	mu_run_test(test_il_validate_pure_fbits);
	mu_run_test(test_il_validate_pure_float_bool_uop);
	mu_run_test(test_il_validate_pure_float_uop);
	mu_run_test(test_il_validate_pure_float_uop_with_round);
	mu_run_test(test_il_validate_pure_forder);
	mu_run_test(test_il_validate_pure_float_binop_with_round);
	mu_run_test(test_il_validate_pure_float_terop_with_round);
	mu_run_test(test_il_validate_pure_float_hybridop_with_round);
	mu_run_test(test_il_validate_pure_fcast_to_int);
	mu_run_test(test_il_validate_pure_icast_to_float);
	mu_run_test(test_il_validate_pure_fconvert);

	return tests_passed != tests_run;
}

mu_main(all_tests)
