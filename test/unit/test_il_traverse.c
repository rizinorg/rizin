// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il.h>
#include <rz_util.h>
#include "minunit.h"

#include <rz_il/rz_il_opbuilder_begin.h>

static RzILOpPure *build_op_pure() {
	return ITE(
		ULE(LOAD(U32(42)), VARG("r0")),
		ADD(U32(123), VARG("r1")),
		LET("tmp", U32(13), VARL("tmp")));
}

static RzILOpEffect *build_op_effect() {
	return BRANCH(
		IL_TRUE,
		SETG("r0", build_op_pure()),
		REPEAT(IL_FALSE, STOREW(U32(42), U32(123))));
}

#include <rz_il/rz_il_opbuilder_end.h>

static RzILRecurseCont pure_rec_cb(RzILOpPure *op, void *user) {
	RzVector *vec = user;
	ut64 code = op->code;
	rz_vector_push(vec, &code);
	return RZ_IL_RECURSE_STEP_INTO;
}

static RzILRecurseCont pure_rec_cb_break(RzILOpPure *op, void *user) {
	RzVector *vec = user;
	ut64 code = op->code;
	rz_vector_push(vec, &code);
	if (op->code == RZ_IL_OP_LOAD) {
		return RZ_IL_RECURSE_BREAK;
	}
	return RZ_IL_RECURSE_STEP_INTO;
}

static RzILRecurseCont pure_rec_cb_step_over(RzILOpPure *op, void *user) {
	RzVector *vec = user;
	ut64 code = op->code;
	rz_vector_push(vec, &code);
	if (op->code == RZ_IL_OP_LOAD || op->code == RZ_IL_OP_LET) {
		return RZ_IL_RECURSE_STEP_OVER;
	}
	return RZ_IL_RECURSE_STEP_INTO;
}

static bool test_il_pure_recurse() {
	RzILOpPure *op = build_op_pure();
	RzVector vec;
	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_pure_recurse(op, pure_rec_cb, &vec);
	mu_assert_eq(rz_vector_len(&vec), 11, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), RZ_IL_OP_ITE, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_ULE, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), RZ_IL_OP_LOAD, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), RZ_IL_OP_BITV, "op 3");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 4), RZ_IL_OP_VAR, "op 4");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 5), RZ_IL_OP_ADD, "op 5");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 6), RZ_IL_OP_BITV, "op 6");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 7), RZ_IL_OP_VAR, "op 7");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 8), RZ_IL_OP_LET, "op 8");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 9), RZ_IL_OP_BITV, "op 9");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 10), RZ_IL_OP_VAR, "op 10");
	rz_vector_fini(&vec);
	mu_end;
}

static bool test_il_pure_recurse_break() {
	RzILOpPure *op = build_op_pure();
	RzVector vec;
	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_pure_recurse(op, pure_rec_cb_break, &vec);
	mu_assert_eq(rz_vector_len(&vec), 3, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), RZ_IL_OP_ITE, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_ULE, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), RZ_IL_OP_LOAD, "op 2");
	rz_vector_fini(&vec);
	mu_end;
}

static bool test_il_pure_recurse_step_over() {
	RzILOpPure *op = build_op_pure();
	RzVector vec;
	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_pure_recurse(op, pure_rec_cb_step_over, &vec);
	mu_assert_eq(rz_vector_len(&vec), 8, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), RZ_IL_OP_ITE, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_ULE, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), RZ_IL_OP_LOAD, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), RZ_IL_OP_VAR, "op 3");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 4), RZ_IL_OP_ADD, "op 4");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 5), RZ_IL_OP_BITV, "op 5");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 6), RZ_IL_OP_VAR, "op 6");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 7), RZ_IL_OP_LET, "op 7");
	rz_vector_fini(&vec);
	mu_end;
}

static RzILRecurseCont effect_rec_cb(RzILOpEffect *op, void *user) {
	RzVector *vec = user;
	ut64 code = (1ull << 63) | (ut64)op->code;
	rz_vector_push(vec, &code);
	return RZ_IL_RECURSE_STEP_INTO;
}

static RzILRecurseCont effect_rec_cb_break(RzILOpEffect *op, void *user) {
	RzVector *vec = user;
	ut64 code = (1ull << 63) | (ut64)op->code;
	rz_vector_push(vec, &code);
	if (op->code == RZ_IL_OP_SET) {
		return RZ_IL_RECURSE_BREAK;
	}
	return RZ_IL_RECURSE_STEP_INTO;
}

static RzILRecurseCont effect_rec_cb_step_over(RzILOpEffect *op, void *user) {
	RzVector *vec = user;
	ut64 code = (1ull << 63) | (ut64)op->code;
	rz_vector_push(vec, &code);
	if (op->code == RZ_IL_OP_SET || op->code == RZ_IL_OP_REPEAT) {
		return RZ_IL_RECURSE_STEP_OVER;
	}
	return RZ_IL_RECURSE_STEP_INTO;
}

static bool test_il_effect_recurse() {
	RzILOpEffect *op = build_op_effect();
	RzVector vec;
	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_effect_recurse(op, effect_rec_cb, &vec, pure_rec_cb, &vec);
	mu_assert_eq(rz_vector_len(&vec), 19, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), (1ull << 63) | (ut64)RZ_IL_OP_BRANCH, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_B1, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), (1ull << 63) | (ut64)RZ_IL_OP_SET, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), RZ_IL_OP_ITE, "op 3");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 4), RZ_IL_OP_ULE, "op 4");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 5), RZ_IL_OP_LOAD, "op 5");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 6), RZ_IL_OP_BITV, "op 6");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 7), RZ_IL_OP_VAR, "op 7");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 8), RZ_IL_OP_ADD, "op 8");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 9), RZ_IL_OP_BITV, "op 9");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 10), RZ_IL_OP_VAR, "op 10");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 11), RZ_IL_OP_LET, "op 11");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 12), RZ_IL_OP_BITV, "op 12");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 13), RZ_IL_OP_VAR, "op 13");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 14), (1ull << 63) | (ut64)RZ_IL_OP_REPEAT, "op 14");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 15), RZ_IL_OP_B0, "op 15");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 16), (1ull << 63) | (ut64)RZ_IL_OP_STOREW, "op 16");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 17), RZ_IL_OP_BITV, "op 17");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 18), RZ_IL_OP_BITV, "op 18");
	rz_vector_fini(&vec);

	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_effect_recurse(op, NULL, NULL, pure_rec_cb, &vec);
	mu_assert_eq(rz_vector_len(&vec), 15, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), RZ_IL_OP_B1, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_ITE, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), RZ_IL_OP_ULE, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), RZ_IL_OP_LOAD, "op 3");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 4), RZ_IL_OP_BITV, "op 4");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 5), RZ_IL_OP_VAR, "op 5");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 6), RZ_IL_OP_ADD, "op 6");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 7), RZ_IL_OP_BITV, "op 7");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 8), RZ_IL_OP_VAR, "op 8");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 9), RZ_IL_OP_LET, "op 9");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 10), RZ_IL_OP_BITV, "op 10");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 11), RZ_IL_OP_VAR, "op 11");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 12), RZ_IL_OP_B0, "op 12");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 13), RZ_IL_OP_BITV, "op 13");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 14), RZ_IL_OP_BITV, "op 14");
	rz_vector_fini(&vec);

	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_effect_recurse(op, effect_rec_cb, &vec, NULL, NULL);
	mu_assert_eq(rz_vector_len(&vec), 4, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), (1ull << 63) | (ut64)RZ_IL_OP_BRANCH, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), (1ull << 63) | (ut64)RZ_IL_OP_SET, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), (1ull << 63) | (ut64)RZ_IL_OP_REPEAT, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), (1ull << 63) | (ut64)RZ_IL_OP_STOREW, "op 3");
	rz_vector_fini(&vec);
	mu_end;
}

static bool test_il_effect_recurse_break() {
	RzILOpEffect *op = build_op_effect();
	RzVector vec;
	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_effect_recurse(op, effect_rec_cb_break, &vec, pure_rec_cb, &vec);
	mu_assert_eq(rz_vector_len(&vec), 3, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), (1ull << 63) | (ut64)RZ_IL_OP_BRANCH, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_B1, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), (1ull << 63) | (ut64)RZ_IL_OP_SET, "op 2");
	rz_vector_fini(&vec);

	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_effect_recurse(op, effect_rec_cb, &vec, pure_rec_cb_break, &vec);
	mu_assert_eq(rz_vector_len(&vec), 6, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), (1ull << 63) | (ut64)RZ_IL_OP_BRANCH, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_B1, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), (1ull << 63) | (ut64)RZ_IL_OP_SET, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), RZ_IL_OP_ITE, "op 3");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 4), RZ_IL_OP_ULE, "op 4");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 5), RZ_IL_OP_LOAD, "op 5");
	rz_vector_fini(&vec);
	mu_end;
}

static bool test_il_effect_recurse_step_over() {
	RzILOpEffect *op = build_op_effect();
	RzVector vec;
	rz_vector_init(&vec, sizeof(ut64), NULL, NULL);
	rz_il_op_effect_recurse(op, effect_rec_cb_step_over, &vec, pure_rec_cb, &vec);
	mu_assert_eq(rz_vector_len(&vec), 4, "traversed length");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 0), (1ull << 63) | (ut64)RZ_IL_OP_BRANCH, "op 0");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 1), RZ_IL_OP_B1, "op 1");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 2), (1ull << 63) | (ut64)RZ_IL_OP_SET, "op 2");
	mu_assert_eq(*(ut64 *)rz_vector_index_ptr(&vec, 3), (1ull << 63) | (ut64)RZ_IL_OP_REPEAT, "op 3");
	rz_vector_fini(&vec);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_il_pure_recurse);
	mu_run_test(test_il_pure_recurse_break);
	mu_run_test(test_il_pure_recurse_step_over);
	mu_run_test(test_il_effect_recurse);
	mu_run_test(test_il_effect_recurse_break);
	mu_run_test(test_il_effect_recurse_step_over);
	return tests_passed != tests_run;
}

mu_main(all_tests)
