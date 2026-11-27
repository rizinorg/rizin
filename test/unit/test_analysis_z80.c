// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include "minunit.h"

/* Regression test for https://github.com/rizinorg/rizin/issues/7011:
 * the z80 analysis decoder read bytes past the caller's buffer when the
 * opcode was not yet fully fetched. Every operand read is now length-guarded;
 * truncated instructions must decode without reading out of bounds. */

static RzAnalysis *z80_analysis(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	if (!analysis) {
		return NULL;
	}
	if (!rz_analysis_use(analysis, "z80") || !rz_analysis_set_bits(analysis, 8)) {
		rz_analysis_free(analysis);
		return NULL;
	}
	return analysis;
}

bool test_z80_analysis_op_truncated(void) {
	RzAnalysis *analysis = z80_analysis();
	if (!analysis) {
		eprintf("z80 analysis plugin not available (use_gpl=false?), skipping\n");
		return true;
	}
	const ut8 jr_truncated[] = { 0x18 };
	const ut8 djnz_truncated[] = { 0x10 };
	const ut8 ld_nn_truncated[] = { 0x22 };
	const ut8 ld_nn_short[] = { 0x22, 0x34 };
	const ut8 call_truncated[] = { 0xcd };
	const ut8 call_short[] = { 0xcd, 0x34 };
	const ut8 jp_truncated[] = { 0xc3 };
	const ut8 jp_short[] = { 0xc3, 0x34 };
	const ut8 ed_truncated[] = { 0xed };
	const ut8 ed_store[] = { 0xed, 0x43 };
	const ut8 ed_store_short[] = { 0xed, 0x43, 0x12 };
	const ut8 dd_truncated[] = { 0xdd };
	const ut8 dd_store[] = { 0xdd, 0x22 };
	const ut8 dd_store_short[] = { 0xdd, 0x22, 0x12 };
	const ut8 fd_truncated[] = { 0xfd };
	const ut8 cb_truncated[] = { 0xcb };

	const struct {
		const ut8 *bytes;
		int len;
		ut64 expect_jump;
		ut64 expect_ptr;
		const char *name;
	} cases[] = {
		{ jr_truncated, sizeof(jr_truncated), 0x1000 + 2, UT64_MAX, "jr with only the opcode" },
		{ djnz_truncated, sizeof(djnz_truncated), 0x1000 + 2, UT64_MAX, "djnz with only the opcode" },
		{ ld_nn_truncated, sizeof(ld_nn_truncated), UT64_MAX, 0, "ld (nn), hl with only the opcode" },
		{ ld_nn_short, sizeof(ld_nn_short), UT64_MAX, 0, "ld (nn), hl with a truncated address" },
		{ call_truncated, sizeof(call_truncated), 0, UT64_MAX, "call with only the opcode" },
		{ call_short, sizeof(call_short), 0, UT64_MAX, "call with a truncated address" },
		{ jp_truncated, sizeof(jp_truncated), 0, UT64_MAX, "jp with only the opcode" },
		{ jp_short, sizeof(jp_short), 0, UT64_MAX, "jp with a truncated address" },
		{ ed_truncated, sizeof(ed_truncated), UT64_MAX, UT64_MAX, "0xed prefix with no opcode byte" },
		{ ed_store, sizeof(ed_store), UT64_MAX, 0, "0xed store with no address" },
		{ ed_store_short, sizeof(ed_store_short), UT64_MAX, 0, "0xed store with a truncated address" },
		{ dd_truncated, sizeof(dd_truncated), UT64_MAX, UT64_MAX, "0xdd prefix with no opcode byte" },
		{ dd_store, sizeof(dd_store), UT64_MAX, 0, "dd store with no address" },
		{ dd_store_short, sizeof(dd_store_short), UT64_MAX, 0, "dd store with a truncated address" },
		{ fd_truncated, sizeof(fd_truncated), UT64_MAX, UT64_MAX, "0xfd prefix with no opcode byte" },
		{ cb_truncated, sizeof(cb_truncated), UT64_MAX, UT64_MAX, "0xcb prefix with no opcode byte" },
	};

	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		RzAnalysisOp op = { 0 };
		rz_analysis_op_init(&op);
		rz_analysis_op(analysis, &op, 0x1000, cases[i].bytes, cases[i].len, RZ_ANALYSIS_OP_MASK_ALL);
		mu_assert_eq(op.jump, cases[i].expect_jump, cases[i].name);
		mu_assert_eq(op.ptr, cases[i].expect_ptr, cases[i].name);
		rz_analysis_op_fini(&op);
	}

	rz_analysis_free(analysis);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_z80_analysis_op_truncated);
	return tests_passed != tests_run;
}

mu_main(all_tests)
