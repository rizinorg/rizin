// SPDX-FileCopyrightText: 2026 Ashish Kumar <15678ashishk@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include "minunit.h"

static bool test_mspcode_disassemble(void) {
	RzAsm *a = rz_asm_new();
	mu_assert_notnull(a, "Failed to create RzAsm");

	bool ret = rz_asm_use(a, "mspcode");
	mu_assert_true(ret, "Failed to use mspcode plugin");

	RzAsmOp op;
	const ut8 buffer[] = { 0x00, 0x01, 0x27, 0x0a }; // Add, Sub, LitI2_Byte 10

	// Test Add
	rz_asm_op_init(&op);
	int len = rz_asm_disassemble(a, &op, buffer, 4);
	mu_assert_eq(len, 1, "Add instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "Add", "Add disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test Sub
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 1, 3);
	mu_assert_eq(len, 1, "Sub instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "Sub", "Sub disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test LitI2_Byte
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 2, 2);
	mu_assert_eq(len, 2, "LitI2_Byte instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "LitI2_Byte 10", "LitI2_Byte disassembly mismatch");
	rz_asm_op_fini(&op);

	rz_asm_free(a);
	mu_end;
}

static bool test_mspcode_disassemble_extended(void) {
	RzAsm *a = rz_asm_new();
	mu_assert_notnull(a, "Failed to create RzAsm");

	bool ret = rz_asm_use(a, "mspcode");
	mu_assert_true(ret, "Failed to use mspcode plugin");

	RzAsmOp op;
	const ut8 buffer[] = { 0x1B, 0x1C, 0x1D, 0x04 };

	// Test 0x1B
	rz_asm_op_init(&op);
	int len = rz_asm_disassemble(a, &op, buffer, 1);
	mu_assert_true(len > 0, "Instruction length should be > 0");
	rz_asm_op_fini(&op);

	// Test 0x1C
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 1, 1);
	mu_assert_true(len > 0, "Instruction length should be > 0");
	rz_asm_op_fini(&op);

	// Test 0x1D
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 2, 1);
	mu_assert_true(len > 0, "Instruction length should be > 0");
	rz_asm_op_fini(&op);

	rz_asm_free(a);
	mu_end;
}

static bool all_tests() {
	mu_run_test(test_mspcode_disassemble);
	mu_run_test(test_mspcode_disassemble_extended);
	return tests_passed != tests_run;
}

mu_main(all_tests)
