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

	const ut8 buffer[] = { 0x00, 0xaa, 0x01, 0x27, 0x0a };

	// Test IDE_BOL (0x00 imm8)
	rz_asm_op_init(&op);
	int len = rz_asm_disassemble(a, &op, buffer, (int)sizeof(buffer));
	mu_assert_eq(len, 2, "IDE_BOL instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "IDE_BOL 0xaa", "IDE_BOL disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test Push [FC0D134] (0x01)
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 2, (int)sizeof(buffer) - 2);
	mu_assert_eq(len, 1, "Push [FC0D134] instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "Push [FC0D134]", "Push [FC0D134] disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test PushVarError (0x27) with an additional immediate byte so the disassembler
	// can print the legacy LitI2_Byte-style alias too.
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 3, (int)sizeof(buffer) - 3);
	mu_assert_eq(len, 2, "PushVarError/LitI2_Byte instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "PushVarError 0x80020004 ; LitI2_Byte 10", "PushVarError/LitI2_Byte disassembly mismatch");
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

	// Extended coverage aligned with `analysis_mspcode`:
	// 0x1B: PushPtr imm16
	// 0x1C: IfZ +imm16
	// 0x1D: IfNZ +imm16
	// 0x1E: Jmp +imm16
	// 0x32: variable-size op => 1 + 2 + nbytes
	const ut8 buffer[] = {
		0x1B, 0x34, 0x12, // PushPtr 0x1234
		0x1C, 0x08, 0x00, // IfZ +0x0008
		0x1D, 0x09, 0x00, // IfNZ +0x0009
		0x1E, 0x0A, 0x00, // Jmp +0x000A
		0x32, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44 // VarOp 0x32 nbytes=4
	};

	// Test PushPtr (0x1B imm16)
	rz_asm_op_init(&op);
	int len = rz_asm_disassemble(a, &op, buffer, (int)sizeof(buffer));
	mu_assert_eq(len, 3, "PushPtr instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "PushPtr 0x1234", "PushPtr disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test IfZ (0x1C imm16)
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 3, (int)sizeof(buffer) - 3);
	mu_assert_eq(len, 3, "IfZ instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "IfZ +0x0008", "IfZ disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test IfNZ (0x1D imm16)
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 6, (int)sizeof(buffer) - 6);
	mu_assert_eq(len, 3, "IfNZ instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "IfNZ +0x0009", "IfNZ disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test Jmp (0x1E imm16)
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 9, (int)sizeof(buffer) - 9);
	mu_assert_eq(len, 3, "Jmp instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "Jmp +0x000a", "Jmp disassembly mismatch");
	rz_asm_op_fini(&op);

	// Test variable-size (0x32 nbytes=4) => size 7
	rz_asm_op_init(&op);
	len = rz_asm_disassemble(a, &op, buffer + 12, (int)sizeof(buffer) - 12);
	mu_assert_eq(len, 7, "VarOp 0x32 instruction length mismatch");
	mu_assert_streq(rz_strbuf_get(&op.buf_asm), "VarOp 0x32 nbytes=4", "VarOp 0x32 disassembly mismatch");
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
