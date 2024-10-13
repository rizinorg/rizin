// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "minunit.h"

#define SWITCH_TO_ARCH_BITS(arch, bits) \
	rz_analysis_use(analysis, arch); \
	rz_analysis_set_bits(analysis, bits);

bool test_rz_analysis_op_val() {
	RzAnalysis *analysis = rz_analysis_new();
	RzAnalysisOp op;
	SWITCH_TO_ARCH_BITS("x86", 64);
	// mov rax, [rbx+rcx+4]
	rz_analysis_op_init(&op);
	int len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x48\x8b\x44\x0b\x04", 5, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 5, "Op is of size 5");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "rax", "Dst reg should be rax");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_MEM, "Source should be mem");
	mu_assert_streq(op.src[0]->reg->name, "rbx", "Source reg base should be rbx");
	mu_assert_streq(op.src[0]->regdelta->name, "rcx", "Source reg delta should be rcx");
	mu_assert_eq(op.src[0]->delta, 4, "Source delta should be 4");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x48\xc7\xc0\x04\x00\x00\x00", 7, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 7, "Op is of size 7");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_IMM, "Source should be imm");
	mu_assert_eq(op.src[0]->imm, 4, "Source imm should be 4");
	rz_analysis_op_fini(&op);

	SWITCH_TO_ARCH_BITS("arm", 64);
	// ldr x1, [x2, x3]
	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x41\x68\x63\xf8", 4, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 4, "Op is of size 4");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "x1", "Dst reg should be x1");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_MEM, "Source should be mem");
	mu_assert_streq(op.src[0]->reg->name, "x2", "Source reg base should be x2");
	mu_assert_streq(op.src[0]->regdelta->name, "x3", "Source reg base should be x3");
	rz_analysis_op_fini(&op);
	// mov x1, 400
	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x01\x32\x80\xd2", 4, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 4, "Op is of size 4");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "x1", "Dst reg should be x1");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_IMM, "Source should be imm");
	mu_assert_eq(op.src[0]->imm, 400, "Source imm should be 400");
	rz_analysis_op_fini(&op);

	SWITCH_TO_ARCH_BITS("arm", 32);
	// ldr r1, [ r2, r3 ]
	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x03\x10\x92\xe7", 4, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 4, "Op is of size 4");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "r1", "Dst reg should be r1");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_MEM, "Source should be mem");
	mu_assert_streq(op.src[0]->reg->name, "r2", "Source reg base should be r2");
	mu_assert_streq(op.src[0]->regdelta->name, "r3", "Source reg base should be r3");
	rz_analysis_op_fini(&op);

	SWITCH_TO_ARCH_BITS("arm", 16);
	// ldr r1, [ r2, r3 ]
	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\xd1\x58", 2, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 2, "Op is of size 2");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "r1", "Dst reg should be r1");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_MEM, "Source should be mem");
	mu_assert_streq(op.src[0]->reg->name, "r2", "Source reg base should be r2");
	mu_assert_streq(op.src[0]->regdelta->name, "r3", "Source reg base should be r3");
	rz_analysis_op_fini(&op);

#if WITH_GPL
	SWITCH_TO_ARCH_BITS("riscv", 32);
	// lw s10, 64(sp)
	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x06\x4d", 2, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 2, "Op is of size 2");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_REG, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "s10", "Dst reg should be s10");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_MEM, "Source should be mem");
	mu_assert_streq(op.src[0]->reg->name, "sp", "Source reg base should be sp");
	mu_assert_eq(op.src[0]->delta, 64, "Source delta should be 64");
	rz_analysis_op_fini(&op);
	// sw s0, 136(sp)
	rz_analysis_op_init(&op);
	len = rz_analysis_op(analysis, &op, 0, (const ut8 *)"\x22\xc5", 2, RZ_ANALYSIS_OP_MASK_VAL);
	mu_assert_eq(len, 2, "Op is of size 2");
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_MEM, "Destination should be reg");
	mu_assert_streq(op.dst->reg->name, "sp", "Dst reg should be s10");
	mu_assert_eq(op.dst->delta, 136, "Source delta should be 64");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_REG, "Source should be reg");
	mu_assert_streq(op.src[0]->reg->name, "s0", "Source reg base should be s0");
	rz_analysis_op_fini(&op);
#endif

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_core_analysis_bytes() {
	RzCore *core = rz_core_new();
	rz_core_set_asm_configs(core, "x86", 64, 0);
	ut8 buf[128];
	int len = rz_hex_str2bin("678D40C0", buf);
	RzIterator *iter = rz_core_analysis_bytes(core, core->offset, buf, len, 0);
	mu_assert_notnull(iter, "rz_core_analysis_bytes");

	RzAnalysisBytes *ab = rz_iterator_next(iter);
	mu_assert_streq(ab->opcode, "push rbp", "rz_core_analysis_bytes opcode");

	ab = rz_iterator_next(iter);
	mu_assert_streq(ab->opcode, "mov rbp, rsp", "rz_core_analysis_bytes opcode");
	mu_assert_streq(ab->pseudo, "rbp = rsp", "rz_core_analysis_bytes pseudo");

	ab = rz_iterator_next(iter);
	mu_assert_streq(ab->opcode, "mov dword [rbp - 4], edi", "rz_core_analysis_bytes opcode");
	mu_assert_streq(ab->pseudo, "dword [rbp - 4] = edi", "rz_core_analysis_bytes pseudo");

	rz_iterator_free(iter);
	rz_core_free(core);
	mu_end;
}

bool test_rz_core_print_disasm() {
	RzCore *core = rz_core_new();
	rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL); // needed to get arrow info (is_valid_offset checks)
	rz_core_set_asm_configs(core, "x86", 64, 0);
	rz_config_set_b(core->config, "asm.lines", false); // arrow info in struct, but not in textual disasm
	ut8 buf[128];
	int len = rz_hex_str2bin("554889e5897dfcebf8", buf);
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_analysis_disasm_text_free);
	RzCoreDisasmOptions options = {
		.vec = vec,
		.cbytes = 1,
	};
	mu_assert_notnull(vec, "rz_core_print_disasm vec not null");
	rz_core_print_disasm(core, 0, buf, len, len, NULL, &options);

	mu_assert_eq(rz_pvector_len(vec), 4, "rz_core_print_disasm len");
	RzAnalysisDisasmText *t = rz_pvector_at(vec, 0);
	mu_assert_eq(t->offset, 0, "rz_core_print_disasm offset");
	mu_assert_eq(t->arrow, UT64_MAX, "rz_core_print_disasm arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1b[32m\x1b[7m0x00000000\x1b[0m      \x1b[35mpush\x1b[0m\x1b[37m  \x1b[0m\x1b[36mrbp\x1b[0m\x1b[0m\x1b[0m",
		"rz_core_print_disasm text");

	t = rz_pvector_at(vec, 1);
	mu_assert_eq(t->offset, 1, "rz_core_print_disasm offset");
	mu_assert_eq(t->arrow, UT64_MAX, "rz_core_print_disasm arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1b[32m0x00000001\x1b[0m      \x1b[37mmov\x1b[0m\x1b[37m   \x1b[0m\x1b[36mrbp\x1b[0m\x1b[37m, \x1b[0m\x1b[36mrsp\x1b[0m\x1b[0m\x1b[0m",
		"rz_core_print_disasm text");

	t = rz_pvector_at(vec, 2);
	mu_assert_eq(t->offset, 4, "rz_core_print_disasm offset");
	mu_assert_eq(t->arrow, UT64_MAX, "rz_core_print_disasm arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1b[32m0x00000004\x1b[0m      \x1b[37mmov\x1b[0m\x1b[37m   \x1b[0m\x1b[37mdword\x1b[0m\x1b[37m [\x1b[0m\x1b[36mrbp\x1b[0m\x1b[37m \x1b[0m\x1b[37m-\x1b[0m\x1b[37m \x1b[0m\x1b[33m4\x1b[0m\x1b[37m], \x1b[0m\x1b[36medi\x1b[0m\x1b[0m\x1b[0m",
		"rz_core_print_disasm text");

	t = rz_pvector_at(vec, 3);
	mu_assert_eq(t->offset, 7, "rz_core_print_disasm offset");
	mu_assert_eq(t->arrow, 1, "rz_core_print_disasm arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1b[32m0x00000007\x1b[0m      \x1b[32mjmp\x1b[0m\x1b[37m   \x1b[0m\x1b[33m1\x1b[0m\x1b[0m\x1b[0m",
		"rz_core_print_disasm text");

	rz_core_free(core);
	rz_pvector_free(vec);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_op_val);
	mu_run_test(test_rz_core_analysis_bytes);
	mu_run_test(test_rz_core_print_disasm);
	return tests_passed != tests_run;
}

mu_main(all_tests)
