// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "minunit.h"

#define SWITCH_TO_ARCH_BITS(arch, bits) \
	rz_analysis_use(analysis, arch); \
	rz_analysis_set_bits(analysis, bits);

bool test_rz_analysis_op_val() {
	RzAnalysis *analysis = rz_analysis_new(NULL);
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

	SWITCH_TO_ARCH_BITS("riscv", 32);
	rz_analysis_set_cpu(analysis, "rv32i2p0_c2p0");
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
	mu_assert_eq(op.dst->type, RZ_ANALYSIS_VAL_MEM, "Destination should be mem");
	mu_assert_streq(op.dst->reg->name, "sp", "Dst reg should be s10");
	mu_assert_eq(op.dst->delta, 136, "Source delta should be 64");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_REG, "Source should be reg");
	mu_assert_streq(op.src[0]->reg->name, "s0", "Source reg base should be s0");
	rz_analysis_op_fini(&op);

	rz_analysis_free(analysis);
	mu_end;
}

bool test_rz_core_analysis_bytes() {
	RzCore *core = rz_core_new();
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);

	ut8 buf[128];
	int len = rz_hex_str2bin("554889e5897dfc", buf);
	RzIterator iter = (RzIterator){ 0 };
	mu_assert_true(rz_core_analysis_bytes(core, core->offset, buf, len, 0, &iter), "rz_core_analysis_bytes failed");

	RzCoreDecodedBytes *ab = rz_iterator_next(&iter);
	mu_assert_streq(ab->opcode, "push rbp", "rz_core_analysis_bytes opcode");

	ab = rz_iterator_next(&iter);
	mu_assert_streq(ab->opcode, "mov rbp, rsp", "rz_core_analysis_bytes opcode");
	mu_assert_streq(ab->pseudo, "rbp = rsp", "rz_core_analysis_bytes pseudo");

	ab = rz_iterator_next(&iter);
	mu_assert_streq(ab->opcode, "mov dword [rbp-0x04], edi", "rz_core_analysis_bytes opcode");
	mu_assert_streq(ab->pseudo, "dword [rbp-0x04] = edi", "rz_core_analysis_bytes pseudo");

	rz_iterator_fini(&iter);
	rz_core_free(core);
	mu_end;
}

bool test_rz_core_analysis_bytes_respect_buffer_len() {
	RzCore *core = rz_core_new();
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);

	// 7 bytes = 3 ops: push rbp; mov rbp, rsp; mov dword [rbp-0x04], edi
	ut8 buf[128];
	int len = rz_hex_str2bin("554889e5897dfc", buf);

	// max_ops larger than the number of ops fitting in the buffer must not
	// make the iterator decode past the end of the provided buffer.
	RzIterator iter = (RzIterator){ 0 };
	mu_assert_true(rz_core_analysis_bytes(core, core->offset, buf, len, 100, &iter), "rz_core_analysis_bytes failed");
	int count = 0;
	RzCoreDecodedBytes *ab;
	while ((ab = rz_iterator_next(&iter))) {
		count++;
		mu_assert_true(ab->an_op.addr >= core->offset && ab->an_op.addr < (ut64)core->offset + len, "op addr must be inside the provided buffer");
	}
	mu_assert_eq(count, 3, "the iterator must stop at the end of the buffer even when max_ops is not reached");
	rz_iterator_fini(&iter);

	// max_ops smaller than the ops fitting in the buffer still wins
	RzIterator iter2 = (RzIterator){ 0 };
	mu_assert_true(rz_core_analysis_bytes(core, core->offset, buf, len, 2, &iter2), "rz_core_analysis_bytes failed");
	count = 0;
	while ((ab = rz_iterator_next(&iter2))) {
		count++;
	}
	mu_assert_eq(count, 2, "max_ops must still be honored");
	rz_iterator_fini(&iter2);

	rz_core_free(core);
	mu_end;
}

bool test_rz_core_analysis_bytes_short_tail() {
	// ARM64 decodes a 4-byte op from the short tail, MIPS rejects it as invalid
	static const struct {
		const char *arch;
		int bits;
	} archs[] = { { "arm", 64 }, { "mips", 32 } };
	// only the first byte belongs to the range, the rest must never leak into the op
	const ut8 buf[] = { 0x00, 0xaa, 0xbb, 0xcc };

	for (size_t i = 0; i < RZ_ARRAY_SIZE(archs); i++) {
		RzCore *core = rz_core_new();
		rz_core_arch_configure(core, archs[i].arch, archs[i].bits, NULL, NULL, NULL);
		RzIterator iter = (RzIterator){ 0 };
		mu_assert_true(rz_core_analysis_bytes(core, 0, buf, 1, 1, &iter), "rz_core_analysis_bytes failed");
		RzCoreDecodedBytes *ab = rz_iterator_next(&iter);
		mu_assert_notnull(ab, "a 1-byte range must still yield an op");
		mu_assert_streq(ab->opcode, "invalid", "a truncated op is invalid");
		mu_assert_streq(ab->bytes, "00", "the op bytes must not go past the range");
		mu_assert_null(rz_iterator_next(&iter), "max_ops must be honored");
		rz_iterator_fini(&iter);
		rz_core_free(core);
	}
	mu_end;
}

bool test_rz_core_analysis_bytes_from_io() {
	RzCore *core = rz_core_new();
	rz_io_open_at(core->io, "malloc://0x1000", RZ_PERM_RWX, 0644, 0, NULL);
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);
	// more ops than one io window holds, so the iterator has to refill it
	ut8 nops[0x600];
	memset(nops, 0x90, sizeof(nops));
	mu_assert_true(rz_io_write_at(core->io, 0, nops, sizeof(nops)), "write the ops");

	RzIterator iter = (RzIterator){ 0 };
	mu_assert_true(rz_core_analysis_bytes(core, 0, NULL, 0, sizeof(nops), &iter), "rz_core_analysis_bytes from io");
	ut64 count = 0;
	RzCoreDecodedBytes *ab;
	while ((ab = rz_iterator_next(&iter))) {
		mu_assert_eq(ab->an_op.addr, count, "op address");
		mu_assert_streq(ab->opcode, "nop", "op read from io");
		count++;
	}
	mu_assert_eq(count, sizeof(nops), "max_ops is the only limit");
	rz_iterator_fini(&iter);

	mu_assert_true(rz_core_analysis_bytes(core, 0, NULL, 3, 0, &iter), "rz_core_analysis_bytes from io, byte limit");
	count = 0;
	while (rz_iterator_next(&iter)) {
		count++;
	}
	mu_assert_eq(count, 3, "n_bytes is the only limit");
	rz_iterator_fini(&iter);

	mu_assert_false(rz_core_analysis_bytes(core, 0, NULL, 0, 0, &iter), "no limit at all");
	rz_core_free(core);
	mu_end;
}

bool test_rz_core_print_disasm() {
	RzCore *core = rz_core_new();
	rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL); // needed to get arrow info (is_valid_offset checks)
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);

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
		"\x1b[32m0x00000004\x1b[0m      \x1b[37mmov\x1b[0m\x1b[37m   \x1b[0m\x1b[37mdword\x1b[0m\x1b[37m [\x1b[0m\x1b[36mrbp\x1b[0m\x1b[37m-\x1b[0m\x1b[33m0x04\x1b[0m\x1b[37m], \x1b[0m\x1b[36medi\x1b[0m\x1b[0m\x1b[0m",
		"rz_core_print_disasm text");

	t = rz_pvector_at(vec, 3);
	mu_assert_eq(t->offset, 7, "rz_core_print_disasm offset");
	mu_assert_eq(t->arrow, 1, "rz_core_print_disasm arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1b[32m0x00000007\x1b[0m      \x1b[32mjmp\x1b[0m\x1b[37m   \x1b[0m\x1b[33m0x1\x1b[0m\x1b[0m\x1b[0m",
		"rz_core_print_disasm text");

	rz_core_free(core);
	rz_pvector_free(vec);
	mu_end;
}

bool test_rz_core_print_disasm_resolve_aav_symbols() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new failed");
	RzIODesc *io_desc = rz_io_open_at(core->io, "malloc://0x200000", RZ_PERM_RWX, 0644, 0, NULL);
	mu_assert_notnull(io_desc, "io open failed");
	bool arch_configured = rz_core_arch_configure(core, "x86", 32, NULL, NULL, NULL);
	mu_assert_true(arch_configured, "rz_core_arch_configure failed");
	bool analysis_arch_set = rz_analysis_use(core->analysis, "x86");
	mu_assert_true(analysis_arch_set, "rz_analysis_use failed");
	bool analysis_bits_set = rz_analysis_set_bits(core->analysis, 32);
	mu_assert_true(analysis_bits_set, "rz_analysis_set_bits failed");
	rz_config_set_i(core->config, "scr.color", 0);
	rz_config_set_b(core->config, "asm.sub.names", true);
	rz_config_set_b(core->config, "asm.sub.rel", true);
	rz_config_set_i(core->config, "asm.sub.varmin", 0);

	ut8 code[] = { 0xa1, 0x20, 0x00, 0x10, 0x00 }; // mov eax, dword [0x100020]
	ut8 ptr[] = { 0x40, 0x00, 0x10, 0x00 }; // *(0x100020) = 0x100040
	rz_io_write_at(core->io, 0x100020, ptr, sizeof(ptr));

	rz_flag_space_set(core->flags, "symbols");
	rz_flag_set(core->flags, "aav.0x00100020", 0x100020, 4);
	rz_flag_set(core->flags, "obj.__stack_chk_guard", 0x100040, 4);

	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_analysis_disasm_text_free);
	mu_assert_notnull(vec, "rz_core_print_disasm vec not null");
	RzCoreDisasmOptions options = {
		.vec = vec,
		.cbytes = 1,
	};
	rz_core_print_disasm(core, 0, code, sizeof(code), sizeof(code), NULL, &options);

	size_t line_count = rz_pvector_len(vec);
	mu_assert_true(line_count >= 1, "rz_core_print_disasm should produce at least one line");
	RzAnalysisDisasmText *t = rz_pvector_at(vec, 0);
	mu_assert_notnull(t, "first disasm line");
	char *insn = rz_str_dup(t->text);
	mu_assert_notnull(insn, "instruction line copy");
	char *comment = strchr(insn, ';');
	if (comment) {
		*comment = '\0';
	}
	mu_assert_strcontains(insn, "obj.__stack_chk_guard", "aav.aav symbol should be resolved to preferred symbol");
	char *aav_symbol = strstr(insn, "aav.aav.");
	mu_assert_null(aav_symbol, "aav.aav symbol should not be present in instruction operand");
	free(insn);

	rz_core_free(core);
	rz_pvector_free(vec);
	mu_end;
}

bool test_rz_core_il_print_rzil() {
	RzCore *core = rz_core_new();
	rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RX, 0644, 0, NULL); // needed to get arrow info (is_valid_offset checks)
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);
	rz_config_set(core->config, "scr.color", "1");
	ut8 buf[128];
	int len = rz_hex_str2bin("554889e5897dfcebf8", buf);
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_analysis_disasm_text_free);
	RzCoreILPrintOptions options = { .cbytes = 1, .pretty = 0, .colorize = 1, .unicode = 1, .vec = vec };
	mu_assert_notnull(vec, "rz_core_il_print_rzil vec not null");
	rz_core_il_print_rzil(core, 0, buf, len, len, &options);

	mu_assert_eq(rz_pvector_len(vec), 4, "rz_core_il_print_rzil len");
	RzAnalysisDisasmText *t = rz_pvector_at(vec, 0);
	mu_assert_eq(t->offset, 0, "rz_core_il_print_rzil offset");
	mu_assert_eq(t->arrow, UT64_MAX, "rz_core_il_print_rzil arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1B[36m0x0\x1B[0m \x1B[90m((\x1B[0m\x1B[31mfinal\x1B[0m \x1B[36m\xE2\x86\x90\x1B[0m \x1B[90m(\x1B[0m\x1B[31mrsp\x1B[0m \x1B[36m-\x1B[0m \x1B[33m0x8\xE2\x82\x86\xE2\x82\x84\x1B[0m\x1B[90m))\x1B[0m\n    \x1B[90m(\x1B[0m\x1B[36m\xEA\x9C\xB1\xE1\xB4\x9B\xE2\x82\x80\x1B[0m \x1B[90m(\x1B[0m\x1B[31mrbp\x1B[0m \x1B[36m\xE2\x89\x88\xE2\x82\x86\xE2\x82\x84\x1B[0m \x1B[36m\xE2\x8A\xA5\x1B[0m\x1B[90m)\x1B[0m \x1B[31mfinal\x1B[0m\x1B[90m)\x1B[0m \x1B[90m(\x1B[0m\x1B[31mrsp\x1B[0m \x1B[36m\xE2\x86\x90\x1B[0m \x1B[31mfinal\x1B[0m\x1B[90m))\x1B[0m",
		"rz_core_il_print_rzil text");

	t = rz_pvector_at(vec, 1);
	mu_assert_eq(t->offset, 1, "rz_core_il_print_rzil offset");
	mu_assert_eq(t->arrow, UT64_MAX, "rz_core_il_print_rzil arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1B[36m0x1\x1B[0m \x1B[90m(\x1B[0m\x1B[31mrbp\x1B[0m \x1B[36m\xE2\x86\x90\x1B[0m \x1B[31mrsp\x1B[0m\x1B[90m)\x1B[0m",
		"rz_core_il_print_rzil text");

	t = rz_pvector_at(vec, 2);
	mu_assert_eq(t->offset, 4, "rz_core_il_print_rzil offset");
	mu_assert_eq(t->arrow, UT64_MAX, "rz_core_il_print_rzil arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1B[36m0x4\x1B[0m \x1B[90m(\x1B[0m\x1B[36m\xEA\x9C\xB1\xE1\xB4\x9B\xE2\x82\x80\x1B[0m \x1B[90m(\x1B[0m\x1B[31mrdi\x1B[0m \x1B[36m\xE2\x89\x88\xE2\x82\x83\xE2\x82\x82\x1B[0m \x1B[36m\xE2\x8A\xA5\x1B[0m\x1B[90m)\x1B[0m \x1B[90m(\x1B[0m\x1B[31mrbp\x1B[0m \x1B[36m+\x1B[0m \x1B[33m0xfffffffffffffffc\xE2\x82\x86\xE2\x82\x84\x1B[0m\x1B[90m))\x1B[0m",
		"rz_core_il_print_rzil text");

	t = rz_pvector_at(vec, 3);
	mu_assert_eq(t->offset, 7, "rz_core_il_print_rzil offset");
	mu_assert_eq(t->arrow, 1, "rz_core_il_print_rzil arrow");
	mu_assert_streq_free(rz_str_trim_dup(t->text),
		"\x1B[36m0x7\x1B[0m \x1B[36m\xE2\x86\xB7\x1B[0m \x1B[90m(\x1B[0m\x1B[33m0x1\xE2\x82\x86\xE2\x82\x84\x1B[0m \x1B[36m\xE2\x89\x88\xE2\x82\x86\xE2\x82\x84\x1B[0m \x1B[36m\xE2\x8A\xA5\x1B[0m\x1B[90m)\x1B[0m",
		"rz_core_il_print_rzil text");

	rz_core_free(core);
	rz_pvector_free(vec);
	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_op_val);
	mu_run_test(test_rz_core_analysis_bytes);
	mu_run_test(test_rz_core_analysis_bytes_respect_buffer_len);
	mu_run_test(test_rz_core_analysis_bytes_short_tail);
	mu_run_test(test_rz_core_analysis_bytes_from_io);
	mu_run_test(test_rz_core_print_disasm);
	mu_run_test(test_rz_core_print_disasm_resolve_aav_symbols);
	mu_run_test(test_rz_core_il_print_rzil);
	return tests_passed != tests_run;
}

mu_main(all_tests)
