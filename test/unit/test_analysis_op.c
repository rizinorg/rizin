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
	RzIterator *iter = rz_core_analysis_bytes(core, core->offset, buf, len, 0);
	mu_assert_notnull(iter, "rz_core_analysis_bytes");

	RzCoreDecodedBytes *ab = rz_iterator_next(iter);
	mu_assert_streq(ab->opcode, "push rbp", "rz_core_analysis_bytes opcode");

	ab = rz_iterator_next(iter);
	mu_assert_streq(ab->opcode, "mov rbp, rsp", "rz_core_analysis_bytes opcode");
	mu_assert_streq(ab->pseudo, "rbp = rsp", "rz_core_analysis_bytes pseudo");

	ab = rz_iterator_next(iter);
	mu_assert_streq(ab->opcode, "mov dword [rbp-0x04], edi", "rz_core_analysis_bytes opcode");
	mu_assert_streq(ab->pseudo, "dword [rbp-0x04] = edi", "rz_core_analysis_bytes pseudo");

	rz_iterator_free(iter);
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

bool test_rz_analysis_op_jump_call_helpers(void) {
	typedef struct {
		ut32 type;
		ut64 jump;
		ut64 fail;
		st64 ptr;
		ut64 val;
		bool exp_jump_ok;
		ut64 exp_jump_out;
		bool exp_call_ok;
		ut64 exp_call_out;
		bool exp_ind_ok;
		ut64 exp_ind_out;
		bool exp_ujump;
		bool exp_ucall;
		bool exp_fail_ok;
		ut64 exp_fail_out;
	} OpHelperCase;
	static const OpHelperCase cases[] = {
		{ RZ_ANALYSIS_OP_TYPE_JMP, 0x1000, UT64_MAX, (st64)UT64_MAX, UT64_MAX, true, 0x1000, false, 0, false, 0, false, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_CJMP, 0x2000, 0x2008, (st64)UT64_MAX, UT64_MAX, true, 0x2000, false, 0, false, 0, false, false, true, 0x2008 },
		{ RZ_ANALYSIS_OP_TYPE_CALL, 0x3000, UT64_MAX, (st64)UT64_MAX, UT64_MAX, false, 0, true, 0x3000, false, 0, false, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_CCALL, 0x4000, 0x4008, (st64)UT64_MAX, UT64_MAX, false, 0, true, 0x4000, false, 0, false, false, true, 0x4008 },
		{ RZ_ANALYSIS_OP_TYPE_UJMP, UT64_MAX, UT64_MAX, (st64)0x5000, UT64_MAX, false, 0, false, 0, true, 0x5000, true, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_RJMP, UT64_MAX, UT64_MAX, (st64)UT64_MAX, 0x6000, false, 0, false, 0, true, 0x6000, true, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_IJMP, UT64_MAX, UT64_MAX, (st64)0x7000, 0x7008, false, 0, false, 0, true, 0x7000, true, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_IRJMP, UT64_MAX, UT64_MAX, (st64)UT64_MAX, UT64_MAX, false, 0, false, 0, false, 0, true, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_MJMP, UT64_MAX, UT64_MAX, (st64)0x8000, UT64_MAX, false, 0, false, 0, true, 0x8000, false, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_UCJMP, UT64_MAX, UT64_MAX, (st64)0x9000, UT64_MAX, false, 0, false, 0, true, 0x9000, true, false, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_ICALL, UT64_MAX, UT64_MAX, (st64)0xa000, UT64_MAX, false, 0, false, 0, true, 0xa000, false, true, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_UCCALL, UT64_MAX, UT64_MAX, (st64)UT64_MAX, 0xb000, false, 0, false, 0, true, 0xb000, false, true, false, 0 },
		{ RZ_ANALYSIS_OP_TYPE_RCJMP, 0xc000, 0xc008, (st64)0xc000, 0xc000, false, 0, false, 0, false, 0, false, false, true, 0xc008 },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		const OpHelperCase *c = &cases[i];
		RzAnalysisOp op;
		rz_analysis_op_init(&op);
		op.type = c->type;
		op.jump = c->jump;
		op.fail = c->fail;
		op.ptr = c->ptr;
		op.val = c->val;
		ut64 out = 0xdeadbeef;
		bool ok = rz_analysis_op_get_jump_target(&op, &out);
		mu_assert_eq(ok, c->exp_jump_ok, "get_jump_target ok");
		mu_assert_eq(ok ? out : 0xdeadbeef, c->exp_jump_ok ? c->exp_jump_out : 0xdeadbeef, "get_jump_target out");
		out = 0xdeadbeef;
		ok = rz_analysis_op_get_call_target(&op, &out);
		mu_assert_eq(ok, c->exp_call_ok, "get_call_target ok");
		mu_assert_eq(ok ? out : 0xdeadbeef, c->exp_call_ok ? c->exp_call_out : 0xdeadbeef, "get_call_target out");
		out = 0xdeadbeef;
		ok = rz_analysis_op_get_indirect_ref(&op, &out);
		mu_assert_eq(ok, c->exp_ind_ok, "get_indirect_ref ok");
		mu_assert_eq(ok ? out : 0xdeadbeef, c->exp_ind_ok ? c->exp_ind_out : 0xdeadbeef, "get_indirect_ref out");
		mu_assert_eq(rz_analysis_op_is_unknown_jump(&op), c->exp_ujump, "is_unknown_jump");
		mu_assert_eq(rz_analysis_op_is_unknown_call(&op), c->exp_ucall, "is_unknown_call");
		out = 0xdeadbeef;
		ok = rz_analysis_op_has_fail_target(&op, &out);
		mu_assert_eq(ok, c->exp_fail_ok, "has_fail_target ok");
		mu_assert_eq(ok ? out : 0xdeadbeef, c->exp_fail_ok ? c->exp_fail_out : 0xdeadbeef, "has_fail_target out");
		rz_analysis_op_fini(&op);
	}

	RzAnalysisOp op;
	rz_analysis_op_init(&op);
	ut64 out = 0xdeadbeef;
	mu_assert_false(rz_analysis_op_get_jump_target(NULL, &out), "jump NULL op");
	mu_assert_eq(out, 0xdeadbeef, "jump NULL op leaves out untouched");
	mu_assert_false(rz_analysis_op_get_jump_target(&op, NULL), "jump NULL out");
	mu_assert_false(rz_analysis_op_get_call_target(NULL, &out), "call NULL op");
	mu_assert_false(rz_analysis_op_get_indirect_ref(NULL, &out), "indirect NULL op");
	mu_assert_false(rz_analysis_op_has_fail_target(NULL, &out), "fail NULL op");
	mu_assert_false(rz_analysis_op_is_unknown_jump(NULL), "ujump NULL op");
	mu_assert_false(rz_analysis_op_is_unknown_call(NULL), "ucall NULL op");

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_UCALL;
	op.ptr = (st64)0xd000;
	mu_assert_true(rz_analysis_op_get_indirect_ref(&op, &out), "ucall indirect");
	mu_assert_eq(out, 0xd000, "ucall indirect out");
	mu_assert_true(rz_analysis_op_is_unknown_call(&op), "ucall is unknown call");
	mu_assert_false(rz_analysis_op_is_unknown_jump(&op), "ucall is not unknown jump");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_RCALL;
	op.ptr = (st64)0xd008;
	mu_assert_true(rz_analysis_op_get_indirect_ref(&op, &out), "rcall indirect");
	mu_assert_eq(out, 0xd008, "rcall indirect out");
	mu_assert_true(rz_analysis_op_is_unknown_call(&op), "rcall is unknown call");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_IRCALL;
	op.val = 0xd010;
	mu_assert_true(rz_analysis_op_get_indirect_ref(&op, &out), "ircall indirect val fallback");
	mu_assert_eq(out, 0xd010, "ircall indirect out");
	mu_assert_true(rz_analysis_op_is_unknown_call(&op), "ircall is unknown call");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_MCJMP;
	op.jump = 0xe000;
	op.ptr = (st64)0xe000;
	op.fail = 0xe008;
	out = 0xdeadbeef;
	mu_assert_false(rz_analysis_op_get_jump_target(&op, &out), "mcjmp matches no jump");
	mu_assert_eq(out, 0xdeadbeef, "mcjmp leaves out untouched");
	mu_assert_false(rz_analysis_op_get_indirect_ref(&op, &out), "mcjmp matches no indirect");
	mu_assert_false(rz_analysis_op_is_unknown_jump(&op), "mcjmp is not unknown jump");
	mu_assert_false(rz_analysis_op_is_unknown_call(&op), "mcjmp is not unknown call");
	mu_assert_true(rz_analysis_op_has_fail_target(&op, &out), "mcjmp fail is type-agnostic");
	mu_assert_eq(out, 0xe008, "mcjmp fail out");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_JMP;
	op.jump = UT64_MAX;
	out = 0xdeadbeef;
	mu_assert_false(rz_analysis_op_get_jump_target(&op, &out), "jmp sentinel has no target");
	mu_assert_eq(out, 0xdeadbeef, "jmp sentinel leaves out untouched");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_CALL;
	op.jump = UT64_MAX;
	out = 0xdeadbeef;
	mu_assert_false(rz_analysis_op_get_call_target(&op, &out), "call sentinel has no target");
	mu_assert_eq(out, 0xdeadbeef, "call sentinel leaves out untouched");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_UJMP;
	op.jump = 0xf000;
	op.ptr = (st64)UT64_MAX;
	op.val = UT64_MAX;
	out = 0xdeadbeef;
	mu_assert_false(rz_analysis_op_get_jump_target(&op, &out), "ujmp has no jump target (no jump-to-ptr fallback)");
	mu_assert_eq(out, 0xdeadbeef, "ujmp leaves out untouched");
	mu_assert_false(rz_analysis_op_get_indirect_ref(&op, &out), "ujmp without ptr/val has no indirect ref");
	mu_assert_true(rz_analysis_op_is_unknown_jump(&op), "ujmp is unknown jump without target");
	rz_analysis_op_fini(&op);

	rz_analysis_op_init(&op);
	op.type = RZ_ANALYSIS_OP_TYPE_JMP;
	op.jump = 0xf008;
	op.ptr = (st64)0xf008;
	out = 0xdeadbeef;
	mu_assert_false(rz_analysis_op_get_indirect_ref(&op, &out), "jmp has no indirect ref");
	mu_assert_eq(out, 0xdeadbeef, "jmp indirect leaves out untouched");
	rz_analysis_op_fini(&op);

	mu_end;
}

int all_tests() {
	mu_run_test(test_rz_analysis_op_jump_call_helpers);
	mu_run_test(test_rz_analysis_op_val);
	mu_run_test(test_rz_core_analysis_bytes);
	mu_run_test(test_rz_core_print_disasm);
	mu_run_test(test_rz_core_print_disasm_resolve_aav_symbols);
	mu_run_test(test_rz_core_il_print_rzil);
	return tests_passed != tests_run;
}

mu_main(all_tests)
