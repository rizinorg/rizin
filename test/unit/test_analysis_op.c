// SPDX-FileCopyrightText: 2021 GustavoLCR <gugulcr@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "minunit.h"
#include "test_config.h"

#define SWITCH_TO_ARCH_BITS(arch, bits) \
	do { \
		mu_assert_true(rz_analysis_use(analysis, arch), "select " arch); \
		mu_assert_true(rz_analysis_set_bits(analysis, bits), "set " arch " bits"); \
	} while (0)

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

#if TEST_HAVE_RISCV_CS
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
#endif

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

static int decode_refline_op(void *user, ut64 addr, RzAnalysisOp *op) {
	RzCore *core = user;
	ut8 buf[4];
	if (!rz_io_read_at_mapped(core->io, addr, buf, sizeof(buf))) {
		return 0;
	}
	return rz_analysis_op(core->analysis, op, addr, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_BASIC);
}

static bool test_counted_refline_range(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	ut64 base = 0x100000000ULL;
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://256", RZ_PERM_RWX, 0644, base, NULL), "map");
	mu_assert_true(rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL), "x86");
	const ut8 code[] = { 0xeb, 1, 0x90, 0xeb, 0xfb };
	mu_assert_true(rz_io_write_at(core->io, base + 128, code, sizeof(code)), "two short jumps");
	mu_assert_true(rz_meta_set(core->analysis, RZ_META_TYPE_HIDE, base, 128, NULL), "hidden first row");
	RzPVector *refs = rz_analysis_reflines_get_count(core->analysis, base, 3, false, false, decode_refline_op, core);
	mu_assert_notnull(refs, "three-row listing");
	mu_assert_eq(rz_pvector_len(refs), 0, "the jump destination is the first byte after the listing");
	rz_pvector_free(refs);
	refs = rz_analysis_reflines_get_count(core->analysis, base, 4, false, false, decode_refline_op, core);
	mu_assert_notnull(refs, "four-row listing");
	mu_assert_eq(rz_pvector_len(refs), 2, "both jump destinations are now visible");
	RzAnalysisRefline *jump = rz_pvector_at(refs, 0);
	mu_assert_eq(jump->from, base + 128, "first jump");
	mu_assert_eq(jump->to, base + 131, "forward destination");
	jump = rz_pvector_at(refs, 1);
	mu_assert_eq(jump->to, base + 128, "backward destination");
	rz_pvector_free(refs);

	rz_analysis_set_max_reflines(core->analysis, 1);
	const ut8 capped[] = { 0xeb, 0x7e, 0xeb, 0x7c, 0x90, 0xeb, 0xfb, 0x90 };
	ut64 addr = base + 200;
	mu_assert_true(rz_io_write_at(core->io, addr, capped, sizeof(capped)), "two external jumps before an internal jump");
	refs = rz_analysis_reflines_get_count(core->analysis, addr, 5, false, false, decode_refline_op, core);
	mu_assert_notnull(refs, "counted listing with a one-line budget");
	mu_assert_eq(rz_pvector_len(refs), 1, "only visible targets consume the budget");
	jump = rz_pvector_at(refs, 0);
	mu_assert_eq(jump->from, addr + 5, "source after both external jumps");
	mu_assert_eq(jump->to, addr + 2, "visible backward target");
	rz_pvector_free(refs);
	refs = rz_analysis_reflines_get(core->analysis, addr, capped, sizeof(capped), -1, false, false);
	mu_assert_notnull(refs, "byte-bounded listing");
	mu_assert_eq(rz_pvector_len(refs), 1, "same budget for a byte range");
	jump = rz_pvector_at(refs, 0);
	mu_assert_eq(jump->to, addr + 2, "same backward target");
	rz_pvector_free(refs);
	refs = rz_analysis_reflines_get_count(core->analysis, addr, 5, true, false, decode_refline_op, core);
	mu_assert_notnull(refs, "external lines enabled");
	mu_assert_eq(rz_pvector_len(refs), 1, "strict cap includes external lines");
	jump = rz_pvector_at(refs, 0);
	mu_assert_eq(jump->to, addr + 128, "first external target");
	rz_pvector_free(refs);
	refs = rz_analysis_reflines_get_count(core->analysis, base, 4, false, false, decode_refline_op, core);
	mu_assert_notnull(refs, "forward jump after a metadata row");
	mu_assert_eq(rz_pvector_len(refs), 1, "later visible edges respect the budget");
	jump = rz_pvector_at(refs, 0);
	mu_assert_eq(jump->to, base + 131, "first target lies on the last row");
	rz_pvector_free(refs);
	rz_core_free(core);
	mu_end;
}

static bool test_disasm_borrowed_prefix(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://256", RZ_PERM_RWX, 0644, 0, NULL), "map");
	mu_assert_true(rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL), "x86");
	ut8 prefix[] = { 0x90, 0x48 };
	const ut8 mapped[] = { 0xcc, 0xcc, 0x89, 0xe5, 0xc3 };
	mu_assert_true(rz_io_write_at(core->io, 0, mapped, sizeof(mapped)), "mapped tail");
	RzPVector *rows = rz_pvector_new((RzPVectorFree)rz_analysis_disasm_text_free);
	mu_assert_notnull(rows, "output");
	RzCoreDisasmOptions options = { .vec = rows };
	int consumed = rz_core_print_disasm(core, 0, prefix, sizeof(prefix), 3, NULL, &options);
	mu_assert_eq(consumed, 5, "nop, mov and ret across the supplied prefix");
	mu_assert_eq(rz_pvector_len(rows), 3, "instruction count");
	RzAnalysisDisasmText *row = rz_pvector_at(rows, 2);
	mu_assert_eq(row->offset, 4, "ret address");
	rz_pvector_clear(rows);
	options.cbytes = true;
	consumed = rz_core_print_disasm(core, 0, prefix, 1, 3, NULL, &options);
	mu_assert_eq(consumed, 1, "explicit byte limit");
	mu_assert_eq(rz_pvector_len(rows), 1, "bounded row count");
	rz_pvector_free(rows);
	rz_core_free(core);
	mu_end;
}

static bool test_avr_op_input_size(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_true(rz_core_arch_configure(core, "avr", 8, NULL, NULL, NULL), "avr");
	const ut8 code[] = { 0x00, 0x10, 0x0c, 0x94, 0x05, 0x00 }; // cpse r0, r0; jmp 0xa
	RzAnalysisOp op;
	int size = rz_analysis_op(core->analysis, &op, 0, code, 2, RZ_ANALYSIS_OP_MASK_IL | RZ_ANALYSIS_OP_MASK_ESIL);
	mu_assert_eq(size, 2, "a skip is a complete two-byte instruction");
	mu_assert_eq(op.fail, 2, "fallthrough is known without lookahead");
	mu_assert_eq(op.jump, UT64_MAX, "the skipped instruction is unavailable");
	mu_assert_null(op.il_op, "unknown skip target");
	mu_assert_streq(rz_strbuf_get(&op.esil), "", "no fabricated ESIL jump");
	rz_analysis_op_fini(&op);
	size = rz_analysis_op(core->analysis, &op, 0, code, 3, RZ_ANALYSIS_OP_MASK_INPUT_SIZE);
	mu_assert_eq(size, -4, "the following opcode word is incomplete");
	rz_analysis_op_fini(&op);
	size = rz_analysis_op(core->analysis, &op, 0, code, 4, RZ_ANALYSIS_OP_MASK_INPUT_SIZE);
	mu_assert_eq(size, 2, "the skipped operand is unnecessary");
	mu_assert_eq(op.jump, 6, "skip a four-byte jump");
	rz_analysis_op_fini(&op);
	size = rz_analysis_op(core->analysis, &op, 2, code + 2, 2, RZ_ANALYSIS_OP_MASK_INPUT_SIZE);
	mu_assert_eq(size, -4, "decoding the jump itself needs its operand");
	rz_analysis_op_fini(&op);
	rz_core_free(core);
	mu_end;
}

static bool test_wasm_op_input_size(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_true(rz_core_arch_configure(core, "wasm", 32, NULL, NULL, NULL), "wasm");
	const ut8 table[] = { 0x0e, 2, 0, 0x80, 1, 0 };
	RzAnalysisOp op;
	int size = rz_analysis_op(core->analysis, &op, 0, table, 2, RZ_ANALYSIS_OP_MASK_BASIC);
	rz_analysis_op_fini(&op);
	mu_assert_eq(size, -1, "legacy result for incomplete input");
	size = rz_analysis_op(core->analysis, &op, 0, table, 2, RZ_ANALYSIS_OP_MASK_INPUT_SIZE);
	rz_analysis_op_fini(&op);
	mu_assert_eq(size, -5, "two labels and a default require at least three more bytes");
	size = rz_analysis_op(core->analysis, &op, 0, table, sizeof(table), RZ_ANALYSIS_OP_MASK_INPUT_SIZE);
	rz_analysis_op_fini(&op);
	mu_assert_eq(size, sizeof(table), "complete table ends at the last input byte");
	rz_core_free(core);
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

static bool test_analysis_read_cache() {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://2", RZ_PERM_RWX,
				  0644, 0x1000, NULL),
		"first mapping");
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://2", RZ_PERM_RWX,
				  0644, 0x1004, NULL),
		"second mapping");
	const ut8 bytes[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	mu_assert_true(rz_io_write_at(core->io, 0x1000, bytes, 2), "write first map");
	mu_assert_true(rz_io_write_at(core->io, 0x1004, bytes + 4, 2), "write second map");
	rz_config_set_b(core->config, "io.cache", true);
	mu_assert_true(rz_io_write_at(core->io, 0x1002, bytes + 2, 2), "cache in map gap");
	mu_assert_true(rz_io_write_at(core->io, 0x1006, bytes + 6, 2), "cache after map");

	// RzIL instruction fetches must see cached patches, including unmapped bytes.
	RzAnalysisCallbacks *cb = rz_analysis_get_callbacks(core->analysis);
	ut8 actual[sizeof(bytes)] = { 0 };
	mu_assert_true(cb->read_at(core->analysis, 0x1000, actual, sizeof(actual)),
		"analysis read spanning maps and cache");
	mu_assert_memeq(actual, bytes, sizeof(bytes), "cached bytes across map boundaries");
	mu_assert_true(cb->read_at(core->analysis, 0x1006, actual, 2),
		"analysis read entirely in cache");
	mu_assert_memeq(actual, bytes + 6, 2, "unmapped cached bytes");
	rz_core_free(core);
	mu_end;
}

static bool test_dalvik_switch_offsets() {
	static const struct {
		ut8 opcode;
		ut64 addr;
		ut32 payload_offset;
		const char *payload;
		ut64 first_target;
		ut64 last_target;
		st64 first_key;
		st64 last_key;
	} cases[] = {
		{ 0x2b, 0x100000020, 0xfffffff0, "00010200ffffffffffffffff05000000",
			0x10000001e, 0x10000002a, -1, 0 },
		{ 0x2c, 0x100000020, 0xfffffff0, "00020200f6ffffffffffff7fffffffff05000000",
			0x10000001e, 0x10000002a, -10, ST32_MAX },
		{ 0x2b, 0x200000000, 0x80000000, "000102000000008000000080ffffff7f",
			0x100000000, 0x2fffffffe, ST32_MIN, ST32_MIN + 1 },
		{ 0x2c, 2, 0x7fffffff, "0002020000000080ffffff7f00000000ffffff7f",
			2, 0x100000000, ST32_MIN, ST32_MAX },
	};
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	rz_core_arch_configure(core, "dalvik", 32, NULL, NULL, NULL);
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://32", RZ_PERM_RWX, 0644,
				  0x100000000, NULL),
		"payload mapping");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		ut8 payload[32];
		int size = rz_hex_str2bin(cases[i].payload, payload);
		mu_assert_true(rz_io_write_at(core->io, 0x100000000, payload, size), "write payload");
		ut8 bytes[6] = { cases[i].opcode, 0 };
		rz_write_le32(bytes + 2, cases[i].payload_offset);
		RzAnalysisOp op;
		mu_assert_eq(rz_analysis_op(core->analysis, &op, cases[i].addr, bytes,
				     sizeof(bytes), RZ_ANALYSIS_OP_MASK_BASIC),
			6, "switch size");
		mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_SWITCH, "switch type");
		mu_assert_eq(op.fail, cases[i].addr + 6, "default fall-through");
		mu_assert_true(op.eob, "switch terminates its block");
		mu_assert_notnull(op.switch_op, "signed payload offset");
		mu_assert_eq(op.switch_op->min_val, (ut64)cases[i].first_key, "first key");
		mu_assert_eq(op.switch_op->max_val, (ut64)cases[i].last_key, "last key");
		mu_assert_eq(op.switch_op->def_val, op.fail, "default address");
		mu_assert_eq(rz_list_length(op.switch_op->cases), 2, "case count");
		RzAnalysisCaseOp *first = rz_list_get_n(op.switch_op->cases, 0);
		RzAnalysisCaseOp *last = rz_list_get_n(op.switch_op->cases, 1);
		mu_assert_eq(first->value, (ut64)cases[i].first_key, "first case value");
		mu_assert_eq(last->value, (ut64)cases[i].last_key, "last case value");
		mu_assert_eq(first->jump, cases[i].first_target, "first signed target");
		mu_assert_eq(last->jump, cases[i].last_target, "last signed target");
		rz_analysis_op_fini(&op);
	}
	rz_core_free(core);
	mu_end;
}

static bool test_dalvik_switch_payload_bounds() {
	static const struct {
		ut8 opcode;
		const char *payload;
	} cases[] = {
		{ 0x2b, "000102" },
		{ 0x2b, "0001010000000000" },
		{ 0x2b, "00010200ffffff7f0400000005000000" },
		{ 0x2b, "0001000000000000" },
		{ 0x2b, "000201000000000004000000" },
		{ 0x2c, "000201" },
		{ 0x2c, "00020200000000000100000004000000" },
		{ 0x2c, "00020000" },
		{ 0x2c, "000101000000000004000000" },
	};
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	rz_core_arch_configure(core, "dalvik", 32, NULL, NULL, NULL);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		ut8 payload[32];
		int size = rz_hex_str2bin(cases[i].payload, payload);
		ut64 addr = 0x100 + i * 0x40;
		char uri[32];
		rz_strf(uri, "malloc://%d", size);
		mu_assert_notnull(rz_io_open_at(core->io, uri, RZ_PERM_RWX, 0644,
					  addr + 0x10, NULL),
			"short payload mapping");
		mu_assert_true(rz_io_write_at(core->io, addr + 0x10, payload, size), "write payload");
		ut8 bytes[] = { cases[i].opcode, 0, 8, 0, 0, 0 };
		RzAnalysisOp op;
		mu_assert_eq(rz_analysis_op(core->analysis, &op, addr, bytes, sizeof(bytes),
				     RZ_ANALYSIS_OP_MASK_BASIC),
			6, "switch size");
		mu_assert_null(op.switch_op, "no cases from invalid or empty payload");
		mu_assert_eq(op.fail, addr + 6, "default survives missing cases");
		rz_analysis_op_fini(&op);
	}
	// A payload may cross adjacent maps; only actual gaps should reject it.
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://2", RZ_PERM_RWX,
				  0644, 0x1000, NULL),
		"payload first map");
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://10", RZ_PERM_RWX,
				  0644, 0x1002, NULL),
		"payload second map");
	const ut8 payload[] = { 0, 1, 1, 0, 0, 0, 0, 0, 4, 0, 0, 0 };
	mu_assert_true(rz_io_write_at(core->io, 0x1000, payload, sizeof(payload)), "write split payload");
	const ut8 bytes[] = { 0x2b, 0, 8, 0, 0, 0 };
	RzAnalysisOp op;
	mu_assert_eq(rz_analysis_op(core->analysis, &op, 0xff0, bytes, sizeof(bytes),
			     RZ_ANALYSIS_OP_MASK_BASIC),
		6, "switch size");
	mu_assert_notnull(op.switch_op, "payload spanning adjacent maps");
	mu_assert_eq(rz_list_length(op.switch_op->cases), 1, "split payload case count");
	rz_analysis_op_fini(&op);
	// The same payload with its size in a gap: padding must not become a size.
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://2", RZ_PERM_RWX,
				  0644, 0x2000, NULL),
		"payload before gap");
	mu_assert_notnull(rz_io_open_at(core->io, "malloc://8", RZ_PERM_RWX,
				  0644, 0x2004, NULL),
		"payload after gap");
	mu_assert_true(rz_io_write_at(core->io, 0x2000, payload, 2), "write ident");
	mu_assert_true(rz_io_write_at(core->io, 0x2004, payload + 4, 8), "write key and target");
	mu_assert_eq(rz_analysis_op(core->analysis, &op, 0x1ff0, bytes, sizeof(bytes),
			     RZ_ANALYSIS_OP_MASK_BASIC),
		6, "gapped switch size");
	mu_assert_null(op.switch_op, "payload with a gap");
	rz_analysis_op_fini(&op);
	// Cached edits inside mapped payloads remain visible to the counted read.
	rz_config_set_b(core->config, "io.cache", true);
	const ut8 target[] = { 5, 0, 0, 0 };
	mu_assert_true(rz_io_write_at(core->io, 0x1008, target, sizeof(target)), "cache target");
	mu_assert_eq(rz_analysis_op(core->analysis, &op, 0xff0, bytes, sizeof(bytes),
			     RZ_ANALYSIS_OP_MASK_BASIC),
		6, "cached switch size");
	mu_assert_notnull(op.switch_op, "cached payload");
	RzAnalysisCaseOp *caseop = rz_list_get_n(op.switch_op->cases, 0);
	mu_assert_eq(caseop->jump, 0xffa, "cached case target");
	rz_analysis_op_fini(&op);
	// Keep supporting clients that only supply an analysis read callback.
	rz_analysis_get_io_bind(core->analysis)->nread_at = NULL;
	mu_assert_eq(rz_analysis_op(core->analysis, &op, 0xff0, bytes, sizeof(bytes),
			     RZ_ANALYSIS_OP_MASK_BASIC),
		6, "callback switch size");
	mu_assert_notnull(op.switch_op, "callback payload");
	caseop = rz_list_get_n(op.switch_op->cases, 0);
	mu_assert_eq(caseop->jump, 0xffa, "callback case target");
	rz_analysis_op_fini(&op);
	rz_core_free(core);
	mu_end;
}

static bool test_dalvik_switch_blocks() {
	const ut64 base = 0x100000000;
	for (ut8 opcode = 0x2b; opcode <= 0x2c; opcode++) {
		RzCore *core = rz_core_new();
		mu_assert_notnull(core, "core");
		rz_core_arch_configure(core, "dalvik", 32, NULL, NULL, NULL);
		mu_assert_notnull(rz_io_open_at(core->io, "malloc://128", RZ_PERM_RWX,
					  0644, base, NULL),
			"method mapping");
		ut8 bytes[128] = { 0 };
		// Enter the switch after two case blocks, which share one of their targets.
		rz_hex_str2bin("280812100f0012200f00", bytes);
		rz_hex_str2bin("2b001000000012300f00", bytes + 0x10);
		bytes[0x10] = opcode;
		const char *payload = opcode == 0x2b
			? "00010300fffffffff9fffffffbfffffffbffffff"
			: "00020300ffffffff0000000001000000f9fffffffbfffffffbffffff";
		rz_hex_str2bin(payload, bytes + 0x30);
		mu_assert_true(rz_io_write_at(core->io, base, bytes, sizeof(bytes)), "write method");
		mu_assert_true(rz_core_analysis_fcn(core, base, UT64_MAX,
				       RZ_ANALYSIS_XREF_TYPE_NULL, 5),
			"analyze method");
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, base);
		mu_assert_notnull(fcn, "function");
		mu_assert_eq(rz_pvector_len(fcn->bbs), 5, "entry, switch, two cases and default");
		RzAnalysisBlock *block = rz_analysis_get_block_at(core->analysis, base + 0x10);
		mu_assert_notnull(block, "switch block");
		mu_assert_eq(block->size, 6, "switch ends the block");
		mu_assert_eq(block->fail, base + 0x16, "default successor");
		mu_assert_notnull(block->switch_op, "retained switch metadata");
		mu_assert_eq(rz_list_length(block->switch_op->cases), 3, "shared cases retained");
		const ut64 targets[] = { base + 2, base + 6, base + 0x16 };
		for (size_t i = 0; i < RZ_ARRAY_SIZE(targets); i++) {
			block = rz_analysis_get_block_at(core->analysis, targets[i]);
			mu_assert_notnull(block, "case/default block");
			mu_assert_true(rz_list_contains(block->fcns, fcn), "case belongs to function");
			mu_assert_eq(block->size, 4, "case includes its return");
			RzList *xrefs = rz_analysis_xrefs_get_to(core->analysis, targets[i]);
			mu_assert_notnull(xrefs, "case/default xrefs");
			mu_assert_eq(rz_list_length(xrefs), 1, "shared target has one xref");
			RzAnalysisXRef *xref = rz_list_get_n(xrefs, 0);
			mu_assert_eq(xref->from, base + 0x10, "xref originates at switch");
			mu_assert_eq(xref->type, RZ_ANALYSIS_XREF_TYPE_CODE, "code xref");
			rz_list_free(xrefs);
		}
		rz_core_free(core);
	}
	mu_end;
}

static bool test_alpha_branch_values(void) {
	RzAnalysis *analysis = rz_analysis_new(NULL);
	mu_assert_notnull(analysis, "analysis");
	if (!rz_analysis_use(analysis, "alpha")) {
		rz_analysis_free(analysis);
		mu_ignore;
	}
	rz_analysis_set_bits(analysis, 64);

	const struct {
		ut8 bytes[4];
		const char *link;
	} cases[] = {
		{ { 0xfe, 0xff, 0x5f, 0xd3 }, "r26" }, // bsr $26
		{ { 0xfe, 0xff, 0x3f, 0xc0 }, "r1" }, // br $1
		{ { 0xfe, 0xff, 0xff, 0xc3 }, NULL }, // br $31
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		RzAnalysisOp op;
		mu_assert_eq(rz_analysis_op(analysis, &op, 0x100000000, cases[i].bytes, sizeof(cases[i].bytes), RZ_ANALYSIS_OP_MASK_VAL), sizeof(cases[i].bytes), "branch size");
		mu_assert_notnull(op.src[0], "branch target");
		mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_IMM, "immediate target");
		mu_assert_eq(op.src[0]->imm, 0xfffffffc, "branch target address");
		if (cases[i].link) {
			mu_assert_notnull(op.dst, "link destination");
			mu_assert_notnull(op.dst->reg, "link register");
			mu_assert_streq(op.dst->reg->name, cases[i].link, "encoded link register");
			mu_assert_eq(op.dst->access, RZ_ANALYSIS_ACC_W, "link register access");
		} else {
			mu_assert_null(op.dst, "r31 discards the link");
		}
		rz_analysis_op_fini(&op);
	}
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_rz_analysis_esil_trace_no_snapshot(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);
	mu_assert_false(rz_core_esil_continue_back(core), "continue_back returns false before aei");
	rz_core_cmd0(core, "aei");
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	mu_assert_notnull(esil, "esil initialized");
	RzAnalysisEsilTrace *no_stack_trace = rz_analysis_esil_trace_new_no_snapshot(esil);
	mu_assert_notnull(no_stack_trace, "no-snapshot trace works before aeim stack init");
	rz_analysis_esil_trace_free(no_stack_trace);
	rz_core_cmd0(core, "aeim");
	mu_assert_false(rz_core_esil_continue_back(core), "continue_back false without trace");
	rz_analysis_esil_trace_restore(esil, 0);

	RzAnalysisEsilTrace *trace = rz_analysis_esil_trace_new_no_snapshot(esil);
	mu_assert_notnull(trace, "no-snapshot trace created");
	mu_assert_notnull(trace->instructions, "instructions vector present");
	mu_assert_null(trace->registers, "registers map skipped");
	mu_assert_null(trace->memory, "memory map skipped");
	mu_assert_null(trace->stack_data, "stack snapshot skipped");

	esil->trace = trace;
	rz_analysis_esil_trace_op(esil, 0x1000, "0x42,rax,=");
	mu_assert_eq(rz_pvector_len(trace->instructions), 1, "instruction traced");
	mu_assert_eq(trace->idx, 1, "idx advanced after first op");
	mu_assert_eq(trace->end_idx, 1, "end_idx advanced after first op");
	RzILTraceInstruction *ins = rz_analysis_esil_get_instruction_trace(trace, 0);
	mu_assert_notnull(ins, "instruction trace entry");
	mu_assert_true(rz_analysis_il_reg_trace_contains(ins, "rax", true), "rax write recorded");

	// Memory writes and reads are still recorded in IL trace entries without a snapshot map.
	rz_analysis_esil_trace_op(esil, 0x1004, "0x11223344,rsp,=[4]");
	mu_assert_eq(rz_pvector_len(trace->instructions), 2, "memory write traced");
	ins = rz_analysis_esil_get_instruction_trace(trace, 1);
	mu_assert_notnull(ins, "memory write instruction trace entry");
	mu_assert_true(ins->stats & RZ_IL_TRACE_INS_HAS_MEM_W, "memory write flag recorded");

	// Restoring, stepping back, or continuing back on a no-snapshot trace must be a safe no-op
	// without modifying trace->idx so subsequent trace_op() calls still execute.
	rz_analysis_esil_trace_restore(esil, 0);
	mu_assert_eq(trace->idx, 2, "restore leaves idx unchanged on no-snapshot trace");
	mu_assert_eq(trace->end_idx, 2, "restore leaves end_idx unchanged on no-snapshot trace");
	mu_assert_eq(rz_core_esil_step_back(core), 0, "step_back returns 0 on no-snapshot trace");
	mu_assert_eq(trace->idx, 2, "step_back leaves idx unchanged on no-snapshot trace");
	mu_assert_false(rz_core_esil_continue_back(core), "continue_back returns false on no-snapshot trace");
	mu_assert_eq(trace->idx, 2, "continue_back leaves idx unchanged on no-snapshot trace");

	rz_analysis_esil_trace_op(esil, 0x1008, "0x99,rbx,=");
	mu_assert_eq(rz_pvector_len(trace->instructions), 3, "third op traced after restore no-op");
	mu_assert_eq(trace->idx, 3, "idx advanced after third op");
	mu_assert_eq(trace->end_idx, 3, "end_idx advanced after third op");
	ins = rz_analysis_esil_get_instruction_trace(trace, 2);
	mu_assert_notnull(ins, "third instruction trace entry");
	mu_assert_true(rz_analysis_il_reg_trace_contains(ins, "rbx", true), "rbx write recorded");

	rz_analysis_esil_trace_free(trace);
	esil->trace = NULL;

	rz_core_free(core);
	mu_end;
}

static bool test_rz_analysis_esil_trace_snapshot_and_continue_back(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);
	rz_core_cmd0(core, "aei; aeim");
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	mu_assert_notnull(esil, "esil initialized");
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	ut64 sp = rz_reg_getv(reg, "rsp");

	RzAnalysisEsilTrace *trace = rz_analysis_esil_trace_new(esil);
	mu_assert_notnull(trace, "snapshot trace created");
	mu_assert_notnull(trace->registers, "registers map present");
	mu_assert_notnull(trace->memory, "memory map present");
	mu_assert_notnull(trace->stack_data, "stack snapshot present");

	esil->trace = trace;
	rz_analysis_esil_trace_op(esil, 0x1000, "0x42,rax,=");
	rz_analysis_esil_trace_op(esil, 0x1004, "0x11223344,rsp,=[4]");
	mu_assert_eq(rz_reg_getv(reg, "rax"), 0x42, "rax updated by trace op");
	ut32 mem_val = 0;
	rz_io_nread_at(core->io, sp, (ut8 *)&mem_val, sizeof(mem_val));
	mu_assert_eq(mem_val, 0x11223344, "stack memory updated by trace op");

	mu_assert_true(rz_core_esil_continue_back(core), "continue_back succeeds on snapshot");
	mu_assert_eq(trace->idx, 0, "continue_back restores idx to 0");
	mu_assert_eq(rz_reg_getv(reg, "rax"), 0, "rax restored to initial value");
	rz_io_nread_at(core->io, sp, (ut8 *)&mem_val, sizeof(mem_val));
	mu_assert_eq(mem_val, 0, "stack memory restored to initial value");

	// Forward restore replays recorded register and memory changes.
	rz_analysis_esil_trace_restore(esil, 2);
	mu_assert_eq(trace->idx, 2, "forward restore sets idx to 2");
	mu_assert_eq(rz_reg_getv(reg, "rax"), 0x42, "rax restored to step 2");
	rz_io_nread_at(core->io, sp, (ut8 *)&mem_val, sizeof(mem_val));
	mu_assert_eq(mem_val, 0x11223344, "stack memory restored to step 2");

	rz_analysis_esil_trace_free(trace);
	esil->trace = NULL;

	// Verify add_reg_change handles NULL RzRegItem when PC alias is absent.
	const char *no_pc_profile = "=SP rsp\ngpr rax .64 0 0\ngpr rsp .64 8 0\n";
	mu_assert_true(rz_reg_set_profile_string(reg, no_pc_profile), "set profile without PC");
	trace = rz_analysis_esil_trace_new(esil);
	mu_assert_notnull(trace, "snapshot trace without PC alias");
	esil->trace = trace;
	rz_analysis_esil_trace_op(esil, 0x1000, "0x7,rax,=");
	mu_assert_eq(rz_reg_getv(reg, "rax"), 0x7, "rax written without PC alias");
	rz_analysis_esil_trace_free(trace);
	esil->trace = NULL;

	rz_core_free(core);
	mu_end;
}

static bool test_rz_core_analysis_type_match_stepping(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);
	RzTypeDB *typedb = rz_analysis_get_type_db(core->analysis);
	rz_type_db_init(typedb, TEST_BUILD_TYPES_DIR, "x86", 64, "linux");
	rz_core_analysis_cc_init_by_path(core, TEST_BUILD_TYPES_DIR, NULL);

	RzIOMap *map = NULL;
	RzIODesc *desc = rz_io_open_at(core->io, "malloc://0x300", RZ_PERM_RWX, 0, 0x1000, &map);
	mu_assert_notnull(desc, "open rwx malloc buffer");
	mu_assert_notnull(map, "io map created");

	// Caller at 0x1000..0x104b calling strncmp at 0x1100; string "hello" at 0x1200.
	static const char *caller_hex =
		"554889e54883ec30488d05f1010000488985f8ffffffb934120000"
		"48898df0ffffff48898de0ffffff488b4df04889ca4889d74089ce"
		"4089cae8c200000090909090488b55d8488902c9c3";
	ut8 code[128];
	int code_len = rz_hex_str2bin(caller_hex, code);
	mu_assert_eq(code_len, 0x4b, "caller code length");
	rz_io_write_at(core->io, 0x1000, code, code_len);
	const ut8 ret_op = 0xc3;
	rz_io_write_at(core->io, 0x1100, &ret_op, 1);
	rz_io_write_at(core->io, 0x1200, (const ut8 *)"hello", 6);
	rz_flag_set(core->flags, "str.hello", 0x1200, 6);

	rz_core_cmd0(core, "af @ 0x1100; afn strncmp @ 0x1100; af @ 0x1000");
	RzAnalysisFunction *callee = rz_analysis_get_function_byname(core->analysis, "strncmp");
	mu_assert_notnull(callee, "callee renamed to strncmp");
	mu_assert_true(rz_type_func_exist(typedb, "strncmp"), "strncmp type loaded");
	mu_assert_notnull(rz_analysis_cc_func(core->analysis, "strncmp"), "strncmp cc loaded");
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, 0x1000, 0);
	mu_assert_notnull(fcn, "caller function analyzed");
	RzAnalysisBlock *bb = rz_analysis_get_block_at(core->analysis, 0x1000);
	mu_assert_notnull(bb, "caller basic block");

	rz_core_cmd0(core, "aei; aeim");
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	ut64 saved_rbp = rz_reg_getv(reg, "rbp");
	ut64 saved_rsp = rz_reg_getv(reg, "rsp");

	// Uninitialized stack registers trigger analysis_emul_init() early exit.
	rz_reg_setv(reg, "rbp", 0);
	rz_reg_setv(reg, "rsp", 0);
	rz_core_analysis_type_match(core, fcn, NULL);
	mu_assert_false(bb->traced, "block not traced when stack regs are zero");
	rz_reg_setv(reg, "rbp", saved_rbp);
	rz_reg_setv(reg, "rsp", saved_rsp);

	// exectrap on non-executable map returns false from type_match_esil_step().
	map->perm = RZ_PERM_R;
	rz_config_set_b(core->config, "esil.exectrap", true);
	rz_core_analysis_type_match(core, fcn, NULL);
	mu_assert_false(bb->traced, "block not traced when exectrap rejects non-exec map");
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	mu_assert_eq(esil->trap, RZ_ANALYSIS_TRAP_EXEC_ERR, "exectrap sets TRAP_EXEC_ERR");

	// Mark executable and test step_size < 1 with breakoninvalid=true and false.
	map->perm = RZ_PERM_RWX;
	rz_analysis_hint_set_size(core->analysis, 0x1000, (ut64)-1);
	rz_config_set_b(core->config, "esil.breakoninvalid", true);
	rz_core_analysis_type_match(core, fcn, NULL);
	mu_assert_false(bb->traced, "block not traced when breakoninvalid aborts step_size < 1");

	rz_config_set_b(core->config, "esil.breakoninvalid", false);
	rz_core_analysis_type_match(core, fcn, NULL);
	mu_assert_true(bb->traced, "block traced when breakoninvalid=false clamps step_size");
	rz_analysis_hint_unset_size(core->analysis, 0x1000);
	bb->traced = false;

	// Exercise get_src_regname_op edge cases on the post-call nop sled:
	// 32-bit reg without 64-bit alias, no-comma token, overlong (>=64) token, and empty ESIL.
	rz_analysis_hint_set_esil(core->analysis, 0x103e, "mxcr_mask,r10,=");
	rz_analysis_hint_set_esil(core->analysis, 0x103f, "r10");
	rz_analysis_hint_set_esil(core->analysis, 0x1040,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,r10,=");

	// Run full type_match with exectrap=true on executable map.
	rz_core_analysis_type_match(core, fcn, NULL);
	mu_assert_true(bb->traced, "block traced on valid executable map");

	RzAnalysisVar *val_var = rz_analysis_function_get_stack_var_at(fcn, -0x28);
	mu_assert_notnull(val_var, "value-propagated stack variable exists");
	char *val_type = rz_type_as_string(typedb, val_var->type);
	mu_assert_streq(val_type, "const char *", "value propagation sets var_20h type");
	free(val_type);

	RzAnalysisVar *ptr_var = rz_analysis_function_get_stack_var_at(fcn, -0x30);
	mu_assert_notnull(ptr_var, "return-pointer stack variable exists");
	char *ptr_type = rz_type_as_string(typedb, ptr_var->type);
	mu_assert_streq(ptr_type, "int *", "return type pointer propagated to var_28h");
	free(ptr_type);

	rz_core_free(core);
	mu_end;
}

static bool test_rz_core_analysis_type_match_block_fcns_and_cache_eviction(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	rz_core_arch_configure(core, "x86", 64, NULL, NULL, NULL);

	RzIODesc *desc = rz_io_open_at(core->io, "malloc://0x2200", RZ_PERM_RWX, 0, 0x10000, NULL);
	mu_assert_notnull(desc, "open malloc buffer");
	ut8 nops[0x2100];
	memset(nops, 0x90, sizeof(nops));
	// Put a short sequence at 0x10000 for multi-function overlap testing.
	static const ut8 seq[] = { 0xb8, 0x01, 0x00, 0x00, 0x00, 0x90, 0x90, 0xc3 };
	memcpy(nops, seq, sizeof(seq));
	rz_io_write_at(core->io, 0x10000, nops, sizeof(nops));
	rz_core_cmd0(core, "aei; aeim");

	// Overlapping blocks owned by fcn_0 hit dedup in type_match_block_fcns_cb().
	RzAnalysisBlock *bb1 = rz_analysis_create_block(core->analysis, 0x10000, sizeof(seq));
	RzAnalysisBlock *bb2 = rz_analysis_create_block(core->analysis, 0x10005, 3);
	mu_assert_notnull(bb1, "bb1 created");
	mu_assert_notnull(bb2, "bb2 created");
	RzAnalysisFunction *fcns[9];
	fcns[0] = rz_analysis_create_function(core->analysis, "fcn_shared_0", 0x10000,
		RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcns[0], "primary shared function created");
	rz_analysis_function_add_block(fcns[0], bb1);
	rz_analysis_function_add_block(fcns[0], bb2);

	// Step once before overflow so overlapping blocks bb1 and bb2 deduplicate fcn_shared_0.
	rz_core_analysis_type_match(core, fcns[0], NULL);
	mu_assert_true(bb1->traced, "overlapping blocks traced for single function");

	for (size_t i = 1; i < RZ_ARRAY_SIZE(fcns); i++) {
		char name[32];
		snprintf(name, sizeof(name), "fcn_shared_%zu", i);
		fcns[i] = rz_analysis_create_function(core->analysis, name, 0x10000 + i,
			RZ_ANALYSIS_FCN_TYPE_FCN);
		mu_assert_notnull(fcns[i], "shared function created");
		rz_analysis_function_add_block(fcns[i], bb1);
	}
	rz_analysis_block_unref(bb1);
	rz_analysis_block_unref(bb2);

	// 9 functions sharing bb1 trigger fctx.overflow fallback to rz_analysis_get_functions_in().
	bb1->traced = false;
	rz_core_analysis_type_match(core, fcns[0], NULL);
	mu_assert_true(bb1->traced, "shared block traced across >8 functions");

	// Single block with > OP_CACHE_LIMIT (8192) instructions exercises op_cache reset.
	RzAnalysisFunction *big_fcn = rz_analysis_create_function(core->analysis, "fcn_big",
		0x10020, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(big_fcn, "big function created");
	RzAnalysisBlock *big_bb = rz_analysis_create_block(core->analysis, 0x10020, 8208);
	mu_assert_notnull(big_bb, "big block created");
	rz_analysis_function_add_block(big_fcn, big_bb);
	rz_analysis_block_unref(big_bb);

	rz_core_analysis_type_match(core, big_fcn, NULL);
	mu_assert_true(big_bb->traced, "big block traced past OP_CACHE_LIMIT");

	rz_core_free(core);
	mu_end;
}

static bool test_rz_core_analysis_type_match_mips_delay_and_pcalign(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new");
	rz_core_arch_configure(core, "mips", 32, NULL, NULL, NULL);
	rz_config_set_b(core->config, "cfg.bigendian", false);
	mu_assert_eq(rz_analysis_get_pc_align(core->analysis), 4, "mips32 pc align is 4");

	RzIODesc *desc = rz_io_open_at(core->io, "malloc://0x100", RZ_PERM_RWX, 0, 0x1000, NULL);
	mu_assert_notnull(desc, "open mips malloc buffer");
	rz_core_cmd0(core, "aei; aeim");

	// 0x1000: lw v0, 0(sp) (linear, delay=1); 0x1004: addiu v1, zero, 7 (non-empty delay slot)
	// 0x1008: lw v0, 0(sp) (linear, delay=1); 0x100c: nop (hinted empty delay slot)
	// 0x1010: lw v0, 0(sp) (linear, delay=1); 0x1014: jr ra (RET in delay slot -> trap)
	// 0x1020: lw v0, 0(sp) (linear, delay=1); 0x1024: nop (hinted size < 1 -> op2->size <= 0)
	// 0x10fc: lw v0, 0(sp) (delay slot at 0x1100 is unmapped -> op2 == NULL)
	ut8 buf[24];
	int len = rz_hex_str2bin("0000a28f070003240000a28f000000000000a28f0800e003", buf);
	mu_assert_eq(len, 24, "mips test bytes length");
	rz_io_write_at(core->io, 0x1000, buf, len);
	rz_io_write_at(core->io, 0x1020, buf + 8, 8);
	rz_io_write_at(core->io, 0x10fc, buf, 4);
	rz_analysis_hint_set_esil(core->analysis, 0x100c, "");
	rz_analysis_hint_set_size(core->analysis, 0x1024, (ut64)-1);

	RzAnalysisFunction *fcn = rz_analysis_create_function(core->analysis, "mips_delay",
		0x1000, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(fcn, "mips function created");
	RzAnalysisBlock *bb_exec = rz_analysis_create_block(core->analysis, 0x1000, 16);
	RzAnalysisBlock *bb_trap = rz_analysis_create_block(core->analysis, 0x1010, 4);
	RzAnalysisBlock *bb_bad = rz_analysis_create_block(core->analysis, 0x1020, 4);
	RzAnalysisBlock *bb_edge = rz_analysis_create_block(core->analysis, 0x10fc, 4);
	mu_assert_notnull(bb_exec, "bb_exec created");
	mu_assert_notnull(bb_trap, "bb_trap created");
	mu_assert_notnull(bb_bad, "bb_bad created");
	mu_assert_notnull(bb_edge, "bb_edge created");
	rz_analysis_function_add_block(fcn, bb_exec);
	rz_analysis_function_add_block(fcn, bb_trap);
	rz_analysis_function_add_block(fcn, bb_bad);
	rz_analysis_function_add_block(fcn, bb_edge);
	rz_analysis_block_unref(bb_exec);
	rz_analysis_block_unref(bb_trap);
	rz_analysis_block_unref(bb_bad);
	rz_analysis_block_unref(bb_edge);

	rz_core_analysis_type_match(core, fcn, NULL);
	mu_assert_true(bb_exec->traced, "mips delay-slot block traced");
	mu_assert_true(bb_trap->traced, "mips branch-in-delay-slot block traced");
	mu_assert_true(bb_bad->traced, "mips invalid-size-delay-slot block traced");
	mu_assert_true(bb_edge->traced, "mips unmapped-delay-slot block traced");
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	mu_assert_eq(rz_reg_getv(reg, "v1"), 7, "delay slot addiu executed");

	// Verify trap flag directly on the single-block branch-in-delay-slot case.
	RzAnalysisFunction *trap_fcn = rz_analysis_create_function(core->analysis, "mips_trap",
		0x1010, RZ_ANALYSIS_FCN_TYPE_FCN);
	mu_assert_notnull(trap_fcn, "mips_trap function created");
	rz_analysis_function_add_block(trap_fcn, bb_trap);
	rz_core_analysis_type_match(core, trap_fcn, NULL);
	RzAnalysisEsil *esil = rz_analysis_get_esil(core->analysis);
	mu_assert_eq(esil->trap, RZ_ANALYSIS_TRAP_EXEC_ERR, "branch in delay slot traps");
	mu_assert_eq(esil->trap_code, 0x1010, "trap_code records delayed instruction address");

	rz_core_free(core);
	mu_end;
}

int all_tests() {
	mu_run_test(test_analysis_read_cache);
	mu_run_test(test_dalvik_switch_offsets);
	mu_run_test(test_dalvik_switch_payload_bounds);
	mu_run_test(test_dalvik_switch_blocks);
	mu_run_test(test_rz_analysis_op_val);
	mu_run_test(test_alpha_branch_values);
	mu_run_test(test_rz_core_analysis_bytes);
	mu_run_test(test_rz_core_analysis_bytes_respect_buffer_len);
	mu_run_test(test_rz_core_analysis_bytes_short_tail);
	mu_run_test(test_rz_core_analysis_bytes_from_io);
	mu_run_test(test_rz_core_print_disasm);
	mu_run_test(test_disasm_borrowed_prefix);
	mu_run_test(test_counted_refline_range);
	mu_run_test(test_wasm_op_input_size);
	mu_run_test(test_avr_op_input_size);
	mu_run_test(test_rz_core_print_disasm_resolve_aav_symbols);
	mu_run_test(test_rz_core_il_print_rzil);
	mu_run_test(test_rz_analysis_esil_trace_no_snapshot);
	mu_run_test(test_rz_analysis_esil_trace_snapshot_and_continue_back);
	mu_run_test(test_rz_core_analysis_type_match_stepping);
	mu_run_test(test_rz_core_analysis_type_match_block_fcns_and_cache_eviction);
	mu_run_test(test_rz_core_analysis_type_match_mips_delay_and_pcalign);
	return tests_passed != tests_run;
}

mu_main(all_tests)
