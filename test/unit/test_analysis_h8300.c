// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_debug.h>
#include <rz_io.h>
#include "minunit.h"

/* Encodings and effects follow the H8/300 Programming Manual and H8/300H
 * Software Manual. h8300h selects the existing advanced-mode register model. */
static RzAnalysis *h8300_analysis(const char *cpu) {
	rz_return_val_if_fail(cpu, NULL);
	RzAnalysis *analysis = rz_analysis_new(NULL);
	if (!analysis) {
		return NULL;
	}
	if (!rz_analysis_use(analysis, "h8300") || !rz_analysis_set_bits(analysis, 16)) {
		rz_analysis_free(analysis);
		return NULL;
	}
	rz_analysis_set_cpu(analysis, cpu);
	return analysis;
}

static bool decode(RzAnalysis *analysis, RzAnalysisOp *op, const char *hex, ut64 addr, RzAnalysisOpMask mask) {
	rz_return_val_if_fail(analysis && op && hex, false);
	ut8 bytes[16];
	int size = rz_hex_str2bin(hex, bytes);
	return size > 0 && rz_analysis_op(analysis, op, addr, bytes, size, mask) == size;
}

static bool reg_is(const RzAnalysisValue *value, const char *name, RzAnalysisValueAccess access) {
	rz_return_val_if_fail(name, false);
	return value && value->type == RZ_ANALYSIS_VAL_REG && value->reg &&
		!strcmp(value->reg->name, name) && value->access == access;
}

static const RzAnalysisValue *find_access(const RzAnalysisOp *op, RzAnalysisValueType type, const char *reg) {
	rz_return_val_if_fail(op, NULL);
	RzListIter *iter;
	RzAnalysisValue *value;
	rz_list_foreach (op->access, iter, value) {
		if (value->type == type && ((!reg && !value->reg) || (reg && value->reg && !strcmp(value->reg->name, reg)))) {
			return value;
		}
	}
	return NULL;
}

static bool test_h8300_stack(void) {
	static const struct {
		const char *cpu;
		const char *hex;
		st64 stackptr;
	} cases[] = {
		{ "h8300", "6df3", 2 }, /* push.w r3 */
		{ "h8300", "6d73", -2 }, /* pop.w r3 */
		{ "h8300", "1b97", 4 }, /* subs #4,r7 */
		{ "h8300", "0b87", -2 }, /* adds #2,r7 */
		{ "h8300", "6cf4", 1 }, /* mov.b r4h,@-r7 */
		{ "h8300", "6c74", -1 }, /* mov.b @r7+,r4h */
		{ "h8300", "5470", -2 },
		{ "h8300", "5670", -4 },
		{ "h8300l", "6df3", 2 },
		{ "h8300l", "6d73", -2 },
		{ "h8300l", "1b97", 4 },
		{ "h8300l", "5470", -2 },
		{ "h8300l", "5670", -4 },
		{ "h8300h", "01006df6", 4 }, /* push.l er6 */
		{ "h8300h", "01006d76", -4 }, /* pop.l er6 */
		{ "h8300h", "6df3", 2 },
		{ "h8300h", "6d73", -2 },
		{ "h8300h", "7a3700000008", 8 }, /* sub.l #8,er7 */
		{ "h8300h", "7a1700000008", -8 }, /* add.l #8,er7 */
		{ "h8300h", "7a17fffffff8", 8 }, /* add.l #-8,er7 */
		{ "h8300h", "1b97", 4 },
		{ "h8300h", "0b87", -2 },
		{ "h8300h", "1bf7", 2 }, /* dec.l #2,er7 */
		{ "h8300h", "0b77", -1 }, /* inc.l #1,er7 */
		{ "h8300h", "6cf4", 1 },
		{ "h8300h", "6c74", -1 },
		{ "h8300h", "01006df2", 4 },
		{ "h8300h", "01406df0", 2 }, /* stc.w ccr,@-er7 */
		{ "h8300h", "01406d70", -2 }, /* ldc.w @er7+,ccr */
		{ "h8300h", "5470", -4 },
		{ "h8300h", "5670", -4 },
	};
	const RzAnalysisOpMask masks[] = {
		RZ_ANALYSIS_OP_MASK_BASIC,
		RZ_ANALYSIS_OP_MASK_VAL,
		RZ_ANALYSIS_OP_MASK_OPEX,
		RZ_ANALYSIS_OP_MASK_ALL,
	};
	RzAnalysis *analysis = h8300_analysis("h8300");
	mu_assert_notnull(analysis, "analysis");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		rz_analysis_set_cpu(analysis, cases[i].cpu);
		for (size_t j = 0; j < RZ_ARRAY_SIZE(masks); j++) {
			RzAnalysisOp op;
			mu_assert_true(decode(analysis, &op, cases[i].hex, 0x100, masks[j]), cases[i].hex);
			mu_assert_eq(op.stackop, RZ_ANALYSIS_STACK_INC, cases[i].hex);
			mu_assert_eq(op.stackptr, cases[i].stackptr, cases[i].hex);
			mu_assert_eq(rz_analysis_op_apply_sp_effect(&op, -16), -16 - cases[i].stackptr, "SP tracker uses signed stackptr");
			if (op.type == RZ_ANALYSIS_OP_TYPE_PUSH || op.type == RZ_ANALYSIS_OP_TYPE_POP) {
				mu_assert_eq(op.direction, op.type == RZ_ANALYSIS_OP_TYPE_PUSH ? RZ_ANALYSIS_OP_DIR_WRITE : RZ_ANALYSIS_OP_DIR_READ, "stack memory direction");
				mu_assert_eq(op.refptr, RZ_ABS(cases[i].stackptr), "stack memory width");
				if (masks[j] & RZ_ANALYSIS_OP_MASK_VAL) {
					mu_assert_true(reg_is(find_access(&op, RZ_ANALYSIS_VAL_REG, "ccr"), "ccr", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "PUSH and POP update condition codes");
				}
			}
			if (!(masks[j] & RZ_ANALYSIS_OP_MASK_VAL)) {
				mu_assert_null(op.access, "access is opt-in");
				mu_assert_null(op.dst, "VAL is opt-in");
			}
			if (!(masks[j] & RZ_ANALYSIS_OP_MASK_OPEX)) {
				mu_assert_null(op.opex, "OPEX is opt-in");
			}
			rz_analysis_op_fini(&op);
		}
	}
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_unknown_sp(void) {
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	const char *encodings[] = {
		"7a3600000008", /* sub.l #8,er6: not SP */
		"79370008", /* sub.w #8,r7: only part of ER7 */
		"0b57", /* inc.w #1,r7: only part of ER7 */
		"1a97", /* sub.l er1,er7: dynamic */
		"0ff7", /* mov.l er7,er7 */
		"0fe7", /* mov.l er6,er7: not a stack reset */
		"7a0700000800", /* mov.l #0x800,er7 */
		"01006d77", /* pop.l er7 overwrites SP */
		"6d77", /* pop.w r7 overwrites part of SP */
		"01006d17", /* mov.l @er1+,er7 */
		"6c7f", /* mov.b @er7+,r7l overwrites part of SP */
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(encodings); i++) {
		RzAnalysisOp op;
		mu_assert_true(decode(analysis, &op, encodings[i], 0x100, RZ_ANALYSIS_OP_MASK_VAL), encodings[i]);
		mu_assert_eq(op.stackop, RZ_ANALYSIS_STACK_NULL, "no invented constant SP effect");
		mu_assert_eq(op.stackptr, 0, "no invented stack delta");
		rz_analysis_op_fini(&op);
	}
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_control_flow(void) {
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	const RzTypeCond conditions[] = {
		RZ_TYPE_COND_AL,
		RZ_TYPE_COND_NV,
		RZ_TYPE_COND_HI,
		RZ_TYPE_COND_LS,
		RZ_TYPE_COND_HS,
		RZ_TYPE_COND_LO,
		RZ_TYPE_COND_NE,
		RZ_TYPE_COND_EQ,
		RZ_TYPE_COND_VC,
		RZ_TYPE_COND_VS,
		RZ_TYPE_COND_PL,
		RZ_TYPE_COND_MI,
		RZ_TYPE_COND_GE,
		RZ_TYPE_COND_LT,
		RZ_TYPE_COND_GT,
		RZ_TYPE_COND_LE,
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(conditions); i++) {
		ut8 bytes[] = { 0x40 + i, 0xfc };
		RzAnalysisOp op;
		mu_assert_eq(rz_analysis_op(analysis, &op, 0x100, bytes, sizeof(bytes), RZ_ANALYSIS_OP_MASK_VAL), 2, "branch size");
		mu_assert_eq(op.cond, conditions[i], "branch condition");
		/* Normalize enum signedness before mu_assert_eq widens both operands. */
		const ut32 expected_type = i == 0 ? RZ_ANALYSIS_OP_TYPE_JMP : i == 1 ? RZ_ANALYSIS_OP_TYPE_NOP
										     : RZ_ANALYSIS_OP_TYPE_CJMP;
		mu_assert_eq(op.type, expected_type, "branch type");
		mu_assert_eq(op.jump, i == 1 ? UT64_MAX : 0xfe, "branch target");
		mu_assert_eq(op.fail, i < 2 ? UT64_MAX : 0x102, "conditional fallthrough only");
		mu_assert_eq(op.eob, i != 1, "BRN does not end block");
		mu_assert_null(op.dst, "branch target is not written");
		mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_IMM, "PC-relative target is not a memory load");
		mu_assert_eq(op.src[0]->imm, 0xfe, "PC-relative operand includes instruction size");
		rz_analysis_op_fini(&op);
	}
	const char *calls[] = { "5516", "5e801234", "5d40", "5f40", "5c00fffc" };
	RzStackAddr sp = -12;
	for (size_t i = 0; i < RZ_ARRAY_SIZE(calls); i++) {
		RzAnalysisOp op;
		mu_assert_true(decode(analysis, &op, calls[i], 0x100, RZ_ANALYSIS_OP_MASK_VAL), "call");
		mu_assert_eq(op.fail, 0x100 + op.size, "call continuation");
		mu_assert_false(op.eob, "call is not noreturn");
		mu_assert_eq(op.stackop, RZ_ANALYSIS_STACK_NOP, "call has balanced net effect");
		sp = rz_analysis_op_apply_sp_effect(&op, sp);
		mu_assert_eq(sp, -12, "successive calls do not accumulate");
		const RzAnalysisValue *push = find_access(&op, RZ_ANALYSIS_VAL_MEM, "er7");
		mu_assert_notnull(push, "actual return address push is described");
		mu_assert_eq(push->access, RZ_ANALYSIS_ACC_W, "return address write");
		mu_assert_eq(push->memref, 4, "advanced mode return address slot");
		mu_assert_eq(push->delta, -4, "return address location");
		mu_assert_null(op.dst, "call target is not a destination");
		if (i == 1) {
			mu_assert_eq(op.jump, 0x801234, "absolute call preserves high address byte");
		} else if (i == 2) {
			mu_assert_true(reg_is(op.src[0], "er4", RZ_ANALYSIS_ACC_R), "register-indirect target is not dereferenced");
		} else if (i == 3) {
			mu_assert_eq(op.ptr, 0x40, "memory-indirect pointer slot");
			mu_assert_eq(op.refptr, 4, "pointer slot size differs from address width");
			mu_assert_eq(op.src[0]->base, 0x40, "MI8 address is not memref");
			mu_assert_eq(op.src[0]->memref, 4, "MI8 memory width");
		} else if (i == 4) {
			mu_assert_eq(op.jump, 0x100, "long BSR target includes instruction size");
		}
		rz_analysis_op_fini(&op);
	}
	RzAnalysisOp op;
	mu_assert_true(decode(analysis, &op, "5aab9234", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "jmp absolute");
	mu_assert_eq(op.fail, UT64_MAX, "JMP has no fallthrough");
	mu_assert_eq(op.jump, 0xab9234, "JMP preserves all 24 target bits");
	mu_assert_true(op.eob, "JMP ends block");
	mu_assert_eq(op.src[0]->type, RZ_ANALYSIS_VAL_IMM, "absolute jump is not a data reference");
	mu_assert_eq(op.src[0]->imm, 0xab9234, "absolute operand matches jump target");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "5a009234", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "low absolute JMP");
	mu_assert_eq(op.jump, 0x9234, "absolute jump address is not sign extended");
	rz_analysis_op_fini(&op);
	rz_analysis_set_cpu(analysis, "h8300");
	mu_assert_true(decode(analysis, &op, "5e009234", 0x100, RZ_ANALYSIS_OP_MASK_ALL), "base CPU absolute call");
	mu_assert_eq(op.jump, 0x9234, "base CPU unsigned target");
	mu_assert_streq(op.mnemonic, "jsr @0x9234", "disassembly matches target");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "4002", 0xfffe, RZ_ANALYSIS_OP_MASK_BASIC), "wrapping branch");
	mu_assert_eq(op.jump, 2, "16-bit branch wraps");
	rz_analysis_op_fini(&op);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_values(void) {
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	RzAnalysisOp op;
	mu_assert_true(decode(analysis, &op, "1d12", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "cmp.w r1,r2");
	mu_assert_true(reg_is(op.src[0], "r1", RZ_ANALYSIS_ACC_R), "CMP reads first register");
	mu_assert_true(reg_is(op.src[1], "r2", RZ_ANALYSIS_ACC_R), "CMP reads second register");
	mu_assert_null(op.dst, "CMP has no data destination");
	mu_assert_streq(op.reg, "r2", "compared register");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "7a1700000008", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "add.l #8,er7");
	mu_assert_eq(op.val, 8, "scalar immediate");
	mu_assert_eq(op.src[0]->imm, 8, "source immediate");
	mu_assert_true(reg_is(op.dst, "er7", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "two-address arithmetic reads and writes destination");
	const RzAnalysisValue *access = find_access(&op, RZ_ANALYSIS_VAL_REG, "er7");
	mu_assert_notnull(access, "ER7 access");
	mu_assert_neq((ut64)access, (ut64)op.dst, "access list owns separate values");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "6e369494", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "mov.b @(-27500,er3),r6h");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_LOAD, "memory MOV is load");
	mu_assert_eq(op.direction, RZ_ANALYSIS_OP_DIR_READ, "read direction");
	mu_assert_eq(op.refptr, 1, "byte load width");
	mu_assert_eq(op.ptrsize, 1, "byte pointer size");
	mu_assert_eq(op.src[0]->delta, -27500, "signed displacement");
	mu_assert_eq((st64)op.disp, -27500, "scalar displacement");
	mu_assert_streq(op.ireg, "er3", "address register");
	mu_assert_eq(op.ptr, UT64_MAX, "dynamic address is not guessed");
	mu_assert_true(reg_is(op.dst, "r6h", RZ_ANALYSIS_ACC_W), "load destination");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "01006b018111", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "mov.l @0xff8111,er1");
	mu_assert_eq(op.ptr, 0xff8111, "absolute address");
	mu_assert_eq(op.src[0]->base, 0xff8111, "absolute value base");
	mu_assert_eq(op.src[0]->absolute, true, "absolute is a boolean");
	mu_assert_eq(op.src[0]->memref, 4, "longword memory access");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "7f997140", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "bnot #4,@0xffff99");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_XOR, "bit inversion type");
	mu_assert_eq(op.direction, RZ_ANALYSIS_OP_DIR_READ | RZ_ANALYSIS_OP_DIR_WRITE, "bit RMW direction");
	mu_assert_eq(op.dst->access, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W, "bit RMW destination");
	mu_assert_null(find_access(&op, RZ_ANALYSIS_VAL_REG, "ccr"), "BNOT preserves CCR");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "7e017310", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "btst #1,@0xffff01");
	mu_assert_null(op.dst, "BTST has no data destination");
	mu_assert_eq(op.src[1]->access, RZ_ANALYSIS_ACC_R, "BTST memory read");
	mu_assert_eq(op.direction, RZ_ANALYSIS_OP_DIR_READ, "BTST does not write memory");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "01c05212", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "mulxs.w r1,er2");
	mu_assert_true(op.sign, "signed multiplication");
	mu_assert_true(reg_is(op.dst, "er2", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "widening multiplication destination");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "17b1", 0x100, RZ_ANALYSIS_OP_MASK_BASIC), "neg.l er1");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_SUB, "negation is arithmetic");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "6acb3322", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "movtpe r3l,@0x3322");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_STORE, "peripheral write");
	mu_assert_eq(op.mmio_address, 0x3322, "peripheral address");
	rz_analysis_op_fini(&op);
	rz_analysis_set_cpu(analysis, "h8300");
	mu_assert_true(decode(analysis, &op, "2588", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "base CPU short absolute address");
	mu_assert_eq(op.ptr, 0xff88, "base CPU has 16-bit addresses");
	mu_assert_eq(op.src[0]->base, 0xff88, "base CPU value address");
	rz_analysis_op_fini(&op);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_opex_and_implicit(void) {
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	RzAnalysisOp op;
	mu_assert_true(decode(analysis, &op, "01006d92", 0x100, RZ_ANALYSIS_OP_MASK_OPEX | RZ_ANALYSIS_OP_MASK_VAL), "mov.l er2,@-er1");
	mu_assert_notnull(op.opex, "OPEX exists");
	char *json = rz_structured_data_to_json(op.opex);
	mu_assert_notnull(json, "OPEX JSON");
	mu_assert_true(rz_json_string_eq(json,
			       "{\"opex\":{\"operands\":[{\"access\":\"r\",\"type\":\"reg\",\"value\":\"er2\"},"
			       "{\"access\":\"w\",\"type\":\"mem\",\"size\":4,\"base\":\"er1\",\"disp\":-4,\"address_mode\":\"predecrement\"}]}}"),
		"typed operands and predecrement location");
	free(json);
	mu_assert_true(reg_is(find_access(&op, RZ_ANALYSIS_VAL_REG, "er1"), "er1", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "predecrement updates base register");
	mu_assert_eq(op.dst->delta, -4, "predecrement access uses updated base");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "01006d12", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "mov.l @er1+,er2");
	mu_assert_eq(op.src[0]->delta, 0, "postincrement accesses old base");
	mu_assert_true(reg_is(find_access(&op, RZ_ANALYSIS_VAL_REG, "er1"), "er1", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "postincrement updates base register");
	rz_analysis_op_fini(&op);
	mu_assert_true(decode(analysis, &op, "7bd4598f", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "eepmov.w");
	mu_assert_true(reg_is(find_access(&op, RZ_ANALYSIS_VAL_REG, "r4"), "r4", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "EEPMOV count");
	const RzAnalysisValue *src = find_access(&op, RZ_ANALYSIS_VAL_MEM, "er5");
	const RzAnalysisValue *dst = find_access(&op, RZ_ANALYSIS_VAL_MEM, "er6");
	mu_assert_notnull(src, "EEPMOV source");
	mu_assert_notnull(dst, "EEPMOV destination");
	mu_assert_eq(src->memref, 1, "EEPMOV.W copies bytes, with a word count");
	mu_assert_eq(dst->access, RZ_ANALYSIS_ACC_W, "EEPMOV memory write");
	rz_analysis_op_fini(&op);
	mu_assert_streq(rz_reg_get_name(rz_analysis_get_reg(analysis), RZ_REG_NAME_BP), "er6", "H8300H BP role");
	mu_assert_eq(rz_analysis_archinfo(analysis, RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE), 10, "maximum decoded instruction size");
	mu_assert_true(decode(analysis, &op, "010078106b2200111111", 0x100, RZ_ANALYSIS_OP_MASK_VAL), "ten-byte MOV");
	mu_assert_eq(op.refptr, 4, "long instruction memory width");
	mu_assert_eq(op.src[0]->delta, 0x111111, "24-bit displacement");
	rz_analysis_op_fini(&op);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_invalid(void) {
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	const ut8 bytes[] = { 0x01, 0x00, 0x78, 0x10, 0x6b, 0x22, 0x00, 0x11, 0x11, 0x11 };
	for (size_t size = 1; size < sizeof(bytes); size++) {
		RzAnalysisOp op;
		int ret = rz_analysis_op(analysis, &op, 0x100, bytes, size, RZ_ANALYSIS_OP_MASK_ALL);
		mu_assert_true(ret < 1, "truncated instruction is rejected");
		mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_ILL, "invalid instruction type");
		mu_assert_null(op.access, "no partial operand accesses");
		mu_assert_null(op.opex, "no partial OPEX");
		rz_analysis_op_fini(&op);
	}
	const ut8 four_byte_ops[][4] = {
		{ 0x5a, 0xab, 0x92, 0x34 },
		{ 0x5e, 0xab, 0x92, 0x34 },
		{ 0x79, 0x00, 0x12, 0x34 },
		{ 0x6b, 0x00, 0x12, 0x34 },
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(four_byte_ops); i++) {
		for (size_t size = 2; size < 4; size++) {
			/* Exact-sized allocations also detect overreads under memory checkers. */
			ut8 *truncated = malloc(size);
			mu_assert_notnull(truncated, "truncated input");
			memcpy(truncated, four_byte_ops[i], size);
			RzAnalysisOp op;
			mu_assert_true(rz_analysis_op(analysis, &op, 0x100, truncated, size, RZ_ANALYSIS_OP_MASK_ALL) < 1, "four-byte opcode requires all four bytes");
			mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_ILL, "truncated opcode is invalid");
			rz_analysis_op_fini(&op);
			free(truncated);
		}
	}
	RzAnalysisOp op;
	const ut8 invalid[] = { 0xff, 0xff };
	/* 0xffff is a valid byte-immediate MOV; use an undefined 0x01 prefix. */
	const ut8 undefined[] = { 0x01, 0xff };
	mu_assert_eq(rz_analysis_op(analysis, &op, 0x100, invalid, sizeof(invalid), RZ_ANALYSIS_OP_MASK_BASIC), 2, "valid all-ones instruction");
	rz_analysis_op_fini(&op);
	mu_assert_true(rz_analysis_op(analysis, &op, 0x100, undefined, sizeof(undefined), RZ_ANALYSIS_OP_MASK_ALL) < 1, "undefined encoding");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_ILL, "undefined type");
	rz_analysis_op_fini(&op);
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_decoded_rendering(void) {
	static const struct {
		const char *hex;
		const char *text;
	} cases[] = {
		{ "6912", "r2 = (short)[er1]" },
		{ "6992", "(short)[er1] = r2" },
		{ "3088", "(char)[0xffff88] = r0h" },
		{ "5d40", "er4()" },
		{ "5940", "goto er4" },
		{ "5f40", "(word)[0x40]()" },
	};
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		RzAnalysisOp op;
		mu_assert_true(decode(analysis, &op, cases[i].hex, 0x100, RZ_ANALYSIS_OP_MASK_VAL), cases[i].hex);
		mu_assert_streq_free(rz_analysis_op_to_string(analysis, &op), cases[i].text, "decoded rendering retains operands");
		if (op.type == RZ_ANALYSIS_OP_TYPE_IRCALL || op.type == RZ_ANALYSIS_OP_TYPE_IRJMP) {
			/* Other plugins still put the indirect target in dst. */
			op.dst = op.src[0];
			op.src[0] = NULL;
			mu_assert_streq_free(rz_analysis_op_to_string(analysis, &op), cases[i].text, "legacy target representation still renders");
		}
		rz_analysis_op_fini(&op);
	}
	rz_analysis_free(analysis);
	mu_end;
}

static bool test_h8300_trace_memory_writes(void) {
	static const struct {
		const char *hex;
		const char *reg;
		ut64 address;
	} cases[] = {
		{ "3088", NULL, 0xffff88 }, /* mov.b r0h,@0xffff88 */
		{ "6ee20010", "er6", 0xffff80 }, /* mov.b r2h,@(16,er6) */
		{ "6ce2", "er6", 0xffff6f }, /* mov.b r2h,@-er6 */
	};
	RzAnalysis *analysis = h8300_analysis("h8300h");
	mu_assert_notnull(analysis, "analysis");
	RzIO *io = rz_io_new();
	mu_assert_notnull(io, "IO");
	io->va = true;
	mu_assert_notnull(rz_io_open_at(io, "malloc://32", RZ_PERM_RWX, 0, 0, NULL), "code mapping");
	mu_assert_notnull(rz_io_open_at(io, "malloc://256", RZ_PERM_RW, 0, 0xffff00, NULL), "data mapping");
	/* No live target is required: register values and memory are supplied here. */
	RzDebug dbg = { .analysis = analysis, .reg = rz_reg_new(), .session = rz_debug_session_new() };
	mu_assert_notnull(dbg.reg, "debug registers");
	mu_assert_notnull(dbg.session, "debug session");
	mu_assert_true(rz_reg_set_profile_string(dbg.reg, rz_analysis_get_reg(analysis)->reg_profile_str), "debug register profile");
	rz_io_bind(io, &dbg.iob);
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		ut8 code[16];
		int size = rz_hex_str2bin(cases[i].hex, code);
		mu_assert_true(size > 0, "instruction encoding");
		mu_assert_true(rz_io_write_at(io, 0, code, size), "instruction bytes");
		mu_assert_true(rz_reg_setv(dbg.reg, "er6", 0xffff70), "base register");
		mu_assert_true(rz_debug_trace_ins_before(&dbg), "trace before store");
		const RzAnalysisValue *write = find_access(dbg.cur_op, RZ_ANALYSIS_VAL_MEM, cases[i].reg);
		mu_assert_notnull(write, "memory write access");
		mu_assert_eq(write->base, cases[i].address, "resolved write destination");
		ut8 byte = 0xa0 + i;
		mu_assert_true(rz_io_write_at(io, cases[i].address, &byte, 1), "simulate store");
		mu_assert_true(rz_debug_trace_ins_after(&dbg), "trace after store");
		RzVector *changes = ht_up_find(dbg.session->memory, cases[i].address, NULL);
		mu_assert_notnull(changes, "session records the actual destination");
		mu_assert_eq(rz_vector_len(changes), 1, "one byte change recorded");
		RzDebugChangeMem *change = rz_vector_index_ptr(changes, 0);
		mu_assert_eq(change->data, byte, "session records the stored byte");
		mu_assert_null(ht_up_find(dbg.session->memory, 0, NULL), "no spurious write at address zero");
	}
	rz_debug_session_free(dbg.session);
	rz_reg_free(dbg.reg);
	rz_io_free(io);
	rz_analysis_free(analysis);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_h8300_stack);
	mu_run_test(test_h8300_unknown_sp);
	mu_run_test(test_h8300_control_flow);
	mu_run_test(test_h8300_values);
	mu_run_test(test_h8300_opex_and_implicit);
	mu_run_test(test_h8300_invalid);
	mu_run_test(test_h8300_decoded_rendering);
	mu_run_test(test_h8300_trace_memory_writes);
	return tests_passed != tests_run;
}

mu_main(all_tests)
