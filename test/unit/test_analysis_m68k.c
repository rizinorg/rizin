// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_core.h>
#include "minunit.h"

/* Expected states follow M68000PRM, sections 4 and 5, and CFPRM, sections 3
 * and 4. Test real encodings through the plugin, including its VAL and OPEX
 * interfaces; IL snapshots alone do not check these values or execution. */

static RzCore *m68k_core_new(const char *cpu) {
	rz_return_val_if_fail(cpu, NULL);
	RzCore *core = rz_core_new();
	if (!core) {
		return NULL;
	}
	if (!rz_core_arch_configure(core, "m68k", 32, cpu, NULL, NULL) ||
		!rz_io_open_at(core->io, "malloc://0x1000", RZ_PERM_RWX, 0, 0, NULL)) {
		rz_core_free(core);
		return NULL;
	}
	rz_config_set_b(core->config, "cfg.bigendian", true);
	return core;
}

static bool m68k_decode(RzCore *core, RzAnalysisOp *op, const char *hex) {
	rz_return_val_if_fail(core && op && hex, false);
	ut8 bytes[32];
	int size = rz_hex_str2bin(hex, bytes);
	rz_analysis_op_init(op);
	return size > 0 && rz_analysis_op(core->analysis, op, 0x100, bytes, size, RZ_ANALYSIS_OP_MASK_VAL | RZ_ANALYSIS_OP_MASK_OPEX) == size;
}

static bool m68k_value_reg(const RzAnalysisValue *value, const char *name, RzAnalysisValueAccess access) {
	rz_return_val_if_fail(name, false);
	mu_assert_notnull(value, "register value exists");
	mu_assert_eq(value->type, RZ_ANALYSIS_VAL_REG, "register value type");
	mu_assert_notnull(value->reg, "register exists");
	mu_assert_streq(value->reg->name, name, "register name");
	mu_assert_eq(value->access, access, "register access");
	return true;
}

#if defined(RZ_CAPSTONE_HAS_M68K_FP_FORMATS) || defined(RZ_CAPSTONE_HAS_M68K_COLDFIRE)
static bool m68k_value_mem(const RzAnalysisValue *value, const char *base, int size, RzAnalysisValueAccess access) {
	rz_return_val_if_fail(base, false);
	mu_assert_notnull(value, "memory value exists");
	mu_assert_eq(value->type, RZ_ANALYSIS_VAL_MEM, "memory value type");
	mu_assert_notnull(value->reg, "base register exists");
	mu_assert_streq(value->reg->name, base, "base register");
	mu_assert_eq(value->memref, size, "memory access size");
	mu_assert_eq(value->access, access, "memory access direction");
	return true;
}

#endif

static bool m68k_opex_is(const RzAnalysisOp *op, const char *expected) {
	rz_return_val_if_fail(op && expected, false);
	mu_assert_notnull(op->opex, "operand metadata exists");
	char *json = rz_structured_data_to_json(op->opex);
	mu_assert_notnull(json, "operand metadata JSON");
	bool equal = rz_json_string_eq(json, expected);
	if (!equal) {
		fprintf(stderr, "OPEX: %s\nExpected: %s\n", json, expected);
	}
	free(json);
	return equal;
}

static bool test_m68k_hidden_fpu_destination(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	const char *encodings[] = {
		"f2000025", "f2001fa5", /* frem fp0 / fp7 */
		"f2000026", "f2001fa6", /* fscale fp0 / fp7 */
		"f2000027", "f2001fa7", /* fsglmul fp0 / fp7 */
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(encodings); i++) {
		RzAnalysisOp op;
		mu_assert_true(m68k_decode(core, &op, encodings[i]), "decode collapsed FPU instruction");
		const char *reg = i % 2 ? "fp7" : "fp0";
		mu_assert_eq(op.family, RZ_ANALYSIS_OP_FAMILY_FPU, "FPU family");
		mu_assert_true(m68k_value_reg(op.src[0], reg, RZ_ANALYSIS_ACC_R), "collapsed source");
		mu_assert_null(op.src[1], "one source");
		mu_assert_true(m68k_value_reg(op.dst, reg, RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "hidden destination is read/write");
		char *expected = rz_str_newf("{\"opex\":{\"operands\":[{\"type\":\"reg\",\"value\":\"%s\"},{\"type\":\"reg\",\"value\":\"%s\"}]}}", reg, reg);
		mu_assert_notnull(expected, "expected operand metadata");
		bool matches = m68k_opex_is(&op, expected);
		free(expected);
		mu_assert_true(matches, "materialized destination in OPEX");
		rz_analysis_op_fini(&op);
	}
	RzAnalysisOp op;
	mu_assert_true(m68k_decode(core, &op, "f2000522"), "fadd fp1, fp2");
	mu_assert_true(m68k_value_reg(op.src[0], "fp1", RZ_ANALYSIS_ACC_R), "explicit source");
	mu_assert_null(op.src[1], "no invented source");
	mu_assert_true(m68k_value_reg(op.dst, "fp2", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "explicit destination");
	rz_analysis_op_fini(&op);

	mu_assert_true(m68k_decode(core, &op, "f2000538"), "fcmp fp1, fp2");
	mu_assert_true(m68k_value_reg(op.src[0], "fp1", RZ_ANALYSIS_ACC_R), "comparison first source");
	mu_assert_true(m68k_value_reg(op.src[1], "fp2", RZ_ANALYSIS_ACC_R), "comparison second source");
	mu_assert_null(op.src[2], "two comparison sources");
	mu_assert_null(op.dst, "comparison does not write a data register");
	rz_analysis_op_fini(&op);

	const char *unary[] = { "f2000018", "f200003a" }; /* fabs fp0, ftst fp0 */
	for (size_t i = 0; i < RZ_ARRAY_SIZE(unary); i++) {
		mu_assert_true(m68k_decode(core, &op, unary[i]), "complete unary FPU instruction");
		mu_assert_true(m68k_value_reg(op.src[0], "fp0", RZ_ANALYSIS_ACC_R), "unary source");
		mu_assert_null(op.src[1], "no synthetic unary source");
		if (i == 0) {
			mu_assert_true(m68k_value_reg(op.dst, "fp0", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "unary destination");
		} else {
			mu_assert_null(op.dst, "ftst has no destination");
		}
		mu_assert_true(m68k_opex_is(&op, "{\"opex\":{\"operands\":[{\"type\":\"reg\",\"value\":\"fp0\"}]}}"), "complete unary operand is not duplicated");
		rz_analysis_op_fini(&op);
	}
	rz_core_free(core);
	mu_end;
}

#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
static bool test_m68k_fp_formats(void) {
	RzCore *core = m68k_core_new("68040");
	mu_assert_notnull(core, "M68K core");
	RzAnalysisOp op;
	mu_assert_true(m68k_decode(core, &op, "f23c48003fff00008000000000000000"), "extended immediate");
	mu_assert_eq(op.family, RZ_ANALYSIS_OP_FAMILY_FPU, "extended FPU family");
	mu_assert_true(m68k_value_reg(op.dst, "fp0", RZ_ANALYSIS_ACC_W), "extended destination");
	mu_assert_true(m68k_opex_is(&op, "{\"opex\":{\"operands\":[{\"type\":\"fp_extended\",\"sign_exp\":16383,\"reserved\":0,\"significand\":9223372036854775808},{\"type\":\"reg\",\"value\":\"fp0\"}]}}"), "extended bits are retained");
	rz_analysis_op_fini(&op);
	mu_assert_true(m68k_decode(core, &op, "f23c4c00002500012345678901234567"), "packed immediate");
	mu_assert_eq(op.family, RZ_ANALYSIS_OP_FAMILY_FPU, "packed FPU family");
	mu_assert_true(m68k_value_reg(op.dst, "fp0", RZ_ANALYSIS_ACC_W), "packed destination");
	mu_assert_true(m68k_opex_is(&op, "{\"opex\":{\"operands\":[{\"type\":\"fp_packed\",\"header\":2424833,\"fraction\":2541551402847782247},{\"type\":\"reg\",\"value\":\"fp0\"}]}}"), "packed bits are retained");
	rz_analysis_op_fini(&op);

	const char *loads[] = { "f2104800", "f2104c00" }; /* fmove.x/p (a0), fp0 */
	for (size_t i = 0; i < RZ_ARRAY_SIZE(loads); i++) {
		mu_assert_true(m68k_decode(core, &op, loads[i]), "extended/packed load");
		mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_LOAD, "FP load type");
		mu_assert_eq(op.direction, RZ_ANALYSIS_OP_DIR_READ, "FP load direction");
		mu_assert_eq(op.refptr, 12, "FP memory representation occupies 12 bytes");
		mu_assert_true(m68k_value_mem(op.src[0], "a0", 12, RZ_ANALYSIS_ACC_R), "FP load source");
		mu_assert_true(m68k_value_reg(op.dst, "fp0", RZ_ANALYSIS_ACC_W), "FP load destination");
		rz_analysis_op_fini(&op);
	}
	const char *stores[] = { "f2116c7b", "f2127d30" }; /* static -5 / dynamic d3 k-factor */
	for (size_t i = 0; i < RZ_ARRAY_SIZE(stores); i++) {
		mu_assert_true(m68k_decode(core, &op, stores[i]), "packed store");
		mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_STORE, "k-factor is not the destination");
		mu_assert_eq(op.direction, RZ_ANALYSIS_OP_DIR_WRITE, "packed store direction");
		mu_assert_eq(op.refptr, 12, "packed store width");
		mu_assert_true(m68k_value_reg(op.src[0], i ? "fp2" : "fp0", RZ_ANALYSIS_ACC_R), "packed source");
		if (i) {
			mu_assert_true(m68k_value_reg(op.src[1], "d3", RZ_ANALYSIS_ACC_R), "dynamic k-factor");
		} else {
			mu_assert_notnull(op.src[1], "static k-factor");
			mu_assert_eq(op.src[1]->type, RZ_ANALYSIS_VAL_IMM, "static k-factor type");
			mu_assert_eq(op.src[1]->imm, -5, "signed static k-factor");
			mu_assert_eq(op.src[1]->access, RZ_ANALYSIS_ACC_R, "static k-factor access");
		}
		mu_assert_null(op.src[2], "only FP value and k-factor are sources");
		mu_assert_true(m68k_value_mem(op.dst, i ? "a2" : "a1", 12, RZ_ANALYSIS_ACC_W), "packed memory destination");
		rz_analysis_op_fini(&op);
	}
	rz_core_free(core);
	mu_end;
}
#endif

static void m68k_reset(RzCore *core, ut32 d0, ut32 d1, ut16 sr) {
	rz_return_if_fail(core);
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	rz_reg_setv(reg, "pc", 0x100);
	rz_reg_setv(reg, "d0", d0);
	rz_reg_setv(reg, "d1", d1);
	rz_reg_setv(reg, "a0", 0x400);
	rz_reg_setv(reg, "a1", 0x500);
	rz_reg_setv(reg, "a7", 0x800);
	rz_reg_setv(reg, "sr", sr);
}

static bool m68k_step(RzCore *core, const char *hex) {
	rz_return_val_if_fail(core && hex, false);
	ut8 bytes[32];
	int size = rz_hex_str2bin(hex, bytes);
	ut64 pc = rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc");
	if (size <= 0 || !rz_io_write_at(core->io, pc, bytes, size)) {
		return false;
	}
	RzAnalysisILVM *vm = rz_analysis_il_vm_new(core->analysis, rz_analysis_get_reg(core->analysis));
	if (!vm) {
		return false;
	}
	RzAnalysisILStepResult result = rz_analysis_il_vm_step(core->analysis, vm, rz_analysis_get_reg(core->analysis));
	rz_analysis_il_vm_free(vm);
	if (result != RZ_ANALYSIS_IL_STEP_RESULT_SUCCESS) {
		fprintf(stderr, "M68K step %s at 0x%" PFMT64x ": result %d\n", hex, pc, result);
		return false;
	}
	return true;
}

/* Bit n gives the condition's value for NZVC == n (M68000PRM table 3-19).
 * This truth table is independent of the lifter's Boolean expressions. */
static const ut16 condition_truth[] = {
	0xffff, 0x0000, 0x0505, 0xfafa, 0x5555, 0xaaaa, 0x0f0f, 0xf0f0,
	0x3333, 0xcccc, 0x00ff, 0xff00, 0xcc33, 0x33cc, 0x0c03, 0xf3fc
};

static bool test_m68k_bcc_conditions(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	for (ut8 condition = 2; condition < 16; condition++) {
		char hex[5];
		snprintf(hex, sizeof(hex), "%02x10", 0x60 | condition);
		for (ut8 flags = 0; flags < 16; flags++) {
			m68k_reset(core, 0x12345678, 0, 0x2010 | flags);
			mu_assert_true(m68k_step(core, hex), "Bcc executes");
			bool taken = (condition_truth[condition] >> flags) & 1;
			mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), taken ? 0x112 : 0x102, "Bcc target or fallthrough");
			mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "sr"), 0x2010 | flags, "Bcc preserves SR");
			mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "d0"), 0x12345678, "Bcc preserves data register");
		}
	}
	rz_core_free(core);
	mu_end;
}

static bool test_m68k_scc_conditions(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	for (ut8 condition = 0; condition < 16; condition++) {
		for (ut8 flags = 0; flags < 16; flags++) {
			ut8 expected = (condition_truth[condition] >> flags) & 1 ? 0xff : 0;
			for (int memory = 0; memory < 2; memory++) {
				char hex[5];
				snprintf(hex, sizeof(hex), "%02x%02x", 0x50 | condition, memory ? 0xd0 : 0xc0);
				m68k_reset(core, 0x12345678, 0, 0x2010 | flags);
				ut8 bytes[] = { 0xaa, 0x55 };
				mu_assert_true(rz_io_write_at(core->io, 0x400, bytes, sizeof(bytes)), "initialize Scc memory");
				mu_assert_true(m68k_step(core, hex), "Scc executes");
				mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), 0x102, "Scc advances PC");
				mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "sr"), 0x2010 | flags, "Scc preserves SR");
				mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "d0"), memory ? 0x12345678 : 0x12345600 | expected, "Scc only changes destination byte");
				mu_assert_eq(rz_io_nread_at(core->io, 0x400, bytes, sizeof(bytes)), sizeof(bytes), "read Scc memory");
				mu_assert_eq(bytes[0], memory ? expected : 0xaa, "Scc memory byte");
				mu_assert_eq(bytes[1], 0x55, "Scc preserves adjacent memory");
			}
		}
	}
	rz_core_free(core);
	mu_end;
}

static bool test_m68k_dbcc_conditions(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	for (ut8 condition = 0; condition < 16; condition++) {
		char hex[9];
		snprintf(hex, sizeof(hex), "%02xc8fffc", 0x50 | condition);
		for (ut8 flags = 0; flags < 16; flags++) {
			for (ut32 counter = 0; counter <= 2; counter += 2) {
				m68k_reset(core, 0x12340000 | counter, 0, 0x2010 | flags);
				mu_assert_true(m68k_step(core, hex), "DBcc executes");
				bool satisfied = (condition_truth[condition] >> flags) & 1;
				ut32 expected = satisfied ? counter : (ut16)(counter - 1);
				mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "d0"), 0x12340000 | expected, "DBcc decrements only the low word when false");
				mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), !satisfied && counter ? 0xfe : 0x104, "DBcc branch, expiry, or condition-true fallthrough");
				mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "sr"), 0x2010 | flags, "DBcc preserves SR");
			}
		}
	}
	rz_core_free(core);
	mu_end;
}

static bool test_m68k_branch_widths_and_calls(void) {
	const struct {
		const char *cpu;
		const char *hex;
		ut32 target;
		bool call;
	} cases[] = {
		{ "68000", "6010", 0x112, false },
		{ "68000", "60f0", 0xf2, false },
		{ "68000", "60000020", 0x122, false },
		{ "68000", "6000ffe0", 0xe2, false },
		{ "68020", "60ff00000040", 0x142, false },
		{ "68020", "60ffffffffc0", 0xc2, false },
		{ "68000", "6110", 0x112, true },
		{ "68000", "61f0", 0xf2, true },
		{ "68000", "61000020", 0x122, true },
		{ "68000", "6100ffe0", 0xe2, true },
		{ "68020", "61ff00000040", 0x142, true },
		{ "68020", "61ffffffffc0", 0xc2, true },
		{ "68000", "4ed0", 0x400, false }, /* jmp (a0) */
		{ "68000", "4ef900000420", 0x420, false },
		{ "68000", "4e90", 0x400, true }, /* jsr (a0) */
		{ "68000", "4eb900000420", 0x420, true },
		{ "68000", "4ebafffc", 0xfe, true }, /* PC-relative jsr */
		{ "68000", "4eaf0004", 0x804, true }, /* target must use A7 before pushing */
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		{ "cfv4e", "6010", 0x112, false },
		{ "cfv4e", "61ff00000040", 0x142, true },
		{ "cfv1", "4e90", 0x400, true },
#endif
	};
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		RzCore *core = m68k_core_new(cases[i].cpu);
		mu_assert_notnull(core, "M68K core");
		m68k_reset(core, 0, 0, 0x201f);
		mu_assert_true(m68k_step(core, cases[i].hex), "branch/call executes");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), cases[i].target, "branch/call target");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "sr"), 0x201f, "branch/call preserves SR");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "a7"), cases[i].call ? 0x7fc : 0x800, "call pushes one longword");
		if (cases[i].call) {
			ut8 bytes[4];
			ut32 next = 0x100 + strlen(cases[i].hex) / 2;
			mu_assert_eq(rz_io_nread_at(core->io, 0x7fc, bytes, sizeof(bytes)), sizeof(bytes), "read return address");
			mu_assert_eq(rz_read_be32(bytes), next, "big-endian return address follows the full instruction");
			mu_assert_true(m68k_step(core, "4e75"), "RTS executes at call target");
			mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), next, "RTS returns to caller");
			mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "a7"), 0x800, "RTS restores stack pointer");
			mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "sr"), 0x201f, "RTS preserves SR");
		}
		rz_core_free(core);
	}
	mu_end;
}

static bool test_m68k_integer_results_and_flags(void) {
	const struct {
		const char *instruction;
		const char *hex;
		ut32 d0, d1;
		ut16 sr;
		ut32 result;
		ut16 flags;
		ut16 mask; /* Zero checks all SR bits; omit architecturally undefined flags. */
	} cases[] = {
		{ "move.b d1,d0", "1001", 0x12345678, 0x80, 0x201f, 0x12345680, 0x2018, 0 },
		{ "move.w d1,d0", "3001", 0x12345678, 0, 0x201f, 0x12340000, 0x2014, 0 },
		{ "move.l d1,d0", "2001", 0, 0x87654321, 0x201f, 0x87654321, 0x2018, 0 },
		{ "moveq -1,d0", "70ff", 0, 0, 0x201f, 0xffffffff, 0x2018, 0 },
		{ "add.b d1,d0 carry", "d001", 0x123400ff, 1, 0x2000, 0x12340000, 0x2015, 0 },
		{ "add.w d1,d0 overflow", "d041", 0x12347fff, 1, 0x2010, 0x12348000, 0x200a, 0 },
		{ "add.l d1,d0 carry", "d081", 0xffffffff, 1, 0x2000, 0, 0x2015, 0 },
		{ "addi.w 1,d0", "06400001", 0x1234ffff, 0, 0x2000, 0x12340000, 0x2015, 0 },
		{ "addq.l 1,d0", "5280", 0x7fffffff, 0, 0x2010, 0x80000000, 0x200a, 0 },
		{ "sub.b d1,d0 borrow", "9001", 0x12340000, 1, 0x2000, 0x123400ff, 0x2019, 0 },
		{ "sub.w d1,d0 overflow", "9041", 0x12348000, 1, 0x2010, 0x12347fff, 0x2002, 0 },
		{ "sub.l d1,d0 zero", "9081", 1, 1, 0x201f, 0, 0x2004, 0 },
		{ "subi.w 1,d0", "04400001", 0x12340000, 0, 0x2000, 0x1234ffff, 0x2019, 0 },
		{ "subq.l 1,d0", "5380", 0, 0, 0x2000, 0xffffffff, 0x2019, 0 },
		{ "cmp.w d1,d0 borrow", "b041", 1, 2, 0x2010, 1, 0x2019, 0 },
		{ "cmp.w d1,d0 equal", "b041", 2, 2, 0x2010, 2, 0x2014, 0 },
		{ "tst.b d0", "4a00", 0x12340000, 0, 0x201f, 0x12340000, 0x2014, 0 },
		{ "and.l d1,d0", "c081", 0xf000000f, 0x0ffffff0, 0x201f, 0, 0x2014, 0 },
		{ "or.l d1,d0", "8081", 0x80000000, 1, 0x201f, 0x80000001, 0x2018, 0 },
		{ "eor.l d1,d0", "b380", 0x80000001, 0x80000000, 0x201f, 1, 0x2010, 0 },
		{ "clr.b d0", "4200", 0x123456ff, 0, 0x201f, 0x12345600, 0x2014, 0 },
		{ "neg.b d0 overflow", "4400", 0x12345680, 0, 0x2000, 0x12345680, 0x201b, 0 },
		{ "neg.l d0 zero", "4480", 0, 0, 0x201f, 0, 0x2004, 0 },
		{ "not.b d0", "4600", 0x123456ff, 0, 0x201f, 0x12345600, 0x2014, 0 },
		{ "ext.w d0", "4880", 0x12340080, 0, 0x201f, 0x1234ff80, 0x2018, 0 },
		{ "swap d0", "4840", 0x12345678, 0, 0x201f, 0x56781234, 0x2010, 0 },
		{ "asl.w 1,d0 overflow", "e340", 0x12344000, 0, 0x2010, 0x12348000, 0x200a, 0 },
		{ "lsl.w 1,d0 carry", "e348", 0x12348000, 0, 0x2000, 0x12340000, 0x2015, 0 },
		{ "asr.w 1,d0", "e240", 0x12348001, 0, 0x2000, 0x1234c000, 0x2019, 0 },
		{ "lsr.w 1,d0", "e248", 0x12348001, 0, 0x2000, 0x12344000, 0x2011, 0 },
		{ "rol.w 1,d0", "e358", 0x12348000, 0, 0x2010, 0x12340001, 0x2011, 0 },
		{ "ror.w 1,d0", "e258", 0x12340001, 0, 0x2010, 0x12348000, 0x2019, 0 },
		{ "roxl.w 1,d0", "e350", 0x12340000, 0, 0x2010, 0x12340001, 0x2000, 0 },
		{ "roxr.w 1,d0", "e250", 0x12340001, 0, 0x2000, 0x12340000, 0x2015, 0 },
		{ "muls.w d1,d0", "c1c1", 0x1234fffe, 3, 0x201f, 0xfffffffa, 0x2018, 0 },
		{ "mulu.w d1,d0", "c0c1", 0xffff, 2, 0x201f, 0x1fffe, 0x2010, 0 },
		{ "divs.w d1,d0", "81c1", 0xfffffff9, 2, 0x201f, 0xfffffffd, 0x2018, 0 },
		{ "divu.w d1,d0", "80c1", 7, 2, 0x201f, 0x00010003, 0x2010, 0 },
		{ "divu.w quotient overflow", "80c1", 0x10000, 1, 0x2010, 0x10000, 0x2012, 0xfff3 },
	};
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cases); i++) {
		m68k_reset(core, cases[i].d0, cases[i].d1, cases[i].sr);
		mu_assert_true(m68k_step(core, cases[i].hex), cases[i].instruction);
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "d0"), cases[i].result, cases[i].instruction);
		ut16 mask = cases[i].mask ? cases[i].mask : UT16_MAX;
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "sr") & mask, cases[i].flags & mask, cases[i].instruction);
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "d1"), cases[i].d1, "source register is preserved");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), 0x100 + strlen(cases[i].hex) / 2, "integer instruction advances PC");
	}
	rz_core_free(core);
	mu_end;
}

static bool test_m68k_data_transfers(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	RzReg *reg = rz_analysis_get_reg(core->analysis);
	m68k_reset(core, 0x8000, 0, 0x201f);
	mu_assert_true(m68k_step(core, "3040"), "movea.w d0,a0");
	mu_assert_eq(rz_reg_getv(reg, "a0"), 0xffff8000, "MOVEA sign extends a word");
	mu_assert_eq(rz_reg_getv(reg, "sr"), 0x201f, "MOVEA preserves SR");
	m68k_reset(core, 0, 0, 0x201f);
	mu_assert_true(m68k_step(core, "41e8fffc"), "lea -4(a0),a0");
	mu_assert_eq(rz_reg_getv(reg, "a0"), 0x3fc, "LEA computes address without loading memory");
	mu_assert_eq(rz_reg_getv(reg, "sr"), 0x201f, "LEA preserves SR");
	m68k_reset(core, 0x12345678, 0, 0x201f);
	mu_assert_true(m68k_step(core, "20c0"), "move.l d0,(a0)+");
	ut8 bytes[4];
	mu_assert_eq(rz_io_nread_at(core->io, 0x400, bytes, sizeof(bytes)), sizeof(bytes), "read stored longword");
	mu_assert_eq(rz_read_be32(bytes), 0x12345678, "MOVE stores big endian");
	mu_assert_eq(rz_reg_getv(reg, "a0"), 0x404, "MOVE postincrement");
	mu_assert_eq(rz_reg_getv(reg, "sr"), 0x2010, "MOVE store flags");
	mu_assert_true(m68k_step(core, "2220"), "move.l -(a0),d1");
	mu_assert_eq(rz_reg_getv(reg, "d1"), 0x12345678, "MOVE loads big endian");
	mu_assert_eq(rz_reg_getv(reg, "a0"), 0x400, "MOVE predecrement");
	m68k_reset(core, 0, 0, 0x201f);
	mu_assert_true(m68k_step(core, "4850"), "pea (a0)");
	mu_assert_eq(rz_reg_getv(reg, "a7"), 0x7fc, "PEA stack delta");
	mu_assert_eq(rz_io_nread_at(core->io, 0x7fc, bytes, sizeof(bytes)), sizeof(bytes), "read pushed effective address");
	mu_assert_eq(rz_read_be32(bytes), 0x400, "PEA pushes address");
	mu_assert_eq(rz_reg_getv(reg, "sr"), 0x201f, "PEA preserves SR");
	m68k_reset(core, 0, 0, 0x201f);
	mu_assert_true(m68k_step(core, "4e50fff8"), "link a0,-8");
	mu_assert_eq(rz_reg_getv(reg, "a0"), 0x7fc, "LINK frame pointer");
	mu_assert_eq(rz_reg_getv(reg, "a7"), 0x7f4, "LINK reserves stack space");
	mu_assert_true(m68k_step(core, "4e58"), "unlk a0");
	mu_assert_eq(rz_reg_getv(reg, "a0"), 0x400, "UNLK restores frame pointer");
	mu_assert_eq(rz_reg_getv(reg, "a7"), 0x800, "UNLK restores stack");
	mu_assert_eq(rz_reg_getv(reg, "sr"), 0x201f, "LINK/UNLK preserve SR");
	rz_core_free(core);
	mu_end;
}

#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
static bool m68k_opex_field(const RzAnalysisOp *op, size_t index, const char *key, const char *expected) {
	rz_return_val_if_fail(op && key && expected, false);
	mu_assert_notnull(op->opex, "operand metadata exists");
	char *text = rz_structured_data_to_json(op->opex);
	char *expected_text = rz_str_dup(expected);
	mu_assert_notnull(text, "operand JSON");
	mu_assert_notnull(expected_text, "expected JSON");
	RzJson *json = rz_json_parse(text);
	RzJson *expected_json = rz_json_parse(expected_text);
	const RzJson *opex = json ? rz_json_get(json, "opex") : NULL;
	const RzJson *operands = opex ? rz_json_get(opex, "operands") : NULL;
	const RzJson *operand = operands ? rz_json_item(operands, index) : NULL;
	const RzJson *field = operand ? operand->children.first : NULL;
	while (field && (!field->key || strcmp(field->key, key))) {
		field = field->next;
	}
	bool matches = field && expected_json && rz_json_eq(field, expected_json);
	if (!matches) {
		fprintf(stderr, "operand %zu %s: expected %s\n", index, key, expected);
	}
	rz_json_free(expected_json);
	rz_json_free(json);
	free(expected_text);
	free(text);
	return matches;
}

static bool test_m68k_coldfire_profiles(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	const RzAsmPlugin *plugin = rz_asm_plugin_current(core->rasm);
	mu_assert_notnull(plugin, "M68K assembler plugin");
	mu_assert_notnull(plugin->get_cpu_desc, "CPU descriptions callback");
	char **descriptions = plugin->get_cpu_desc();
	const char *cpus[] = { "cfv1", "cfv2", "cfv3", "cfv4", "cfv4e", "cfv5", "coldfire" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(cpus); i++) {
		bool listed = false;
		for (size_t j = 0; descriptions[j]; j += 2) {
			if (!strcmp(descriptions[j], cpus[i])) {
				listed = descriptions[j + 1] && *descriptions[j + 1];
				break;
			}
		}
		mu_assert_true(listed, "ColdFire profile has a description");
		mu_assert_true(rz_core_arch_configure(core, "m68k", 32, cpus[i], NULL, NULL), "select ColdFire profile");
		RzAnalysisOp op;
		mu_assert_true(m68k_decode(core, &op, "101f"), "MOVE.B (A7)+,D0 on ColdFire");
		mu_assert_true(m68k_value_mem(op.src[0], "a7", 1, RZ_ANALYSIS_ACC_R), "byte load source");
		rz_analysis_op_fini(&op);
		m68k_reset(core, 0, 0, 0x2010);
		mu_assert_true(m68k_step(core, "101f"), "byte load executes on selected CPU");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "a7"), 0x801, "ColdFire A7 byte increment");
		mu_assert_true(rz_core_arch_configure(core, "m68k", 32, "68020", NULL, NULL), "switch back to classic M68K");
		m68k_reset(core, 0, 0, 0x2010);
		mu_assert_true(m68k_step(core, "101f"), "byte load executes on classic CPU");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "a7"), 0x802, "ColdFire mode does not leak into classic execution");
	}
	rz_core_free(core);
	mu_end;
}

static bool test_m68k_coldfire_values(void) {
	RzCore *core = m68k_core_new("cfv1");
	mu_assert_notnull(core, "ColdFire core");
	RzAnalysisOp op;
	mu_assert_true(m68k_decode(core, &op, "a140"), "MOV3Q on CFv1");
	mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_MOV, "MOV3Q type");
	mu_assert_notnull(op.src[0], "MOV3Q immediate");
	mu_assert_eq(op.src[0]->imm, UT32_MAX, "MOV3Q encodes minus one");
	mu_assert_true(m68k_value_reg(op.dst, "d0", RZ_ANALYSIS_ACC_W), "MOV3Q destination");
	rz_analysis_op_fini(&op);
	const char *unary[] = { "00c0", "02c0", "04c0", "4c80" }; /* BITREV, BYTEREV, FF1, SATS */
	for (size_t i = 0; i < RZ_ARRAY_SIZE(unary); i++) {
		mu_assert_true(m68k_decode(core, &op, unary[i]), "ColdFire unary operation");
		mu_assert_true(m68k_value_reg(op.src[0], "d0", RZ_ANALYSIS_ACC_R), "unary source");
		mu_assert_true(m68k_value_reg(op.dst, "d0", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "unary destination");
		rz_analysis_op_fini(&op);
	}
	const char *casts[] = { "7100", "7180", "7110", "7190" }; /* MVS/MVZ from D0/(A0) */
	for (size_t i = 0; i < RZ_ARRAY_SIZE(casts); i++) {
		mu_assert_true(m68k_decode(core, &op, casts[i]), "ColdFire sign/zero extension");
		mu_assert_eq(op.type, i < 2 ? RZ_ANALYSIS_OP_TYPE_CAST : RZ_ANALYSIS_OP_TYPE_LOAD, "cast or load type");
		mu_assert_eq(op.sign, !(i % 2), "MVS is signed; MVZ is unsigned");
		if (i < 2) {
			mu_assert_true(m68k_value_reg(op.src[0], "d0", RZ_ANALYSIS_ACC_R), "cast source");
		} else {
			mu_assert_true(m68k_value_mem(op.src[0], "a0", 1, RZ_ANALYSIS_ACC_R), "cast memory source");
		}
		mu_assert_true(m68k_value_reg(op.dst, "d0", RZ_ANALYSIS_ACC_W), "cast destination");
		rz_analysis_op_fini(&op);
	}
	mu_assert_true(m68k_decode(core, &op, "40e746fc24d2"), "STRLDSR");
	mu_assert_eq(op.stackptr, -4, "STRLDSR stack delta");
	mu_assert_notnull(op.src[0], "STRLDSR immediate");
	mu_assert_eq(op.src[0]->imm, 0x24d2, "STRLDSR new SR");
	mu_assert_true(m68k_value_reg(op.src[1], "sr", RZ_ANALYSIS_ACC_R), "STRLDSR reads old SR");
	mu_assert_true(m68k_value_reg(op.dst, "sr", RZ_ANALYSIS_ACC_W), "STRLDSR writes SR");
	rz_analysis_op_fini(&op);
	const char *transfers[] = { "fc900000", "fd900000", "fe900000", "ff900000" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(transfers); i++) {
		mu_assert_true(m68k_decode(core, &op, transfers[i]), "coprocessor memory transfer");
		if (i % 2) {
			mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_STORE, "coprocessor store");
			mu_assert_true(m68k_value_mem(op.dst, "a0", 4, RZ_ANALYSIS_ACC_W), "coprocessor store destination");
			mu_assert_null(op.src[0], "coprocessor store has no CPU source");
		} else {
			mu_assert_eq(op.type, RZ_ANALYSIS_OP_TYPE_LOAD, "coprocessor load");
			mu_assert_true(m68k_value_mem(op.src[0], "a0", 4, RZ_ANALYSIS_ACC_R), "coprocessor load source");
			mu_assert_null(op.dst, "coprocessor load has no CPU destination");
		}
		rz_analysis_op_fini(&op);
	}
	mu_assert_true(rz_core_arch_configure(core, "m68k", 32, "cfv4e", NULL, NULL), "select EMAC");
	mu_assert_true(m68k_decode(core, &op, "a1c0"), "MOVCLR");
	mu_assert_true(m68k_value_reg(op.src[0], "acc0", RZ_ANALYSIS_ACC_R), "MOVCLR accumulator source");
	mu_assert_true(m68k_value_reg(op.dst, "d0", RZ_ANALYSIS_ACC_W), "MOVCLR destination");
	rz_analysis_op_fini(&op);

	/* The flags are part of OPEX's numeric interface: lower=1, upper=2,
	 * left=4, right=8, masked memory=16. */
	const char *macs[] = { "a293a2a9", "a293a4a9" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(macs); i++) {
		mu_assert_true(m68k_decode(core, &op, macs[i]), "MAC with register halves, shift, and masked load");
		mu_assert_true(m68k_opex_field(&op, 0, "value", "\"a1\""), "MAC first register");
		mu_assert_true(m68k_opex_field(&op, 0, "flags", "1"), "MAC lower half");
		mu_assert_true(m68k_opex_field(&op, 1, "flags", "2"), "MAC upper half");
		mu_assert_true(m68k_opex_field(&op, 2, "type", "\"shift\""), "MAC shift operand");
		mu_assert_true(m68k_opex_field(&op, 2, "flags", i ? "8" : "4"), "MAC shift direction");
		mu_assert_true(m68k_opex_field(&op, 3, "flags", "16"), "MAC masked memory");
		mu_assert_true(m68k_value_reg(op.dst, "acc0", RZ_ANALYSIS_ACC_R | RZ_ANALYSIS_ACC_W), "MAC accumulator destination");
		rz_analysis_op_fini(&op);
	}
	rz_core_free(core);
	mu_end;
}

#endif

static bool test_m68k_address_metadata(void) {
	RzCore *core = m68k_core_new("68020");
	mu_assert_notnull(core, "M68K core");
	const char *hex[] = { "20380000", "20387fff", "20388000", "2038fffc", "203912345678" };
	const ut32 address[] = { 0, 0x7fff, 0xffff8000, 0xfffffffc, 0x12345678 };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(hex); i++) {
		RzAnalysisOp op;
		mu_assert_true(m68k_decode(core, &op, hex[i]), "absolute MOVE");
		mu_assert_notnull(op.src[0], "absolute memory source");
		mu_assert_true(op.src[0]->absolute, "absolute address");
		mu_assert_eq(op.src[0]->base, address[i], "absolute address value");
		mu_assert_eq(op.src[0]->delta, 0, "absolute address is not counted twice");
		mu_assert_eq(op.src[0]->memref, 4, "absolute memory width");
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
		char expected[16];
		snprintf(expected, sizeof(expected), "%" PFMT32u, address[i]);
		mu_assert_true(m68k_opex_field(&op, 0, "address", expected), "absolute address in OPEX");
#endif
		rz_analysis_op_fini(&op);
	}
	const char *jumps[] = { "4ef8fffc", "4eb8fffc" }; /* JMP/JSR absolute short */
	for (size_t i = 0; i < RZ_ARRAY_SIZE(jumps); i++) {
		RzAnalysisOp op;
		mu_assert_true(m68k_decode(core, &op, jumps[i]), "absolute-short jump/call");
		mu_assert_eq(op.jump, 0xfffffffc, "analysis jump target is sign-extended");
		rz_analysis_op_fini(&op);
		m68k_reset(core, 0, 0, 0x2010);
		mu_assert_true(m68k_step(core, jumps[i]), "absolute-short jump/call executes");
		mu_assert_eq(rz_reg_getv(rz_analysis_get_reg(core->analysis), "pc"), 0xfffffffc, "analysis agrees with execution");
	}
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	const char *indexed[] = { "20300122fff0ffe0", "20300133fffffff0ffffffe0" };
	for (size_t i = 0; i < RZ_ARRAY_SIZE(indexed); i++) {
		RzAnalysisOp op;
		mu_assert_true(m68k_decode(core, &op, indexed[i]), "full-format preindexed MOVE");
		mu_assert_true(m68k_value_mem(op.src[0], "a0", 4, RZ_ANALYSIS_ACC_R), "indexed memory source");
		mu_assert_true(m68k_opex_field(&op, 0, "in_disp", "-16"), "signed base displacement");
		mu_assert_true(m68k_opex_field(&op, 0, "out_disp", "-32"), "signed outer displacement");
		/* Capstone's displacement-size metadata uses 0 for word, 1 for long. */
		mu_assert_true(m68k_opex_field(&op, 0, "in_disp_size", i ? "1" : "0"), "base displacement size");
		mu_assert_true(m68k_opex_field(&op, 0, "out_disp_size", i ? "1" : "0"), "outer displacement size");
		rz_analysis_op_fini(&op);
	}
#endif
	rz_core_free(core);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_m68k_hidden_fpu_destination);
#ifdef RZ_CAPSTONE_HAS_M68K_FP_FORMATS
	mu_run_test(test_m68k_fp_formats);
#endif
	mu_run_test(test_m68k_bcc_conditions);
	mu_run_test(test_m68k_scc_conditions);
	mu_run_test(test_m68k_dbcc_conditions);
	mu_run_test(test_m68k_branch_widths_and_calls);
	mu_run_test(test_m68k_integer_results_and_flags);
	mu_run_test(test_m68k_data_transfers);
#ifdef RZ_CAPSTONE_HAS_M68K_COLDFIRE
	mu_run_test(test_m68k_coldfire_profiles);
	mu_run_test(test_m68k_coldfire_values);
#endif
	mu_run_test(test_m68k_address_metadata);
	return tests_passed != tests_run;
}

mu_main(all_tests)
