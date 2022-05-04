// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_util.h>
#include <rz_vector.h>
#include <rz_list.h>
#include "config.h"
#include "minunit.h"
#include "rz_analysis.h"
#include "rz_util/rz_print.h"
#include "rz_util/rz_str.h"

static RzAnalysis *setup_x86_analysis() {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "x86");
	rz_analysis_set_bits(a, 32);
	return a;
}

static RzAnalysis *setup_hexagon_analysis() {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "hexagon");
	rz_analysis_set_bits(a, 32);
	return a;
}

static RzAsm *setup_hexagon_asm() {
	RzAsm *a = rz_asm_new();
	rz_asm_use(a, "hexagon");
	rz_asm_set_bits(a, 32);
	return a;
}

static bool test_rz_tokenize_generic_0_no_reg_profile(void) {
	RzStrBuf *asm_str = rz_strbuf_new("mov al, 0x11");
	RzAsmToken tokens[6] = {
		{ .start = 0, .len = 3, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 },
		{ .start = 3, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 4, .len = 2, .type = RZ_ASM_TOKEN_UNKNOWN, .val.number = 0 },
		{ .start = 6, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 8, .len = 4, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 17 }
	};
	RzAsmTokenString *toks = rz_asm_tokenize_asm_string(asm_str, NULL);

	mu_assert_eq(rz_vector_len(toks->tokens), 5, "Number of generated tokens");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	mu_end;
}

static bool test_rz_tokenize_generic_0(void) {
	RzAnalysis *a = setup_x86_analysis();
	RzStrBuf *asm_str = rz_strbuf_new("mov al, 0x11");
	RzAsmToken tokens[6] = {
		{ .start = 0, .len = 3, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 },
		{ .start = 3, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 4, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 },
		{ .start = 6, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 8, .len = 4, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 17 }
	};
	RzAsmParseParam param = { .reg_sets = a->reg->regset };
	RzAsmTokenString *toks = rz_asm_tokenize_asm_string(asm_str, &param);

	mu_assert_eq(rz_vector_len(toks->tokens), 5, "Number of generated tokens");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	mu_end;
}

static bool test_rz_tokenize_generic_1(void) {
	RzAnalysis *a = setup_hexagon_analysis();
	RzStrBuf *asm_str = rz_strbuf_new("if (!P0) R5:4 = memd(R0+Q2<<#0x1)");
	RzAsmToken tokens[20] = {
		{ .start = 0, .len = 2, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // if
		{ .start = 2, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s(
		{ .start = 4, .len = 1, .type = RZ_ASM_TOKEN_OPERATOR, .val.number = 0 }, // !
		{ .start = 5, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 }, // P0
		{ .start = 7, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // )\s
		{ .start = 9, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 }, // R5
		{ .start = 11, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // :
		{ .start = 12, .len = 1, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 4 }, // 4
		{ .start = 13, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 14, .len = 1, .type = RZ_ASM_TOKEN_OPERATOR, .val.number = 0 }, // =
		{ .start = 15, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 16, .len = 4, .type = RZ_ASM_TOKEN_UNKNOWN, .val.number = 0 }, // memd
		{ .start = 20, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // (
		{ .start = 21, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 }, // R0
		{ .start = 23, .len = 1, .type = RZ_ASM_TOKEN_OPERATOR, .val.number = 0 }, // +
		{ .start = 24, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 }, // Q2
		{ .start = 26, .len = 2, .type = RZ_ASM_TOKEN_OPERATOR, .val.number = 0 }, // <<
		{ .start = 28, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // #
		{ .start = 29, .len = 3, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 1 }, // 0x1
		{ .start = 32, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 } // )
	};
	RzAsmParseParam param = { .reg_sets = a->reg->regset };
	RzAsmTokenString *toks = rz_asm_tokenize_asm_string(asm_str, &param);

	mu_assert_eq(rz_vector_len(toks->tokens), 20, "Number of generated tokens");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	mu_end;
}

static bool test_rz_tokenize_generic_2(void) {
	RzAnalysis *a = setup_x86_analysis();
	RzStrBuf *asm_str = rz_strbuf_new("mov ip, 🍍");
	RzAsmToken tokens[5] = {
		{ .start = 0, .len = 3, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 },
		{ .start = 3, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 4, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 },
		{ .start = 6, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 8, .len = 4, .type = RZ_ASM_TOKEN_UNKNOWN, .val.number = 0 }
	};
	RzAsmParseParam param = { .reg_sets = a->reg->regset };
	RzAsmTokenString *toks = rz_asm_tokenize_asm_string(asm_str, &param);

	mu_assert_eq(rz_vector_len(toks->tokens), 5, "Number generated tokens");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	mu_end;
}

static bool test_rz_tokenize_generic_3(void) {
	RzAnalysis *a = setup_x86_analysis();
	RzStrBuf *asm_str = rz_strbuf_new("mov eax, 0xffffffff");
	RzAsmToken tokens[6] = {
		{ .start = 0, .len = 3, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 },
		{ .start = 3, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 4, .len = 3, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 },
		{ .start = 7, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 9, .len = 10, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 0xffffffff }
	};
	RzAsmParseParam param = { .reg_sets = a->reg->regset };
	RzAsmTokenString *toks = rz_asm_tokenize_asm_string(asm_str, &param);

	mu_assert_eq(rz_vector_len(toks->tokens), 5, "Number of generated tokens");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	mu_end;
}

static bool test_rz_tokenize_custom_hexagon_0(void) {
	RzAsm *a = setup_hexagon_asm();
	const ut8 buf[] = "\x0c\xc0\x00\x54"; // "[   trap0(#0x3)"
	RzAsmToken tokens[7] = {
		{ .start = 0, .len = 1, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // [
		{ .start = 1, .len = 3, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s\s\s
		{ .start = 4, .len = 5, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // trap0
		{ .start = 9, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // (
		{ .start = 10, .len = 1, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // #
		{ .start = 11, .len = 3, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 3 }, // 0x3
		{ .start = 14, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 } // )
	};
	RzAsmOp *op = RZ_NEW0(RzAsmOp);
	a->cur->disassemble(a, op, buf, 4);

	mu_assert_eq(rz_vector_len(op->asm_toks->tokens), 7, "Number of generated tokens.");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(op->asm_toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	mu_end;
}

static bool test_rz_tokenize_custom_hexagon_1(void) {
	RzAsm *a = setup_hexagon_asm();

	const ut8 buf[] = "\x50\xc7\x14\x24"; // [       if (cmp.eq(<err>.new,#0x7)) jump:nt 0x2a4
	RzAsmToken tokens[21] = {
		{ .start = 0, .len = 1, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // │
		{ .start = 1, .len = 3, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s\s\s
		{ .start = 4, .len = 2, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // if
		{ .start = 6, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 7, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // (
		{ .start = 8, .len = 3, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // cmp
		{ .start = 11, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // .
		{ .start = 12, .len = 2, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // eq
		{ .start = 14, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // (
		{ .start = 15, .len = 5, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // <err>
		{ .start = 20, .len = 4, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // .new
		{ .start = 24, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // ,
		{ .start = 25, .len = 1, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // #
		{ .start = 26, .len = 3, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 7 }, // 0x7
		{ .start = 29, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // )
		{ .start = 30, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // )
		{ .start = 31, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 32, .len = 4, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // jump
		{ .start = 36, .len = 3, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // :nt
		{ .start = 39, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 40, .len = 5, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 0x2a4 } // 0x2a4
	};

	RzAsmOp *op = RZ_NEW0(RzAsmOp);
	a->pc += 4;
	a->cur->disassemble(a, op, buf, 4);

	mu_assert_eq(rz_vector_len(op->asm_toks->tokens), 21, "Number of generated tokens.");
	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach(op->asm_toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	};

	mu_end;
}

// Generic
//  - Type recognition
//     trap0, mov, if(P0),
//  - numbers strings -> value
//     0x0 and 0. Hex number 64bit + >64bit, decimal number
// Custom
//  - Type recognition.
//  - number strings -> value
//  - Ambiguities with numbers in mnemonics (trap0 etc.)
// Color
//  - Color in ambiguities with numbers in mnemonics (trap0 etc.)
//  - General coloring of numbers.
// UTF8 tests

static int all_tests() {
	mu_run_test(test_rz_tokenize_generic_0_no_reg_profile);
	mu_run_test(test_rz_tokenize_generic_0);
	mu_run_test(test_rz_tokenize_generic_1);
	mu_run_test(test_rz_tokenize_generic_2);
	mu_run_test(test_rz_tokenize_generic_3);
	mu_run_test(test_rz_tokenize_custom_hexagon_0);
	mu_run_test(test_rz_tokenize_custom_hexagon_1);

	return tests_passed != tests_run;
}

mu_main(all_tests)