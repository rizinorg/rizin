// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_util/rz_strbuf.h"
#include <rz_asm.h>
#include <rz_util.h>
#include <rz_vector.h>
#include <rz_list.h>
#include <config.h>
#include <minunit.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_str.h>

static RzPrint *setup_print() {
	RzPrint *p = rz_print_new();
	p->cons = rz_cons_new();
	p->cons->context = RZ_NEW0(RzConsContext);
	p->cons->context->color_mode = COLOR_MODE_16M;
	rz_cons_pal_init(p->cons->context);
	rz_cons_pal_update_event();
	return p;
}

static RzAsm *setup_arm_asm(ut32 bits) {
	RzAsm *a = rz_asm_new();
	rz_asm_setup(a, "arm", bits, false);
	return a;
}

static RzAsm *setup_x86_asm(ut32 bits) {
	RzAsm *a = rz_asm_new();
	rz_asm_setup(a, "x86", bits, false);
	return a;
}

static RzAnalysis *setup_x86_analysis(ut32 bits) {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "x86");
	rz_analysis_set_bits(a, bits);
	return a;
}

static RzAnalysis *setup_arm_analysis(ut32 bits) {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "arm");
	rz_analysis_set_bits(a, bits);
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
	rz_asm_setup(a, "hexagon", 32, false);
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
	RzAnalysis *a = setup_x86_analysis(32);
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
	RzAnalysis *a = setup_x86_analysis(32);
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
	RzAnalysis *a = setup_x86_analysis(32);
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

static bool test_rz_tokenize_generic_4(void) {
	RzAnalysis *a = setup_arm_analysis(16);
	RzStrBuf *asm_str = rz_strbuf_new("adc.w r8, sb, sl, ror 31");
	RzAsmToken tokens[11] = {
		{ .start = 0, .len = 5, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 },
		{ .start = 5, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 6, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 },
		{ .start = 8, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 10, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 },
		{ .start = 12, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 14, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 },
		{ .start = 16, .len = 2, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 18, .len = 3, .type = RZ_ASM_TOKEN_UNKNOWN, .val.number = 0 },
		{ .start = 21, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 },
		{ .start = 22, .len = 2, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 31 }
	};
	RzAsmParseParam param = { .reg_sets = a->reg->regset };
	RzAsmTokenString *toks = rz_asm_tokenize_asm_string(asm_str, &param);

	mu_assert_eq(rz_vector_len(toks->tokens), 11, "Number of generated tokens");

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
	if (!op->asm_toks) {
		mu_fail("NULL check failed.\n");
	}
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
	if (!op->asm_toks) {
		mu_fail("NULL check failed.\n");
	}
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

static bool test_rz_colorize_generic_0(void) {
	RzAnalysis *a = setup_arm_analysis(64);
	RzAsm *d = setup_arm_asm(64);
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "ldr w2, [x8, -256]" 020150b8
	ut8 buf[] = "\x02\x01\x50\xb8";

	rz_asm_disassemble(d, asmop, buf, 4);
	rz_analysis_op(a, anaop, 0x0, buf, 4, RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[38;2;136;23;152mldur\x1b[0m\x1b[38;2;204;204;204m"
					   " \x1b[0m\x1b[38;2;58;150;221mw2\x1b[0m\x1b[38;2;204;204;204m, [\x1b[0m\x1b[38;2;58;150;221mx8\x1b[0m\x1b[38;2;204;204;204m,"
					   " \x1b[0m\x1b[38;2;204;204;204m-\x1b[0m\x1b[38;2;193;156;0m0x100\x1b[0m\x1b[38;2;204;204;204m]\x1b[0m");
	char err_msg[1024];
	sprintf(err_msg, "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	mu_end;
}

static bool test_rz_colorize_generic_1(void) {
	RzAnalysis *a = setup_arm_analysis(16);
	RzAsm *d = setup_arm_asm(16);
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "adc.w r8, sb, sl, lsl 31" 49ebca78
	ut8 buf[] = "\x49\xeb\xca\x78";

	rz_asm_disassemble(d, asmop, buf, 4);
	rz_analysis_op(a, anaop, 0x0, buf, 4, RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[38;2;193;156;0madc.w\x1b[0m\x1b[38;2;204;204;204m"
					   " \x1b[0m\x1b[38;2;58;150;221mr8\x1b[0m\x1b[38;2;204;204;204m, \x1b[0m\x1b[38;2;58;150;221msb\x1b[0m\x1b[38;2;204;204;204m,"
					   " \x1b[0m\x1b[38;2;58;150;221msl\x1b[0m\x1b[38;2;204;204;204m, \x1b[0m\x1b[38;2;204;204;204mlsl\x1b[0m\x1b[38;2;204;204;204m"
					   " \x1b[0m\x1b[38;2;193;156;0m31\x1b[0m");
	char err_msg[1024];
	sprintf(err_msg, "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	mu_end;
}

static bool test_rz_colorize_generic_2(void) {
	RzAnalysis *a = setup_x86_analysis(64);
	RzAsm *d = setup_x86_asm(64);
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "movabs rax, 0x1122334455667788" 48b88877665544332211
	ut8 buf[] = "\x48\xb8\x88\x77\x66\x55\x44\x33\x22\x11";

	rz_asm_disassemble(d, asmop, buf, 10);
	rz_analysis_op(a, anaop, 0x0, buf, 10, RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[38;2;204;204;204mmovabs\x1b[0m\x1b[38;2;204;204;204m"
					   " \x1b[0m\x1b[38;2;58;150;221mrax\x1b[0m\x1b[38;2;204;204;204m, \x1b[0m\x1b[38;2;193;156;0m0x1122334455667788\x1b[0m");
	char err_msg[1024];
	sprintf(err_msg, "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	mu_end;
}

static bool test_rz_colorize_custom_hexagon_0(void) {
	RzAnalysis *a = setup_hexagon_analysis();
	RzAsm *d = setup_hexagon_asm();
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "?   if (cmp.eq(<err>.new,#0x0)) jump:nt 0x40" 20c00224
	ut8 buf[] = "\x20\xc0\x02\x24";

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[38;2;118;118;118m?\x1b[0m\x1b[38;2;204;204;204m"
					   "   \x1b[0m\x1b[38;2;19;161;14mif\x1b[0m\x1b[38;2;204;204;204m \x1b[0m\x1b[38;2;204;204;204m("
					   "\x1b[0m\x1b[38;2;19;161;14mcmp\x1b[0m\x1b[38;2;204;204;204m.\x1b[0m\x1b[38;2;19;161;14meq"
					   "\x1b[0m\x1b[38;2;204;204;204m(\x1b[0m\x1b[38;2;118;118;118m<err>\x1b[0m\x1b[38;2;118;118;118m.new"
					   "\x1b[0m\x1b[38;2;204;204;204m,\x1b[0m\x1b[38;2;118;118;118m#\x1b[0m\x1b[38;2;193;156;0m0x0\x1b[0m"
					   "\x1b[38;2;204;204;204m)\x1b[0m\x1b[38;2;204;204;204m)\x1b[0m\x1b[38;2;204;204;204m \x1b[0m\x1b[38;2;19;161;14mjump"
					   "\x1b[0m\x1b[38;2;118;118;118m:nt\x1b[0m\x1b[38;2;204;204;204m \x1b[0m\x1b[38;2;193;156;0m0x40\x1b[0m");
	char err_msg[1024];
	sprintf(err_msg, "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	mu_end;
}

static bool test_rz_colorize_custom_hexagon_1(void) {
	RzAnalysis *a = setup_hexagon_analysis();
	RzAsm *d = setup_hexagon_asm();
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "?   LR:FP = dealloc_return(FP):raw" 1ec01e96
	ut8 buf[] = "\x1e\xc0\x1e\x96";

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[38;2;118;118;118m?\x1b[0m\x1b[38;2;204;204;204m"
					   "   \x1b[0m\x1b[38;2;58;150;221mLR\x1b[0m\x1b[38;2;204;204;204m:\x1b[0m\x1b[38;2;58;150;221mFP"
					   "\x1b[0m\x1b[38;2;204;204;204m \x1b[0m\x1b[38;2;204;204;204m=\x1b[0m\x1b[38;2;204;204;204m"
					   " \x1b[0m\x1b[38;2;197;15;31mdealloc_return\x1b[0m\x1b[38;2;204;204;204m(\x1b[0m\x1b[38;2;58;150;221mFP"
					   "\x1b[0m\x1b[38;2;204;204;204m)\x1b[0m\x1b[38;2;118;118;118m:raw\x1b[0m");
	char err_msg[1024];
	sprintf(err_msg, "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	mu_end;
}

static int all_tests() {
	mu_run_test(test_rz_tokenize_generic_0_no_reg_profile);
	mu_run_test(test_rz_tokenize_generic_0);
	mu_run_test(test_rz_tokenize_generic_1);
	mu_run_test(test_rz_tokenize_generic_2);
	mu_run_test(test_rz_tokenize_generic_3);
	mu_run_test(test_rz_tokenize_generic_4);
	mu_run_test(test_rz_tokenize_custom_hexagon_0);
	mu_run_test(test_rz_tokenize_custom_hexagon_1);
	mu_run_test(test_rz_colorize_generic_0);
	mu_run_test(test_rz_colorize_generic_1);
	mu_run_test(test_rz_colorize_generic_2);
	mu_run_test(test_rz_colorize_custom_hexagon_0);
	mu_run_test(test_rz_colorize_custom_hexagon_1);

	return tests_passed != tests_run;
}

mu_main(all_tests)