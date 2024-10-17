// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_assert.h>
#include <rz_util/rz_strbuf.h>
#include <rz_asm.h>
#include <rz_util.h>
#include <rz_vector.h>
#include <rz_list.h>
#include <minunit.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_str.h>

static RzPrint *setup_print() {
	RzPrint *p = rz_print_new();
	p->cons = rz_cons_new();
	p->cons->context = RZ_NEW0(RzConsContext);
	p->cons->context->color_mode = COLOR_MODE_16;
	rz_cons_pal_init(p->cons->context);
	rz_cons_pal_update_event();
	return p;
}

static RzAsm *setup_bf_asm() {
	RzAsm *a = rz_asm_new();
	rz_asm_setup(a, "bf", 32, false);
	return a;
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

static ut32 hexagon_set_next_pc(RZ_BORROW RzAsm *a) {
	static ut32 pc = 0;
	if (a) {
		rz_asm_set_pc(a, pc);
	}
	ut32 tmp = pc;
	pc += 4;
	return tmp;
}

static RzAnalysis *setup_tms_analysis(const char *cpu) {
	RzAnalysis *a = rz_analysis_new();
	rz_analysis_use(a, "tms320");
	rz_analysis_set_bits(a, 32);
	rz_analysis_set_cpu(a, cpu);
	return a;
}

static RzAsm *setup_tms_asm(const char *cpu) {
	RzAsm *a = rz_asm_new();
	rz_asm_setup(a, "tms320", 32, false);
	rz_asm_set_cpu(a, cpu);
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
	rz_vector_foreach (toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	rz_asm_token_string_free(toks);
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
	rz_vector_foreach (toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	rz_analysis_free(a);
	rz_asm_token_string_free(toks);
	mu_end;
}

static bool test_rz_tokenize_generic_1(void) {
	RzAnalysis *a = setup_hexagon_analysis();
	hexagon_set_next_pc(NULL);
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
	rz_vector_foreach (toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	rz_analysis_free(a);
	rz_asm_token_string_free(toks);
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
	rz_vector_foreach (toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	rz_analysis_free(a);
	rz_asm_token_string_free(toks);
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
	rz_vector_foreach (toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	rz_analysis_free(a);
	rz_asm_token_string_free(toks);
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
	rz_vector_foreach (toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_strbuf_free(asm_str);
	rz_analysis_free(a);
	rz_asm_token_string_free(toks);
	mu_end;
}

static bool test_rz_tokenize_custom_hexagon_0(void) {
	RzAsm *a = setup_hexagon_asm();
	hexagon_set_next_pc(a);

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
	a->cur->disassemble(a, op, buf, sizeof(buf));
	if (!op->asm_toks) {
		mu_fail("NULL check failed.\n");
	}
	mu_assert_eq(rz_vector_len(op->asm_toks->tokens), 7, "Number of generated tokens.");

	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach (op->asm_toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	}

	rz_asm_op_fini(op);
	mu_end;
}

static bool test_rz_tokenize_custom_hexagon_1(void) {
	RzAsm *a = setup_hexagon_asm();
	hexagon_set_next_pc(a);

	const ut8 buf[] = "\x08\x48\x00\x5c"; // \   if (P0.new) jump:nt 0x18
	RzAsmToken tokens[13] = {
		{ .start = 0, .len = 1, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // backslash
		{ .start = 1, .len = 3, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s\s\s
		{ .start = 4, .len = 2, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // if
		{ .start = 6, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 7, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // (
		{ .start = 8, .len = 2, .type = RZ_ASM_TOKEN_REGISTER, .val.number = 0 }, // P0
		{ .start = 10, .len = 4, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // .new
		{ .start = 14, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // )
		{ .start = 15, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 16, .len = 4, .type = RZ_ASM_TOKEN_MNEMONIC, .val.number = 0 }, // jump
		{ .start = 20, .len = 3, .type = RZ_ASM_TOKEN_META, .val.number = 0 }, // :nt
		{ .start = 23, .len = 1, .type = RZ_ASM_TOKEN_SEPARATOR, .val.number = 0 }, // \s
		{ .start = 24, .len = 4, .type = RZ_ASM_TOKEN_NUMBER, .val.number = 0x18 } // 0x18
	};

	RzAsmOp *op = RZ_NEW0(RzAsmOp);
	rz_asm_disassemble(a, op, buf, sizeof(buf));
	if (!op->asm_toks) {
		mu_fail("NULL check failed.\n");
	}
	mu_assert_eq(rz_vector_len(op->asm_toks->tokens), 13, "Number of generated tokens.");
	int i = 0;
	RzAsmToken *it;
	rz_vector_foreach (op->asm_toks->tokens, it) {
		mu_assert_eq(it->start, tokens[i].start, "Token start");
		mu_assert_eq(it->len, tokens[i].len, "Token length");
		mu_assert_eq(it->type, tokens[i].type, "Token type");
		mu_assert_eq(it->val.number, tokens[i].val.number, "Token value");
		++i;
	};

	rz_asm_op_fini(op);
	mu_end;
}

static bool test_rz_colorize_generic_0(void) {
	RzAnalysis *a = setup_arm_analysis(64);
	RzAsm *d = setup_arm_asm(64);
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "ldr x4, [x6, 0x14]" c44041f8
	ut8 buf[] = "\xc4\x40\x41\xf8";

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzAsmParseParam *param = rz_asm_get_parse_param(a->reg, anaop->type);
	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		param, asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[35mldur\x1b[0m\x1b[37m \x1b[0m\x1b[36mx4\x1b[0m\x1b[37m, [\x1b[0m\x1b[36mx6\x1b[0m\x1b[37m, \x1b[0m\x1b[33m0x14\x1b[0m\x1b[37m]\x1b[0m");
	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_parse_param_free(param);
	rz_asm_op_fini(asmop);
	rz_analysis_op_free(anaop);
	rz_asm_free(d);
	rz_analysis_free(a);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
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

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[33madc.w\x1b[0m\x1b[37m \x1b[0m\x1b[36mr8\x1b[0m\x1b[37m, \x1b[0m\x1b[36msb\x1b[0m\x1b[37m, \x1b[0m\x1b[36msl\x1b[0m\x1b[37m, \x1b[0m\x1b[37mlsl\x1b[0m\x1b[37m \x1b[0m\x1b[33m31\x1b[0m");
	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_op_fini(asmop);
	rz_analysis_op_free(anaop);
	rz_asm_free(d);
	rz_analysis_free(a);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
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

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[37mmovabs\x1b[0m\x1b[37m \x1b[0m\x1b[36mrax\x1b[0m\x1b[37m, \x1b[0m\x1b[33m0x1122334455667788\x1b[0m");
	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_op_fini(asmop);
	rz_analysis_op_free(anaop);
	rz_asm_free(d);
	rz_analysis_free(a);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
	mu_end;
}

static bool test_rz_colorize_generic_3(void) {
	RzAnalysis *a = setup_tms_analysis("c55x+");
	RzAsm *d = setup_tms_asm("c55x+");
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "mov ac0.l, *ar2 || mov *(ar1+t0b) << t3, ac1" - 395102a0b411014033
	ut8 buf[] = "\x39\x51\x02\xa0\xb4\x11\x01\x40\x33";
	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[37mmov\x1b[0m\x1b[37m \x1b[0m\x1b[36mac0\x1b[0m\x1b[37m.\x1b[0m\x1b[37ml\x1b[0m\x1b[37m, \x1b[0m\x1b[37m*\x1b[0m\x1b[36mar2\x1b[0m\x1b[37m |\x1b[0m\x1b[37m|\x1b[0m\x1b[37m \x1b[0m\x1b[37mmov\x1b[0m\x1b[37m \x1b[0m\x1b[37m*\x1b[0m\x1b[37m(\x1b[0m\x1b[36mar1\x1b[0m\x1b[37m+\x1b[0m\x1b[37mt0b\x1b[0m\x1b[37m) \x1b[0m\x1b[37m<<\x1b[0m\x1b[37m \x1b[0m\x1b[36mt3\x1b[0m\x1b[37m, \x1b[0m\x1b[36mac1\x1b[0m");

	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_op_fini(asmop);
	rz_analysis_op_free(anaop);
	rz_asm_free(d);
	rz_analysis_free(a);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
	mu_end;
}

static bool test_rz_colorize_generic_4(void) {
	RzAnalysis *a = setup_tms_analysis("c55x+");
	RzAsm *d = setup_tms_asm("c55x+");
	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "mov ac0.l, *ar2 || mov *(ar1+t0b) << t3, ac1" - 395102a0b411014033
	ut8 buf[] = "\x39\x51\x02\xa0\xb4\x11\x01\x40\x33";
	rz_asm_disassemble(d, asmop, buf, sizeof(buf));
	rz_analysis_op(a, anaop, 0x0, buf, sizeof(buf), RZ_ANALYSIS_OP_MASK_ALL);

	RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop->buf_asm, p,
		rz_asm_get_parse_param(a->reg, anaop->type), asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[37mmov\x1b[0m\x1b[37m \x1b[0m\x1b[36mac0\x1b[0m\x1b[37m.\x1b[0m\x1b[37ml\x1b[0m\x1b[37m, \x1b[0m\x1b[37m*\x1b[0m\x1b[36mar2\x1b[0m\x1b[37m |\x1b[0m\x1b[37m|\x1b[0m\x1b[37m \x1b[0m\x1b[37mmov\x1b[0m\x1b[37m \x1b[0m\x1b[37m*\x1b[0m\x1b[37m(\x1b[0m\x1b[36mar1\x1b[0m\x1b[37m+\x1b[0m\x1b[37mt0b\x1b[0m\x1b[37m) \x1b[0m\x1b[37m<<\x1b[0m\x1b[37m \x1b[0m\x1b[36mt3\x1b[0m\x1b[37m, \x1b[0m\x1b[36mac1\x1b[0m");

	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_op_fini(asmop);
	rz_analysis_op_free(anaop);
	rz_asm_free(d);
	rz_analysis_free(a);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
	mu_end;
}

static bool test_rz_colorize_custom_hexagon_0(void) {
	RzAsm *d = setup_hexagon_asm();
	struct dummy_rz_core_t core = { 0 };
	core.rasm = d;
	d->core = &core;

	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	RzAnalysisOp *anaop = rz_analysis_op_new();
	// "?   if (P0.new) jump:nt 0x18
	ut8 buf[] = "\x08\xe8\x00\x5c";

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));

	RzStrBuf *colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[90m?\x1b[0m\x1b[37m   \x1b[0m\x1b[32mif\x1b[0m\x1b[37m \x1b[0m\x1b[37m(\x1b[0m\x1b[36mP0\x1b[0m\x1b[90m.new\x1b[0m\x1b[37m)\x1b[0m\x1b[37m \x1b[0m\x1b[32mjump\x1b[0m\x1b[90m:nt\x1b[0m\x1b[37m \x1b[0m\x1b[33m0x210\x1b[0m");
	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_op_fini(asmop);
	rz_analysis_op_free(anaop);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
	mu_end;
}

static bool test_rz_colorize_custom_hexagon_1(void) {
	RzAsm *d = setup_hexagon_asm();
	struct dummy_rz_core_t core = { 0 };
	core.rasm = d;
	d->core = &core;

	RzPrint *p = setup_print();
	RzAsmOp *asmop = rz_asm_op_new();
	// "[   LR:FP = dealloc_return(FP):raw" 1ec01e96
	ut8 buf[] = "\x1e\xc0\x1e\x96";

	rz_asm_disassemble(d, asmop, buf, sizeof(buf));

	RzStrBuf *colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);

	RzStrBuf *expected = rz_strbuf_new("\x1b[90m?\x1b[0m\x1b[37m   \x1b[0m\x1b[36mLR\x1b[0m\x1b[37m:\x1b[0m\x1b[36mFP\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[31mdealloc_return\x1b[0m\x1b[37m(\x1b[0m\x1b[36mFP\x1b[0m\x1b[37m)\x1b[0m\x1b[90m:raw\x1b[0m");
	char err_msg[2048];
	snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
	mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);

	rz_asm_op_fini(asmop);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	rz_strbuf_free(expected);
	rz_strbuf_free(colored_asm);
	mu_end;
}

static bool test_rz_colorize_custom_hexagon_2(void) {
	RzAsm *d = setup_hexagon_asm();
	d->utf8 = true;
	struct dummy_rz_core_t core = { 0 };
	core.rasm = d;
	d->core = &core;

	RzPrint *p = setup_print();
	RzAsmOp *asmop;
	RzStrBuf *colored_asm;
	RzStrBuf *expected;
	char err_msg[2048];
	// ?   memd(R0++#0x8) = R19:18
	// ┌   R7:6 = valignb(R13:12,R11:10,P2)
	// │   P0 = cmp.gtu(R4,##0x1)
	// │   R11:10 = memd(R1++#0x8)
	// └   memd(R0++#0x8) = R7:6     ∎ endloop0
	ut8 buf[] = "\x08\xd2\xc0\xab\x46\x8c\x0a\xc2\x20\x40\x84\x75\x2a\x40\xc1\x9b\x08\xc6\xc0\xab";
	const char *expected_str[] = {
		"\x1b[90m?\x1b[0m\x1b[37m   \x1b[0m\x1b[37mmemd\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR0\x1b[0m\x1b[37m++\x1b[0m\x1b[90m#\x1b[0m\x1b[33m0x8\x1b[0m\x1b[37m)\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[36mR19:18\x1b[0m",
		"\x1b[90m┌\x1b[0m\x1b[37m   \x1b[0m\x1b[36mR7:6\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[37mvalignb\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR13:12\x1b[0m\x1b[37m,\x1b[0m\x1b[36mR11:10\x1b[0m\x1b[37m,\x1b[0m\x1b[36mP2\x1b[0m\x1b[37m)\x1b[0m",
		"\x1b[90m│\x1b[0m\x1b[37m   \x1b[0m\x1b[36mP0\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[37mcmp\x1b[0m\x1b[37m.\x1b[0m\x1b[37mgtu\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR4\x1b[0m\x1b[37m,\x1b[0m\x1b[90m##\x1b[0m\x1b[33m0x1\x1b[0m\x1b[37m)\x1b[0m",
		"\x1b[90m│\x1b[0m\x1b[37m   \x1b[0m\x1b[36mR11:10\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[37mmemd\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR1\x1b[0m\x1b[37m++\x1b[0m\x1b[90m#\x1b[0m\x1b[33m0x8\x1b[0m\x1b[37m)\x1b[0m",
		"\x1b[90m└\x1b[0m\x1b[37m   \x1b[0m\x1b[32mmemd\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR0\x1b[0m\x1b[37m++\x1b[0m\x1b[90m#\x1b[0m\x1b[33m0x8\x1b[0m\x1b[37m)\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[36mR7:6\x1b[0m\x1b[37m     \x1b[0m\x1b[90m∎ endloop0\x1b[0m"
	};

	for (int i = 0; i < 0x14; i += 4) {
		asmop = rz_asm_op_new();
		rz_asm_set_pc(d, i);
		rz_asm_disassemble(d, asmop, buf + i, 4);
		colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);
		expected = rz_strbuf_new(expected_str[i / 4]);
		snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
		mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);
		rz_strbuf_free(colored_asm);
		rz_strbuf_free(expected);
	}

	rz_asm_op_fini(asmop);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	mu_end;
}

static bool test_rz_colorize_custom_hexagon_3(void) {
	RzAsm *d = setup_hexagon_asm();
	d->utf8 = true;
	struct dummy_rz_core_t core = { 0 };
	core.rasm = d;
	d->core = &core;

	RzPrint *p = setup_print();
	RzAsmOp *asmop;
	RzStrBuf *colored_asm;
	RzStrBuf *expected;
	char err_msg[2048];
	// {
	// 	r25 = convert_df2w(r1:0):chop
	// 	if (!p1) jump:nt 0x24
	// }
	// {
	// 	r3:2 = convert_w2df(r25)
	// 	r4 = p1
	// }
	ut8 buf[] = "\x39\x40\xe0\x88\x12\xc1\x20\x5c\x42\x40\x99\x84\x04\xc0\x41\x89";
	const char *expected_str[] = {
		"\x1b[90m?\x1b[0m\x1b[37m   \x1b[0m\x1b[36mR25\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[37mconvert_df2w\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR1:0\x1b[0m\x1b[37m)\x1b[0m\x1b[37m:\x1b[0m\x1b[37mchop\x1b[0m",
		"\x1b[90m?\x1b[0m\x1b[37m   \x1b[0m\x1b[32mif\x1b[0m\x1b[37m \x1b[0m\x1b[37m(\x1b[0m\x1b[37m!\x1b[0m\x1b[36mP1\x1b[0m\x1b[37m)\x1b[0m\x1b[37m \x1b[0m\x1b[32mjump\x1b[0m\x1b[90m:nt\x1b[0m\x1b[37m \x1b[0m\x1b[33m0x24\x1b[0m",
		"\x1b[90m┌\x1b[0m\x1b[37m   \x1b[0m\x1b[36mR3:2\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[37mconvert_W2df\x1b[0m\x1b[37m(\x1b[0m\x1b[36mR25\x1b[0m\x1b[37m)\x1b[0m",
		"\x1b[90m└\x1b[0m\x1b[37m   \x1b[0m\x1b[36mR4\x1b[0m\x1b[37m \x1b[0m\x1b[37m=\x1b[0m\x1b[37m \x1b[0m\x1b[36mP1\x1b[0m",

	};

	for (int i = 0; i < 0x10; i += 4) {
		asmop = rz_asm_op_new();
		rz_asm_set_pc(d, i);
		rz_asm_disassemble(d, asmop, buf + i, 4);

		colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);
		expected = rz_strbuf_new(expected_str[i / 4]);
		snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
		mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);
		rz_strbuf_free(colored_asm);
		rz_strbuf_free(expected);
	}

	rz_asm_op_fini(asmop);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
	mu_end;
}

static bool test_rz_tokenize_custom_bf_0(void) {
	RzAsm *a = setup_bf_asm();

	// nop
	// while [ptr]
	// inc [ptr]
	// dec [ptr]
	// in [ptr]
	// dec ptr
	// inc ptr
	// out [ptr]
	// loop
	// trap
	const ut8 buf[] = "\x07[+-,<>.]\xff";
	const char *expected_str[] = {
		"\x1b[34mnop\x1b[0m",
		"\x1b[32mwhile\x1b[0m\x1b[37m \x1b[0m\x1b[37m[\x1b[0m\x1b[36mptr\x1b[0m\x1b[37m]\x1b[0m",
		"\x1b[33minc\x1b[0m\x1b[37m \x1b[0m\x1b[37m[\x1b[0m\x1b[36mptr\x1b[0m\x1b[37m]\x1b[0m",
		"\x1b[33mdec\x1b[0m\x1b[37m \x1b[0m\x1b[37m[\x1b[0m\x1b[36mptr\x1b[0m\x1b[37m]\x1b[0m",
		"\x1b[1;95min\x1b[0m\x1b[37m \x1b[0m\x1b[37m[\x1b[0m\x1b[36mptr\x1b[0m\x1b[37m]\x1b[0m",
		"\x1b[33mdec\x1b[0m\x1b[37m \x1b[0m\x1b[36mptr\x1b[0m",
		"\x1b[33minc\x1b[0m\x1b[37m \x1b[0m\x1b[36mptr\x1b[0m",
		"\x1b[35mout\x1b[0m\x1b[37m \x1b[0m\x1b[37m[\x1b[0m\x1b[36mptr\x1b[0m\x1b[37m]\x1b[0m",
		"\x1b[32mloop\x1b[0m",
		"\x1b[1;91mtrap\x1b[0m",

	};

	RzPrint *p = setup_print();
	char err_msg[2048];
	for (int i = 0; i < sizeof(buf) - 1; i++) {
		RzAsmOp *asmop = rz_asm_op_new();
		rz_asm_disassemble(a, asmop, buf + i, 1);
		RzStrBuf *colored_asm = rz_print_colorize_asm_str(p, asmop->asm_toks);
		RzStrBuf *expected = rz_strbuf_new(expected_str[i]);
		snprintf(err_msg, sizeof(err_msg), "Colors of \"%s\" are incorrect. Should be \"%s\"\n.", rz_strbuf_get(colored_asm), rz_strbuf_get(expected));
		mu_assert_true(rz_strbuf_equals(colored_asm, expected), err_msg);
		rz_asm_op_fini(asmop);
		rz_strbuf_free(expected);
		rz_strbuf_free(colored_asm);
	}

	rz_asm_free(a);
	rz_cons_context_free(p->cons->context);
	rz_print_free(p);
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
	mu_run_test(test_rz_colorize_generic_3);
	mu_run_test(test_rz_colorize_generic_4);
	mu_run_test(test_rz_colorize_custom_hexagon_0);
	mu_run_test(test_rz_colorize_custom_hexagon_1);
	mu_run_test(test_rz_colorize_custom_hexagon_2);
	mu_run_test(test_rz_colorize_custom_hexagon_3);
	mu_run_test(test_rz_tokenize_custom_bf_0);

	return tests_passed != tests_run;
}

mu_main(all_tests)
