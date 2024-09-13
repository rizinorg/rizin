// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

// https://www.renesas.com/us/en/doc/products/mpumcu/doc/v850/r01us0037ej0100_v850e2.pdf

#include "parse_helper.h"

static RzList /*<char *>*/ *v850_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar v850_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "2 += 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addi", "3 = 2 + 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "3 = 2 & 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("andi", "3 = 2 & 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clr1", "2 &= ~(#1 << 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmov", "4 == 1 ? 2 : 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp", "2 == 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("di", "disable-interrupts"),
	RZ_PSEUDO_DEFINE_GRAMMAR("divh", "2 /= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("divh", "3 = 2 / 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ei", "enable-interrupts"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jarl", "call 1 # 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jmp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jr", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld.b", "3 = (byte) *(2 + 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld.bu", "3 = (unsigned byte) *(2 + 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld.h", "3 = (Zhalf) *(2 + 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld.hu", "3 = (unsigned half) *(2 + 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld.w", "3 = (word) *(2 + 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldsr", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movea", "3 = 1 & 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movhi", "3 = (1 << XX) + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul", "3 = 2 * 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mulf.s", "3 = 2 * 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mulh", "2 *= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("not", "2 = ~1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "3 = 2 | 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ori", "3 = 2 | 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("reti", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("set1", "2 |= (#1 << 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shl", "2 <<= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shr", "2 >>= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sld.b", "2 = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sld.h", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sld.w", "2 = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sst.b", "2 = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sst.h", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sst.w", "2 = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("st.b", "*(3 + 2) = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("st.h", "*(3 + 2) = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("st.w", "*(3 + 2) = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stsr", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "2 -= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tst", "2 == 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tst1", "2 == 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor", "2 ^= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xori", "3 = 1 ^ 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("zxb", "1 = 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("zxh", "1 = 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("zxw", "1 = 0"),
};

static const RzPseudoReplace v850_replace[] = {
	RZ_PSEUDO_DEFINE_REPLACE(" + 0)", ")", 0),
	RZ_PSEUDO_DEFINE_REPLACE("+ -", "- ", 1),
	RZ_PSEUDO_DEFINE_REPLACE(",", "", 1),
};

static const RzPseudoConfig v850_config = RZ_PSEUDO_DEFINE_CONFIG_NO_DIRECT(v850_lexicon, v850_replace, 4, v850_tokenize);

static const char *v850_short_op[] = {
	"and",
	"or",
};

RzList /*<char *>*/ *v850_tokenize(const char *assembly, size_t length) {
	size_t i, p;
	char *buf = NULL;
	bool insert_zero = false;
	RzList *tokens = NULL;

	buf = rz_str_ndup(assembly, length);
	if (!buf) {
		return NULL;
	}

	for (i = 0, p = 0; p < length; ++i, ++p) {
		if (buf[p] == ',') {
			p++;
		} else if (buf[p] == '[') {
			buf[p] = ' ';
			if (!IS_HEXCHAR(buf[p - 1])) {
				p++;
				insert_zero = true;
			}
		} else if (buf[p] == ']') {
			buf[p] = ' ';
			if (buf[p + 1] == ',') {
				p++;
			}
		}
		if (p > i) {
			buf[i] = buf[p];
		}
	}
	buf[i] = 0;

	tokens = rz_str_split_duplist(buf, " ", true);
	free(buf);
	if (!tokens) {
		return NULL;
	}

	buf = rz_list_first(tokens);
	for (i = 0; i < RZ_ARRAY_SIZE(v850_short_op); ++i) {
		if (!strcmp(buf, v850_short_op[i])) {
			rz_list_insert(tokens, 1, rz_str_dup("0"));
			break;
		}
	}

	if (insert_zero) {
		rz_list_insert(tokens, rz_list_length(tokens) - 1, rz_str_dup("0"));
	}

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&v850_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_v850_pseudo = {
	.name = "v850.pseudo",
	.desc = "v850 pseudo syntax",
	.parse = parse,
};
