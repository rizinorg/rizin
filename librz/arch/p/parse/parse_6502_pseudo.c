// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

#include "parse_helper.h"

static RzList /*<char *>*/ *_6502_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar _6502_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("adc", "a += (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "a &= (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asl", "a = 1 << #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bcc", "if (carry == 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bcs", "if (carry != 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("beq", "if (eq) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bmi", "if (lt) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bne", "if (ne) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bpl", "if (gt) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brk", "break"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clc", "carry = 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cld", "decimal = 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cli", "interrupt = 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clv", "overflow = 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp", "cmp (1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cpx", "cmp (x, 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cpy", "cmp (y, 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dcx", "x--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dcy", "y--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dec", "(1 + 2)--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dex", "x--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dey", "y--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("eor", "a ^= (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("inc", "(1 + 2)++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("inc", "1++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("inx", "x++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iny", "y++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jmp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jsr", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lda", "a = (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldx", "x = (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldy", "y = (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("ora", "a |= (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pha", "push a"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rti", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rts", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbc", "a -= (1 + 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sec", "carry = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sed", "decimal = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sei", "interrupt = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sta", "[1 + 2] = a"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stx", "[1 + 2] = x"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sty", "[1 + 2] = y"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tax", "x = a"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tay", "y = a"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tsx", "x = s"),
	RZ_PSEUDO_DEFINE_GRAMMAR("txa", "a = x"),
	RZ_PSEUDO_DEFINE_GRAMMAR("txs", "s = x"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tya", "a = y"),
};

static const RzPseudoConfig _6502_config = RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(_6502_lexicon, 3, _6502_tokenize);

RzList /*<char *>*/ *_6502_tokenize(const char *assembly, size_t length) {
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
			buf[p] = ' ';
		} else if (buf[p] == '#') {
			p++;
		} else if (buf[p] == '(') {
			buf[p] = ' ';
			if (!IS_HEXCHAR(buf[p - 1])) {
				p++;
				insert_zero = true;
			}
		} else if (buf[p] == ')') {
			buf[p] = 0;
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

	if (insert_zero) {
		rz_list_insert(tokens, rz_list_length(tokens) - 1, rz_str_dup("0"));
	}

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&_6502_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_6502_pseudo = {
	.name = "6502.pseudo",
	.desc = "6502 pseudo syntax",
	.parse = parse,
};
