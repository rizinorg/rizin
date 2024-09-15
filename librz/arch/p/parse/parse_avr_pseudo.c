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

static RzList /*<char *>*/ *avr_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar avr_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("adc", "1 += 2 + carry"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adiw", "1+#1:1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "1 &= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("andi", "1 &= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asr", "1 >>= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("breq", "if(!var) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brge", "if(var >= 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brlo", "if(var < 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brlt", "if(var < 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brmi", "if(var < 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brne", "if(var) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brpl", "if(var > 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brsh", "if(var >= 0) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("call", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cbr", "1 &= (#0xff - 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clc", "c = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clh", "h = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cli", "i = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cln", "n = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clr", "1 ^= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cls", "s = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clt", "t = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clv", "v = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clz", "z = #0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("com", "1 = #0xff - 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cp", "var = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cpc", "var = 1 - 2 - carry"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cpi", "var = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cpse", "if(1 == 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dec", "1--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("eor", "1 ^= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("halt", "_halt()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("icall", "goto z"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ijmp", "goto z"),
	RZ_PSEUDO_DEFINE_GRAMMAR("in", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("inc", "1++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iret", "return_interrupt()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jmp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld", "1 = *(2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldd", "1 = *(2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldi", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lds", "1 = *(2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lpm", "r0 = z"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsl", "1 <<= #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsr", "1 >>= #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movw", "1+#1:1 = 2+#1:2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul", "#r1:r0 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg", "1 = -1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ori", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("out", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pop", "1 = pop()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("push", "push(1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rcall", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ret", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rjmp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rol", "1 = (1 << #1) | (1 >> #7)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ror", "1 = (1 << #7) | (1 >> #1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbc", "1 -= (2 + carry)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbci", "1 -= (2 + carry)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbiw", "1+#1:1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbrc", "if((1 & (#1 << 2)) != #0)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbrs", "if((1 & (#1 << 2)) != #1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbr", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sec", "c = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("seh", "h = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sei", "i = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sen", "n = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ser", "1 = #0xff"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ses", "s = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("set", "t = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sev", "v = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sez", "z = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("st", "*(1) = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("std", "*(1) = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sts", "*(1) = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subi", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("swap", "1 = ((1 & #0xf0) >> #4) | ((1 & #0x0f) << #4)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tst", "1 &= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("wdr", "_watchdog_reset()"),
};

static const RzPseudoConfig avr_config = RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(avr_lexicon, 3, avr_tokenize);

RzList /*<char *>*/ *avr_tokenize(const char *assembly, size_t length) {
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
	return rz_pseudo_convert(&avr_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_avr_pseudo = {
	.name = "avr.pseudo",
	.desc = "AVR pseudo syntax",
	.parse = parse
};
