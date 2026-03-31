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

static RzList /*<char *>*/ *m68k_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar m68k_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adda", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addi", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addq", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("andi", "2 &= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bcc", "if (cc) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bcs", "if (cs) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bne", "if (!=) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("beq", "if (==) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bge", "if (>=) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bgt", "if (>) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ble", "if (<=) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("blt", "if (<) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bra", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bsr", "call 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("btst", "1 == 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp", "1 == 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpi", "2 == 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jmp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jsr", "call 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lea", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsl", "2 <<= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsr", "2 >>= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movea", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movem", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("moveq", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "2 |= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ori", "2 |= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rts", "ret"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subq", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tst", "1 == 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clr", "1 = 0"),
};

static const RzPseudoReplace m68k_replace[] = {
	RZ_PSEUDO_DEFINE_REPLACE("+ -", "- ", 1),
};

static const RzPseudoConfig m68k_config = RZ_PSEUDO_DEFINE_CONFIG_NO_DIRECT(m68k_lexicon, m68k_replace, 4, m68k_tokenize);

RzList /*<char *>*/ *m68k_tokenize(const char *assembly, size_t length) {
	size_t i, p;
	char *buf = NULL;
	RzList *tokens = NULL;

	buf = rz_str_ndup(assembly, length);
	if (!buf) {
		return NULL;
	}

	for (i = 0, p = 0; p < length; ++i, ++p) {
		if (buf[p] == ',') {
			p++;
		}
		if (p > i) {
			buf[i] = buf[p];
		}
	}
	buf[i] = 0;

	tokens = rz_str_split_duplist(buf, " ", true);
	free(buf);
	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	char *copy = rz_str_dup(assembly);
	if (!copy) {
		rz_strbuf_setf(sb, "asm(\"%s\")", assembly);
		return true;
	}
	copy = rz_str_replace(copy, ".l", "", 0);
	copy = rz_str_replace(copy, ".w", "", 0);
	copy = rz_str_replace(copy, ".d", "", 0);
	copy = rz_str_replace(copy, ".b", "", 0);
	bool res = rz_pseudo_convert(&m68k_config, copy, sb);
	free(copy);
	return res;
}

RzParsePlugin rz_parse_plugin_m68k_cs_pseudo = {
	.name = "m68k.pseudo",
	.desc = "M68K pseudo syntax",
	.parse = parse,
};
