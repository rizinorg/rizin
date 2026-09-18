// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

// https://www.ti.com/lit/ug/spru732j/spru732j.pdf
#include "parse_helper.h"

static RzList /*<char *>*/ *tms320_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar tms320_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addab", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addah", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addaw", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addk", "2 += 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addu", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addw", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("andn", "3 = 1 ~ 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("avg2", "3 = 1 avg 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("band", "3 = 1 & 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clr", "4 = 2 .bitclear 1 .. 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpeq", "3 = 1 == 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpge", "3 = 1 >= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpgtu", "3 = 1 > 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmplt", "3 = 1 < 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ext", "4 = 2 ext 1 .. 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("extu", "4 = 2 ext 1 .. 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldb", "2 = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldbu", "2 = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lddw", "2 = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldh", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldhu", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldndw", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldnw", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldw", "2 = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("max2", "3 = max(1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpy", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpy2", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyh", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhi", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhir", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhl", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhl", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhlu", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhslu", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhsu", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhu", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhul", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhuls", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyhus", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpylh", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyli", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpylir", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyluhs", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpysu", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyu", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyu4", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mv", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mvk", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mvklh", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "3 = 2 | 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pack2", "3 = 1 pack 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("reti", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sadd", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sadd2", "3 = 1 + 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("set", "4 = 2 .bitset 1 .. 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shl", "3 = (2 & #0xffffff) << 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shlmb", "3 = << 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shr", "3 = (2 & #0xffffff) << 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("smpy", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("smpy", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("smpyh", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("smpyhl", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("smpylh", "3 = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ssub", "3 = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stb", "2 = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stdw", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sth", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stndw", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stnw", "2 = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stw", "2 = (word) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "3 = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub2", "3 = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subab", "3 = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subu", "3 = 1 - 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("zero", "1 = 0"),
};

static const RzPseudoConfig tms320_config = RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(tms320_lexicon, 5, tms320_tokenize);

/**
 * The C28x needs its own lexicon: it shares mnemonics with the C6000 above but
 * not their shapes -- C6000 "add" is three-operand, C28x "add" is two-operand,
 * so one grammar cannot serve both. Entries are the two-operand accumulator and
 * memory forms the decoder actually emits (SPRU430F).
 */
static const RzPseudoGrammar c28x_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addb", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addl", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addu", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "1 &= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("andb", "1 &= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asr", "1 >>= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp", "cmp(1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpb", "cmp(1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpl", "cmp(1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dec", "1--"),
	RZ_PSEUDO_DEFINE_GRAMMAR("inc", "1++"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lb", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lc", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lcr", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lretr", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsl", "1 <<= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsr", "1 >>= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movb", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movl", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movw", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movz", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpy", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mpyb", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg", "1 = -1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("not", "1 = ~1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("orb", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pop", "1 = pop()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("push", "push(1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sb", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subb", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subl", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subu", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tbit", "test(1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor", "1 ^= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xorb", "1 ^= 2"),
};

static const RzPseudoConfig c28x_config = RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(c28x_lexicon, 4, tms320_tokenize);

RzList /*<char *>*/ *tms320_tokenize(const char *assembly, size_t length) {
	char *buf = NULL, *sp = NULL;
	RzList *tokens = NULL;
	buf = rz_str_ndup(assembly, length);
	if (!buf) {
		return NULL;
	}

	sp = strchr(buf, ' ');
	if (sp) {
		*sp = ',';
	}

	tokens = rz_str_split_duplist(buf, ",", true);
	free(buf);

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	// the lexicons are per-core, so pick by cpu; analb.anal is the sanctioned
	// way to reach it from here
	const char *cpu = parse && parse->analb.analysis ? rz_analysis_get_cpu(parse->analb.analysis) : NULL;
	if (cpu && !rz_str_casecmp(cpu, "c28x")) {
		return rz_pseudo_convert(&c28x_config, assembly, sb);
	}
	return rz_pseudo_convert(&tms320_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_tms320_pseudo = {
	.name = "tms320.pseudo",
	.desc = "tms320 pseudo syntax",
	.parse = parse,
};
