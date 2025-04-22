// SPDX-FileCopyrightText: 2017-2021 deroad <wargio@libero.it>
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

static RzList /*<char *>*/ *sh_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar sh_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "2 += 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addc", "2 += 1 + t"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addv", "2 += 1; t = int_overflow (2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "2 &= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and.b", "2 &= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bf", "if (!t) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bf/s", "if (!t) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bra", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("brk", "_break_exception ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bsr", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bsrf", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bt", "if (t) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bt/s", "if (t) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clrmac", "_clrmac ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clrs", "_clrs ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("clrt", "_clrt ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/eq", "t = 2 == 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/ge", "t = 2 >= 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/gt", "t = 2 > 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/hi", "t = (unsigned) 2 > (unsigned) 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/hs", "t = (unsigned) 2 >= (unsigned) 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/pl", "t = 1 > 0 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/pz", "t = 1 >= 0 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp/str", "t = 1 ^ 2 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div1", "2 /= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dmuls.l", "mac = 2 * 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dmulu.l", "mac = (unsigned) 2 * (unsigned) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dt", "1--; t = !1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("exts.b", "2 = (int) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("exts.w", "2 = (int) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("extu.b", "2 = (unsigned int) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("extu.w", "2 = (unsigned int) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fabs", "1 = abs (1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fadd", "2 += 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fcmp/eq", "t = 2 == 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fcmp/gt", "t = 2 > 1 ? #1 : 0"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fcnvds", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fdiv", "2 /= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fldi0", "1 = 0.0f"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fldi1", "1 = #1.0f"),
	RZ_PSEUDO_DEFINE_GRAMMAR("flds", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("float", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fmac", "3 += 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fmov", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fmov.s", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fmul", "2 *= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fneg", "1 = -1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fsqrt", "1 = sqrt (1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fsts", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fsub", "2 -= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ftrc", "2 = trunc (1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ftrv", "2 *= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jmp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jsr", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldr", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldr.l", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lds", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lds.l", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov.b", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov.l", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov.w", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movca.l", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movt", "1 = t"),
	RZ_PSEUDO_DEFINE_GRAMMAR("muls.w", "macl = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mulu.w", "macl = (unsigned) 1 * (unsigned) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg", "1 = -1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("negc", "1 = (-1) - t"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("not", "1 = !1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "2 |= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rotcl", "t = 1 & 0x#80000000 ? 0 : #1; 1 = (1 << #1) | t"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rotl", "1 = (1 << #1) | (1 >> #31)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rotr", "1 = (1 << #31) | (1 >> #1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rte", "_rte ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rts", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sets", "s = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sett", "t = #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shad", "2 = 1 >= 0 ? 2 << 1 | 2 >> (#31 - 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shal", "1 <<= #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shar", "1 >>= #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shld", "2 = 1 >= 0 ? 2 << 1 | 2 >> (#31 - 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shll", "1 <<= #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shll16", "1 <<= #16"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shll2", "1 <<= #2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shll8", "1 <<= #8"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shlr", "1 >>= #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shlr16", "1 >>= #16"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shlr2", "1 >>= #2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shlr8", "1 >>= #8"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sleep", "_halt ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stc", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stc.l", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sts", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sts.l", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "2 -= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subc", "2 -= 1 - t"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subv", "2 -= 1; t = int_underflow (2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("swap.b", "swap_byte (2, 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("swap.w", "swap_word (2, 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tas.b", "test_and_set (1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("trapa", "trap (1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tst", "t = 2 & 1 ? 0 : #1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor", "2 ^= 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor.b", "2 ^= 1"),
};

static const RzPseudoReplace sh_replace[] = {
	RZ_PSEUDO_DEFINE_REPLACE("+ -", "- ", 1),
};

static const RzPseudoConfig sh_config = RZ_PSEUDO_DEFINE_CONFIG_NO_DIRECT(sh_lexicon, sh_replace, 4, sh_tokenize);

RzList /*<char *>*/ *sh_tokenize(const char *assembly, size_t length) {
	size_t i, p;
	char *buf = NULL;
	bool ignore_comma = false;
	RzList *tokens = NULL;

	buf = rz_str_ndup(assembly, length);
	if (!buf) {
		return NULL;
	}

	for (i = 0, p = 0; p < length; ++i, ++p) {
		if (buf[p] == ',' && !ignore_comma) {
			p++;
		} else if (buf[p] == '(') {
			ignore_comma = true;
		} else if (buf[p] == ')') {
			ignore_comma = false;
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

	RzListIter *it;
	rz_list_foreach (tokens, it, buf) {
		char *repl = rz_str_replace(buf, ",", " + ", 1);
		rz_list_iter_set_data(it, repl);
	}

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&sh_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_sh_pseudo = {
	.name = "sh.pseudo",
	.desc = "SH-4 pseudo syntax",
	.parse = parse
};
