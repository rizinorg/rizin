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

static RzList /*<char *>*/ *z80_tokenize(const char *assembly, size_t length);

// https://wikiti.brandonw.net/index.php?title=Z80_Instruction_Set
static const RzPseudoGrammar z80_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("adc", "1 += 2 + cf"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "1 &= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bit", "tmp = 2 & (#1 << 1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("call", "call 1"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("ccf", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("cp", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("cpd", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("cpdr", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("cpi", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("cpir", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cpl", "1 = ~1"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("daa", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dec", "1--"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("di", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("djnz", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("ei", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ex", "swap(1, 2)"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("exx", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("halt", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("im", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("in", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("in", "1 = [2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("inc", "1++"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("ind", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("indr", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("ini", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("inir", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jp", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jp", "goto [1]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jr", "goto +1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ld", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldd", "1 = 2--"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("lddr", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("ldi", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("ldir", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("mulub", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("muluw", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg", "1 = -1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "1 |= 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("otdr", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("otir", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("out", "1 = 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("outd", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("outi", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pop", "pop 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("push", "push 1"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("res", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ret", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("reti", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("retn", "return"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rl", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rla", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rlc", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rlca", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rld", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rr", "1 <<= 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rra", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rrc", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rrca", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("rrd", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rst", "call 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbc", "1 -= 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("scf", "1 = 1 ? 2"),
	//	RZ_PSEUDO_DEFINE_GRAMMAR("set", "1 = 1 ? 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sla", "1 <<= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sra", "1 >>= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("srl", "1 >>= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor", "1 ^= 2"),
};

static const RzPseudoConfig z80_config = RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(z80_lexicon, 3, z80_tokenize);

RzList /*<char *>*/ *z80_tokenize(const char *assembly, size_t length) {
	size_t i, p;
	char *buf = NULL;
	const char *comma_replace = NULL;
	bool keep = false;
	RzList *tokens = NULL;

	buf = rz_str_ndup(assembly, length);
	if (!buf) {
		return NULL;
	}

	for (i = 0, p = 0; p < length; ++i, ++p) {
		if (buf[p] == ',') {
			if (!keep) {
				p++;
			} else if (buf[p + 1] == ' ') {
				buf[i] = buf[p];
				p++;
				continue;
			}
		} else if (buf[p] == '(') {
			keep = true;
			comma_replace = ", ";
		} else if (buf[p] == ')') {
			keep = false;
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

	if (!strcmp((char *)rz_list_first_val(tokens), "call") && rz_list_length(tokens) == 3) {
		void *arg1 = rz_list_get_n(tokens, 1);
		void *arg2 = rz_list_get_n(tokens, 2);
		rz_list_set_n(tokens, 1, arg2);
		rz_list_set_n(tokens, 2, arg1);
	}

	if (comma_replace) {
		RzListIter *it;
		rz_list_foreach (tokens, it, buf) {
			char *repl = rz_str_replace(buf, ",", comma_replace, 1);
			rz_list_iter_set_data(it, repl);
		}
	}

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&z80_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_z80_gnu_pseudo = {
	.name = "z80.pseudo",
	.desc = "z80 pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
};
