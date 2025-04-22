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

static RzList /*<char *>*/ *dalvik_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar dalvik_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("+iget-wide-volatile", "1 = (wide-volatile) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("+invoke-interface/range", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("+invoke-virtual-quick", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-double", "1 = (double)(2 + 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-double", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-double/2addr", "1 += (double)2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-int", "1 = (int)(2 + 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-int/2addr", "1 += 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-int/lit16", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-int/lit8", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add-long", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget", "1 = 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget-boolean", "1 = (boolean) 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget-byte", "1 = (byte) 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget-char", "1 = (char) 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget-object", "1 = (object) 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget-short", "1 = (short) 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aget-wide", "1 = (wide) 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and-byte", "1 &= (byte) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and-int", "1 &= (int) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and-long/2addr", "1 &= (long) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput", "2[3] = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput-boolean", "2[3] = (bool) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput-byte", "2[3] = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput-char", "2[3] = (char) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput-object", "2[3] = (object) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput-short", "2[3] = (short) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("aput-wide", "2[3] = (wide) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("array-length", "1 = Array.length (2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("check-cast", "if (1 instanceof 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp-int", "1 = (2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp-long", "1 = (2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpg-double", "1 = (2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpg-float", "1 = (2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpl-double", "1 = (double)(2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpl-float", "1 = (float)(2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmpl-int", "1 = (int)(2 == 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-class", "1 = (class) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-string", "1 = (string) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-string/jumbo", "1 = (jumbo-string) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-wide", "1 = (wide) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-wide/16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-wide/32", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const-wide/high16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const/16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const/4", "1 = (wide) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("const/high16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-double", "1 = (double) 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-double/2addr", "1 /= (double) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-float", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-float/2addr", "1 /= (float) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-int", "1 = (int)(2 / 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-int/2addr", "1 /= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-int/lit16", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div-int/lit8", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("double-to-int", "1 = (int) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("double-to-long", "1 = (long) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("filled-new-array", "1 = new Array(2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("float-to-double", "1 = (double)(float) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("float-to-int", "1 = (int)(float) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("float-to-long", "1 = (long)(float) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("goto/16", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("goto/32", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-eq", "if (1 == 2) goto 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-eqz", "if (!1) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-ge", "if (1 > zero) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-gtz", "if (1 > 0) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-le", "if (1 <= 2) goto 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-lt", "if (1 < 2) goto 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-ltz", "if (1 <=) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-ne", "if (1 != 2) goto 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("if-nez", "if (1) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget", "1 = 2[3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget-boolean", "1 = (bool) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget-byte", "1 = (byte) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget-char", "1 = (char) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget-object", "1 = (2) 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget-short", "1 = (short) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iget-wide", "1 = (wide) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("instance-of", "1 = insteanceof (2) == 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("int-to-byte", "1 = (byte) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("int-to-double", "1 = (double) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("int-to-long", "1 = (long) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-direct", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-direct/range", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-interface", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-interface/range", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-polymorphic", "call polymorphic 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-static", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-super", "call super 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-super/range", "call super 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-virtual", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("invoke-virtual/range", "call 2 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iput", "2[3] = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iput-boolean", "2[3] = (bool) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iput-byte", "2[3] = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iput-char", "2[3] = (char) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iput-int", "2[3] = (int) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("iput-object", "2[3] = (object) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("long-to-double", "1 = (double) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("long-to-float", "1 = (float)(long) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("long-to-int", "1 = (int)(long) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-exception", "1 = exception"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-object", "1 = (object) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-object/16", "1 = (object) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-object/from16", "1 = (object) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-result", "1 = result"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-result-object", "1 = (object) result"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-result-wide", "1 = (wide) result"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-wide", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-wide/16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move-wide/from16", "1 = (wide) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move/16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move/from16", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul-double", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul-float", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul-float/2addr", "1 *= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul-int", "1 = (int)(2 * 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul-int/lit8", "1 = (2 * 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul-long", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg-double", "1 = -2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg-float", "1 = -2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg-long", "1 = -2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("new-array", "1 = new array (2, 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("new-instance", "1 = 2.new"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("not-int", "1 = !2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or-int", "1 = (int)(2 | 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or-int/2addr", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or-long", "1 |= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("packed-switch", "switch 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rem-double", "1 = (double) 2 % 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rem-double/2addr", "1 %= (double) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rem-float", "1 = (float) 2 % 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rem-float/2addr", "1 %= (float) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rem-long", "1 = (long) 2 % 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rem-long/2addr", "1 %= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("return-object", "return (object) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("return-void", "return"),
	RZ_PSEUDO_DEFINE_GRAMMAR("return-wide", "return (wide) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rsub-int", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sget", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sget-boolean", "1 = (bool) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sget-byte", "1 = (byte) 2 [3]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sget-char", "1 = (char) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sget-object", "1 = (object) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sget-short", "1 = (short) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shl-int", "1 = (int) 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shl-int/2addr", "1 <<<= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shl-long", "1 = (long) 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shr-int", "1 = (int) 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shr-long", "1 = (long) 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("shr-long/2addr", "1 >>= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sparse-switch", "switch 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sput", "1 = 2 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sput-boolean", "2[3] = (bool) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sput-char", "2[3] = (char) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sput-object", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sput-wide", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-float", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-float/2addr", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-int", "1 = (int) 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-int", "1 = (int)(2 - 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-int/2addr", "1 -= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-long", "1 = (long) 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub-long/2addr", "1 -= (long) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ushl-int/2addr", "1 <<<= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ushr-int", "1 = (int) 2 >>> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ushr-int/2addr", "1 >>>= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ushr-long", "1 = (long) 2 >>> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor-byte", "1 = (byte)(2 ^ 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor-int", "1 = (int)(2 ^ 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor-int/2addr", "1 ^= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor-long", "1 = (long)(2 ^ 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor-short", "1 = (short)(2 ^ 3)"),
};

static const RzPseudoReplace dalvik_replace[] = {
	RZ_PSEUDO_DEFINE_REPLACE("{", "(", 1),
	RZ_PSEUDO_DEFINE_REPLACE("}", ")", 1),
	RZ_PSEUDO_DEFINE_REPLACE(";", "", 1),
};

static const RzPseudoConfig dalvik_config = RZ_PSEUDO_DEFINE_CONFIG_NO_DIRECT(dalvik_lexicon, dalvik_replace, 4, dalvik_tokenize);

RzList /*<char *>*/ *dalvik_tokenize(const char *assembly, size_t length) {
	size_t i, p;
	char *buf = NULL;
	RzList *tokens = NULL;
	const char *comma_replace = NULL;
	bool keep = false;

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
		} else if (buf[p] == '{') {
			keep = true;
			comma_replace = ", ";
		} else if (buf[p] == '}') {
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
	return rz_pseudo_convert(&dalvik_config, assembly, sb);
}

RzParsePlugin rz_parse_plugin_dalvik_pseudo = {
	.name = "dalvik.pseudo",
	.desc = "DALVIK pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
};
