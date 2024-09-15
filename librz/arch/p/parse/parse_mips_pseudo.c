// SPDX-FileCopyrightText: 2012-2017 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2018-2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>
#include <rz_util/rz_regex.h>

#include "parse_helper.h"

static RzList /*<char *>*/ *mips_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar mips_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addi", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addiu", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addu", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "1 = 2 & 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("andi", "1 = 2 & 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bal", "call 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("begzal", "if (1 >= 0) call 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("beq", "if (1 == 2) goto 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("beqz", "if (!1) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bgez", "if (1 >= 0) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bgtz", "if (1 > 0) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("blez", "if (1 <= 0) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bltz", "if (1 < 0) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bltzal", "if (1 < 0) call 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bne", "if (1 != 2) goto 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bnez", "if (1) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("j", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jal", "call 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jalr", "call 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("jr", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lb", "1 = byte [3 + 2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lbu", "1 = (unsigned) byte [3 + 2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lh", "1 = halfword [3 + 2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lhu", "1 = (unsigned) halfword [3 + 2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("li", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lui", "1 = 2 << #16"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lw", "1 = word [3 + 2]"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mfhi", "1 = hi"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mflo", "1 = lo"),
	RZ_PSEUDO_DEFINE_GRAMMAR("move", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movn", "if (3) 1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movz", "if (!3) 1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mult", "(hi,lo) = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("multu", "unsigned (hi,lo) = 1 * 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mulu", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("negu", "1 = ~2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("nop", ""),
	RZ_PSEUDO_DEFINE_GRAMMAR("nor", "1 = ~(2 | 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("or", "1 = 2 | 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ori", "1 = 2 | 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sb", "byte [3 + 2] = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sh", "halfword [3 + 2] = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sll", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sllv", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("slr", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("slt", "1 = (2 < 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("slti", "1 = (2 < 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sltiu", "1 = (unsigned) (2 < 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sltu", "1 = (unsigned) (2 < 3)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sra", "1 = (signed) 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("srl", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("srlv", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subu", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sw", "word [3 + 2] = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("syscall", "syscall"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xor", "1 = 2 ^ 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("xori", "1 = 2 ^ 3"),
};

static const RzPseudoDirect mips_direct[] = {
	RZ_PSEUDO_DEFINE_DIRECT("jr ra", "return"),
};

static const RzPseudoReplace mips_replace[] = {
	RZ_PSEUDO_DEFINE_REPLACE(" + 0]", "]", 0),
	RZ_PSEUDO_DEFINE_REPLACE("+ -", "- ", 1),
	RZ_PSEUDO_DEFINE_REPLACE("0 << 16", "0", 1),
};

static const RzPseudoConfig mips_config = RZ_PSEUDO_DEFINE_CONFIG(mips_direct, mips_lexicon, mips_replace, 4, mips_tokenize);

RzList /*<char *>*/ *mips_tokenize(const char *assembly, size_t length) {
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
		} else if (buf[p] == 'z' && buf[p + 1] == 'e' && buf[p + 2] == 'r' && buf[p + 3] == 'o') {
			p += 3;
			buf[p] = '0';
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
	return rz_pseudo_convert(&mips_config, assembly, sb);
}

static char *subvar_stack(RzParse *p, RzAnalysisOp *op, RZ_NULLABLE RzAnalysisFunction *f, char *tstr) {
	const ut64 addr = op->addr;

	if (!p->var_expr_for_reg_access || !f) {
		return tstr;
	}

	const char *re_str;
	int group_idx_reg;
	int group_idx_sign;
	int group_idx_addend;
	if (!p->pseudo) {
		// match e.g. -0x18(fp)
		// capturing "-0x18", "0x", "fp"
		re_str = "(-?(0x)?[0-9a-f]+)\\(([a-z][0-9a-z])\\)";
		group_idx_reg = 3;
		group_idx_sign = -1;
		group_idx_addend = 1;
	} else {
		// match e.g. fp - 0x42
		// capturing "fp", "-", "0x42"
		re_str = "([a-z][0-9a-z])\\s*(\\+|-)\\s*((0x)?[0-9a-f]+h?)";
		group_idx_reg = 1;
		group_idx_sign = 2;
		group_idx_addend = 3;
	}

	RzRegex *var_re = rz_regex_new(re_str, RZ_REGEX_EXTENDED | RZ_REGEX_CASELESS, 0);
	if (!var_re) {
		return tstr;
	}
	RzPVector *matches = rz_regex_match_first(var_re, tstr, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	if (!matches || rz_pvector_empty(matches)) {
		rz_regex_free(var_re);
		rz_pvector_free(matches);
		return tstr;
	}
	rz_regex_free(var_re);

	rz_return_val_if_fail(rz_pvector_len(matches) > group_idx_reg, tstr);
	RzRegexMatch *match = rz_pvector_at(matches, group_idx_reg);
	char *reg_str = rz_str_ndup(tstr + match->start, match->len);
	if (!reg_str) {
		rz_pvector_free(matches);
		return tstr;
	}

	rz_return_val_if_fail(rz_pvector_len(matches) >= group_idx_addend, tstr);
	match = rz_pvector_at(matches, group_idx_addend);
	const char *addend_str = tstr + match->start;
	st64 reg_addend = strtoll(addend_str, NULL, 0);

	if (group_idx_sign >= 0) {
		rz_return_val_if_fail(rz_pvector_len(matches) >= group_idx_sign, tstr);
		match = rz_pvector_at(matches, group_idx_sign);
		char sign = tstr[match->start];
		if (sign == '-') {
			reg_addend = -reg_addend;
		}
	}

	char *varstr = p->var_expr_for_reg_access(f, addr, reg_str, reg_addend);
	if (!varstr) {
		free(reg_str);
		rz_pvector_free(matches);
		return tstr;
	}

	// information gathered, now perform the replacement in the string
	RzRegexMatch *match_full = rz_pvector_at(matches, 0);
	size_t tail_len = strlen(tstr) - (match_full->start + match_full->len);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	// reserve with a bit of padding for brackets, reg, whitespace, ...
	rz_strbuf_reserve(&sb, match_full->start + strlen(varstr) + tail_len + 32);
	rz_strbuf_append_n(&sb, tstr, match_full->start);
	if (p->localvar_only) {
		if (p->pseudo) {
			rz_strbuf_append(&sb, varstr);
		} else {
			rz_strbuf_appendf(&sb, "(%s)", varstr);
		}
	} else {
		if (p->pseudo) {
			rz_strbuf_appendf(&sb, "%s %c %s", reg_str, reg_addend < 0 ? '-' : '+', varstr);
		} else {
			rz_strbuf_appendf(&sb, "%s(%s)", varstr, reg_str);
		}
	}
	rz_strbuf_append_n(&sb, tstr + match_full->start + match_full->len, tail_len);
	free(reg_str);
	free(varstr);
	free(tstr);
	rz_pvector_free(matches);
	return rz_strbuf_drain_nofree(&sb);
}

static bool subvar(RzParse *p, RzAnalysisFunction *f, RzAnalysisOp *op, char *data, char *str, int len) {
	char *tstr = rz_str_dup(data);
	tstr = subvar_stack(p, op, f, tstr);
	bool ret = true;
	if (len > strlen(tstr)) {
		strcpy(str, tstr);
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		ret = false;
	}
	free(tstr);
	return ret;
}

RzParsePlugin rz_parse_plugin_mips_cs_pseudo = {
	.name = "mips.pseudo",
	.desc = "MIPS pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.subvar = subvar,
};
