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

#include "parse_common.c"

static RzList *mips_tokenize(const char *assembly, size_t length);

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

RzList *mips_tokenize(const char *assembly, size_t length) {
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
		rz_list_insert(tokens, rz_list_length(tokens) - 1, strdup("0"));
	}

	return tokens;
}

static bool parse(RzParse *parse, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&mips_config, assembly, sb);
}

static bool subvar(RzParse *p, RzAnalysisFunction *f, RzAnalysisOp *op, char *data, char *str, int len) {
	const ut64 addr = op->addr;
	RzListIter *iter;
	char *oldstr;
	char *tstr = strdup(data);
	RzAnalysis *analysis = p->analb.analysis;

	if (!p->varlist) {
		free(tstr);
		return false;
	}
	RzList *bpargs = p->varlist(f, 'b');
	RzList *spargs = p->varlist(f, 's');
	const bool ucase = IS_UPPER(*tstr);
	RzAnalysisVarField *var;
	rz_list_foreach (spargs, iter, var) {
		st64 delta = p->get_ptr_at
			? p->get_ptr_at(f, var->delta, addr)
			: ST64_MAX;
		if (delta == ST64_MAX && var->field) {
			delta = var->delta;
		} else if (delta == ST64_MAX) {
			continue;
		}
		const char *reg = NULL;
		if (p->get_reg_at) {
			reg = p->get_reg_at(f, var->delta, addr);
		}
		if (!reg) {
			reg = analysis->reg->name[RZ_REG_NAME_SP];
		}
		char *tmpf;
		// TODO: honor asm pseudo
		if (RZ_ABS(delta) < 10) {
			tmpf = "%d(%s)";
		} else if (delta > 0) {
			tmpf = "0x%x(%s)";
		} else {
			tmpf = "-0x%x(%s)";
		}
		oldstr = rz_str_newf(tmpf, RZ_ABS(delta), reg);
		if (ucase) {
			char *comma = strchr(oldstr, ',');
			if (comma) {
				*comma = 0;
				rz_str_case(oldstr, true);
				*comma = ',';
			}
		}
		if (strstr(tstr, oldstr)) {
			char *newstr = (p->localvar_only)
				? rz_str_newf("(%s)", var->name)
				: rz_str_newf("%s%s(%s)", delta > 0 ? "" : "-", var->name, reg);
			tstr = rz_str_replace(tstr, oldstr, newstr, 1);
			free(newstr);
			free(oldstr);
			break;
		}
		free(oldstr);
	}
	rz_list_foreach (bpargs, iter, var) {
		char *tmpf = NULL;
		st64 delta = p->get_ptr_at
			? p->get_ptr_at(f, var->delta, addr)
			: ST64_MAX;
		if (delta == ST64_MAX && var->field) {
			delta = var->delta + f->bp_off;
		} else if (delta == ST64_MAX) {
			continue;
		}
		const char *reg = NULL;
		if (p->get_reg_at) {
			reg = p->get_reg_at(f, var->delta, addr);
		}
		if (!reg) {
			reg = analysis->reg->name[RZ_REG_NAME_BP];
		}
		if (RZ_ABS(delta) < 10) {
			tmpf = "%d(%s)";
		} else if (delta > 0) {
			tmpf = "0x%x(%s)";
		} else {
			tmpf = "-0x%x(%s)";
		}
		oldstr = rz_str_newf(tmpf, RZ_ABS(delta), reg);
		if (ucase) {
			char *comma = strchr(oldstr, ',');
			if (comma) {
				*comma = 0;
				rz_str_case(oldstr, true);
				*comma = ',';
			}
		}
		if (strstr(tstr, oldstr)) {
			char *newstr = (p->localvar_only)
				? rz_str_newf("(%s)", var->name)
				: rz_str_newf("%s%s(%s)", delta > 0 ? "" : "-", var->name, reg);
			tstr = rz_str_replace(tstr, oldstr, newstr, 1);
			free(newstr);
			free(oldstr);
			break;
		}
		free(oldstr);
	}
	bool ret = true;
	if (len > strlen(tstr)) {
		strcpy(str, tstr);
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		ret = false;
	}
	free(tstr);
	rz_list_free(bpargs);
	rz_list_free(spargs);
	return ret;
}

RzParsePlugin rz_parse_plugin_mips_pseudo = {
	.name = "mips.pseudo",
	.desc = "MIPS pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.parse = parse,
	.subvar = subvar,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_PARSE,
	.data = &rz_parse_plugin_mips_pseudo,
	.version = RZ_VERSION
};
#endif
