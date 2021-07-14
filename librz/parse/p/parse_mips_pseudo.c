// SPDX-FileCopyrightText: 2012-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

typedef struct {
	const char *mnemonic;
	int mnemonic_length;
	const char *grammar;
	int grammar_length;
} MipsOp;

#define MIPS_SET_OP(x, y) \
	{ .mnemonic = x, .mnemonic_length = sizeof(x) - 1, .grammar = y, .grammar_length = sizeof(y) - 1 }
const MipsOp ops[] = {
	MIPS_SET_OP("add", "1 = 2 + 3"),
	MIPS_SET_OP("addi", "1 = 2 + 3"),
	MIPS_SET_OP("addiu", "1 = 2 + 3"),
	MIPS_SET_OP("addu", "1 = 2 + 3"),
	MIPS_SET_OP("and", "1 = 2 & 3"),
	MIPS_SET_OP("andi", "1 = 2 & 3"),
	MIPS_SET_OP("b", "goto 1"),
	MIPS_SET_OP("bal", "call 1"),
	MIPS_SET_OP("begzal", "if (1 >= 0) call 2"),
	MIPS_SET_OP("beq", "if (1 == 2) goto 3"),
	MIPS_SET_OP("beqz", "if (!1) goto 2"),
	MIPS_SET_OP("bgez", "if (1 >= 0) goto 2"),
	MIPS_SET_OP("bgtz", "if (1 > 0) goto 2"),
	MIPS_SET_OP("blez", "if (1 <= 0) goto 2"),
	MIPS_SET_OP("bltz", "if (1 < 0) goto 2"),
	MIPS_SET_OP("bltzal", "if (1 < 0) call 2"),
	MIPS_SET_OP("bne", "if (1 != 2) goto 3"),
	MIPS_SET_OP("bnez", "if (1) goto 2"),
	MIPS_SET_OP("j", "goto 1"),
	MIPS_SET_OP("jal", "call 1"),
	MIPS_SET_OP("jalr", "call 1"),
	MIPS_SET_OP("jr", "goto 1"),
	MIPS_SET_OP("lb", "1 = byte [3 + 2]"),
	MIPS_SET_OP("lbu", "1 = (unsigned) byte [3 + 2]"),
	MIPS_SET_OP("lh", "1 = halfword [3 + 2]"),
	MIPS_SET_OP("lhu", "1 = (unsigned) halfword [3 + 2]"),
	MIPS_SET_OP("li", "1 = 2"),
	MIPS_SET_OP("lui", "1 = 2 << #16"),
	MIPS_SET_OP("lw", "1 = word [3 + 2]"),
	MIPS_SET_OP("mfhi", "1 = hi"),
	MIPS_SET_OP("mflo", "1 = lo"),
	MIPS_SET_OP("move", "1 = 2"),
	MIPS_SET_OP("movn", "if (3) 1 = 2"),
	MIPS_SET_OP("movz", "if (!3) 1 = 2"),
	MIPS_SET_OP("mult", "(hi,lo) = 1 * 2"),
	MIPS_SET_OP("multu", "unsigned (hi,lo) = 1 * 2"),
	MIPS_SET_OP("mul", "1 = 2 * 3"),
	MIPS_SET_OP("mulu", "1 = 2 * 3"),
	MIPS_SET_OP("negu", "1 = ~2"),
	MIPS_SET_OP("nop", ""),
	MIPS_SET_OP("nor", "1 = ~(2 | 3)"),
	MIPS_SET_OP("or", "1 = 2 | 3"),
	MIPS_SET_OP("ori", "1 = 2 | 3"),
	MIPS_SET_OP("sb", "byte [3 + 2] = 1"),
	MIPS_SET_OP("sh", "halfword [3 + 2] = 1"),
	MIPS_SET_OP("sll", "1 = 2 << 3"),
	MIPS_SET_OP("sllv", "1 = 2 << 3"),
	MIPS_SET_OP("slr", "1 = 2 >> 3"),
	MIPS_SET_OP("slt", "1 = (2 < 3)"),
	MIPS_SET_OP("slti", "1 = (2 < 3)"),
	MIPS_SET_OP("sltiu", "1 = (unsigned) (2 < 3)"),
	MIPS_SET_OP("sltu", "1 = (unsigned) (2 < 3)"),
	MIPS_SET_OP("sra", "1 = (signed) 2 >> 3"),
	MIPS_SET_OP("srl", "1 = 2 >> 3"),
	MIPS_SET_OP("srlv", "1 = 2 >> 3"),
	MIPS_SET_OP("subu", "1 = 2 - 3"),
	MIPS_SET_OP("sub", "1 = 2 - 3"),
	MIPS_SET_OP("sw", "word [3 + 2] = 1"),
	MIPS_SET_OP("syscall", "syscall"),
	MIPS_SET_OP("xor", "1 = 2 ^ 3"),
	MIPS_SET_OP("xori", "1 = 2 ^ 3"),
};
#undef MIPS_SET_OP

static const MipsOp *find_opcode(const char *data) {
	for (int i = 0; i < RZ_ARRAY_SIZE(ops); ++i) {
		if (!strncmp(ops[i].mnemonic, data, ops[i].mnemonic_length)) {
			return &ops[i];
		}
	}
	return NULL;
}

static bool parse(RzParse *parse, const char *data, RzStrBuf *sb) {
	int i, p, len;
	char *buf = NULL;
	const char *arg = NULL;
	const MipsOp *op = NULL;
	bool insert_zero = false;
	if (!strcmp(data, "jr ra")) {
		rz_strbuf_set(sb, "return");
		return true;
	}

	op = find_opcode(data);
	if (!op) {
		return false;
	}

	len = strlen(data);
	buf = rz_str_ndup(data, len);
	if (!buf) {
		return false;
	}
	for (i = 0, p = 0; p < len; ++i, ++p) {
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

	RzList *tokens = rz_str_split_list(buf, " ", 0);
	if (!tokens) {
		free(buf);
		return false;
	}

	if (insert_zero) {
		rz_list_insert(tokens, rz_list_length(tokens) - 1, strdup("0"));
	}

	for (i = 0, p = 0; i < op->grammar_length; ++p) {
		int index = op->grammar[p] - '0';
		switch (index) {
		case 1:
		case 2:
		case 3:
			arg = (const char *)rz_list_get_n(tokens, index);
			if (!arg) {
				rz_warn_if_reached();
			}
			rz_strbuf_append_n(sb, op->grammar + i, p - i);
			i = p + 1;
			rz_strbuf_append(sb, arg);
			break;
		default:
			if (op->grammar[p] == '#') {
				rz_strbuf_append_n(sb, op->grammar + i, p - i);
				i = p + 1;
				p++;
				while (IS_DIGIT(op->grammar[p])) {
					++p;
				}
			}
			break;
		}
	}

	if (i < p) {
		rz_strbuf_append_n(sb, op->grammar + i, p - i);
	}

	if (insert_zero) {
		rz_str_replace(rz_strbuf_get(sb), " + 0", "", 1);
	} else {
		rz_str_replace(rz_strbuf_get(sb), "+ -", "- ", 1);
		rz_str_replace(rz_strbuf_get(sb), "0 << 16", "0", 1);
	}

	rz_list_free(tokens);
	free(buf);
	return true;
}

static bool subvar(RzParse *p, RzAnalysisFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
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
		//TODO: honor asm pseudo
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
