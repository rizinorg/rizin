// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
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

static RzList *arm_tokenize(const char *assembly, size_t length);

static const RzPseudoGrammar arm_lexicon[] = {
	RZ_PSEUDO_DEFINE_GRAMMAR("abs", "1 = abs(1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adc", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("add.w", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adds", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("addw", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adf", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adr", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("adrp", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("and", "1 = 2 & 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ands", "1 &= 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asl", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asls", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asr", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("asrs", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b.gt", "if (? > ?) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b.le", "if (? < ?) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("b.w", "goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("beq", "if (? == ?) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bge", "if (? >= ?) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bkpt", "breakpoint 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bl", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("blx", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("bxeq", "if (? == ?) goto 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("call", "1 ()"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cbnz", "if (1) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cbz", "if (!1) goto 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmf", "if (1 == 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmn", "if (1 != 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("cmp", "if (1 == 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("div", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("dvf", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("eor", "1 = 2 ^ 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fcmp", "if (1 == 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fdiv", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fdv", "1 = 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fml", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fmov", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fmul", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("fsub", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldp", "(1, 2) = 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldr", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldr.w", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldrb", "1 = (byte) 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldrh", "1 = (word) 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldrsb", "1 = (byte) 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldrsw", "1 = 2 + 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("ldrsw", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsl", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsls", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsr", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsrs", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mov", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movk", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movn", "1 = ~2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movz", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("muf", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mul", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("muls", "1 = 2 * 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("mvn", "1 = ~2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("neg", "1 = !2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("orr", "1 = 2 | 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("rmf", "1 = 2 % 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sbc", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sqt", "1 = sqrt(2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stp", "3 = (1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("str", "[2 + 3] = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("strb", "[2 + 3] = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("strh", "[2 + 3] = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("strh.w", "[2 + 3] = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("stur", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subs", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("swp", "swap(1, 2)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sxtb", "1 = (char) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sxth", "1 = (short) 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sxtw", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("tst", "if ((1 & 2) == 0)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("udf", "undefined 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("udiv", "1 = (unsigned) 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("vmov.i32", "1 = 2"),
	/* arm thumb */
	RZ_PSEUDO_DEFINE_GRAMMAR("lsl.w", "1 = 2 << 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("lsr.w", "1 = 2 >> 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movs", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movt", "1 |= 2 << #16"),
	RZ_PSEUDO_DEFINE_GRAMMAR("movw", "1 = 2"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pop", "pop 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("pop.w", "pop 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("push", "push 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("push.w", "push 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("sub", "1 -= 2"), // THUMB
	RZ_PSEUDO_DEFINE_GRAMMAR("sub.w", "1 = 2 - 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("subs", "1 -= 2"), // THUMB
	RZ_PSEUDO_DEFINE_GRAMMAR("tst.w", "if ((1 & 2) == 0)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("vdiv.f64", "1 = (float) 2 / 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("vmov", "1 = (float) 2 . 3"),
	RZ_PSEUDO_DEFINE_GRAMMAR("vpop", "pop(1)"),
	RZ_PSEUDO_DEFINE_GRAMMAR("vpush", "push(1)"),
};

static const RzPseudoDirect arm_direct[] = {
	RZ_PSEUDO_DEFINE_DIRECT("beq lr", "if (? == ?) return"),
	RZ_PSEUDO_DEFINE_DIRECT("bx lr", "return"),
};

static const RzPseudoReplace arm_replace[] = {
	RZ_PSEUDO_DEFINE_REPLACE(" + 0]", "]", 0),
	RZ_PSEUDO_DEFINE_REPLACE("+ -", "- ", 1),
	RZ_PSEUDO_DEFINE_REPLACE("0 << 16", "0", 1),
	RZ_PSEUDO_DEFINE_REPLACE("{", "(", 1),
	RZ_PSEUDO_DEFINE_REPLACE("}", ")", 1),
};

static const RzPseudoConfig arm_config = RZ_PSEUDO_DEFINE_CONFIG(arm_direct, arm_lexicon, arm_replace, 5, arm_tokenize);

RzList *arm_tokenize(const char *assembly, size_t length) {
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
			buf[p] = ' ';
		} else if (buf[p] == ')') {
			buf[p] = ' ';
		} else if (buf[p] == '[') {
			keep = true;
			comma_replace = " + ";
		} else if (buf[p] == ']') {
			keep = false;
		} else if (buf[p] == '{') {
			if (strchr(buf + p + 1, ',') < strchr(buf + p + 1, '}')) {
				keep = true;
				comma_replace = ", ";
			} else {
				p++;
			}
		} else if (buf[p] == '}') {
			if (!comma_replace) {
				p++;
			}
			keep = false;
		} else if ((buf[p] == 'w' || buf[p] == 'x') && buf[p + 1] == 'z' && buf[p + 2] == 'r') {
			p += 2;
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

	if (comma_replace) {
		RzListIter *it;
		rz_list_foreach (tokens, it, buf) {
			it->data = rz_str_replace(buf, ",", comma_replace, 1);
		}
	}

	return tokens;
}

static bool parse(RzParse *p, const char *assembly, RzStrBuf *sb) {
	return rz_pseudo_convert(&arm_config, assembly, sb);
}

static char *subs_var_string(RzParse *p, RzAnalysisVarField *var, char *tstr, const char *oldstr, const char *reg, int delta) {
	char *newstr = p->localvar_only
		? rz_str_newf("%s", var->name)
		: rz_str_newf("%s %c %s", reg, delta > 0 ? '+' : '-', var->name);
	if (IS_UPPER(*tstr)) {
		char *space = strrchr(newstr, ' ');
		if (space) {
			*space = 0;
			rz_str_case(newstr, true);
			*space = ' ';
		}
	}
	char *ret = rz_str_replace(tstr, oldstr, newstr, 1);
	free(newstr);
	return ret;
}

static char *mount_oldstr(RzParse *p, const char *reg, st64 delta, bool ucase) {
	const char *tmplt;
	char *oldstr;
	if (delta > -10 && delta < 10) {
		if (p->pseudo) {
			char sign = '+';
			if (delta < 0) {
				sign = '-';
			}
			oldstr = rz_str_newf("%s %c %" PFMT64d, reg, sign, RZ_ABS(delta));
		} else {
			oldstr = rz_str_newf("%s, %" PFMT64d, reg, delta);
		}
	} else if (delta > 0) {
		tmplt = p->pseudo ? "%s + 0x%x" : (ucase ? "%s, 0x%X" : "%s, 0x%x");
		oldstr = rz_str_newf(tmplt, reg, delta);
	} else {
		tmplt = p->pseudo ? "%s - 0x%x" : (ucase ? "%s, -0x%X" : "%s, -0x%x");
		oldstr = rz_str_newf(tmplt, reg, -delta);
	}
	if (ucase) {
		char *comma = strchr(oldstr, ',');
		if (comma) {
			*comma = 0;
			rz_str_case(oldstr, true);
			*comma = ',';
		}
	}
	return oldstr;
}

static bool subvar(RzParse *p, RzAnalysisFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	RzList *spargs = NULL;
	RzList *bpargs = NULL;
	RzListIter *iter;
	RzAnalysis *analysis = p->analb.analysis;
	char *oldstr;
	char *tstr = strdup(data);
	if (!tstr) {
		return false;
	}

	if (!p->varlist) {
		free(tstr);
		return false;
	}
	if (p->subrel) {
		char *rip;
		if (p->pseudo) {
			rip = (char *)rz_str_casestr(tstr, "[pc +");
			if (!rip) {
				rip = (char *)rz_str_casestr(tstr, "[pc -");
			}
		} else {
			rip = (char *)rz_str_casestr(tstr, "[pc, ");
		}

		if (rip) {
			rip += 4;
			char *tstr_new, *ripend = strchr(rip, ']');
			const char *neg = strchr(rip, '-');
			ut64 off = (oplen == 2 || strstr(tstr, ".w") || strstr(tstr, ".W")) ? 4 : 8;
			ut64 repl_num = (addr + off) & ~3;
			if (!ripend) {
				ripend = "]";
			}
			if (neg) {
				repl_num -= rz_num_get(NULL, neg + 1);
			} else {
				repl_num += rz_num_get(NULL, rip);
			}
			rip -= 3;
			*rip = 0;
			tstr_new = rz_str_newf("%s0x%08" PFMT64x "%s", tstr, repl_num, ripend);
			free(tstr);
			tstr = tstr_new;
		}
	}

	bpargs = p->varlist(f, 'b');
	spargs = p->varlist(f, 's');
	bool ucase = IS_UPPER(*tstr);
	RzAnalysisVarField *var;
	rz_list_foreach (bpargs, iter, var) {
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
		oldstr = mount_oldstr(p, reg, delta, ucase);
		if (strstr(tstr, oldstr)) {
			tstr = subs_var_string(p, var, tstr, oldstr, reg, delta);
			free(oldstr);
			break;
		}
		free(oldstr);
	}
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
		oldstr = mount_oldstr(p, reg, delta, ucase);
		if (strstr(tstr, oldstr)) {
			tstr = subs_var_string(p, var, tstr, oldstr, reg, delta);
			free(oldstr);
			break;
		}
		free(oldstr);
	}
	rz_list_free(bpargs);
	rz_list_free(spargs);
	if (len > strlen(tstr)) {
		strcpy(str, tstr);
	} else {
		// TOO BIG STRING CANNOT REPLACE HERE
		free(tstr);
		return false;
	}
	free(tstr);
	return true;
}

RzParsePlugin rz_parse_plugin_arm_pseudo = {
	.name = "arm.pseudo",
	.desc = "ARM/ARM64 pseudo syntax",
	.parse = parse,
	.subvar = &subvar,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_PARSE,
	.data = &rz_parse_plugin_arm_pseudo,
	.version = RZ_VERSION
};
#endif
