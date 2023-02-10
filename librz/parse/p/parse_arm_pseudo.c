// SPDX-FileCopyrightText: 2015-2018 pancake <pancake@nopcode.org>
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

#include "parse_common.c"

static RzList /*<char *>*/ *arm_tokenize(const char *assembly, size_t length);

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
	RZ_PSEUDO_DEFINE_GRAMMAR("str", "2 = 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("strb", "2 = (byte) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("strh", "2 = (half) 1"),
	RZ_PSEUDO_DEFINE_GRAMMAR("strh.w", "2 = (half) 1"),
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

RzList /*<char *>*/ *arm_tokenize(const char *assembly, size_t length) {
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

static bool op_is_stack_addr_addition(RzAnalysisOp *op) {
	return op->type == RZ_ANALYSIS_OP_TYPE_ADD && op->dst && op->dst->reg && op->dst->reg->name && rz_str_casecmp(op->dst->reg->name, "fp") && rz_str_casecmp(op->dst->reg->name, "sp");
}

static char *subvar_stack(RzParse *p, RzAnalysisOp *op, RZ_NULLABLE RzAnalysisFunction *f, char *tstr) {
	const ut64 addr = op->addr;

	if (!p->var_expr_for_reg_access || !f) {
		return tstr;
	}

	const char *re_str;
	int group_idx_sign = -1;
	int group_idx_addend = 2;
	bool brackets = true;
	if (p->pseudo) {
		// match e.g. "fp - 0x42"
		// capturing "fp", "-", "0x42"
		re_str = "\\[([a-z][0-9a-z][0-9]?)\\s*(\\+|-)\\s*(-?(0x)?[0-9a-f]+)\\]";
		group_idx_sign = 2;
		group_idx_addend = 3;
	} else if (op && op_is_stack_addr_addition(op)) {
		// only in add instructions like "add r7, sp, 0x42" we want to match
		// without brackets around the "sp, 0x42". That is because we want to
		// avoid matching cases like the following:
		//  * sub r7, sp, 0x42
		//  * sub sp, 0x42
		//  * add fp, sp, 4

		// match e.g. "fp, -0x42"
		// capturing "fp", "-0x42"
		re_str = "([a-z][0-9a-z][0-9]?),\\s*(-?(0x)?[0-9a-f]+)";
		brackets = false;
	} else {
		// match e.g. "[fp, -0x42]"
		// capturing "fp", "-0x42"
		re_str = "\\[([a-z][0-9a-z][0-9]?),\\s*(-?(0x)?[0-9a-f]+)\\]";
	}

	RzRegex var_re;
	if (rz_regex_comp(&var_re, re_str, RZ_REGEX_EXTENDED | RZ_REGEX_ICASE) != 0) {
		rz_regex_fini(&var_re);
		return tstr;
	}
	RzRegexMatch match[4] = { 0 };
	if (rz_regex_exec(&var_re, tstr, RZ_ARRAY_SIZE(match), match, 0) != 0) {
		rz_regex_fini(&var_re);
		return tstr;
	}
	for (size_t i = 0; i < RZ_ARRAY_SIZE(match); i++) {
		char *s = rz_regex_match_extract(tstr, &match[i]);
		free(s);
	}
	rz_regex_fini(&var_re);

	rz_return_val_if_fail(match[1].rm_so >= 0, tstr);
	char *reg_str = rz_regex_match_extract(tstr, &match[1]);
	if (!reg_str) {
		return tstr;
	}

	rz_return_val_if_fail(match[group_idx_addend].rm_so >= 0, tstr);
	char *addend_str = rz_regex_match_extract(tstr, &match[group_idx_addend]);
	if (!addend_str) {
		free(reg_str);
		return tstr;
	}
	st64 reg_addend = strtoll(addend_str, NULL, 0);
	free(addend_str);

	if (group_idx_sign >= 0) {
		rz_return_val_if_fail(match[group_idx_sign].rm_so >= 0, tstr);
		char sign = tstr[match[group_idx_sign].rm_so];
		if (sign == '-') {
			reg_addend = -reg_addend;
		}
	}

	char *varstr = p->var_expr_for_reg_access(f, addr, reg_str, reg_addend);
	if (!varstr) {
		free(reg_str);
		return tstr;
	}

	// replace!
	size_t tail_len = strlen(tstr) - match[0].rm_eo;
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	// reserve with a bit of padding for brackets, reg, whitespace, ...
	rz_strbuf_reserve(&sb, match[0].rm_so + strlen(varstr) + tail_len + 32);
	rz_strbuf_append_n(&sb, tstr, match[0].rm_so);
	if (brackets) {
		rz_strbuf_append(&sb, "[");
	}
	if (!p->localvar_only) {
		rz_strbuf_appendf(&sb, "%s %c ", reg_str, reg_addend < 0 ? '-' : '+');
	}
	rz_strbuf_append(&sb, varstr);
	if (brackets) {
		rz_strbuf_append(&sb, "]");
	}
	rz_strbuf_append_n(&sb, tstr + match[0].rm_eo, tail_len);
	free(reg_str);
	free(varstr);
	free(tstr);
	return rz_strbuf_drain_nofree(&sb);
}

static bool subvar(RzParse *p, RzAnalysisFunction *f, RzAnalysisOp *op, char *data, char *str, int len) {
	const ut64 addr = op->addr;
	const int oplen = op->size;
	char *tstr = strdup(data);
	if (!tstr) {
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
			const char *maybe_num = neg ? neg + 1 : rip;
			maybe_num = rz_str_trim_head_ro(maybe_num);
			if (rz_is_valid_input_num_value(NULL, maybe_num)) {
				if (neg) {
					repl_num -= rz_num_get(NULL, maybe_num);
				} else {
					repl_num += rz_num_get(NULL, maybe_num);
				}
				rip -= 3;
				*rip = 0;
				tstr_new = rz_str_newf("%s0x%08" PFMT64x "%s", tstr, repl_num, ripend);
				free(tstr);
				tstr = tstr_new;
			}
		}
	}

	tstr = subvar_stack(p, op, f, tstr);

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
