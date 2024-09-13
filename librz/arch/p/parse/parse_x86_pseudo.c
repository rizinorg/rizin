// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_analysis.h>
#include <rz_parse.h>
// 16 bit examples
//    0x0001f3a4      9a67620eca       call word 0xca0e:0x6267
//    0x0001f41c      eabe76de12       jmp word 0x12de:0x76be [2]
//    0x0001f56a      ea7ed73cd3       jmp word 0xd33c:0xd77e [6]
static int replace(int argc, char *argv[], char *newstr) {
#define MAXPSEUDOOPS 10
	int i, j, k, d;
	char ch;
	struct {
		char *op;
		char *str;
		int args[MAXPSEUDOOPS]; // XXX can't use flex arrays, all unused will be 0
	} ops[] = {
		{ "adc", "# += #", { 1, 2 } },
		{ "add", "# += #", { 1, 2 } },
		{ "and", "# &= #", { 1, 2 } },
		{ "call", "# ()", { 1 } },
		{ "cmove", "if (!var) # = #", { 1, 2 } },
		{ "cmovl", "if (var < 0) # = #", { 1, 2 } },
		{ "cmp", "var = # - #", { 1, 2 } },
		{ "cmpsq", "var = # - #", { 1, 2 } },
		{ "cmpsb", "while (CX != 0) { var = *(DS*16 + SI) - *(ES*16 + DI); SI++; DI++; CX--; if (!var) break; }", { 0 } },
		{ "cmpsw", "while (CX != 0) { var = *(DS*16 + SI) - *(ES*16 + DI); SI+=4; DI+=4; CX--; if (!var) break; }", { 0 } },
		{ "dec", "#--", { 1 } },
		{ "div", "# /= #", { 1, 2 } },
		{ "fabs", "abs(#)", { 1 } },
		{ "fadd", "# = # + #", { 1, 1, 2 } },
		{ "fcomp", "var = # - #", { 1, 2 } },
		{ "fcos", "# = cos(#)", { 1, 1 } },
		{ "fdiv", "# = # / #", { 1, 1, 2 } },
		{ "fiadd", "# = # / #", { 1, 1, 2 } },
		{ "ficom", "var = # - #", { 1, 2 } },
		{ "fidiv", "# = # / #", { 1, 1, 2 } },
		{ "fidiv", "# = # * #", { 1, 1, 2 } },
		{ "fisub", "# = # - #", { 1, 1, 2 } },
		{ "fnul", "# = # * #", { 1, 1, 2 } },
		{ "fnop", " ", { 0 } },
		{ "frndint", "# = (int) #", { 1, 1 } },
		{ "fsin", "# = sin(#)", { 1, 1 } },
		{ "fsqrt", "# = sqrt(#)", { 1, 1 } },
		{ "fsub", "# = # - #", { 1, 1, 2 } },
		{ "fxch", "#,# = #,#", { 1, 2, 2, 1 } },
		{ "idiv", "# /= #", { 1, 2 } },
		{ "imul", "# = # * #", { 1, 2, 3 } },
		{ "in", "# = io[#]", { 1, 2 } },
		{ "inc", "#++", { 1 } },
		{ "ja", "if (((unsigned) var) > 0) goto #", { 1 } },
		{ "jb", "if (((unsigned) var) < 0) goto #", { 1 } },
		{ "jbe", "if (((unsigned) var) <= 0) goto #", { 1 } },
		{ "je", "if (!var) goto #", { 1 } },
		{ "jg", "if (var > 0) goto #", { 1 } },
		{ "jge", "if (var >= 0) goto #", { 1 } },
		{ "jle", "if (var <= 0) goto #", { 1 } },
		{ "jmp", "goto #", { 1 } },
		{ "jne", "if (var) goto #", { 1 } },
		{ "lea", "# = #", { 1, 2 } },
		{ "mov", "# = #", { 1, 2 } },
		{ "movabs", "# = #", { 1, 2 } },
		{ "movq", "# = #", { 1, 2 } },
		{ "movaps", "# = #", { 1, 2 } },
		{ "movups", "# = #", { 1, 2 } },
		{ "movsd", "# = #", { 1, 2 } },
		{ "movsx", "# = #", { 1, 2 } },
		{ "movsxd", "# = #", { 1, 2 } },
		{ "movzx", "# = #", { 1, 2 } },
		{ "movntdq", "# = #", { 1, 2 } },
		{ "movnti", "# = #", { 1, 2 } },
		{ "movntpd", "# = #", { 1, 2 } },
		{ "pcmpeqb", "# == #", { 1, 2 } },

		{ "movdqu", "# = #", { 1, 2 } },
		{ "movdqa", "# = #", { 1, 2 } },
		{ "pextrb", "# = (byte) # [#]", { 1, 2, 3 } },
		{ "palignr", "# = # align #", { 1, 2, 3 } },
		{ "pxor", "# ^= #", { 1, 2 } },
		{ "xorps", "# ^= #", { 1, 2 } },
		{ "mul", "# = # * #", { 1, 2, 3 } },
		{ "mulss", "# = # * #", { 1, 2, 3 } },
		{ "neg", "# ~= #", { 1, 1 } },
		{ "nop", "", { 0 } },
		{ "not", "# = !#", { 1, 1 } },
		{ "or", "# |= #", { 1, 2 } },
		{ "out", "io[#] = #", { 1, 2 } },
		{ "pop", "pop #", { 1 } },
		{ "push", "push #", { 1 } },
		{ "ret", "return", { 0 } },
		{ "sal", "# <<= #", { 1, 2 } },
		{ "sar", "# >>= #", { 1, 2 } },
		{ "sete", "# = e", { 1 } },
		{ "setne", "# = ne", { 1 } },
		{ "shl", "# <<<= #", { 1, 2 } },
		{ "shld", "# <<<= #", { 1, 2 } },
		{ "sbb", "# = # - #", { 1, 1, 2 } },
		{ "shr", "# >>>= #", { 1, 2 } },
		{ "shlr", "# >>>= #", { 1, 2 } },
		//{ "strd",  "# = # - #", {1, 2, 3}},
		{ "sub", "# -= #", { 1, 2 } },
		{ "swap", "var = #; # = #; # = var", { 1, 1, 2, 2 } },
		{ "test", "var = # & #", { 1, 2 } },
		{ "xchg", "#,# = #,#", { 1, 2, 2, 1 } },
		{ "xadd", "#,# = #,#+#", { 1, 2, 2, 1, 2 } },
		{ "xor", "# ^= #", { 1, 2 } },
		{ NULL }
	};

	if (argc > 2 && !strcmp(argv[0], "xor")) {
		if (!strcmp(argv[1], argv[2])) {
			argv[0] = "mov";
			argv[2] = "0";
		}
	}
	for (i = 0; ops[i].op != NULL; i++) {
		if (!strcmp(ops[i].op, argv[0])) {
			if (newstr != NULL) {
				d = 0;
				j = 0;
				ch = ops[i].str[j];
				for (j = 0, k = 0; ch != '\0'; j++, k++) {
					ch = ops[i].str[j];
					if (ch == '#') {
						if (d >= MAXPSEUDOOPS) {
							// XXX Shouldn't ever happen...
							continue;
						}
						int idx = ops[i].args[d];
						d++;
						if (idx <= 0) {
							// XXX Shouldn't ever happen...
							continue;
						}
						const char *w = argv[idx];
						if (w != NULL) {
							strcpy(newstr + k, w);
							k += strlen(w) - 1;
						}
					} else {
						newstr[k] = ch;
					}
				}
				newstr[k] = '\0';
			}
			return true;
		}
	}

	/* TODO: this is slow */
	if (newstr) {
		newstr[0] = '\0';
		for (i = 0; i < argc; i++) {
			strcat(newstr, argv[i]);
			strcat(newstr, (i == 0 || i == argc - 1) ? " " : ",");
		}
	}
	return false;
}

static bool parse(RzParse *p, const char *data, RzStrBuf *sb) {
	char w0[256], w1[256], w2[256], w3[256];
	char str[1024] = { 0 };
	int i;
	size_t len = strlen(data);
	int sz = 32;
	char *buf, *ptr, *optr, *end;
	if (len >= sizeof(w0) || sz >= sizeof(w0)) {
		return false;
	}
	// rz_str_dup can be slow here :?
	if (!(buf = rz_str_dup(data))) {
		return false;
	}
	*w0 = *w1 = *w2 = *w3 = '\0';
	if (*buf) {
		end = buf + strlen(buf);
		ptr = strchr(buf, ' ');
		if (!ptr) {
			ptr = strchr(buf, '\t');
		}
		if (!ptr) {
			ptr = end;
		}
		*ptr = '\0';
		if (ptr != end) {
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
		}
		rz_str_ncpy(w0, buf, sizeof(w0));
		rz_str_ncpy(w1, ptr, sizeof(w1));
		optr = ptr;
		ptr = strchr(ptr, ',');
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			rz_str_ncpy(w1, optr, sizeof(w1));
			rz_str_ncpy(w2, ptr, sizeof(w2));
			optr = ptr;
			ptr = strchr(ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				rz_str_ncpy(w2, optr, sizeof(w2));
				rz_str_ncpy(w3, ptr, sizeof(w3));
			}
		}
	}
	char *wa[] = { w0, w1, w2, w3 };
	int nw = 0;
	for (i = 0; i < 4; i++) {
		if (wa[i][0] != '\0') {
			nw++;
		}
	}
	/* TODO: interpretation of memory location fails*/
	// ensure imul & mul interpretations works
	if (strstr(w0, "mul")) {
		if (nw == 2) {
			rz_str_ncpy(wa[3], wa[1], sizeof(w3));

			switch (wa[3][0]) {
			case 'q':
			case 'r': // qword, r..
				rz_str_ncpy(wa[1], "rax", sizeof(w1));
				rz_str_ncpy(wa[2], "rax", sizeof(w2));
				break;
			case 'd':
			case 'e': // dword, e..
				if (strlen(wa[3]) > 2) {
					rz_str_ncpy(wa[1], "eax", sizeof(w1));
					rz_str_ncpy(wa[2], "eax", sizeof(w2));
				}
				break;
			default: // .x, .p, .i or word
				if (wa[3][1] == 'x' || wa[3][1] == 'p' ||
					wa[3][1] == 'i' || wa[3][0] == 'w') {
					rz_str_ncpy(wa[1], "ax", sizeof(w1));
					rz_str_ncpy(wa[2], "ax", sizeof(w2));
				} else { // byte and lowest 8 bit registers
					rz_str_ncpy(wa[1], "al", sizeof(w1));
					rz_str_ncpy(wa[2], "al", sizeof(w2));
				}
				break;
			}
		} else if (nw == 3) {
			rz_str_ncpy(wa[3], wa[2], sizeof(w3));
			rz_str_ncpy(wa[2], wa[1], sizeof(w2));
		}

		replace(nw, wa, str);

	} else if (strstr(w0, "lea")) {
		rz_str_replace_char(w2, '[', 0);
		rz_str_replace_char(w2, ']', 0);
		replace(nw, wa, str);
	} else if ((strstr(w1, "ax") || strstr(w1, "ah") || strstr(w1, "al")) && !p->retleave_asm) {
		if (!(p->retleave_asm = (char *)malloc(sz))) {
			return false;
		}
		rz_snprintf(p->retleave_asm, sz, "return %s", w2);
		replace(nw, wa, str);
	} else if ((strstr(w0, "leave") && p->retleave_asm) || (strstr(w0, "pop") && strstr(w1, "bp"))) {
		rz_str_ncpy(wa[0], " ", 2);
		rz_str_ncpy(wa[1], " ", 2);
		replace(nw, wa, str);
	} else if (strstr(w0, "ret") && p->retleave_asm) {
		rz_str_ncpy(str, p->retleave_asm, sz);
		RZ_FREE(p->retleave_asm);
	} else if (p->retleave_asm) {
		RZ_FREE(p->retleave_asm);
		replace(nw, wa, str);
	} else {
		replace(nw, wa, str);
	}
	free(buf);
	rz_strbuf_set(sb, str);
	return true;
}

static char *subvar_stack(RzParse *p, RzAnalysisOp *op, RZ_NULLABLE RzAnalysisFunction *f, RZ_OWN char *tstr, bool att) {
	const ut64 addr = op->addr;

	if (!p->var_expr_for_reg_access || !f) {
		return tstr;
	}

	const char *re_str;
	int group_idx_reg;
	int group_idx_sign;
	int group_idx_addend;
	if (att) {
		// match e.g. -0x18(%rbp)
		// capturing "-0x18", "0x", "rbp"
		re_str = "(-?(0x)?[0-9a-f]+)\\(%([re][0-9a-z][0-9a-z])\\)";
		group_idx_reg = 3;
		group_idx_sign = -1;
		group_idx_addend = 1;
	} else {
		// match e.g. rbp - 0x42
		// capturing "rbp", "-", "0x42"
		re_str = "([re][0-9a-z][0-9a-z])\\s*(\\+|-)\\s*((0x)?[0-9a-f]+h?)";
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
	int base = 0;
	size_t addend_len = match->len;
	if (addend_len && (addend_str[addend_len - 1] == 'h' || addend_str[addend_len - 1] == 'H')) {
		// MASM syntax prints hex numbers like `1234h`
		base = 16;
	}
	st64 reg_addend = strtoll(addend_str, NULL, base);

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

	// replace!
	RzRegexMatch *match_full = rz_pvector_at(matches, 0);
	size_t tail_len = strlen(tstr) - (match_full->start + match_full->len);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	// reserve with a bit of padding for brackets, reg, whitespace, ...
	rz_strbuf_reserve(&sb, match_full->start + strlen(varstr) + tail_len + 32);
	rz_strbuf_append_n(&sb, tstr, match_full->start);
	if (!p->localvar_only && !att) {
		rz_strbuf_appendf(&sb, "%s %c ", reg_str, reg_addend < 0 ? '-' : '+');
	}
	rz_strbuf_appendf(&sb, "%s", varstr);
	if (!p->localvar_only && att) {
		rz_strbuf_appendf(&sb, "(%%%s)", reg_str);
	}
	rz_strbuf_append_n(&sb, tstr + match_full->start + match_full->len, tail_len);
	free(reg_str);
	free(varstr);
	free(tstr);
	rz_pvector_free(matches);
	return rz_strbuf_drain_nofree(&sb);
}

static bool subvar(RzParse *p, RzAnalysisFunction *f, RzAnalysisOp *op, char *data, char *str, int len) {
	const ut64 addr = op->addr;
	const int oplen = op->size;
	char *tstr = rz_str_dup(data);
	if (!tstr) {
		return false;
	}

	bool att = strchr(data, '%');

	if (p->subrel) {
		if (att) {
			char *rip = (char *)rz_str_casestr(tstr, "(%rip)");
			if (rip) {
				*rip = 0;
				char *pre = tstr;
				char *pos = rip + 6;
				char *word = rip;
				while (word > tstr && *word != ' ') {
					word--;
				}

				if (word > tstr) {
					*word++ = 0;
					*rip = 0;
					st64 n = rz_num_math(NULL, word);
					ut64 repl_num = oplen + addr + n;
					char *tstr_new = rz_str_newf("%s 0x%08" PFMT64x "%s", pre, repl_num, pos);
					*rip = '(';
					free(tstr);
					tstr = tstr_new;
				}
			}
		} else {
			char *rip = (char *)rz_str_casestr(tstr, "[rip");
			if (rip) {
				char *ripend = strchr(rip + 3, ']');
				const char *plus = strchr(rip, '+');
				const char *neg = strchr(rip, '-');
				char *tstr_new;
				ut64 repl_num = oplen + addr;

				if (!ripend) {
					ripend = "]";
				}
				if (plus) {
					repl_num += rz_num_get(NULL, plus + 1);
				}
				if (neg) {
					repl_num -= rz_num_get(NULL, neg + 1);
				}

				rip[1] = '\0';
				tstr_new = rz_str_newf("%s0x%08" PFMT64x "%s", tstr, repl_num, ripend);
				free(tstr);
				tstr = tstr_new;
			}
		}
	}

	tstr = subvar_stack(p, op, f, tstr, att);

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

RzParsePlugin rz_parse_plugin_x86_cs_pseudo = {
	.name = "x86.pseudo",
	.desc = "X86 pseudo syntax",
	.parse = &parse,
	.subvar = &subvar,
};
