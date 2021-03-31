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

static int replace(int argc, const char *argv[], char *newstr) {
#define MAXPSEUDOOPS 10
	int i, j, k, d;
	char ch;
	struct {
		int narg;
		char *op;
		char *str;
		int args[MAXPSEUDOOPS];
	} ops[] = {
		{ 0, "abs", "# = abs(#)", { 1, 1 } },
		{ 0, "adc", "# = # + #", { 1, 2, 3 } },
		{ 3, "add", "# = # + #", { 1, 2, 3 } },
		{ 2, "add", "# += #", { 1, 2 } },
		{ 2, "adds", "# += #", { 1, 2 } },
		{ 3, "adds", "# = # + #", { 1, 2, 3 } },
		{ 3, "addw", "# = # + #", { 1, 2, 3 } },
		{ 3, "add.w", "# = # + #", { 1, 2, 3 } },
		{ 0, "adf", "# = # + #", { 1, 2, 3 } },
		{ 0, "adrp", "# = #", { 1, 2 } },
		{ 0, "adr", "# = #", { 1, 2 } },
		{ 0, "and", "# = # & #", { 1, 2, 3 } },
		{ 0, "ands", "# &= #", { 1, 2 } },
		{ 0, "asls", "# = # << #", { 1, 2, 3 } },
		{ 0, "asl", "# = # << #", { 1, 2, 3 } },
		{ 0, "asrs", "# = # >> #", { 1, 2, 3 } },
		{ 0, "asr", "# = # >> #", { 1, 2, 3 } },
		{ 0, "b", "jmp #", { 1 } },
		{ 0, "cbz", "if !# jmp #", { 1, 2 } },
		{ 0, "cbnz", "if # jmp #", { 1, 2 } },
		{ 0, "b.w", "jmp #", { 1 } },
		{ 0, "b.gt", "jmp ifgt #", { 1 } },
		{ 0, "b.le", "jmp ifle #", { 1 } },
		{ 0, "beq lr", "ifeq ret", { 0 } },
		{ 0, "beq", "je #", { 1 } },
		{ 0, "call", "# ()", { 1 } },
		{ 0, "bl", "# ()", { 1 } },
		{ 0, "blx", "# ()", { 1 } },
		{ 0, "bx lr", "ret", { 0 } },
		{ 0, "bxeq", "je #", { 1 } },
		{ 0, "cmf", "if (# == #)", { 1, 2 } },
		{ 0, "cmn", "if (# != #)", { 1, 2 } },
		{ 0, "cmp", "if (# == #)", { 1, 2 } },
		{ 0, "fcmp", "if (# == #)", { 1, 2 } },
		{ 0, "tst", "if ((# & #) == 0)", { 1, 2 } },
		{ 0, "dvf", "# = # / #", { 1, 2, 3 } },
		{ 0, "eor", "# = # ^ #", { 1, 2, 3 } },
		{ 1, "bkpt", "breakpoint #", { 1 } },
		{ 1, "udf", "undefined #", { 1 } },
		{ 2, "sxtb", "# = (char) #", { 1, 2 } },
		{ 2, "sxth", "# = (short) #", { 1, 2 } },
		{ 0, "fdv", "# = # / #", { 1, 2, 3 } },
		{ 0, "fml", "# = # * #", { 1, 2, 3 } },
		{ 2, "ldr", "# = #", { 1, 2 } },
		{ 2, "ldrh", "# = (word) #", { 1, 2 } },
		{ 3, "ldrh", "# = (word) # + #", { 1, 2, 3 } },
		{ 2, "ldrb", "# = (byte) #", { 1, 2 } },
		{ 3, "ldrb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 2, "ldrsb", "# = (byte) #", { 1, 2 } },
		{ 2, "ldr.w", "# = #", { 1, 2 } },
		{ 2, "ldrsw", "# = #", { 1, 2 } },
		{ 3, "ldr", "# = # + #", { 1, 2, 3 } },
		{ 3, "ldrb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 3, "ldrsb", "# = (byte) # + #", { 1, 2, 3 } },
		{ 3, "ldr.w", "# = # + #", { 1, 2, 3 } },
		{ 3, "ldrsw", "# = # + #", { 1, 2, 3 } },
		{ 0, "lsl", "# = # << #", { 1, 2, 3 } },
		{ 0, "lsr", "# = # >> #", { 1, 2, 3 } },
		{ 0, "mov", "# = #", { 1, 2 } },
		{ 0, "fmov", "# = #", { 1, 2 } },
		{ 0, "mvn", "# = ~#", { 1, 2 } },
		{ 0, "movz", "# = #", { 1, 2 } },
		{ 0, "movk", "# = #", { 1, 2 } },
		{ 0, "movn", "# = ~#", { 1, 2 } },
		{ 0, "neg", "# = !#", { 1, 2 } },
		{ 0, "sxtw", "# = #", { 1, 2 } },
		{ 0, "stur", "# = #", { 2, 1 } },
		{ 0, "stp", "# = (#, 2)", { 3, 1 } },
		{ 0, "ldp", "(#, 2) = 3", { 1 } },
		{ 0, "vmov.i32", "# = #", { 1, 2 } },
		{ 0, "muf", "# = # * #", { 1, 2, 3 } },
		{ 0, "mul", "# = # * #", { 1, 2, 3 } },
		{ 0, "fmul", "# = # * #", { 1, 2, 3 } },
		{ 0, "muls", "# = # * #", { 1, 2, 3 } },
		{ 0, "div", "# = # / #", { 1, 2, 3 } },
		{ 0, "fdiv", "# = # / #", { 1, 2, 3 } },
		{ 0, "udiv", "# = (unsigned) # / #", { 1, 2, 3 } },
		{ 0, "orr", "# = # | #", { 1, 2, 3 } },
		{ 0, "rmf", "# = # % #", { 1, 2, 3 } },
		{ 0, "bge", "(>=) goto #", { 1 } },
		{ 0, "sbc", "# = # - #", { 1, 2, 3 } },
		{ 0, "sqt", "# = sqrt(#)", { 1, 2 } },
		{ 0, "lsrs", "# = # >> #", { 1, 2, 3 } },
		{ 0, "lsls", "# = # << #", { 1, 2, 3 } },
		{ 0, "lsr", "# = # >> #", { 1, 2, 3 } },
		{ 0, "lsl", "# = # << #", { 1, 2, 3 } },
		{ 2, "str", "# = #", { 2, 1 } },
		{ 2, "strb", "# = (byte) #", { 2, 1 } },
		{ 2, "strh", "# = (half) #", { 2, 1 } },
		{ 2, "strh.w", "# = (half) #", { 2, 1 } },
		{ 3, "str", "# + # = #", { 2, 3, 1 } },
		{ 3, "strb", "# + # = (byte) #", { 2, 3, 1 } },
		{ 3, "strh", "# + # = (half) #", { 2, 3, 1 } },
		{ 3, "strh.w", "# + # = (half) #", { 2, 3, 1 } },
		{ 3, "sub", "# = # - #", { 1, 2, 3 } },
		{ 3, "subs", "# = # - #", { 1, 2, 3 } },
		{ 3, "fsub", "# = # - #", { 1, 2, 3 } },
		{ 2, "sub", "# -= #", { 1, 2 } }, // THUMB
		{ 2, "subs", "# -= #", { 1, 2 } }, // THUMB
		{ 0, "swp", "swap(#, 2)", { 1 } },
		/* arm thumb */
		{ 0, "movs", "# = #", { 1, 2 } },
		{ 0, "movw", "# = #", { 1, 2 } },
		{ 0, "movt", "# |= # << 16", { 1, 2 } },
		{ 0, "vmov", "# = (float) # . #", { 1, 2, 3 } },
		{ 0, "vdiv.f64", "# = (float) # / #", { 1, 2, 3 } },
		{ 0, "addw", "# = # + #", { 1, 2, 3 } },
		{ 0, "sub.w", "# = # - #", { 1, 2, 3 } },
		{ 0, "tst.w", "if ((# & #) == 0)", { 1, 2 } },
		{ 0, "lsr.w", "# = # >> #", { 1, 2, 3 } },
		{ 0, "lsl.w", "# = # << #", { 1, 2, 3 } },
		{ 0, "pop.w", "pop #", { 1 } },
		{ 0, "vpop", "pop #", { 1 } },
		{ 0, "vpush", "push #", { 1 } },
		{ 0, "push.w", "push #", { 1 } },
		{ 0, NULL }
	};
	if (!newstr) {
		return false;
	}

	for (i = 0; ops[i].op; i++) {
		if (ops[i].narg) {
			if (argc - 1 != ops[i].narg) {
				continue;
			}
		}
		if (!strcmp(ops[i].op, argv[0])) {
			if (newstr) {
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
						if (w) {
							strcpy(newstr + k, w);
							k += strlen(w) - 1;
						}
					} else {
						newstr[k] = ch;
					}
				}
				newstr[k] = '\0';
			}

			rz_str_replace_char(newstr, '{', '(');
			rz_str_replace_char(newstr, '}', ')');
			return true;
		}
	}

	/* TODO: this is slow */
	newstr[0] = '\0';
	for (i = 0; i < argc; i++) {
		strcat(newstr, argv[i]);
		strcat(newstr, (!i || i == argc - 1) ? " " : ",");
	}
	rz_str_replace_char(newstr, '{', '(');
	rz_str_replace_char(newstr, '}', ')');
	return false;
}

static int parse(RzParse *p, const char *data, char *str) {
	char w0[256], w1[256], w2[256], w3[256];
	int i, len = strlen(data);
	char *buf, *ptr, *optr;

	if (len >= sizeof(w0)) {
		return false;
	}
	// malloc can be slow here :?
	if (!(buf = malloc(len + 1))) {
		return false;
	}
	memcpy(buf, data, len + 1);
	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = '\0';
		ptr = strchr(buf, ' ');
		if (!ptr) {
			ptr = strchr(buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			strncpy(w0, buf, sizeof(w0) - 1);
			strncpy(w1, ptr, sizeof(w1) - 1);

			optr = ptr;
			if (*ptr == '(') {
				ptr = strchr(ptr + 1, ')');
			}
			if (ptr && *ptr == '[') {
				ptr = strchr(ptr + 1, ']');
			}
			if (ptr && *ptr == '{') {
				ptr = strchr(ptr + 1, '}');
			}
			if (!ptr) {
				eprintf("Unbalanced bracket\n");
				free(buf);
				return false;
			}
			ptr = strchr(ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				strncpy(w1, optr, sizeof(w1) - 1);
				strncpy(w2, ptr, sizeof(w2) - 1);
				optr = ptr;
				ptr = strchr(ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr == ' '; ptr++) {
						;
					}
					strncpy(w2, optr, sizeof(w2) - 1);
					strncpy(w3, ptr, sizeof(w3) - 1);
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3 };
			int nw = 0;
			for (i = 0; i < 4; i++) {
				if (wa[i][0]) {
					nw++;
				}
			}
			replace(nw, wa, str);
		}
	}
	{
		char *s = strdup(str);
		s = rz_str_replace(s, "+ -", "- ", 1);
		s = rz_str_replace(s, "- -", "+ ", 1);
		strcpy(str, s);
		free(s);
	}
	free(buf);
	return true;
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

		if (rip && !strchr(rip + 4, ',')) {
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
