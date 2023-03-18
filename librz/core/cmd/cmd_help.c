// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include <math.h> // required for signbit
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_util.h"

static ut32 vernum(const char *s) {
	// XXX this is known to be buggy, only works for strings like "x.x.x"
	// XXX anything like "x.xx.x" will break the parsing
	// XXX -git is ignored, maybe we should shift for it
	char *a = strdup(s);
	a = rz_str_replace(a, ".", "0", 1);
	char *dash = strchr(a, '-');
	if (dash) {
		*dash = 0;
	}
	ut32 res = atoi(a);
	free(a);
	return res;
}

static const char *help_msg_percent[] = {
	"Usage:", "%[name[=value]]", "Set each NAME to VALUE in the environment",
	"%", "", "list all environment variables",
	"%", "SHELL", "prints SHELL value",
	"%", "TMPDIR=/tmp", "sets TMPDIR value to \"/tmp\"",
	NULL
};

// NOTE: probably not all environment vars takes sesnse
// because they can be replaced by commands in the given
// command.. we should only expose the most essential and
// unidirectional ones.
static const char *help_msg_env[] = {
	"\nEnvironment:", "", "",
	"RZ_FILE", "", "file name",
	"RZ_OFFSET", "", "10base offset 64bit value",
	"RZ_XOFFSET", "", "same as above, but in 16 base",
	"RZ_BSIZE", "", "block size",
	"RZ_ENDIAN", "", "'big' or 'little'",
	"RZ_IOVA", "", "is io.va true? virtual addressing (1,0)",
	"RZ_DEBUG", "", "debug mode enabled? (1,0)",
	"RZ_SIZE", "", "file size",
	"RZ_ARCH", "", "value of asm.arch",
	"RZ_BITS", "", "arch reg size (8, 16, 32, 64)",
	"RZ_BIN_LANG", "", "assume this lang to demangle",
	"RZ_BIN_DEMANGLE", "", "demangle or not",
	"RZ_BIN_PDBSERVER", "", "e pdb.server",
	NULL
};

static const char *help_msg_question_v[] = {
	"Usage: ?v [$.]", "", "",
	"flag", "", "offset of flag",
	"$", "{ev}", "get value of eval config variable",
	"$$", "", "here (current virtual seek)",
	"$$$", "", "current non-temporary virtual seek",
	"$?", "", "last comparison value",
	"$alias", "=value", "alias commands (simple macros)",
	"$B", "", "base address (aligned lowest map address)",
	"$b", "", "block size",
	"$c", "", "get terminal width in character columns",
	"$Cn", "", "get nth call of function",
	"$D", "", "current debug map base address ?v $D @ rsp",
	"$DB", "", "same as dbg.baddr, progam base address",
	"$DD", "", "current debug map size",
	"$Dn", "", "get nth data reference in function",
	"$e", "", "1 if end of block, else 0",
	"$e", "{flag}", "end of flag (flag->offset + flag->size)",
	"$f", "", "jump fail address (e.g. jz 0x10 => next instruction)",
	"$F", "", "Same as $FB",
	"$Fb", "", "begin of basic block",
	"$FB", "", "begin of function",
	"$Fe", "", "end of basic block",
	"$FE", "", "end of function",
	"$Ff", "", "function false destination",
	"$Fi", "", "basic block instructions",
	"$FI", "", "function instructions",
	"$Fj", "", "function jump destination",
	"$fl", "", "flag length (size) at current address (fla; pD $l @ entry0)",
	"$FS", "", "function size (linear length)",
	"$Fs", "", "size of the current basic block",
	"$FSS", "", "function size (sum bb sizes)",
	"$j", "", "jump address (e.g. jmp 0x10, jz 0x10 => 0x10)",
	"$Ja", "", "get nth jump of function",
	"$k{kv}", "", "get value of an sdb query value",
	"$l", "", "opcode length",
	"$M", "", "map address (lowest map address)",
	"$m", "", "opcode memory reference (e.g. mov eax,[0x10] => 0x10)",
	"$MM", "", "map size (lowest map address)",
	"$O", "", "cursor here (current offset pointed by the cursor)",
	"$o", "", "here (current disk io offset)",
	"$p", "", "getpid()",
	"$P", "", "pid of children (only in debug)",
	"$r", "", "get console height (in rows, see $c for columns)",
	"$r", "{reg}", "get value of named register",
	"$s", "", "file size",
	"$S", "", "section offset",
	"$SS", "", "section size",
	"$s", "{flag}", "get size of flag",
	"$v", "", "opcode immediate value (e.g. lui a0,0x8010 => 0x8010)",
	"$w", "", "get word size, 4 if asm.bits=32, 8 if 64, ...",
	"$Xn", "", "get nth xref of function",
	"RzNum", "", "$variables usable in math expressions",
	NULL
};

static const char *help_msg_greater_sign[] = {
	"Usage:", "[cmd]>[file]", "redirects console from 'cmd' output to 'file'",
	"[cmd] > [file]", "", "redirect STDOUT of 'cmd' to 'file'",
	"[cmd] > $alias", "", "save the output of the command as an alias (see $?)",
	"[cmd] H> [file]", "", "redirect html output of 'cmd' to 'file'",
	"[cmd] 2> [file]", "", "redirect STDERR of 'cmd' to 'file'",
	"[cmd] 2> /dev/null", "", "omit the STDERR output of 'cmd'",
	NULL
};

static void cmd_help_percent(RzCore *core) {
	rz_core_cmd_help(core, help_msg_percent);
	rz_core_cmd_help(core, help_msg_env);
}

static const char *findBreakChar(const char *s) {
	while (*s) {
		if (!rz_name_validate_char(*s, true)) {
			break;
		}
		s++;
	}
	return s;
}

static char *filterFlags(RzCore *core, const char *msg) {
	const char *dollar, *end;
	char *word, *buf = NULL;
	for (;;) {
		dollar = strchr(msg, '$');
		if (!dollar) {
			break;
		}
		buf = rz_str_appendlen(buf, msg, dollar - msg);
		if (dollar[1] == '{') {
			// find }
			end = strchr(dollar + 2, '}');
			if (end) {
				word = rz_str_newlen(dollar + 2, end - dollar - 2);
				end++;
			} else {
				msg = dollar + 1;
				buf = rz_str_append(buf, "$");
				continue;
			}
		} else {
			end = findBreakChar(dollar + 1);
			if (!end) {
				end = dollar + strlen(dollar);
			}
			word = rz_str_newlen(dollar + 1, end - dollar - 1);
		}
		if (end && word) {
			ut64 val = rz_num_math(core->num, word);
			char num[32];
			snprintf(num, sizeof(num), "0x%" PFMT64x, val);
			buf = rz_str_append(buf, num);
			msg = end;
		} else {
			break;
		}
		free(word);
	}
	buf = rz_str_append(buf, msg);
	return buf;
}

static const char *avatar_orangg[] = {
	"      _______\n"
	"     /       \\      .-%s-.\n"
	"   _| ( o) (o)\\_    | %s |\n"
	"  / _     .\\. | \\  <| %s |\n"
	"  \\| \\   ____ / 7`  | %s |\n"
	"  '|\\|  `---'/      `-%s-'\n"
	"     | /----. \\\n"
	"     | \\___/  |___\n"
	"     `-----'`-----'\n"
};

static const char *avatar_clippy[] = {
	" .--.     .-%s-.\n"
	" | _|     | %s |\n"
	" | O O   <  %s |\n"
	" |  |  |  | %s |\n"
	" || | /   `-%s-'\n"
	" |`-'|\n"
	" `---'\n",
	" .--.     .-%s-.\n"
	" |   \\    | %s |\n"
	" | O o   <  %s |\n"
	" |   | /  | %s |\n"
	" |  ( /   `-%s-'\n"
	" |   / \n"
	" `--'\n",
	" .--.     .-%s-.\n"
	" | _|_    | %s |\n"
	" | O O   <  %s |\n"
	" |  ||    | %s |\n"
	" | _:|    `-%s-'\n"
	" |   |\n"
	" `---'\n",
};

static const char *avatar_clippy_utf8[] = {
	" ╭──╮    ╭─%s─╮\n"
	" │ _│    │ %s │\n"
	" │ O O  <  %s │\n"
	" │  │╭   │ %s │\n"
	" ││ ││   ╰─%s─╯\n"
	" │└─┘│\n"
	" ╰───╯\n",
	" ╭──╮    ╭─%s─╮\n"
	" │ ╶│╶   │ %s │\n"
	" │ O o  <  %s │\n"
	" │  │  ╱ │ %s │\n"
	" │ ╭┘ ╱  ╰─%s─╯\n"
	" │ ╰ ╱\n"
	" ╰──'\n",
	" ╭──╮    ╭─%s─╮\n"
	" │ _│_   │ %s │\n"
	" │ O O  <  %s │\n"
	" │  │╷   │ %s │\n"
	" │  ││   ╰─%s─╯\n"
	" │ ─╯│\n"
	" ╰───╯\n",
};

static const char *avatar_cybcat[] = {
	"     /\\.---./\\       .-%s-.\n"
	" '--           --'   | %s |\n"
	"----   ^   ^   ---- <  %s |\n"
	"  _.-    Y    -._    | %s |\n"
	"                     `-%s-'\n",
	"     /\\.---./\\       .-%s-.\n"
	" '--   @   @   --'   | %s |\n"
	"----     Y     ---- <  %s |\n"
	"  _.-    O    -._    | %s |\n"
	"                     `-%s-'\n",
	"     /\\.---./\\       .-%s-.\n"
	" '--   =   =   --'   | %s |\n"
	"----     Y     ---- <  %s |\n"
	"  _.-    U    -._    | %s |\n"
	"                     `-%s-'\n",
};

enum {
	RZ_AVATAR_ORANGG,
	RZ_AVATAR_CYBCAT,
	RZ_AVATAR_CLIPPY,
};

/**
 * \brief Returns all the $ variable names in a NULL-terminated array.
 */
RZ_API const char **rz_core_help_vars_get(RzCore *core) {
	static const char *vars[] = {
		"$$", "$$$", "$?", "$B", "$b", "$c", "$Cn", "$D", "$DB", "$DD", "$Dn",
		"$e", "$f", "$F", "$Fb", "$FB", "$Fe", "$FE", "$Ff", "$Fi", "$FI", "$Fj",
		"$fl", "$FS", "$Fs", "$FSS", "$j", "$Ja", "$l", "$M", "$m", "$MM", "$O",
		"$o", "$p", "$P", "$r", "$s", "$S", "$SS", "$v", "$w", "$Xn", NULL
	};
	return vars;
}

RZ_API void rz_core_help_vars_print(RzCore *core) {
	int i = 0;
	const char **vars = rz_core_help_vars_get(core);
	const bool wideOffsets = rz_config_get_i(core->config, "scr.wideoff");
	while (vars[i]) {
		const char *pad = rz_str_pad(' ', 6 - strlen(vars[i]));
		if (wideOffsets) {
			rz_cons_printf("%s %s 0x%016" PFMT64x "\n", vars[i], pad, rz_num_math(core->num, vars[i]));
		} else {
			rz_cons_printf("%s %s 0x%08" PFMT64x "\n", vars[i], pad, rz_num_math(core->num, vars[i]));
		}
		i++;
	}
}

/**
 * \brief Get clippy echo string.
 * \param msg The message to echo.
 */
RZ_API RZ_OWN char *rz_core_clippy(RZ_NONNULL RzCore *core, RZ_NONNULL const char *msg) {
	rz_return_val_if_fail(core && msg, NULL);
	int type = RZ_AVATAR_CLIPPY;
	if (*msg == '+' || *msg == '3') {
		char *space = strchr(msg, ' ');
		if (!space) {
			return NULL;
		}
		type = (*msg == '+') ? RZ_AVATAR_ORANGG : RZ_AVATAR_CYBCAT;
		msg = space + 1;
	}
	const char *f;
	int msglen = rz_str_len_utf8(msg);
	char *s = strdup(rz_str_pad(' ', msglen));
	char *l;

	if (type == RZ_AVATAR_ORANGG) {
		l = strdup(rz_str_pad('-', msglen));
		f = avatar_orangg[0];
	} else if (type == RZ_AVATAR_CYBCAT) {
		l = strdup(rz_str_pad('-', msglen));
		f = avatar_cybcat[rz_num_rand(RZ_ARRAY_SIZE(avatar_cybcat))];
	} else if (rz_config_get_i(core->config, "scr.utf8")) {
		l = (char *)rz_str_repeat("─", msglen);
		f = avatar_clippy_utf8[rz_num_rand(RZ_ARRAY_SIZE(avatar_clippy_utf8))];
	} else {
		l = strdup(rz_str_pad('-', msglen));
		f = avatar_clippy[rz_num_rand(RZ_ARRAY_SIZE(avatar_clippy))];
	}

	char *string = rz_str_newf(f, l, s, msg, s, l);
	free(l);
	free(s);
	return string;
}

RZ_IPI void rz_core_clippy_print(RzCore *core, const char *msg) {
	char *string = rz_core_clippy(core, msg);
	if (string) {
		rz_cons_print(string);
		free(string);
	}
}

RZ_API void rz_core_cmd_help_calc_expr(RZ_NONNULL RzCore *core, RZ_NONNULL const char *input) {
	rz_return_if_fail(core && input);

	char *asnum, unit[8];
	ut32 s, a;
	double d;
	float f;
	char number[128], out[128] = RZ_EMPTY;
	char *inputs = strdup(input + 1);
	RzList *list = rz_num_str_split_list(inputs);
	const int list_len = rz_list_length(list);
	PJ *pj = NULL;
	if (*input == 'j') {
		pj = pj_new();
		pj_o(pj);
	}
	for (ut32 i = 0; i < list_len; i++) {
		const char *str = rz_list_pop_head(list);
		if (!*str) {
			continue;
		}
		ut64 n = rz_num_math(core->num, str);
		if (core->num->dbz) {
			RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
			return;
		}
		asnum = rz_num_as_string(NULL, n, false);
		/* decimal, hexa, octal */
		s = n >> 16 << 12;
		a = n & 0x0fff;
		rz_num_units(unit, sizeof(unit), n);
		if (*input == 'j') {
			pj_ks(pj, "int32", rz_strf(number, "%d", (st32)(n & UT32_MAX)));
			pj_ks(pj, "uint32", rz_strf(number, "%u", (ut32)n));
			pj_ks(pj, "int64", rz_strf(number, "%" PFMT64d, (st64)n));
			pj_ks(pj, "uint64", rz_strf(number, "%" PFMT64u, (ut64)n));
			pj_ks(pj, "hex", rz_strf(number, "0x%08" PFMT64x, n));
			pj_ks(pj, "octal", rz_strf(number, "0%" PFMT64o, n));
			pj_ks(pj, "unit", unit);
			pj_ks(pj, "segment", rz_strf(number, "%04x:%04x", s, a));

		} else {
			if (n >> 32) {
				rz_cons_printf("int64   %" PFMT64d "\n", (st64)n);
				rz_cons_printf("uint64  %" PFMT64u "\n", (ut64)n);
			} else {
				rz_cons_printf("int32   %d\n", (st32)n);
				rz_cons_printf("uint32  %u\n", (ut32)n);
			}
			rz_cons_printf("hex     0x%" PFMT64x "\n", n);
			rz_cons_printf("octal   0%" PFMT64o "\n", n);
			rz_cons_printf("unit    %s\n", unit);
			rz_cons_printf("segment %04x:%04x\n", s, a);

			if (asnum) {
				rz_cons_printf("string  \"%s\"\n", asnum);
				free(asnum);
			}
		}
		/* binary and floating point */
		rz_str_bits64(out, n);
		f = d = core->num->fvalue;
		/* adjust sign for nan floats, different libcs are confused */
		if (isnan(f) && signbit(f)) {
			f = -f;
		}
		if (isnan(d) && signbit(d)) {
			d = -d;
		}
		if (*input == 'j') {
			pj_ks(pj, "fvalue", rz_strf(number, "%.1lf", core->num->fvalue));
			pj_ks(pj, "float", rz_strf(number, "%ff", f));
			pj_ks(pj, "double", rz_strf(number, "%lf", d));
			pj_ks(pj, "binary", rz_strf(number, "0b%s", out));
			rz_num_to_trits(out, n);
			pj_ks(pj, "trits", rz_strf(number, "0t%s", out));
		} else {
			rz_cons_printf("fvalue  %.1lf\n", core->num->fvalue);
			rz_cons_printf("float   %ff\n", f);
			rz_cons_printf("double  %lf\n", d);
			rz_cons_printf("binary  0b%s\n", out);

			/* ternary */
			rz_num_to_trits(out, n);
			rz_cons_printf("trits   0t%s\n", out);
		}
	}
	if (*input == 'j') {
		pj_end(pj);
	}
	free(inputs);
	rz_list_free(list);
	if (pj) {
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI int rz_cmd_help(void *data, const char *input) {
	/*
		RzCore *core = (RzCore *)data;
		RzIOMap *map;
		const char *k;
		RzListIter *iter;
		char *p, out[128] = RZ_EMPTY;
		ut64 n;
		int i;
		RzList *tmp;

		switch (input[0]) {
		case 'b': // "?b"
			} else if (input[1] == 't' && input[2] == 'w') { // "?btw"
				if (rz_num_between(core->num, input + 3) == -1) {
					RZ_LOG_ERROR("core: Usage: ?btw num|(expr) num|(expr) num|(expr)\n");
				}
			}
		case '@': // "?@"
			if (input[1] == '@') {
				if (input[2] == '@') {
					rz_core_cmd_help(core, help_msg_at_at_at);
				} else {
					rz_core_cmd_help(core, help_msg_at_at);
				}
			} else {
				rz_core_cmd_help(core, help_msg_at);
			}
		case '?': // "??"
			if (input[1] == '?') {
				if (input[2] == '?') { // "???"
					rz_core_clippy_print(core, "What are you doing?");
					return 0;
				}
				if (input[2]) {
					if (core->num->value) {
						rz_core_cmd(core, input + 1, 0);
					}
					break;
				}
				rz_core_cmd_help(core, help_msg_question);
				return 0;
			} else if (input[1]) {
				if (core->num->value) {
					core->num->value = rz_core_cmd(core, input + 1, 0);
				}
			} else {
				if (core->num->dbz) {
					RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
				}
				rz_cons_printf("%" PFMT64d "\n", core->num->value);
			}
			break;
		case '\0': // "?"
		default:
			break;
		}
		*/
	return 0;
}

RZ_IPI RzCmdStatus rz_calculate_expr_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	char unit[8];
	char number[128], out[128] = RZ_EMPTY;

	for (int i = 1; i < argc; i++) {
		const char *str = argv[i];
		if (!*str) {
			continue;
		}

		ut64 n = rz_num_math(core->num, str);
		if (core->num->dbz) {
			RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
			core->num->dbz = 0;
			return RZ_CMD_STATUS_ERROR;
		}

		/* decimal, hexa, octal */
		ut32 s, a;
		s = n >> 16 << 12;
		a = n & 0x0fff;
		rz_num_units(unit, sizeof(unit), n);

		/* binary and floating point */
		double d;
		float f;
		rz_str_bits64(out, n);
		f = d = core->num->fvalue;
		/* adjust sign for nan floats, different libcs are confused */
		if (isnan(f) && signbit(f)) {
			f = -f;
		}
		if (isnan(d) && signbit(d)) {
			d = -d;
		}

		if (state->mode == RZ_OUTPUT_MODE_JSON) {
			PJ *pj = state->d.pj;
			pj_o(pj);
			if (n >> 32) {
				pj_ks(pj, "int32", rz_strf(number, "%d", (st32)(n & UT32_MAX)));
				pj_ks(pj, "uint32", rz_strf(number, "%u", (ut32)n));
			} else {
				pj_ks(pj, "int64", rz_strf(number, "%" PFMT64d, (st64)n));
				pj_ks(pj, "uint64", rz_strf(number, "%" PFMT64u, (ut64)n));
			}
			pj_ks(pj, "hex", rz_strf(number, "0x%08" PFMT64x, n));
			pj_ks(pj, "octal", rz_strf(number, "0%" PFMT64o, n));
			pj_ks(pj, "unit", unit);
			pj_ks(pj, "segment", rz_strf(number, "%04x:%04x", s, a));
			pj_ks(pj, "fvalue", rz_strf(number, "%.1lf", core->num->fvalue));
			pj_ks(pj, "float", rz_strf(number, "%ff", f));
			pj_ks(pj, "double", rz_strf(number, "%lf", d));
			pj_ks(pj, "binary", rz_strf(number, "0b%s", out));
			/* ternary */
			rz_num_to_trits(out, n);
			pj_ks(pj, "trits", rz_strf(number, "0t%s", out));

			pj_end(pj);
			rz_cons_printf("%s\n", pj_string(pj));
		} else {
			if (n >> 32) {
				rz_cons_printf("int64   %" PFMT64d "\n", (st64)n);
				rz_cons_printf("uint64  %" PFMT64u "\n", (ut64)n);
			} else {
				rz_cons_printf("int32   %d\n", (st32)n);
				rz_cons_printf("uint32  %u\n", (ut32)n);
			}
			rz_cons_printf("hex     0x%" PFMT64x "\n", n);
			rz_cons_printf("octal   0%" PFMT64o "\n", n);
			rz_cons_printf("unit    %s\n", unit);
			rz_cons_printf("segment %04x:%04x\n", s, a);
			char *asnum = rz_num_as_string(NULL, n, false);
			if (asnum) {
				rz_cons_printf("string  \"%s\"\n", asnum);
				free(asnum);
			}
			rz_cons_printf("fvalue  %.1lf\n", core->num->fvalue);
			rz_cons_printf("float   %ff\n", f);
			rz_cons_printf("double  %lf\n", d);
			rz_cons_printf("binary  0b%s\n", out);
			/* ternary*/
			rz_num_to_trits(out, n);
			rz_cons_printf("trits   0t%s\n", out);
		}
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_active_tab_zero_handler(RzCore *core, int argc, const char **argv) {
	core->curtab = 0;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_active_tab_next_handler(RzCore *core, int argc, const char **argv) {
	if (core->curtab < 0) {
		core->curtab = 0;
	}
	core->curtab++;
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_generate_random_number_handler(RzCore *core, int argc, const char **argv) {
	// TODO : Add support for 64bit random numbers
	ut64 b = 0;
	ut32 r = UT32_MAX;

	if (argc == 1) {
		r = 0;
	}

	if (argc == 2) {
		const char *out = argv[1];
		if (argc == 3) {
			const char *p = argv[2];
			b = (ut32)rz_num_math(core->num, out);
			r = (ut32)rz_num_math(core->num, p) - b;
		} else {
			r = (ut32)rz_num_math(core->num, out);
		}
	}

	if (!r) {
		r = UT32_MAX >> 1;
	}
	core->num->value = (ut64)(b + rz_num_rand(r));
	rz_cons_printf("0x%" PFMT64x "\n", core->num->value);

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_ascii_table_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%s", ret_ascii_table());
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_binary_handler(RzCore *core, int argc, const char **argv) {
	char out[128] = RZ_EMPTY;
	ut64 n;
	n = rz_num_math(core->num, argv[1]);
	rz_num_to_bits(out, n);
	rz_cons_printf("%sb\n", out);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_base64_encode_handler(RzCore *core, int argc, const char **argv) {
	char *buf = NULL;
	for (int i = 1; i < argc; i++) {
		const int buflen = (strlen(argv[i]) * 4) + 1;
		buf = (char *)realloc((void *)buf, buflen * sizeof(char));
		if (!buf) {
			RZ_LOG_ERROR("core: Out of memory!");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_base64_encode(buf, (const ut8 *)argv[i], strlen(argv[i]));
		rz_cons_println((const char *)buf);
	}
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_base64_decode_handler(RzCore *core, int argc, const char **argv) {
	ut8 *buf = NULL;
	for (int i = 1; i < argc; i++) {
		const int buflen = (strlen(argv[i]) * 4) + 1;
		buf = (ut8 *)realloc((void *)buf, buflen * sizeof(ut8));
		if (!buf) {
			RZ_LOG_ERROR("core: Out of memory!");
			return RZ_CMD_STATUS_ERROR;
		}
		rz_base64_decode(buf, argv[i], -1);
		rz_cons_println((const char *)buf);
	}
	free(buf);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_boundaries_prot_handler(RzCore *core, int argc, const char **argv) {
	const char *mode = rz_str_trim_head_ro(argv[0]);
	RzList *list = rz_core_get_boundaries_prot(core, -1, mode, "search");
	if (!list) {
		RZ_LOG_ERROR("core: Failed to get boundaries protection values in RzList");
		return RZ_CMD_STATUS_ERROR;
	}
	RzListIter *iter;
	RzIOMap *map;
	rz_list_foreach (list, iter, map) {
		rz_cons_printf("0x%" PFMT64x " 0x%" PFMT64x "\n", map->itv.addr, rz_itv_end(map->itv));
	}
	rz_list_free(list);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_djb2_hash_handler(RzCore *core, int argc, const char **argv) {
	for (int i = 1; i < argc; i++) {
		ut32 hash = (ut32)rz_str_djb2_hash(argv[i]);
		rz_cons_printf("0x%08x\n", hash);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_flush_console_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_flush();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_bitstring_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = 0;
	n = rz_num_get(core->num, argv[1]);
	char out[128] = RZ_EMPTY;
	rz_str_bits(out, (const ut8 *)&n, sizeof(n) * 8, argv[2]);
	rz_cons_println(out);

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_eval_expr_print_octal_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_cons_printf("0%" PFMT64o "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_print_init_time_values_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("plug.init = %" PFMT64d "\n"
		       "plug.load = %" PFMT64d "\n"
		       "file.load = %" PFMT64d "\n",
		core->times->loadlibs_init_time,
		core->times->loadlibs_time,
		core->times->file_open_time);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_num_to_units_handler(RzCore *core, int argc, const char **argv) {
	char unit[8];
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_num_units(unit, sizeof(unit), n);
	rz_cons_println(unit);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_last_eval_expr_handler(RzCore *core, int argc, const char **argv) {
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_num_math(core->num, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_handler(RzCore *core, int argc, const char **argv) {
	ut64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%" PFMT64x "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_hex_handler(RzCore *core, int argc, const char **argv) {
	ut64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("0x%08" PFMT64x "\n", n); // differs from ?v here 0x%08
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_i1_handler(RzCore *core, int argc, const char **argv) {
	ut64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", (st8)(n & UT8_MAX));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_i2_handler(RzCore *core, int argc, const char **argv) {
	ut64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", (st16)(n & UT16_MAX));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_value_i4_handler(RzCore *core, int argc, const char **argv) {
	ut64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%d\n", (st32)(n & UT32_MAX));
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_show_value_i8_handler(RzCore *core, int argc, const char **argv) {
	ut64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%" PFMT64d "\n", (st64)(n & UT64_MAX));
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_show_value_int_handler(RzCore *core, int argc, const char **argv) {
	st64 n;
	if (argc == 1) {
		n = core->num->value;
	} else {
		n = rz_num_math(core->num, argv[1]);
	}
	if (core->num->dbz) {
		RZ_LOG_ERROR("core: RzNum ERROR: Division by Zero\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%" PFMT64d "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_core_num_value_handler(RzCore *core, int argc, const char **argv) {
	rz_num_math(core->num, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_compare_and_set_core_num_value_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = strcmp(argv[1], argv[2]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_positive_handler(RzCore *core, int argc, const char **argv) {
	st64 n = (st64)core->num->value;
	if (n > 0) {
		rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_negative_handler(RzCore *core, int argc, const char **argv) {
	st64 n = (st64)core->num->value;
	if (n < 0) {
		rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_zero_handler(RzCore *core, int argc, const char **argv) {
	if (core->num->value == 0) {
		core->num->value = rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

/* RZ_IPI RzCmdStatus rz_show_help_at_handler(RzCore *core, int argc, const char **argv) { */
/* 	rz_core_cmd_help(core, help_msg_at); */
/* 	return RZ_CMD_STATUS_OK; */
/* } */

RZ_IPI RzCmdStatus rz_show_help_tasks_handler(RzCore *core, int argc, const char **argv) {
	helpCmdTasks(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_help_percent_handler(RzCore *core, int argc, const char **argv) {
	cmd_help_percent(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_help_vars_handler(RzCore *core, int argc, const char **argv) {
	rz_core_help_vars_print(core);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_help_dollar_handler(RzCore *core, int argc, const char **argv) {
	rz_core_cmd_help(core, help_msg_question_v);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_info_handler(RzCore *core, int argc, const char **argv) {
	char *v = rz_version_str(NULL);
	rz_cons_printf("%s\n", v);
	free(v);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_numeric_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", vernum(RZ_VERSION));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_json_handler(RzCore *core, int argc, const char **argv) {
	PJ *pj = pj_new();
	if (!pj) {
		RZ_LOG_ERROR("core: Out of memory!");
		return RZ_CMD_STATUS_ERROR;
	}
	pj_o(pj);
	pj_ks(pj, "arch", RZ_SYS_ARCH);
	pj_ks(pj, "os", RZ_SYS_OS);
	pj_ki(pj, "bits", RZ_SYS_BITS);
	pj_ki(pj, "major", RZ_VERSION_MAJOR);
	pj_ki(pj, "minor", RZ_VERSION_MINOR);
	pj_ki(pj, "patch", RZ_VERSION_PATCH);
	pj_ki(pj, "number", RZ_VERSION_NUMBER);
	pj_ki(pj, "nversion", vernum(RZ_VERSION));
	pj_ks(pj, "version", RZ_VERSION);
	pj_end(pj);
	rz_cons_printf("%s\n", pj_string(pj));
	pj_free(pj);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_numeric2_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", RZ_VERSION_NUMBER);
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_show_version_quiet_mode_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_println(RZ_VERSION);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_major_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", RZ_VERSION_MAJOR);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_minor_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", RZ_VERSION_MINOR);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_patch_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", RZ_VERSION_PATCH);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_compute_string_length_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = strlen(argv[1]);
	rz_cons_printf("%" PFMT64d "\n", core->num->value);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_compute_string_length_quiet_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = strlen(argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_calc_expr_show_hex_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	rz_cons_printf("%" PFMT64x "\n", n);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_ascii_to_hex_handler(RzCore *core, int argc, const char **argv) {
	const char *str = argv[1];
	int n = strlen(str);
	for (int i = 0; i < n; i++) {
		rz_cons_printf("%02x", str[i]);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_numeric_expr_to_hex_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = rz_num_math(core->num, argv[1]);
	int bits = rz_num_to_bits(NULL, n) / 8;
	for (int i = 0; i < bits; i++) {
		rz_cons_printf("%02x", (ut8)((n >> (i * 8)) & 0xff));
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_hex_to_ascii_handler(RzCore *core, int argc, const char **argv) {
	ut8 *out = malloc(strlen(argv[1]) + 1);
	if (out) {
		int len = rz_hex_str2bin(argv[1], out);
		if (len >= 0) {
			out[len] = 0;
			rz_cons_println((const char *)out);
		} else {
			RZ_LOG_ERROR("core: Error parsing the hexpair string\n");
		}
		free(out);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_clippy_echo_handler(RzCore *core, int argc, const char **argv) {
	rz_core_clippy_print(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_echo_msg_newline_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 1) {
		const char *msg = argv[1];
		// TODO: replace all ${flagname} by its value in hexa
		char *newmsg = filterFlags(core, msg);
		rz_str_unescape(newmsg);
		rz_cons_print(newmsg);
		free(newmsg);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_echo_msg_no_newline_handler(RzCore *core, int argc, const char **argv) {
	const char *msg = argv[1];
	// TODO: replace all ${flagname} by its value in hexa
	char *newmsg = filterFlags(core, msg);
	rz_str_unescape(newmsg);
	rz_cons_print(newmsg);
	free(newmsg);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_echo_gotoxy_handler(RzCore *core, int argc, const char **argv) {
	int x = atoi(argv[1]);
	int y = atoi(argv[2]);
	rz_cons_gotoxy(x, y);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_echo_goto_column_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_column(rz_num_math(core->num, argv[1]));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_echo_show_progress_handler(RzCore *core, int argc, const char **argv) {
	ut64 pc = rz_num_math(core->num, argv[1]);
	RzBarOptions opts = {
		.unicode = rz_config_get_b(core->config, "scr.utf8"),
		.thinline = !rz_config_get_b(core->config, "scr.hist.block"),
		.legend = true,
		.offset = rz_config_get_b(core->config, "hex.offset"),
		.offpos = 0,
		.cursor = false,
		.curpos = 0,
		.color = rz_config_get_i(core->config, "scr.color")
	};
	RzStrBuf *strbuf = rz_progressbar(&opts, pc, 80);
	if (!strbuf) {
		RZ_LOG_ERROR("Cannot generate progressbar\n");
	} else {
		char *bar = rz_strbuf_drain(strbuf);
		rz_cons_print(bar);
		free(bar);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_set_console_title_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_set_title(argv[1]);
	return RZ_CMD_STATUS_OK;
}
RZ_IPI RzCmdStatus rz_generate_sequence_handler(RzCore *core, int argc, const char **argv) {
	ut64 from, to, step;
	from = rz_num_math(core->num, argv[1]);
	to = rz_num_math(core->num, argv[2]);
	if (argc == 4) {
		step = rz_num_math(core->num, argv[3]);
		if (step == 0) {
			step = 1;
		}
	} else {
		step = 1;
	}

	for (; from <= to; from += step)
		rz_cons_printf("%" PFMT64d " ", from);
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_phys2virt_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = argc == 2 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 vaddr = rz_io_p2v(core->io, n);
	if (vaddr == UT64_MAX) {
		rz_cons_printf("no map at 0x%08" PFMT64x "\n", n);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\n", vaddr);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_virt2phys_handler(RzCore *core, int argc, const char **argv) {
	ut64 n = argc == 2 ? rz_num_math(core->num, argv[1]) : core->offset;
	ut64 paddr = rz_io_v2p(core->io, n);
	if (paddr == UT64_MAX) {
		rz_cons_printf("no map at 0x%08" PFMT64x "\n", n);
	} else {
		rz_cons_printf("0x%08" PFMT64x "\n", paddr);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_yank_hud_file_handler(RzCore *core, int argc, const char **argv) {
	rz_core_yank_hud_file(core, argv[1]);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_numerical_expr_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	char foo[1024];
	rz_cons_flush();
	// TODO: rz_cons_input()
	snprintf(foo, sizeof(foo) - 1, "%s: ", argv[1]);
	rz_line_set_prompt(foo);
	rz_cons_fgets(foo, sizeof(foo), 0, NULL);
	foo[sizeof(foo) - 1] = 0;
	rz_core_yank_set_str(core, RZ_CORE_FOREIGN_ADDR, foo);
	core->num->value = rz_num_math(core->num, foo);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yesno_no_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_cons_yesno(0, "%s? (y/N)", argv[1]);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yesno_yes_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_cons_yesno(0, "%s? (Y/n)", argv[1]);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_any_key_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	rz_cons_any_key(NULL);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_yank_hud_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = rz_core_yank_hud_path(core, argv[1], 0) == true;
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_msg_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	rz_cons_message(argv[1]);
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_input_conditional_handler(RzCore *core, int argc, const char **argv) {
	if (!rz_cons_is_interactive()) {
		RZ_LOG_ERROR("core: Not running in interactive mode\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	core->num->value = !rz_num_conditional(core->num, argv[1]);
	rz_cons_printf("%s\n", rz_str_bool(!core->num->value));
	rz_cons_set_raw(0);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_get_addr_references_handler(RzCore *core, int argc, const char **argv) {
	ut64 addr = rz_num_math(core->num, argv[1]);
	char *rstr = core->print->hasrefs(core->print->user, addr, true);
	if (!rstr) {
		RZ_LOG_ERROR("core: Cannot get refs\n");
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(rstr);
	free(rstr);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_calculate_command_time_handler(RzCore *core, int argc, const char **argv) {
	ut64 start = rz_time_now_mono();
	rz_core_cmd(core, argv[1], 0);
	ut64 end = rz_time_now_mono();
	double seconds = (double)(end - start) / RZ_USEC_PER_SEC;
	core->num->value = (ut64)seconds;
	rz_cons_printf("%lf\n", seconds);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_exec_cmd_if_core_num_value_positive2_handler(RzCore *core, int argc, const char **argv) {
	if (core->num->value) {
		core->num->value = rz_core_cmd(core, argv[1], 0);
	}
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_help_handler(RzCore *core, int argc, const char **argv) {
	const char *cmd_color = rz_cons_singleton()->context->pal.help;
	const char *reset = rz_cons_singleton()->context->pal.reset;
	rz_cons_printf("Welcome to Rizin!\n\n");
	rz_cons_printf("Type %s?%s for a list of commands available.\n", cmd_color, reset);
	rz_cons_printf("Append %s?%s to any command to get the list of sub-commands or more details about a specific command.\n", cmd_color, reset);
	rz_cons_printf("Append %s??%s to any command to get the full description of a command, e.g. with examples.\n", cmd_color, reset);
	rz_cons_printf("\n");
	rz_cons_printf("Commands output can be redirected as in a regular shell, see %s>?%s for more info.\n", cmd_color, reset);
	rz_cons_printf("You can grep commands output with the 'internal grep', see %s~?%s for more info.\n", cmd_color, reset);
	rz_cons_printf("You can pipe an internal Rizin command to a system program, see %s|?%s for more info.\n", cmd_color, reset);
	rz_cons_printf("\n");
	rz_cons_printf("Chain multiple commands with %s;%s.\n", cmd_color, reset);
	rz_cons_printf("Temporary modifiers are your friends, see %s@?%s for more info, but here some useful ones:\n", cmd_color, reset);
	rz_cons_printf(" - %s@ %s temporarily switch to a different address\n", cmd_color, reset);
	rz_cons_printf(" - %s@a:<arch>%s temporarily switch to a different architecture\n", cmd_color, reset);
	rz_cons_printf(" - %s@e:<varname>=<varvalue>%s temporarily change an eval variable\n", cmd_color, reset);
	rz_cons_printf("\n");
	rz_cons_printf("There are a lot of settings that customize Rizin's behaviour, see them with %sel%s. Have a look at %se?%s to know how to interact with them.\n", cmd_color, reset, cmd_color, reset);
	rz_cons_printf("You can save your preferred settings in %s~/.rizinrc%s.\n", cmd_color, reset);
	return RZ_CMD_STATUS_OK;
}
