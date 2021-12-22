// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stddef.h>
#include "rz_cons.h"
#include "rz_core.h"

static const char *help_msg_f[] = {
	"Usage: f", "[?] [flagname]", " # Manage offset-name flags",
	"f", "", "list flags (will only list flags from selected flagspaces)",
	"f?", "flagname", "check if flag exists or not, See ?? and ?!",
	"f.", " [*[*]]", "list local per-function flags (*) as rizin commands",
	"f.", "blah=$$+12", "set local function label named 'blah'",
	"f.", " fname", "list all local labels for the given function",
	"f,", "", "table output for flags",
	"f*", "", "list flags in r commands",
	"f", " name 12 @ 33", "set flag 'name' with length 12 at offset 33",
	"f", " name = 33", "alias for 'f name @ 33' or 'f name 1 33'",
	"f", " name 12 33 [cmt]", "same as above + optional comment",
	"f-", ".blah@fcn.foo", "delete local label from function at current seek (also f.-)",
	"f--", "", "delete all flags and flagspaces (deinit)",
	"f+", "name 12 @ 33", "like above but creates new one if doesnt exist",
	"f-", "name", "remove flag 'name'",
	"f-", "@addr", "remove flag at address expression",
	"f=", " [glob]", "list range bars graphics with flag offsets and sizes",
	"fa", " [name] [alias]", "alias a flag to evaluate an expression",
	"fb", " [addr]", "set base address for new flags",
	"fb", " [addr] [flag*]", "move flags matching 'flag' to relative addr",
	"fc", "[?][name] [color]", "set color for given flag",
	"fC", " [name] [cmt]", "set comment for given flag",
	"fd", "[?] addr", "return flag+delta",
	"fe-", "", "resets the enumerator counter",
	"fe", " [name]", "create flag name.#num# enumerated flag. See fe?",
	"ff", " ([glob])", "distance in bytes to reach the next flag (see sn/sp)",
	"fi", " [size] | [from] [to]", "show flags in current block or range",
	"fg", "[*] ([prefix])", "construct a graph with the flag names",
	"fj", "", "list flags in JSON format",
	"fl", " (@[flag]) [size]", "show or set flag length (size)",
	"fla", " [glob]", "automatically compute the size of all flags matching glob",
	"fm", " addr", "move flag at current offset to new address",
	"fn", "", "list flags displaying the real name (demangled)",
	"fnj", "", "list flags displaying the real name (demangled) in JSON format",
	"fN", "", "show real name of flag at current address",
	"fN", " [[name]] [realname]", "set flag real name (if no flag name current seek one is used)",
	"fo", "", "show fortunes",
	"fO", " [glob]", "flag as ordinals (sym.* func.* method.*)",
	//" fc [name] [cmt]  ; set execution command for a specific flag"
	"fr", " [[old]] [new]", "rename flag (if no new flag current seek one is used)",
	"fR", "[?] [f] [t] [m]", "relocate all flags matching f&~m 'f'rom, 't'o, 'm'ask",
	"fs", "[?]+-*", "manage flagspaces",
	"ft", "[?]*", "flag tags, useful to find all flags matching some words",
	"fV", "[*-] [nkey] [offset]", "dump/restore visual marks (mK/'K)",
	"fx", "[d]", "show hexdump (or disasm) of flag:flagsize",
	"fq", "", "list flags in quiet mode",
	"fz", "[?][name]", "add named flag zone -name to delete. see fz?[name]",
	NULL
};

static const char *help_msg_fc[] = {
	"Usage: fc", "<flagname> [color]", " # List colors with 'ecs'",
	"fc", " flagname", "Get current color for given flagname",
	"fc", " flagname color", "Set color to a flag",
	NULL
};
static const char *help_msg_fd[] = {
	"Usage: fd[d]", " [offset|flag|expression]", " # Describe flags",
	"fd", " $$", "# describe flag + delta for given offset",
	"fd.", " $$", "# check flags in current address (no delta)",
	"fdd", " $$", "# describe flag without space restrictions",
	"fdw", " [string]", "# filter closest flag by string for current offset",
	NULL
};

static const char *help_msg_fs[] = {
	"Usage: fs", "[*] [+-][flagspace|addr]", " # Manage flagspaces",
	"fs", "", "display flagspaces",
	"fs*", "", "display flagspaces as rizin commands",
	"fsj", "", "display flagspaces in JSON",
	"fs", " *", "select all flagspaces",
	"fs", " flagspace", "select flagspace or create if it doesn't exist",
	"fs", "-flagspace", "remove flagspace",
	"fs", "-*", "remove all flagspaces",
	"fs", "+foo", "push previous flagspace and set",
	"fs", "-", "pop to the previous flagspace",
	"fs", "-.", "remove the current flagspace",
	"fsq", "", "list flagspaces in quiet mode",
	"fsm", " [addr]", "move flags at given address to the current flagspace",
	"fss", "", "display flagspaces stack",
	"fss*", "", "display flagspaces stack in rizin commands",
	"fssj", "", "display flagspaces stack in JSON",
	"fsr", " newname", "rename selected flagspace",
	NULL
};

static const char *help_msg_fz[] = {
	"Usage: f", "[?|-name| name] [@addr]", " # Manage flagzones",
	" fz", " math", "add new flagzone named 'math'",
	" fz-", "math", "remove the math flagzone",
	" fz-", "*", "remove all flagzones",
	" fz.", "", "show around flagzone context",
	" fz:", "", "show what's in scr.flagzone for visual",
	" fz*", "", "dump into rizin commands, for projects",
	NULL
};

static const char *help_msg_ft[] = {
	"Usage: ft", "[?ln] [k] [v ...]", " # Flag tags",
	"ft", " tag strcpy strlen ...", "set words for the 'string' tag",
	"ft", " tag", "get offsets of all matching flags",
	"ft", "", "list all tags",
	"ftn", " tag", "get matching flagnames fot given tag",
	"ftw", "", "flag tags within this file",
	"ftj", "", "list all flagtags in JSON format",
	"ft*", "", "list all flagtags in rizin commands",
	NULL
};

static bool listFlag(RzFlagItem *flag, void *user) {
	rz_list_append(user, flag);
	return true;
}

static size_t countMatching(const char *a, const char *b) {
	size_t matches = 0;
	for (; *a && *b; a++, b++) {
		if (*a != *b) {
			break;
		}
		matches++;
	}
	return matches;
}

static const char *__isOnlySon(RzCore *core, RzList *flags, const char *kw) {
	RzListIter *iter;
	RzFlagItem *f;

	size_t count = 0;
	char *fname = NULL;
	rz_list_foreach (flags, iter, f) {
		if (!strncmp(f->name, kw, strlen(kw))) {
			count++;
			if (count > 1) {
				return NULL;
			}
			fname = f->name;
		}
	}
	return fname;
}

static RzList *__childrenFlagsOf(RzCore *core, RzList *flags, const char *prefix) {
	RzList *list = rz_list_newf(free);
	RzListIter *iter, *iter2;
	RzFlagItem *f, *f2;
	char *fn;

	const size_t prefix_len = strlen(prefix);
	rz_list_foreach (flags, iter, f) {
		if (prefix_len > 0 && strncmp(f->name, prefix, prefix_len)) {
			continue;
		}
		if (prefix_len > strlen(f->name)) {
			continue;
		}
		if (rz_cons_is_breaked()) {
			break;
		}
		const char *name = f->name;
		int name_len = strlen(name);
		rz_list_foreach (flags, iter2, f2) {
			if (prefix_len > strlen(f2->name)) {
				continue;
			}
			if (prefix_len > 0 && strncmp(f2->name, prefix, prefix_len)) {
				continue;
			}
			int matching = countMatching(name, f2->name);
			if (matching < prefix_len || matching == name_len) {
				continue;
			}
			if (matching > name_len) {
				break;
			}
			if (matching < name_len) {
				name_len = matching;
			}
		}
		char *kw = rz_str_ndup(name, name_len + 1);
		const int kw_len = strlen(kw);
		const char *only = __isOnlySon(core, flags, kw);
		if (only) {
			free(kw);
			kw = strdup(only);
		} else {
			const char *fname = NULL;
			size_t fname_len = 0;
			rz_list_foreach (flags, iter2, f2) {
				if (strncmp(f2->name, kw, kw_len)) {
					continue;
				}
				if (fname) {
					int matching = countMatching(fname, f2->name);
					if (fname_len) {
						if (matching < fname_len) {
							fname_len = matching;
						}
					} else {
						fname_len = matching;
					}
				} else {
					fname = f2->name;
				}
			}
			if (fname_len > 0) {
				free(kw);
				kw = rz_str_ndup(fname, fname_len);
			}
		}

		bool found = false;
		rz_list_foreach (list, iter2, fn) {
			if (!strcmp(fn, kw)) {
				found = true;
				break;
			}
		}
		if (found) {
			free(kw);
		} else {
			if (strcmp(prefix, kw)) {
				rz_list_append(list, kw);
			} else {
				free(kw);
			}
		}
	}
	return list;
}

static void __printRecursive(RzCore *core, RzList *list, const char *prefix, int mode, int depth);

static void __printRecursive(RzCore *core, RzList *flags, const char *prefix, int mode, int depth) {
	char *fn;
	RzListIter *iter;
	const int prefix_len = strlen(prefix);
	// eprintf ("# fg %s\n", prefix);
	if (mode == '*' && !*prefix) {
		rz_cons_printf("agn root\n");
	}
	if (rz_flag_get(core->flags, prefix)) {
		return;
	}
	RzList *children = __childrenFlagsOf(core, flags, prefix);
	rz_list_foreach (children, iter, fn) {
		if (!strcmp(fn, prefix)) {
			continue;
		}
		if (mode == '*') {
			rz_cons_printf("agn %s %s\n", fn, fn + prefix_len);
			rz_cons_printf("age %s %s\n", *prefix ? prefix : "root", fn);
		} else {
			rz_cons_printf("%s %s\n", rz_str_pad(' ', prefix_len), fn + prefix_len);
		}
		// rz_cons_printf (".fg %s\n", fn);
		__printRecursive(core, flags, fn, mode, depth + 1);
	}
	rz_list_free(children);
}

static void __flag_graph(RzCore *core, const char *input, int mode) {
	RzList *flags = rz_list_newf(NULL);
	rz_flag_foreach_space(core->flags, rz_flag_space_cur(core->flags), listFlag, flags);
	__printRecursive(core, flags, input, mode, 0);
	rz_list_free(flags);
}

static void spaces_list(RzSpaces *sp, RzOutputMode mode) {
	RzSpaceIter it;
	RzSpace *s;
	const RzSpace *cur = rz_spaces_current(sp);
	PJ *pj = NULL;
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj = pj_new();
		pj_a(pj);
	}
	rz_spaces_foreach(sp, it, s) {
		int count = rz_spaces_count(sp, s->name);
		if (mode == RZ_OUTPUT_MODE_JSON) {
			pj_o(pj);
			pj_ks(pj, "name", s->name);
			pj_ki(pj, "count", count);
			pj_kb(pj, "selected", cur == s);
			pj_end(pj);
		} else if (mode == RZ_OUTPUT_MODE_QUIET) {
			rz_cons_printf("%s\n", s->name);
		} else if (mode == RZ_OUTPUT_MODE_RIZIN) {
			rz_cons_printf("%s %s\n", sp->name, s->name);
		} else {
			rz_cons_printf("%5d %c %s\n", count, (!cur || cur == s) ? '*' : '.',
				s->name);
		}
	}
	if (mode == RZ_OUTPUT_MODE_RIZIN && rz_spaces_current(sp)) {
		rz_cons_printf("%s %s # current\n", sp->name, rz_spaces_current_name(sp));
	}
	if (mode == RZ_OUTPUT_MODE_JSON) {
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI void rz_core_flag_describe(RzCore *core, ut64 addr, bool strict_offset, RzOutputMode mode) {
	RzFlagItem *f = rz_flag_get_at(core->flags, addr, !strict_offset);
	if (f) {
		if (f->offset != addr) {
			if (mode == RZ_OUTPUT_MODE_JSON) {
				PJ *pj = pj_new();
				pj_o(pj);
				pj_kn(pj, "offset", f->offset);
				pj_ks(pj, "name", f->name);
				// Print flag's real name if defined
				if (f->realname) {
					pj_ks(pj, "realname", f->realname);
				}
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				if (pj) {
					pj_free(pj);
				}
			} else {
				// Print realname if exists and asm.flags.real is enabled
				if (core->flags->realnames && f->realname) {
					rz_cons_printf("%s + %d\n", f->realname,
						(int)(addr - f->offset));
				} else {
					rz_cons_printf("%s + %d\n", f->name,
						(int)(addr - f->offset));
				}
			}
		} else {
			if (mode == RZ_OUTPUT_MODE_JSON) {
				PJ *pj = pj_new();
				pj_o(pj);
				pj_ks(pj, "name", f->name);
				// Print flag's real name if defined
				if (f->realname) {
					pj_ks(pj, "realname", f->realname);
				}
				pj_end(pj);
				rz_cons_println(pj_string(pj));
				pj_free(pj);
			} else {
				// Print realname if exists and asm.flags.real is enabled
				if (core->flags->realnames && f->realname) {
					rz_cons_println(f->realname);
				} else {
					rz_cons_println(f->name);
				}
			}
		}
	}
}

static void cmd_fz(RzCore *core, const char *input) {
	switch (*input) {
	case '?': // "fz?"
		rz_core_cmd_help(core, help_msg_fz);
		break;
	case '.': // "fz."
	{
		const char *a = NULL, *b = NULL;
		rz_flag_zone_around(core->flags, core->offset, &a, &b);
		rz_cons_printf("%s %s\n", a ? a : "~", b ? b : "~");
	} break;
	case ':': // "fz:"
	{
		const char *a, *b;
		int a_len = 0;
		int w = rz_cons_get_size(NULL);
		rz_flag_zone_around(core->flags, core->offset, &a, &b);
		if (a) {
			rz_cons_printf("[<< %s]", a);
			a_len = strlen(a) + 4;
		}
		int padsize = (w / 2) - a_len;
		int title_size = 12;
		if (a || b) {
			char *title = rz_str_newf("[ 0x%08" PFMT64x " ]", core->offset);
			title_size = strlen(title);
			padsize -= strlen(title) / 2;
			const char *halfpad = rz_str_pad(' ', padsize);
			rz_cons_printf("%s%s", halfpad, title);
			free(title);
		}
		if (b) {
			padsize = (w / 2) - title_size - strlen(b) - 4;
			const char *halfpad = padsize > 1 ? rz_str_pad(' ', padsize) : "";
			rz_cons_printf("%s[%s >>]", halfpad, b);
		}
		if (a || b) {
			rz_cons_newline();
		}
	} break;
	case ' ':
		rz_flag_zone_add(core->flags, rz_str_trim_head_ro(input + 1), core->offset);
		break;
	case '-':
		if (input[1] == '*') {
			rz_flag_zone_reset(core->flags);
		} else {
			rz_flag_zone_del(core->flags, input + 1);
		}
		break;
	case '*':
		rz_flag_zone_list(core->flags, '*');
		break;
	case 0:
		rz_flag_zone_list(core->flags, 0);
		break;
	}
}

struct flagbar_t {
	RzCore *core;
	int cols;
};

static bool flagbar_foreach(RzFlagItem *fi, void *user) {
	struct flagbar_t *u = (struct flagbar_t *)user;
	ut64 min = 0, max = rz_io_size(u->core->io);
	RzIOMap *m = rz_io_map_get(u->core->io, fi->offset);
	if (m) {
		min = m->itv.addr;
		max = m->itv.addr + m->itv.size;
	}
	rz_cons_printf("0x%08" PFMT64x " ", fi->offset);
	rz_print_rangebar(u->core->print, fi->offset, fi->offset + fi->size, min, max, u->cols);
	rz_cons_printf("  %s\n", fi->name);
	return true;
}

static void flagbars(RzCore *core, const char *glob) {
	int cols = rz_cons_get_size(NULL);
	cols -= 80;
	if (cols < 0) {
		cols += 80;
	}

	struct flagbar_t u = { .core = core, .cols = cols };
	rz_flag_foreach_space_glob(core->flags, glob, rz_flag_space_cur(core->flags), flagbar_foreach, &u);
}

struct flag_to_flag_t {
	ut64 next;
	ut64 offset;
};

static bool flag_to_flag_foreach(RzFlagItem *fi, void *user) {
	struct flag_to_flag_t *u = (struct flag_to_flag_t *)user;
	if (fi->offset < u->next && fi->offset > u->offset) {
		u->next = fi->offset;
	}
	return true;
}

static int flag_to_flag(RzCore *core, const char *glob) {
	rz_return_val_if_fail(glob, 0);
	glob = rz_str_trim_head_ro(glob);
	struct flag_to_flag_t u = { .next = UT64_MAX, .offset = core->offset };
	rz_flag_foreach_glob(core->flags, glob, flag_to_flag_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->offset) {
		return u.next - core->offset;
	}
	return 0;
}

typedef struct {
	RzTable *t;
} FlagTableData;

static bool __tableItemCallback(RzFlagItem *flag, void *user) {
	FlagTableData *ftd = user;
	if (!RZ_STR_ISEMPTY(flag->name)) {
		RzTable *t = ftd->t;
		const char *spaceName = (flag->space && flag->space->name) ? flag->space->name : "";
		const char *addr = sdb_fmt("0x%08" PFMT64x, flag->offset);
		rz_table_add_row(t, addr, sdb_fmt("%" PFMT64d, flag->size), spaceName, flag->name, NULL);
	}
	return true;
}

static void cmd_flag_table(RzCore *core, const char *input) {
	const char fmt = *input++;
	const char *q = input;
	FlagTableData ftd = { 0 };
	RzTable *t = rz_core_table(core);
	ftd.t = t;
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	rz_table_add_column(t, typeNumber, "addr", 0);
	rz_table_add_column(t, typeNumber, "size", 0);
	rz_table_add_column(t, typeString, "space", 0);
	rz_table_add_column(t, typeString, "name", 0);

	RzSpace *curSpace = rz_flag_space_cur(core->flags);
	rz_flag_foreach_space(core->flags, curSpace, __tableItemCallback, &ftd);
	if (rz_table_query(t, q)) {
		char *s = (fmt == 'j')
			? rz_table_tojson(t)
			: rz_table_tostring(t);
		rz_cons_printf("%s\n", s);
		free(s);
	}
	rz_table_free(t);
}

static void cmd_flag_tags(RzCore *core, const char *input) {
	char mode = input[1];
	for (; *input && !IS_WHITESPACE(*input); input++) {
	}
	char *inp = strdup(input);
	char *arg = inp;
	rz_str_trim(arg);
	if (!*arg && !mode) {
		const char *tag;
		RzListIter *iter;
		RzList *list = rz_flag_tags_list(core->flags, NULL);
		rz_list_foreach (list, iter, tag) {
			rz_cons_printf("%s\n", tag);
		}
		rz_list_free(list);
		free(inp);
		return;
	}
	if (mode == '?') {
		rz_core_cmd_help(core, help_msg_ft);
		free(inp);
		return;
	}
	if (mode == 'w') { // "ftw"
		const char *tag;
		RzListIter *iter;
		RzList *list = rz_flag_tags_list(core->flags, NULL);
		rz_list_foreach (list, iter, tag) {
			rz_cons_printf("%s:\n", tag);
			rz_core_cmdf(core, "ftn %s", tag);
		}
		rz_list_free(list);
		free(inp);
		return;
	}
	if (mode == '*') { // "ft*"
		RzListIter *iter;
		const char *tag;
		RzList *list = rz_flag_tags_list(core->flags, NULL);
		rz_list_foreach (list, iter, tag) {
			const char *flags = sdb_get(core->flags->tags, sdb_fmt("tag.%s", tag), NULL);
			rz_cons_printf("ft %s %s\n", tag, flags);
		}
		rz_list_free(list);
		free(inp);
		return;
	}
	if (mode == 'j') { // "ftj"
		RzListIter *iter, *iter2;
		const char *tag, *flg;
		PJ *pj = pj_new();
		pj_o(pj);
		RzList *list = rz_flag_tags_list(core->flags, NULL);
		rz_list_foreach (list, iter, tag) {
			pj_k(pj, tag);
			pj_a(pj);
			RzList *flags = rz_flag_tags_list(core->flags, tag);
			rz_list_foreach (flags, iter2, flg) {
				pj_s(pj, flg);
			}
			pj_end(pj);
			rz_list_free(flags);
		}
		pj_end(pj);
		rz_list_free(list);
		free(inp);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
		return;
	}
	char *arg1 = strchr(arg, ' ');
	if (arg1) {
		*arg1 = 0;
		const char *a1 = rz_str_trim_head_ro(arg1 + 1);
		rz_flag_tags_set(core->flags, arg, a1);
	} else {
		RzListIter *iter;
		RzFlagItem *flag;
		RzList *flags = rz_flag_tags_get(core->flags, arg);
		switch (mode) {
		case 'n':
			rz_list_foreach (flags, iter, flag) {
				// rz_cons_printf ("0x%08"PFMT64x"\n", flag->offset);
				rz_cons_printf("0x%08" PFMT64x "  %s\n", flag->offset, flag->name);
			}
			break;
		default:
			rz_list_foreach (flags, iter, flag) {
				rz_cons_printf("0x%08" PFMT64x "\n", flag->offset);
			}
			break;
		}
	}
	free(inp);
}

struct rename_flag_t {
	RzCore *core;
	const char *pfx;
	int count;
};

static bool rename_flag_ordinal(RzFlagItem *fi, void *user) {
	struct rename_flag_t *u = (struct rename_flag_t *)user;
	char *newName = rz_str_newf("%s%d", u->pfx, u->count++);
	if (!newName) {
		return false;
	}
	rz_flag_rename(u->core->flags, fi, newName);
	free(newName);
	return true;
}

static void flag_ordinals(RzCore *core, const char *str) {
	const char *glob = rz_str_trim_head_ro(str);
	char *pfx = strdup(glob);
	char *p = strchr(pfx, '*');
	if (p) {
		*p = 0;
	}

	struct rename_flag_t u = { .core = core, .pfx = pfx, .count = 0 };
	rz_flag_foreach_glob(core->flags, glob, rename_flag_ordinal, &u);
	free(pfx);
}

static int cmpflag(const void *_a, const void *_b) {
	const RzFlagItem *flag1 = _a, *flag2 = _b;
	return (flag1->offset - flag2->offset);
}

struct find_flag_t {
	RzFlagItem *win;
	ut64 at;
};

static bool find_flag_after(RzFlagItem *flag, void *user) {
	struct find_flag_t *u = (struct find_flag_t *)user;
	if (flag->offset > u->at && (!u->win || flag->offset < u->win->offset)) {
		u->win = flag;
	}
	return true;
}

static bool find_flag_after_foreach(RzFlagItem *flag, void *user) {
	if (flag->size != 0) {
		return true;
	}

	RzFlag *flags = (RzFlag *)user;
	struct find_flag_t u = { .win = NULL, .at = flag->offset };
	rz_flag_foreach(flags, find_flag_after, &u);
	if (u.win) {
		flag->size = u.win->offset - flag->offset;
	}
	return true;
}

static bool adjust_offset(RzFlagItem *flag, void *user) {
	st64 base = *(st64 *)user;
	flag->offset += base;
	return true;
}

static void print_space_stack(RzFlag *f, int ordinal, const char *name, bool selected, PJ *pj, int mode) {
	bool first = ordinal == 0;
	switch (mode) {
	case 'j': {
		char *ename = rz_str_escape(name);
		if (!ename) {
			return;
		}

		pj_o(pj);
		pj_ki(pj, "ordinal", ordinal);
		pj_ks(pj, "name", ename);
		pj_kb(pj, "selected", selected);
		pj_end(pj);
		free(ename);
		break;
	}
	case '*': {
		const char *fmt = first ? "fs %s\n" : "fs+%s\n";
		rz_cons_printf(fmt, name);
		break;
	}
	default:
		rz_cons_printf("%-2d %s%s\n", ordinal, name, selected ? " (selected)" : "");
		break;
	}
}

static int flag_space_stack_list(RzFlag *f, int mode) {
	RzListIter *iter;
	char *space;
	int i = 0;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new();
		pj_a(pj);
	}
	rz_list_foreach (f->spaces.spacestack, iter, space) {
		print_space_stack(f, i++, space, false, pj, mode);
	}
	const char *cur_name = rz_flag_space_cur_name(f);
	print_space_stack(f, i++, cur_name, true, pj, mode);
	if (mode == 'j') {
		pj_end(pj);
		rz_cons_printf("%s\n", pj_string(pj));
		pj_free(pj);
	}
	return i;
}

typedef struct {
	int rad;
	PJ *pj;
	RzAnalysisFunction *fcn;
} PrintFcnLabelsCtx;

static bool print_function_labels_cb(void *user, const ut64 addr, const void *v) {
	const PrintFcnLabelsCtx *ctx = user;
	const char *name = v;
	switch (ctx->rad) {
	case '*':
	case 1:
		rz_cons_printf("f.%s@0x%08" PFMT64x "\n", name, addr);
		break;
	case 'j':
		pj_kn(ctx->pj, name, addr);
		break;
	default:
		rz_cons_printf("0x%08" PFMT64x " %s   [%s + %" PFMT64d "]\n",
			addr,
			name, ctx->fcn->name,
			addr - ctx->fcn->addr);
	}
	return true;
}

static void print_function_labels_for(RzAnalysisFunction *fcn, int rad, PJ *pj) {
	rz_return_if_fail(fcn && (rad != 'j' || pj));
	bool json = rad == 'j';
	if (json) {
		pj_o(pj);
	}
	PrintFcnLabelsCtx ctx = { rad, pj, fcn };
	ht_up_foreach(fcn->labels, print_function_labels_cb, &ctx);
	if (json) {
		pj_end(pj);
	}
}

static void print_function_labels(RzAnalysis *analysis, RzAnalysisFunction *fcn, int rad) {
	rz_return_if_fail(analysis || fcn);
	PJ *pj = NULL;
	bool json = rad == 'j';
	if (json) {
		pj = pj_new();
	}
	if (fcn) {
		print_function_labels_for(fcn, rad, pj);
	} else {
		if (json) {
			pj_o(pj);
		}
		RzAnalysisFunction *f;
		RzListIter *iter;
		rz_list_foreach (analysis->fcns, iter, f) {
			if (!f->labels->count) {
				continue;
			}
			if (json) {
				pj_k(pj, f->name);
			}
			print_function_labels_for(f, rad, pj);
		}
		if (json) {
			pj_end(pj);
		}
	}
	if (json) {
		rz_cons_println(pj_string(pj));
		pj_free(pj);
	}
}

RZ_IPI int rz_cmd_flag(void *data, const char *input) {
	static int flagenum = 0;
	RzCore *core = (RzCore *)data;
	ut64 off = core->offset;
	char *ptr, *str = NULL;
	RzFlagItem *item;
	char *name = NULL;
	st64 base;

	// TODO: off+=cursor
	if (*input) {
		str = strdup(input + 1);
	}
rep:
	switch (*input) {
	case 'f': // "ff"
		if (input[1] == 's') { // "ffs"
			int delta = flag_to_flag(core, input + 2);
			if (delta > 0) {
				rz_cons_printf("0x%08" PFMT64x "\n", core->offset + delta);
			}
		} else {
			rz_cons_printf("%d\n", flag_to_flag(core, input + 1));
		}
		break;
	case 'e': // "fe"
		switch (input[1]) {
		case ' ':
			ptr = rz_str_newf("%s.%d", input + 2, flagenum);
			(void)rz_flag_set(core->flags, ptr, core->offset, 1);
			flagenum++;
			free(ptr);
			break;
		case '-':
			flagenum = 0;
			break;
		default:
			eprintf("|Usage: fe[-| name] @@= 1 2 3 4\n");
			break;
		}
		break;
	case '=': // "f="
		switch (input[1]) {
		case ' ':
			flagbars(core, input + 2);
			break;
		case 0:
			flagbars(core, NULL);
			break;
		default:
		case '?':
			eprintf("Usage: f= [glob] to grep for matching flag names\n");
			break;
		}
		break;
	case 'a':
		if (input[1] == ' ') {
			RzFlagItem *fi;
			RZ_FREE(str);
			str = strdup(input + 2);
			ptr = strchr(str, '=');
			if (!ptr)
				ptr = strchr(str, ' ');
			if (ptr)
				*ptr++ = 0;
			name = (char *)rz_str_trim_head_ro(str);
			ptr = (char *)rz_str_trim_head_ro(ptr);
			fi = rz_flag_get(core->flags, name);
			if (!fi)
				fi = rz_flag_set(core->flags, name,
					core->offset, 1);
			if (fi) {
				rz_flag_item_set_alias(fi, ptr);
			} else {
				eprintf("Cannot find flag '%s'\n", name);
			}
		} else {
			eprintf("Usage: fa flagname flagalias\n");
		}
		break;
	case 'V': // visual marks
		switch (input[1]) {
		case '-':
			rz_core_visual_mark_reset(core);
			break;
		case ' ': {
			int n = atoi(input + 1);
			if (n + ASCII_MAX + 1 < UT8_MAX) {
				const char *arg = strchr(input + 2, ' ');
				ut64 addr = arg ? rz_num_math(core->num, arg) : core->offset;
				rz_core_visual_mark_set(core, n + ASCII_MAX + 1, addr);
			}
		} break;
		case '?':
			eprintf("Usage: fV[*-] [nkey] [offset]\n");
			eprintf("Dump/Restore visual marks (mK/'K)\n");
			break;
		default:
			rz_core_visual_mark_dump(core);
			break;
		}
		break;
	case 'm': // "fm"
		rz_flag_move(core->flags, core->offset, rz_num_math(core->num, input + 1));
		break;
	case 'R': // "fR"
		switch (*str) {
		case '\0':
			eprintf("Usage: fR [from] [to] ([mask])\n");
			eprintf("Example to relocate PIE flags on debugger:\n"
				" > fR entry0 `dm~:1[1]`\n");
			break;
		case '?':
			rz_cons_println("Usage: fR [from] [to] ([mask])");
			rz_cons_println("Example to relocate PIE flags on debugger:\n"
					" > fR entry0 `dm~:1[1]`");
			break;
		default: {
			char *p = strchr(str + 1, ' ');
			ut64 from, to, mask = 0xffff;
			int ret;
			if (p) {
				char *q = strchr(p + 1, ' ');
				*p = 0;
				if (q) {
					*q = 0;
					mask = rz_num_math(core->num, q + 1);
				}
				from = rz_num_math(core->num, str + 1);
				to = rz_num_math(core->num, p + 1);
				ret = rz_flag_relocate(core->flags, from, mask, to);
				eprintf("Relocated %d flags\n", ret);
			} else {
				eprintf("Usage: fR [from] [to] ([mask])\n");
				eprintf("Example to relocate PIE flags on debugger:\n"
					" > fR entry0 `dm~:1[1]`\n");
			}
		}
		}
		break;
	case 'b': // "fb"
		switch (input[1]) {
		case ' ':
			free(str);
			str = strdup(input + 2);
			ptr = strchr(str, ' ');
			if (ptr) {
				RzFlag *f = core->flags;
				*ptr = 0;
				base = rz_num_math(core->num, str);
				rz_flag_foreach_glob(f, ptr + 1, adjust_offset, &base);
			} else {
				core->flags->base = rz_num_math(core->num, input + 1);
			}
			RZ_FREE(str);
			break;
		case '\0':
			rz_cons_printf("%" PFMT64d " 0x%" PFMT64x "\n",
				core->flags->base,
				core->flags->base);
			break;
		default:
			eprintf("Usage: fb [addr] [[flags*]]\n");
			break;
		}
		break;
	case '+': // "f+'
	case ' ': {
		const char *cstr = rz_str_trim_head_ro(str);
		char *eq = strchr(cstr, '=');
		char *b64 = strstr(cstr, "base64:");
		char *s = strchr(cstr, ' ');
		char *s2 = NULL, *s3 = NULL;
		char *comment = NULL;
		bool comment_needs_free = false;
		ut32 bsze = 1; // core->blocksize;
		int eqdir = 0;

		if (eq && eq > cstr) {
			char *prech = eq - 1;
			if (*prech == '+') {
				eqdir = 1;
				*prech = 0;
			} else if (*prech == '-') {
				eqdir = -1;
				*prech = 0;
			}
		}

		// Get outta here as fast as we can so we can make sure that the comment
		// buffer used on later code can be freed properly if necessary.
		if (*cstr == '.') {
			input++;
			goto rep;
		}
		// Check base64 padding
		if (eq && !(b64 && eq > b64 && (eq[1] == '\0' || (eq[1] == '=' && eq[2] == '\0')))) {
			*eq = 0;
			ut64 arg = rz_num_math(core->num, eq + 1);
			RzFlagItem *item = rz_flag_get(core->flags, cstr);
			if (eqdir && item) {
				off = item->offset + (arg * eqdir);
			} else {
				off = arg;
			}
		}
		if (s) {
			*s = '\0';
			s2 = strchr(s + 1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1] && s2[2]) {
					off = rz_num_math(core->num, s2 + 1);
				}
				s3 = strchr(s2 + 1, ' ');
				if (s3) {
					*s3 = '\0';
					if (!strncmp(s3 + 1, "base64:", 7)) {
						comment = (char *)rz_base64_decode_dyn(s3 + 8, -1);
						comment_needs_free = true;
					} else if (s3[1]) {
						comment = s3 + 1;
					}
				}
			}
			bsze = (s[1] == '=') ? 1 : rz_num_math(core->num, s + 1);
		}

		bool addFlag = true;
		if (input[0] == '+') {
			if ((item = rz_flag_get_at(core->flags, off, false))) {
				addFlag = false;
			}
		}
		if (addFlag) {
			item = rz_flag_set(core->flags, cstr, off, bsze);
		}
		if (item && comment) {
			rz_flag_item_set_comment(item, comment);
			if (comment_needs_free) {
				free(comment);
			}
		}
	} break;
	case '-':
		if (input[1] == '-') {
			rz_flag_unset_all(core->flags);
		} else if (input[1]) {
			const char *flagname = rz_str_trim_head_ro(input + 1);
			while (*flagname == ' ') {
				flagname++;
			}
			if (*flagname == '.') {
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
				if (fcn) {
					rz_analysis_function_delete_label_at(fcn, off);
				} else {
					eprintf("Cannot find function at 0x%08" PFMT64x "\n", off);
				}
			} else {
				if (strchr(flagname, '*')) {
					rz_flag_unset_glob(core->flags, flagname);
				} else {
					rz_flag_unset_name(core->flags, flagname);
				}
			}
		} else {
			rz_flag_unset_off(core->flags, off);
		}
		break;
	case '.': // "f."
		input = rz_str_trim_head_ro(input + 1) - 1;
		if (input[1]) {
			if (input[1] == '*' || input[1] == 'j') {
				if (input[2] == '*') {
					print_function_labels(core->analysis, NULL, input[1]);
				} else {
					RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
					if (fcn) {
						print_function_labels(core->analysis, fcn, input[1]);
					} else {
						eprintf("Cannot find function at 0x%08" PFMT64x "\n", off);
					}
				}
			} else {
				char *name = strdup(input + ((input[2] == ' ') ? 2 : 1));
				RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
				if (name) {
					char *eq = strchr(name, '=');
					if (eq) {
						*eq = 0;
						off = rz_num_math(core->num, eq + 1);
					}
					rz_str_trim(name);
					if (fcn) {
						if (*name == '-') {
							rz_analysis_function_delete_label(fcn, name + 1);
						} else {
							rz_analysis_function_set_label(fcn, name, off);
						}
					} else {
						eprintf("Cannot find function at 0x%08" PFMT64x "\n", off);
					}
					free(name);
				}
			}
		} else {
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
			if (fcn) {
				print_function_labels(core->analysis, fcn, 0);
			} else {
				eprintf("Local flags require a function to work.");
			}
		}
		break;
	case 'l': // "fl"
		if (input[1] == '?') { // "fl?"
			eprintf("Usage: fl[a] [flagname] [flagsize]\n");
		} else if (input[1] == 'a') { // "fla"
			// TODO: we can optimize this if core->flags->flags is sorted by flagitem->offset
			char *glob = strchr(input, ' ');
			if (glob) {
				glob++;
			}
			rz_flag_foreach_glob(core->flags, glob, find_flag_after_foreach, core->flags);
		} else if (input[1] == ' ') { // "fl ..."
			char *p, *arg = strdup(input + 2);
			rz_str_trim(arg);
			p = strchr(arg, ' ');
			if (p) {
				*p++ = 0;
				item = rz_flag_get_i(core->flags,
					rz_num_math(core->num, arg));
				if (item)
					item->size = rz_num_math(core->num, p);
			} else {
				if (*arg) {
					item = rz_flag_get_i(core->flags, core->offset);
					if (item) {
						item->size = rz_num_math(core->num, arg);
					}
				} else {
					item = rz_flag_get_i(core->flags, rz_num_math(core->num, arg));
					if (item) {
						rz_cons_printf("0x%08" PFMT64x "\n", item->size);
					}
				}
			}
			free(arg);
		} else { // "fl"
			item = rz_flag_get_i(core->flags, core->offset);
			if (item)
				rz_cons_printf("0x%08" PFMT64x "\n", item->size);
		}
		break;
#if 0
	case 'd':
		if (input[1] == ' ') {
			char cmd[128];
			RzFlagItem *item = rz_flag_get_i (core->flags,
				rz_num_math (core->num, input+2));
			if (item) {
				rz_cons_printf ("0x%08"PFMT64x"\n", item->offset);
				snprintf (cmd, sizeof (cmd), "pD@%"PFMT64d":%"PFMT64d,
					 item->offset, item->size);
				rz_core_cmd0 (core, cmd);
			}
		} else eprintf ("Missing arguments\n");
		break;
#endif
	case 'z': // "fz"
		cmd_fz(core, input + 1);
		break;
	case 'x':
		if (input[1] == ' ') {
			char cmd[128];
			RzFlagItem *item = rz_flag_get_i(core->flags,
				rz_num_math(core->num, input + 2));
			if (item) {
				rz_cons_printf("0x%08" PFMT64x "\n", item->offset);
				snprintf(cmd, sizeof(cmd), "px@%" PFMT64d ":%" PFMT64d,
					item->offset, item->size);
				rz_core_cmd0(core, cmd);
			}
		} else {
			eprintf("Missing arguments\n");
		}
		break;
	case ',': // "f,"
		cmd_flag_table(core, input);
		break;
	case 't': // "ft"
		cmd_flag_tags(core, input);
		break;
	case 's': // "fs"
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_fs);
			break;
		case '+': {
			char *name = strdup(input + 2);
			if (!name) {
				return 0;
			}
			rz_str_trim(name);
			rz_flag_space_push(core->flags, name);
			free(name);
			break;
		}
		case 'r':
			if (input[2] == ' ') {
				char *newname = strdup(input + 3);
				rz_str_trim(newname);
				rz_flag_space_rename(core->flags, NULL, newname);
				free(newname);
			} else {
				eprintf("Usage: fsr [newname]\n");
			}
			break;
		case 's':
			flag_space_stack_list(core->flags, input[2]);
			break;
		case '-':
			switch (input[2]) {
			case '*':
				rz_flag_space_unset(core->flags, NULL);
				break;
			case '.': {
				const RzSpace *sp = rz_flag_space_cur(core->flags);
				if (sp) {
					rz_flag_space_unset(core->flags, sp->name);
				}
				break;
			}
			case 0:
				rz_flag_space_pop(core->flags);
				break;
			default:
				rz_flag_space_unset(core->flags, input + 2);
				break;
			}
			break;
		case ' ': {
			char *name = strdup(input + 2);
			rz_str_trim(name);
			rz_flag_space_set(core->flags, name);
			free(name);
			break;
		}
		case 'm': {
			RzFlagItem *f;
			ut64 off = core->offset;
			if (input[2] == ' ') {
				off = rz_num_math(core->num, input + 2);
			}
			f = rz_flag_get_i(core->flags, off);
			if (f) {
				f->space = rz_flag_space_cur(core->flags);
			} else {
				eprintf("Cannot find any flag at 0x%" PFMT64x ".\n", off);
			}
		} break;
		case 'j':
			spaces_list(&core->flags->spaces, RZ_OUTPUT_MODE_JSON);
			break;
		case '*':
			spaces_list(&core->flags->spaces, RZ_OUTPUT_MODE_RIZIN);
			break;
		case 'q':
			spaces_list(&core->flags->spaces, RZ_OUTPUT_MODE_QUIET);
			break;
		case '\0':
		default:
			spaces_list(&core->flags->spaces, RZ_OUTPUT_MODE_STANDARD);
			break;
		}
		break;
	case 'g': // "fg"
		switch (input[1]) {
		case '*':
			__flag_graph(core, rz_str_trim_head_ro(input + 2), '*');
			break;
		case ' ':
			__flag_graph(core, rz_str_trim_head_ro(input + 2), ' ');
			break;
		case 0:
			__flag_graph(core, rz_str_trim_head_ro(input + 1), 0);
			break;
		default:
			eprintf("Usage: fg[*] ([prefix])\n");
			break;
		}
		break;
	case 'c': // "fc"
		if (input[1] == '?' || input[1] != ' ') {
			rz_core_cmd_help(core, help_msg_fc);
		} else {
			RzFlagItem *fi;
			const char *ret;
			char *arg = rz_str_trim_dup(input + 2);
			char *color = strchr(arg, ' ');
			if (color && color[1]) {
				*color++ = 0;
			}
			fi = rz_flag_get(core->flags, arg);
			if (fi) {
				ret = rz_flag_item_set_color(fi, color);
				if (!color && ret)
					rz_cons_println(ret);
			} else {
				eprintf("Unknown flag '%s'\n", arg);
			}
			free(arg);
		}
		break;
	case 'C': // "fC"
		if (input[1] == ' ') {
			RzFlagItem *item;
			char *q, *p = strdup(input + 2), *dec = NULL;
			q = strchr(p, ' ');
			if (q) {
				*q = 0;
				item = rz_flag_get(core->flags, p);
				if (item) {
					if (!strncmp(q + 1, "base64:", 7)) {
						dec = (char *)rz_base64_decode_dyn(q + 8, -1);
						if (dec) {
							rz_flag_item_set_comment(item, dec);
							free(dec);
						} else {
							eprintf("Failed to decode base64-encoded string\n");
						}
					} else {
						rz_flag_item_set_comment(item, q + 1);
					}
				} else {
					eprintf("Cannot find flag with name '%s'\n", p);
				}
			} else {
				item = rz_flag_get_i(core->flags, rz_num_math(core->num, p));
				if (item && item->comment) {
					rz_cons_println(item->comment);
				} else {
					eprintf("Cannot find item\n");
				}
			}
			free(p);
		} else
			eprintf("Usage: fC [name] [comment]\n");
		break;
	case 'o': // "fo"
		rz_core_fortune_print_random(core);
		break;
	case 'O': // "fO"
		flag_ordinals(core, input + 1);
		break;
	case 'r':
		if (input[1] == ' ' && input[2]) {
			RzFlagItem *item;
			char *old = str + 1;
			char *new = strchr(old, ' ');
			if (new) {
				*new = 0;
				new ++;
				item = rz_flag_get(core->flags, old);
				if (!item && !strncmp(old, "fcn.", 4)) {
					item = rz_flag_get(core->flags, old + 4);
				}
			} else {
				new = old;
				item = rz_flag_get_i(core->flags, core->offset);
			}
			if (item) {
				if (!rz_flag_rename(core->flags, item, new)) {
					eprintf("Invalid name\n");
				}
			} else {
				eprintf("Usage: fr [[old]] [new]\n");
			}
		}
		break;
	case 'N':
		if (!input[1]) {
			RzFlagItem *item = rz_flag_get_i(core->flags, core->offset);
			if (item) {
				rz_cons_printf("%s\n", item->realname);
			}
			break;
		} else if (input[1] == ' ' && input[2]) {
			RzFlagItem *item;
			char *name = str + 1;
			char *realname = strchr(name, ' ');
			if (realname) {
				*realname = 0;
				realname++;
				item = rz_flag_get(core->flags, name);
				if (!item && !strncmp(name, "fcn.", 4)) {
					item = rz_flag_get(core->flags, name + 4);
				}
			} else {
				realname = name;
				item = rz_flag_get_i(core->flags, core->offset);
			}
			if (item) {
				rz_flag_item_set_realname(item, realname);
			}
			break;
		}
		eprintf("Usage: fN [[name]] [[realname]]\n");
		break;
	case '\0':
	case 'n': // "fn" "fnj"
	case '*': // "f*"
	case 'j': // "fj"
	case 'q': // "fq"
		if (input[0]) {
			switch (input[1]) {
			case 'j':
			case 'q':
			case 'n':
			case '*':
				input++;
				break;
			}
		}
		if (input[0] && input[1] == '.') {
			const int mode = input[2];
			const RzList *list = rz_flag_get_list(core->flags, core->offset);
			PJ *pj = NULL;
			if (mode == 'j') {
				pj = pj_new();
				pj_a(pj);
			}
			RzListIter *iter;
			RzFlagItem *item;
			rz_list_foreach (list, iter, item) {
				switch (mode) {
				case '*':
					rz_cons_printf("f %s = 0x%08" PFMT64x "\n", item->name, item->offset);
					break;
				case 'j': {
					pj_o(pj);
					pj_ks(pj, "name", item->name);
					pj_ks(pj, "realname", item->realname);
					pj_kn(pj, "offset", item->offset);
					pj_kn(pj, "size", item->size);
					pj_end(pj);
				} break;
				default:
					rz_cons_printf("%s\n", item->name);
					break;
				}
			}
			if (mode == 'j') {
				pj_end(pj);
				char *s = pj_drain(pj);
				rz_cons_printf("%s\n", s);
				free(s);
			}
		} else {
			rz_flag_list(core->flags, *input, input[0] ? input + 1 : "");
		}
		break;
	case 'i': // "fi"
		if (input[1] == ' ' || (input[1] && input[2] == ' ')) {
			char *arg = strdup(rz_str_trim_head_ro(input + 2));
			if (*arg) {
				arg = strdup(rz_str_trim_head_ro(input + 2));
				char *sp = strchr(arg, ' ');
				if (!sp) {
					char *newarg = rz_str_newf("%c0x%" PFMT64x " %s+0x%" PFMT64x,
						input[1], core->offset, arg, core->offset);
					free(arg);
					arg = newarg;
				} else {
					char *newarg = rz_str_newf("%c%s", input[1], arg);
					free(arg);
					arg = newarg;
				}
			} else {
				free(arg);
				arg = rz_str_newf(" 0x%" PFMT64x " 0x%" PFMT64x,
					core->offset, core->offset + core->blocksize);
			}
			rz_flag_list(core->flags, 'i', arg);
			free(arg);
		} else {
			// XXX dupe for prev case
			char *arg = rz_str_newf(" 0x%" PFMT64x " 0x%" PFMT64x,
				core->offset, core->offset + core->blocksize);
			rz_flag_list(core->flags, 'i', arg);
			free(arg);
		}
		break;
	case 'd': // "fd"
	{
		ut64 addr = core->offset;
		char *arg = NULL;
		bool strict_offset = false;
		switch (input[1]) {
		case '?':
			rz_core_cmd_help(core, help_msg_fd);
			if (str) {
				free(str);
			}
			return false;
		case '\0':
			addr = core->offset;
			break;
		case 'd':
			arg = strchr(input, ' ');
			if (arg) {
				addr = rz_num_math(core->num, arg + 1);
			}
			break;
		case '.': // "fd." list all flags at given offset
		{
			RzFlagItem *flag;
			RzListIter *iter;
			bool isJson = false;
			const RzList *flaglist;
			arg = strchr(input, ' ');
			if (arg) {
				addr = rz_num_math(core->num, arg + 1);
			}
			flaglist = rz_flag_get_list(core->flags, addr);
			isJson = strchr(input, 'j');
			PJ *pj = pj_new();
			if (isJson) {
				pj_a(pj);
			}

			// Sometime an address has multiple flags assigned to, show them all
			rz_list_foreach (flaglist, iter, flag) {
				if (flag) {
					if (isJson) {
						pj_o(pj);
						pj_ks(pj, "name", flag->name);
						if (flag->realname) {
							pj_ks(pj, "realname", flag->realname);
						}
						pj_end(pj);

					} else {
						// Print realname if exists and asm.flags.real is enabled
						if (core->flags->realnames && flag->realname) {
							rz_cons_println(flag->realname);
						} else {
							rz_cons_println(flag->name);
						}
					}
				}
			}

			if (isJson) {
				pj_end(pj);
				rz_cons_println(pj_string(pj));
			}

			if (pj) {
				pj_free(pj);
			}

			return 0;
		}
		case 'w': {
			arg = strchr(input, ' ');
			if (!arg) {
				return 0;
			}
			arg++;
			if (!*arg) {
				return 0;
			}

			RzFlag *f = core->flags;
			RzList *temp = rz_flag_all_list(f, true);
			ut64 loff = 0;
			ut64 uoff = 0;
			ut64 curseek = core->offset;
			char *lmatch = NULL, *umatch = NULL;
			RzFlagItem *flag;
			RzListIter *iter;
			rz_list_sort(temp, &cmpflag);
			rz_list_foreach (temp, iter, flag) {
				if (strstr(flag->name, arg) != NULL) {
					if (flag->offset < core->offset) {
						loff = flag->offset;
						lmatch = flag->name;
						continue;
					}
					uoff = flag->offset;
					umatch = flag->name;
					break;
				}
			}
			char *match = (curseek - loff) < (uoff - curseek) ? lmatch : umatch;
			if (match) {
				if (*match) {
					rz_cons_println(match);
				}
			}
			rz_list_free(temp);
			return 0;
		}
		default:
			arg = strchr(input, ' ');
			if (arg) {
				addr = rz_num_math(core->num, arg + 1);
			}
			break;
		}
		RzOutputMode mode = strchr(input, 'j')
			? RZ_OUTPUT_MODE_JSON
			: RZ_OUTPUT_MODE_STANDARD;
		rz_core_flag_describe(core, addr, strict_offset, mode);
	} break;
	case '?':
	default:
		if (input[1]) {
			core->num->value = rz_flag_get(core->flags, input + 1) ? 1 : 0;
		} else {
			rz_core_cmd_help(core, help_msg_f);
			break;
		}
	}
	free(str);
	return 0;
}
