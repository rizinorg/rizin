// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_analysis.h"
#include "rz_bin.h"
#include "rz_cons.h"
#include "rz_core.h"
#include "rz_util.h"
#include "rz_types.h"
#include <sdb.h>

char *getcommapath(RzCore *core);

static const char *help_msg_C[] = {
	"Usage:", "C[-LCvsdfm*?][*?] [...]", " # Metadata management",
	"C", "", "list meta info in human friendly form",
	"C*", "", "list meta info in rizin commands",
	"C*.", "", "list meta info of current offset in rizin commands",
	"C-", " [len] [[@]addr]", "delete metadata at given address range",
	"C.", "", "list meta info of current offset in human friendly form",
	"CC!", " [@addr]", "edit comment with $EDITOR",
	"CC", "[?] [-] [comment-text] [@addr]", "add/remove comment",
	"CC.", "[addr]", "show comment in current address",
	"CCa", "[+-] [addr] [text]", "add/remove comment at given address",
	"CCu", " [comment-text] [@addr]", "add unique comment",
	"CF", "[sz] [fcn-sign..] [@addr]", "function signature",
	"CS", "[-][space]", "manage meta-spaces to filter comments, etc..",
	"C[Cthsdmf]", "", "list comments/types/hidden/strings/data/magic/formatted in human friendly form",
	"C[Cthsdmf]*", "", "list comments/types/hidden/strings/data/magic/formatted in rizin commands",
	"Cd", "[-] [size] [repeat] [@addr]", "hexdump data array (Cd 4 10 == dword [10])",
	"Cd.", " [@addr]", "show size of data at current address",
	"Cf", "[?][-] [sz] [0|cnt][fmt] [a0 a1...] [@addr]", "format memory (see pf?)",
	"Ch", "[-] [size] [@addr]", "hide data",
	"Cm", "[-] [sz] [fmt..] [@addr]", "magic parse (see pm?)",
	"Cs", "[?] [-] [size] [@addr]", "add string",
	"Ct", "[?] [-] [comment-text] [@addr]", "add/remove type analysis comment",
	"Ct.", "[@addr]", "show comment at current or specified address",
	"Cv", "[bsr][?]", "add comments to args",
	"Cz", "[@addr]", "add string (see Cs?)",
	NULL
};

static const char *help_msg_CC[] = {
	"Usage:", "CC[-+!*au] [base64:..|str] @ addr", "",
	"CC!", "", "edit comment using cfg.editor (vim, ..)",
	"CC", " [text]", "append comment at current address",
	"CC", "", "list all comments in human friendly form",
	"CC*", "", "list all comments in rizin commands",
	"CC+", " [text]", "append comment at current address",
	"CC,", " [file]", "show or set comment file",
	"CC-", " @ cmt_addr", "remove comment at given address",
	"CC.", "", "show comment at current offset",
	"CCf", "", "list comments in function",
	"CCf-", "", "delete all comments in current function",
	"CCu", " base64:AA== @ addr", "add comment in base64",
	"CCu", " good boy @ addr", "add good boy comment at given address",
	NULL
};

static const char *help_msg_Ct[] = {
	"Usage: Ct", "[.|-] [@ addr]", " # Manage comments for variable types",
	"Ct", "", "list all variable type comments",
	"Ct", " comment-text [@ addr]", "place comment at current or specified address",
	"Ct.", " [@ addr]", "show comment at current or specified address",
	"Ct-", " [@ addr]", "remove comment at current or specified address",
	NULL
};

static const char *help_msg_CS[] = {
	"Usage: CS", "[*] [+-][metaspace|addr]", " # Manage metaspaces",
	"CS", "", "display metaspaces",
	"CS", " *", "select all metaspaces",
	"CS", " metaspace", "select metaspace or create if it doesn't exist",
	"CS", "-metaspace", "remove metaspace",
	"CS", "-*", "remove all metaspaces",
	"CS", "+foo", "push previous metaspace and set",
	"CS", "-", "pop to the previous metaspace",
	//	"CSm"," [addr]","move metas at given address to the current metaspace",
	"CSr", " newname", "rename selected metaspace",
	NULL
};

static const char *help_msg_Cs[] = {
	"Usage:", "Cs[ga-*.] [size] [@addr]", "",
	"NOTE:", " size", "1 unit in bytes == width in bytes of smallest possible char in encoding,",
	"", "", "  so ascii/latin1/utf8 = 1, utf16le = 2",
	" Cz", " [size] [@addr]", "ditto",
	"Cs", " [size] @addr", "add string (guess latin1/utf16le)",
	"Cs", "", "list all strings in human friendly form",
	"Cs*", "", "list all strings in rizin commands",
	"Cs-", " [@addr]", "remove string",
	"Cs.", "", "show string at current address",
	"Cs..", "", "show string + info about it at current address",
	"Cs.j", "", "show string at current address in JSON",
	"Cs8", " [size] [@addr]", "add utf8 string",
	"Csa", " [size] [@addr]", "add ascii/latin1 string",
	"Csg", " [size] [@addr]", "as above but addr not needed",
	NULL
};

static const char *help_msg_Cvb[] = {
	"Usage:", "Cvb", "[name] [comment]",
	"Cvb?", "", "show this help",
	"Cvb", "", "list all base pointer args/vars comments in human friendly format",
	"Cvb*", "", "list all base pointer args/vars comments in rizin format",
	"Cvb-", "[name]", "delete comments for var/arg at current offset for base pointer",
	"Cvb", " [name]", "Show comments for var/arg at current offset for base pointer",
	"Cvb", " [name] [comment]", "add/append comment for the variable with the current name",
	"Cvb!", "[name]", "edit comment using cfg editor",
	NULL
};

static const char *help_msg_Cvr[] = {
	"Usage:", "Cvr", "[name] [comment]",
	"Cvr?", "", "show this help",
	"Cvr", "", "list all register based args comments in human friendly format",
	"Cvr*", "", "list all register based args comments in rizin format",
	"Cvr-", "[name]", "delete comments for register based arg for that name",
	"Cvr", "[name]", "Show comments for register based arg for that name",
	"Cvr", "[name] [comment]", "add/append comment for the variable",
	"Cvr!", "[name]", "edit comment using cfg editor",
	NULL
};

static const char *help_msg_Cvs[] = {
	"Usage:", "Cvs", "[name] [comment]",
	"Cvs!", "[name]", "edit comment using cfg editor",
	"Cvs", "", "list all stack based args/vars comments in human friendly format",
	"Cvs", "[name] [comment]", "add/append comment for the variable",
	"Cvs", "[name]", "Show comments for stack pointer var/arg with that name",
	"Cvs*", "", "list all stack based args/vars comments in rizin format",
	"Cvs-", "[name]", "delete comments for stack pointer var/arg with that name",
	"Cvs?", "", "show this help",
	NULL
};

RZ_IPI void rz_core_meta_comment_add(RzCore *core, const char *comment, ut64 addr) {
	const char *oldcomment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
	if (!oldcomment || (oldcomment && !strstr(oldcomment, comment))) {
		rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, comment);
	}
}

static int cmd_meta_comment(RzCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[1]) {
	case '?':
		rz_core_cmd_help(core, help_msg_CC);
		break;
	case ',': // "CC,"
		if (input[2] == '?') {
			eprintf("Usage: CC, [file]\n");
		} else if (input[2] == ' ') {
			const char *fn = input + 2;
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
			while (*fn == ' ')
				fn++;
			if (comment && *comment) {
				// append filename in current comment
				char *nc = rz_str_newf("%s ,(%s)", comment, fn);
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, nc);
				free(nc);
			} else {
				char *newcomment = rz_str_newf(",(%s)", fn);
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, newcomment);
				free(newcomment);
			}
		} else {
			const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
			if (comment && *comment) {
				char *cmtfile = rz_str_between(comment, ",(", ")");
				if (cmtfile && *cmtfile) {
					char *cwd = getcommapath(core);
					rz_cons_printf("%s" RZ_SYS_DIR "%s\n", cwd, cmtfile);
					free(cwd);
				}
				free(cmtfile);
			}
		}
		break;
	case '.': {
		ut64 at = input[2] ? rz_num_math(core->num, input + 2) : addr;
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, at);
		if (comment) {
			rz_cons_println(comment);
		}
	} break;
	case 0: // "CC"
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_COMMENT, 0);
		break;
	case 'f': // "CCf"
		switch (input[2]) {
		case '-': // "CCf-"
		{
			ut64 arg = rz_num_math(core->num, input + 2);
			if (!arg) {
				arg = core->offset;
			}
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, arg, 0);
			if (fcn) {
				RzAnalysisBlock *bb;
				RzListIter *iter;
				rz_list_foreach (fcn->bbs, iter, bb) {
					int i;
					for (i = 0; i < bb->size; i++) {
						ut64 addr = bb->addr + i;
						rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, addr, 1);
					}
				}
			}
		} break;
		case 'j': // "CCfj"
			rz_meta_print_list_in_function(core->analysis, RZ_META_TYPE_COMMENT, 'j', core->offset);
			break;
		case '*': // "CCf*"
			rz_meta_print_list_in_function(core->analysis, RZ_META_TYPE_COMMENT, 1, core->offset);
			break;
		default:
			rz_meta_print_list_in_function(core->analysis, RZ_META_TYPE_COMMENT, 0, core->offset);
			break;
		}
		break;
	case 'j': // "CCj"
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_COMMENT, 'j');
		break;
	case '!': {
		char *out;
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
		out = rz_core_editor(core, NULL, comment);
		if (out) {
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, addr, 1);
			rz_meta_set_string(core->analysis,
				RZ_META_TYPE_COMMENT, addr, out);
			free(out);
		}
	} break;
	case '+':
	case ' ': {
		const char *newcomment = rz_str_trim_head_ro(input + 2);
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
		char *text;
		char *nc = strdup(newcomment);
		rz_str_unescape(nc);
		if (comment) {
			text = malloc(strlen(comment) + strlen(newcomment) + 2);
			if (text) {
				strcpy(text, comment);
				strcat(text, " ");
				strcat(text, nc);
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, text);
				free(text);
			} else {
				rz_sys_perror("malloc");
			}
		} else {
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, nc);
		}
		free(nc);
	} break;
	case '*': // "CC*"
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_COMMENT, 1);
		break;
	case '-': // "CC-"
		if (input[2] == '*') { // "CC-*"
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, UT64_MAX, UT64_MAX);
		} else if (input[2]) { // "CC-$$+32"
			ut64 arg = rz_num_math(core->num, input + 2);
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, arg, 1);
		} else { // "CC-"
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, core->offset, 1);
		}
		break;
	case 'u': // "CCu"
		//
		{
			char *comment;
			const char *arg = input + 2;
			while (*arg && *arg == ' ')
				arg++;
			if (!strncmp(arg, "base64:", 7)) {
				char *s = (char *)sdb_decode(arg + 7, NULL);
				if (s) {
					comment = s;
				} else {
					comment = NULL;
				}
			} else {
				comment = strdup(arg);
			}
			if (comment) {
				rz_core_meta_comment_add(core, comment, addr);
				free(comment);
			}
		}
		break;
	case 'a': // "CCa"
	{
		char *s, *p;
		s = strchr(input, ' ');
		if (s) {
			s = strdup(s + 1);
		} else {
			eprintf("Usage\n");
			return false;
		}
		p = strchr(s, ' ');
		if (p) {
			*p++ = 0;
		}
		ut64 addr;
		if (input[2] == '-') {
			if (input[3]) {
				addr = rz_num_math(core->num, input + 3);
				rz_meta_del(core->analysis,
					RZ_META_TYPE_COMMENT,
					addr, 1);
			} else
				eprintf("Usage: CCa-[address]\n");
			free(s);
			return true;
		}
		addr = rz_num_math(core->num, s);
		// Comment at
		if (p) {
			if (input[2] == '+') {
				const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
				if (comment) {
					char *text = rz_str_newf("%s\n%s", comment, p);
					rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, addr, 1, text);
					free(text);
				} else {
					rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, addr, 1, p);
				}
			} else {
				rz_meta_set(core->analysis, RZ_META_TYPE_COMMENT, addr, 1, p);
			}
		} else {
			eprintf("Usage: CCa [address] [comment]\n");
		}
		free(s);
		return true;
	}
	}
	return true;
}

static int cmd_meta_vartype_comment(RzCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[1]) {
	case '?': // "Ct?"
		rz_core_cmd_help(core, help_msg_Ct);
		break;
	case 0: // "Ct"
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_VARTYPE, 0);
		break;
	case ' ': // "Ct <vartype comment> @ addr"
	{
		const char *newcomment = rz_str_trim_head_ro(input + 2);
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_VARTYPE, addr);
		char *nc = strdup(newcomment);
		rz_str_unescape(nc);
		if (comment) {
			char *text = rz_str_newf("%s %s", comment, nc);
			if (text) {
				rz_meta_set_string(core->analysis, RZ_META_TYPE_VARTYPE, addr, text);
				free(text);
			} else {
				rz_sys_perror("malloc");
			}
		} else {
			rz_meta_set_string(core->analysis, RZ_META_TYPE_VARTYPE, addr, nc);
		}
		free(nc);
	} break;
	case '.': // "Ct. @ addr"
	{
		ut64 at = input[2] ? rz_num_math(core->num, input + 2) : addr;
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_VARTYPE, at);
		if (comment) {
			rz_cons_println(comment);
		}
	} break;
	case '-': // "Ct-"
		rz_meta_del(core->analysis, RZ_META_TYPE_VARTYPE, core->offset, 1);
		break;
	default:
		rz_core_cmd_help(core, help_msg_Ct);
		break;
	}

	return true;
}

static int cmd_meta_others(RzCore *core, const char *input) {
	int n, type = input[0], subtype;
	char *t = 0, *p, *p2, name[256];
	int repeat = 1;
	ut64 addr = core->offset;

	if (!type) {
		return 0;
	}

	switch (input[1]) {
	case '?':
		switch (input[0]) {
		case 'f': // "Cf?"
			rz_cons_println(
				"Usage: Cf[-] [sz] [fmt..] [@addr]\n\n"
				"'sz' indicates the byte size taken up by struct.\n"
				"'fmt' is a 'pf?' style format string. It controls only the display format.\n\n"
				"You may wish to have 'sz' != sizeof(fmt) when you have a large struct\n"
				"but have only identified specific fields in it. In that case, use 'fmt'\n"
				"to show the fields you know about (perhaps using 'skip' fields), and 'sz'\n"
				"to match the total struct size in mem.\n");
			break;
		case 's': // "Cs?"
			rz_core_cmd_help(core, help_msg_Cs);
			break;
		default:
			rz_cons_println("See C?");
			break;
		}
		break;
	case '-': // "Cf-", "Cd-", ...
		switch (input[2]) {
		case '*': // "Cf-*", "Cd-*", ...
			rz_meta_del(core->analysis, input[0], 0, UT64_MAX);
			break;
		case ' ':
			p2 = strchr(input + 3, ' ');
			if (p2) {
				ut64 i;
				ut64 size = rz_num_math(core->num, input + 3);
				ut64 rep = rz_num_math(core->num, p2 + 1);
				ut64 cur_addr = addr;
				if (!size) {
					break;
				}
				for (i = 0; i < rep && UT64_MAX - cur_addr > size; i++, cur_addr += size) {
					rz_meta_del(core->analysis, input[0], cur_addr, size);
				}
				break;
			} else {
				addr = rz_num_math(core->num, input + 3);
				/* fallthrough */
			}
		default:
			rz_meta_del(core->analysis, input[0], addr, 1);
			break;
		}
		break;
	case '*': // "Cf*", "Cd*", ...
		rz_meta_print_list_all(core->analysis, input[0], 1);
		break;
	case 'j': // "Cfj", "Cdj", ...
		rz_meta_print_list_all(core->analysis, input[0], 'j');
		break;
	case '!': // "Cf!", "Cd!", ...
	{
		char *out;
		const char *comment = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, addr);
		out = rz_core_editor(core, NULL, comment);
		if (out) {
			rz_meta_del(core->analysis, RZ_META_TYPE_COMMENT, addr, 1);
			rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr, out);
			free(out);
		}
	} break;
	case '.': // "Cf.", "Cd.", ...
		if (input[2] == '.') { // "Cs.."
			ut64 size;
			RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, addr, type, &size);
			if (mi) {
				rz_meta_print(core->analysis, mi, addr, size, input[3], NULL, false);
			}
			break;
		} else if (input[2] == 'j') { // "Cs.j"
			ut64 size;
			RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, addr, type, &size);
			if (mi) {
				rz_meta_print(core->analysis, mi, addr, size, input[2], NULL, false);
				rz_cons_newline();
			}
			break;
		}
		ut64 size;
		RzAnalysisMetaItem *mi = rz_meta_get_at(core->analysis, addr, type, &size);
		if (!mi) {
			break;
		}
		if (type == 's') {
			char *esc_str;
			bool esc_bslash = core->print->esc_bslash;
			switch (mi->subtype) {
			case RZ_STRING_ENC_UTF8:
				esc_str = rz_str_escape_utf8(mi->str, false, esc_bslash);
				break;
			case 0: /* temporary legacy workaround */
				esc_bslash = false;
			default:
				esc_str = rz_str_escape_latin1(mi->str, false, esc_bslash, false);
			}
			if (esc_str) {
				rz_cons_printf("\"%s\"\n", esc_str);
				free(esc_str);
			} else {
				rz_cons_println("<oom>");
			}
		} else if (type == 'd') {
			rz_cons_printf("%" PFMT64u "\n", size);
		} else {
			rz_cons_println(mi->str);
		}
		break;
	case ' ': // "Cf", "Cd", ...
	case '\0':
	case 'g':
	case 'a':
	case '8':
		if (type != 'z' && !input[1] && !core->tmpseek) {
			rz_meta_print_list_all(core->analysis, type, 0);
			break;
		}
		if (type == 'z') {
			type = 's';
		}
		int len = (!input[1] || input[1] == ' ') ? 2 : 3;
		if (strlen(input) > len) {
			char *rep = strchr(input + len, '[');
			if (!rep) {
				rep = strchr(input + len, ' ');
			}
			if (*input == 'd') {
				if (rep) {
					repeat = rz_num_math(core->num, rep + 1);
				}
			}
		}
		int repcnt = 0;
		if (repeat < 1) {
			repeat = 1;
		}
		while (repcnt < repeat) {
			int off = (!input[1] || input[1] == ' ') ? 1 : 2;
			t = strdup(rz_str_trim_head_ro(input + off));
			p = NULL;
			n = 0;
			strncpy(name, t, sizeof(name) - 1);
			if (type != 'C') {
				n = rz_num_math(core->num, t);
				if (type == 'f') { // "Cf"
					p = strchr(t, ' ');
					if (p) {
						p = (char *)rz_str_trim_head_ro(p);
						if (*p == '.') {
							const char *realformat = rz_type_db_format_get(core->analysis->typedb, p + 1);
							if (realformat) {
								p = (char *)realformat;
							} else {
								eprintf("Cannot resolve format '%s'\n", p + 1);
								break;
							}
						}
						if (n < 1) {
							n = rz_type_format_struct_size(core->analysis->typedb, p, 0, 0);
							if (n < 1) {
								eprintf("Warning: Cannot resolve struct size for '%s'\n", p);
								n = 32; //
							}
						}
						//make sure we do not overflow on rz_type_format
						if (n > core->blocksize) {
							n = core->blocksize;
						}
						char *format = rz_type_format_data(core->analysis->typedb, core->print, addr, core->block,
							n, p, 0, NULL, NULL);
						if (!format) {
							n = -1;
						} else {
							rz_cons_print(format);
							free(format);
						}
					} else {
						eprintf("Usage: Cf [size] [pf-format-string]\n");
						break;
					}
				} else if (type == 's') { // "Cs"
					char tmp[256] = RZ_EMPTY;
					int i, j, name_len = 0;
					if (input[1] == 'a' || input[1] == '8') {
						(void)rz_io_read_at(core->io, addr, (ut8 *)name, sizeof(name) - 1);
						name[sizeof(name) - 1] = '\0';
						name_len = strlen(name);
					} else {
						(void)rz_io_read_at(core->io, addr, (ut8 *)tmp, sizeof(tmp) - 3);
						name_len = rz_str_nlen_w(tmp, sizeof(tmp) - 3);
						//handle wide strings
						for (i = 0, j = 0; i < sizeof(name); i++, j++) {
							name[i] = tmp[j];
							if (!tmp[j]) {
								break;
							}
							if (!tmp[j + 1]) {
								if (j + 3 < sizeof(tmp)) {
									if (tmp[j + 3]) {
										break;
									}
								}
								j++;
							}
						}
						name[sizeof(name) - 1] = '\0';
					}
					if (n == 0) {
						n = name_len + 1;
					} else {
						if (n > 0 && n < name_len) {
							name[n] = 0;
						}
					}
				}
				if (n < 1) {
					/* invalid length, do not insert into db */
					return false;
				}
				if (!*t || n > 0) {
					RzFlagItem *fi;
					p = strchr(t, ' ');
					if (p) {
						*p++ = '\0';
						p = (char *)rz_str_trim_head_ro(p);
						strncpy(name, p, sizeof(name) - 1);
					} else {
						if (type != 's') {
							fi = rz_flag_get_i(core->flags, addr);
							if (fi) {
								strncpy(name, fi->name, sizeof(name) - 1);
							}
						}
					}
				}
			}
			if (!n) {
				n++;
			}
			if (type == 's') {
				switch (input[1]) {
				case 'a':
				case '8':
					subtype = input[1];
					break;
				default:
					subtype = RZ_STRING_ENC_GUESS;
				}
				rz_meta_set_with_subtype(core->analysis, type, subtype, addr, n, name);
			} else {
				rz_meta_set(core->analysis, type, addr, n, name);
			}
			free(t);
			repcnt++;
			addr += n;
		}
		//rz_meta_cleanup (core->analysis->meta, 0LL, UT64_MAX);
		break;
	default:
		eprintf("Missing space after CC\n");
		break;
	}

	return true;
}

void rz_comment_var_help(RzCore *core, char type) {
	switch (type) {
	case 'b':
		rz_core_cmd_help(core, help_msg_Cvb);
		break;
	case 's':
		rz_core_cmd_help(core, help_msg_Cvs);
		break;
	case 'r':
		rz_core_cmd_help(core, help_msg_Cvr);
		break;
	case '?':
		rz_cons_printf("See Cvb?, Cvs? and Cvr?\n");
	}
}

void rz_comment_vars(RzCore *core, const char *input) {
	//TODO enable base64 and make it the default for C*
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	char *oname = NULL, *name = NULL;

	if (!input[0] || input[1] == '?' || (input[0] != 'b' && input[0] != 'r' && input[0] != 's')) {
		rz_comment_var_help(core, input[0]);
		return;
	}
	if (!fcn) {
		eprintf("Can't find function here\n");
		return;
	}
	oname = name = rz_str_trim_dup(input + 1);
	switch (input[1]) {
	case '*': // "Cv*"
	case '\0': { // "Cv"
		void **it;
		char kind = input[0];
		rz_pvector_foreach (&fcn->vars, it) {
			RzAnalysisVar *var = *it;
			if (var->kind != kind || !var->comment) {
				continue;
			}
			if (!input[1]) {
				rz_cons_printf("%s : %s\n", var->name, var->comment);
			} else {
				char *b64 = sdb_encode((const ut8 *)var->comment, strlen(var->comment));
				if (!b64) {
					continue;
				}
				rz_cons_printf("\"Cv%c %s base64:%s @ 0x%08" PFMT64x "\"\n", kind, var->name, b64, fcn->addr);
			}
		}
	} break;
	case ' ': { // "Cv "
		char *comment = strchr(name, ' ');
		char *heap_comment = NULL;
		if (comment) { // new comment given
			if (*comment) {
				*comment++ = 0;
			}
			if (!strncmp(comment, "base64:", 7)) {
				heap_comment = (char *)sdb_decode(comment + 7, NULL);
				comment = heap_comment;
			}
		}
		RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
		if (!var) {
			int idx = (int)strtol(name, NULL, 0);
			var = rz_analysis_function_get_var(fcn, input[0], idx);
		}
		if (!var) {
			eprintf("can't find variable at given offset\n");
		} else {
			if (var->comment) {
				if (comment && *comment) {
					char *text = rz_str_newf("%s\n%s", var->comment, comment);
					free(var->comment);
					var->comment = text;
				} else {
					rz_cons_println(var->comment);
				}
			} else {
				var->comment = strdup(comment);
			}
		}
		free(heap_comment);
	} break;
	case '-': { // "Cv-"
		name++;
		rz_str_trim(name);
		RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
		if (!var) {
			int idx = (int)strtol(name, NULL, 0);
			var = rz_analysis_function_get_var(fcn, input[0], idx);
		}
		if (!var) {
			eprintf("can't find variable at given offset\n");
			break;
		}
		free(var->comment);
		var->comment = NULL;
		break;
	}
	case '!': { // "Cv!"
		char *comment;
		name++;
		rz_str_trim(name);
		RzAnalysisVar *var = rz_analysis_function_get_var_byname(fcn, name);
		if (!var) {
			eprintf("can't find variable named `%s`\n", name);
			break;
		}
		comment = rz_core_editor(core, NULL, var->comment);
		if (comment) {
			free(var->comment);
			var->comment = comment;
		}
	} break;
	}
	free(oname);
}

RZ_IPI int rz_cmd_meta(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	RzAnalysisFunction *f;
	RzSpaces *ms;
	int i;

	switch (*input) {
	case 'v': // "Cv"
		rz_comment_vars(core, input + 1);
		break;
	case '\0': // "C"
		rz_meta_print_list_all(core->analysis, RZ_META_TYPE_ANY, 0);
		break;
	case 'j': // "Cj"
	case '*': { // "C*"
		if (!input[0] || input[1] == '.') {
			rz_meta_print_list_at(core->analysis, core->offset, *input);
		} else {
			rz_meta_print_list_all(core->analysis, RZ_META_TYPE_ANY, *input);
		}
		break;
	}
	case '.': { // "C."
		rz_meta_print_list_at(core->analysis, core->offset, 0);
		break;
	}
	case 'C': // "CC"
		cmd_meta_comment(core, input);
		break;
	case 't': // "Ct" type analysis commnets
		cmd_meta_vartype_comment(core, input);
		break;
	case 'r': // "Cr" run command
	case 'h': // "Ch" comment
	case 's': // "Cs" string
	case 'z': // "Cz" zero-terminated string
	case 'd': // "Cd" data
	case 'm': // "Cm" magic
	case 'f': // "Cf" formatted
		cmd_meta_others(core, input);
		break;
	case '-': // "C-"
		if (input[1] != '*') {
			i = input[1] ? rz_num_math(core->num, input + (input[1] == ' ' ? 2 : 1)) : 1;
			rz_meta_del(core->analysis, RZ_META_TYPE_ANY, core->offset, i);
		} else {
			rz_meta_del(core->analysis, RZ_META_TYPE_ANY, 0, UT64_MAX);
		}
		break;
	case '?': // "C?"
		rz_core_cmd_help(core, help_msg_C);
		break;
	case 'F': // "CF"
		f = rz_analysis_get_fcn_in(core->analysis, core->offset,
			RZ_ANALYSIS_FCN_TYPE_FCN | RZ_ANALYSIS_FCN_TYPE_SYM);
		if (f) {
			rz_analysis_function_set_type_str(core->analysis, f, input + 2);
		} else {
			eprintf("Cannot find function here\n");
		}
		break;
	case 'S': // "CS"
		ms = &core->analysis->meta_spaces;
		/** copypasta from `fs`.. this must be refactorized to be shared */
		switch (input[1]) {
		case '?': // "CS?"
			rz_core_cmd_help(core, help_msg_CS);
			break;
		case '+': // "CS+"
			rz_spaces_push(ms, input + 2);
			break;
		case 'r': // "CSr"
			if (input[2] == ' ') {
				rz_spaces_rename(ms, NULL, input + 2);
			} else {
				eprintf("Usage: CSr [newname]\n");
			}
			break;
		case '-': // "CS-"
			if (input[2]) {
				if (input[2] == '*') {
					rz_spaces_unset(ms, NULL);
				} else {
					rz_spaces_unset(ms, input + 2);
				}
			} else {
				rz_spaces_pop(ms);
			}
			break;
		case 'j': // "CSj"
		case '\0': // "CS"
		case '*': // "CS*"
			spaces_list(ms, input[1]);
			break;
		case ' ': // "CS "
			rz_spaces_set(ms, input + 2);
			break;
		default:
			spaces_list(ms, 0);
			break;
		}
		break;
	}
	return true;
}
