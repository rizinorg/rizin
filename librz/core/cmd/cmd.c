// SPDX-FileCopyrightText: 2009-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define INTERACTIVE_MAX_REP 1024

#include <rz_core.h>
#include <rz_analysis.h>
#include <rz_cons.h>
#include <rz_cmd.h>
#include <stdint.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdarg.h>
#if __UNIX__
#include <sys/utsname.h>
#endif

#include <cmd_descs.h>

#include <tree_sitter/api.h>
TSLanguage *tree_sitter_rzcmd();

RZ_API void rz_save_panels_layout(RzCore *core, const char *_name);
RZ_API bool rz_load_panels_layout(RzCore *core, const char *_name);

static RzCmdDescriptor *cmd_descriptor(const char *cmd, const char *help[]) {
	RzCmdDescriptor *d = RZ_NEW0(RzCmdDescriptor);
	if (d) {
		d->cmd = cmd;
		d->help_msg = help;
	}
	return d;
}

#define DEPRECATED_DEFINE_CMD_DESCRIPTOR(core, cmd_) \
	{ \
		RzCmdDescriptor *d = cmd_descriptor(#cmd_, help_msg_##cmd_); \
		if (d) { \
			rz_list_append((core)->cmd_descriptors, d); \
		} \
	}

#define DEPRECATED_DEFINE_CMD_DESCRIPTOR_WITH_DETAIL(core, cmd_) \
	{ \
		RzCmdDescriptor *d = cmd_descriptor(#cmd_, help_msg##cmd_); \
		if (d) { \
			d->help_detail = help_detail_##cmd_; \
			rz_list_append((core)->cmd_descriptors, d); \
		} \
	}

#define DEPRECATED_DEFINE_CMD_DESCRIPTOR_WITH_DETAIL2(core, cmd_) \
	{ \
		RzCmdDescriptor *d = cmd_descriptor(#cmd_, help_msg_##cmd_); \
		if (d) { \
			d->help_detail = help_detail_##cmd_; \
			d->help_detail2 = help_detail2_##cmd_; \
			rz_list_append((core)->cmd_descriptors, d); \
		} \
	}

#define DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL(core, cmd_, named_cmd) \
	{ \
		RzCmdDescriptor *d = RZ_NEW0(RzCmdDescriptor); \
		if (d) { \
			d->cmd = #cmd_; \
			d->help_msg = help_msg_##named_cmd; \
			rz_list_append((core)->cmd_descriptors, d); \
		} \
	}

static int rz_core_cmd_subst_i(RzCore *core, char *cmd, char *colon, bool *tmpseek);

static bool lastcmd_repeat(RzCore *core, int next);

#include "cmd_block.c"
#include "cmd_quit.c"
#include "cmd_hash.c"
#include "cmd_debug.c"
#include "cmd_plugins.c"
#include "cmd_flag.c"
#include "cmd_zign.c"
#include "cmd_project.c"
#include "cmd_write.c"
#include "cmd_cmp.c"
#include "cmd_egg.c"
#include "cmd_eval.c"
#include "cmd_interpret.c"
#include "cmd_analysis.c"
#include "cmd_regs.c"
#include "cmd_open.c"
#include "cmd_type.c"
#include "cmd_info.c"
#include "cmd_meta.c"
#include "cmd_macro.c"
#include "cmd_magic.c"
#include "cmd_seek.c"
#include "cmd_search.c" // defines incDigitBuffer... used by cmd_print
#include "cmd_shell.c"
#include "cmd_print.c"
#include "cmd_help.c"
#include "cmd_remote.c"
#include "cmd_resize.c"
#include "cmd_tasks.c"
#include "cmd_system.c"
#include "cmd_history.c"
#include "cmd_yank.c"
#include "cmd_linux_heap_glibc.c"
#include "cmd_windows_heap.c"

static const char *help_msg_dollar[] = {
	"Usage:", "$alias[=cmd] [args...]", "Alias commands and strings (See ?$? for help on $variables)",
	"$", "", "list all defined aliases",
	"$*", "", "list all the aliases as rizin commands in base64",
	"$**", "", "same as above, but using plain text",
	"$", "foo:=123", "alias for 'f foo=123'",
	"$", "foo-=4", "alias for 'f foo-=4'",
	"$", "foo+=4", "alias for 'f foo+=4'",
	"$", "foo", "alias for 's foo' (note that command aliases can override flag resolution)",
	"$", "dis=base64:AAA==", "alias this base64 encoded text to be printed when $dis is called",
	"$", "dis=$hello world", "alias this text to be printed when $dis is called",
	"$", "dis=-", "open cfg.editor to set the new value for dis alias",
	"$", "dis=af;pdf", "create command - analyze to show function",
	"$", "test=#!pipe node /tmp/test.js", "create command - rlangpipe script",
	"$", "dis=", "undefine alias",
	"$", "dis", "execute the previously defined alias",
	"$", "dis?", "show commands aliased by $dis",
	"$", "dis?n", "show commands aliased by $dis, without a new line",
	NULL
};

static const char *help_msg_star[] = {
	"Usage:", "*<addr>[=[0x]value]", "Pointer read/write data/values",
	"*", "entry0=cc", "write trap in entrypoint",
	"*", "entry0+10=0x804800", "write value in delta address",
	"*", "entry0", "read byte at given address",
	"*", "/", "end multiline comment. (use '/*' to start mulitiline comment",
	"TODO: last command should honor asm.bits", "", "",
	NULL
};

static const char *help_msg_dot[] = {
	"Usage:", ".[rizincmd] | [file] | [!command] | [(macro)]", "# define macro or interpret rizin, rz_lang,\n"
								   "    cparse, d, es6, exe, go, js, lsp, pl, py, rb, sh, vala or zig file",
	".", "", "repeat last command backward",
	".", "rizincmd", "interpret the output of the command as rizin commands",
	"..", " [file]", "run the output of the execution of a script as rizin commands",
	"...", "", "repeat last command forward (same as \\n)",
	".:", "8080", "listen for commands on given tcp port",
	".--", "", "terminate tcp server for remote commands",
	".", " foo.rz", "interpret script",
	".-", "", "open cfg.editor and interpret tmp file",
	".*", " file ...", "same as #!pipe open cfg.editor and interpret tmp file",
	".!", "rabin -ri $FILE", "interpret output of command",
	".", "(foo 1 2 3)", "run macro 'foo' with args 1, 2, 3",
	"./", " ELF", "interpret output of command /m ELF as r. commands",
	NULL
};

static const char *help_msg_k[] = {
	"Usage:",
	"k[s] [key[=value]]",
	"Sdb Query",
	"k",
	" analysis/**",
	"list namespaces under analysis",
	"k",
	" analysis/meta/*",
	"list kv from analysis > meta namespaces",
	"k",
	" analysis/meta/meta.0x80404",
	"get value for meta.0x80404 key",
	"k",
	" foo",
	"show value",
	"k",
	" foo=bar",
	"set value",
	"k",
	"",
	"list keys",
	"kd",
	" [file.sdb] [ns]",
	"dump namespace to disk",
	"kj",
	"",
	"List all namespaces and sdb databases in JSON format",
	"ko",
	" [file.sdb] [ns]",
	"open file into namespace",
	"ks",
	" [ns]",
	"enter the sdb query shell",
	//"kl", " ha.sdb", "load keyvalue from ha.sdb",
	//"ks", " ha.sdb", "save keyvalue to ha.sdb",
	NULL,
};

static const char *help_msg_u[] = {
	"Usage:", "u", "uname or undo write/seek",
	"u", "", "show system uname",
	"uw", "", "alias for wc (requires: e io.cache=true)",
	"us", "", "alias for s- (seek history)",
	"uc", "", "undo core commands (uc?, ucl, uc*, ..)",
	NULL
};

static const char *help_msg_vertical_bar[] = {
	"Usage:", "[cmd] | [program|H|T|.|]", "",
	"", "[cmd] |?", "show this help",
	"", "[cmd] |", "disable scr.html and scr.color",
	"", "[cmd] |H", "enable scr.html, respect scr.color",
	"", "[cmd] | [program]", "pipe output of command to program",
	"", "[cmd] |.", "alias for .[cmd]",
	NULL
};

static const char *help_msg_v[] = {
	"Usage:", "v[*i]", "",
	"v", "", "open visual panels",
	"v", " test", "load saved layout with name test",
	"v=", " test", "save current layout with name test",
	"vi", " test", "open the file test in 'cfg.editor'",
	NULL
};

RZ_API void rz_core_cmd_help(const RzCore *core, const char *help[]) {
	rz_cons_cmd_help(help, core->print->flags & RZ_PRINT_FLAGS_COLOR);
}

struct duplicate_flag_t {
	RzList *ret;
	const char *word;
};

static bool duplicate_flag(RzFlagItem *flag, void *u) {
	struct duplicate_flag_t *user = (struct duplicate_flag_t *)u;
	/* filter per flag spaces */
	if (!user->word || rz_str_glob(flag->name, user->word)) {
		RzFlagItem *cloned_item = rz_flag_item_clone(flag);
		if (!cloned_item) {
			return false;
		}
		rz_list_append(user->ret, cloned_item);
	}
	return true;
}

static void recursive_help_go(RzCore *core, int detail, RzCmdDescriptor *desc) {
	int i;
	if (desc->help_msg) {
		rz_core_cmd_help(core, desc->help_msg);
	}
	if (detail >= 1) {
		if (desc->help_detail) {
			rz_core_cmd_help(core, desc->help_detail);
		}
		if (detail >= 2 && desc->help_detail2) {
			rz_core_cmd_help(core, desc->help_detail2);
		}
	}
	for (i = 32; i < RZ_ARRAY_SIZE(desc->sub); i++) {
		if (desc->sub[i]) {
			recursive_help_go(core, detail, desc->sub[i]);
		}
	}
}

static void recursive_help(RzCore *core, int detail, const char *cmd_prefix) {
	const ut8 *p;
	RzCmdDescriptor *desc = &core->root_cmd_descriptor;
	for (p = (const ut8 *)cmd_prefix; *p && *p < RZ_ARRAY_SIZE(desc->sub); p++) {
		if (!(desc = desc->sub[*p])) {
			return;
		}
	}
	recursive_help_go(core, detail, desc);
}

static bool lastcmd_repeat(RzCore *core, int next) {
	int res = -1;
	// Fix for backtickbug px`~`
	if (!core->lastcmd || core->cons->context->cmd_depth < 1) {
		return false;
	}
	switch (*core->lastcmd) {
	case '.':
		if (core->lastcmd[1] == '(') { // macro call
			res = rz_core_cmd0(core, core->lastcmd);
		}
		break;
	case 'd': // debug
		res = rz_core_cmd0(core, core->lastcmd);
		switch (core->lastcmd[1]) {
		case 's':
		case 'c':
			rz_core_seek_to_register(core, "PC", false);
			rz_core_cmd0(core, "pd 1");
		}
		break;
	case 'p': // print
	case 'x':
	case '$':
		if (!strncmp(core->lastcmd, "pd", 2)) {
			if (core->lastcmd[2] == ' ') {
				ut64 addr = rz_num_math(core->num, core->lastcmd + 3);
				rz_core_seek_opcode(core, addr, false);
			} else {
				rz_core_cmd0(core, "so `pi~?`");
			}
		} else {
			if (next) {
				rz_core_seek(core, core->offset + core->blocksize, true);
			} else {
				if (core->blocksize > core->offset) {
					rz_core_seek(core, 0, true);
				} else {
					rz_core_seek(core, core->offset - core->blocksize, true);
				}
			}
		}
		res = rz_core_cmd0(core, core->lastcmd);
		break;
	}
	core->is_lastcmd = true;
	return res != -1;
}

static int rz_core_cmd_nullcallback(void *data) {
	RzCore *core = (RzCore *)data;
	if (core->cons->context->breaked) {
		core->cons->context->breaked = false;
		return 0;
	}
	if (!core->cmdrepeat) {
		return 0;
	}
	lastcmd_repeat(core, true);
	return 1;
}

RZ_IPI int rz_cmd_alias(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (*input == '?') {
		rz_core_cmd_help(core, help_msg_dollar);
		return 0;
	}
	int i = strlen(input);
	char *buf = malloc(i + 2);
	if (!buf) {
		return 0;
	}
	*buf = '$'; // prefix aliases with a dollar
	memcpy(buf + 1, input, i + 1);
	char *q = strchr(buf, ' ');
	char *def = strchr(buf, '=');
	char *desc = strchr(buf, '?');
	char *nonl = strchr(buf, 'n');

	int defmode = 0;
	if (def && def > buf) {
		char *prev = def - 1;
		switch (*prev) {
		case ':':
			defmode = *prev;
			*prev = 0;
			break;
		case '+':
			defmode = *prev;
			*prev = 0;
			break;
		case '-':
			defmode = *prev;
			*prev = 0;
			break;
		}
	}

	/* create alias */
	if ((def && q && (def < q)) || (def && !q)) {
		*def++ = 0;
		size_t len = strlen(def);
		if (defmode) {
			ut64 at = rz_num_math(core->num, def);
			switch (defmode) {
			case ':':
				rz_flag_set(core->flags, buf + 1, at, 1);
				return 1;
			case '+':
				at = rz_num_get(core->num, buf + 1) + at;
				rz_flag_set(core->flags, buf + 1, at, 1);
				return 1;
			case '-':
				at = rz_num_get(core->num, buf + 1) - at;
				rz_flag_set(core->flags, buf + 1, at, 1);
				return 1;
			}
		}
		/* Remove quotes */
		if (len > 0 && (def[0] == '\'') && (def[len - 1] == '\'')) {
			def[len - 1] = 0x00;
			def++;
		}
		if (!q || (q && q > def)) {
			if (*def) {
				if (!strcmp(def, "-")) {
					char *v = rz_cmd_alias_get(core->rcmd, buf, 0);
					char *n = rz_core_editor(core, NULL, v);
					if (n) {
						rz_cmd_alias_set(core->rcmd, buf, n, 0);
						free(n);
					}
				} else {
					rz_cmd_alias_set(core->rcmd, buf, def, 0);
				}
			} else {
				rz_cmd_alias_del(core->rcmd, buf);
			}
		}
		/* Show command for alias */
	} else if (desc && !q) {
		*desc = 0;
		char *v = rz_cmd_alias_get(core->rcmd, buf, 0);
		if (v) {
			if (nonl == desc + 1) {
				rz_cons_print(v);
			} else {
				rz_cons_println(v);
			}
			free(buf);
			return 1;
		} else {
			eprintf("unknown key '%s'\n", buf);
		}
	} else if (buf[1] == '*') {
		/* Show aliases */
		int i, count = 0;
		char **keys = rz_cmd_alias_keys(core->rcmd, &count);
		for (i = 0; i < count; i++) {
			char *v = rz_cmd_alias_get(core->rcmd, keys[i], 0);
			char *q = rz_base64_encode_dyn((const ut8 *)v, strlen(v));
			if (buf[2] == '*') {
				rz_cons_printf("%s=%s\n", keys[i], v);
			} else {
				rz_cons_printf("%s=base64:%s\n", keys[i], q);
			}
			free(q);
		}
	} else if (!buf[1]) {
		int i, count = 0;
		char **keys = rz_cmd_alias_keys(core->rcmd, &count);
		for (i = 0; i < count; i++) {
			rz_cons_println(keys[i]);
		}
	} else {
		/* Execute alias */
		if (q) {
			*q = 0;
		}
		char *v = rz_cmd_alias_get(core->rcmd, buf, 0);
		if (v) {
			if (*v == '$') {
				rz_cons_strcat(v + 1);
				rz_cons_newline();
			} else if (q) {
				char *out = rz_str_newf("%s %s", v, q + 1);
				rz_core_cmd0(core, out);
				free(out);
			} else {
				rz_core_cmd0(core, v);
			}
		} else {
			ut64 at = rz_num_get(core->num, buf + 1);
			if (at != UT64_MAX) {
				rz_core_seek(core, at, true);
			} else {
				eprintf("Unknown alias '%s'\n", buf + 1);
			}
		}
	}
	free(buf);
	return 0;
}

static int lang_run_file(RzCore *core, RzLang *lang, const char *file) {
	rz_core_sysenv_begin(core);
	return rz_lang_run_file(core->lang, file);
}

static char *langFromHashbang(RzCore *core, const char *file) {
	int fd = rz_sys_open(file, O_RDONLY, 0);
	if (fd != -1) {
		char firstLine[128] = { 0 };
		int len = read(fd, (ut8 *)firstLine, sizeof(firstLine) - 1);
		if (len < 1) {
			close(fd);
			return NULL;
		}
		firstLine[len] = 0;
		if (!strncmp(firstLine, "#!/", 3)) {
			// I CAN HAS A HASHBANG
			char *nl = strchr(firstLine, '\n');
			if (nl) {
				*nl = 0;
			}
			nl = strchr(firstLine, ' ');
			if (nl) {
				*nl = 0;
			}
			nl = strdup(firstLine + 2);
			close(fd);
			return nl;
		}
		close(fd);
	}
	return NULL;
}

RZ_API bool rz_core_run_script(RzCore *core, const char *file) {
	bool ret = false;
	RzListIter *iter;
	RzLangPlugin *p;
	char *name;

	rz_list_foreach (core->scriptstack, iter, name) {
		if (!strcmp(file, name)) {
			eprintf("WARNING: ignored nested source: %s\n", file);
			return false;
		}
	}
	rz_list_push(core->scriptstack, strdup(file));

	if (!strcmp(file, "-")) {
		char *out = rz_core_editor(core, NULL, NULL);
		if (out) {
			ret = rz_core_cmd_lines(core, out);
			free(out);
		}
	} else if (rz_str_endswith(file, ".html")) {
		char *httpIndex = strdup(rz_config_get(core->config, "http.index"));
		char *absfile = rz_file_abspath(file);
		rz_config_set(core->config, "http.index", absfile);
		free(absfile);
		rz_equal_H_handler_old(core, "");
		rz_config_set(core->config, "http.index", httpIndex);
		free(httpIndex);
		ret = true;
	} else if (rz_str_endswith(file, ".c")) {
		rz_core_cmd_strf(core, "#!c %s", file);
		ret = true;
	} else if (rz_file_is_c(file)) {
		const char *dir = rz_config_get(core->config, "dir.types");
		char *error_msg = NULL;
		int result = rz_type_parse_file(core->analysis->typedb, file, dir, &error_msg);
		if (error_msg) {
			eprintf("%s", error_msg);
			free(error_msg);
		}
		ret = result != 0;
	} else {
		p = rz_lang_get_by_extension(core->lang, file);
		if (p) {
			rz_lang_use(core->lang, p->name);
			ret = lang_run_file(core, core->lang, file);
		} else {
// XXX this is an ugly hack, we need to use execve here and specify args properly
#if __WINDOWS__
#define cmdstr(x) rz_str_newf(x " %s", file);
#else
#define cmdstr(x) rz_str_newf(x " '%s'", file);
#endif
			const char *p = rz_str_lchr(file, '.');
			if (p) {
				const char *ext = p + 1;
				/* TODO: handle this inside rz_lang_pipe with new APIs */
				if (!strcmp(ext, "js")) {
					char *cmd = cmdstr("node");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "exe")) {
#if __WINDOWS__
					char *cmd = rz_str_newf("%s", file);
#else
					char *cmd = cmdstr("wine");
#endif
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "zig")) {
					char *cmd = cmdstr("zig run");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "d")) {
					char *cmd = cmdstr("dmd -run");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "go")) {
					char *cmd = cmdstr("go run");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "rb")) {
					char *cmd = cmdstr("ruby");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "vala")) {
					rz_lang_use(core->lang, "vala");
					lang_run_file(core, core->lang, file);
					ret = 1;
				} else if (!strcmp(ext, "sh")) {
					char *shell = rz_sys_getenv("SHELL");
					if (!shell) {
						shell = strdup("sh");
					}
					if (shell) {
						rz_lang_use(core->lang, "pipe");
						char *cmd = rz_str_newf("%s '%s'", shell, file);
						if (cmd) {
							lang_run_file(core, core->lang, cmd);
							free(cmd);
						}
						free(shell);
					}
					ret = 1;
				} else if (!strcmp(ext, "pl")) {
					char *cmd = cmdstr("perl");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				} else if (!strcmp(ext, "py")) {
					char *cmd = cmdstr("python");
					rz_lang_use(core->lang, "pipe");
					lang_run_file(core, core->lang, cmd);
					free(cmd);
					ret = 1;
				}
			} else {
				char *abspath = rz_file_path(file);
				char *lang = langFromHashbang(core, file);
				if (lang) {
					rz_lang_use(core->lang, "pipe");
					char *cmd = rz_str_newf("%s '%s'", lang, file);
					lang_run_file(core, core->lang, cmd);
					free(lang);
					free(cmd);
					ret = 1;
				}
				free(abspath);
			}
			if (!ret) {
				ret = rz_core_cmd_file(core, file);
			}
		}
	}
	free(rz_list_pop(core->scriptstack));
	return ret;
}

RZ_IPI int rz_cmd_interpret(void *data, const char *input) {
	char *str, *ptr, *eol, *rbuf, *filter, *inp;
	const char *host, *port, *cmd;
	RzCore *core = (RzCore *)data;

	if (!strcmp(input, "?")) {
		rz_core_cmd_help(core, help_msg_dot);
		return 0;
	}
	switch (*input) {
	case '\0': // "."
		lastcmd_repeat(core, 0);
		break;
	case ':': // ".:"
		if ((ptr = strchr(input + 1, ' '))) {
			/* .:port cmd */
			/* .:host:port cmd */
			cmd = ptr + 1;
			*ptr = 0;
			eol = strchr(input + 1, ':');
			if (eol) {
				*eol = 0;
				host = input + 1;
				port = eol + 1;
			} else {
				host = "localhost";
				port = input + ((input[1] == ':') ? 2 : 1);
			}
			rbuf = rz_core_rtr_cmds_query(core, host, port, cmd);
			if (rbuf) {
				rz_cons_print(rbuf);
				free(rbuf);
			}
		} else {
			rz_core_rtr_cmds(core, input + 1);
		}
		break;
	case '.': // ".." same as \n
		if (input[1] == '.') { // "..." run the last command repeated
			// same as \n with e cmd.repeat=true
			lastcmd_repeat(core, 1);
		} else if (input[1]) {
			char *str = rz_core_cmd_str_pipe(core, rz_str_trim_head_ro(input));
			if (str) {
				rz_core_cmd(core, str, 0);
				free(str);
			}
		} else {
			eprintf("Usage: .. ([file])\n");
		}
		break;
	case '*': // ".*"
	{
		const char *a = rz_str_trim_head_ro(input + 1);
		char *s = strdup(a);
		char *sp = strchr(s, ' ');
		if (sp) {
			*sp = 0;
		}
		if (RZ_STR_ISNOTEMPTY(s)) {
			rz_core_run_script(core, s);
		}
		free(s);
	} break;
	case '-': // ".-"
		if (input[1] == '?') {
			rz_cons_printf("Usage: '-' '.-' '. -' do the same\n");
		} else {
			rz_core_run_script(core, "-");
		}
		break;
	case ' ': // ". "
	{
		const char *script_file = rz_str_trim_head_ro(input + 1);
		if (*script_file == '$') {
			rz_core_cmd0(core, script_file);
		} else {
			if (!rz_core_run_script(core, script_file)) {
				eprintf("Cannot find script '%s'\n", script_file);
				core->num->value = 1;
			} else {
				core->num->value = 0;
			}
		}
	} break;
	case '!': // ".!"
		/* from command */
		rz_core_cmd_command(core, input + 1);
		break;
	case '(': // ".("
		rz_cmd_macro_call(&core->rcmd->macro, input + 1);
		break;
	default:
		if (*input >= 0 && *input <= 9) {
			eprintf("|ERROR| No .[0..9] to avoid infinite loops\n");
			break;
		}
		inp = strdup(input);
		filter = strchr(inp, '~');
		if (filter) {
			*filter = 0;
		}
		int tmp_html = rz_cons_singleton()->is_html;
		rz_cons_singleton()->is_html = 0;
		ptr = str = rz_core_cmd_str(core, inp);
		rz_cons_singleton()->is_html = tmp_html;

		if (filter) {
			*filter = '~';
		}
		rz_cons_break_push(NULL, NULL);
		if (ptr) {
			for (;;) {
				if (rz_cons_is_breaked()) {
					break;
				}
				eol = strchr(ptr, '\n');
				if (eol) {
					*eol = '\0';
				}
				if (*ptr) {
					char *p = rz_str_append(strdup(ptr), filter);
					rz_core_cmd0(core, p);
					free(p);
				}
				if (!eol) {
					break;
				}
				ptr = eol + 1;
			}
		}
		rz_cons_break_pop();
		free(str);
		free(inp);
		break;
	}
	return 0;
}

static bool callback_foreach_kv(void *user, const char *k, const char *v) {
	rz_cons_printf("%s=%s\n", k, v);
	return true;
}

RZ_API int rz_line_hist_sdb_up(RzLine *line) {
	if (!line->sdbshell_hist_iter || !line->sdbshell_hist_iter->n) {
		return false;
	}
	line->sdbshell_hist_iter = line->sdbshell_hist_iter->n;
	strncpy(line->buffer.data, line->sdbshell_hist_iter->data, RZ_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen(line->buffer.data);
	return true;
}

RZ_API int rz_line_hist_sdb_down(RzLine *line) {
	if (!line->sdbshell_hist_iter || !line->sdbshell_hist_iter->p) {
		return false;
	}
	line->sdbshell_hist_iter = line->sdbshell_hist_iter->p;
	strncpy(line->buffer.data, line->sdbshell_hist_iter->data, RZ_LINE_BUFSIZE - 1);
	line->buffer.index = line->buffer.length = strlen(line->buffer.data);
	return true;
}

RZ_IPI void rz_core_kuery_print(RzCore *core, const char *k) {
	char *out = sdb_querys(core->sdb, NULL, 0, k);
	if (out) {
		rz_cons_print(out);
	}
	free(out);
}

RZ_IPI int rz_cmd_kuery(void *data, const char *input) {
	char buf[1024], *out;
	RzCore *core = (RzCore *)data;
	const char *sp, *p = "[sdb]> ";
	Sdb *s = core->sdb;

	char *cur_pos = NULL, *cur_cmd = NULL, *next_cmd = NULL;
	char *temp_pos = NULL, *temp_cmd = NULL;

	switch (input[0]) {

	case 'j':
		out = sdb_querys(s, NULL, 0, "analysis/**");
		if (!out) {
			rz_cons_println("No Output from sdb");
			break;
		}
		PJ *pj = pj_new();
		if (!pj) {
			free(out);
			break;
		}
		pj_o(pj);
		pj_ko(pj, "analysis");
		pj_ka(pj, "cur_cmd");

		while (*out) {
			cur_pos = strchr(out, '\n');
			if (!cur_pos) {
				break;
			}
			cur_cmd = rz_str_ndup(out, cur_pos - out);
			pj_s(pj, cur_cmd);

			free(next_cmd);
			next_cmd = rz_str_newf("analysis/%s/*", cur_cmd);
			char *query_result = sdb_querys(s, NULL, 0, next_cmd);

			if (!query_result) {
				out = cur_pos + 1;
				continue;
			}

			char *temp = query_result;
			while (*temp) {
				temp_pos = strchr(temp, '\n');
				if (!temp_pos) {
					break;
				}
				temp_cmd = rz_str_ndup(temp, temp_pos - temp);
				pj_s(pj, temp_cmd);
				temp = temp_pos + 1;
			}
			out = cur_pos + 1;
			free(query_result);
		}
		pj_end(pj);
		pj_end(pj);
		pj_end(pj);
		rz_cons_println(pj_string(pj));
		pj_free(pj);
		RZ_FREE(next_cmd);
		free(next_cmd);
		free(cur_cmd);
		break;

	case ' ':
		rz_core_kuery_print(core, input + 1);
		break;
	// case 's': rz_pair_save (s, input + 3); break;
	// case 'l': rz_pair_load (sdb, input + 3); break;
	case '\0':
		sdb_foreach(s, callback_foreach_kv, NULL);
		break;
	// TODO: add command to list all namespaces // sdb_ns_foreach ?
	case 's': // "ks"
		if (core->http_up) {
			return false;
		}
		if (!rz_cons_is_interactive()) {
			return false;
		}
		if (input[1] == ' ') {
			char *n, *o, *p = strdup(input + 2);
			// TODO: slash split here? or inside sdb_ns ?
			for (n = o = p; n; o = n) {
				n = strchr(o, '/'); // SDB_NS_SEPARATOR NAMESPACE
				if (n) {
					*n++ = 0;
				}
				s = sdb_ns(s, o, 1);
			}
			free(p);
		}
		if (!s) {
			s = core->sdb;
		}
		RzLine *line = core->cons->line;
		if (!line->sdbshell_hist) {
			line->sdbshell_hist = rz_list_newf(free);
			rz_list_append(line->sdbshell_hist, rz_str_new("\0"));
		}
		RzList *sdb_hist = line->sdbshell_hist;
		rz_line_set_hist_callback(line, &rz_line_hist_sdb_up, &rz_line_hist_sdb_down);
		for (;;) {
			rz_line_set_prompt(p);
			if (rz_cons_fgets(buf, sizeof(buf), 0, NULL) < 1) {
				break;
			}
			if (!*buf) {
				break;
			}
			if (sdb_hist) {
				if ((rz_list_length(sdb_hist) == 1) || (rz_list_length(sdb_hist) > 1 && strcmp(rz_list_get_n(sdb_hist, 1), buf))) {
					rz_list_insert(sdb_hist, 1, strdup(buf));
				}
				line->sdbshell_hist_iter = sdb_hist->head;
			}
			out = sdb_querys(s, NULL, 0, buf);
			if (out) {
				rz_cons_println(out);
				rz_cons_flush();
			}
		}
		rz_line_set_hist_callback(core->cons->line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
		break;
	case 'o': // "ko"
		if (input[1] == ' ') {
			char *fn = strdup(input + 2);
			if (!fn) {
				eprintf("Unable to allocate memory\n");
				return 0;
			}
			char *ns = strchr(fn, ' ');
			if (ns) {
				Sdb *db;
				*ns++ = 0;
				if (rz_file_exists(fn)) {
					db = sdb_ns_path(core->sdb, ns, 1);
					if (db) {
						Sdb *newdb = sdb_new(NULL, fn, 0);
						if (newdb) {
							sdb_drain(db, newdb);
						} else {
							eprintf("Cannot open sdb '%s'\n", fn);
						}
					} else {
						eprintf("Cannot find sdb '%s'\n", ns);
					}
				} else {
					eprintf("Cannot open file\n");
				}
			} else {
				eprintf("Missing sdb namespace\n");
			}
			free(fn);
		} else {
			eprintf("Usage: ko [file] [namespace]\n");
		}
		break;
	case 'd': // "kd"
		if (input[1] == ' ') {
			char *fn = strdup(input + 2);
			char *ns = strchr(fn, ' ');
			if (ns) {
				*ns++ = 0;
				Sdb *db = sdb_ns_path(core->sdb, ns, 0);
				if (db) {
					sdb_file(db, fn);
					sdb_sync(db);
				} else {
					eprintf("Cannot find sdb '%s'\n", ns);
				}
			} else {
				eprintf("Missing sdb namespace\n");
			}
			free(fn);
		} else {
			eprintf("Usage: kd [file] [namespace]\n");
		}
		break;
	case '?':
		rz_core_cmd_help(core, help_msg_k);
		break;
	}

	if (input[0] == '\0') {
		/* nothing more to do, the command has been parsed. */
		return 0;
	}

	sp = strchr(input + 1, ' ');
	if (sp) {
		char *inp = strdup(input);
		inp[(size_t)(sp - input)] = 0;
		s = sdb_ns(core->sdb, inp + 1, 1);
		out = sdb_querys(s, NULL, 0, sp + 1);
		if (out) {
			rz_cons_println(out);
			free(out);
		}
		free(inp);
		return 0;
	}
	return 0;
}

RZ_IPI int rz_cmd_panels(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (core->vmode) {
		return false;
	}
	if (!rz_cons_is_interactive()) {
		eprintf("Panel mode requires scr.interactive=true.\n");
		return false;
	}
	char *sp = strchr(input, ' ');
	switch (input[0]) {
	case ' ': // "v [name]"
		if (core->panels) {
			rz_load_panels_layout(core, input + 1);
		}
		rz_config_set(core->config, "scr.layout", input + 1);
		return true;
	case '=': // "v= [name]"
		rz_save_panels_layout(core, input + 1);
		rz_config_set(core->config, "scr.layout", input + 1);
		return true;
	case 'i': // "vi [file]"
		if (sp) {
			char *r = rz_core_editor(core, sp + 1, NULL);
			if (r) {
				free(r);
			} else {
				eprintf("Cannot open file (%s)\n", sp + 1);
			}
		}
		////rz_sys_cmdf ("v%s", input);
		return false;
	case 0:
		rz_core_visual_panels_root(core, core->panels_root);
		return true;
	default:
		rz_core_cmd_help(core, help_msg_v);
		return false;
	}
}

RZ_IPI int rz_cmd_visual(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (core->http_up) {
		return false;
	}
	if (!rz_cons_is_interactive()) {
		eprintf("Visual mode requires scr.interactive=true.\n");
		return false;
	}
	return rz_core_visual((RzCore *)data, input);
}

RZ_IPI int rz_cmd_pipein(void *user, const char *input) {
	char *buf = strdup(input);
	int len = rz_str_unescape(buf);
	rz_cons_readpush(buf, len);
	free(buf);
	return 0;
}

RZ_IPI RzCmdStatus rz_push_escaped_handler(RzCore *core, int argc, const char **argv) {
	char *input = rz_str_array_join(argv + 1, argc - 1, " ");
	RzCmdStatus res = rz_cmd_int2status(rz_cmd_pipein(core, input));
	free(input);
	return res;
}

RZ_IPI int rz_cmd_tasks(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case '\0': // "&"
	case 'j': // "&j"
		rz_core_task_list(core, *input);
		break;
	case 'b': { // "&b"
		int tid = rz_num_math(core->num, input + 1);
		task_break(core, tid);
		break;
	}
	case '&': { // "&&"
		int tid = rz_num_math(core->num, input + 1);
		rz_core_task_join(&core->tasks, core->tasks.current_task, tid ? tid : -1);
		break;
	}
	case '=': { // "&="
		int tid = rz_num_math(core->num, input + 1);
		task_output(core, tid);
		break;
	}
	case '-': // "&-"
		if (input[1] == '*') {
			rz_core_task_del_all_done(core);
		} else {
			rz_core_task_del(&core->tasks, rz_num_math(core->num, input + 1));
		}
		break;
	case '?': // "&?"
	default:
		helpCmdTasks(core);
		break;
	case ' ': // "& "
	case '_': // "&_"
	case 't': { // "&t"
		task_enqueue(core, input + 1, input[0] == 't');
		break;
	}
	}
	return 0;
}

RZ_IPI int rz_cmd_pointer(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int ret = true;
	char *str, *eq;
	input = rz_str_trim_head_ro(input);
	while (*input == ' ') {
		input++;
	}
	if (!*input || *input == '?') {
		rz_core_cmd_help(core, help_msg_star);
		return ret;
	}
	str = strdup(input);
	eq = strchr(str, '=');
	if (eq) {
		*eq++ = 0;
		if (!strncmp(eq, "0x", 2)) {
			ret = rz_core_cmdf(core, "wv %s @ %s", eq, str);
		} else {
			ret = rz_core_cmdf(core, "wx %s @ %s", eq, str);
		}
	} else {
		ret = rz_core_cmdf(core, "?v [%s]", input);
	}
	free(str);
	return ret;
}

RZ_IPI RzCmdStatus rz_pointer_handler(RzCore *core, int argc, const char **argv) {
	int ret;
	switch (argc) {
	case 2:
		ret = rz_core_cmdf(core, "?v [%s]", argv[1]);
		return rz_cmd_int2status(ret);
	case 3:
		if (rz_str_startswith(argv[2], "0x")) {
			ret = rz_core_cmdf(core, "wv %s @ %s", argv[2], argv[1]);
		} else {
			ret = rz_core_cmdf(core, "wx %s @ %s", argv[2], argv[1]);
		}
		return rz_cmd_int2status(ret);
	default:
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
}

RZ_IPI int rz_cmd_env(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	int ret = true;
	switch (*input) {
	case '?':
		cmd_help_percent(core);
		break;
	default:
		ret = rz_core_cmdf(core, "env %s", input);
	}
	return ret;
}

RZ_IPI int rz_cmd_last(void *data, const char *input) {
	switch (*input) {
	case 0:
		rz_cons_last();
		break;
	default:
		eprintf("Usage: _  print last output\n");
	}
	return 0;
}

RZ_IPI RzCmdStatus rz_last_output_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_last();
	return RZ_CMD_STATUS_OK;
}

#if __WINDOWS__
#include <tchar.h>
#define __CLOSE_DUPPED_PIPES() \
	close(1); \
	close(fd_out); \
	fd_out = -1;

static void rz_w32_cmd_pipe(RzCore *core, char *rizin_cmd, char *shell_cmd) {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	SECURITY_ATTRIBUTES sa;
	HANDLE pipe[2] = { NULL, NULL };
	int fd_out = -1, cons_out = -1;
	char *_shell_cmd = NULL;
	LPTSTR _shell_cmd_ = NULL;
	DWORD mode;
	TCHAR *systemdir = NULL;
	GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode);

	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	if (!CreatePipe(&pipe[0], &pipe[1], &sa, 0)) {
		rz_sys_perror("rz_w32_cmd_pipe/CreatePipe");
		goto err_r_w32_cmd_pipe;
	}
	if (!SetHandleInformation(pipe[1], HANDLE_FLAG_INHERIT, 0)) {
		rz_sys_perror("rz_w32_cmd_pipe/SetHandleInformation");
		goto err_r_w32_cmd_pipe;
	}
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = pipe[0];
	si.dwFlags |= STARTF_USESTDHANDLES;
	si.cb = sizeof(si);
	_shell_cmd = shell_cmd;
	while (*_shell_cmd && isspace((ut8)*_shell_cmd)) {
		_shell_cmd++;
	}
	char *tmp = rz_str_newf("/Q /c \"%s\"", _shell_cmd);
	if (!tmp) {
		goto err_r_w32_cmd_pipe;
	}
	_shell_cmd = tmp;
	_shell_cmd_ = rz_sys_conv_utf8_to_win(_shell_cmd);
	free(tmp);
	if (!_shell_cmd_) {
		goto err_r_w32_cmd_pipe;
	}
	systemdir = calloc(MAX_PATH, sizeof(TCHAR));
	if (!systemdir) {
		goto err_r_w32_cmd_pipe;
	}
	int ret = GetSystemDirectory(systemdir, MAX_PATH);
	if (!ret) {
		rz_sys_perror("rz_w32_cmd_pipe/systemdir");
		goto err_r_w32_cmd_pipe;
	}
	_tcscat_s(systemdir, MAX_PATH, TEXT("\\cmd.exe"));
	// exec windows process
	if (!CreateProcess(systemdir, _shell_cmd_, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
		rz_sys_perror("rz_w32_cmd_pipe/CreateProcess");
		goto err_r_w32_cmd_pipe;
	}
	fd_out = _open_osfhandle((intptr_t)pipe[1], _O_WRONLY | _O_TEXT);
	if (fd_out == -1) {
		perror("_open_osfhandle");
		goto err_r_w32_cmd_pipe;
	}
	cons_out = dup(1);
	dup2(fd_out, 1);
	// exec rizin command
	rz_core_cmd(core, rizin_cmd, 0);

	HANDLE th = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)rz_cons_flush, NULL, 0, NULL);
	if (!th) {
		__CLOSE_DUPPED_PIPES();
		goto err_r_w32_cmd_pipe;
	}
	while (true) {
		int ret = WaitForSingleObject(th, 50);
		if (!ret) {
			// Successfully written everything to pipe
			__CLOSE_DUPPED_PIPES();
			WaitForSingleObject(pi.hProcess, INFINITE);
			break;
		}
		ret = WaitForSingleObject(pi.hProcess, 50);
		if (!ret) {
			// Process exited before we finished writing to pipe
			DWORD exit;
			if (GetExitCodeThread(th, &exit) && exit == STILL_ACTIVE) {
				CancelSynchronousIo(th);
			}
			WaitForSingleObject(th, INFINITE);
			__CLOSE_DUPPED_PIPES();
			break;
		}
	}
	CloseHandle(th);
err_r_w32_cmd_pipe:
	if (pi.hProcess) {
		CloseHandle(pi.hProcess);
	}
	if (pi.hThread) {
		CloseHandle(pi.hThread);
	}
	if (pipe[0]) {
		CloseHandle(pipe[0]);
	}
	if (fd_out != -1) {
		close(fd_out);
	}
	if (cons_out != -1) {
		dup2(cons_out, 1);
		close(cons_out);
	}
	free(systemdir);
	free(_shell_cmd_);
	SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), mode);
}
#undef __CLOSE_DUPPED_PIPES
#endif

RZ_API int rz_core_cmd_pipe_old(RzCore *core, char *rizin_cmd, char *shell_cmd) {
#if __UNIX__
	int stdout_fd, fds[2];
	int child;
#endif
	int si, olen, ret = -1, pipecolor = -1;
	char *str, *out = NULL;

	si = rz_cons_is_interactive();
	rz_config_set_i(core->config, "scr.interactive", 0);
	if (!rz_config_get_i(core->config, "scr.color.pipe")) {
		pipecolor = rz_config_get_i(core->config, "scr.color");
		rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
	}
	if (*shell_cmd == '!') {
		rz_cons_grep_parsecmd(shell_cmd, "\"");
		olen = 0;
		out = NULL;
		// TODO: implement foo
		str = rz_core_cmd_str(core, rizin_cmd);
		rz_sys_cmd_str_full(shell_cmd + 1, str, &out, &olen, NULL);
		free(str);
		rz_cons_memcat(out, olen);
		free(out);
		ret = 0;
	}
#if __UNIX__
	rz_str_trim_head(rizin_cmd);
	rz_str_trim_head(shell_cmd);

	rz_sys_signal(SIGPIPE, SIG_IGN);
	stdout_fd = dup(1);
	if (stdout_fd != -1) {
		if (rz_sys_pipe(fds, true) == 0) {
			child = rz_sys_fork();
			if (child == -1) {
				eprintf("Cannot fork\n");
				close(stdout_fd);
			} else if (child) {
				dup2(fds[1], 1);
				rz_sys_pipe_close(fds[1]);
				rz_sys_pipe_close(fds[0]);
				rz_core_cmd(core, rizin_cmd, 0);
				rz_cons_flush();
				close(1);
				wait(&ret);
				dup2(stdout_fd, 1);
				close(stdout_fd);
			} else {
				close(fds[1]);
				dup2(fds[0], 0);
				// dup2 (1, 2); // stderr goes to stdout
				rz_sys_execl("/bin/sh", "sh", "-c", shell_cmd, (const char *)NULL);
				close(stdout_fd);
			}
		} else {
			eprintf("rz_core_cmd_pipe: Could not pipe\n");
		}
	}
#elif __WINDOWS__
	rz_w32_cmd_pipe(core, rizin_cmd, shell_cmd);
#else
#ifdef _MSC_VER
#pragma message("rz_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM")
#else
#warning rz_core_cmd_pipe UNIMPLEMENTED FOR THIS PLATFORM
#endif
	eprintf("rz_core_cmd_pipe: unimplemented for this platform\n");
#endif
	if (pipecolor != -1) {
		rz_config_set_i(core->config, "scr.color", pipecolor);
	}
	rz_config_set_i(core->config, "scr.interactive", si);
	return ret;
}

static char *parse_tmp_evals(RzCore *core, const char *str) {
	char *s = strdup(str);
	int i, argc = rz_str_split(s, ',');
	char *res = strdup("");
	if (!s || !res) {
		free(s);
		free(res);
		return NULL;
	}
	for (i = 0; i < argc; i++) {
		char *eq, *kv = (char *)rz_str_word_get0(s, i);
		if (!kv) {
			break;
		}
		eq = strchr(kv, '=');
		if (eq) {
			*eq = 0;
			const char *ov = rz_config_get(core->config, kv);
			if (!ov) {
				continue;
			}
			char *cmd = rz_str_newf("e %s=%s;", kv, ov);
			if (!cmd) {
				free(s);
				free(res);
				return NULL;
			}
			res = rz_str_prepend(res, cmd);
			free(cmd);
			rz_config_set(core->config, kv, eq + 1);
			*eq = '=';
		} else {
			eprintf("Missing '=' in e: expression (%s)\n", kv);
		}
	}
	free(s);
	return res;
}

static bool is_macro_command(const char *ptr) {
	ptr = rz_str_trim_head_ro(ptr);
	while (IS_DIGIT(*ptr)) {
		ptr++;
	}
	return *ptr == '(';
}

static char *find_ch_after_macro(char *ptr, char ch) {
	int depth = 0;
	while (*ptr) {
		if (depth == 0 && *ptr == ch) {
			return ptr;
		}
		if (*ptr == '(') {
			depth++;
		} else if (*ptr == ')') {
			depth--;
		}
		ptr++;
	}
	return NULL;
}

static int rz_core_cmd_subst(RzCore *core, char *cmd) {
	ut64 rep = strtoull(cmd, NULL, 10);
	int ret = 0, orep;
	char *colon = NULL, *icmd = NULL;
	bool tmpseek = false;
	bool original_tmpseek = core->tmpseek;

	if (rz_str_startswith(cmd, "GET /cmd/")) {
		memmove(cmd, cmd + 9, strlen(cmd + 9) + 1);
		char *http = strstr(cmd, "HTTP");
		if (http) {
			*http = 0;
			http--;
			if (*http == ' ') {
				*http = 0;
			}
		}
		rz_cons_printf("HTTP/1.0 %d %s\r\n%s"
			       "Connection: close\r\nContent-Length: %d\r\n\r\n",
			200, "OK", "", -1);
		return rz_core_cmd0(core, cmd);
	}

	/* must store a local orig_offset because there can be
	 * nested call of this function */
	ut64 orig_offset = core->offset;
	icmd = strdup(cmd);
	if (!icmd) {
		goto beach;
	}

	if (core->max_cmd_depth - core->cons->context->cmd_depth == 1) {
		core->prompt_offset = core->offset;
	}
	cmd = (char *)rz_str_trim_head_ro(icmd);
	rz_str_trim_tail(cmd);
	// lines starting with # are ignored (never reach cmd_hash()), except #! and #?
	if (!*cmd) {
		if (core->cmdrepeat > 0) {
			lastcmd_repeat(core, true);
			ret = rz_core_cmd_nullcallback(core);
		}
		goto beach;
	}
	if (!icmd || (cmd[0] == '#' && cmd[1] != '!' && cmd[1] != '?')) {
		goto beach;
	}
	if (*icmd && !strchr(icmd, '"')) {
		char *hash;
		for (hash = icmd + 1; *hash; hash++) {
			if (*hash == '\\') {
				hash++;
				if (*hash == '#') {
					continue;
				}
			}
			if (*hash == '#') {
				break;
			}
		}
		if (hash && *hash) {
			*hash = 0;
			rz_str_trim_tail(icmd);
		}
	}
	if (*cmd != '"') {
		if (!strchr(cmd, '\'')) { // allow | awk '{foo;bar}' // ignore ; if there's a single quote
			if (is_macro_command(cmd)) {
				colon = find_ch_after_macro(cmd, ';');
			} else {
				colon = strchr(cmd, ';');
			}
			if (colon) {
				*colon = 0;
			}
		}
	} else {
		colon = NULL;
	}
	if (rep > 0) {
		while (IS_DIGIT(*cmd)) {
			cmd++;
		}
		// do not repeat null cmd
		if (!*cmd) {
			goto beach;
		}
	}
	if (rep < 1) {
		rep = 1;
	}
	// XXX if output is a pipe then we don't want to be interactive
	if (rep > INTERACTIVE_MAX_REP) {
		if (rz_cons_is_interactive()) {
			if (!rz_cons_yesno('n', "Are you sure to repeat this %" PFMT64d " times? (y/N)", rep)) {
				goto beach;
			}
		}
	}
	// TODO: store in core->cmdtimes to speedup ?
	const char *cmdrep = core->cmdtimes ? core->cmdtimes : "";
	orep = rep;

	rz_cons_break_push(NULL, NULL);

	int ocur_enabled = core->print && core->print->cur_enabled;
	while (rep-- && *cmd) {
		if (core->print) {
			core->print->cur_enabled = false;
			if (ocur_enabled && core->seltab >= 0) {
				if (core->seltab == core->curtab) {
					core->print->cur_enabled = true;
				}
			}
		}
		if (rz_cons_is_breaked()) {
			break;
		}
		char *cr = strdup(cmdrep);
		core->break_loop = false;
		ret = rz_core_cmd_subst_i(core, cmd, colon, (rep == orep - 1) ? &tmpseek : NULL);
		if (ret && *cmd == 'q') {
			free(cr);
			goto beach;
		}
		if (core->break_loop) {
			free(cr);
			break;
		}
		if (cr && *cr && orep > 1) {
			// XXX: do not flush here, we need rz_cons_push () and rz_cons_pop()
			rz_cons_flush();
			// XXX: we must import register flags in C
			rz_core_reg_update_flags(core);
			(void)rz_core_cmd0(core, cr);
		}
		free(cr);
	}

	rz_cons_break_pop();

	if (tmpseek) {
		rz_core_seek(core, orig_offset, true);
		core->tmpseek = original_tmpseek;
	}
	if (core->print) {
		core->print->cur_enabled = ocur_enabled;
	}
	if (colon && colon[1]) {
		for (++colon; *colon == ';'; colon++) {
			;
		}
		rz_core_cmd_subst(core, colon);
	} else {
		if (!*icmd) {
			rz_core_cmd_nullcallback(core);
		}
	}
beach:
	free(icmd);
	return ret;
}

static char *find_eoq(char *p) {
	for (; *p; p++) {
		if (*p == '"') {
			break;
		}
		if (*p == '\\' && p[1] == '"') {
			p++;
		}
	}
	return p;
}

static char *findSeparator(char *p) {
	char *q = strchr(p, '+');
	if (q) {
		return q;
	}
	return strchr(p, '-');
}

static void tmpenvs_free(void *item) {
	rz_sys_setenv(item, NULL);
	free(item);
}

static bool set_tmp_arch(RzCore *core, char *arch, char **tmparch) {
	rz_return_val_if_fail(tmparch, false);
	*tmparch = strdup(rz_config_get(core->config, "asm.arch"));
	rz_config_set(core->config, "asm.arch", arch);
	core->fixedarch = true;
	return true;
}

static bool set_tmp_bits(RzCore *core, int bits, char **tmpbits, int *cmd_ignbithints) {
	rz_return_val_if_fail(tmpbits, false);
	*tmpbits = strdup(rz_config_get(core->config, "asm.bits"));
	rz_config_set_i(core->config, "asm.bits", bits);
	core->fixedbits = true;
	// XXX: why?
	*cmd_ignbithints = rz_config_get_i(core->config, "analysis.ignbithints");
	rz_config_set_i(core->config, "analysis.ignbithints", 1);
	return true;
}

static int rz_core_cmd_subst_i(RzCore *core, char *cmd, char *colon, bool *tmpseek) {
	RzList *tmpenvs = rz_list_newf(tmpenvs_free);
	const char *quotestr = "`";
	const char *tick = NULL;
	char *ptr, *ptr2, *str;
	char *arroba = NULL;
	char *grep = NULL;
	RzIODesc *tmpdesc = NULL;
	int pamode = !core->io->va;
	int i, ret = 0, pipefd;
	bool usemyblock = false;
	int scr_html = -1;
	int scr_color = -1;
	bool eos = false;
	bool haveQuote = false;
	bool oldfixedarch = core->fixedarch;
	bool oldfixedbits = core->fixedbits;
	bool cmd_tmpseek = false;
	ut64 tmpbsz = core->blocksize;
	int cmd_ignbithints = -1;

	if (!cmd) {
		rz_list_free(tmpenvs);
		return 0;
	}
	rz_str_trim(cmd);

	char *$0 = strstr(cmd, "$(");
	if ($0) {
		char *$1 = strchr($0 + 2, ')');
		if ($1) {
			*$0 = '`';
			*$1 = '`';
			memmove($0 + 1, $0 + 2, strlen($0 + 2) + 1);
		} else {
			eprintf("Unterminated $() block\n");
		}
	}

	/* quoted / raw command */
	switch (*cmd) {
	case '.':
		if (cmd[1] == '"') { /* interpret */
			rz_list_free(tmpenvs);
			return rz_cmd_call(core->rcmd, cmd);
		}
		break;
	case '"':
		for (; *cmd;) {
			int pipefd = -1;
			ut64 oseek = UT64_MAX;
			char *line, *p;
			haveQuote = *cmd == '"';
			if (haveQuote) {
				cmd++;
				p = *cmd ? find_eoq(cmd) : NULL;
				if (!p || !*p) {
					eprintf("Missing \" in (%s).", cmd);
					rz_list_free(tmpenvs);
					return false;
				}
				*p++ = 0;
				if (!*p) {
					eos = true;
				}
			} else {
				char *sc = strchr(cmd, ';');
				if (sc) {
					*sc = 0;
				}
				rz_core_cmd0(core, cmd);
				if (!sc) {
					break;
				}
				cmd = sc + 1;
				continue;
			}
			char op0 = 0;
			if (*p) {
				// workaround :D
				if (p[0] == '@') {
					p--;
				}
				while (p[1] == ';' || IS_WHITESPACE(p[1])) {
					p++;
				}
				if (p[1] == '@' || (p[1] && p[2] == '@')) {
					char *q = strchr(p + 1, '"');
					if (q) {
						op0 = *q;
						*q = 0;
					}
					haveQuote = q != NULL;
					oseek = core->offset;
					rz_core_seek(core, rz_num_math(core->num, p + 2), true);
					if (q) {
						*p = '"';
						p = q;
					} else {
						p = strchr(p + 1, ';');
					}
				}
				if (p && *p && p[1] == '>') {
					str = p + 2;
					while (*str == '>') {
						str++;
					}
					str = (char *)rz_str_trim_head_ro(str);
					rz_cons_flush();
					const bool append = p[2] == '>';
					pipefd = rz_cons_pipe_open(str, 1, append);
				}
			}
			line = strdup(cmd);
			line = rz_str_replace(line, "\\\"", "\"", true);
			if (p && *p && p[1] == '|') {
				str = (char *)rz_str_trim_head_ro(p + 2);
				rz_core_cmd_pipe_old(core, cmd, str);
			} else {
				rz_cmd_call(core->rcmd, line);
			}
			free(line);
			if (oseek != UT64_MAX) {
				rz_core_seek(core, oseek, true);
			}
			if (pipefd != -1) {
				rz_cons_flush();
				rz_cons_pipe_close(pipefd);
			}
			if (!p) {
				break;
			}
			if (eos) {
				break;
			}
			if (haveQuote) {
				if (*p == ';') {
					cmd = p + 1;
				} else {
					if (*p == '"') {
						cmd = p;
					} else {
						*p = op0;
						cmd = p;
					}
				}
			} else {
				cmd = p + 1;
			}
		}
		rz_list_free(tmpenvs);
		return true;
	case '(':
		if (cmd[1] != '*' && !strstr(cmd, ")()")) {
			rz_list_free(tmpenvs);
			return rz_cmd_call(core->rcmd, cmd);
		}
		break;
	case '?':
		if (cmd[1] == '>') {
			rz_core_cmd_help(core, help_msg_greater_sign);
			rz_list_free(tmpenvs);
			return true;
		}
	}

	// TODO must honor `
	/* comments */
	if (*cmd != '#') {
		ptr = (char *)rz_str_firstbut(cmd, '#', "`\""); // TODO: use quotestr here
		if (ptr && (ptr[1] == ' ' || ptr[1] == '\t')) {
			*ptr = '\0';
		}
	}

	/* multiple commands */
	// TODO: must honor " and ` boundaries
	// ptr = strrchr (cmd, ';');
	if (*cmd != '#') {
		if (is_macro_command(cmd)) {
			ptr = find_ch_after_macro(cmd, ';');
		} else {
			ptr = (char *)rz_str_lastbut(cmd, ';', quotestr);
		}
		if (colon && ptr) {
			int ret;
			*ptr = '\0';
			if (rz_core_cmd_subst(core, cmd) == -1) {
				rz_list_free(tmpenvs);
				return -1;
			}
			cmd = ptr + 1;
			ret = rz_core_cmd_subst(core, cmd);
			*ptr = ';';
			rz_list_free(tmpenvs);
			return ret;
			// rz_cons_flush ();
		}
	}

	// TODO must honor " and `
	/* pipe console to shell process */
	// ptr = strchr (cmd, '|');
	ptr = (char *)rz_str_lastbut(cmd, '|', quotestr);
	if (ptr) {
		if (ptr > cmd) {
			char *ch = ptr - 1;
			if (*ch == '\\') {
				memmove(ch, ptr, strlen(ptr) + 1);
				goto escape_pipe;
			}
		}
		char *ptr2 = strchr(cmd, '`');
		if (!ptr2 || (ptr2 && ptr2 > ptr)) {
			if (!tick || (tick && tick > ptr)) {
				*ptr = '\0';
				cmd = rz_str_trim_nc(cmd);
				if (!strcmp(ptr + 1, "?")) { // "|?"
					rz_core_cmd_help(core, help_msg_vertical_bar);
					rz_list_free(tmpenvs);
					return ret;
				} else if (!strncmp(ptr + 1, "H", 1)) { // "|H"
					scr_html = rz_config_get_i(core->config, "scr.html");
					rz_config_set_i(core->config, "scr.html", true);
				} else if (!strcmp(ptr + 1, ".")) { // "|."
					ret = *cmd ? rz_core_cmdf(core, ".%s", cmd) : 0;
					rz_list_free(tmpenvs);
					return ret;
				} else if (ptr[1]) { // "| grep .."
					int value = core->num->value;
					if (*cmd) {
						rz_core_cmd_pipe_old(core, cmd, ptr + 1);
					} else {
						char *res = rz_io_system(core->io, ptr + 1);
						if (res) {
							rz_cons_printf("%s\n", res);
							free(res);
						}
					}
					core->num->value = value;
					rz_list_free(tmpenvs);
					return 0;
				} else { // "|"
					scr_html = rz_config_get_i(core->config, "scr.html");
					rz_config_set_i(core->config, "scr.html", 0);
					scr_color = rz_config_get_i(core->config, "scr.color");
					rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
				}
			}
		}
	}
escape_pipe:

	// TODO must honor " and `
	/* bool conditions */
	ptr = (char *)rz_str_lastbut(cmd, '&', quotestr);
	// ptr = strchr (cmd, '&');
	while (ptr && *ptr && ptr[1] == '&') {
		*ptr = '\0';
		ret = rz_cmd_call(core->rcmd, cmd);
		if (ret == -1) {
			eprintf("command error(%s)\n", cmd);
			if (scr_html != -1) {
				rz_config_set_i(core->config, "scr.html", scr_html);
			}
			if (scr_color != -1) {
				rz_config_set_i(core->config, "scr.color", scr_color);
			}
			rz_list_free(tmpenvs);
			return ret;
		}
		for (cmd = ptr + 2; cmd && *cmd == ' '; cmd++) {
			;
		}
		ptr = strchr(cmd, '&');
	}

	ptr = strstr(cmd, "?*");
	if (ptr && (ptr == cmd || ptr[-1] != '~')) {
		ptr[0] = 0;
		if (*cmd != '#') {
			int detail = 0;
			if (cmd < ptr && ptr[-1] == '?') {
				detail++;
				if (cmd < ptr - 1 && ptr[-2] == '?') {
					detail++;
				}
			}
			rz_cons_break_push(NULL, NULL);
			recursive_help(core, detail, cmd);
			rz_cons_break_pop();
			rz_cons_grep_parsecmd(ptr + 2, "`");
			if (scr_html != -1) {
				rz_config_set_i(core->config, "scr.html", scr_html);
			}
			if (scr_color != -1) {
				rz_config_set_i(core->config, "scr.color", scr_color);
			}
			rz_list_free(tmpenvs);
			return 0;
		}
	}

	/* pipe console to file */
	ptr = (char *)rz_str_firstbut(cmd, '>', "\"");
	// TODO honor `
	if (ptr) {
		if (ptr > cmd) {
			char *ch = ptr - 1;
			if (*ch == '\\') {
				memmove(ch, ptr, strlen(ptr) + 1);
				goto escape_redir;
			}
		}
		if (ptr[0] && ptr[1] == '?') {
			rz_core_cmd_help(core, help_msg_greater_sign);
			rz_list_free(tmpenvs);
			return true;
		}
		int fdn = 1;
		int pipecolor = rz_config_get_i(core->config, "scr.color.pipe");
		int use_editor = false;
		int ocolor = rz_config_get_i(core->config, "scr.color");
		*ptr = '\0';
		str = ptr + 1 + (ptr[1] == '>');
		rz_str_trim(str);
		if (!*str) {
			eprintf("No output?\n");
			goto next2;
		}
		/* rz_cons_flush() handles interactive output (to the terminal)
		 * differently (e.g. asking about too long output). This conflicts
		 * with piping to a file. Disable it while piping. */
		if (ptr > (cmd + 1) && IS_WHITECHAR(ptr[-2])) {
			char *fdnum = ptr - 1;
			if (*fdnum == 'H') { // "H>"
				scr_html = rz_config_get_i(core->config, "scr.html");
				rz_config_set_i(core->config, "scr.html", true);
				pipecolor = true;
				*fdnum = 0;
			} else {
				if (IS_DIGIT(*fdnum)) {
					fdn = *fdnum - '0';
				}
				*fdnum = 0;
			}
		}
		rz_cons_set_interactive(false);
		if (!strcmp(str, "-")) {
			use_editor = true;
			str = rz_file_temp("dumpedit");
			rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
		}
		const bool appendResult = (ptr[1] == '>');
		if (*str == '$') {
			// pipe to alias variable
			// register output of command as an alias
			char *o = rz_core_cmd_str(core, cmd);
			if (appendResult) {
				char *oldText = rz_cmd_alias_get(core->rcmd, str, 1);
				if (oldText) {
					char *two = rz_str_newf("%s%s", oldText, o);
					if (two) {
						rz_cmd_alias_set(core->rcmd, str, two, 1);
						free(two);
					}
				} else {
					char *n = rz_str_newf("$%s", o);
					rz_cmd_alias_set(core->rcmd, str, n, 1);
					free(n);
				}
			} else {
				char *n = rz_str_newf("$%s", o);
				rz_cmd_alias_set(core->rcmd, str, n, 1);
				free(n);
			}
			ret = 0;
			free(o);
		} else if (fdn > 0) {
			// pipe to file (or append)
			pipefd = rz_cons_pipe_open(str, fdn, appendResult);
			if (pipefd != -1) {
				if (!pipecolor) {
					rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
				}
				ret = rz_core_cmd_subst(core, cmd);
				rz_cons_flush();
				rz_cons_pipe_close(pipefd);
			}
		}
		rz_cons_set_last_interactive();
		if (!pipecolor) {
			rz_config_set_i(core->config, "scr.color", ocolor);
		}
		if (use_editor) {
			const char *editor = rz_config_get(core->config, "cfg.editor");
			if (editor && *editor) {
				rz_sys_cmdf("%s '%s'", editor, str);
				rz_file_rm(str);
			} else {
				eprintf("No cfg.editor configured\n");
			}
			rz_config_set_i(core->config, "scr.color", ocolor);
			free(str);
		}
		if (scr_html != -1) {
			rz_config_set_i(core->config, "scr.html", scr_html);
		}
		if (scr_color != -1) {
			rz_config_set_i(core->config, "scr.color", scr_color);
		}
		rz_list_free(tmpenvs);
		return ret;
	}
escape_redir:
next2:
	/* sub commands */
	ptr = strchr(cmd, '`');
	if (ptr) {
		if (ptr > cmd) {
			char *ch = ptr - 1;
			if (*ch == '\\') {
				memmove(ch, ptr, strlen(ptr) + 1);
				goto escape_backtick;
			}
		}
		bool empty = false;
		int oneline = 1;
		if (ptr[1] == '`') {
			memmove(ptr, ptr + 1, strlen(ptr));
			oneline = 0;
			empty = true;
		}
		ptr2 = strchr(ptr + 1, '`');
		if (empty) {
			/* do nothing */
		} else if (!ptr2) {
			eprintf("parse: Missing backtick in expression.\n");
			goto fail;
		} else {
			int value = core->num->value;
			*ptr = '\0';
			*ptr2 = '\0';
			if (ptr[1] == '!') {
				str = rz_core_cmd_str_pipe(core, ptr + 1);
			} else {
				// Color disabled when doing backticks ?e `pi 1`
				int ocolor = rz_config_get_i(core->config, "scr.color");
				rz_config_set_i(core->config, "scr.color", 0);
				core->cmd_in_backticks = true;
				str = rz_core_cmd_str(core, ptr + 1);
				core->cmd_in_backticks = false;
				rz_config_set_i(core->config, "scr.color", ocolor);
			}
			if (!str) {
				goto fail;
			}
			// ignore contents if first char is pipe or comment
			if (*str == '|' || *str == '*') {
				eprintf("rz_core_cmd_subst_i: invalid backticked command\n");
				free(str);
				goto fail;
			}
			if (oneline && str) {
				for (i = 0; str[i]; i++) {
					if (str[i] == '\n') {
						str[i] = ' ';
					}
				}
			}
			str = rz_str_append(str, ptr2 + 1);
			cmd = rz_str_append(strdup(cmd), str);
			core->num->value = value;
			ret = rz_core_cmd_subst(core, cmd);
			free(cmd);
			if (scr_html != -1) {
				rz_config_set_i(core->config, "scr.html", scr_html);
			}
			free(str);
			rz_list_free(tmpenvs);
			return ret;
		}
	}
escape_backtick:
	// TODO must honor " and `
	if (*cmd != '"' && *cmd) {
		const char *s = strstr(cmd, "~?");
		if (s) {
			bool showHelp = false;
			if (cmd == s) {
				// ~?
				// ~??
				showHelp = true;
			} else {
				// pd~?
				// pd~??
				if (!strcmp(s, "~??")) {
					showHelp = true;
				}
			}
			if (showHelp) {
				rz_cons_grep_help();
				rz_list_free(tmpenvs);
				return true;
			}
		}
	}
	if (*cmd != '.') {
		grep = rz_cons_grep_strip(cmd, quotestr);
	}

	/* temporary seek commands */
	// if (*cmd != '(' && *cmd != '"') {
	if (*cmd != '"') {
		ptr = strchr(cmd, '@');
		if (ptr == cmd + 1 && *cmd == '?') {
			ptr = NULL;
		}
	} else {
		ptr = NULL;
	}

	cmd_tmpseek = core->tmpseek = ptr != NULL;
	int rc = 0;
	if (ptr) {
		char *f, *ptr2 = strchr(ptr + 1, '!');
		ut64 addr = core->offset;
		bool addr_is_set = false;
		char *tmpbits = NULL;
		const char *offstr = NULL;
		bool is_bits_set = false;
		bool is_arch_set = false;
		char *tmpeval = NULL;
		char *tmpasm = NULL;
		bool flgspc_changed = false;
		int tmpfd = -1;
		size_t sz;
		int len;
		ut8 *buf;

		*ptr++ = '\0';
	repeat_arroba:
		arroba = (ptr[0] && ptr[1] && ptr[2]) ? strchr(ptr + 2, '@') : NULL;
		if (arroba) {
			*arroba = 0;
		}

		for (; *ptr == ' '; ptr++) {
			// nothing to see here
		}
		if (*ptr && ptr[1] == ':') {
			/* do nothing here */
		} else {
			ptr--;
		}

		rz_str_trim_tail(ptr);

		if (ptr[1] == '?') {
			rz_core_cmd_help(core, help_msg_at);
		} else if (ptr[1] == '%') { // "@%"
			char *k = strdup(ptr + 2);
			char *v = strchr(k, '=');
			if (v) {
				*v++ = 0;
				rz_sys_setenv(k, v);
				rz_list_append(tmpenvs, k);
			} else {
				free(k);
			}
		} else if (ptr[1] == '.') { // "@."
			if (ptr[2] == '.') { // "@.."
				if (ptr[3] == '.') { // "@..."
					ut64 addr = rz_num_tail(core->num, core->offset, ptr + 4);
					rz_core_block_size(core, RZ_ABS((st64)addr - (st64)core->offset));
					goto fuji;
				} else {
					addr = rz_num_tail(core->num, core->offset, ptr + 3);
					rz_core_seek(core, addr, true);
					cmd_tmpseek = core->tmpseek = true;
					goto fuji;
				}
			} else {
				// WAT DU
				eprintf("TODO: what do you expect for @. import offset from file maybe?\n");
			}
		} else if (ptr[0] && ptr[1] == ':' && ptr[2]) {
			switch (ptr[0]) {
			case 'F': // "@F:" // temporary flag space
				flgspc_changed = rz_flag_space_push(core->flags, ptr + 2);
				break;
			case 'B': // "@B:#" // seek to the last instruction in current bb
			{
				int index = (int)rz_num_math(core->num, ptr + 2);
				RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
				if (bb) {
					// handle negative indices
					if (index < 0) {
						index = bb->ninstr + index;
					}

					if (index >= 0 && index < bb->ninstr) {
						ut64 inst_addr = rz_analysis_block_get_op_addr(bb, index);
						rz_core_seek(core, inst_addr, true);
						cmd_tmpseek = core->tmpseek = true;
					} else {
						eprintf("The current basic block has %d instructions\n", bb->ninstr);
					}
				} else {
					eprintf("Can't find a basic block for 0x%08" PFMT64x "\n", core->offset);
				}
				break;
			} break;
			case 'f': // "@f:" // slurp file in block
				f = rz_file_slurp(ptr + 2, &sz);
				if (f) {
					{
						RzBuffer *b = rz_buf_new_with_bytes((const ut8 *)f, (ut64)sz);
						RzIODesc *d = rz_io_open_buffer(core->io, b, RZ_PERM_RWX, 0);
						if (d) {
							if (tmpdesc) {
								rz_io_desc_close(tmpdesc);
							}
							tmpdesc = d;
							if (pamode) {
								rz_config_set_i(core->config, "io.va", 1);
							}
							rz_io_map_new(core->io, d->fd, d->perm, 0, core->offset, rz_buf_size(b));
						}
					}
				} else {
					eprintf("cannot open '%s'\n", ptr + 3);
				}
				break;
			case 'r': // "@r:" // regname
				if (ptr[1] == ':') {
					ut64 regval;
					char *mander = strdup(ptr + 2);
					char *sep = findSeparator(mander);
					if (sep) {
						char ch = *sep;
						*sep = 0;
						regval = rz_debug_reg_get(core->dbg, mander);
						*sep = ch;
						char *numexpr = rz_str_newf("0x%" PFMT64x "%s", regval, sep);
						regval = rz_num_math(core->num, numexpr);
						free(numexpr);
					} else {
						regval = rz_debug_reg_get(core->dbg, ptr + 2);
					}
					rz_core_seek(core, regval, true);
					cmd_tmpseek = core->tmpseek = true;
					free(mander);
				}
				break;
			case 'b': // "@b:" // bits
				is_bits_set = set_tmp_bits(core, rz_num_math(core->num, ptr + 2), &tmpbits, &cmd_ignbithints);
				break;
			case 'i': // "@i:"
			{
				ut64 addr = rz_num_math(core->num, ptr + 2);
				if (addr) {
					rz_core_seek_opcode(core, addr, false);
					cmd_tmpseek = core->tmpseek = true;
				}
			} break;
			case 'e': // "@e:"
			{
				char *cmd = parse_tmp_evals(core, ptr + 2);
				if (!tmpeval) {
					tmpeval = cmd;
				} else {
					tmpeval = rz_str_prepend(tmpeval, cmd);
					free(cmd);
				}
			} break;
			case 'v': // "@v:" // value (honors asm.bits and cfg.bigendian)
				if (ptr[1] == ':') {
					ut8 buf[8] = { 0 };
					ut64 v = rz_num_math(core->num, ptr + 2);
					int be = rz_config_get_i(core->config, "cfg.bigendian");
					int bi = rz_config_get_i(core->config, "asm.bits");
					if (bi == 64) {
						rz_write_ble64(buf, v, be);
						len = 8;
					} else {
						rz_write_ble32(buf, v, be);
						len = 4;
					}
					rz_core_block_size(core, RZ_ABS(len));
					RzBuffer *b = rz_buf_new_with_bytes(buf, len);
					RzIODesc *d = rz_io_open_buffer(core->io, b, RZ_PERM_RWX, 0);
					if (d) {
						if (tmpdesc) {
							rz_io_desc_close(tmpdesc);
						}
						tmpdesc = d;
						if (pamode) {
							rz_config_set_i(core->config, "io.va", 1);
						}
						rz_io_map_new(core->io, d->fd, d->perm, 0, core->offset, rz_buf_size(b));
						rz_core_block_size(core, len);
						rz_core_block_read(core);
					}
				} else {
					eprintf("Invalid @v: syntax\n");
				}
				break;
			case 'x': // "@x:" // hexpairs
				if (ptr[1] == ':') {
					buf = malloc(strlen(ptr + 2) + 1);
					if (buf) {
						len = rz_hex_str2bin(ptr + 2, buf);
						rz_core_block_size(core, RZ_ABS(len));
						if (len > 0) {
							RzBuffer *b = rz_buf_new_with_bytes(buf, len);
							RzIODesc *d = rz_io_open_buffer(core->io, b, RZ_PERM_RWX, 0);
							if (d) {
								if (tmpdesc) {
									rz_io_desc_close(tmpdesc);
								}
								tmpdesc = d;
								if (pamode) {
									rz_config_set_i(core->config, "io.va", 1);
								}
								rz_io_map_new(core->io, d->fd, d->perm, 0, core->offset, rz_buf_size(b));
								rz_core_block_size(core, len);
								rz_core_block_read(core);
							}
						} else {
							eprintf("Error: Invalid hexpairs for @x:\n");
						}
						free(buf);
					} else {
						eprintf("cannot allocate\n");
					}
				} else {
					eprintf("Invalid @x: syntax\n");
				}
				break;
			case 'k': // "@k"
			{
				char *out = sdb_querys(core->sdb, NULL, 0, ptr + ((ptr[1]) ? 2 : 1));
				if (out) {
					rz_core_seek(core, rz_num_math(core->num, out), true);
					free(out);
					usemyblock = true;
				}
			} break;
			case 'o': // "@o:3"
				if (ptr[1] == ':') {
					tmpfd = core->io->desc ? core->io->desc->fd : -1;
					rz_io_use_fd(core->io, atoi(ptr + 2));
				}
				break;
			case 'a': // "@a:"
				if (ptr[1] == ':') {
					char *q = strchr(ptr + 2, ':');
					if (q) {
						*q++ = 0;
						int bits = rz_num_math(core->num, q);
						is_bits_set = set_tmp_bits(core, bits, &tmpbits, &cmd_ignbithints);
					}
					is_arch_set = set_tmp_arch(core, ptr + 2, &tmpasm);
				} else {
					eprintf("Usage: pd 10 @a:arm:32\n");
				}
				break;
			case 's': // "@s:" // wtf syntax
			{
				len = strlen(ptr + 2);
				rz_core_block_size(core, len);
				const ut8 *buf = (const ut8 *)rz_str_trim_head_ro(ptr + 2);

				if (len > 0) {
					RzBuffer *b = rz_buf_new_with_bytes(buf, len);
					RzIODesc *d = rz_io_open_buffer(core->io, b, RZ_PERM_RWX, 0);
					if (!core->io->va) {
						rz_config_set_i(core->config, "io.va", 1);
					}
					if (d) {
						if (tmpdesc) {
							rz_io_desc_close(tmpdesc);
						}
						tmpdesc = d;
						if (pamode) {
							rz_config_set_i(core->config, "io.va", 1);
						}
						rz_io_map_new(core->io, d->fd, d->perm, 0, core->offset, rz_buf_size(b));
						rz_core_block_size(core, len);
						// rz_core_block_read (core);
					}
				}
			} break;
			default:
				goto ignore;
			}
			*ptr = '@';
			/* trim whitespaces before the @ */
			/* Fixes pd @x:9090 */
			char *trim = ptr - 2;
			while (trim > cmd) {
				if (!IS_WHITESPACE(*trim)) {
					break;
				}
				*trim = 0;
				trim--;
			}
			goto next_arroba;
		}
	ignore:
		rz_str_trim_head(ptr + 1);
		cmd = rz_str_trim_nc(cmd);
		if (ptr2) {
			if (strlen(ptr + 1) == 13 && strlen(ptr2 + 1) == 6 &&
				!memcmp(ptr + 1, "0x", 2) &&
				!memcmp(ptr2 + 1, "0x", 2)) {
				/* 0xXXXX:0xYYYY */
			} else if (strlen(ptr + 1) == 9 && strlen(ptr2 + 1) == 4) {
				/* XXXX:YYYY */
			} else {
				*ptr2 = '\0';
				if (!ptr2[1]) {
					goto fail;
				}
				rz_core_block_size(
					core, rz_num_math(core->num, ptr2 + 1));
			}
		}

		rz_str_trim_head(ptr + 1);
		offstr = ptr + 1;

		addr = (*offstr == '{') ? core->offset : rz_num_math(core->num, offstr);
		addr_is_set = true;

		if (isalpha((ut8)ptr[1]) && !addr) {
			if (!rz_flag_get(core->flags, ptr + 1)) {
				eprintf("Invalid address (%s)\n", ptr + 1);
				goto fail;
			}
		} else {
			char ch = *offstr;
			if (ch == '-' || ch == '+') {
				addr = core->offset + addr;
			}
		}
		// remap thhe tmpdesc if any
		if (addr) {
			RzIODesc *d = tmpdesc;
			if (d) {
				rz_io_map_new(core->io, d->fd, d->perm, 0, addr, rz_io_desc_size(d));
			}
		}
	next_arroba:
		if (arroba) {
			ptr = arroba + 1;
			*arroba = '@';
			arroba = NULL;
			goto repeat_arroba;
		}
		core->fixedblock = !!tmpdesc;
		if (core->fixedblock) {
			rz_core_block_read(core);
		}
		if (ptr[1] == '@') {
			if (ptr[2] == '@') {
				char *rule = ptr + 3;
				while (*rule && *rule == ' ') {
					rule++;
				}
				ret = rz_core_cmd_foreach3(core, cmd, rule);
			} else {
				ret = rz_core_cmd_foreach(core, cmd, ptr + 2);
			}
		} else {
			bool tmpseek = false;
			const char *fromvars[] = { "analysis.from", "diff.from", "graph.from", "search.from", "zoom.from", NULL };
			const char *tovars[] = { "analysis.to", "diff.to", "graph.to", "search.to", "zoom.to", NULL };
			ut64 curfrom[RZ_ARRAY_SIZE(fromvars) - 1], curto[RZ_ARRAY_SIZE(tovars) - 1];

			// "@{A B}"
			if (ptr[1] == '{') {
				char *range = ptr + 2;
				char *p = strchr(range, ' ');
				if (!p) {
					eprintf("Usage: / ABCD @{0x1000 0x3000}\n");
					eprintf("Run command and define the following vars:\n");
					eprintf(" (analysis|diff|graph|search|zoom).{from,to}\n");
					free(tmpeval);
					free(tmpasm);
					free(tmpbits);
					goto fail;
				}
				char *arg = p + 1;
				int arg_len = strlen(arg);
				if (arg_len > 0) {
					arg[arg_len - 1] = 0;
				}
				*p = '\x00';
				ut64 from = rz_num_math(core->num, range);
				ut64 to = rz_num_math(core->num, arg);
				// save current ranges
				for (i = 0; fromvars[i]; i++) {
					curfrom[i] = rz_config_get_i(core->config, fromvars[i]);
				}
				for (i = 0; tovars[i]; i++) {
					curto[i] = rz_config_get_i(core->config, tovars[i]);
				}
				// set new ranges
				for (i = 0; fromvars[i]; i++) {
					rz_config_set_i(core->config, fromvars[i], from);
				}
				for (i = 0; tovars[i]; i++) {
					rz_config_set_i(core->config, tovars[i], to);
				}
				tmpseek = true;
			}
			if (usemyblock) {
				if (addr_is_set) {
					core->offset = addr;
				}
				ret = rz_cmd_call(core->rcmd, rz_str_trim_head_ro(cmd));
			} else {
				if (addr_is_set) {
					if (ptr[1]) {
						rz_core_seek(core, addr, true);
						rz_core_block_read(core);
					}
				}
				ret = rz_cmd_call(core->rcmd, rz_str_trim_head_ro(cmd));
			}
			if (tmpseek) {
				// restore ranges
				for (i = 0; fromvars[i]; i++) {
					rz_config_set_i(core->config, fromvars[i], curfrom[i]);
				}
				for (i = 0; tovars[i]; i++) {
					rz_config_set_i(core->config, tovars[i], curto[i]);
				}
			}
		}
		if (ptr2) {
			*ptr2 = '!';
			rz_core_block_size(core, tmpbsz);
		}
		if (is_arch_set) {
			core->fixedarch = oldfixedarch;
			rz_config_set(core->config, "asm.arch", tmpasm);
			RZ_FREE(tmpasm);
		}
		if (tmpfd != -1) {
			// TODO: reuse tmpfd instead of
			rz_io_use_fd(core->io, tmpfd);
		}
		if (tmpdesc) {
			if (pamode) {
				rz_config_set_i(core->config, "io.va", 0);
			}
			rz_io_desc_close(tmpdesc);
			tmpdesc = NULL;
		}
		if (is_bits_set) {
			rz_config_set(core->config, "asm.bits", tmpbits);
			core->fixedbits = oldfixedbits;
		}
		if (tmpbsz != core->blocksize) {
			rz_core_block_size(core, tmpbsz);
		}
		if (tmpeval) {
			rz_core_cmd0(core, tmpeval);
			RZ_FREE(tmpeval);
		}
		if (flgspc_changed) {
			rz_flag_space_pop(core->flags);
		}
		*ptr = '@';
		rc = ret;
		goto beach;
	}
fuji:
	if (cmd) {
		rz_str_trim_head(cmd);
		rc = rz_cmd_call(core->rcmd, cmd);
	} else {
		rc = false;
	}
beach:
	if (grep) {
		char *old_grep = grep;
		grep = rz_cmd_unescape_arg(old_grep, true);
		free(old_grep);
	}
	rz_cons_grep_process(grep);
	if (scr_html != -1) {
		rz_cons_flush();
		rz_config_set_i(core->config, "scr.html", scr_html);
	}
	if (scr_color != -1) {
		rz_config_set_i(core->config, "scr.color", scr_color);
	}
	rz_list_free(tmpenvs);
	if (tmpdesc) {
		rz_io_desc_close(tmpdesc);
		tmpdesc = NULL;
	}
	core->fixedarch = oldfixedarch;
	core->fixedbits = oldfixedbits;
	if (tmpseek) {
		*tmpseek = cmd_tmpseek;
	}
	if (cmd_ignbithints != -1) {
		rz_config_set_i(core->config, "analysis.ignbithints", cmd_ignbithints);
	}
	return rc;
fail:
	rc = -1;
	goto beach;
}

struct exec_command_t {
	RzCore *core;
	const char *cmd;
};

static bool copy_into_flagitem_list(RzFlagItem *flg, void *u) {
	RzFlagItem *fi = rz_mem_dup(flg, sizeof(RzFlagItem));
	rz_list_append(u, fi);
	return true;
}

static void foreach_pairs(RzCore *core, const char *cmd, const char *each) {
	const char *arg;
	int pair = 0;
	for (arg = each;;) {
		if (!arg) {
			return;
		}
		char *next = strchr(arg, ' ');
		if (next) {
			*next = 0;
		}
		if (arg && *arg) {
			ut64 n = rz_num_get(NULL, arg);
			if (pair % 2) {
				rz_core_block_size(core, n);
				rz_core_cmd0(core, cmd);
			} else {
				rz_core_seek(core, n, true);
			}
			pair++;
		}
		if (!next) {
			break;
		}
		arg = next + 1;
	}
}

RZ_API int rz_core_cmd_foreach3(RzCore *core, const char *cmd, char *each) { // "@@@"
	RzDebug *dbg = core->dbg;
	RzList *list;
	const RzList *head;
	RzListIter *iter;
	int i;
	const char *filter = NULL;

	if (each[0] && each[1] == ':') {
		filter = each + 2;
	}

	switch (each[0]) {
	case '=':
		foreach_pairs(core, cmd, each + 1);
		break;
	case '?':
		rz_core_cmd_help(core, help_msg_at_at_at);
		break;
	case 'c':
		if (filter) {
			char *arg = rz_core_cmd_str(core, filter);
			foreach_pairs(core, cmd, arg);
			free(arg);
		} else {
			eprintf("Usage: @@@c:command   # same as @@@=`command`\n");
		}
		break;
	case 'C': {
		char *glob = filter ? rz_str_trim_dup(filter) : NULL;
		RzIntervalTreeIter it;
		RzAnalysisMetaItem *meta;
		rz_interval_tree_foreach (&core->analysis->meta, it, meta) {
			if (meta->type != RZ_META_TYPE_COMMENT) {
				continue;
			}
			if (!glob || (meta->str && rz_str_glob(meta->str, glob))) {
				rz_core_seek(core, rz_interval_tree_iter_get(&it)->start, true);
				rz_core_cmd0(core, cmd);
			}
		}
		free(glob);
		break;
	}
	case 'm': {
		int fd = rz_io_fd_get_current(core->io);
		// only iterate maps of current fd
		RzList *maps = rz_io_map_get_for_fd(core->io, fd);
		RzIOMap *map;
		if (maps) {
			RzListIter *iter;
			rz_list_foreach (maps, iter, map) {
				rz_core_seek(core, map->itv.addr, true);
				rz_core_block_size(core, map->itv.size);
				rz_core_cmd0(core, cmd);
			}
			rz_list_free(maps);
		}
	} break;
	case 'M':
		if (dbg && dbg->cur && dbg->maps) {
			RzDebugMap *map;
			rz_list_foreach (dbg->maps, iter, map) {
				rz_core_seek(core, map->addr, true);
				// rz_core_block_size (core, map->size);
				rz_core_cmd0(core, cmd);
			}
		}
		break;
	case 't':
		// iterate over all threads
		if (dbg && dbg->cur && dbg->cur->threads) {
			int origpid = dbg->pid;
			RzDebugPid *p;
			list = dbg->cur->threads(dbg, dbg->pid);
			if (!list) {
				return false;
			}
			rz_list_foreach (list, iter, p) {
				rz_core_cmdf(core, "dp %d", p->pid);
				rz_cons_printf("PID %d\n", p->pid);
				rz_core_cmd0(core, cmd);
			}
			rz_core_cmdf(core, "dp %d", origpid);
			rz_list_free(list);
		}
		break;
	case 'r': // @@@r
	{
		RzReg *reg = rz_core_reg_default(core);
		ut64 offorig = core->offset;
		for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
			RzRegItem *item;
			ut64 value;
			head = rz_reg_get_list(reg, i);
			if (!head) {
				continue;
			}
			RzList *list = rz_list_newf(free);
			rz_list_foreach (head, iter, item) {
				if (item->size != core->analysis->bits) {
					continue;
				}
				if (item->type != i) {
					continue;
				}
				rz_list_append(list, strdup(item->name));
			}
			const char *item_name;
			rz_list_foreach (list, iter, item_name) {
				value = rz_reg_getv(reg, item_name);
				rz_core_seek(core, value, true);
				rz_cons_printf("%s: ", item_name);
				rz_core_cmd0(core, cmd);
			}
			rz_list_free(list);
		}
		rz_core_seek(core, offorig, true);
	} break;
	case 'i': // @@@i
	{
		RzBinImport *imp;
		ut64 offorig = core->offset;
		list = rz_bin_get_imports(core->bin);
		RzList *lost = rz_list_newf(free);
		rz_list_foreach (list, iter, imp) {
			char *impflag = rz_str_newf("sym.imp.%s", imp->name);
			ut64 addr = rz_num_math(core->num, impflag);
			ut64 *n = RZ_NEW(ut64);
			*n = addr;
			rz_list_append(lost, n);
			free(impflag);
		}
		ut64 *naddr;
		rz_list_foreach (lost, iter, naddr) {
			ut64 addr = *naddr;
			if (addr && addr != UT64_MAX) {
				rz_core_seek(core, addr, true);
				rz_core_cmd0(core, cmd);
			}
		}
		rz_core_seek(core, offorig, true);
		rz_list_free(lost);
	} break;
	case 'S': // "@@@S"
	{
		RzBinObject *obj = rz_bin_cur_object(core->bin);
		if (obj) {
			ut64 offorig = core->offset;
			ut64 bszorig = core->blocksize;
			RzBinSection *sec;
			RzListIter *iter;
			rz_list_foreach (obj->sections, iter, sec) {
				rz_core_seek(core, sec->vaddr, true);
				rz_core_block_size(core, sec->vsize);
				rz_core_cmd0(core, cmd);
			}
			rz_core_block_size(core, bszorig);
			rz_core_seek(core, offorig, true);
		}
	}
#if ATTIC
		if (each[1] == 'S') {
			RzListIter *it;
			RzBinSection *sec;
			RzBinObject *obj = rz_bin_cur_object(core->bin);
			int cbsz = core->blocksize;
			rz_list_foreach (obj->sections, it, sec) {
				ut64 addr = sec->vaddr;
				ut64 size = sec->vsize;
				// TODO:
				// if (RZ_BIN_SCN_EXECUTABLE & sec->perm) {
				//	continue;
				//}
				rz_core_seek_size(core, addr, size);
				rz_core_cmd(core, cmd, 0);
			}
			rz_core_block_size(core, cbsz);
		}
#endif
		break;
	case 's':
		if (each[1] == 't') { // strings
			list = rz_bin_get_strings(core->bin);
			if (list) {
				ut64 offorig = core->offset;
				ut64 obs = core->blocksize;
				RzBinString *s;
				RzList *lost = rz_list_newf(free);
				rz_list_foreach (list, iter, s) {
					RzBinString *bs = rz_mem_dup(s, sizeof(RzBinString));
					rz_list_append(lost, bs);
				}
				rz_list_foreach (lost, iter, s) {
					rz_core_block_size(core, s->size);
					rz_core_seek(core, s->vaddr, true);
					rz_core_cmd0(core, cmd);
				}
				rz_core_block_size(core, obs);
				rz_core_seek(core, offorig, true);
				rz_list_free(lost);
			}
		} else {
			// symbols
			RzBinSymbol *sym;
			ut64 offorig = core->offset;
			ut64 obs = core->blocksize;
			list = rz_bin_get_symbols(core->bin);
			rz_cons_break_push(NULL, NULL);
			RzList *lost = rz_list_newf(free);
			rz_list_foreach (list, iter, sym) {
				RzBinSymbol *bs = rz_mem_dup(sym, sizeof(RzBinSymbol));
				rz_list_append(lost, bs);
			}
			rz_list_foreach (lost, iter, sym) {
				if (rz_cons_is_breaked()) {
					break;
				}
				rz_core_block_size(core, sym->size);
				rz_core_seek(core, sym->vaddr, true);
				rz_core_cmd0(core, cmd);
			}
			rz_cons_break_pop();
			rz_list_free(lost);
			rz_core_block_size(core, obs);
			rz_core_seek(core, offorig, true);
		}
		break;
	case 'f': // flags
	{
		// TODO: honor ^C
		char *glob = filter ? rz_str_trim_dup(filter) : NULL;
		ut64 off = core->offset;
		ut64 obs = core->blocksize;
		RzList *flags = rz_list_newf(free);
		rz_flag_foreach_glob(core->flags, glob, copy_into_flagitem_list, flags);
		RzListIter *iter;
		RzFlagItem *f;
		rz_list_foreach (flags, iter, f) {
			rz_core_block_size(core, f->size);
			rz_core_seek(core, f->offset, true);
			rz_core_cmd0(core, cmd);
		}
		rz_core_seek(core, off, false);
		rz_core_block_size(core, obs);
		free(glob);
	} break;
	case 'F': // functions
	{
		ut64 obs = core->blocksize;
		ut64 offorig = core->offset;
		RzAnalysisFunction *fcn;
		list = core->analysis->fcns;
		rz_cons_break_push(NULL, NULL);
		rz_list_foreach (list, iter, fcn) {
			if (rz_cons_is_breaked()) {
				break;
			}
			if (!filter || rz_str_glob(fcn->name, filter)) {
				rz_core_seek(core, fcn->addr, true);
				rz_core_block_size(core, rz_analysis_function_linear_size(fcn));
				rz_core_cmd0(core, cmd);
			}
		}
		rz_cons_break_pop();
		rz_core_block_size(core, obs);
		rz_core_seek(core, offorig, true);
	} break;
	case 'b': {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		ut64 offorig = core->offset;
		ut64 obs = core->blocksize;
		if (fcn) {
			RzListIter *iter;
			RzAnalysisBlock *bb;
			rz_list_foreach (fcn->bbs, iter, bb) {
				rz_core_seek(core, bb->addr, true);
				rz_core_block_size(core, bb->size);
				rz_core_cmd0(core, cmd);
			}
			rz_core_block_size(core, obs);
			rz_core_seek(core, offorig, true);
		}
	} break;
	}
	return 0;
}

static void foreachOffset(RzCore *core, const char *_cmd, const char *each) {
	char *cmd = strdup(_cmd);
	char *nextLine = NULL;
	ut64 addr;
	/* foreach list of items */
	while (each) {
		// skip spaces
		while (*each == ' ') {
			each++;
		}
		// stahp if empty string
		if (!*each) {
			break;
		}
		// find newline
		char *nl = strchr(each, '\n');
		if (nl) {
			*nl = 0;
			nextLine = nl + 1;
		} else {
			nextLine = NULL;
		}
		// chop comment in line
		nl = strchr(each, '#');
		if (nl) {
			*nl = 0;
		}
		// space separated numbers
		while (each && *each) {
			// find spaces
			while (*each == ' ') {
				each++;
			}
			char *str = strchr(each, ' ');
			if (str) {
				*str = '\0';
				addr = rz_num_math(core->num, each);
				*str = ' ';
				each = str + 1;
			} else {
				if (!*each) {
					break;
				}
				addr = rz_num_math(core->num, each);
				each = NULL;
			}
			rz_core_seek(core, addr, true);
			rz_core_cmd(core, cmd, 0);
			rz_cons_flush();
		}
		each = nextLine;
	}
	free(cmd);
}

static int bb_cmp(const void *a, const void *b) {
	const RzAnalysisBlock *ba = a;
	const RzAnalysisBlock *bb = b;
	return ba->addr - bb->addr;
}

RZ_API int rz_core_cmd_foreach(RzCore *core, const char *cmd, char *each) {
	int i, j;
	char ch;
	char *word = NULL;
	char *str, *ostr = NULL;
	RzListIter *iter;
	RzFlagItem *flag;
	ut64 oseek, addr;

	for (; *cmd == ' '; cmd++) {
		;
	}

	oseek = core->offset;
	ostr = str = strdup(each);
	rz_cons_break_push(NULL, NULL); // pop on return
	switch (each[0]) {
	case '/': // "@@/"
	{
		char *cmdhit = strdup(rz_config_get(core->config, "cmd.hit"));
		rz_config_set(core->config, "cmd.hit", cmd);
		rz_core_cmd0(core, each);
		rz_config_set(core->config, "cmd.hit", cmdhit);
		free(cmdhit);
	}
		free(ostr);
		return 0;
	case '?': // "@@?"
		rz_core_cmd_help(core, help_msg_at_at);
		break;
	case 'b': // "@@b" - function basic blocks
	{
		RzListIter *iter;
		RzAnalysisBlock *bb;
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, core->offset);
		int bs = core->blocksize;
		if (fcn) {
			rz_list_sort(fcn->bbs, bb_cmp);
			rz_list_foreach (fcn->bbs, iter, bb) {
				rz_core_block_size(core, bb->size);
				rz_core_seek(core, bb->addr, true);
				rz_core_cmd(core, cmd, 0);
				if (rz_cons_is_breaked()) {
					break;
				}
			}
		}
		rz_core_block_size(core, bs);
		goto out_finish;
	} break;
	case 's': // "@@s" - sequence
	{
		char *str = each + 1;
		if (*str == ':' || *str == ' ') {
			str++;
		}
		int count = rz_str_split(str, ' ');
		if (count == 3) {
			ut64 cur;
			ut64 from = rz_num_math(core->num, rz_str_word_get0(str, 0));
			ut64 to = rz_num_math(core->num, rz_str_word_get0(str, 1));
			ut64 step = rz_num_math(core->num, rz_str_word_get0(str, 2));
			for (cur = from; cur <= to; cur += step) {
				(void)rz_core_seek(core, cur, true);
				rz_core_cmd(core, cmd, 0);
				if (rz_cons_is_breaked()) {
					break;
				}
			}
		} else {
			eprintf("Usage: cmd @@s:from to step\n");
		}
		goto out_finish;
	} break;
	case 'i': // "@@i" - function instructions
	{
		RzListIter *iter;
		RzAnalysisBlock *bb;
		int i;
		RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, core->offset);
		if (fcn) {
			rz_list_sort(fcn->bbs, bb_cmp);
			rz_list_foreach (fcn->bbs, iter, bb) {
				for (i = 0; i < bb->op_pos_size; i++) {
					ut64 addr = bb->addr + bb->op_pos[i];
					rz_core_seek(core, addr, true);
					rz_core_cmd(core, cmd, 0);
					if (rz_cons_is_breaked()) {
						break;
					}
				}
			}
		}
		goto out_finish;
	} break;
	case 'f': // "@@f"
		if (each[1] == ':') {
			RzAnalysisFunction *fcn;
			RzListIter *iter;
			if (core->analysis) {
				rz_list_foreach (core->analysis->fcns, iter, fcn) {
					if (each[2] && strstr(fcn->name, each + 2)) {
						rz_core_seek(core, fcn->addr, true);
						rz_core_cmd(core, cmd, 0);
						if (rz_cons_is_breaked()) {
							break;
						}
					}
				}
			}
			goto out_finish;
		} else {
			RzAnalysisFunction *fcn;
			RzListIter *iter;
			if (core->analysis) {
				RzConsGrep grep = core->cons->context->grep;
				rz_list_foreach (core->analysis->fcns, iter, fcn) {
					char *buf;
					rz_core_seek(core, fcn->addr, true);
					rz_cons_push();
					rz_core_cmd(core, cmd, 0);
					buf = rz_cons_get_buffer_dup();
					rz_cons_pop();
					rz_cons_strcat(buf);
					free(buf);
					if (rz_cons_is_breaked()) {
						break;
					}
				}
				core->cons->context->grep = grep;
			}
			goto out_finish;
		}
		break;
	case 't': // "@@t"
	{
		RzDebugPid *p;
		int pid = core->dbg->pid;
		if (core->dbg->cur && core->dbg->cur->pids) {
			RzList *list = core->dbg->cur->pids(core->dbg, RZ_MAX(0, pid));
			rz_list_foreach (list, iter, p) {
				rz_cons_printf("# PID %d\n", p->pid);
				rz_debug_select(core->dbg, p->pid, p->pid);
				rz_core_cmd(core, cmd, 0);
				rz_cons_newline();
			}
			rz_list_free(list);
		}
		rz_debug_select(core->dbg, pid, pid);
		goto out_finish;
	} break;
	case 'c': // "@@c:"
		if (each[1] == ':') {
			char *arg = rz_core_cmd_str(core, each + 2);
			if (arg) {
				foreachOffset(core, cmd, arg);
				free(arg);
			}
		}
		break;
	case '=': // "@@="
		foreachOffset(core, cmd, str + 1);
		break;
	case 'd': // "@@d"
		if (each[1] == 'b' && each[2] == 't') {
			ut64 oseek = core->offset;
			RzDebugFrame *frame;
			RzListIter *iter;
			RzList *list;
			list = rz_debug_frames(core->dbg, UT64_MAX);
			i = 0;
			rz_list_foreach (list, iter, frame) {
				switch (each[3]) {
				case 'b':
					rz_core_seek(core, frame->bp, true);
					break;
				case 's':
					rz_core_seek(core, frame->sp, true);
					break;
				default:
				case 'a':
					rz_core_seek(core, frame->addr, true);
					break;
				}
				rz_core_cmd(core, cmd, 0);
				rz_cons_newline();
				i++;
			}
			rz_core_seek(core, oseek, false);
			rz_list_free(list);
		} else {
			eprintf("Invalid for-each statement. Use @@=dbt[abs]\n");
		}
		break;
	case 'k': // "@@k"
		/* foreach list of items */
		{
			char *out = sdb_querys(core->sdb, NULL, 0, str + ((str[1]) ? 2 : 1));
			if (out) {
				each = out;
				do {
					while (*each == ' ') {
						each++;
					}
					if (!*each) {
						break;
					}
					str = strchr(each, ' ');
					if (str) {
						*str = '\0';
						addr = rz_num_math(core->num, each);
						*str = ' ';
					} else {
						addr = rz_num_math(core->num, each);
					}
					// eprintf ("; 0x%08"PFMT64x":\n", addr);
					each = str + 1;
					rz_core_seek(core, addr, true);
					rz_core_cmd(core, cmd, 0);
					rz_cons_flush();
				} while (str != NULL);
				free(out);
			}
		}
		break;
	case '.': // "@@."
		if (each[1] == '(') {
			char cmd2[1024];
			// XXX what's this 999 ?
			i = 0;
			for (core->rcmd->macro.counter = 0; i < 999; core->rcmd->macro.counter++) {
				if (rz_cons_is_breaked()) {
					break;
				}
				rz_cmd_macro_call(&core->rcmd->macro, each + 2);
				if (!core->rcmd->macro.brk_value) {
					break;
				}
				addr = core->rcmd->macro._brk_value;
				sprintf(cmd2, "%s @ 0x%08" PFMT64x "", cmd, addr);
				eprintf("0x%08" PFMT64x " (%s)\n", addr, cmd2);
				rz_core_seek(core, addr, true);
				rz_core_cmd(core, cmd2, 0);
				i++;
			}
		} else {
			char buf[1024];
			char cmd2[1024];
			FILE *fd = rz_sys_fopen(each + 1, "r");
			if (fd) {
				core->rcmd->macro.counter = 0;
				while (!feof(fd)) {
					buf[0] = '\0';
					if (!fgets(buf, sizeof(buf), fd)) {
						break;
					}
					addr = rz_num_math(core->num, buf);
					eprintf("0x%08" PFMT64x ": %s\n", addr, cmd);
					sprintf(cmd2, "%s @ 0x%08" PFMT64x "", cmd, addr);
					rz_core_seek(core, addr, true); // XXX
					rz_core_cmd(core, cmd2, 0);
					core->rcmd->macro.counter++;
				}
				fclose(fd);
			} else {
				eprintf("cannot open file '%s' to read offsets\n", each + 1);
			}
		}
		break;
	default:
		core->rcmd->macro.counter = 0;
		for (; *each == ' '; each++) {
			;
		}
		i = 0;
		while (str[i]) {
			j = i;
			for (; str[j] && str[j] == ' '; j++) {
				; // skip spaces
			}
			for (i = j; str[i] && str[i] != ' '; i++) {
				; // find EOS
			}
			ch = str[i];
			str[i] = '\0';
			word = strdup(str + j);
			if (!word) {
				break;
			}
			str[i] = ch;
			{
				const RzSpace *flagspace = rz_flag_space_cur(core->flags);
				RzList *match_flag_items = rz_list_newf((RzListFree)rz_flag_item_free);
				if (!match_flag_items) {
					break;
				}

				/* duplicate flags that match word, to be sure
				   the command is going to be executed on flags
				   values at the moment the command is called
				   (without side effects) */
				struct duplicate_flag_t u = {
					.ret = match_flag_items,
					.word = word,
				};
				rz_flag_foreach_space(core->flags, flagspace, duplicate_flag, &u);

				/* for all flags that match */
				rz_list_foreach (match_flag_items, iter, flag) {
					if (rz_cons_is_breaked()) {
						break;
					}

					char *buf = NULL;
					rz_core_seek(core, flag->offset, true);
					rz_cons_push();
					rz_core_cmd(core, cmd, 0);
					buf = rz_cons_get_buffer_dup();
					rz_cons_pop();
					rz_cons_strcat(buf);
					free(buf);
					rz_core_task_yield(&core->tasks);
				}

				rz_list_free(match_flag_items);
				core->rcmd->macro.counter++;
				RZ_FREE(word);
			}
		}
	}
	rz_cons_break_pop();
	// XXX: use rz_core_seek here
	core->offset = oseek;

	free(word);
	free(ostr);
	return true;
out_finish:
	free(ostr);
	rz_cons_break_pop();
	return false;
}

static int run_cmd_depth(RzCore *core, char *cmd);

struct tsr2cmd_state {
	TSParser *parser;
	RzCore *core;
	char *input;
	RzPVector /*<char *>*/ saved_input;
	TSTree *tree;
	RzPVector /*<TSTree *>*/ saved_tree;
	bool log;
	bool split_lines;
	TSNode substitute_cmd;
};

struct tsr2cmd_edit {
	char *new_text;
	char *old_text;
	ut32 start;
	ut32 end;
	TSPoint start_point;
	TSPoint end_point;
};

typedef RzCmdStatus (*ts_handler)(struct tsr2cmd_state *state, TSNode node);

struct ts_data_symbol_map {
	const char *name;
	void *data;
};

#define TS_START_END(node, start, end) \
	do { \
		start = ts_node_start_byte(node); \
		end = ts_node_end_byte(node); \
	} while (0)

static char *ts_node_sub_string(TSNode node, const char *cstr) {
	ut32 start, end;
	TS_START_END(node, start, end);
	return rz_str_newf("%.*s", end - start, cstr + start);
}

static char *ts_node_sub_parent_string(TSNode parent, TSNode node, const char *cstr) {
	ut32 start, end;
	TS_START_END(node, start, end);
	ut32 parent_start = ts_node_start_byte(parent);
	start -= parent_start;
	end -= parent_start;
	return rz_str_newf("%.*s", end - start, cstr + start);
}

#define DEFINE_SYMBOL_TS_FCN(name) TSSymbol ts_##name##_symbol

#define DEFINE_IS_TS_FCN(name) \
	static inline bool is_ts_##name(TSNode node) { \
		return ts_node_symbol(node) == ts_##name##_symbol; \
	}

#define DEFINE_IS_TS_FCN_AND_SYMBOL(name) \
	DEFINE_SYMBOL_TS_FCN(name); \
	DEFINE_IS_TS_FCN(name)

#define DEFINE_HANDLE_TS_FCN(name) \
	static RzCmdStatus handle_ts_##name##_internal(struct tsr2cmd_state *state, TSNode node, char *node_string); \
	static RzCmdStatus handle_ts_##name(struct tsr2cmd_state *state, TSNode node) { \
		char *node_string = ts_node_sub_string(node, state->input); \
		RZ_LOG_DEBUG(#name ": '%s'\n", node_string); \
		RzCmdStatus res = handle_ts_##name##_internal(state, node, node_string); \
		free(node_string); \
		return res; \
	} \
	static RzCmdStatus handle_ts_##name##_internal(struct tsr2cmd_state *state, TSNode node, char *node_string)

#define DEFINE_HANDLE_TS_FCN_AND_SYMBOL(name) \
	DEFINE_SYMBOL_TS_FCN(name); \
	DEFINE_HANDLE_TS_FCN(name)

#define UPDATE_CMD_STATUS_RES(res, cmd_res, label) \
	if ((cmd_res) != RZ_CMD_STATUS_OK) { \
		res = (cmd_res); \
		goto label; \
	}

static RzCmdStatus handle_ts_stmt(struct tsr2cmd_state *state, TSNode node);
static RzCmdStatus handle_ts_stmt_tmpseek(struct tsr2cmd_state *state, TSNode node);
static RzCmdStatus core_cmd_tsrzcmd(RzCore *core, const char *cstr, bool split_lines, bool log);

static char *system_exec_stdin(bool is_pipe, int argc, char **argv, const ut8 *input, int input_len, int *length) {
	char *output = NULL;
	if (!rz_subprocess_init()) {
		RZ_LOG_ERROR("Cannot initialize subprocess.\n");
		return NULL;
	}

	RzSubprocessOpt opt = {
		.file = argv[0],
		.args = (const char **)&argv[1],
		.args_size = argc - 1,
		.envvars = NULL,
		.envvals = NULL,
		.env_size = 0,
		.stdin_pipe = RZ_SUBPROCESS_PIPE_CREATE,
		.stdout_pipe = is_pipe ? RZ_SUBPROCESS_PIPE_CREATE : RZ_SUBPROCESS_PIPE_NONE,
		.stderr_pipe = is_pipe ? RZ_SUBPROCESS_PIPE_STDOUT : RZ_SUBPROCESS_PIPE_NONE,
	};

	RzSubprocess *proc = rz_subprocess_start_opt(&opt);
	if (!proc) {
		RZ_LOG_ERROR("Cannot start subprocess.\n");
		rz_subprocess_fini();
		return NULL;
	}

	rz_subprocess_stdin_write(proc, input, input_len);
	rz_subprocess_wait(proc, UT64_MAX);

	output = (char *)rz_subprocess_out(proc, length);
	rz_subprocess_free(proc);
	rz_subprocess_fini();

	return output;
}

static ut8 *core_cmd_raw_node(RzCore *core, struct tsr2cmd_state *state, TSNode rizin_cmd, int *length) {
	const char *static_str;
	ut8 *retstr = NULL;
	rz_cons_push();
	if (handle_ts_stmt(state, rizin_cmd) != RZ_CMD_STATUS_OK) {
		rz_cons_pop();
		return NULL;
	}
	rz_cons_filter();

	static_str = rz_cons_get_buffer();
	int len = rz_cons_get_buffer_len();
	retstr = (ut8 *)rz_str_newlen(static_str, len);
	*length = len;

	rz_cons_pop();
	rz_cons_echo(NULL);
	return retstr;
}

/**
 * \brief Executes a rizin command and pipes the result to the stdin of the program specified in argc/argv
 *
 * Executes a rizin command specified in \p rizin_cmd and pipe its stdout to the
 * stdin of the system program specified in \p argc and \p argv arguments.
 *
 * The output of the second program is then sent into RzCons.
 * */
static RzCmdStatus core_cmd_pipe(RzCore *core, struct tsr2cmd_state *state, TSNode rizin_cmd, int argc, char **argv) {
	int length = 0;
	bool is_pipe = core->is_pipe;
	core->is_pipe = true;
	ut8 *bytes = core_cmd_raw_node(core, state, rizin_cmd, &length);
	core->is_pipe = is_pipe;
	if (!bytes) {
		return RZ_CMD_STATUS_ERROR;
	}

	char *out = system_exec_stdin(core->is_pipe, argc, argv, bytes, length, &length);
	if (out) {
		rz_cons_memcat(out, length);
	}

	free(bytes);
	free(out);
	return RZ_CMD_STATUS_OK;
}

DEFINE_IS_TS_FCN_AND_SYMBOL(fdn_redirect_operator)
DEFINE_IS_TS_FCN_AND_SYMBOL(fdn_append_operator)
DEFINE_IS_TS_FCN_AND_SYMBOL(html_redirect_operator)
DEFINE_IS_TS_FCN_AND_SYMBOL(html_append_operator)
DEFINE_IS_TS_FCN_AND_SYMBOL(cmd_substitution_arg)
DEFINE_IS_TS_FCN_AND_SYMBOL(args)
DEFINE_IS_TS_FCN_AND_SYMBOL(arg)
DEFINE_IS_TS_FCN_AND_SYMBOL(arg_identifier)
DEFINE_IS_TS_FCN_AND_SYMBOL(pf_arg)
DEFINE_IS_TS_FCN_AND_SYMBOL(pf_args)
DEFINE_IS_TS_FCN_AND_SYMBOL(pf_dot_cmd_args)
DEFINE_IS_TS_FCN_AND_SYMBOL(pf_new_args)
DEFINE_IS_TS_FCN_AND_SYMBOL(pf_concatenation)
DEFINE_IS_TS_FCN_AND_SYMBOL(double_quoted_arg)
DEFINE_IS_TS_FCN_AND_SYMBOL(single_quoted_arg)
DEFINE_IS_TS_FCN_AND_SYMBOL(concatenation)
DEFINE_IS_TS_FCN_AND_SYMBOL(grep_specifier)
DEFINE_IS_TS_FCN_AND_SYMBOL(statements)

static struct tsr2cmd_edit *create_cmd_edit(struct tsr2cmd_state *state, TSNode arg, char *new_text) {
	struct tsr2cmd_edit *e = RZ_NEW0(struct tsr2cmd_edit);
	ut32 command_start = ts_node_start_byte(state->substitute_cmd);
	TSPoint command_point = ts_node_start_point(state->substitute_cmd);
	e->new_text = new_text;
	e->old_text = ts_node_sub_parent_string(state->substitute_cmd, arg, state->input);
	e->start = ts_node_start_byte(arg) - command_start;
	e->end = ts_node_end_byte(arg) - command_start;
	e->start_point = ts_node_start_point(arg);
	e->end_point = ts_node_end_point(arg);
	if (e->start_point.row == command_point.row) {
		e->start_point.column -= command_point.column;
	}
	if (e->end_point.row == command_point.row) {
		e->end_point.column -= command_point.column;
	}
	e->start_point.row -= command_point.row;
	e->end_point.row -= command_point.row;
	return e;
}

static void replace_whitespaces(char *s, char ch) {
	while (*s) {
		if (*s == '#') {
			while (*s && *s != '\r' && *s != '\n') {
				*s = ch;
				s++;
			}
		}
		if (isspace(*s)) {
			*s = ch;
		}
		s++;
	}
}

void free_tsr2cmd_edit(struct tsr2cmd_edit *edit) {
	free(edit->new_text);
	free(edit->old_text);
	free(edit);
}

static char *do_handle_substitution_cmd(struct tsr2cmd_state *state, TSNode inn_cmd) {
	RzCore *core = state->core;
	int value = core->num->value;
	char *inn_str = ts_node_sub_parent_string(state->substitute_cmd, inn_cmd, state->input);

	// save current color and disable it
	int ocolor = rz_config_get_i(core->config, "scr.color");
	rz_config_set_i(core->config, "scr.color", 0);
	core->cmd_in_backticks = true;

	// execute the sub command
	char *o_out = inn_str[0] == '!' ? rz_core_cmd_str_pipe(core, inn_str) : rz_core_cmd_str(core, inn_str);

	// restore color and cmd_in_backticks
	core->num->value = value;
	core->cmd_in_backticks = false;
	rz_config_set_i(core->config, "scr.color", ocolor);
	free(inn_str);
	if (!o_out) {
		return NULL;
	}

	// replace the output of the sub command with the current argument
	char *out = strdup(o_out);
	rz_str_trim(out);
	RZ_LOG_DEBUG("output of inner command: '%s'\n", out);
	free(o_out);

	// replace newlines and similar with spaces
	replace_whitespaces(out, ' ');
	return out;
}

static void handle_cmd_substitution_arg(struct tsr2cmd_state *state, TSNode arg, RzList *edits) {
	TSNode inn_cmd = ts_node_child(arg, 1);
	rz_return_if_fail(!ts_node_is_null(inn_cmd));
	char *out = do_handle_substitution_cmd(state, inn_cmd);
	if (!out) {
		return;
	}

	char *res = NULL;
	// escape special chars to prevent creation of new tokens when parsing again
	if (is_ts_double_quoted_arg(ts_node_parent(arg))) {
		res = rz_cmd_escape_arg(out, RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG);
	} else if (is_ts_pf_arg(ts_node_parent(arg))) {
		res = rz_cmd_escape_arg(out, RZ_CMD_ESCAPE_PF_ARG);
	} else {
		res = rz_cmd_escape_arg(out, RZ_CMD_ESCAPE_MULTI_ARG);
	}
	free(out);
	struct tsr2cmd_edit *e = create_cmd_edit(state, arg, res);
	rz_list_append(edits, e);
}

static bool is_group_of_args(TSNode args) {
	return is_ts_args(args) || is_ts_concatenation(args) ||
		is_ts_double_quoted_arg(args) ||
		is_ts_pf_concatenation(args) || is_ts_pf_args(args) ||
		is_ts_pf_dot_cmd_args(args) || is_ts_pf_new_args(args) ||
		is_ts_grep_specifier(args);
}

static bool is_arg(TSNode args) {
	return is_ts_arg(args) || is_ts_pf_arg(args);
}

static bool is_handled_args(TSNode args) {
	return is_group_of_args(args) || is_arg(args) ||
		is_ts_cmd_substitution_arg(args) || is_ts_grep_specifier(args);
}

static void handle_substitution_args(struct tsr2cmd_state *state, TSNode args, RzList *edits) {
	if (is_group_of_args(args)) {
		uint32_t n_children = ts_node_named_child_count(args);
		uint32_t i;
		for (i = 0; i < n_children; i++) {
			TSNode arg = ts_node_named_child(args, i);
			handle_substitution_args(state, arg, edits);
		}
	} else if (is_ts_cmd_substitution_arg(args)) {
		handle_cmd_substitution_arg(state, args, edits);
	} else if (is_arg(args)) {
		TSNode arg = ts_node_named_child(args, 0);
		handle_substitution_args(state, arg, edits);
	}
}

static char *do_handle_ts_unescape_arg(struct tsr2cmd_state *state, TSNode arg, bool do_unwrap) {
	if (is_ts_arg(arg)) {
		return do_handle_ts_unescape_arg(state, ts_node_named_child(arg, 0), do_unwrap);
	} else if (is_ts_arg_identifier(arg)) {
		char *arg_str = ts_node_sub_string(arg, state->input);
		char *unescaped_arg = rz_cmd_unescape_arg(arg_str, RZ_CMD_ESCAPE_ONE_ARG);
		free(arg_str);
		return unescaped_arg;
	} else if (is_ts_single_quoted_arg(arg) || is_ts_double_quoted_arg(arg)) {
		char *o_arg_str = ts_node_sub_string(arg, state->input);
		char *arg_str = o_arg_str;
		if (do_unwrap) {
			// remove quotes
			arg_str[strlen(arg_str) - 1] = '\0';
			arg_str++;
		}
		char *res;
		if (is_ts_single_quoted_arg(arg)) {
			res = rz_cmd_unescape_arg(arg_str, RZ_CMD_ESCAPE_SINGLE_QUOTED_ARG);
		} else {
			res = rz_cmd_unescape_arg(arg_str, RZ_CMD_ESCAPE_DOUBLE_QUOTED_ARG);
		}
		free(o_arg_str);
		return res;
	} else if (is_ts_concatenation(arg)) {
		uint32_t i, n_children = ts_node_named_child_count(arg);
		RzStrBuf *sb = rz_strbuf_new(NULL);
		for (i = 0; i < n_children; i++) {
			TSNode sub_arg = ts_node_named_child(arg, i);
			char *s = do_handle_ts_unescape_arg(state, sub_arg, do_unwrap);
			rz_strbuf_append(sb, s);
			free(s);
		}
		return rz_strbuf_drain(sb);
	} else {
		return ts_node_sub_string(arg, state->input);
	}
}

static RzCmdParsedArgs *parse_args(struct tsr2cmd_state *state, TSNode args, bool do_unwrap) {
	if (ts_node_is_null(args)) {
		return rz_cmd_parsed_args_newargs(0, NULL);
	} else if (is_ts_args(args)) {
		uint32_t n_children = ts_node_named_child_count(args);
		uint32_t i;
		char **unescaped_args = RZ_NEWS0(char *, n_children);
		for (i = 0; i < n_children; i++) {
			TSNode arg = ts_node_named_child(args, i);
			unescaped_args[i] = do_handle_ts_unescape_arg(state, arg, do_unwrap);
		}
		RzCmdParsedArgs *res = rz_cmd_parsed_args_newargs(n_children, unescaped_args);
		for (i = 0; i < n_children; i++) {
			free(unescaped_args[i]);
		}
		free(unescaped_args);
		return res;
	} else {
		char *unescaped_args[] = { do_handle_ts_unescape_arg(state, args, do_unwrap) };
		RzCmdParsedArgs *res = rz_cmd_parsed_args_newargs(1, unescaped_args);
		free(unescaped_args[0]);
		return res;
	}
}

static TSTree *apply_edits(struct tsr2cmd_state *state, RzList *edits) {
	struct tsr2cmd_edit *edit;
	RzListIter *it;

	RZ_LOG_DEBUG("old input = '%s'\n", state->input);
	rz_list_foreach (edits, it, edit) {
		RZ_LOG_DEBUG("apply_edits: about to replace '%s' with '%s'\n", edit->old_text, edit->new_text);
		state->input = rz_str_replace(state->input, edit->old_text, edit->new_text, 0);
	}
	RZ_LOG_DEBUG("new input = '%s'\n", state->input);
	return ts_parser_parse_string(state->parser, NULL, state->input, strlen(state->input));
}

static void substitute_args_fini(struct tsr2cmd_state *state) {
	TSTree *saved_tree = rz_pvector_pop(&state->saved_tree);
	if (state->tree != saved_tree) {
		ts_tree_delete(state->tree);
	}
	state->tree = saved_tree;

	char *saved_input = rz_pvector_pop(&state->saved_input);
	if (state->input != saved_input) {
		free(state->input);
	}
	state->input = saved_input;
}

static void substitute_args_init(struct tsr2cmd_state *state, TSNode command) {
	rz_pvector_push(&state->saved_input, state->input);
	rz_pvector_push(&state->saved_tree, state->tree);

	state->substitute_cmd = command;
	state->input = ts_node_sub_string(state->substitute_cmd, state->input);
	RZ_LOG_DEBUG("Shrinking input to '%s'\n", state->input);
}

static bool substitute_args_do(struct tsr2cmd_state *state, RzList *edits, TSNode *new_command) {
	TSTree *new_tree = apply_edits(state, edits);
	if (!new_tree) {
		return false;
	}

	TSNode root = ts_tree_root_node(new_tree);
	if (ts_node_has_error(root)) {
		ts_tree_delete(new_tree);
		return false;
	}
	*new_command = ts_node_named_child(root, 0);
	state->tree = new_tree;
	return true;
}

static bool substitute_args(struct tsr2cmd_state *state, TSNode args, TSNode *new_command) {
	RzList *edits = rz_list_newf((RzListFree)free_tsr2cmd_edit);

	if (is_handled_args(args)) {
		handle_substitution_args(state, args, edits);
	}

	bool res = substitute_args_do(state, edits, new_command);
	rz_list_free(edits);
	return res;
}

static RzCmdParsedArgs *ts_node_handle_arg_prargs(struct tsr2cmd_state *state, TSNode command, TSNode arg, uint32_t child_idx, bool do_unwrap) {
	RzCmdParsedArgs *res = NULL;
	TSNode new_command;
	substitute_args_init(state, command);
	bool ok = substitute_args(state, arg, &new_command);
	if (!ok) {
		RZ_LOG_ERROR("Error while substituting arguments\n");
		goto err;
	}

	arg = ts_node_named_child(new_command, child_idx);
	res = parse_args(state, arg, do_unwrap);
	if (res == NULL) {
		RZ_LOG_ERROR("Cannot parse arg\n");
		goto err;
	}
err:
	substitute_args_fini(state);
	return res;
}

static char *ts_node_handle_arg(struct tsr2cmd_state *state, TSNode command, TSNode arg, uint32_t child_idx) {
	RzCmdParsedArgs *a = ts_node_handle_arg_prargs(state, command, arg, child_idx, true);
	char *str = rz_cmd_parsed_args_argstr(a);
	rz_cmd_parsed_args_free(a);
	return str;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(arged_stmt) {
	TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
	rz_return_val_if_fail(!ts_node_is_null(command), false);

	TSNode command_extra = ts_node_child_by_field_name(command, "extra", strlen("extra"));
	char *command_str = NULL, *command_extra_str = NULL;
	if (!ts_node_is_null(command_extra)) {
		command_extra_str = ts_node_sub_string(command_extra, state->input);
		RZ_LOG_DEBUG("command_extra_str = '%s'\n", command_extra_str);

		ut32 start = ts_node_start_byte(command);
		ut32 end = ts_node_start_byte(command_extra);
		command_str = rz_str_newf("%.*s", end - start, state->input + start);
	} else {
		command_str = ts_node_sub_string(command, state->input);
	}

	rz_str_unescape(command_str);
	RZ_LOG_DEBUG("arged_stmt command: '%s'\n", command_str);
	TSNode args = ts_node_child_by_field_name(node, "args", strlen("args"));
	RzCmdStatus res = RZ_CMD_STATUS_INVALID;

	// FIXME: this special handling should be removed once we have a proper
	//        command tree
	if (!strcmp(command_str, "|.")) {
		char *cmd_str = ts_node_sub_string(args, state->input);
		char *exec_string = rz_str_newf(".%s", cmd_str);
		free(cmd_str);
		free(command_str);
		res = core_cmd_tsrzcmd(state->core, exec_string, state->split_lines, false);
		free(exec_string);
		return res;
	}

	RzCmdParsedArgs *pr_args = NULL;
	if (!ts_node_is_null(args)) {
		RzCmdDesc *cd = rz_cmd_get_desc(state->core->rcmd, command_str);
		bool do_unwrap = cd && cd->type != RZ_CMD_DESC_TYPE_OLDINPUT;
		pr_args = ts_node_handle_arg_prargs(state, node, args, 1, do_unwrap);
		if (!pr_args) {
			goto err;
		}
		rz_cmd_parsed_args_setcmd(pr_args, command_str);
	} else {
		pr_args = rz_cmd_parsed_args_newcmd(command_str);
		if (!pr_args) {
			goto err;
		}
	}

	pr_args->extra = command_extra_str;
	pr_args->has_space_after_cmd = !ts_node_is_null(args) && ts_node_end_byte(command) < ts_node_start_byte(args);
	res = rz_cmd_call_parsed_args(state->core->rcmd, pr_args);
	if (res == RZ_CMD_STATUS_WRONG_ARGS) {
		const char *cmdname = rz_cmd_parsed_args_cmd(pr_args);
		eprintf("Wrong number of arguments passed to `%s`, see its help with `%s?`\n", cmdname, cmdname);
		RzCmdDesc *cd = rz_cmd_get_desc(state->core->rcmd, cmdname);
		if (cd) {
			char *cmdname_help = rz_str_newf("%s?", cmdname);
			if (!cmdname_help) {
				goto err;
			}
			RzCmdParsedArgs *help_pra = rz_cmd_parsed_args_newcmd(cmdname_help);
			if (!help_pra) {
				goto err;
			}
			bool use_color = state->core->print->flags & RZ_PRINT_FLAGS_COLOR;
			char *help_msg = rz_cmd_get_help(state->core->rcmd, help_pra, use_color);
			if (!help_msg) {
				goto help_pra_err;
			}
			eprintf("%s", help_msg);
			free(help_msg);
		help_pra_err:
			rz_cmd_parsed_args_free(help_pra);
		}
	} else if (res == RZ_CMD_STATUS_NONEXISTINGCMD) {
		const char *cmdname = rz_cmd_parsed_args_cmd(pr_args);
		eprintf("Command '%s' does not exist.\n", cmdname);
		if (rz_str_endswith(cmdname, "?") && pr_args->argc > 1) {
			eprintf("Did you want to see the help? Try `%s` without any argument.\n", cmdname);
		}
	} else if (res == RZ_CMD_STATUS_ERROR) {
		RZ_LOG_DEBUG("Something wrong during the execution of `%s` command.\n", rz_cmd_parsed_args_cmd(pr_args));
	}

err:
	RZ_LOG_DEBUG("arged_stmt finished command: '%s'\n", command_str);
	rz_cmd_parsed_args_free(pr_args);
	free(command_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(legacy_quoted_stmt) {
	return rz_cmd_int2status(run_cmd_depth(state->core, node_string));
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(repeat_stmt) {
	TSNode number = ts_node_child_by_field_name(node, "arg", strlen("arg"));
	char *number_str = ts_node_sub_string(number, state->input);
	int rep = atoi(number_str);
	free(number_str);

	TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
	if (rep > INTERACTIVE_MAX_REP && rz_cons_is_interactive()) {
		if (!rz_cons_yesno('n', "Are you sure to repeat this %d times? (y/N)", rep)) {
			return RZ_CMD_STATUS_INVALID;
		}
	}

	RzCmdStatus res = RZ_CMD_STATUS_OK;
	size_t i;
	for (i = 0; i < rep; i++) {
		RzCmdStatus cmd_res = handle_ts_stmt(state, command);
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
	}
err:
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(redirect_stmt) {
	bool pipecolor = rz_config_get_b(state->core->config, "scr.color.pipe");
	int ocolor = rz_config_get_i(state->core->config, "scr.color");
	int scr_html = -1;
	RzCmdStatus res = RZ_CMD_STATUS_INVALID, is_append = false, is_html = false;
	int fdn = 1;

	TSNode redirect_op = ts_node_child_by_field_name(node, "redirect_operator", strlen("redirect_operator"));
	if (is_ts_fdn_redirect_operator(redirect_op)) {
		// this is the default operation, no html and no append
	} else if (is_ts_fdn_append_operator(redirect_op)) {
		is_append = true;
	} else if (is_ts_html_redirect_operator(redirect_op)) {
		is_html = true;
	} else if (is_ts_html_append_operator(redirect_op)) {
		is_html = true;
		is_append = true;
	} else {
		RZ_LOG_ERROR("This should never happen, redirect_operator is no known type");
		rz_warn_if_reached();
	}

	if (is_html) {
		scr_html = rz_config_get_i(state->core->config, "scr.html");
		rz_config_set_i(state->core->config, "scr.html", true);
		pipecolor = true;
	} else {
		TSNode fd_desc = ts_node_named_child(redirect_op, 0);
		if (!ts_node_is_null(fd_desc)) {
			char *fd_str = ts_node_sub_string(fd_desc, state->input);
			fdn = atoi(fd_str);
			free(fd_str);
		}
	}

	rz_cons_set_interactive(false);
	// TODO: allow to use editor as the old behaviour

	// extract the string of the filename we need to write to
	TSNode arg = ts_node_child_by_field_name(node, "arg", strlen("arg"));
	char *arg_str = ts_node_sub_string(arg, state->input);

	if (arg_str[0] == '$') {
		// redirect output of command to an alias variable
		RZ_LOG_DEBUG("redirect_stmt: alias = '%s'\n", arg_str);
		TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
		char *command_str = ts_node_sub_string(command, state->input);

		char *output = rz_core_cmd_str(state->core, command_str);
		char *old_alias_value = rz_cmd_alias_get(state->core->rcmd, arg_str, 1);
		char *new_alias_value;
		const char *start_char = "$";
		if (is_append && old_alias_value) {
			start_char = "";
		} else {
			old_alias_value = "";
		}
		new_alias_value = rz_str_newf("%s%s%s", start_char, old_alias_value, output ? output : "");
		free(output);
		rz_cmd_alias_set(state->core->rcmd, arg_str, new_alias_value, 1);
		free(new_alias_value);
		free(command_str);
		res = RZ_CMD_STATUS_OK;
	} else {
		rz_cons_flush();
		RZ_LOG_DEBUG("redirect_stmt: fdn = %d, is_append = %d\n", fdn, is_append);
		int pipefd = rz_cons_pipe_open(arg_str, fdn, is_append);
		if (pipefd != -1) {
			if (!pipecolor) {
				rz_config_set_i(state->core->config, "scr.color", COLOR_MODE_DISABLED);
			}
			TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
			res = handle_ts_stmt(state, command);
			rz_cons_flush();
			rz_cons_pipe_close(pipefd);
		} else {
			RZ_LOG_WARN("Could not open pipe to %d", fdn);
		}
	}
	free(arg_str);
	rz_cons_set_last_interactive();
	if (!pipecolor) {
		rz_config_set_i(state->core->config, "scr.color", ocolor);
	}
	if (scr_html != -1) {
		rz_config_set_i(state->core->config, "scr.html", scr_html);
	}
	return res;
}

typedef struct _search_help {
	bool color;
	RzStrBuf *sb;
	PJ *pj;
} RzHelpSearch;

static bool help_search_cmd_desc_entry(RzCmd *cmd, const RzCmdDesc *cd, void *user) {
	rz_return_val_if_fail(cd, false);
	RzHelpSearch *hs = (RzHelpSearch *)user;
	if (hs->pj) {
		rz_cmd_get_help_json(cmd, cd, hs->pj);
	} else {
		rz_cmd_get_help_strbuf(cmd, cd, hs->color, hs->sb);
	}
	return true;
}

RZ_IPI RzCmdStatus rz_cmd_help_search_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	RzCmdStatus status = RZ_CMD_STATUS_OK;
	RzCmdDesc *begin = NULL;

	if (argc == 2) {
		begin = rz_cmd_get_desc(core->rcmd, argv[1]);
		if (!begin) {
			status = RZ_CMD_STATUS_NONEXISTINGCMD;
			goto exit_status;
		}
	}

	RzHelpSearch hs = {
		.color = core->print->flags & RZ_PRINT_FLAGS_COLOR,
		.pj = NULL,
		.sb = NULL,
	};

	if (mode & RZ_OUTPUT_MODE_JSON) {
		hs.pj = pj_new();
		if (!hs.pj) {
			status = RZ_CMD_STATUS_ERROR;
			goto exit_status;
		}
		pj_o(hs.pj);
	} else {
		hs.sb = rz_strbuf_new(NULL);
		if (!hs.sb) {
			status = RZ_CMD_STATUS_ERROR;
			goto exit_status;
		}
	}

	rz_cmd_foreach_cmdname(core->rcmd, begin, help_search_cmd_desc_entry, &hs);

	if (mode & RZ_OUTPUT_MODE_JSON) {
		pj_end(hs.pj);
		rz_cons_printf("%s\n", pj_string(hs.pj));
		pj_free(hs.pj);
	} else {
		char *help = rz_strbuf_drain(hs.sb);
		rz_cons_printf("%s", help);
		free(help);
	}
exit_status:
	return status;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(help_stmt) {
	size_t node_str_len = strlen(node_string);
	if (node_str_len >= 2 && !strcmp(node_string + node_str_len - 2, "?*")) {
		node_string[node_str_len - 2] = 0;
		const char *argv[2] = { NULL, node_string };
		return rz_cmd_help_search_handler(state->core, 2, argv, RZ_OUTPUT_MODE_STANDARD);
	} else if (node_str_len >= 3 && !strcmp(node_string + node_str_len - 3, "?*j")) {
		node_string[node_str_len - 3] = 0;
		const char *argv[2] = { NULL, node_string };
		return rz_cmd_help_search_handler(state->core, 2, argv, RZ_OUTPUT_MODE_JSON);
	}

	TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
	char *command_str = ts_node_sub_string(command, state->input);
	TSNode args = ts_node_child_by_field_name(node, "args", strlen("args"));
	RzCmdParsedArgs *pr_args = NULL;
	RzCmdStatus res = RZ_CMD_STATUS_INVALID;
	if (!ts_node_is_null(args)) {
		RzCmdDesc *cd = rz_cmd_get_desc(state->core->rcmd, command_str);
		bool do_unwrap = cd && cd->type != RZ_CMD_DESC_TYPE_OLDINPUT;
		pr_args = ts_node_handle_arg_prargs(state, node, args, 1, do_unwrap);
		if (!pr_args) {
			goto err_else;
		}
		rz_cmd_parsed_args_setcmd(pr_args, command_str);
	} else {
		pr_args = rz_cmd_parsed_args_newcmd(command_str);
		if (!pr_args) {
			goto err_else;
		}
	}

	// let's try first with the new auto-generated help, if
	// something fails fallback to old behaviour
	bool use_color = state->core->print->flags & RZ_PRINT_FLAGS_COLOR;
	char *help_msg = rz_cmd_get_help(state->core->rcmd, pr_args, use_color);
	if (help_msg) {
		rz_cons_printf("%s", help_msg);
		free(help_msg);
		res = RZ_CMD_STATUS_OK;
	}
err_else:
	rz_cmd_parsed_args_free(pr_args);
	free(command_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_seek_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	TSNode offset = ts_node_named_child(node, 1);
	char *offset_string = ts_node_handle_arg(state, node, offset, 1);
	ut64 offset_val = rz_num_math(state->core->num, offset_string);
	ut64 orig_offset = state->core->offset;
	if (!offset_val && isalpha((int)offset_string[0])) {
		if (!rz_flag_get(state->core->flags, offset_string)) {
			eprintf("Invalid address (%s)\n", offset_string);
			free(offset_string);
			return RZ_CMD_STATUS_INVALID;
		}
	}
	if (offset_string[0] == '-' || offset_string[0] == '+') {
		offset_val += state->core->offset;
	}
	RZ_LOG_DEBUG("tmp_seek_stmt, changing offset to %" PFMT64x "\n", offset_val);
	rz_core_seek(state->core, offset_val, true);
	RzCmdStatus res = handle_ts_stmt_tmpseek(state, command);
	rz_core_seek(state->core, orig_offset, true);
	free(offset_string);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_blksz_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	TSNode blksz = ts_node_named_child(node, 1);
	char *blksz_string = ts_node_handle_arg(state, node, blksz, 1);
	ut64 orig_blksz = state->core->blocksize;
	RZ_LOG_DEBUG("tmp_blksz_stmt, changing blksz to %s\n", blksz_string);
	rz_core_block_size(state->core, rz_num_math(state->core->num, blksz_string));
	RzCmdStatus res = handle_ts_stmt(state, command);
	rz_core_block_size(state->core, orig_blksz);
	free(blksz_string);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_fromto_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode fromto = ts_node_named_child(node, 1);
	RzCmdParsedArgs *a = ts_node_handle_arg_prargs(state, node, fromto, 1, true);
	if (!a || a->argc != 2 + 1) {
		rz_cmd_parsed_args_free(a);
		return RZ_CMD_STATUS_INVALID;
	}

	char *from_str = a->argv[1];
	char *to_str = a->argv[2];

	const char *fromvars[] = { "analysis.from", "diff.from", "graph.from",
		"search.from", "zoom.from", NULL };
	const char *tovars[] = { "analysis.to", "diff.to", "graph.to",
		"search.to", "zoom.to", NULL };
	ut64 from_val = rz_num_math(core->num, from_str);
	ut64 to_val = rz_num_math(core->num, to_str);
	RZ_LOG_DEBUG("tmp_fromto_stmt, changing fromto to (%" PFMT64x ", %" PFMT64x ")\n", from_val, to_val);

	RzConfigHold *hc = rz_config_hold_new(core->config);
	int i;
	for (i = 0; fromvars[i]; i++) {
		rz_config_hold_i(hc, fromvars[i], NULL);
		rz_config_set_i(core->config, fromvars[i], from_val);
	}
	for (i = 0; tovars[i]; i++) {
		rz_config_hold_i(hc, tovars[i], NULL);
		rz_config_set_i(core->config, tovars[i], to_val);
	}

	RzCmdStatus res = handle_ts_stmt(state, command);

	rz_config_hold_restore(hc);

	rz_config_hold_free(hc);
	rz_cmd_parsed_args_free(a);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_arch_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	char *tmparch, *tmpbits;
	bool is_arch_set = false, is_bits_set = false;
	bool oldfixedarch = core->fixedarch, oldfixedbits = core->fixedbits;
	int cmd_ignbithints = -1;

	// change arch and bits
	char *q = strchr(arg_str, ':');
	if (q) {
		*q++ = '\0';
		int bits = rz_num_math(core->num, q);
		is_bits_set = set_tmp_bits(core, bits, &tmpbits, &cmd_ignbithints);
	}
	is_arch_set = set_tmp_arch(core, arg_str, &tmparch);

	// execute command with changed settings
	RzCmdStatus res = handle_ts_stmt(state, command);

	// restore original settings
	if (is_arch_set) {
		core->fixedarch = oldfixedarch;
		rz_config_set(core->config, "asm.arch", tmparch);
		free(tmparch);
	}
	if (is_bits_set) {
		rz_config_set(core->config, "asm.bits", tmpbits);
		core->fixedbits = oldfixedbits;
		free(tmpbits);
	}
	if (cmd_ignbithints != -1) {
		rz_config_set_i(core->config, "analysis.ignbithints", cmd_ignbithints);
	}
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_bits_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	bool oldfixedbits = core->fixedbits;
	char *tmpbits;
	int cmd_ignbithints;

	int bits = rz_num_math(core->num, arg_str);
	set_tmp_bits(core, bits, &tmpbits, &cmd_ignbithints);

	RzCmdStatus res = handle_ts_stmt(state, command);

	rz_config_set(core->config, "asm.bits", tmpbits);
	core->fixedbits = oldfixedbits;
	rz_config_set_i(core->config, "analysis.ignbithints", cmd_ignbithints);

	free(tmpbits);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_nthi_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);

	ut64 orig_offset = state->core->offset;
	int index = rz_num_math(core->num, arg_str);
	RzAnalysisBlock *bb = rz_analysis_find_most_relevant_block_in(core->analysis, core->offset);
	if (bb) {
		// handle negative indices
		if (index < 0) {
			index = bb->ninstr + index;
		}

		if (index >= 0 && index < bb->ninstr) {
			ut16 inst_off = rz_analysis_block_get_op_offset(bb, index);
			rz_core_seek(core, bb->addr + inst_off, true);
		} else {
			eprintf("The current basic block has just %d instructions\n", bb->ninstr);
		}
	} else {
		eprintf("Can't find a basic block for 0x%08" PFMT64x "\n", core->offset);
	}

	RzCmdStatus res = handle_ts_stmt_tmpseek(state, command);

	rz_core_seek(core, orig_offset, true);

	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_eval_stmt) {
	// TODO: support cmd_substitution in tmp_eval_args
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode args = ts_node_named_child(node, 1);

	RzConfigHold *hc = rz_config_hold_new(core->config);
	uint32_t i, n_args = ts_node_named_child_count(args);
	for (i = 0; i < n_args; i++) {
		TSNode arg = ts_node_named_child(args, i);
		char *arg_str = ts_node_sub_string(arg, state->input);
		char *eq = strchr(arg_str, '=');
		if (eq) {
			*eq = 0;
			rz_config_hold_s(hc, arg_str, NULL);
			rz_config_set(core->config, arg_str, eq + 1);
		} else {
			eprintf("Missing '=' in e: expression (%s)\n", arg_str);
		}
		free(arg_str);
	}

	RzCmdStatus res = handle_ts_stmt(state, command);

	rz_config_hold_restore(hc);
	rz_config_hold_free(hc);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_fs_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	rz_flag_space_push(core->flags, arg_str);
	RzCmdStatus res = handle_ts_stmt(state, command);
	rz_flag_space_pop(core->flags);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_reli_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	ut64 orig_offset = state->core->offset;
	ut64 addr = rz_num_math(core->num, arg_str);
	if (addr) {
		rz_core_seek_opcode(core, addr, false);
	}
	RzCmdStatus res = handle_ts_stmt_tmpseek(state, command);
	rz_core_seek(state->core, orig_offset, true);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_kuery_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	ut64 orig_offset = state->core->offset;
	char *out = sdb_querys(core->sdb, NULL, 0, arg_str);
	if (out) {
		rz_core_seek(core, rz_num_math(core->num, out), true);
		free(out);
	}
	RzCmdStatus res = handle_ts_stmt_tmpseek(state, command);
	rz_core_seek(state->core, orig_offset, true);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_fd_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	int tmpfd = core->io->desc ? core->io->desc->fd : -1;
	rz_io_use_fd(core->io, atoi(arg_str));
	RzCmdStatus res = handle_ts_stmt(state, command);
	rz_io_use_fd(core->io, tmpfd);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_reg_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	ut64 orig_offset = state->core->offset;
	// TODO: add support for operations (e.g. @r:PC+10)
	ut64 regval = rz_debug_reg_get(core->dbg, arg_str);
	rz_core_seek(core, regval, true);
	RzCmdStatus res = handle_ts_stmt_tmpseek(state, command);
	rz_core_seek(core, orig_offset, true);
	free(arg_str);
	return res;
}

static bool handle_tmp_desc(struct tsr2cmd_state *state, TSNode command, const ut8 *buf, int sz) {
	RzCore *core = state->core;
	int pamode = !core->io->va;
	RzCmdStatus res = RZ_CMD_STATUS_INVALID, o_fixedblock = core->fixedblock;
	RzBuffer *b = rz_buf_new_with_bytes(buf, sz);
	int cur_fd = rz_io_fd_get_current(core->io);
	RzIODesc *d = rz_io_open_buffer(core->io, b, RZ_PERM_RWX, 0);
	if (!d) {
		eprintf("Cannot open io buffer\n");
		goto out_buf;
	}
	if (pamode) {
		rz_config_set_i(core->config, "io.va", 1);
	}
	rz_io_map_new(core->io, d->fd, d->perm, 0, core->offset, rz_buf_size(b));
	ut32 obsz = core->blocksize;
	rz_core_block_size(core, rz_buf_size(b));
	core->fixedblock = true;
	rz_core_block_read(core);

	res = handle_ts_stmt(state, command);

	core->fixedblock = o_fixedblock;
	if (pamode) {
		rz_config_set_i(core->config, "io.va", 0);
	}
	rz_io_desc_close(d);
	rz_core_block_size(core, obsz);
	rz_io_use_fd(core->io, cur_fd);

out_buf:
	rz_buf_free(b);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_file_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	size_t sz;
	RzCmdStatus res = RZ_CMD_STATUS_INVALID;

	char *f = rz_file_slurp(arg_str, &sz);
	if (!f) {
		eprintf("Cannot open '%s'\n", arg_str);
		goto out;
	}

	res = handle_tmp_desc(state, command, (ut8 *)f, (int)sz);

	free(f);
out:
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_string_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	int sz;

	sz = strlen(arg_str);
	const ut8 *buf = (const ut8 *)arg_str;

	RzCmdStatus res = handle_tmp_desc(state, command, buf, sz);

	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_value_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);

	ut64 v = rz_num_math(core->num, arg_str);
	ut8 buf[8] = { 0 };
	int be = rz_config_get_i(core->config, "cfg.bigendian");
	int bi = rz_config_get_i(core->config, "asm.bits");

	rz_write_ble(buf, v, be, bi);
	int sz = bi / 8;

	RzCmdStatus res = handle_tmp_desc(state, command, buf, sz);

	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(tmp_hex_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	int sz;

	size_t len = strlen(arg_str);
	ut8 *buf = RZ_NEWS(ut8, len + 1);
	sz = rz_hex_str2bin(arg_str, buf);

	RzCmdStatus res = handle_tmp_desc(state, command, buf, sz);

	free(buf);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_flags_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = NULL;
	if (!ts_node_is_null(arg)) {
		arg_str = ts_node_handle_arg(state, node, arg, 1);
	}
	const RzSpace *flagspace = rz_flag_space_cur(core->flags);
	RzFlagItem *flag;
	RzListIter *iter;
	RzCmdStatus ret = RZ_CMD_STATUS_OK;
	RzList *match_flag_items = rz_list_newf((RzListFree)rz_flag_item_free);
	if (!match_flag_items) {
		return RZ_CMD_STATUS_OK;
	}

	/* duplicate flags that match word, to be sure the command is going to
	   be executed on flags values at the moment the command is called
	   (without side effects) */
	struct duplicate_flag_t u = {
		.ret = match_flag_items,
		.word = arg_str,
	};
	rz_flag_foreach_space(core->flags, flagspace, duplicate_flag, &u);

	/* for all flags that match */
	rz_list_foreach (match_flag_items, iter, flag) {
		if (rz_cons_is_breaked()) {
			break;
		}

		RZ_LOG_DEBUG("iter_flags_stmt: seek to %" PFMT64x "\n", flag->offset);
		rz_core_seek(core, flag->offset, true);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		rz_core_task_yield(&core->tasks);
		UPDATE_CMD_STATUS_RES(ret, cmd_res, err);
	}

err:
	rz_list_free(match_flag_items);
	free(arg_str);
	return ret;
}

enum dbt_commands_mode {
	DBT_COMMANDS_MODE_ADDR,
	DBT_COMMANDS_MODE_BP,
	DBT_COMMANDS_MODE_SP,
};

static bool iter_dbt_commands(struct tsr2cmd_state *state, TSNode node, enum dbt_commands_mode mode) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzList *list = rz_debug_frames(core->dbg, UT64_MAX);
	ut64 orig_offset = core->offset;
	RzDebugFrame *frame;
	RzListIter *iter;
	RzCmdStatus res = RZ_CMD_STATUS_OK;

	rz_list_foreach (list, iter, frame) {
		switch (mode) {
		case DBT_COMMANDS_MODE_ADDR:
			rz_core_seek(core, frame->addr, true);
			break;
		case DBT_COMMANDS_MODE_SP:
			rz_core_seek(core, frame->sp, true);
			break;
		case DBT_COMMANDS_MODE_BP:
			rz_core_seek(core, frame->bp, true);
			break;
		default:
			rz_warn_if_reached();
			return RZ_CMD_STATUS_INVALID;
		}
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		rz_cons_newline();
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
	}
err:
	rz_core_seek(core, orig_offset, true);
	rz_list_free(list);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_dbta_stmt) {
	return iter_dbt_commands(state, node, DBT_COMMANDS_MODE_ADDR);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_dbtb_stmt) {
	return iter_dbt_commands(state, node, DBT_COMMANDS_MODE_BP);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_dbts_stmt) {
	return iter_dbt_commands(state, node, DBT_COMMANDS_MODE_SP);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_file_lines_stmt) {
	RzCore *core = state->core;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	TSNode command = ts_node_named_child(node, 0);
	TSNode arg = ts_node_named_child(node, 1);
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	ut64 orig_offset = core->offset;
	FILE *fd = rz_sys_fopen(arg_str, "r");
	if (!fd) {
		res = RZ_CMD_STATUS_INVALID;
		goto arg_out;
	}

	core->rcmd->macro.counter = 0;
	while (!feof(fd)) {
		char buf[1024];
		buf[0] = '\0';
		if (!fgets(buf, sizeof(buf), fd)) {
			break;
		}
		ut64 addr = rz_num_math(core->num, buf);
		rz_core_seek(core, addr, true);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		core->rcmd->macro.counter++;
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
	}
err:
	rz_core_seek(core, orig_offset, true);
	fclose(fd);

arg_out:
	free(arg_str);
	return res;
}

static RzCmdStatus do_iter_offsets(RzCore *core, struct tsr2cmd_state *state, TSNode *command, RzCmdParsedArgs *a, bool has_size) {
	RzCmdStatus res = RZ_CMD_STATUS_OK;

	const char *s;
	int i;
	ut64 orig_offset = core->offset;
	ut64 orig_blk_sz = core->blocksize;
	rz_cmd_parsed_args_foreach_arg(a, i, s) {
		ut64 addr = rz_num_math(core->num, s);
		ut64 blk_sz = core->blocksize;
		if (has_size) {
			blk_sz = rz_num_math(core->num, a->argv[i++ + 1]);
		}
		rz_core_seek(core, addr, true);
		if (has_size) {
			rz_core_block_size(core, blk_sz);
		}
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, *command);
		rz_cons_flush();
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
	}

err:
	if (has_size) {
		rz_core_block_size(core, orig_blk_sz);
	}
	rz_core_seek(core, orig_offset, true);
	return res;
}

static RzCmdStatus iter_offsets_common(struct tsr2cmd_state *state, TSNode node, bool has_size) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	if (ts_node_named_child_count(node) < 2) {
		// no offsets provided, all's good.
		return RZ_CMD_STATUS_OK;
	}

	TSNode args = ts_node_named_child(node, 1);

	RzCmdParsedArgs *a = ts_node_handle_arg_prargs(state, node, args, 1, true);
	if (!a || (has_size && (a->argc - 1) % 2 != 0)) {
		RZ_LOG_ERROR("Cannot parse args\n");
		rz_cmd_parsed_args_free(a);
		return RZ_CMD_STATUS_INVALID;
	}

	RzCmdStatus res = do_iter_offsets(core, state, &command, a, has_size);
	rz_cmd_parsed_args_free(a);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_offsets_stmt) {
	return iter_offsets_common(state, node, false);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_offsetssizes_stmt) {
	return iter_offsets_common(state, node, true);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_instrs_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	RzCore *core = state->core;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	ut64 orig_offset = core->offset;
	int bs = core->blocksize;
	RzList *bbl = rz_analysis_get_blocks_in(core->analysis, core->offset);
	if (!bbl || rz_list_empty(bbl)) {
		eprintf("No basic block contains current address\n");
		return RZ_CMD_STATUS_INVALID;
	}
	RzAnalysisBlock *bb = rz_list_get_top(bbl);
	rz_analysis_block_ref(bb);
	rz_list_free(bbl);

	int i;
	for (i = 0; i < bb->ninstr; i++) {
		ut64 i_addr = rz_analysis_block_get_op_addr(bb, i);
		int sz = rz_analysis_block_get_op_size(bb, i);
		rz_core_block_size(core, sz);
		rz_core_seek(core, i_addr, true);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		if (rz_cons_is_breaked()) {
			break;
		}
	}
	rz_analysis_block_unref(bb);

err:
	rz_core_block_size(core, bs);
	rz_core_seek(core, orig_offset, true);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_step_stmt) {
	TSNode command = ts_node_named_child(node, 0);
	TSNode args = ts_node_named_child(node, 1);
	RzCmdParsedArgs *a = ts_node_handle_arg_prargs(state, node, args, 1, true);
	if (!a || a->argc != 3 + 1) {
		rz_cmd_parsed_args_free(a);
		return RZ_CMD_STATUS_INVALID;
	}

	RzCore *core = state->core;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	ut64 orig_offset = core->offset;
	int bs = core->blocksize;

	char *from_str = a->argv[1];
	char *to_str = a->argv[2];
	char *step_str = a->argv[3];
	ut64 from = rz_num_math(core->num, from_str);
	ut64 to = rz_num_math(core->num, to_str);
	ut64 step = rz_num_math(core->num, step_str);

	ut64 cur;
	for (cur = from; cur < to; cur += step) {
		rz_core_seek(core, cur, true);
		rz_core_block_size(core, step);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		if (rz_cons_is_breaked()) {
			break;
		}
	}

err:
	rz_core_block_size(core, bs);
	rz_core_seek(core, orig_offset, true);
	rz_cmd_parsed_args_free(a);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_hit_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode search_cmd = ts_node_named_child(node, 1);
	char *command_str = ts_node_sub_string(command, state->input);
	char *cmdhit = strdup(rz_config_get(core->config, "cmd.hit"));
	rz_config_set(core->config, "cmd.hit", command_str);
	RzCmdStatus res = handle_ts_stmt(state, search_cmd);
	rz_config_set(core->config, "cmd.hit", cmdhit);
	free(command_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_bbs_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
	ut64 offorig = core->offset;
	ut64 obs = core->blocksize;
	if (!fcn) {
		return RZ_CMD_STATUS_INVALID;
	}

	RzListIter *iter;
	RzAnalysisBlock *bb;
	RzCmdStatus ret = RZ_CMD_STATUS_OK;
	rz_list_sort(fcn->bbs, bb_cmp);
	rz_list_foreach (fcn->bbs, iter, bb) {
		rz_core_seek(core, bb->addr, true);
		rz_core_block_size(core, bb->size);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		UPDATE_CMD_STATUS_RES(ret, cmd_res, err);
	}
err:
	rz_core_block_size(core, obs);
	rz_core_seek(core, offorig, true);
	return ret;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_interpret_stmt) {
	// convert @@c: command into a @@= one, by using the output of the
	// in_cmd as addr of @@=
	RzCmdStatus res = RZ_CMD_STATUS_INVALID;
	TSNode in_cmd = ts_node_named_child(node, 1);
	substitute_args_init(state, node);

	RzList *edits = rz_list_newf((RzListFree)free_tsr2cmd_edit);
	if (!edits) {
		goto edits_err;
	}

	char *in_cmd_out = do_handle_substitution_cmd(state, in_cmd);
	if (!in_cmd_out) {
		goto err;
	}

	char *in_cmd_out_es = rz_cmd_escape_arg(in_cmd_out, RZ_CMD_ESCAPE_MULTI_ARG);
	free(in_cmd_out);
	struct tsr2cmd_edit *e = create_cmd_edit(state, in_cmd, in_cmd_out_es);
	rz_list_append(edits, e);

	TSNode op = ts_node_child(node, 1);
	e = create_cmd_edit(state, op, strdup("@@="));
	rz_list_append(edits, e);

	TSNode new_command;
	if (!substitute_args_do(state, edits, &new_command)) {
		goto err;
	}
	res = handle_ts_stmt(state, new_command);
err:
	rz_list_free(edits);
edits_err:
	substitute_args_fini(state);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_interpret_offsetssizes_stmt) {
	// convert @@@c: command into a @@@= one, by using the output of the
	// in_cmd as addr/blksz of @@@=
	RzCmdStatus res = RZ_CMD_STATUS_INVALID;
	TSNode in_cmd = ts_node_named_child(node, 1);
	substitute_args_init(state, node);

	RzList *edits = rz_list_newf((RzListFree)free_tsr2cmd_edit);
	if (!edits) {
		goto edits_err;
	}

	char *in_cmd_out = do_handle_substitution_cmd(state, in_cmd);
	if (!in_cmd_out) {
		goto err;
	}

	char *in_cmd_out_es = rz_cmd_escape_arg(in_cmd_out, RZ_CMD_ESCAPE_MULTI_ARG);
	free(in_cmd_out);
	struct tsr2cmd_edit *e = create_cmd_edit(state, in_cmd, in_cmd_out_es);
	rz_list_append(edits, e);

	TSNode op = ts_node_child(node, 1);
	e = create_cmd_edit(state, op, strdup("@@@="));
	rz_list_append(edits, e);

	TSNode new_command;
	if (!substitute_args_do(state, edits, &new_command)) {
		goto err;
	}
	res = handle_ts_stmt(state, new_command);
err:
	rz_list_free(edits);
edits_err:
	substitute_args_fini(state);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_comment_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode filter_node = ts_node_named_child(node, 1);
	char *glob = !ts_node_is_null(filter_node)
		? ts_node_sub_string(filter_node, state->input)
		: NULL;
	ut64 off = core->offset;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *meta;
	rz_interval_tree_foreach (&core->analysis->meta, it, meta) {
		if (meta->type != RZ_META_TYPE_COMMENT) {
			continue;
		}
		if (!glob || (meta->str && rz_str_glob(meta->str, glob))) {
			rz_core_seek(core, rz_interval_tree_iter_get(&it)->start, true);
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	}
err:
	rz_core_seek(core, off, false);
	free(glob);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_import_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzBinSymbol *imp;
	ut64 offorig = core->offset;
	RzList *list = rz_bin_get_symbols(core->bin);
	if (!list) {
		return RZ_CMD_STATUS_OK;
	}

	RzList *lost = rz_list_newf(free);
	RzListIter *iter;
	rz_list_foreach (list, iter, imp) {
		if (!imp->is_imported) {
			continue;
		}
		ut64 *n = RZ_NEW(ut64);
		*n = imp->vaddr;
		rz_list_append(lost, n);
	}
	ut64 *naddr;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	rz_list_foreach (lost, iter, naddr) {
		ut64 addr = *naddr;
		if (addr != UT64_MAX) {
			rz_core_seek(core, addr, true);
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	}
err:
	rz_core_seek(core, offorig, true);
	rz_list_free(lost);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_register_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	ut64 offorig = core->offset;
	RzReg *reg = rz_core_reg_default(core);
	int i;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	for (i = 0; i < RZ_REG_TYPE_LAST; i++) {
		RzRegItem *item;
		ut64 value;
		const RzList *head = rz_reg_get_list(reg, i);
		if (!head) {
			continue;
		}
		RzList *list = rz_list_newf(free);
		RzListIter *iter;
		rz_list_foreach (head, iter, item) {
			if (item->size != core->analysis->bits) {
				continue;
			}
			if (item->type != i) {
				continue;
			}
			rz_list_append(list, strdup(item->name));
		}
		const char *item_name;
		rz_list_foreach (list, iter, item_name) {
			value = rz_reg_getv(reg, item_name);
			rz_core_seek(core, value, true);
			rz_cons_printf("%s: ", item_name);
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	err:
		rz_list_free(list);
	}
	rz_core_seek(core, offorig, true);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_symbol_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzBinSymbol *sym;
	ut64 offorig = core->offset;
	ut64 obs = core->blocksize;
	RzList *list = rz_bin_get_symbols(core->bin);
	RzListIter *iter;
	rz_cons_break_push(NULL, NULL);
	RzList *lost = rz_list_newf(free);
	rz_list_foreach (list, iter, sym) {
		RzBinSymbol *bs = rz_mem_dup(sym, sizeof(RzBinSymbol));
		rz_list_append(lost, bs);
	}
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	rz_list_foreach (lost, iter, sym) {
		if (rz_cons_is_breaked()) {
			break;
		}
		rz_core_block_size(core, sym->size);
		rz_core_seek(core, sym->vaddr, true);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
	}
err:
	rz_cons_break_pop();
	rz_list_free(lost);
	rz_core_block_size(core, obs);
	rz_core_seek(core, offorig, true);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_string_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzList *list = rz_bin_get_strings(core->bin);
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	if (list) {
		ut64 offorig = core->offset;
		ut64 obs = core->blocksize;
		RzBinString *s;
		RzList *lost = rz_list_newf(free);
		RzListIter *iter;
		rz_list_foreach (list, iter, s) {
			RzBinString *bs = rz_mem_dup(s, sizeof(RzBinString));
			rz_list_append(lost, bs);
		}
		rz_list_foreach (lost, iter, s) {
			rz_core_block_size(core, s->size);
			rz_core_seek(core, s->vaddr, true);
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	err:
		rz_core_block_size(core, obs);
		rz_core_seek(core, offorig, true);
		rz_list_free(lost);
	}
	return res;
}

static RzCmdStatus do_iter_sections(struct tsr2cmd_state *state, TSNode node, bool show_sections) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzBinObject *obj = rz_bin_cur_object(core->bin);
	if (!obj) {
		return false;
	}
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	ut64 offorig = core->offset;
	ut64 bszorig = core->blocksize;
	RzBinSection *sec;
	RzListIter *iter;
	rz_list_foreach (obj->sections, iter, sec) {
		if ((sec->is_segment && show_sections) || (!sec->is_segment && !show_sections)) {
			continue;
		}
		rz_core_seek(core, sec->vaddr, true);
		rz_core_block_size(core, sec->vsize);
		RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
		UPDATE_CMD_STATUS_RES(res, cmd_res, err);
	}
err:
	rz_core_block_size(core, bszorig);
	rz_core_seek(core, offorig, true);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_sections_stmt) {
	return do_iter_sections(state, node, true);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_segments_stmt) {
	return do_iter_sections(state, node, false);
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_iomap_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	int fd = rz_io_fd_get_current(core->io);
	// only iterate maps of current fd
	RzList *maps = rz_io_map_get_for_fd(core->io, fd);
	RzIOMap *map;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	if (maps) {
		RzListIter *iter;
		rz_list_foreach (maps, iter, map) {
			rz_core_seek(core, map->itv.addr, true);
			rz_core_block_size(core, map->itv.size);
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	err:
		rz_list_free(maps);
	}
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_dbgmap_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzDebug *dbg = core->dbg;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	if (dbg && dbg->cur && dbg->maps) {
		RzList *dbg_maps_addrs = rz_list_newf((RzListFree)free);
		if (!dbg_maps_addrs) {
			return RZ_CMD_STATUS_INVALID;
		}

		RzDebugMap *map;
		RzListIter *iter;
		rz_list_foreach (dbg->maps, iter, map) {
			int *val = RZ_NEW(int);
			*val = map->addr;
			rz_list_append(dbg_maps_addrs, val);
		}

		int *map_addr;
		rz_list_foreach (dbg_maps_addrs, iter, map_addr) {
			rz_core_seek(core, *map_addr, true);
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	err:
		rz_list_free(dbg_maps_addrs);
	}
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_function_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	TSNode filter_node = ts_node_named_child(node, 1);
	char *filter = NULL;
	if (!ts_node_is_null(filter_node)) {
		filter = ts_node_sub_string(filter_node, state->input);
	}
	ut64 obs = core->blocksize;
	ut64 offorig = core->offset;
	RzAnalysisFunction *fcn;
	RzList *list = core->analysis->fcns;
	RzListIter *iter;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	rz_cons_break_push(NULL, NULL);
	rz_list_foreach (list, iter, fcn) {
		if (rz_cons_is_breaked()) {
			break;
		}
		if (!filter || rz_str_glob(fcn->name, filter)) {
			rz_core_seek(core, fcn->addr, true);
			rz_core_block_size(core, rz_analysis_function_linear_size(fcn));
			RzCmdStatus cmd_res = handle_ts_stmt_tmpseek(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	}
err:
	rz_cons_break_pop();
	rz_core_block_size(core, obs);
	rz_core_seek(core, offorig, true);
	free(filter);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(iter_threads_stmt) {
	RzCore *core = state->core;
	TSNode command = ts_node_named_child(node, 0);
	RzDebug *dbg = core->dbg;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	if (dbg && dbg->cur && dbg->cur->threads) {
		int origtid = dbg->tid;
		RzDebugPid *p;
		RzList *list = dbg->cur->threads(dbg, dbg->pid);
		if (!list) {
			return RZ_CMD_STATUS_INVALID;
		}
		RzListIter *iter;
		rz_list_foreach (list, iter, p) {
			rz_debug_select(dbg, dbg->pid, p->pid);
			rz_cons_printf("PID %d\n", p->pid);
			RzCmdStatus cmd_res = handle_ts_stmt(state, command);
			UPDATE_CMD_STATUS_RES(res, cmd_res, err);
		}
	err:
		rz_debug_select(dbg, dbg->pid, origtid);
		rz_list_free(list);
	}
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(grep_stmt) {
	TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
	TSNode arg = ts_node_child_by_field_name(node, "specifier", strlen("specifier"));
	char *arg_str = ts_node_handle_arg(state, node, arg, 1);
	bool is_pipe = state->core->is_pipe;
	state->core->is_pipe = true;
	RzCmdStatus res = handle_ts_stmt(state, command);
	state->core->is_pipe = is_pipe;
	RZ_LOG_DEBUG("grep_stmt specifier: '%s'\n", arg_str);
	RzStrBuf *sb = rz_strbuf_new(arg_str);
	rz_strbuf_prepend(sb, "~");
	char *specifier_str_es = rz_cons_grep_strip(rz_strbuf_get(sb), "`");
	rz_strbuf_free(sb);
	char *specifier_str = rz_cmd_unescape_arg(specifier_str_es, true);
	RZ_LOG_DEBUG("grep_stmt processed specifier: '%s'\n", specifier_str);
	rz_cons_grep_process(specifier_str);
	free(specifier_str_es);
	free(arg_str);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(html_disable_stmt) {
	TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
	int scr_html = rz_config_get_i(state->core->config, "scr.html");
	rz_config_set_i(state->core->config, "scr.html", 0);
	int scr_color = rz_config_get_i(state->core->config, "scr.color");
	rz_config_set_i(state->core->config, "scr.color", COLOR_MODE_DISABLED);
	RzCmdStatus res = handle_ts_stmt(state, command);
	if (scr_html != -1) {
		rz_cons_flush();
		rz_config_set_i(state->core->config, "scr.html", scr_html);
	}
	if (scr_color != -1) {
		rz_config_set_i(state->core->config, "scr.color", scr_color);
	}
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(html_enable_stmt) {
	TSNode command = ts_node_child_by_field_name(node, "command", strlen("command"));
	int scr_html = rz_config_get_i(state->core->config, "scr.html");
	rz_config_set_i(state->core->config, "scr.html", true);
	RzCmdStatus res = handle_ts_stmt(state, command);
	if (scr_html != -1) {
		rz_cons_flush();
		rz_config_set_i(state->core->config, "scr.html", scr_html);
	}
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(pipe_stmt) {
	TSNode command_rizin = ts_node_named_child(node, 0);
	TSNode command_pipe = ts_node_named_child(node, 1);

	RzCmdStatus res = RZ_CMD_STATUS_INVALID;
	RzCmdParsedArgs *a = ts_node_handle_arg_prargs(state, node, command_pipe, 1, true);
	if (a && a->argc > 1) {
		res = core_cmd_pipe(state->core, state, command_rizin, a->argc - 1, a->argv + 1);
	}

	rz_cmd_parsed_args_free(a);
	return res;
}

DEFINE_HANDLE_TS_FCN_AND_SYMBOL(number_stmt) {
	ut64 addr = rz_num_math(state->core->num, node_string);
	rz_core_seek(state->core, addr, true);
	return RZ_CMD_STATUS_OK;
}

static RzCmdStatus handle_ts_stmt(struct tsr2cmd_state *state, TSNode node) {
	RzCmdStatus ret = RZ_CMD_STATUS_INVALID;
	RzCore *core = state->core;
	RzCmd *cmd = core->rcmd;

	// NOTE: code copied from rz_core_cmd, needs rewrite when all the "remote"
	// concept is re-considered.
	if (core->cmdremote) {
		if (*state->input == 'q') {
			RZ_FREE(core->cmdremote);
			return RZ_CMD_STATUS_OK;
		} else if (*state->input != '=' && strncmp(state->input, "!=", 2)) {
			if (core->cmdremote[0]) {
				char *s = rz_str_newf("%s %s", core->cmdremote, state->input);
				rz_core_rtr_cmd(core, s);
				free(s);
			} else {
				char *res = rz_io_system(core->io, state->input);
				if (res) {
					rz_cons_printf("%s\n", res);
					free(res);
				}
			}
			return RZ_CMD_STATUS_OK;
		}
	}

	TSSymbol node_symbol = ts_node_symbol(node);
	ts_handler handler = ht_up_find(cmd->ts_symbols_ht, node_symbol, NULL);

	bool is_lastcmd = state->core->is_lastcmd;
	state->core->is_lastcmd = false;
	if (handler) {
		ret = handler(state, node);
	} else {
		RZ_LOG_WARN("No handler for this kind of command `%s`\n", ts_node_type(node));
	}
	if (state->log && !state->core->is_lastcmd) {
		free(state->core->lastcmd);
		state->core->lastcmd = ts_node_sub_string(node, state->input);
	}
	state->core->is_lastcmd = is_lastcmd;
	return ret;
}

static RzCmdStatus handle_ts_stmt_tmpseek(struct tsr2cmd_state *state, TSNode node) {
	// TODO: remove tmpseek when no commands will change behaviour based on `@` (tmpseek)
	RzCore *core = state->core;
	bool saved_tmpseek = core->tmpseek;
	core->tmpseek = true;
	RzCmdStatus ret = handle_ts_stmt(state, node);
	core->tmpseek = saved_tmpseek;
	return ret;
}

DEFINE_HANDLE_TS_FCN(statements) {
	RzCore *core = state->core;
	RzCmdStatus res = RZ_CMD_STATUS_OK;
	ut32 child_count = ts_node_named_child_count(node);
	int i;

	RZ_LOG_DEBUG("commands with %d childs\n", child_count);
	if (child_count == 0 && !*state->input) {
		if (core->cons->context->breaked) {
			core->cons->context->breaked = false;
			return RZ_CMD_STATUS_INVALID;
		}
		if (!core->cmdrepeat) {
			return RZ_CMD_STATUS_OK;
		}
		return lastcmd_repeat(core, true) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_INVALID;
	}
	if (state->split_lines) {
		rz_cons_break_push(NULL, NULL);
	}
	for (i = 0; i < child_count; i++) {
		if (core->cons->context->cmd_depth < 1) {
			RZ_LOG_ERROR("handle_ts_statements: That was too deep...\n");
			return RZ_CMD_STATUS_INVALID;
		}
		core->cons->context->cmd_depth--;
		if (core->max_cmd_depth - core->cons->context->cmd_depth == 1) {
			core->prompt_offset = core->offset;
		}

		if (state->split_lines && rz_cons_is_breaked()) {
			rz_cons_break_pop();
			return res;
		}
		TSNode command = ts_node_named_child(node, i);
		RzCmdStatus cmd_res = handle_ts_stmt(state, command);
		if (state->split_lines) {
			rz_cons_flush();
			rz_core_task_yield(&core->tasks);
		}
		core->cons->context->cmd_depth++;
		if (cmd_res == RZ_CMD_STATUS_INVALID) {
			char *command_str = ts_node_sub_string(command, state->input);
			eprintf("Error while executing command: %s\n", command_str);
			free(command_str);
			res = cmd_res;
			goto err;
		} else if (cmd_res == RZ_CMD_STATUS_ERROR) {
			// make the whole script return ERROR, but continue to
			// execute the other commands
			res = cmd_res;
		} else if (cmd_res != RZ_CMD_STATUS_OK) {
			res = cmd_res;
			goto err;
		}
	}
err:
	if (state->split_lines) {
		rz_cons_break_pop();
	}
	return res;
}

#define HANDLER_RULE_OP(name) { #name, handle_ts_##name },
#define RULE_OP(name)

struct ts_data_symbol_map map_ts_stmt_handlers[] = {
#include "rz-shell-parser-cmds.inc"
	{ NULL, NULL },
};

#define RULE_OP(name)         { #name, &ts_##name##_symbol },
#define HANDLER_RULE_OP(name) RULE_OP(name)

struct ts_data_symbol_map map_ts_symbols[] = {
#include "rz-shell-parser-cmds.inc"
	{ NULL, NULL },
};

/**
 * \brief Create an instance of RzCmd for the Rizin language
 */
RZ_API RzCmd *rz_core_cmd_new(bool has_cons) {
	RzCmd *res = rz_cmd_new(has_cons);
	if (!res) {
		return NULL;
	}

	TSLanguage *lang = tree_sitter_rzcmd();
	res->language = lang;
	res->ts_symbols_ht = ht_up_new0();
	struct ts_data_symbol_map *entry = map_ts_stmt_handlers;
	while (entry->name) {
		TSSymbol symbol = ts_language_symbol_for_name(lang, entry->name, strlen(entry->name), true);
		ht_up_insert(res->ts_symbols_ht, symbol, entry->data);
		entry++;
	}

	entry = map_ts_symbols;
	while (entry->name) {
		TSSymbol *sym_ptr = entry->data;
		*sym_ptr = ts_language_symbol_for_name(lang, entry->name, strlen(entry->name), true);
		entry++;
	}
	return res;
}

static RzCmdStatus core_cmd_tsrzcmd(RzCore *core, const char *cstr, bool split_lines, bool log) {
	TSParser *parser = ts_parser_new();
	bool language_ok = ts_parser_set_language(parser, (TSLanguage *)core->rcmd->language);
	rz_return_val_if_fail(language_ok, RZ_CMD_STATUS_INVALID);

	char *input = strdup(rz_str_trim_head_ro(cstr));

	TSTree *tree = ts_parser_parse_string(parser, NULL, input, strlen(input));
	if (!tree) {
		rz_warn_if_reached();
		free(input);
		return RZ_CMD_STATUS_INVALID;
	}

	TSNode root = ts_tree_root_node(tree);

	RzCmdStatus res = RZ_CMD_STATUS_INVALID;
	struct tsr2cmd_state state;
	state.parser = parser;
	state.core = core;
	state.input = input;
	state.tree = tree;
	state.log = log;
	state.split_lines = split_lines;
	rz_pvector_init(&state.saved_input, NULL);
	rz_pvector_init(&state.saved_tree, NULL);

	if (state.log) {
		rz_line_hist_add(state.input);
	}

	char *ts_str = ts_node_string(root);
	RZ_LOG_DEBUG("s-expr %s\n", ts_str);
	free(ts_str);

	if (is_ts_statements(root) && !ts_node_has_error(root)) {
		res = handle_ts_statements(&state, root);
	} else {
		// TODO: print a more meaningful error message and use the ERROR
		// tokens to indicate where, probably, the error is.
		eprintf("Error while parsing command: `%s`\n", input);
	}

	ts_tree_delete(tree);
	ts_parser_delete(parser);
	free(input);
	rz_pvector_fini(&state.saved_input);
	rz_pvector_fini(&state.saved_tree);
	return res;
}

static int run_cmd_depth(RzCore *core, char *cmd) {
	char *rcmd;
	int ret = false;

	if (core->cons->context->cmd_depth < 1) {
		eprintf("rz_core_cmd: That was too deep (%s)...\n", cmd);
		return false;
	}
	core->cons->context->cmd_depth--;
	for (rcmd = cmd;;) {
		char *ptr = strchr(rcmd, '\n');
		if (ptr) {
			*ptr = '\0';
		}
		ret = rz_core_cmd_subst(core, rcmd);
		if (ret == -1) {
			eprintf("|ERROR| Invalid command '%s' (0x%02x)\n", rcmd, *rcmd);
			break;
		}
		if (!ptr) {
			break;
		}
		rcmd = ptr + 1;
	}
	core->cons->context->cmd_depth++;
	return ret;
}

RZ_API RzCmdStatus rz_core_cmd_rzshell(RzCore *core, const char *cstr, int log) {
	return core_cmd_tsrzcmd(core, cstr, false, log);
}

RZ_API int rz_core_cmd(RzCore *core, const char *cstr, int log) {
	if (core->use_tree_sitter_rzcmd) {
		return rz_cmd_status2int(core_cmd_tsrzcmd(core, cstr, false, log));
	}

	int ret = false, i;

	if (core->cmdfilter) {
		const char *invalid_chars = ";|>`@";
		for (i = 0; invalid_chars[i]; i++) {
			if (strchr(cstr, invalid_chars[i])) {
				ret = true;
				goto beach;
			}
		}
		if (strncmp(cstr, core->cmdfilter, strlen(core->cmdfilter))) {
			ret = true;
			goto beach;
		}
	}
	if (core->cmdremote) {
		if (*cstr == 'q') {
			RZ_FREE(core->cmdremote);
			goto beach; // false
		} else if (*cstr != '=' && strncmp(cstr, "!=", 2)) {
			if (core->cmdremote[0]) {
				char *s = rz_str_newf("%s %s", core->cmdremote, cstr);
				rz_core_rtr_cmd(core, s);
				free(s);
			} else {
				char *res = rz_io_system(core->io, cstr);
				if (res) {
					rz_cons_printf("%s\n", res);
					free(res);
				}
			}
			if (log) {
				rz_line_hist_add(cstr);
			}
			goto beach; // false
		}
	}

	if (!cstr || (*cstr == '|' && cstr[1] != '?')) {
		// raw comment syntax
		goto beach; // false;
	}
	if (!strncmp(cstr, "/*", 2)) {
		core->incomment = true;
	} else if (!strncmp(cstr, "*/", 2)) {
		core->incomment = false;
		goto beach; // false
	}
	if (core->incomment) {
		goto beach; // false
	}
	if (log && (*cstr && (*cstr != '.' || !strncmp(cstr, ".(", 2)))) {
		free(core->lastcmd);
		core->lastcmd = strdup(cstr);
	}

	char *cmd = malloc(strlen(cstr) + 4096);
	if (!cmd) {
		goto beach;
	}
	rz_str_cpy(cmd, cstr);
	if (log) {
		rz_line_hist_add(cstr);
	}

	ret = run_cmd_depth(core, cmd);
	free(cmd);
beach:
	return ret;
}

RZ_API RzCmdStatus rz_core_cmd_lines_rzshell(RzCore *core, const char *lines) {
	return core_cmd_tsrzcmd(core, lines, true, false);
}

RZ_API int rz_core_cmd_lines(RzCore *core, const char *lines) {
	if (core->use_tree_sitter_rzcmd) {
		RzCmdStatus status = core_cmd_tsrzcmd(core, lines, true, false);
		return status == RZ_CMD_STATUS_OK;
	}
	int r, ret = true;
	char *nl, *data, *odata;

	if (!lines || !*lines) {
		return true;
	}
	data = odata = strdup(lines);
	if (!odata) {
		return false;
	}
	nl = strchr(odata, '\n');
	if (nl) {
		rz_cons_break_push(NULL, NULL);
		do {
			if (rz_cons_is_breaked()) {
				free(odata);
				rz_cons_break_pop();
				return ret;
			}
			*nl = '\0';
			r = rz_core_cmd(core, data, 0);
			if (r < 0) { //== -1) {
				data = nl + 1;
				ret = -1; // r; //false;
				break;
			}
			rz_cons_flush();
			if (data[0] == 'q') {
				if (data[1] == '!') {
					ret = -1;
				} else {
					eprintf("'q': quit ignored. Use 'q!'\n");
				}
				data = nl + 1;
				break;
			}
			data = nl + 1;
			rz_core_task_yield(&core->tasks);
		} while ((nl = strchr(data, '\n')));
		rz_cons_break_pop();
	}
	if (ret >= 0 && data && *data) {
		rz_core_cmd(core, data, 0);
		rz_cons_flush();
		rz_core_task_yield(&core->tasks);
	}
	free(odata);
	return ret;
}

RZ_API int rz_core_cmd_file(RzCore *core, const char *file) {
	char *data = rz_file_abspath(file);
	if (!data) {
		return false;
	}
	char *odata = rz_file_slurp(data, NULL);
	free(data);
	if (!odata) {
		return false;
	}
	if (!rz_core_cmd_lines(core, odata)) {
		eprintf("Failed to run script '%s'\n", file);
		free(odata);
		return false;
	}
	free(odata);
	return true;
}

RZ_API int rz_core_cmd_command(RzCore *core, const char *command) {
	int ret, len;
	char *buf, *rcmd;
	rz_core_sysenv_begin(core);
	rcmd = buf = rz_sys_cmd_str(command, 0, &len);
	if (!buf) {
		return -1;
	}
	ret = rz_core_cmd(core, rcmd, 0);
	rz_core_sysenv_end(core);
	free(buf);
	return ret;
}

// TODO: Fix disasm loop is mandatory
RZ_API char *rz_core_disassemble_instr(RzCore *core, ut64 addr, int l) {
	char *cmd, *ret = NULL;
	cmd = rz_str_newf("pd %i @ 0x%08" PFMT64x, l, addr);
	if (cmd) {
		ret = rz_core_cmd_str(core, cmd);
		free(cmd);
	}
	return ret;
}

RZ_API char *rz_core_disassemble_bytes(RzCore *core, ut64 addr, int b) {
	char *cmd, *ret = NULL;
	cmd = rz_str_newf("pD %i @ 0x%08" PFMT64x, b, addr);
	if (cmd) {
		ret = rz_core_cmd_str(core, cmd);
		free(cmd);
	}
	return ret;
}

RZ_API int rz_core_cmd_buffer(RzCore *core, const char *buf) {
	char *ptr, *optr, *str = strdup(buf);
	if (!str) {
		return false;
	}
	optr = str;
	ptr = strchr(str, '\n');
	while (ptr) {
		*ptr = '\0';
		rz_core_cmd(core, optr, 0);
		optr = ptr + 1;
		ptr = strchr(str, '\n');
	}
	rz_core_cmd(core, optr, 0);
	free(str);
	return true;
}

RZ_API int rz_core_cmdf(RzCore *core, const char *fmt, ...) {
	char string[4096];
	int ret;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(string, sizeof(string), fmt, ap);
	ret = rz_core_cmd(core, string, 0);
	va_end(ap);
	return ret;
}

RZ_API RzCmdStatus rz_core_cmd0_rzshell(RzCore *core, const char *cmd) {
	return rz_core_cmd_rzshell(core, cmd, 0);
}

RZ_API int rz_core_cmd0(RzCore *core, const char *cmd) {
	return rz_core_cmd(core, cmd, 0);
}

RZ_API int rz_core_flush(RzCore *core, const char *cmd) {
	int ret = rz_core_cmd(core, cmd, 0);
	rz_cons_flush();
	return ret;
}

RZ_API char *rz_core_cmd_str_pipe(RzCore *core, const char *cmd) {
	char *tmp = NULL;
	char *p = (*cmd != '"') ? strchr(cmd, '|') : NULL;
	if (!p && *cmd != '!' && *cmd != '.') {
		return rz_core_cmd_str(core, cmd);
	}
	rz_cons_reset();
	if (rz_file_mkstemp("cmd", &tmp) != -1) {
		int pipefd = rz_cons_pipe_open(tmp, 1, 0);
		if (pipefd == -1) {
			rz_file_rm(tmp);
			free(tmp);
			return rz_core_cmd_str(core, cmd);
		}
		char *_cmd = strdup(cmd);
		if (core->use_tree_sitter_rzcmd) {
			rz_core_cmd(core, _cmd, 0);
		} else {
			rz_core_cmd_subst(core, _cmd);
		}
		rz_cons_flush();
		rz_cons_pipe_close(pipefd);
		if (rz_file_exists(tmp)) {
			char *s = rz_file_slurp(tmp, NULL);
			rz_file_rm(tmp);
			free(tmp);
			free(_cmd);
			return s ? s : strdup("");
		}
		eprintf("slurp %s fails\n", tmp);
		rz_file_rm(tmp);
		free(tmp);
		free(_cmd);
		return rz_core_cmd_str(core, cmd);
	}
	return NULL;
}

RZ_API char *rz_core_cmd_strf(RzCore *core, const char *fmt, ...) {
	char string[4096];
	char *ret;
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(string, sizeof(string), fmt, ap);
	ret = rz_core_cmd_str(core, string);
	va_end(ap);
	return ret;
}

static ut8 *core_cmd_raw(RzCore *core, const char *cmd, int *length) {
	const char *static_str;
	ut8 *retstr = NULL;
	rz_cons_push();
	bool is_pipe = core->is_pipe;
	core->is_pipe = true;
	if (rz_core_cmd(core, cmd, 0) == -1) {
		core->is_pipe = is_pipe;
		rz_cons_pop();
		return NULL;
	}
	core->is_pipe = is_pipe;
	rz_cons_filter();
	static_str = rz_cons_get_buffer();
	if (length) {
		int len = rz_cons_get_buffer_len();
		retstr = (ut8 *)rz_str_newlen(static_str, len);
		*length = len;
	} else {
		retstr = (ut8 *)strdup(rz_str_get(static_str));
	}

	rz_cons_pop();
	rz_cons_echo(NULL);
	return retstr;
}

/**
 * \brief Executes a rizin command and returns the stdout as a string
 */
RZ_API char *rz_core_cmd_str(RzCore *core, const char *cmd) {
	rz_return_val_if_fail(core && cmd, NULL);
	return (char *)core_cmd_raw(core, cmd, NULL);
}

/**
 * \brief Executes a rizin command and returns the raw stdout and its length
 */
RZ_API ut8 *rz_core_cmd_raw(RzCore *core, const char *cmd, int *length) {
	rz_return_val_if_fail(core && cmd && length, NULL);
	return core_cmd_raw(core, cmd, length);
}

RZ_IPI int rz_cmd_ox(void *data, const char *input) {
	return rz_core_cmdf((RzCore *)data, "s 0%s", input);
}

static int compare_cmd_descriptor_name(const void *a, const void *b) {
	return strcmp(((RzCmdDescriptor *)a)->cmd, ((RzCmdDescriptor *)b)->cmd);
}

static void cmd_descriptor_init(RzCore *core) {
	const ut8 *p;
	RzListIter *iter;
	RzCmdDescriptor *x, *y;
	int n = core->cmd_descriptors->length;
	rz_list_sort(core->cmd_descriptors, compare_cmd_descriptor_name);
	rz_list_foreach (core->cmd_descriptors, iter, y) {
		if (--n < 0) {
			break;
		}
		x = &core->root_cmd_descriptor;
		for (p = (const ut8 *)y->cmd; *p; p++) {
			if (!x->sub[*p]) {
				if (p[1]) {
					RzCmdDescriptor *d = RZ_NEW0(RzCmdDescriptor);
					rz_list_append(core->cmd_descriptors, d);
					x->sub[*p] = d;
				} else {
					x->sub[*p] = y;
				}
			} else if (!p[1]) {
				eprintf("Command '%s' is duplicated, please check\n", y->cmd);
			}
			x = x->sub[*p];
		}
	}
}

static int core_cmd0_wrapper(void *core, const char *cmd) {
	return rz_core_cmd0((RzCore *)core, cmd);
}

RZ_API void rz_core_cmd_init(RzCore *core) {
	struct {
		const char *cmd;
		const char *description;
		RzCmdCb cb;
	} cmds[] = {
		{ "_", "print last output", rz_cmd_last },
		{ "#", "calculate hash", rz_cmd_hash },
		{ "$", "alias", rz_cmd_alias },
		{ "%", "short version of 'env' command", rz_cmd_env },
		{ "&", "tasks", rz_cmd_tasks },
		{ "(", "macro", rz_cmd_macro },
		{ "*", "pointer read/write", rz_cmd_pointer },
		{ ".", "interpret", rz_cmd_interpret },
		{ "/", "search kw, pattern aes", rz_cmd_search },
		{ "R", "io pipe", rz_cmd_remote },
		{ "?", "help message", rz_cmd_help },
		{ "<", "pipe into RzCons.readChar", rz_cmd_pipein },
		{ "0", "alias for s 0x", rz_cmd_ox },
		{ "a", "analysis", rz_cmd_analysis },
		{ "d", "debugger operations", rz_cmd_debug },
		{ "f", "get/set flags", rz_cmd_flag },
		{ "k", "perform sdb query", rz_cmd_kuery },
		{ "o", "open or map file", rz_cmd_open },
		{ "p", "print current block", rz_cmd_print },
		{ "q", "exit program session", rz_cmd_quit },
		{ "V", "enter visual mode", rz_cmd_visual },
		{ "v", "enter visual mode", rz_cmd_panels },
		{ "w", "write bytes", rz_cmd_write },
		{ "x", "alias for px", rz_cmd_hexdump },
		{ "z", "zignatures", rz_cmd_zign },
	};

	core->rcmd = rz_core_cmd_new(!!core->cons);
	core->rcmd->macro.user = core;
	core->rcmd->macro.num = core->num;
	core->rcmd->macro.cmd = core_cmd0_wrapper;
	core->rcmd->nullcallback = rz_core_cmd_nullcallback;
	core->rcmd->macro.cb_printf = (PrintfCallback)rz_cons_printf;
	rz_cmd_set_data(core->rcmd, core);
	core->cmd_descriptors = rz_list_newf(free);

	size_t i;
	for (i = 0; i < RZ_ARRAY_SIZE(cmds); i++) {
		if (cmds[i].cb) {
			rz_cmd_add(core->rcmd, cmds[i].cmd, cmds[i].cb);
		}
	}
	DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL(core, $, dollar);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL(core, %, percent);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL(core, *, star);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL(core, ., dot);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR_SPECIAL(core, =, equal);

	DEPRECATED_DEFINE_CMD_DESCRIPTOR(core, k);
	DEPRECATED_DEFINE_CMD_DESCRIPTOR(core, u);
	cmd_descriptor_init(core);
	rzshell_cmddescs_init(core);
}

RZ_IPI RzCmdStatus rz_basefind_compute_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	ut32 pointer_size = 0;
	if (argc != 2 || RZ_STR_ISEMPTY(argv[1])) {
		pointer_size = 32;
	} else if (!strcmp(argv[1], "32")) {
		pointer_size = 32;
	} else if (!strcmp(argv[1], "64")) {
		pointer_size = 64;
	}
	return bool2status(rz_core_bin_basefind_print(core, pointer_size, state));
}
