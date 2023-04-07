// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

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

// ascii
RZ_IPI RzCmdStatus rz_cmd_shell_ascii_table_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%s", ret_ascii_table());
	return RZ_CMD_STATUS_OK;
}

// env
RZ_IPI RzCmdStatus rz_cmd_shell_env_handler(RzCore *core, int argc, const char **argv) {
	char *p, **e;
	switch (argc) {
	case 1:
		e = rz_sys_get_environ();
		while (!RZ_STR_ISEMPTY(e)) {
			rz_cons_println(*e);
			e++;
		}
		return RZ_CMD_STATUS_OK;
	case 2:
		p = rz_sys_getenv(argv[1]);
		if (!p) {
			return RZ_CMD_STATUS_OK;
		}
		rz_cons_println(p);
		free(p);
		return RZ_CMD_STATUS_OK;
	case 3:
		rz_sys_setenv(argv[1], argv[2]);
		return RZ_CMD_STATUS_OK;
	default:
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
}

// exit
RZ_IPI RzCmdStatus rz_cmd_shell_exit_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = 0LL;
	return RZ_CMD_STATUS_EXIT;
}

// ls
RZ_IPI RzCmdStatus rz_cmd_shell_ls_handler(RzCore *core, int argc, const char **argv) {
	char *arg = rz_str_array_join(argv + 1, argc - 1, " ");
	char *res = rz_syscmd_ls(arg);
	free(arg);
	if (!res) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(res);
	free(res);
	return RZ_CMD_STATUS_OK;
}

// rm
RZ_IPI RzCmdStatus rz_cmd_shell_rm_handler(RzCore *core, int argc, const char **argv) {
	return rz_file_rm(argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// sleep
RZ_IPI RzCmdStatus rz_cmd_shell_sleep_handler(RzCore *core, int argc, const char **argv) {
	void *bed = rz_cons_sleep_begin();
	rz_sys_sleep(atoi(argv[1]));
	rz_cons_sleep_end(bed);
	return RZ_CMD_STATUS_OK;
}

// uniq
RZ_IPI RzCmdStatus rz_cmd_shell_uniq_handler(RzCore *core, int argc, const char **argv) {
	char *res = rz_syscmd_uniq(argv[1]);
	if (!res) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(res);
	free(res);
	return RZ_CMD_STATUS_OK;
}

// uname
RZ_IPI RzCmdStatus rz_cmd_shell_uname_handler(RzCore *core, int argc, const char **argv) {
	RSysInfo *si = rz_sys_info();
	if (!si) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_printf("%s", si->sysname);
	if (argc > 1 && strcmp(argv[1], "-r") == 0) {
		rz_cons_printf(" %s", si->release);
	}
	rz_cons_newline();
	rz_sys_info_free(si);
	return RZ_CMD_STATUS_OK;
}

// echo
RZ_IPI RzCmdStatus rz_cmd_shell_echo_handler(RzCore *core, int argc, const char **argv) {
	if (argc >= 2) {
		char *output = rz_str_array_join(argv + 1, argc - 1, " ");
		// TODO: replace all ${flagname} by its value in hexa
		char *newmsg = filterFlags(core, output);
		rz_str_unescape(newmsg);
		rz_cons_print(newmsg);
		free(output);
		free(newmsg);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}

// cp
RZ_IPI RzCmdStatus rz_cmd_shell_cp_handler(RzCore *core, int argc, const char **argv) {
	bool rc = rz_file_copy(argv[1], argv[2]);
	if (!rc) {
		RZ_LOG_ERROR("Failed to copy %s to %s\n", argv[1], argv[2]);
	}
	return rc ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cd
RZ_IPI RzCmdStatus rz_cmd_shell_cd_handler(RzCore *core, int argc, const char **argv) {
	static char *olddir = NULL;
	bool ret = false;
	const char *dir = "~";
	if (argc > 1) {
		dir = argv[1];
	}
	if (!strcmp(dir, "-")) {
		if (olddir) {
			char *newdir = olddir;
			olddir = rz_sys_getdir();
			if (!rz_sys_chdir(newdir)) {
				RZ_LOG_ERROR("Cannot chdir to %s\n", newdir);
				free(olddir);
				olddir = newdir;
			} else {
				free(newdir);
				ret = true;
			}
		} else {
			RZ_LOG_ERROR("No old directory found\n");
		}
	} else {
		char *cwd = rz_sys_getdir();
		if (!rz_sys_chdir(dir)) {
			RZ_LOG_ERROR("Cannot chdir to %s\n", dir);
			free(cwd);
		} else {
			free(olddir);
			olddir = cwd;
			ret = true;
		}
	}
	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cat
RZ_IPI RzCmdStatus rz_cmd_shell_cat_handler(RzCore *core, int argc, const char **argv) {
	const char *path = argv[1];
	if (*path == '$') {
		const char *oldText = rz_cmd_alias_get(core->rcmd, path, 1);
		if (oldText) {
			rz_cons_printf("%s\n", oldText + 1);
		} else {
			RZ_LOG_ERROR("Invalid alias\n");
		}
		return oldText ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	}
	char *res = rz_syscmd_cat(path);
	if (res) {
		rz_cons_print(res);
		free(res);
	}
	return RZ_CMD_STATUS_OK;
}

// mv
RZ_IPI RzCmdStatus rz_cmd_shell_mv_handler(RzCore *core, int argc, const char **argv) {
	char *input = rz_str_newf("mv %s %s", argv[1], argv[2]);
	int ec = rz_sys_system(input);
	free(input);
	return ec == 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// mkdir
RZ_IPI RzCmdStatus rz_cmd_shell_mkdir_handler(RzCore *core, int argc, const char **argv) {
	RzStrBuf *buf = rz_strbuf_new(NULL);
	for (int i = 1; i < argc; i++) {
		rz_strbuf_appendf(buf, " %s", argv[i]);
	}
	char *input = rz_strbuf_drain(buf);
	char *res = rz_syscmd_mkdir(input);
	free(input);
	if (res) {
		rz_cons_print(res);
		free(res);
	}
	return RZ_CMD_STATUS_OK;
}

// pwd
RZ_IPI RzCmdStatus rz_cmd_shell_pwd_handler(RzCore *core, int argc, const char **argv) {
	char *cwd = rz_sys_getdir();
	if (cwd) {
		rz_cons_println(cwd);
		free(cwd);
	}
	return RZ_CMD_STATUS_OK;
}

// sort
RZ_IPI RzCmdStatus rz_cmd_shell_sort_handler(RzCore *core, int argc, const char **argv) {
	char *res = rz_syscmd_sort(argv[1]);
	if (res) {
		rz_cons_print(res);
		free(res);
	}
	return RZ_CMD_STATUS_OK;
}

// clear
// cls
RZ_IPI RzCmdStatus rz_cmd_shell_clear_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_clear00();
	return RZ_CMD_STATUS_OK;
}

// flush
RZ_IPI RzCmdStatus rz_cmd_shell_flush_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_flush();
	return RZ_CMD_STATUS_OK;
}

// which
RZ_IPI RzCmdStatus rz_cmd_shell_which_handler(RzCore *core, int argc, const char **argv) {
	char *solved = rz_file_path(argv[1]);
	if (!solved) {
		RZ_LOG_ERROR("Could not get the full path of '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_println(solved);
	free(solved);
	return RZ_CMD_STATUS_OK;
}

// fortune
RZ_IPI RzCmdStatus rz_cmd_shell_fortune_handler(RzCore *core, int argc, const char **argv) {
	rz_core_fortune_print_random(core);
	return RZ_CMD_STATUS_OK;
}

// diff
RZ_IPI RzCmdStatus rz_cmd_shell_diff_handler(RzCore *core, int argc, const char **argv) {
	char *a = rz_file_slurp(argv[1], NULL);
	if (!a) {
		RZ_LOG_ERROR("core: Cannot open file A: \"%s\"\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	char *b = rz_file_slurp(argv[2], NULL);
	if (!b) {
		RZ_LOG_ERROR("core: Cannot open file B: \"%s\"\n", argv[2]);
		free(a);
		return RZ_CMD_STATUS_ERROR;
	}
	RzDiff *dff = rz_diff_lines_new(a, b, NULL);
	bool color = rz_config_get_i(core->config, "scr.color") > 0;
	char *uni = rz_diff_unified_text(dff, argv[1], argv[2], false, color);
	rz_diff_free(dff);
	rz_cons_printf("%s\n", uni);
	free(uni);
	free(a);
	free(b);
	return RZ_CMD_STATUS_OK;
}

// date
RZ_IPI RzCmdStatus rz_cmd_shell_date_handler(RzCore *core, int argc, const char **argv) {
	char *now = rz_time_date_now_to_string();
	rz_cons_printf("%s\n", now);
	free(now);
	return RZ_CMD_STATUS_OK;
}

// pkill
RZ_IPI RzCmdStatus rz_cmd_shell_pkill_handler(RzCore *core, int argc, const char **argv) {
	RzListIter *iter;
	RzDebugPid *pid;
	RzList *pids = (core->dbg->cur && core->dbg->cur->pids)
		? core->dbg->cur->pids(core->dbg, 0)
		: NULL;
	rz_list_foreach (pids, iter, pid) {
		if (strstr(pid->path, argv[1])) {
			rz_debug_kill(core->dbg, pid->pid, 0, 9);
		}
	}
	rz_list_free(pids);
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

RZ_IPI RzCmdStatus rz_calculate_command_time_handler(RzCore *core, int argc, const char **argv) {
	ut64 start = rz_time_now_mono();
	rz_core_cmd(core, argv[1], 0);
	ut64 end = rz_time_now_mono();
	double seconds = (double)(end - start) / RZ_USEC_PER_SEC;
	core->num->value = (ut64)seconds;
	rz_cons_printf("%lf\n", seconds);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_info_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	switch (state->mode) {
	case RZ_OUTPUT_MODE_STANDARD: {
		char *v = rz_version_str(NULL);
		rz_cons_printf("%s\n", v);
		free(v);
		break;
	}
	case RZ_OUTPUT_MODE_QUIET: {
		rz_cons_println(RZ_VERSION);
		break;
	}
	case RZ_OUTPUT_MODE_JSON: {
		PJ *pj = state->d.pj;
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
		break;
	}
	default:
		rz_warn_if_reached();
		return RZ_CMD_STATUS_ERROR;
	}

	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_numeric_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", vernum(RZ_VERSION));
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_show_version_numeric2_handler(RzCore *core, int argc, const char **argv) {
	rz_cons_printf("%d\n", RZ_VERSION_NUMBER);
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
		f = avatar_cybcat[rz_num_rand32(RZ_ARRAY_SIZE(avatar_cybcat))];
	} else if (rz_config_get_i(core->config, "scr.utf8")) {
		l = (char *)rz_str_repeat("─", msglen);
		f = avatar_clippy_utf8[rz_num_rand32(RZ_ARRAY_SIZE(avatar_clippy_utf8))];
	} else {
		l = strdup(rz_str_pad('-', msglen));
		f = avatar_clippy[rz_num_rand32(RZ_ARRAY_SIZE(avatar_clippy))];
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

RZ_IPI RzCmdStatus rz_cmd_shell_clippy_handler(RzCore *core, int argc, const char **argv) {
	if (argc >= 2) {
		char *output = rz_str_array_join(argv + 1, argc - 1, " ");
		rz_core_clippy_print(core, output);
		free(output);
	}
	rz_cons_newline();
	return RZ_CMD_STATUS_OK;
}
