// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

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
		rz_cons_println(output);
		free(output);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
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
