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
			return RZ_CMD_STATUS_ERROR;
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
	if (!res) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(res);
	free(res);
	free(arg);
	return RZ_CMD_STATUS_OK;
}

// rm
RZ_IPI RzCmdStatus rz_cmd_shell_rm_handler(RzCore *core, int argc, const char **argv) {
	return rz_file_rm(argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// sleep
RZ_IPI RzCmdStatus rz_cmd_shell_sleep_handler(RzCore *core, int argc, const char **argv) {
	void *bed = rz_cons_sleep_begin();
	rz_sys_sleep(atoi(argv[1] + 1));
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

// cp.
RZ_IPI RzCmdStatus rz_cmd_shell_cp_ext_handler(RzCore *core, int argc, const char **argv) {
	const char *file = rz_config_get(core->config, "file.path");
	char *new_file = rz_str_newf("%s.%s", file, argv[1]);
	bool rc = rz_file_copy(file, new_file);
	if (!rc) {
		RZ_LOG_ERROR("Failed to copy %s to %s\n", file, new_file);
	}
	free(new_file);
	return rc ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

// cd
RZ_IPI RzCmdStatus rz_cmd_shell_cd_handler(RzCore *core, int argc, const char **argv) {
	static char *olddir = NULL;
	bool ret = true;
	if (!strcmp(argv[1], "-")) {
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
		if (!rz_sys_chdir(argv[1])) {
			RZ_LOG_ERROR("Cannot chdir to %s\n", argv[1]);
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
	char *res = rz_syscmd_cat(path);
	if (res) {
		rz_cons_print(res);
		free(res);
	}
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_shell_mv_handler(RzCore *core, int argc, const char **argv) {
	char *input = rz_str_newf("mv %s %s", argv[0], argv[1]);
	int ec = rz_sys_system(input);
	free(input);
	return ec == 0 ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_shell_mkdir_handler(RzCore *core, int argc, const char **argv) {
	char *res = rz_syscmd_mkdir(argv[1]);
	if (res) {
		rz_cons_print(res);
		free(res);
	}
	return res ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
