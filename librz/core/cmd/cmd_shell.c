// SPDX-FileCopyrightText: 2021 Dhruv Maroo <dhruvmaru007@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

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

RZ_IPI RzCmdStatus rz_cmd_shell_exit_handler(RzCore *core, int argc, const char **argv) {
	core->num->value = 0LL;
	return RZ_CMD_STATUS_EXIT;
}

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

RZ_IPI RzCmdStatus rz_cmd_shell_rm_handler(RzCore *core, int argc, const char **argv) {
	return rz_file_rm(argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_shell_sleep_handler(RzCore *core, int argc, const char **argv) {
	void *bed = rz_cons_sleep_begin();
	rz_sys_sleep(atoi(argv[1] + 1));
	rz_cons_sleep_end(bed);
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_cmd_shell_uniq_handler(RzCore *core, int argc, const char **argv) {
	char *res = rz_syscmd_uniq(argv[1]);
	if (!res) {
		return RZ_CMD_STATUS_ERROR;
	}
	rz_cons_print(res);
	free(res);
	return RZ_CMD_STATUS_OK;
}

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

RZ_IPI RzCmdStatus rz_cmd_shell_echo_handler(RzCore *core, int argc, const char **argv) {
	if (argc >= 2) {
		char *output = rz_str_array_join(argv + 1, argc - 1, " ");
		rz_cons_println(output);
		free(output);
		return RZ_CMD_STATUS_OK;
	}
	return RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_cmd_shell_cp_handler(RzCore *core, int argc, const char **argv) {
	// if (input[1] == '.') {
	// 	char *file = rz_core_cmd_strf(core, "ij~{core.file}");
	// 	rz_str_trim(file);
	// 	char *newfile = rz_str_newf("%s.%s", file, input + 2);
	// 	rz_file_copy(file, newfile);
	// 	free(file);
	// 	free(newfile);
	// 	return true;
	// }
	// char *cmd = strdup(input + 2);
	// if (cmd) {
	// 	char **files = rz_str_argv(cmd, NULL);
	// 	if (files[0] && files[1]) {
	// 		bool rc = rz_file_copy(files[0], files[1]);
	// 		free(cmd);
	// 		rz_str_argv_free(files);
	// 		return rc;
	// 	}
	// 	rz_str_argv_free(files);
	// }
	bool rc = true;
	for (int i = 1; i < argc - 1; i++) {
		rc &= rz_file_copy(argv[i], argv[argc - 1]);
		if (!rc) {
			RZ_LOG_ERROR("Failed to copy %s to %s\n", argv[i], argv[argc - 1]);
		}
		rc = true;
	}
	return RZ_CMD_STATUS_OK;
}

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
