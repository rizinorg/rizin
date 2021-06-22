static char *system_cmd_new(int argc, const char **argv) {
	if (argc == 1) {
		return strdup(argv[0]);
	}

	RzStrBuf *sb = rz_strbuf_new(argv[0]);
	if (!sb) {
		return NULL;
	}

	for (int i = 1; i < argc; ++i) {
		rz_strbuf_append(sb, " \"");
		const char *arg = argv[i];
		if (strchr(arg, '"') || strchr(arg, '\\')) {
			size_t p, s, len = strlen(arg);
			for (p = 0, s = 0; p < len; ++p) {
				if (arg[p] == '\\' || arg[p] == '"') {
					rz_strbuf_append_n(sb, arg + s, p - s);
					rz_strbuf_append(sb, "\\");
					s = p;
				}
			}
			arg += s;
		}
		rz_strbuf_appendf(sb, "%s\"", arg);
	}

	return rz_strbuf_drain(sb);
}

RZ_IPI RzCmdStatus rz_system_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		rz_line_hist_list();
		return RZ_CMD_STATUS_OK;
	}

	char *cmd = system_cmd_new(argc - 1, &argv[1]);
	if (!cmd) {
		RZ_LOG_ERROR("Cannot allocate memory to command line buffer.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	rz_core_sysenv_begin(core);
	void *bed = rz_cons_sleep_begin();

	int ret = rz_sys_system(cmd);
	free(cmd);

	rz_cons_sleep_end(bed);
	rz_core_sysenv_end(core);

	return !ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_API RzCmdStatus rz_system_to_cons_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	int olen, ret;
	char *out = NULL;
	char *cmd = system_cmd_new(argc - 1, &argv[1]);
	if (!cmd) {
		RZ_LOG_ERROR("Cannot allocate memory to command line buffer.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	rz_core_sysenv_begin(core);
	void *bed = rz_cons_sleep_begin();

	ret = rz_sys_cmd_str_full(cmd, NULL, &out, &olen, NULL);

	rz_cons_sleep_end(bed);
	rz_core_sysenv_end(core);

	rz_cons_memcat(out, olen);
	free(out);
	free(cmd);

	return !ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_list_or_exec_history_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		rz_line_hist_list();
		return RZ_CMD_STATUS_OK;
	} else if (argc > 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	int index = atoi(argv[1]);
	if (index < 1) {
		RZ_LOG_ERROR("index must be a positive number.\n");
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	const char *cmd = rz_line_hist_get(index);
	if (!cmd) {
		RZ_LOG_ERROR("cannot find command with index %d.\n", index);
		return RZ_CMD_STATUS_ERROR;
	}

	int ret = rz_core_cmd0(core, cmd);
	return !ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_clear_history_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	rz_line_hist_free();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_history_save_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	rz_line_hist_save(RZ_HOME_HISTORY);
	return RZ_CMD_STATUS_OK;
}
