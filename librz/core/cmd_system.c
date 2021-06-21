//RZ_IPI int rz_cmd_system(void *data, const char *input)
static int system_exec(int argc, const char **argv) {
	if (argc == 1) {
		return rz_sys_system(argv[0]);
	}

	RzStrBuf *sb = rz_strbuf_new(argv[0]);
	if (!sb) {
		return 1;
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

	int ret = rz_sys_system(rz_strbuf_get(sb));
	rz_strbuf_free(sb);
	return ret;
}

RZ_IPI RzCmdStatus rz_system_list_history_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		rz_line_hist_list();
		return RZ_CMD_STATUS_OK;
	}
	rz_core_sysenv_begin(core);
	void *bed = rz_cons_sleep_begin();
	int ret = system_exec(argc - 1, &argv[1]);
	
	rz_cons_sleep_end(bed);
	rz_core_sysenv_end(core);

	return !ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_clear_history_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	rz_line_hist_free();
	return RZ_CMD_STATUS_OK;
}


RZ_IPI RzCmdStatus rz_clear_history_save_handler(RzCore *core, int argc, const char **argv) {
	if (argc != 1) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	rz_line_hist_free();
	rz_line_hist_save(RZ_HOME_HISTORY);
	return RZ_CMD_STATUS_OK;
}


