RZ_IPI RzCmdStatus rz_history_list_or_exec_handler(RzCore *core, int argc, const char **argv) {
	if (argc == 1) {
		rz_line_hist_list();
		return RZ_CMD_STATUS_OK;
	}

	int index = atoi(argv[1]);
	if (index < 1) {
		RZ_LOG_ERROR("index must be a positive number.\n");
		return RZ_CMD_STATUS_ERROR;
	}

	const char *cmd = rz_line_hist_get(index);
	if (!cmd) {
		RZ_LOG_ERROR("cannot find command with index %d.\n", index);
		return RZ_CMD_STATUS_ERROR;
	}

	int ret = rz_core_cmd0(core, cmd);
	return !ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_history_clear_handler(RzCore *core, int argc, const char **argv) {
	rz_line_hist_free();
	return RZ_CMD_STATUS_OK;
}

RZ_IPI RzCmdStatus rz_history_save_handler(RzCore *core, int argc, const char **argv) {
	rz_line_hist_save(RZ_HOME_HISTORY);
	return RZ_CMD_STATUS_OK;
}
