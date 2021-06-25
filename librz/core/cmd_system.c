static char *config_path(RzCore *core) {
	char *path = NULL;
	int fd = rz_file_mkstemp(NULL, &path);
	if (fd >= 0) {
		close(fd);
	}
	if (!path) {
		return NULL;
	}

	Sdb *sdb = sdb_new(NULL, path, 0);
	if (!sdb) {
		return NULL;
	}
	rz_config_serialize(core->config, sdb);
	sdb_sync(sdb);
	sdb_free(sdb);

	return path;
}

static const char *system_apply_env_var(const char *env, const char *value, const char *arg, RzList *alloc) {
	char *string = NULL;
	RzListIter *it = NULL;
	size_t len = strlen(arg);
	if (!strstr(arg, env)) {
		return arg;
	} else if (strlen(env) == len) {
		return value;
	}

	if ((it = rz_list_find_ptr(alloc, (void *)arg))) {
		string = it->data;
	} else {
		string = strdup(arg);
	}

	string = rz_str_replace(string, env, value, 1);
	if (it) {
		it->data = string;
	} else {
		rz_list_append(alloc, string);
	}
	return string;
}

static bool system_exec(RzCore *core, int argc, const char **argv, char **output) {
	char file_size[32];
	char core_offset[32];
	char block_size[32];
	const char *file_path = rz_config_get(core->config, "file.path");
	const char *asm_arch = rz_config_get(core->config, "asm.arch");
	const char *asm_bits = rz_config_get(core->config, "asm.bits");
	const char *bin_demangle = rz_config_get(core->config, "bin.demangle");
	const char *bin_lang = rz_config_get(core->config, "bin.lang");
	const char *cfg_debug = rz_config_get(core->config, "cfg.debug");
	const char *io_va = rz_config_get(core->config, "io.va");
	const char *pdb_server = rz_config_get(core->config, "pdb.server");
	const char *scr_color = rz_config_get(core->config, "scr.color");
	const char *endian = rz_str_bool(core->rasm->big_endian);
	char *cfg_path = config_path(core);
	snprintf(file_size, sizeof(file_size), "%" PFMT64u, core->file ? rz_io_fd_size(core->io, core->file->fd) : 0);
	snprintf(core_offset, sizeof(core_offset), "%" PFMT64u, core->offset);
	snprintf(block_size, sizeof(block_size), "%u", core->blocksize);

	const char *envvars[] = {
		"RZ_FILE",
		"RZ_SIZE",
		"RZ_ARCH",
		"RZ_BITS",
		"RZ_OFFSET",
		"RZ_ENDIAN",
		"RZ_BIN_DEMANGLE",
		"RZ_BIN_LANG",
		"RZ_BIN_PDBSERVER",
		"RZ_IOVA",
		"RZ_COLOR",
		"RZ_BSIZE",
		"RZ_DEBUG",
		"RZ_CONFIG"
	};
	const char *envvals[] = {
		file_path,
		file_size,
		asm_arch,
		asm_bits,
		core_offset,
		endian,
		bin_demangle,
		bin_lang,
		pdb_server,
		io_va,
		scr_color,
		block_size,
		cfg_debug,
		cfg_path ? cfg_path : ""
	};

	RzList *alloc = rz_list_newf(free);
	if (!alloc) {
		RZ_LOG_ERROR("Cannot allocate list of allocated strings.\n");
		free(cfg_path);
		return false;
	}

	const char **args = RZ_NEWS0(const char *, argc);
	if (!args) {
		RZ_LOG_ERROR("Cannot allocate list of args.\n");
		rz_list_free(alloc);
		free(cfg_path);
		return false;
	}

	if (!rz_subprocess_init()) {
		RZ_LOG_ERROR("Cannot initialize subprocess.\n");
		rz_list_free(alloc);
		free(cfg_path);
		free(args);
		return false;
	}

	for (int i = 0; i < argc; ++i) {
		args[i] = system_apply_env_var("${RZ_FILE}" /*         */, file_path /*   */, argv[i], alloc);
		args[i] = system_apply_env_var("${RZ_SIZE}" /*         */, file_size /*   */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_ARCH}" /*         */, asm_arch /*    */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_BITS}" /*         */, asm_bits /*    */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_OFFSET}" /*       */, core_offset /* */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_ENDIAN}" /*       */, endian /*      */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_BIN_DEMANGLE}" /* */, bin_demangle /**/, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_BIN_LANG}" /*     */, bin_lang /*    */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_BIN_PDBSERVER}" /**/, pdb_server /*  */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_IOVA}" /*         */, io_va /*       */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_COLOR}" /*        */, scr_color /*   */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_BSIZE}" /*        */, block_size /*  */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_DEBUG}" /*        */, cfg_debug /*   */, args[i], alloc);
		args[i] = system_apply_env_var("${RZ_CONFIG}" /*       */, cfg_path /*    */, args[i], alloc);
	}

	RzSubprocessOpt opt = {
		.file = args[0],
		.args = &args[1],
		.args_size = argc - 1,
		.envvars = envvars,
		.envvals = envvals,
		.env_size = RZ_ARRAY_SIZE(envvars),
		.stdin_pipe = RZ_SUBPROCESS_PIPE_NONE,
		.stdout_pipe = output ? RZ_SUBPROCESS_PIPE_CREATE : RZ_SUBPROCESS_PIPE_NONE,
		.stderr_pipe = output ? RZ_SUBPROCESS_PIPE_STDOUT : RZ_SUBPROCESS_PIPE_NONE,
	};

	RzSubprocess *proc = rz_subprocess_start_opt(&opt);
	if (!proc) {
		RZ_LOG_ERROR("Cannot start subprocess.\n");
		rz_subprocess_fini();
		free(cfg_path);
		rz_list_free(alloc);
		free(args);
		return false;
	}

	rz_subprocess_wait(proc, UT64_MAX);
	int ret = rz_subprocess_ret(proc);

	if (output) {
		*output = rz_subprocess_out(proc);
	}

	rz_subprocess_free(proc);
	rz_subprocess_fini();
	rz_list_free(alloc);
	free(cfg_path);
	free(args);

	return ret >= 0;
}

RZ_IPI RzCmdStatus rz_system_handler(RzCore *core, int argc, const char **argv) {
	void *bed = rz_cons_sleep_begin();
	bool ret = system_exec(core, argc - 1, &argv[1], NULL);
	rz_cons_sleep_end(bed);

	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_system_to_cons_handler(RzCore *core, int argc, const char **argv) {
	char *out = NULL;

	void *bed = rz_cons_sleep_begin();
	bool ret = system_exec(core, argc - 1, &argv[1], &out);
	rz_cons_sleep_end(bed);

	rz_cons_print(out);
	free(out);

	return ret ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}
