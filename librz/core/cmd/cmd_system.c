// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

#if __WINDOWS__
#define START_ENV_CHAR "%"
#define END_ENV_CHAR   "%"
#else // __WINDOWS__
#define START_ENV_CHAR "${"
#define END_ENV_CHAR   "}"
#endif

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
		free(path);
		return NULL;
	}
	rz_config_serialize(core->config, sdb);
	sdb_sync(sdb);
	sdb_free(sdb);

	return path;
}

static const char *system_apply_env_var(const char *env, const char *value, const char *arg, char **alloc_str) {
	size_t len = strlen(arg);
	if (!strstr(arg, env)) {
		return arg;
	} else if (strlen(env) == len) {
		return value;
	}

	if (!*alloc_str) {
		*alloc_str = rz_str_dup(arg);
	}

	*alloc_str = rz_str_replace(*alloc_str, env, value, 1);
	return *alloc_str;
}

static int system_exec(RzCore *core, int argc, const char **argv, char **output, int *length, int *ret) {
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

	rz_strf(file_size, "%" PFMT64u, core->file ? rz_io_fd_size(core->io, core->file->fd) : 0);
	rz_strf(core_offset, "%" PFMT64u, core->offset);
	rz_strf(block_size, "%u", core->blocksize);

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
		rz_str_get(cfg_path)
	};

	bool success = false;

	RzList *alloc = rz_list_newf(free);
	if (!alloc) {
		RZ_LOG_ERROR("Cannot allocate list of allocated strings.\n");
		goto alloc_err;
	}

	const char **args = RZ_NEWS0(const char *, argc);
	if (!args) {
		RZ_LOG_ERROR("Cannot allocate list of args.\n");
		goto args_err;
	}

	if (!rz_subprocess_init()) {
		RZ_LOG_ERROR("Cannot initialize subprocess.\n");
		goto subprocess_err;
	}

	for (int i = 0; i < argc; ++i) {
		char *alloc_str = NULL;
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_FILE" END_ENV_CHAR, file_path, argv[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_SIZE" END_ENV_CHAR, file_size, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_ARCH" END_ENV_CHAR, asm_arch, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_BITS" END_ENV_CHAR, asm_bits, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_OFFSET" END_ENV_CHAR, core_offset, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_ENDIAN" END_ENV_CHAR, endian, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_BIN_DEMANGLE" END_ENV_CHAR, bin_demangle, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_BIN_LANG" END_ENV_CHAR, bin_lang, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_BIN_PDBSERVER" END_ENV_CHAR, pdb_server, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_IOVA" END_ENV_CHAR, io_va, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_COLOR" END_ENV_CHAR, scr_color, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_BSIZE" END_ENV_CHAR, block_size, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_DEBUG" END_ENV_CHAR, cfg_debug, args[i], &alloc_str);
		args[i] = system_apply_env_var(START_ENV_CHAR "RZ_CONFIG" END_ENV_CHAR, cfg_path, args[i], &alloc_str);
		if (alloc_str) {
			rz_list_append(alloc, alloc_str);
		}
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
		.stderr_pipe = RZ_SUBPROCESS_PIPE_NONE,
	};

	RzSubprocess *proc = rz_subprocess_start_opt(&opt);
	if (!proc) {
		RZ_LOG_ERROR("Cannot start subprocess.\n");
		goto proc_start_err;
	}

	rz_subprocess_wait(proc, UT64_MAX);
	*ret = rz_subprocess_ret(proc);

	if (output) {
		*output = (char *)rz_subprocess_out(proc, length);
	}
	success = true;

	rz_subprocess_free(proc);
proc_start_err:
	rz_subprocess_fini();
subprocess_err:
	free(args);
args_err:
	rz_list_free(alloc);
alloc_err:
	rz_file_rm(cfg_path);
	free(cfg_path);

	return success;
}

static RzCmdStatus system_common_handler(RzCore *core, bool force_rzcons, int argc, const char **argv) {
	char *out = NULL;
	int length = 0;
	void *bed = rz_cons_sleep_begin();
	bool need_rzcons = force_rzcons || core->is_pipe;
	int ret = -1;
	bool succ = system_exec(core, argc - 1, &argv[1], need_rzcons ? &out : NULL, &length, &ret);
	rz_cons_sleep_end(bed);
	if (need_rzcons) {
#if __WINDOWS__
		char *src = out;
		char *dest = src;
		char *end = out + length;
		while (src != end) {
			*dest = *src;
			if (src[0] == '\r' && src + 1 != end && src[1] == '\n') {
				// dest does not move
				length--;
			} else {
				dest++;
			}
			src++;
		}
#endif
		rz_cons_memcat(out, length);
	}
	free(out);
	core->num->value = (ut64)ret;
	return succ ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_system_handler(RzCore *core, int argc, const char **argv) {
	return system_common_handler(core, false, argc, argv);
}

RZ_IPI RzCmdStatus rz_system_to_cons_handler(RzCore *core, int argc, const char **argv) {
	return system_common_handler(core, true, argc, argv);
}

#undef START_ENV_CHAR
#undef END_ENV_CHAR
