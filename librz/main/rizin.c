// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define USE_THREADS       1
#define ALLOW_THREADED    0
#define UNCOLORIZE_NONTTY 0

#include <rz_core.h>
#include <rz_demangler.h>
#include <rz_project.h>
#include <rz_flirt.h>
#include <rz_socket.h>

static bool is_valid_gdb_file(RzCoreFile *fh) {
	RzIODesc *d = fh && fh->core ? rz_io_desc_get(fh->core->io, fh->fd) : NULL;
	return d && strncmp(d->name, "gdb://", 6);
}

static bool is_valid_dmp_file(RzCoreFile *fh) {
	RzIODesc *d = fh && fh->core ? rz_io_desc_get(fh->core->io, fh->fd) : NULL;
	return d && strncmp(d->name, "dmp://", 6);
}

static char *get_file_in_cur_dir(const char *filepath) {
	filepath = rz_file_basename(filepath);
	if (rz_file_exists(filepath) && !rz_file_is_directory(filepath)) {
		return rz_file_abspath(filepath);
	}
	return NULL;
}

static int rz_main_version_verify(int show) {
	int i, ret;
	typedef const char *(*vc)();
	const char *base = RZ_VERSION;
	struct vcs_t {
		const char *name;
		vc callback;
	} vcs[] = {
		{ "rz_lib", rz_lib_version },
		{ "rz_egg", rz_egg_version },
		{ "rz_arch", rz_arch_version },
		{ "rz_bin", rz_bin_version },
		{ "rz_cons", rz_cons_version },
		{ "rz_flag", rz_flag_version },
		{ "rz_core", rz_core_version },
		{ "rz_crypto", rz_crypto_version },
		{ "rz_bp", rz_bp_version },
		{ "rz_debug", rz_debug_version },
		{ "rz_main", rz_main_version },
		{ "rz_hash", rz_hash_version },
		{ "rz_io", rz_io_version },
#if !USE_LIB_MAGIC
		{ "rz_magic", rz_magic_version },
#endif
		{ "rz_reg", rz_reg_version },
		{ "rz_sign", rz_sign_version },
		{ "rz_search", rz_search_version },
		{ "rz_syscall", rz_syscall_version },
		{ "rz_util", rz_util_version },
		{ "rz_diff", rz_diff_version },
		{ "rz_demangler", rz_demangler_version },
		/* ... */
		{ NULL, NULL }
	};

	if (show) {
		printf("%s  rizin\n", base);
	}
	for (i = ret = 0; vcs[i].name; i++) {
		struct vcs_t *v = &vcs[i];
		const char *name = v->callback();
		if (!ret && strcmp(base, name)) {
			ret = 1;
		}
		if (show) {
			printf("%s  %s\n", name, v->name);
		}
	}
	if (ret) {
		if (show) {
			eprintf("WARNING: rizin library versions mismatch!\n");
		} else {
			eprintf("WARNING: rizin library versions mismatch! See rizin -V\n");
		}
	}
	return ret;
}

static int main_help(int line) {

	if (line < 2) {
		printf("%s%s", Color_CYAN, "Usage: ");
		printf(Color_RESET "rizin [-ACdfLMnNqStuvwzX] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]\n"
				   "             [-s addr] [-B baddr] [-m maddr] [-c cmd] [-e k=v] file|pid|-|--|=\n");
	}
	if (line != 1) {
		const char *options[] = {
			// clang-format off
			"--",          "",          "Run rizin without opening any file",
			"=",           "",          "Same as 'rizin malloc://512",
			"- ",          "",          "Read file from stdin",
			"-=",          "",          "Perform R=! command to run all commands remotely",
			"-0",          "",          "Print \\x00 after init and every command",
			"-2",          "",          "Close stderr file descriptor (silent warning messages)",
			"-a",          "[arch]",    "Set asm.arch",
			"-A",          "",          "Run 'aaa' command to analyze all referenced code",
			"-b",          "[bits]",    "Set asm.bits",
			"-B",          "[baddr]",   "Set base address for PIE binaries",
			"-c 'cmd..'",  "",          "Execute rizin command",
			"-C",          "",          "File is host:port (alias for -cR+http://%%s/cmd/)",
			"-d",          "",          "Debug the executable 'file' or running process 'pid",
			"-D",          "[backend]", "Enable debug mode (e cfg.debug=true)",
			"-e k=v",      "",          "Evaluate config var",
			"-f",          "",          "Block size = file size",
			"-F",          "[binplug]", "Force to use that rbin plugin",
			"-h, -hh",     "",          "Show help message, -hh for long",
			"-H",          "([var])",   "Display variable",
			"-i",          "[file]",    "Run script file",
			"-I",          "[file]",    "Run script file before the file is opened",
			"-k",          "[OS/kern]", "Set asm.os (linux, macos, w32, netbsd, ...)",
			"-l",          "[lib]",     "Load plugin file",
			"-L",          "",          "List supported IO plugins",
			"-m",          "[addr]",    "Map file at given address (loadaddr)",
			"-M",          "",          "Do not demangle symbol names",
			"-n, -nn",     "",          "Do not load RzBin info (-nn only load bin structures)",
			"-N",          "",          "Do not load user settings and scripts",
			"-NN",         "",          "Do not load any script or plugin",
			"-q",          "",          "Quiet mode (no prompt) and quit after -i and -c",
			"-qq",         "",          "Quiet mode (no prompt) and force quit",
			"-p",          "[p.rzdb]",  "Load project file",
			"-r",          "[rz-run]",  "Specify rz-run profile to load (same as -e dbg.profile=X)",
			"-R",          "[rule]",    "Specify custom rz-run directive",
			"-s",          "[addr]",    "Initial seek",
		#if USE_THREADS && ALLOW_THREADED
			"-t",          "",          "load rz-bin info in thread",
		#endif
			"-T",          "",          "Do not compute file hashes",
			"-u",          "",          "Set bin.filter=false to get raw sym/sec/cls names",
			"-v, -V",      "",          "Show rizin version (-V show lib versions)",
			"-w",          "",          "Open file in write mode",
			"-x",          "",          "Open without exec-flag (asm.emu will not work), See io.exec",
			"-X",          "",          "Same as -e bin.usextr=false (useful for dyldcache)",
			"-z, -zz",     "",          "Do not load strings or load them even in raw",
			// clang-format on
		};
		size_t maxOptionAndArgLength = 0;
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			size_t optionLength = strlen(options[i]);
			size_t argLength = strlen(options[i + 1]);
			size_t totalLength = optionLength + argLength;
			if (totalLength > maxOptionAndArgLength) {
				maxOptionAndArgLength = totalLength;
			}
		}
		for (int i = 0; i < sizeof(options) / sizeof(options[0]); i += 3) {
			if (i + 1 < sizeof(options) / sizeof(options[0])) {
				rz_print_colored_help_option(options[i], options[i + 1], options[i + 2], maxOptionAndArgLength);
			}
		}
	}
	if (line == 2) {
		char *datahome = rz_path_home_prefix(RZ_DATADIR);
		char *incdir = rz_path_incdir();
		char *libdir = rz_path_libdir();
		char *home_rc = rz_path_home_rc();
		char *home_config_rc = rz_path_home_config_rc();
		char *home_config_rcdir = rz_path_home_config_rcdir();
		char *system_rc = rz_path_system_rc();
		char *binrc_dir = rz_path_home_prefix(RZ_BINRC);
		char *binrc = rz_file_path_join(binrc_dir, "bin-<format>");
		char *system_magic = rz_path_system(RZ_SDB_MAGIC);
		char *home_plugins = rz_path_home_prefix(RZ_PLUGINS);
		char *system_plugins = rz_path_system(RZ_PLUGINS);
		char *extra_plugins = rz_path_extra(RZ_PLUGINS);
		char *system_sigdb = rz_path_system(RZ_SIGDB);
		char *extra_sigdb = rz_path_extra(RZ_SIGDB);
		char *dirPrefix = rz_path_prefix(NULL);
		char *extra_prefix = rz_path_extra(NULL);
		// clang-format off
		printf(
			"Scripts:\n"
			" system       %s\n"
			" user         %s %s (and %s)\n"
			" file         ${filename}.rz\n"
			"Plugins:\n"
			" binrc            %s (elf, elf64, mach0, ..)\n"
			" RZ_USER_PLUGINS  %s\n"
			" RZ_LIB_PLUGINS   %s\n"
			" RZ_EXTRA_PLUGINS %s\n"
			"Environment:\n"
			" _NT_DEBUGGER_EXTENSION_PATH  path(s) to debugger extension DLLs\n"
			" ALACRITTY_LOG                alacritty log file's path\n"
			" ANSICON                      ansicon's W & H of the buffer and w & h of the window in the form of: \"WxH (wxh)\"\n"
			" CC                           compiler's name or path\n"
			" DEBUGINFOD_URLS              e bin.dbginfo.debuginfod_urls - use alternative debuginfod server\n"
			" COLORTERM                    extra color capabilities for a terminal\n"
			" COLUMNS                      terminal columns to use\n"
			" LD_LIBRARY_PATH              path(s) to search for shared libraries at run time\n"
			" LIBRARY_PATH                 path(s) to search for static and shared libraries at compile time\n"
			" PATH                         path(s) with executables\n"
			" RZ_CURL                      whether to use curl (for SSL support)\n"
			" RZ_DEBUG                     if defined, show error messages and crash signal\n"
			" RZ_DEBUG_ASSERT=1            set a breakpoint when hitting an assert\n"
			" RZ_DEBUG_TOOL=gdb            debug tool to use when showing error messages and crash signal\n"
			" RZ_DYLDCACHE_FILTER          dyld cache filter (MacOS dynamic libraries location(s) at runtime)\n"
			" RZ_HTTP_AUTHFILE             HTTP Authentification user file\n"
			" RZ_LOGCOLORS                 should the log output use colors\n"
			" RZ_LOGFILE                   logging output filename/path\n"
			" RZ_LOGLEVEL                  target log level/severity (0:DEBUG, 1:VERBOSE, 2:INFO, 3:WARN, 4:ERROR, 5:FATAL)\n"
			" RZ_LOGSHOWSOURCES            should the log output contain src info (filename:lineno)\n"
			" RZ_PIPE_IN                   rzpipe cmd input (file descriptor)\n"
			" RZ_PIPE_OUT                  rzpipe cmd output (file descriptor)\n"
			" RZ_MAGICPATH                 %s\n"
			" RZ_NOPLUGINS                 do not load rizin shared plugins\n"
			" RZ_RCFILE                    %s (user preferences, batch script)\n"
			" RZ_DATAHOME                  %s\n"
			" RZ_VERSION                   contains the current version of rizin\n"
			" SFLIBPATH                    SFLib syscall library path\n"
			" SHELL=sh                     shell to use (eg: \"sh\")\n"
			" TEMP                         Temp directory path (Windows)\n"
			" TMPDIR=/tmp                  tmp directory path (eg: /tmp)\n"
			" WT_SESSION                   check if in Windows terminal\n"
			" TERM                         terminal's type and color\n"
			"Paths:\n"
			" RZ_PREFIX       %s\n"
			" RZ_EXTRA_PREFIX %s\n"
			" RZ_INCDIR       %s\n"
			" RZ_LIBDIR       %s\n"
			" RZ_SIGDB        %s\n"
			" RZ_EXTRA_SIGDB  %s\n"
			" RZ_LIBEXT       " RZ_LIB_EXT "\n",
			system_rc,
			home_rc, home_config_rc, home_config_rcdir,
			binrc,
			home_plugins,
			system_plugins,
			rz_str_get(extra_plugins),
			system_magic,
			home_rc,
			datahome,
			dirPrefix,
			rz_str_get(extra_prefix),
			incdir,
			libdir,
			system_sigdb,
			rz_str_get(extra_sigdb));
		// clang-format on
		free(datahome);
		free(incdir);
		free(libdir);
		free(home_rc);
		free(home_config_rc);
		free(home_config_rcdir);
		free(system_rc);
		free(binrc_dir);
		free(binrc);
		free(system_magic);
		free(home_plugins);
		free(system_plugins);
		free(extra_plugins);
		free(system_sigdb);
		free(extra_sigdb);
		free(dirPrefix);
		free(extra_prefix);
	}
	return 0;
}

static int main_print_var(const char *var_name) {
	int i = 0;
	char *prefix = rz_path_prefix(NULL);
	char *extra_prefix = rz_path_extra(NULL);
	char *incdir = rz_path_incdir();
	char *libdir = rz_path_libdir();
	char *confighome = rz_path_home_config();
	char *datahome = rz_path_home_prefix(RZ_DATADIR);
	char *cachehome = rz_path_home_cache();
	char *homeplugins = rz_path_home_prefix(RZ_PLUGINS);
	char *sigdbdir = rz_path_system(RZ_SIGDB);
	char *extrasigdbdir = rz_path_extra(RZ_SIGDB);
	char *plugins = rz_path_system(RZ_PLUGINS);
	char *extraplugins = rz_path_extra(RZ_PLUGINS);
	char *magicpath = rz_path_system(RZ_SDB_MAGIC);
	const char *is_portable = RZ_IS_PORTABLE ? "1" : "0";
	struct rizin_var_t {
		const char *name;
		const char *value;
	} rz_vars[] = {
		{ "RZ_VERSION", RZ_VERSION },
		{ "RZ_PREFIX", prefix },
		{ "RZ_EXTRA_PREFIX", rz_str_get(extra_prefix) },
		{ "RZ_MAGICPATH", magicpath },
		{ "RZ_INCDIR", incdir },
		{ "RZ_LIBDIR", libdir },
		{ "RZ_SIGDB", sigdbdir },
		{ "RZ_EXTRA_SIGDB", rz_str_get(extrasigdbdir) },
		{ "RZ_LIBEXT", RZ_LIB_EXT },
		{ "RZ_CONFIGHOME", confighome },
		{ "RZ_DATAHOME", datahome },
		{ "RZ_CACHEHOME", cachehome },
		{ "RZ_LIB_PLUGINS", plugins },
		{ "RZ_EXTRA_PLUGINS", rz_str_get(extraplugins) },
		{ "RZ_USER_PLUGINS", homeplugins },
		{ "RZ_IS_PORTABLE", is_portable },
		{ NULL, NULL }
	};
	int delta = 0;
	if (var_name && strncmp(var_name, "RZ_", 3)) {
		delta = 3;
	}
	if (var_name) {
		while (rz_vars[i].name) {
			if (!strcmp(rz_vars[i].name + delta, var_name)) {
				printf("%s\n", rz_vars[i].value);
				break;
			}
			i++;
		}
	} else {
		while (rz_vars[i].name) {
			printf("%s=%s\n", rz_vars[i].name, rz_vars[i].value);
			i++;
		}
	}
	free(incdir);
	free(libdir);
	free(confighome);
	free(datahome);
	free(cachehome);
	free(homeplugins);
	free(sigdbdir);
	free(extrasigdbdir);
	free(extraplugins);
	free(plugins);
	free(magicpath);
	free(extra_prefix);
	free(prefix);
	return 0;
}

static bool run_commands(RzCore *r, RzList /*<char *>*/ *cmds, RzList /*<char *>*/ *files, bool quiet, int do_analysis) {
	RzListIter *iter;
	const char *cmdn;
	const char *file;
	int ret;
	/* -i */
	rz_list_foreach (files, iter, file) {
		if (!rz_file_exists(file)) {
			RZ_LOG_ERROR("Script '%s' not found.\n", file);
			goto beach;
		}
		ret = rz_core_run_script(r, file);
		if (ret == -2) {
			RZ_LOG_ERROR("[c] Cannot open '%s'\n", file);
		}
		if (ret < 0 || (ret == 0 && quiet)) {
			rz_cons_flush();
			return false;
		}
	}
	/* -c */
	rz_list_foreach (cmds, iter, cmdn) {
		// rz_core_cmd0 (r, cmdn);
		rz_core_cmd_lines(r, cmdn);
		rz_cons_flush();
	}
beach:
	if (quiet) {
		if (do_analysis) {
			return true;
		}
		if (cmds && !rz_list_empty(cmds)) {
			return true;
		}
		if (!rz_list_empty(files)) {
			return true;
		}
	}
	return false;
}

static bool mustSaveHistory(RzConfig *c) {
	if (!rz_config_get_i(c, "scr.histsave")) {
		return false;
	}
	if (!rz_cons_is_interactive()) {
		return false;
	}
	return true;
}

// Try to set the correct scr.color for the current terminal.
static void set_color_default(RzCore *r) {
#ifdef __WINDOWS__
	char *alacritty = rz_sys_getenv("ALACRITTY_LOG");
	if (alacritty) {
		// Despite the setting of env vars to the contrary, Alacritty on
		// Windows may not actually support >16 colors out-of-the-box
		// (https://github.com/jwilm/alacritty/issues/1662).
		// TODO: Windows 10 version check.
		rz_config_set_i(r->config, "scr.color", COLOR_MODE_16);
		free(alacritty);
		return;
	}
#endif
	char *tmp = rz_sys_getenv("COLORTERM");
	if (tmp) {
		if ((rz_str_endswith(tmp, "truecolor") || rz_str_endswith(tmp, "24bit"))) {
			rz_config_set_i(r->config, "scr.color", COLOR_MODE_16M);
		}
	} else {
		tmp = rz_sys_getenv("TERM");
		if (!tmp) {
			return;
		}
		if (rz_str_endswith(tmp, "truecolor") || rz_str_endswith(tmp, "24bit")) {
			rz_config_set_i(r->config, "scr.color", COLOR_MODE_16M);
		} else if (rz_str_endswith(tmp, "256color")) {
			rz_config_set_i(r->config, "scr.color", COLOR_MODE_256);
		} else if (!strcmp(tmp, "dumb")) {
			// Dumb terminals don't get color by default.
			rz_config_set_i(r->config, "scr.color", COLOR_MODE_DISABLED);
		}
	}
	free(tmp);
}

static bool has_file_arg(int argc, const char **argv, RzGetopt *opt) {
	return (argc >= 2 && argv[opt->ind] && strcmp(argv[opt->ind], "--")) || ((!strcmp(argv[opt->ind - 1], "--") && argv[opt->ind]));
}

RZ_API int rz_main_rizin(int argc, const char **argv) {
	RzCore *r;
	bool forcequit = false;
	bool haveRarunProfile = false;
	RzListIter *iter;
	int do_analysis = 0;
	char *cmdn, *tmp;
	RzCoreFile *fh = NULL;
	RzIODesc *iod = NULL;
	const char *prj = NULL;
	int debug = 0;
	int zflag = 0;
	bool do_connect = false;
	bool fullfile = false;
	bool zerosep = false;
	int help = 0;
	enum { LOAD_BIN_ALL,
		LOAD_BIN_NOTHING,
		LOAD_BIN_STRUCTURES_ONLY } load_bin = LOAD_BIN_ALL;
	bool run_rc = true;
	int ret, c, perms = RZ_PERM_RX;
	ut64 baddr = UT64_MAX;
	ut64 seek = UT64_MAX;
	bool do_list_io_plugins = false;
	char *file = NULL;
	char *pfile = NULL;
	const char *asmarch = NULL;
	const char *asmos = NULL;
	const char *forcebin = NULL;
	const char *asmbits = NULL;
	char *customRarunProfile = NULL;
	ut64 mapaddr = 0LL;
	bool quiet = false;
	int is_gdb = false;
	const char *s_seek = NULL;
	bool compute_hashes = true;
	RzList *cmds = rz_list_new();
	RzList *evals = rz_list_new();
	RzList *files = rz_list_new();
	RzList *prefiles = rz_list_new();
	RzCmdStateOutput state = { 0 };

#define LISTS_FREE() \
	{ \
		rz_list_free(cmds); \
		rz_list_free(evals); \
		rz_list_free(files); \
		rz_list_free(prefiles); \
	}

	bool noStderr = false;

#ifdef __UNIX
	sigset_t sigBlockMask;
	sigemptyset(&sigBlockMask);
	sigaddset(&sigBlockMask, SIGWINCH);
	rz_signal_sigmask(SIG_BLOCK, &sigBlockMask, NULL);
#endif

	rz_sys_env_init();
	// Create rz-run profile with startup environ
	char **env = rz_sys_get_environ();
	char *envprofile = rz_run_get_environ_profile(env);

	if (rz_sys_getenv_asbool("RZ_DEBUG")) {
		char *sysdbg = rz_sys_getenv("RZ_DEBUG_TOOL");
		char *fmt = (sysdbg && *sysdbg)
			? rz_str_newf("%s %%d", sysdbg)
#if __APPLE__
			: rz_str_newf("lldb -p %%d");
#else
			: rz_str_newf("gdb --pid %%d");
#endif
		rz_sys_crash_handler(fmt);
		free(fmt);
		free(sysdbg);
	}

	r = rz_core_new();
	if (!r) {
		RZ_LOG_ERROR("Cannot initialize RzCore\n");
		LISTS_FREE();
		free(envprofile);
		return 1;
	}
	r->rz_main_rizin = rz_main_rizin;
	r->rz_main_rz_diff = rz_main_rz_diff;
	r->rz_main_rz_find = rz_main_rz_find;
	r->rz_main_rz_bin = rz_main_rz_bin;
	r->rz_main_rz_gg = rz_main_rz_gg;
	r->rz_main_rz_asm = rz_main_rz_asm;
	r->rz_main_rz_ax = rz_main_rz_ax;

	r->io->envprofile = envprofile;

	rz_core_task_sync_begin(&r->tasks);
	// HACK TO PERMIT '#!/usr/bin/rz - -i' hashbangs
	if (argc > 2 && !strcmp(argv[1], "-") && !strcmp(argv[2], "-i")) {
		argv[1] = argv[0];
		argc--;
		argv++;
	}

	// -H option without argument
	if (argc == 2 && !strcmp(argv[1], "-H")) {
		main_print_var(NULL);
		LISTS_FREE();
		return 0;
	}

	set_color_default(r);
	bool load_l = true;
	char *debugbackend = strdup("native");

	RzGetopt opt;
	rz_getopt_init(&opt, argc, argv, "=02AMCwxfF:H:hm:e:nk:NdqQs:p:b:B:a:Lui:I:l:R:r:c:D:vVSTzuXt");
	while (argc >= 2 && (c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case '-':
			RZ_LOG_ERROR("%c: invalid combinations of argument flags - %s\n", opt.opt, opt.argv[2]);
			ret = 1;
			goto beach;
			break;
		case '=':
			RZ_FREE(r->cmdremote);
			r->cmdremote = strdup("");
			break;
		case '2':
			noStderr = true;
			break;
		case '0':
			zerosep = true;
			/* implicit -q */
			rz_config_set(r->config, "scr.interactive", "false");
			rz_config_set(r->config, "scr.prompt", "false");
			rz_config_set_i(r->config, "scr.color", COLOR_MODE_DISABLED);
			quiet = true;
			break;
		case 'u':
			rz_config_set(r->config, "bin.filter", "false");
			break;
		case 'a':
			asmarch = opt.arg;
			break;
		case 'z':
			zflag++;
			break;
		case 'A':
			do_analysis += do_analysis ? 1 : 2;
			break;
		case 'b':
			asmbits = opt.arg;
			break;
		case 'B':
			baddr = rz_num_math(r->num, opt.arg);
			break;
		case 'X':
			rz_config_set(r->config, "bin.usextr", "false");
			break;
		case 'c':
			rz_list_append(cmds, (void *)opt.arg);
			break;
		case 'C':
			do_connect = true;
			break;
#if DEBUGGER
		case 'd': debug = 1; break;
#else
		case 'd':
			RZ_LOG_ERROR("Sorry. No debugger backend available.\n");
			return 1;
#endif
		case 'D': {
			debug = 2;
			free(debugbackend);
			debugbackend = strdup(opt.arg);
			RzCmdStateOutput state = { 0 };
			rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_QUIET);
			if (!strcmp(opt.arg, "?")) {
				rz_core_debug_plugins_print(r, &state);
				rz_cmd_state_output_print(&state);
				rz_cmd_state_output_fini(&state);
				rz_cons_flush();
				LISTS_FREE();
				return 0;
			}
			break;
		}
		case 'e':
			if (!strcmp(opt.arg, "q")) {
				rz_core_cmd0(r, "eq");
			} else {
				rz_config_eval(r->config, opt.arg);
				rz_list_append(evals, (void *)opt.arg);
			}
			break;
		case 'f':
			fullfile = true;
			break;
		case 'F':
			forcebin = opt.arg;
			break;
		case 'h':
			help++;
			break;
		case 'H':
			main_print_var(opt.arg);
			LISTS_FREE();
			return 0;
		case 'i':
			if (RZ_STR_ISEMPTY(opt.arg)) {
				RZ_LOG_ERROR("Cannot open empty script path\n");
				ret = 1;
				goto beach;
			}
			rz_list_append(files, (void *)opt.arg);
			break;
		case 'I':
			if (RZ_STR_ISEMPTY(opt.arg)) {
				RZ_LOG_ERROR("Cannot open empty script path\n");
				ret = 1;
				goto beach;
			}
			rz_list_append(prefiles, (void *)opt.arg);
			break;
		case 'k':
			asmos = opt.arg;
			break;
		case 'l':
			rz_lib_open(r->lib, opt.arg);
			break;
		case 'L':
			do_list_io_plugins = true;
			break;
		case 'm':
			mapaddr = rz_num_math(r->num, opt.arg);
			s_seek = opt.arg;
			rz_config_set_i(r->config, "file.offset", mapaddr);
			break;
		case 'M':
			rz_config_set(r->config, "bin.demangle", "false");
			rz_config_set(r->config, "asm.demangle", "false");
			break;
		case 'n':
			if (load_bin == LOAD_BIN_ALL) { // "-n"
				load_bin = LOAD_BIN_NOTHING;
			} else if (load_bin == LOAD_BIN_NOTHING) { // second n => "-nn"
				load_bin = LOAD_BIN_STRUCTURES_ONLY;
			}
			rz_config_set(r->config, "file.info", "false");
			break;
		case 'N':
			if (run_rc) {
				run_rc = false;
			} else {
				load_l = false;
			}
			break;
		case 'p':
			prj = *opt.arg ? opt.arg : NULL;
			break;
		case 'q':
			rz_config_set(r->config, "scr.interactive", "false");
			rz_config_set(r->config, "scr.prompt", "false");
			rz_config_set(r->config, "cfg.fortunes", "false");
			if (quiet) {
				forcequit = true;
			}
			quiet = true;
			break;
		case 'r':
			if (RZ_STR_ISEMPTY(opt.arg)) {
				RZ_LOG_ERROR("Cannot open empty rz-run profile path\n");
				ret = 1;
				goto beach;
			}
			haveRarunProfile = true;
			rz_config_set(r->config, "dbg.profile", opt.arg);
			break;
		case 'R':
			customRarunProfile = rz_str_appendf(customRarunProfile, "%s\n", opt.arg);
			break;
		case 's':
			s_seek = opt.arg;
			break;
#if USE_THREADS
		case 't':
#if ALLOW_THREADED
			threaded = true;
#else
			eprintf("WARNING: -t is temporarily disabled!\n");
#endif
			break;
#endif
		case 'T':
			compute_hashes = false;
			break;
		case 'v':
			if (quiet) {
				printf("%s\n", RZ_VERSION);
				LISTS_FREE();
				RZ_FREE(debugbackend);
				free(customRarunProfile);
				return 0;
			} else {
				rz_main_version_verify(0);
				LISTS_FREE();
				RZ_FREE(debugbackend);
				free(customRarunProfile);
				return rz_main_version_print("rizin");
			}
		case 'V':
			return rz_main_version_verify(1);
		case 'w':
			perms |= RZ_PERM_W;
			break;
		case 'x':
			perms &= ~RZ_PERM_X;
			rz_config_set(r->config, "io.exec", "false");
			break;
		default:
			help++;
		}
	}
	if (noStderr) {
		if (-1 == close(2)) {
			RZ_LOG_ERROR("Failed to close stderr\n");
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		const char nul[] = RZ_SYS_DEVNULL;
		int new_stderr = open(nul, O_RDWR);
		if (-1 == new_stderr) {
			RZ_LOG_ERROR("Failed to open %s\n", nul);
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		if (2 != new_stderr) {
			if (-1 == dup2(new_stderr, 2)) {
				RZ_LOG_ERROR("Failed to dup2 stderr\n");
				LISTS_FREE();
				RZ_FREE(debugbackend);
				return 1;
			}
			if (-1 == close(new_stderr)) {
				RZ_LOG_ERROR("Failed to close %s\n", nul);
				LISTS_FREE();
				RZ_FREE(debugbackend);
				return 1;
			}
		}
	}
	{
		const char *dbg_profile = rz_config_get(r->config, "dbg.profile");
		if (dbg_profile && *dbg_profile) {
			char *msg = rz_file_slurp(dbg_profile, NULL);
			if (msg) {
				char *program = strstr(msg, "program=");
				if (program) {
					program += 8;
					char *p = 0;
					p = strstr(program, "\r\n");
					if (!p) {
						p = strchr(program, '\n');
					}
					if (p) {
						*p = 0;
						pfile = strdup(program);
					}
				}
				free(msg);
			} else {
				eprintf("Cannot read dbg.profile '%s'\n", dbg_profile);
				pfile = NULL; // strdup ("");
			}
		} else {
			pfile = argv[opt.ind] ? strdup(argv[opt.ind]) : NULL;
		}
	}

	if (pfile && !*pfile) {
		RZ_LOG_ERROR("Cannot open empty path\n");
		ret = 1;
		goto beach;
	}

	if (do_list_io_plugins) {
		if (rz_config_get_i(r->config, "cfg.plugins")) {
			rz_core_loadlibs(r, RZ_CORE_LOADLIBS_ALL);
		}
		run_commands(r, NULL, prefiles, false, do_analysis);
		run_commands(r, cmds, files, quiet, do_analysis);
		rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_STANDARD);
		rz_core_io_plugins_print(r->io, &state);
		rz_cmd_state_output_print(&state);
		rz_cmd_state_output_fini(&state);
		rz_cons_flush();
		LISTS_FREE();
		free(pfile);
		RZ_FREE(debugbackend);
		return 0;
	}

	if (help > 0) {
		LISTS_FREE();
		free(pfile);
		RZ_FREE(debugbackend);
		return main_help(help > 1 ? 2 : 0);
	}
	if (customRarunProfile) {
		char *tfn = rz_file_temp(".rz-run");
		if (!rz_file_dump(tfn, (const ut8 *)customRarunProfile, strlen(customRarunProfile), 0)) {
			eprintf("Cannot create %s\n", tfn);
		} else {
			haveRarunProfile = true;
			rz_config_set(r->config, "dbg.profile", tfn);
		}
		free(tfn);
	}
	if (debug == 1) {
		if (opt.ind >= argc && !haveRarunProfile) {
			RZ_LOG_ERROR("Missing argument for -d\n");
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		const char *src = haveRarunProfile ? pfile : argv[opt.ind];
		if (src && *src) {
			char *uri = strdup(src);
			if (uri) {
				char *p = strstr(uri, "://");
				if (p) {
					*p = 0;
					// TODO: this must be specified by the io plugin, not hardcoded here
					if (!strcmp(uri, "winedbg")) {
						debugbackend = strdup("io");
					} else {
						debugbackend = uri;
						uri = NULL;
					}
					debug = 2;
				}
				free(uri);
			}
		}
	}

	tmp = NULL;
	if (!load_l || (tmp = rz_sys_getenv("RZ_NOPLUGINS"))) {
		rz_config_set_i(r->config, "cfg.plugins", 0);
		free(tmp);
	}
	if (rz_config_get_i(r->config, "cfg.plugins")) {
		rz_core_loadlibs(r, RZ_CORE_LOADLIBS_ALL);
	}
	run_commands(r, NULL, prefiles, false, do_analysis);
	rz_list_free(prefiles);
	prefiles = NULL;

	rz_bin_force_plugin(r->bin, forcebin);

	if (prj) {
		rz_core_project_load_for_cli(r, prj, !pfile);
	}

	if (do_connect) {
		const char *uri = argv[opt.ind];
		if (opt.ind >= argc) {
			RZ_LOG_ERROR("Missing URI for -C\n");
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		if (strstr(uri, "://")) {
			rz_core_rtr_add(r, uri);
		} else {
			argv[opt.ind] = rz_str_newf("http://%s/cmd/", argv[opt.ind]);
			rz_core_rtr_add(r, argv[opt.ind]);
		}
		rz_core_rtr_enable(r, "0");
		argv[opt.ind] = "-";
	}

	switch (zflag) {
	case 1:
		rz_config_set(r->config, "bin.strings", "false");
		break;
	default:
		break;
	}
	if (zflag > 3) {
		eprintf("Sleeping now...\n");
		rz_sys_sleep(zflag);
	}

	if (run_rc) {
		rz_core_parse_rizinrc(r);
	} else {
		rz_config_set(r->config, "scr.utf8", "false");
	}

	if (pfile && rz_file_is_directory(pfile)) {
		if (debug) {
			RZ_LOG_ERROR("Error: Cannot debug directories, yet.\n");
			LISTS_FREE();
			free(pfile);
			RZ_FREE(debugbackend);
			return 1;
		}
		if (rz_sys_chdir(argv[opt.ind])) {
			RZ_LOG_ERROR("[d] Cannot open directory\n");
			LISTS_FREE();
			free(pfile);
			RZ_FREE(debugbackend);
			return 1;
		}
	} else if (argv[opt.ind] && !strcmp(argv[opt.ind], "-")) {
		int sz;
#if __WINDOWS__
		int result = _setmode(_fileno(stdin), _O_BINARY);
		if (result == -1) {
			RZ_LOG_ERROR("Cannot set stdin to binary mode\n");
			return 1;
		}
#endif
		/* stdin/batch mode */
		char *buf = rz_stdin_slurp(&sz);
		eprintf("^D\n");
#if __WINDOWS__
		const char *con_dev = "CON";
#else
		const char *con_dev = "/dev/tty";
#endif
		ut64 scr_color = rz_config_get_i(r->config, "scr.color");
		const char *scr_interactive = rz_config_get(r->config, "scr.interactive");
		while (rz_cons_free())
			;
		rz_xfreopen(con_dev, "r", stdin);
		rz_cons_new();
		rz_config_set_i(r->config, "scr.color", scr_color);
		rz_config_set(r->config, "scr.interactive", scr_interactive);
		if (buf && sz > 0) {
			char *path = rz_str_newf("malloc://%d", sz);
			fh = rz_core_file_open(r, path, perms, mapaddr);
			if (!fh) {
				rz_cons_flush();
				free(buf);
				RZ_LOG_ERROR("[=] Cannot open '%s'\n", path);
				LISTS_FREE();
				free(path);
				return 1;
			}
			rz_io_map_new(r->io, fh->fd, 7, 0LL, mapaddr,
				rz_io_fd_size(r->io, fh->fd));
			rz_io_write_at(r->io, mapaddr, (const ut8 *)buf, sz);
			rz_core_block_read(r);
			free(buf);
			free(path);
			// TODO: load rbin thing
		} else {
			RZ_LOG_ERROR("Cannot slurp from stdin\n");
			free(buf);
			LISTS_FREE();
			return 1;
		}
	} else if (has_file_arg(argc, argv, &opt)) {
		if (debug) {
			if (asmbits) {
				rz_config_set(r->config, "asm.bits", asmbits);
			}
			rz_config_set(r->config, "search.in", "dbg.map"); // implicit?
			rz_config_set(r->config, "cfg.debug", "true");
			perms = RZ_PERM_RWX;
			if (opt.ind >= argc) {
				RZ_LOG_ERROR("No program given to -d\n");
				LISTS_FREE();
				RZ_FREE(debugbackend);
				return 1;
			}
			if (debug == 2) {
				// autodetect backend with -D
				if (strcmp(debugbackend, "dmp")) {
					rz_config_set(r->config, "dbg.backend", debugbackend);
				}
				if (strcmp(debugbackend, "native")) {
					if (!haveRarunProfile) {
						pfile = strdup(argv[opt.ind++]);
					}
					// If plugin is winkd we should keep RWX permission to be able to write to the fd
					if (strcmp(debugbackend, "winkd")) {
						perms = RZ_PERM_RX; // XXX. should work with rw too
					}
					if (!strstr(pfile, "://")) {
						opt.ind--; // take filename
					}
					fh = rz_core_file_open(r, pfile, perms, mapaddr);
					iod = (r->io && fh) ? rz_io_desc_get(r->io, fh->fd) : NULL;
					if (!strcmp(debugbackend, "gdb") || !strcmp(debugbackend, "dmp")) {
						const char *filepath = rz_config_get(r->config, "dbg.exe.path");
						ut64 addr = baddr;
						if (addr == UINT64_MAX) {
							addr = rz_config_get_i(r->config, "bin.baddr");
						}
						if (RZ_STR_ISNOTEMPTY(filepath) && rz_file_exists(filepath) && !rz_file_is_directory(filepath)) {
							char *newpath = rz_file_abspath(filepath);
							if (newpath) {
								if (iod) {
									free(iod->name);
									iod->name = newpath;
								}
								if (addr == UINT64_MAX) {
									addr = rz_debug_get_baddr(r->dbg, newpath);
								}
								rz_core_bin_load(r, NULL, addr);
							}
						} else if (is_valid_gdb_file(fh) || is_valid_dmp_file(fh)) {
							filepath = iod->name;
							if (RZ_STR_ISNOTEMPTY(filepath) && rz_file_exists(filepath) && !rz_file_is_directory(filepath)) {
								if (addr == UINT64_MAX) {
									addr = rz_debug_get_baddr(r->dbg, filepath);
								}
								rz_core_bin_load(r, filepath, addr);
							} else if ((filepath = get_file_in_cur_dir(filepath))) {
								// Present in local directory
								if (iod) {
									free(iod->name);
									iod->name = (char *)filepath;
								}
								if (addr == UINT64_MAX) {
									addr = rz_debug_get_baddr(r->dbg, filepath);
								}
								rz_core_bin_load(r, NULL, addr);
							}
						}
					}
				}
			} else {
				const char *f = (haveRarunProfile && pfile) ? pfile : argv[opt.ind];
				is_gdb = (!memcmp(f, "gdb://", RZ_MIN(f ? strlen(f) : 0, 6)));
				if (!is_gdb) {
					pfile = strdup("dbg://");
				}
#if __UNIX__
				/* implicit ./ to make unix behave like windows */
				if (f) {
					char *path, *escaped_path;
					if (strchr(f, '/')) {
						// f is a path
						path = strdup(f);
					} else {
						// f is a filename
						if (rz_file_exists(f)) {
							path = rz_str_prepend(strdup(f), "./");
						} else {
							path = rz_file_path(f);
						}
					}
					escaped_path = rz_str_arg_escape(path);
					pfile = rz_str_append(pfile, escaped_path);
					file = pfile; // probably leaks
					RZ_FREE(escaped_path);
					RZ_FREE(path);
				}
#else
				if (f) {
					char *escaped_path = rz_str_arg_escape(f);
					pfile = rz_str_append(pfile, escaped_path);
					free(escaped_path);
					file = pfile; // rz_str_append (file, escaped_path);
				}
#endif
				opt.ind++;
				while (opt.ind < argc) {
					char *escaped_arg = rz_str_arg_escape(argv[opt.ind]);
					file = rz_str_append(file, " ");
					file = rz_str_append(file, escaped_arg);
					free(escaped_arg);
					opt.ind++;
				}
				pfile = file;
			}
		}
		if (asmarch) {
			rz_config_set(r->config, "asm.arch", asmarch);
		}
		if (asmbits) {
			rz_config_set(r->config, "asm.bits", asmbits);
		}
		if (asmos) {
			rz_config_set(r->config, "asm.os", asmos);
		}

		if (!debug || debug == 2) {
			const char *dbg_profile = rz_config_get(r->config, "dbg.profile");
			if (opt.ind == argc && dbg_profile && *dbg_profile) {
				if (RZ_STR_ISEMPTY(pfile)) {
					RZ_LOG_ERROR("Missing file to open\n");
					ret = 1;
					RZ_FREE(debugbackend);
					goto beach;
				}
				fh = rz_core_file_open(r, pfile, perms, mapaddr);
				if (fh) {
					rz_core_bin_load(r, pfile, baddr);
				}
			}
			if (opt.ind < argc) {
				RZ_FREE(pfile);
				while (opt.ind < argc) {
					pfile = strdup(argv[opt.ind++]);
					fh = rz_core_file_open(r, pfile, perms, mapaddr);
					if (!fh && perms & RZ_PERM_W) {
						perms |= RZ_PERM_CREAT;
						fh = rz_core_file_open(r, pfile, perms, mapaddr);
					}
					if (perms & RZ_PERM_CREAT) {
						if (fh) {
							rz_config_set_i(r->config, "io.va", false);
						} else {
							eprintf("rz_io_create: Permission denied.\n");
						}
					}
					if (fh) {
						iod = r->io ? rz_io_desc_get(r->io, fh->fd) : NULL;
						if (iod && perms & RZ_PERM_X) {
							iod->perm |= RZ_PERM_X;
						}
						if (load_bin == LOAD_BIN_ALL) {
							const char *filepath = NULL;
							if (debug) {
								// XXX: incorrect for PIE binaries
								filepath = file ? strstr(file, "://") : NULL;
								filepath = filepath ? filepath + 3 : pfile;
							}
							if (r->file && iod && (iod->fd == r->file->fd) && iod->name) {
								filepath = iod->name;
							}
							/* Load rbin info from rz dbg:// or rz /bin/ls */
							/* the baddr should be set manually here */
							(void)rz_core_bin_load(r, filepath, baddr);
							// check if bin info is loaded and complain if -B was used
							RzBinFile *bi = rz_bin_cur(r->bin);
							bool haveBinInfo = bi && bi->o && bi->o->info && bi->o->info->type;
							if (!haveBinInfo && baddr != UT64_MAX) {
								eprintf("Warning: Don't use -B on unknown files. Consider using -m.\n");
							}
						} else {
							rz_io_map_new(r->io, iod->fd, perms, 0LL, mapaddr, rz_io_desc_size(iod));
							if (load_bin == LOAD_BIN_STRUCTURES_ONLY) {
								rz_core_bin_load_structs(r, iod->name);
							}
						}
					}
				}
			} else {
				if (fh) {
					iod = r->io ? rz_io_desc_get(r->io, fh->fd) : NULL;
					if (iod) {
						perms = iod->perm;
						rz_io_map_new(r->io, iod->fd, perms, 0LL, 0LL, rz_io_desc_size(iod));
					}
				}
			}
			if (mapaddr) {
				if (rz_config_get_i(r->config, "file.info")) {
					int fd = rz_io_fd_get_current(r->io);
					RzIODesc *desc = rz_io_desc_get(r->io, fd);
					if (desc) {
						RzBinOptions opt;
						opt.sz = 1024 * 1024 * 1;
						rz_core_bin_options_init(r, &opt, desc->fd, mapaddr, 0);
						RzBinFile *bf = rz_bin_open_io(r->bin, &opt);
						rz_core_bin_apply_all_info(r, bf);
					}
				}
			}
		} else {
			RzCoreFile *f = rz_core_file_open(r, pfile, perms, mapaddr);
			if (f) {
				fh = f;
			}
			if (fh) {
				rz_debug_use(r->dbg, is_gdb ? "gdb" : debugbackend);
			}
			/* load symbols when doing rz -d ls */
			// NOTE: the baddr is redefined to support PIE/ASLR
			baddr = rz_debug_get_baddr(r->dbg, pfile);

			if (baddr != UT64_MAX && baddr != 0 && r->dbg->verbose) {
				eprintf("bin.baddr 0x%08" PFMT64x "\n", baddr);
			}
			if (load_bin == LOAD_BIN_ALL) {
				if (baddr && baddr != UT64_MAX && r->dbg->verbose) {
					eprintf("Using 0x%" PFMT64x "\n", baddr);
				}
				if (rz_core_bin_load(r, pfile, baddr)) {
					RzBinObject *obj = rz_bin_cur_object(r->bin);
					if (obj && obj->info) {
						if (r->dbg->verbose) {
							eprintf("asm.bits %d\n", obj->info->bits);
						}
#if __linux__ && __GNU_LIBRARY__ && __GLIBC__ && __GLIBC_MINOR__ && __x86_64__
						ut64 bitness = rz_config_get_i(r->config, "asm.bits");
						if (bitness == 32) {
							eprintf("glibc.fc_offset = 0x00148\n");
							rz_config_set_i(r->config, "dbg.glibc.fc_offset", 0x00148);
						}
#endif
					}
				}
			}
			rz_core_debug_map_update_flags(r);
			// Set Thumb Mode if necessary
			RzRegItem *thumb_reg = rz_reg_get(r->dbg->reg, "thumb", RZ_REG_TYPE_ANY);
			if (thumb_reg && rz_reg_get_value(r->dbg->reg, thumb_reg)) {
				rz_config_set_i(r->config, "asm.bits", 16);
			}
			rz_cons_reset();
		}
		if (!pfile) {
			pfile = file;
		}
		if (!fh && !prj) {
			if (pfile && *pfile) {
				rz_cons_flush();
				if (perms & RZ_PERM_W) {
					RZ_LOG_ERROR("[w] Cannot open '%s' for writing.\n", pfile);
				} else {
					RZ_LOG_ERROR("[r] Cannot open '%s'\n", pfile);
				}
			} else {
				RZ_LOG_ERROR("Missing file to open\n");
			}
			ret = 1;
			goto beach;
		}
		if (!r->file) { // no given file
			ret = 1;
			goto beach;
		}
		if (r->bin->cur && r->bin->cur->o && r->bin->cur->o->info && r->bin->cur->o->info->rclass && !strcmp("fs", r->bin->cur->o->info->rclass)) {
			const char *fstype = r->bin->cur->o->info->bclass;
			rz_core_cmdf(r, "m /root %s @ 0", fstype);
		}
		// initalize io subsystem
		char *res = rz_io_system(r->io, NULL);
		if (res) {
			rz_cons_println(res);
			free(res);
		}

		iod = r->io && fh ? rz_io_desc_get(r->io, fh->fd) : NULL;
		if (mapaddr) {
			rz_core_seek(r, mapaddr, true);
		}
		rz_list_foreach (evals, iter, cmdn) {
			rz_config_eval(r->config, cmdn);
			rz_cons_flush();
		}
		if (asmarch) {
			rz_config_set(r->config, "asm.arch", asmarch);
		}
		if (asmbits) {
			rz_config_set(r->config, "asm.bits", asmbits);
		}
		if (asmos) {
			rz_config_set(r->config, "asm.os", asmos);
		}

		debug = r->file && iod && (r->file->fd == iod->fd) && iod->plugin &&
			(iod->plugin->isdbg || (debug == 2 && !strcmp(iod->plugin->name, "dmp")));
		if (debug) {
			rz_core_setup_debugger(r, debugbackend, baddr == UT64_MAX);
		}
		RZ_FREE(debugbackend);
		RzBinObject *o = rz_bin_cur_object(r->bin);
		if (!debug && o && !o->regstate) {
			RzFlagItem *fi = rz_flag_get(r->flags, "entry0");
			if (fi) {
				rz_core_seek(r, fi->offset, true);
			} else {
				if (o) {
					RzBinObject *obj = rz_bin_cur_object(r->bin);
					const RzPVector *sections = obj ? rz_bin_object_get_sections_all(obj) : NULL;
					void **iter;
					RzBinSection *s;
					rz_pvector_foreach (sections, iter) {
						s = *iter;
						if (s->perm & RZ_PERM_X) {
							ut64 addr = s->vaddr ? s->vaddr : s->paddr;
							rz_core_seek(r, addr, true);
							break;
						}
					}
				}
			}
		}
		if (o && o->info && compute_hashes) {
			// TODO: recall with limit=0 ?
			ut64 limit = rz_config_get_i(r->config, "bin.hashlimit");
			RzBinFile *bf = r->bin->cur;
			if (bf) {
				RzPVector *old_hashes = rz_bin_file_set_hashes(r->bin, rz_bin_file_compute_hashes(r->bin, bf, limit));
				rz_pvector_free(old_hashes);
			}
		}
		if (s_seek) {
			seek = rz_num_math(r->num, s_seek);
			if (seek != UT64_MAX) {
				rz_core_seek(r, seek, true);
			}
		}

		if (fullfile) {
			rz_core_block_size(r, rz_io_desc_size(iod));
		}

		rz_core_seek(r, r->offset, true); // read current block

		/* check if file.path has changed */
		if (iod && !strstr(iod->uri, "://")) {
			const char *npath;
			char *path = strdup(rz_config_get(r->config, "file.path"));
			iod = r->io ? rz_io_desc_get(r->io, fh->fd) : NULL;
			npath = rz_config_get(r->config, "file.path");
			if (!quiet && path && *path && npath && strcmp(path, npath)) {
				eprintf("WARNING: file.path change: %s => %s\n", path, npath);
			}
			free(path);
		}

		rz_list_foreach (evals, iter, cmdn) {
			rz_config_eval(r->config, cmdn);
			rz_cons_flush();
		}

		// no flagspace selected by default the beginning
		rz_flag_space_set(r->flags, NULL);
		/* load <file>.rz */
		{
			char *f = rz_str_newf("%s.rz", pfile);
			const char *uri_splitter = strstr(f, "://");
			const char *path = uri_splitter ? uri_splitter + 3 : f;
			if (rz_file_exists(path)) {
				// TODO: should 'q' unset the interactive bit?
				bool isInteractive = rz_cons_is_interactive();
				if (isInteractive && rz_cons_yesno('n', "Do you want to run the '%s' script? (y/N) ", path)) {
					rz_core_cmd_file(r, path);
				}
			}
			free(f);
		}
	} else {
		rz_core_block_read(r);

		rz_list_foreach (evals, iter, cmdn) {
			rz_config_eval(r->config, cmdn);
			rz_cons_flush();
		}
		if (asmarch) {
			rz_config_set(r->config, "asm.arch", asmarch);
		}
		if (asmbits) {
			rz_config_set(r->config, "asm.bits", asmbits);
		}
		if (asmos) {
			rz_config_set(r->config, "asm.os", asmos);
		}
	}
	{
		char *global_rc = rz_path_system_rc();
		if (rz_file_exists(global_rc)) {
			(void)rz_core_run_script(r, global_rc);
		}
		free(global_rc);
	}

	if (do_analysis > 0) {
		switch (do_analysis) {
		case 1: rz_core_perform_auto_analysis(r, RZ_CORE_ANALYSIS_SIMPLE); break;
		case 2: rz_core_perform_auto_analysis(r, RZ_CORE_ANALYSIS_DEEP); break;
		case 3: rz_core_perform_auto_analysis(r, RZ_CORE_ANALYSIS_EXPERIMENTAL); break;
		default: rz_core_cmd_show_analysis_help(r); break;
		}
		rz_cons_flush();
	}
#if UNCOLORIZE_NONTTY
#if __UNIX__
	if (!rz_cons_isatty()) {
		rz_config_set_i(r->config, "scr.color", COLOR_MODE_DISABLED);
	}
#endif
#endif
	if (fullfile) {
		rz_core_block_size(r, rz_io_desc_size(iod));
	}
	if (perms & RZ_PERM_W) {
		RzPVector *maps = rz_io_maps(r->io);
		void **it;
		rz_pvector_foreach (maps, it) {
			RzIOMap *map = *it;
			map->perm |= RZ_PERM_W;
		}
	}
	ret = run_commands(r, cmds, files, quiet, do_analysis);
	rz_list_free(cmds);
	rz_list_free(evals);
	rz_list_free(files);
	cmds = evals = files = NULL;
	if (forcequit) {
		ret = 1;
	}
	if (ret) {
		ret = 0;
		goto beach;
	}
	if (rz_config_get_i(r->config, "scr.prompt")) {
		if (run_rc && rz_config_get_i(r->config, "cfg.fortunes")) {
			rz_core_fortune_print_random(r);
			rz_cons_flush();
		}
	}
	if (quiet) {
		rz_config_set(r->config, "scr.wheel", "false");
		rz_config_set(r->config, "scr.interactive", "false");
		rz_config_set(r->config, "scr.prompt", "false");
	}
	r->num->value = 0;
	if (zerosep) {
		rz_cons_zero();
	}
	if (seek != UT64_MAX) {
		rz_core_seek(r, seek, true);
	}

	// no flagspace selected by default the beginning
	rz_flag_space_set(r->flags, NULL);
	for (;;) {
		rz_core_prompt_loop(r);
		ret = r->num->value;
		debug = rz_config_get_i(r->config, "cfg.debug");
		if (ret != -1 && rz_cons_is_interactive()) {
			char *question;
			bool no_question_debug = ret & 1;
			bool no_question_save = (ret & 2) >> 1;
			bool y_kill_debug = (ret & 4) >> 2;
			bool y_save_project = (ret & 8) >> 3;

			if (rz_core_task_running_tasks_count(&r->tasks) > 0) {
				if (rz_cons_yesno('y', "There are running background tasks. Do you want to kill them? (Y/n)")) {
					rz_core_task_break_all(&r->tasks);
					rz_core_task_join(&r->tasks, r->tasks.main_task, -1);
				} else {
					continue;
				}
			}

			prj = rz_config_get(r->config, "prj.file");
			bool compress = rz_config_get_b(r->config, "prj.compress");
			RzProjectErr prj_err = RZ_PROJECT_ERR_SUCCESS;
			if (no_question_save) {
				if (prj && *prj && y_save_project) {
					prj_err = rz_project_save_file(r, prj, compress);
				}
			} else {
				question = rz_str_newf("Do you want to save the '%s' project? (Y/n)", prj);
				if (prj && *prj && rz_cons_yesno('y', "%s", question)) {
					prj_err = rz_project_save_file(r, prj, compress);
				}
				free(question);
			}
			if (prj_err != RZ_PROJECT_ERR_SUCCESS) {
				RZ_LOG_ERROR("Failed to save project: %s\n", rz_project_err_message(prj_err));
				continue;
			}

			if (rz_config_get_i(r->config, "scr.confirmquit")) {
				if (!rz_cons_yesno('n', "Do you want to quit? (Y/n)")) {
					continue;
				}
			}

			if (debug) {
				if (no_question_debug) {
					if (rz_config_get_i(r->config, "dbg.exitkills") && y_kill_debug) {
						rz_debug_kill(r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
					}
				} else if (rz_config_get_i(r->config, "dbg.exitkills") &&
					rz_debug_can_kill(r->dbg) &&
					rz_cons_yesno('y', "Do you want to kill the process? (Y/n)")) {
					rz_debug_kill(r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
				}
			}
		} else {
			// rz_core_project_save (r, prj);
			if (debug && rz_config_get_i(r->config, "dbg.exitkills")) {
				rz_debug_kill(r->dbg, 0, false, 9); // KILL
			}
		}
		break;
	}

	if (mustSaveHistory(r->config)) {
		char *history = rz_path_home_history();
		rz_line_hist_save(r->cons->line, history);
		free(history);
	}

	/* capture return value */
	ret = r->num->value;
beach:
	if (!rz_debug_is_dead(r->dbg)) {
		if (!rz_cons_is_interactive() && rz_config_get_i(r->config, "dbg.exitkills") &&
			rz_debug_can_kill(r->dbg)) {
			rz_debug_kill(r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
		}
		// Always detach properly if still attached, even if we already killed the process,
		// otherwise there will be a zombie on macOS!
		rz_debug_detach(r->dbg, r->dbg->pid);
	}

	rz_core_task_sync_end(&r->tasks);

	// not really needed, cause rz_core_fini will close the file
	// and this fh may be come stale during the command
	// execution.
	// rz_core_file_close (r, fh);
	rz_core_free(r);
	rz_cons_set_raw(0);
	rz_cons_free();
	LISTS_FREE();
	free(debugbackend);
	RZ_FREE(pfile);
	return ret;
}
