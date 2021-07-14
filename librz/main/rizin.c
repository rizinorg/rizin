// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#define USE_THREADS       1
#define ALLOW_THREADED    0
#define UNCOLORIZE_NONTTY 0
#ifdef _MSC_VER
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <rz_core.h>
#include <rz_project.h>

static bool is_valid_gdb_file(RzCoreFile *fh) {
	RzIODesc *d = fh && fh->core ? rz_io_desc_get(fh->core->io, fh->fd) : NULL;
	return d && strncmp(d->name, "gdb://", 6);
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
		{ "rz_analysis", rz_analysis_version },
		{ "rz_lib", rz_lib_version },
		{ "rz_egg", rz_egg_version },
		{ "rz_asm", rz_asm_version },
		{ "rz_bin", rz_bin_version },
		{ "rz_cons", rz_cons_version },
		{ "rz_flag", rz_flag_version },
		{ "rz_core", rz_core_version },
		{ "rz_crypto", rz_crypto_version },
		{ "rz_bp", rz_bp_version },
		{ "rz_debug", rz_debug_version },
		{ "rz_main", rz_main_version },
		{ "rz_msg_digest", rz_msg_digest_version },
		{ "rz_io", rz_io_version },
#if !USE_LIB_MAGIC
		{ "rz_magic", rz_magic_version },
#endif
		{ "rz_parse", rz_parse_version },
		{ "rz_reg", rz_reg_version },
		{ "rz_sign", rz_sign_version },
		{ "rz_search", rz_search_version },
		{ "rz_syscall", rz_syscall_version },
		{ "rz_util", rz_util_version },
		{ "rz_diff", rz_diff_version },
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
		printf("Usage: rizin [-ACdfLMnNqStuvwzX] [-P patch] [-p prj] [-a arch] [-b bits] [-i file]\n"
		       "             [-s addr] [-B baddr] [-m maddr] [-c cmd] [-e k=v] file|pid|-|--|=\n");
	}
	if (line != 1) {
		printf(
			" --           run rizin without opening any file\n"
			" =            same as 'rizin malloc://512'\n"
			" -            read file from stdin \n"
			" -=           perform R=! command to run all commands remotely\n"
			" -0           print \\x00 after init and every command\n"
			" -2           close stderr file descriptor (silent warning messages)\n"
			" -a [arch]    set asm.arch\n"
			" -A           run 'aaa' command to analyze all referenced code\n"
			" -b [bits]    set asm.bits\n"
			" -B [baddr]   set base address for PIE binaries\n"
			" -c 'cmd..'   execute rizin command\n"
			" -C           file is host:port (alias for -cR+http://%%s/cmd/)\n"
			" -d           debug the executable 'file' or running process 'pid'\n"
			" -D [backend] enable debug mode (e cfg.debug=true)\n"
			" -e k=v       evaluate config var\n"
			" -f           block size = file size\n"
			" -F [binplug] force to use that rbin plugin\n"
			" -h, -hh      show help message, -hh for long\n"
			" -H ([var])   display variable\n"
			" -i [file]    run script file\n"
			" -I [file]    run script file before the file is opened\n"
			" -k [OS/kern] set asm.os (linux, macos, w32, netbsd, ...)\n"
			" -l [lib]     load plugin file\n"
			" -L           list supported IO plugins\n"
			" -m [addr]    map file at given address (loadaddr)\n"
			" -M           do not demangle symbol names\n"
			" -n, -nn      do not load RzBin info (-nn only load bin structures)\n"
			" -N           do not load user settings and scripts\n"
			" -NN          do not load any script or plugin\n"
			" -q           quiet mode (no prompt) and quit after -i\n"
			" -qq          quit after running all -c and -i\n"
			" -Q           quiet mode (no prompt) and quit faster (quickLeak=true)\n"
			" -p [p.rzdb]  load project file\n"
			" -r [rz-run]  specify rz-run profile to load (same as -e dbg.profile=X)\n"
			" -R [rrz_testule] specify custom rz-run directive\n"
			" -s [addr]    initial seek\n"
#if USE_THREADS && ALLOW_THREADED
			" -t           load rz-bin info in thread\n"
#endif
			" -T           do not compute file hashes\n"
			" -u           set bin.filter=false to get raw sym/sec/cls names\n"
			" -v, -V       show rizin version (-V show lib versions)\n"
			" -w           open file in write mode\n"
			" -x           open without exec-flag (asm.emu will not work), See io.exec\n"
			" -X           same as -e bin.usextr=false (useful for dyldcache)\n"
			" -z, -zz      do not load strings or load them even in raw\n");
	}
	if (line == 2) {
		char *datahome = rz_str_home(RZ_HOME_DATADIR);
		char *incdir = rz_str_rz_prefix(RZ_INCDIR);
		char *libdir = rz_str_rz_prefix(RZ_LIBDIR);
		const char *dirPrefix = rz_sys_prefix(NULL);
		printf(
			"Scripts:\n"
			" system       ${RZ_PREFIX}/share/rizin/rizinrc\n"
			" user         ~/.rizinrc " RZ_JOIN_2_PATHS("~", RZ_HOME_RC) " (and " RZ_JOIN_3_PATHS("~", RZ_HOME_RC_DIR, "") ")\n"
																       " file         ${filename}.rz\n"
																       "Plugins:\n"
																       " binrc        " RZ_JOIN_4_PATHS("~", RZ_HOME_BINRC, "bin-<format>", "") " (elf, elf64, mach0, ..)\n"
																										" RZ_USER_PLUGINS " RZ_JOIN_2_PATHS("~", RZ_HOME_PLUGINS) "\n"
																																	  " RZ_LIBR_PLUGINS " RZ_JOIN_2_PATHS("%s", RZ_PLUGINS) "\n"
																																								" RZ_USER_ZIGNS " RZ_JOIN_2_PATHS("~", RZ_HOME_ZIGNS) "\n"
																																														      "Environment:\n"
																																														      " RZ_CFG_OLDSHELL sets cfg.oldshell=true\n"
																																														      " RZ_DEBUG      if defined, show error messages and crash signal\n"
																																														      " RZ_DEBUG_ASSERT=1 set a breakpoint when hitting an assert\n"
																																														      " RZ_MAGICPATH " RZ_JOIN_2_PATHS("%s", RZ_SDB_MAGIC) "\n"
																																																					   " RZ_NOPLUGINS do not load rizin shared plugins\n"
																																																					   " RZ_RCFILE    ~/.rizinrc (user preferences, batch script)\n" // TOO GENERIC
																																																					   " RZ_RDATAHOME %s\n" // TODO: rename to RHOME RZHOME?
																																																					   " RZ_VERSION   contains the current version of rizin\n"
																																																					   "Paths:\n"
																																																					   " RZ_PREFIX    %s\n"
																																																					   " RZ_INCDIR    %s\n"
																																																					   " RZ_LIBDIR    %s\n"
																																																					   " RZ_LIBEXT    " RZ_LIB_EXT "\n",
			dirPrefix, datahome, dirPrefix, dirPrefix, incdir, libdir);
		free(libdir);
		free(incdir);
		free(datahome);
	}
	return 0;
}

static int main_print_var(const char *var_name) {
	int i = 0;
	const char *prefix = rz_sys_prefix(NULL);
	char *incdir = rz_str_rz_prefix(RZ_INCDIR);
	char *libdir = rz_str_rz_prefix(RZ_LIBDIR);
	char *confighome = rz_str_home(RZ_HOME_CONFIGDIR);
	char *datahome = rz_str_home(RZ_HOME_DATADIR);
	char *cachehome = rz_str_home(RZ_HOME_CACHEDIR);
	char *homeplugins = rz_str_home(RZ_HOME_PLUGINS);
	char *homezigns = rz_str_home(RZ_HOME_ZIGNS);
	char *plugins = rz_str_rz_prefix(RZ_PLUGINS);
	char *magicpath = rz_str_rz_prefix(RZ_SDB_MAGIC);
	const char *is_portable = RZ_IS_PORTABLE ? "1" : "0";
	struct rizin_var_t {
		const char *name;
		const char *value;
	} rz_vars[] = {
		{ "RZ_VERSION", RZ_VERSION },
		{ "RZ_PREFIX", prefix },
		{ "RZ_MAGICPATH", magicpath },
		{ "RZ_INCDIR", incdir },
		{ "RZ_LIBDIR", libdir },
		{ "RZ_LIBEXT", RZ_LIB_EXT },
		{ "RZ_RCONFIGHOME", confighome },
		{ "RZ_RDATAHOME", datahome },
		{ "RZ_RCACHEHOME", cachehome },
		{ "RZ_LIBR_PLUGINS", plugins },
		{ "RZ_USER_PLUGINS", homeplugins },
		{ "RZ_USER_ZIGNS", homezigns },
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
	free(homezigns);
	free(plugins);
	free(magicpath);
	return 0;
}

static bool run_commands(RzCore *r, RzList *cmds, RzList *files, bool quiet, int do_analysis) {
	RzListIter *iter;
	const char *cmdn;
	const char *file;
	int ret;
	/* -i */
	rz_list_foreach (files, iter, file) {
		if (!rz_file_exists(file)) {
			eprintf("Script '%s' not found.\n", file);
			goto beach;
		}
		ret = rz_core_run_script(r, file);
		if (ret == -2) {
			eprintf("[c] Cannot open '%s'\n", file);
		}
		if (ret < 0 || (ret == 0 && quiet)) {
			rz_cons_flush();
			return false;
		}
	}
	/* -c */
	rz_list_foreach (cmds, iter, cmdn) {
		//rz_core_cmd0 (r, cmdn);
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
	bool quietLeak = false;
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
		eprintf("Cannot initialize RzCore\n");
		LISTS_FREE();
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
			eprintf("%c: invalid combinations of argument flags - %s\n", opt.opt, opt.argv[2]);
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
		case 'd': eprintf("Sorry. No debugger backend available.\n"); return 1;
#endif
		case 'D': {
			debug = 2;
			free(debugbackend);
			debugbackend = strdup(opt.arg);
			RzCmdStateOutput state = { 0 };
			state.mode = RZ_OUTPUT_MODE_QUIET;
			if (!strcmp(opt.arg, "?")) {
				rz_core_debug_plugins_print(r, &state);
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
				rz_config_eval(r->config, opt.arg, false);
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
				eprintf("Cannot open empty script path\n");
				ret = 1;
				goto beach;
			}
			rz_list_append(files, (void *)opt.arg);
			break;
		case 'I':
			if (RZ_STR_ISEMPTY(opt.arg)) {
				eprintf("Cannot open empty script path\n");
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
		case 'Q':
			quiet = true;
			quietLeak = true;
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
				eprintf("Cannot open empty rz-run profile path\n");
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
			eprintf("Failed to close stderr");
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		const char nul[] = RZ_SYS_DEVNULL;
		int new_stderr = open(nul, O_RDWR);
		if (-1 == new_stderr) {
			eprintf("Failed to open %s", nul);
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		if (2 != new_stderr) {
			if (-1 == dup2(new_stderr, 2)) {
				eprintf("Failed to dup2 stderr");
				LISTS_FREE();
				RZ_FREE(debugbackend);
				return 1;
			}
			if (-1 == close(new_stderr)) {
				eprintf("Failed to close %s", nul);
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
				pfile = NULL; //strdup ("");
			}
		} else {
			pfile = argv[opt.ind] ? strdup(argv[opt.ind]) : NULL;
		}
	}

	if (pfile && !*pfile) {
		eprintf("Cannot open empty path\n");
		ret = 1;
		goto beach;
	}

	if (do_list_io_plugins) {
		if (rz_config_get_i(r->config, "cfg.plugins")) {
			rz_core_loadlibs(r, RZ_CORE_LOADLIBS_ALL, NULL);
		}
		run_commands(r, NULL, prefiles, false, do_analysis);
		run_commands(r, cmds, files, quiet, do_analysis);
		if (quietLeak) {
			exit(0);
		}
		state.mode = RZ_OUTPUT_MODE_STANDARD;
		rz_core_io_plugins_print(r->io, &state);
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
#if __WINDOWS__
	pfile = rz_acp_to_utf8(pfile);
#endif // __WINDOWS__
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
			eprintf("Missing argument for -d\n");
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
		rz_core_loadlibs(r, RZ_CORE_LOADLIBS_ALL, NULL);
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
			eprintf("Missing URI for -C\n");
			LISTS_FREE();
			RZ_FREE(debugbackend);
			return 1;
		}
		if (strstr(uri, "://")) {
			rz_core_cmdf(r, "R+ %s", uri);
		} else {
			argv[opt.ind] = rz_str_newf("http://%s/cmd/", argv[opt.ind]);
			rz_core_cmdf(r, "R+ %s", argv[opt.ind]);
		}
		rz_core_cmd0(r, "R!=");
		argv[opt.ind] = "-";
	}

	switch (zflag) {
	case 1:
		rz_config_set(r->config, "bin.strings", "false");
		break;
	case 2:
		rz_config_set(r->config, "bin.rawstr", "true");
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

	if (rz_config_get_i(r->config, "zign.autoload")) {
		char *path = rz_file_abspath(rz_config_get(r->config, "dir->zigns"));
		char *complete_path = NULL;
		RzList *list = rz_sys_dir(path);
		RzListIter *iter;
		char *file = NULL;
		rz_list_foreach (list, iter, file) {
			if (file && *file && *file != '.') {
				complete_path = rz_str_newf("%s" RZ_SYS_DIR "%s", path, file);
				if (rz_str_endswith(complete_path, "gz")) {
					rz_sign_load_gz(r->analysis, complete_path);
				} else {
					rz_sign_load(r->analysis, complete_path);
				}
				free(complete_path);
			}
		}
		rz_list_free(list);
		free(path);
	}

	if (pfile && rz_file_is_directory(pfile)) {
		if (debug) {
			eprintf("Error: Cannot debug directories, yet.\n");
			LISTS_FREE();
			free(pfile);
			RZ_FREE(debugbackend);
			return 1;
		}
		if (rz_sys_chdir(argv[opt.ind])) {
			eprintf("[d] Cannot open directory\n");
			LISTS_FREE();
			free(pfile);
			RZ_FREE(debugbackend);
			return 1;
		}
	} else if (argv[opt.ind] && !strcmp(argv[opt.ind], "-")) {
		int sz;
		/* stdin/batch mode */
		char *buf = rz_stdin_slurp(&sz);
		eprintf("^D\n");
		rz_cons_set_raw(false);
#if __UNIX__
		// TODO: keep flags :?
		rz_xfreopen("/dev/tty", "rb", stdin);
		rz_xfreopen("/dev/tty", "w", stdout);
		rz_xfreopen("/dev/tty", "w", stderr);
#else
		eprintf("Cannot reopen stdin without UNIX\n");
		free(buf);
		return 1;
#endif
		if (buf && sz > 0) {
			char *path = rz_str_newf("malloc://%d", sz);
			fh = rz_core_file_open(r, path, perms, mapaddr);
			if (!fh) {
				rz_cons_flush();
				free(buf);
				eprintf("[=] Cannot open '%s'\n", path);
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
			eprintf("Cannot slurp from stdin\n");
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
				eprintf("No program given to -d\n");
				LISTS_FREE();
				RZ_FREE(debugbackend);
				return 1;
			}
			if (debug == 2) {
				// autodetect backend with -D
				rz_config_set(r->config, "dbg.backend", debugbackend);
				if (strcmp(debugbackend, "native")) {
					if (!haveRarunProfile) {
						pfile = strdup(argv[opt.ind++]);
					}
					perms = RZ_PERM_RX; // XXX. should work with rw too
					debug = 2;
					if (!strstr(pfile, "://")) {
						opt.ind--; // take filename
					}
#if __WINDOWS__
					pfile = rz_acp_to_utf8(pfile);
#endif // __WINDOWS__
					fh = rz_core_file_open(r, pfile, perms, mapaddr);
					iod = (r->io && fh) ? rz_io_desc_get(r->io, fh->fd) : NULL;
					if (!strcmp(debugbackend, "gdb")) {
						const char *filepath = rz_config_get(r->config, "dbg.exe.path");
						ut64 addr = baddr;
						if (addr == UINT64_MAX) {
							addr = rz_config_get_i(r->config, "bin.baddr");
						}
						if (rz_file_exists(filepath) && !rz_file_is_directory(filepath)) {
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
						} else if (is_valid_gdb_file(fh)) {
							filepath = iod->name;
							if (rz_file_exists(filepath) && !rz_file_is_directory(filepath)) {
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
#if __WINDOWS__
				f = rz_acp_to_utf8(f);
#endif // __WINDOWS__
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
					eprintf("Missing file to open\n");
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
#if __WINDOWS__
					pfile = rz_acp_to_utf8(pfile);
#endif
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
					eprintf("Warning: using oba to load the syminfo from different mapaddress.\n");
					// load symbols when using rz -m 0x1000 /bin/ls
					rz_core_cmdf(r, "oba 0 0x%" PFMT64x, mapaddr);
					rz_core_cmd0(r, ".ies*");
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
			rz_core_cmd0(r, ".dm*");
			// Set Thumb Mode if necessary
			rz_core_cmd0(r, "dr? thumb;?? e asm.bits=16");
			rz_cons_reset();
		}
		if (!pfile) {
			pfile = file;
		}
		if (!fh && !prj) {
			if (pfile && *pfile) {
				rz_cons_flush();
				if (perms & RZ_PERM_W) {
					eprintf("[w] Cannot open '%s' for writing.\n", pfile);
				} else {
					eprintf("[r] Cannot open '%s'\n", pfile);
				}
			} else {
				eprintf("Missing file to open\n");
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
		rz_core_cmd0(r, "R!"); // initalize io subsystem
		iod = r->io && fh ? rz_io_desc_get(r->io, fh->fd) : NULL;
		if (mapaddr) {
			rz_core_seek(r, mapaddr, true);
		}
		rz_list_foreach (evals, iter, cmdn) {
			rz_config_eval(r->config, cmdn, false);
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
			iod->plugin->isdbg;
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
					RzList *sections = rz_bin_get_sections(r->bin);
					RzListIter *iter;
					RzBinSection *s;
					rz_list_foreach (sections, iter, s) {
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
				rz_bin_file_set_hashes(r->bin, rz_bin_file_compute_hashes(r->bin, bf, limit));
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
			rz_config_eval(r->config, cmdn, false);
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
			rz_config_eval(r->config, cmdn, false);
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
		char *global_rc = rz_str_rz_prefix(RZ_GLOBAL_RC);
		if (rz_file_exists(global_rc)) {
			(void)rz_core_run_script(r, global_rc);
		}
		free(global_rc);
	}

	// only analyze if file contains entrypoint
	{
		char *s = rz_core_cmd_str(r, "ieq");
		if (s && *s) {
			int da = rz_config_get_i(r->config, "file.analyze");
			if (da > do_analysis) {
				do_analysis = da;
			}
		}
		free(s);
	}
	if (do_analysis > 0) {
		switch (do_analysis) {
		case 1: rz_core_cmd0(r, "aa"); break;
		case 2: rz_core_cmd0(r, "aaa"); break;
		case 3: rz_core_cmd0(r, "aaaa"); break;
		default: rz_core_cmd0(r, "aaaaa"); break;
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
		rz_core_cmd0(r, "omfg+w");
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

			if (debug) {
				if (no_question_debug) {
					if (rz_config_get_i(r->config, "dbg.exitkills") && y_kill_debug) {
						rz_debug_kill(r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
					}
				} else {
					if (rz_cons_yesno('y', "Do you want to quit? (Y/n)")) {
						if (rz_config_get_i(r->config, "dbg.exitkills") &&
							rz_cons_yesno('y', "Do you want to kill the process? (Y/n)")) {
							rz_debug_kill(r->dbg, r->dbg->pid, r->dbg->tid, 9); // KILL
						} else {
							rz_debug_detach(r->dbg, r->dbg->pid);
						}
					} else {
						continue;
					}
				}
			}

			prj = rz_config_get(r->config, "prj.file");
			RzProjectErr prj_err = RZ_PROJECT_ERR_SUCCESS;
			if (no_question_save) {
				if (prj && *prj && y_save_project) {
					prj_err = rz_project_save_file(r, prj);
				}
			} else {
				question = rz_str_newf("Do you want to save the '%s' project? (Y/n)", prj);
				if (prj && *prj && rz_cons_yesno('y', "%s", question)) {
					prj_err = rz_project_save_file(r, prj);
				}
				free(question);
			}
			if (prj_err != RZ_PROJECT_ERR_SUCCESS) {
				eprintf("Failed to save project: %s\n", rz_project_err_message(prj_err));
				continue;
			}

			if (rz_config_get_i(r->config, "scr.confirmquit")) {
				if (!rz_cons_yesno('n', "Do you want to quit? (Y/n)")) {
					continue;
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
		rz_line_hist_save(RZ_HOME_HISTORY);
	}

	/* capture return value */
	ret = r->num->value;
beach:
	if (quietLeak) {
		exit(ret);
		return ret;
	}

	rz_core_task_sync_end(&r->tasks);

	// not really needed, cause rz_core_fini will close the file
	// and this fh may be come stale during the command
	// execution.
	//rz_core_file_close (r, fh);
	rz_core_free(r);
	rz_cons_set_raw(0);
	rz_cons_free();
	LISTS_FREE();
	RZ_FREE(pfile);
	return ret;
}
