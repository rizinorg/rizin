// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_demangler.h>
#include "config.h"

#define MAX_FILE_NAME_SIZE		8096		/* Temporary macros */

#define CB(x, y) \
	static int __lib_##x##_cb(RzLibPlugin *pl, void *user, void *data) { \
		struct rz_##x##_plugin_t *hand = (struct rz_##x##_plugin_t *)data; \
		RzCore *core = (RzCore *)user; \
		pl->free = NULL; \
		rz_##x##_add(core->y, hand); \
		return true; \
	} \
	static int __lib_##x##_dt(RzLibPlugin *pl, void *p, void *u) { return true; }

static int __lib_demangler_cb(RzLibPlugin *pl, void *user, void *data) {
	RzCore *core = (RzCore *)user;
	rz_demangler_plugin_add(core->bin->demangler, (RzDemanglerPlugin *)data);
	return true;
}

static int __lib_demangler_dt(RzLibPlugin *pl, void *p, void *u) {
	return true;
}

static int __lib_core_cb(RzLibPlugin *pl, void *user, void *data) {
	struct rz_core_plugin_t *hand = (struct rz_core_plugin_t *)data;
	RzCore *core = (RzCore *)user;
	pl->free = NULL;
	rz_core_plugin_add(core, hand);
	return true;
}

static int __lib_core_dt(RzLibPlugin *pl, void *p, void *u) {
	return true;
}

#define rz_io_add rz_io_plugin_add
CB(io, io)
#define rz_debug_add rz_debug_plugin_add
CB(debug, dbg)
#define rz_bp_add rz_bp_plugin_add
CB(bp, dbg->bp)
CB(lang, lang)
CB(analysis, analysis)
CB(asm, rasm)
CB(parse, parser)
#define rz_bin_add rz_bin_plugin_add
CB(bin, bin)
CB(egg, egg)

#if RZ_LOADLIBS
static void rz_core_load_plugins(RzCore *core, int where, const char *path) {
	const char *dir_plugins;
	char *p;

	if (!where)
		where = -1;
	if (path)
		rz_lib_opendir(core->lib, path);
	dir_plugins = rz_config_get(core->config, "dir.plugins");
	if (where & RZ_CORE_LOADLIBS_CONFIG)
		rz_lib_opendir(core->lib, dir_plugins);
	if (where & RZ_CORE_LOADLIBS_ENV) {
		p = rz_sys_getenv(RZ_LIB_ENV);
		if (p != NULL) {
			if (*p) {
				rz_lib_opendir(core->lib, p);
			}
			free(p);
		}
	}
	if (where & RZ_CORE_LOADLIBS_HOME) {
		p = rz_str_home(RZ_HOME_PLUGINS);
		if (p != NULL) {
			if (*p) {
				rz_lib_opendir(core->lib, p);
			}
			free(p);
		}
	}
	if (where & RZ_CORE_LOADLIBS_SYSTEM) {
#define RZ_CORE_PROC_DIR(x) \
		if (dir_plugins == NULL || !rz_str_endswith(dir_plugins, x)) { \
			snprintf (user_path, MAX_FILE_NAME_SIZE, "%s%s", RZ_SYS_DIR, x); \
			rz_lib_opendir(core->lib, user_path); \
		}
		char user_path[MAX_FILE_NAME_SIZE];
		RZ_CORE_PROC_DIR(RZ_PLUGINS);
		RZ_CORE_PROC_DIR(RZ_EXTRAS);
		RZ_CORE_PROC_DIR(RZ_BINDINGS);
	}
	return;
}

#endif

RZ_API void rz_core_loadlibs_init(RzCore *core) {
	ut64 prev = rz_time_now_mono();
#define DF(x, y, z) rz_lib_add_handler(core->lib, RZ_LIB_TYPE_##x, y, &__lib_##z##_cb, &__lib_##z##_dt, core);
	core->lib = rz_lib_new(RZ_LIB_SYMNAME, RZ_LIB_SYMFUNC);
	if (core->lib == NULL) {
		eprintf ("Failed to allocate new libs data\n");
		return;
	}
	DF(DEMANGLER, "demangler plugins", demangler);
	DF(IO, "io plugins", io);
	DF(CORE, "core plugins", core);
	DF(DBG, "debugger plugins", debug);
	DF(BP, "debugger breakpoint plugins", bp);
	DF(LANG, "language plugins", lang);
	DF(ANALYSIS, "analysis plugins", analysis);
	DF(ASM, "(dis)assembler plugins", asm);
	DF(PARSE, "parsing plugins", parse);
	DF(BIN, "bin plugins", bin);
	DF(EGG, "egg plugins", egg);
	core->times->loadlibs_init_time = rz_time_now_mono() - prev;
	return;
}

static bool __isScriptFilename(const char *name) {
	const char *ext = rz_str_lchr(name, '.');

	if (ext == NULL) {
		return false;
	}
	ext++;
	if (!strcmp(ext, "py") || !strcmp(ext, "js") || !strcmp(ext, "lua")) {
		return true;
	} else {
		return false;
	}
}

RZ_API bool rz_core_loadlibs(RzCore *core, int where, const char *path) {
	char *homeplugindir, *file;
	char script_file[MAX_FILE_NAME_SIZE];
	RzList *files;
	RzListIter *iter;
	ut64 prev;

	prev = rz_time_now_mono();
#if RZ_LOADLIBS
	rz_core_load_plugins(core, where, path);
#endif
	/* TODO: all those default plugin paths should be defined in rz_lib */
	if (!rz_config_get_i(core->config, "cfg.plugins")) {
		core->times->loadlibs_time = 0;
		return false;
	}
	homeplugindir = rz_str_home(RZ_HOME_PLUGINS);
	if (homeplugindir == NULL) {
		eprintf("Failed to alloc string %s\n", RZ_HOME_PLUGINS);
		return false;
	}

	files = rz_sys_dir(homeplugindir);
	rz_list_foreach (files, iter, file) {
		if (!__isScriptFilename(file)) {
			continue;
		}
		snprintf(script_file, MAX_FILE_NAME_SIZE, "%s/%s", homeplugindir, file);
		if (!rz_core_run_script(core, script_file)) {
			eprintf("Cannot find script '%s'\n", script_file);
		}
	}
	free(homeplugindir);
	rz_list_free(files);
	core->times->loadlibs_time = rz_time_now_mono() - prev;
	return true;
}
