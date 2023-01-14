// SPDX-FileCopyrightText: 2009-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_demangler.h>
#include "config.h"

#define CB(x, y) \
	static bool lib_##x##_cb(RzLibPlugin *pl, void *user, void *data) { \
		struct rz_##x##_plugin_t *hand = (struct rz_##x##_plugin_t *)data; \
		RzCore *core = (RzCore *)user; \
		return rz_##x##_plugin_add(core->y, hand); \
	} \
	static bool lib_##x##_dt(RzLibPlugin *pl, void *user, void *data) { \
		struct rz_##x##_plugin_t *hand = (struct rz_##x##_plugin_t *)data; \
		RzCore *core = (RzCore *)user; \
		return rz_##x##_plugin_del(core->y, hand); \
	}

static bool lib_core_cb(RzLibPlugin *pl, void *user, void *data) {
	RzCore *core = (RzCore *)user;
	return rz_core_plugin_add(core, (RzCorePlugin *)data);
}

static bool lib_core_dt(RzLibPlugin *pl, void *user, void *data) {
	RzCore *core = (RzCore *)user;
	return rz_core_plugin_del(core, (RzCorePlugin *)data);
}

CB(io, io)
CB(crypto, crypto)
CB(debug, dbg)
CB(bp, dbg->bp)
CB(lang, lang)
CB(analysis, analysis)
CB(asm, rasm)
CB(parse, parser)
CB(bin, bin)
CB(demangler, bin->demangler)
CB(egg, egg)
CB(hash, hash)

static void loadSystemPlugins(RzCore *core, int where) {
#if RZ_LOADLIBS
	const char *dir_plugins = rz_config_get(core->config, "dir.plugins");
	if (where & RZ_CORE_LOADLIBS_CONFIG) {
		rz_lib_opendir(core->lib, dir_plugins, false);
	}
	if (where & RZ_CORE_LOADLIBS_ENV) {
		char *p = rz_sys_getenv(RZ_LIB_ENV);
		if (p && *p) {
			rz_lib_opendir(core->lib, p, false);
		}
		free(p);
	}
	if (where & RZ_CORE_LOADLIBS_HOME) {
		char *hpd = rz_path_home_prefix(RZ_PLUGINS);
		rz_lib_opendir(core->lib, hpd, false);
		free(hpd);
	}
	if (where & RZ_CORE_LOADLIBS_SYSTEM) {
		char *spd = rz_path_system(RZ_PLUGINS);
		rz_lib_opendir(core->lib, spd, false);
		free(spd);
	}
#endif
}

RZ_API void rz_core_loadlibs_init(RzCore *core) {
	ut64 prev = rz_time_now_mono();
#define DF(x, y, z) rz_lib_add_handler(core->lib, RZ_LIB_TYPE_##x, y, &lib_##z##_cb, &lib_##z##_dt, core);
	core->lib = rz_lib_new(NULL, NULL);
	DF(DEMANGLER, "demangler plugins", demangler);
	DF(IO, "io plugins", io);
	DF(CORE, "core plugins", core);
	DF(CRYPTO, "crypto plugins", crypto);
	DF(DBG, "debugger plugins", debug);
	DF(BP, "debugger breakpoint plugins", bp);
	DF(LANG, "language plugins", lang);
	DF(ANALYSIS, "analysis plugins", analysis);
	DF(ASM, "(dis)assembler plugins", asm);
	DF(PARSE, "parsing plugins", parse);
	DF(BIN, "bin plugins", bin);
	DF(EGG, "egg plugins", egg);
	DF(HASH, "hash plugins", hash);
	core->times->loadlibs_init_time = rz_time_now_mono() - prev;
}

static bool __isScriptFilename(const char *name) {
	const char *ext = rz_str_lchr(name, '.');
	if (ext) {
		ext++;
		if (!strcmp(ext, "py") || !strcmp(ext, "js") || !strcmp(ext, "lua")) {
			return true;
		}
	}
	return false;
}

RZ_API int rz_core_loadlibs(RzCore *core, int where) {
	ut64 prev = rz_time_now_mono();
	loadSystemPlugins(core, where);
	/* TODO: all those default plugin paths should be defined in rz_lib */
	if (!rz_config_get_i(core->config, "cfg.plugins")) {
		core->times->loadlibs_time = 0;
		return false;
	}
	// load script plugins
	char *homeplugindir = rz_path_home_prefix(RZ_PLUGINS);
	RzList *files = rz_sys_dir(homeplugindir);
	RzListIter *iter;
	char *file;
	rz_list_foreach (files, iter, file) {
		if (__isScriptFilename(file)) {
			char *script_file = rz_str_newf("%s/%s", homeplugindir, file);
			if (!rz_core_run_script(core, script_file)) {
				RZ_LOG_ERROR("core: cannot find script '%s'\n", script_file);
			}
			free(script_file);
		}
	}

	free(homeplugindir);
	core->times->loadlibs_time = rz_time_now_mono() - prev;
	rz_list_free(files);
	return true;
}
