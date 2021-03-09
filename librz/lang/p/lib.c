// SPDX-FileCopyrightText: 2017-2020 condret
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_core.h>
#include <rz_lang.h>

static int lang_lib_init(RzLang *user) {
	return true;
}

static int lang_lib_file_run(RzLang *user, const char *file) {
	char *libpath;
	void *lib;
	if (!(libpath = rz_str_new(file))) {
		return -1;
	}
	if (!rz_str_startswith(libpath, "/") && !rz_str_startswith(libpath, "./")) {
		libpath = rz_str_prepend(libpath, "./");
	}
	if (!rz_file_exists(libpath)) {
		if (!rz_str_endswith(libpath, RZ_LIB_EXT)) {
			libpath = rz_str_appendf(libpath, ".%s", RZ_LIB_EXT);
		}
	}
	if (!rz_file_exists(libpath)) {
		free(libpath);
		return -1;
	}

	lib = rz_lib_dl_open(libpath);
	if (lib) {
		void (*fcn)(RzCore *);
		fcn = rz_lib_dl_sym(lib, "entry");
		if (fcn) {
			fcn(user->user);
		} else {
			eprintf("Cannot find 'entry' symbol in library\n");
		}
		rz_lib_dl_close(lib);
	}
	free(libpath);
	return 0;
}

static RzLangPlugin rz_lang_plugin_lib = {
	.name = "lib",
	.ext = RZ_LIB_EXT,
	.desc = "Load libs directly into rizin",
	.license = "LGPL",
	.init = lang_lib_init,
	.run_file = lang_lib_file_run,
};
