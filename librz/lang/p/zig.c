// SPDX-FileCopyrightText: 2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_core.h>
#include <rz_lang.h>

static int lang_zig_file(RzLang *lang, const char *file) {
	void *lib;
	char *a, *cc, *p;
	const char *libpath, *libname;

	if (!rz_file_exists(file)) {
		eprintf("file not found (%s)\n", file);
		return false;
	}
	char *name = strdup(file);

	a = (char *)rz_str_lchr(name, '/');
	if (a) {
		*a = 0;
		libpath = name;
		libname = a + 1;
	} else {
		libpath = ".";
		libname = name;
	}
	p = strstr(name, ".zig");
	if (p) {
		*p = 0;
	}
	cc = rz_sys_getenv("ZIG");
	if (cc && !*cc) {
		RZ_FREE(cc);
	}
	if (!cc) {
		cc = strdup("zig");
	}
	char *cmd = rz_str_newf("zig build-lib --output %s.%s --release-fast %s.zig --library rz_core", name, RZ_LIB_EXT, name);
	if (rz_sys_system(cmd) != 0) {
		free(name);
		free(cmd);
		free(cc);
		return false;
	}
	free(cmd);

	char *path = rz_str_newf("%s/%s.%s", libpath, libname, RZ_LIB_EXT);
	lib = rz_lib_dl_open(path);
	if (lib) {
		void (*fcn)(RzCore *);
		fcn = rz_lib_dl_sym(lib, "entry");
		if (fcn) {
			fcn(lang->user);
		} else {
			eprintf("Cannot find 'entry' symbol in library\n");
		}
		rz_lib_dl_close(lib);
	} else {
		eprintf("Cannot open library\n");
		free(path);
		free(cc);
		return false;
	}
	rz_file_rm(path); // remove lib
	free(path);
	free(cc);
	return true;
}

static int lang_zig_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static int lang_zig_run(RzLang *lang, const char *code, int len) {
	const char *file = "_tmp.zig";
	FILE *fd = rz_sys_fopen(file, "w");
	if (fd) {
		const char *zig_header =
			"extern fn puts(&const u8) void;\n"
			"extern fn rz_core_cmd_str(&u8, &const u8) &u8;\n"
			"extern fn rz_core_new() &u8;\n"
			"extern fn rz_core_free(&u8) void;\n"
			"\n"
			"export fn entry(core: &u8) void {\n";
		const char *zig_footer =
			"\n}\n"
			"pub fn rzcmd(core: &u8, cmd: u8) &u8 {\n"
			"  return rz_core_cmd_str(core, cmd);\n"
			"}\n";
		fputs(zig_header, fd);
		fputs(code, fd);
		fputs(zig_footer, fd);
		fclose(fd);
		lang_zig_file(lang, file);
		rz_file_rm(file);
	} else {
		eprintf("Cannot open %s\n", file);
	}
	return true;
}

static RzLangPlugin rz_lang_plugin_zig = {
	.name = "zig",
	.ext = "zig",
	.license = "MIT",
	.desc = "Zig language extension",
	.run = lang_zig_run,
	.init = (void *)lang_zig_init,
	.run_file = (void *)lang_zig_file,
};
