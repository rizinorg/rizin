// SPDX-FileCopyrightText: 2016-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_lib.h"
#include "rz_core.h"
#include "rz_lang.h"

static int lang_rust_file(RzLang *lang, const char *file) {
	void *lib;
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;

	if (strlen(file) > (sizeof(name) - 10)) {
		return false;
	}
	if (!strstr(file, ".rs")) {
		sprintf(name, "%s.rs", file);
	} else {
		strcpy(name, file);
	}
	if (!rz_file_exists(name)) {
		eprintf("file not found (%s)\n", name);
		return false;
	}

	a = (char *)rz_str_lchr(name, '/');
	if (a) {
		*a = 0;
		libpath = name;
		libname = a + 1;
	} else {
		libpath = ".";
		libname = name;
	}
	char *libdir = rz_str_rz_prefix(RZ_LIBDIR);
	char *pkgconf_path = rz_file_path_join(libdir, "pkgconfig");
	rz_sys_setenv("PKG_CONFIG_PATH", pkgconf_path);
	free(pkgconf_path);
	free(libdir);
	p = strstr(name, ".rs");
	if (p)
		*p = 0;
	cc = rz_sys_getenv("RUSTC");
	if (cc && !*cc) {
		RZ_FREE(cc);
	}
	if (!cc) {
		cc = strdup("rustc");
	}
	char *cmd = rz_str_newf("%s --crate-type dylib %s -o %s/lib%s." RZ_LIB_EXT " -L native=/usr/local/lib/ -l rz_core",
		cc, file, libpath, libname);
	free(cc);
	if (rz_sys_system(cmd) != 0) {
		free(cmd);
		return false;
	}
	free(cmd);

	char *path = rz_str_newf("%s/lib%s." RZ_LIB_EXT, libpath, libname);
	lib = rz_lib_dl_open(path);
	if (lib != NULL) {
		void (*fcn)(RzCore *);
		fcn = rz_lib_dl_sym(lib, "entry");
		if (fcn)
			fcn(lang->user);
		else
			eprintf("Cannot find 'entry' symbol in library\n");
		rz_lib_dl_close(lib);
	} else {
		eprintf("Cannot open library\n");
	}
	rz_file_rm(path); // remove lib
	free(path);
	return 0;
}

static int lang_rust_init(void *user) {
	// TODO: check if "valac" is found in path
	return true;
}

static int lang_rust_run(RzLang *lang, const char *code, int len) {
	FILE *fd = rz_sys_fopen("_tmp.rs", "w");
	if (fd) {
		const char *rust_header =
			"use std::ffi::CStr;\n"
			"extern {\n"
			"        pub fn rz_core_cmd_str(core: *const u8, s: *const u8) -> *const u8;\n"
			"        pub fn free (ptr: *const u8);\n"
			"}\n"
			"\n"
			"pub struct Rz;\n"
			"\n"
			"#[allow(dead_code)]\n"
			"impl Rz {\n"
			"        fn cmdstr(&self, c: *const u8, str: &str) -> String {\n"
			"                unsafe {\n"
			"                        let ptr = rz_core_cmd_str(c, str.as_ptr()) as *const i8;\n"
			"                        let c_str = CStr::from_ptr(ptr).to_string_lossy().into_owned();\n"
			"                        free (ptr as *const u8);\n"
			"                        String::from (c_str)\n"
			"                }\n"
			"        }\n"
			"}\n"
			"\n"
			"#[no_mangle]\n"
			"#[allow(unused_variables)]\n"
			"#[allow(unused_unsafe)]\n"
			"pub extern fn entry(core: *const u8) {\n"
			"        let rz = Rz;\n"
			"        unsafe { /* because core is external */\n";
		const char *rust_footer =
			"        }\n"
			"}\n";
		fputs(rust_header, fd);
		fputs(code, fd);
		fputs(rust_footer, fd);
		fclose(fd);
		lang_rust_file(lang, "_tmp.rs");
		rz_file_rm("_tmp.rs");
	} else
		eprintf("Cannot open _tmp.rs\n");
	return true;
}

static RzLangPlugin rz_lang_plugin_rust = {
	.name = "rust",
	.ext = "rs",
	.license = "MIT",
	.desc = "Rust language extension",
	.run = lang_rust_run,
	.init = (void *)lang_rust_init,
	.run_file = (void *)lang_rust_file,
};
