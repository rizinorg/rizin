// SPDX-FileCopyrightText: 2011-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file
 * A plugin allowing to run "scripts" written in C language
 */

#include <rz_lib.h>
#include <rz_core.h>
#include <rz_lang.h>

#if __UNIX__
static int ac = 0;
static const char **av = NULL;

static bool lang_c_set_argv(RzLang *lang, int argc, const char **argv) {
	ac = argc;
	av = argv;
	return true;
}

static int lang_c_file(RzLang *lang, const char *file) {
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;
	void *lib;

	if (strlen(file) > (sizeof(name) - 10)) {
		return false;
	}
	if (!strstr(file, ".c")) {
		sprintf(name, "%s.c", file);
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
	p = strstr(name, ".c");
	if (p) {
		*p = 0;
	}
	cc = rz_sys_getenv("CC");
	if (RZ_STR_ISEMPTY(cc)) {
		cc = rz_str_dup("gcc");
	}
	char *libdir = rz_path_libdir();
	char *pkgconf_path = rz_file_path_join(libdir, "pkgconfig");
	char *file_esc = rz_str_escape_sh(file);
	char *libpath_esc = rz_str_escape_sh(libpath);
	char *libname_esc = rz_str_escape_sh(libname);
	char *buf = rz_str_newf("%s -fPIC -shared \"%s\" -o \"%s/lib%s." RZ_LIB_EXT "\""
				" $(PKG_CONFIG_PATH=%s pkg-config --cflags --libs rz_core)",
		cc, file_esc, libpath_esc, libname_esc, pkgconf_path);
	free(libname_esc);
	free(libpath_esc);
	free(file_esc);
	free(libdir);
	free(pkgconf_path);
	free(cc);
	if (rz_sys_system(buf) != 0) {
		free(buf);
		return false;
	}
	free(buf);
	buf = rz_str_newf("%s/lib%s." RZ_LIB_EXT, libpath, libname);
	lib = rz_sys_dlopen(buf);
	if (lib) {
		void (*fcn)(RzCore *, int argc, const char **argv);
		fcn = rz_sys_dlsym(lib, "entry");
		if (fcn) {
			fcn(lang->user, ac, av);
			ac = 0;
			av = NULL;
		} else {
			eprintf("Cannot find 'entry' symbol in library\n");
		}
		rz_sys_dlclose(lib);
	} else {
		eprintf("Cannot open library\n");
	}
	rz_file_rm(buf); // remove lib
	free(buf);
	return 0;
}

static int lang_c_init(void *user) {
	// TODO: check if C compiler is found in path
	return true;
}

static int lang_c_run(RzLang *lang, const char *code, int len) {
	FILE *fd = rz_sys_fopen(".tmp.c", "w");
	if (fd) {
		fputs("#include <rz_core.h>\n\nvoid entry(RzCore *core, int argc, const char **argv) {\n", fd);
		fputs(code, fd);
		fputs("\n}\n", fd);
		fclose(fd);
		lang_c_file(lang, ".tmp.c");
		rz_file_rm(".tmp.c");
	} else
		eprintf("Cannot open .tmp.c\n");
	return true;
}

RzLangPlugin rz_lang_plugin_c = {
	.name = "c",
	.ext = "c",
	.desc = "C language extension",
	.license = "LGPL",
	.run = lang_c_run,
	.init = (void *)lang_c_init,
	.run_file = (void *)lang_c_file,
	.set_argv = (void *)lang_c_set_argv,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_LANG,
	.data = &rz_lang_plugin_c,
	.version = RZ_VERSION
};
#endif

#else
#ifdef _MSC_VER
#pragma message("Warning: C RzLangPlugin is not implemented on this platform")
#else
#warning C RzLangPlugin is not implemented on this platform
#endif
#endif
