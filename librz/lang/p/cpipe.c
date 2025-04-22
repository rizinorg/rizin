// SPDX-FileCopyrightText: 2011-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file
 * A plugin allowing to run rz-pipe "scripts" written in C language
 */

#include <rz_lib.h>
#include <rz_core.h>
#include <rz_lang.h>
#include "pipe_helper.h"

#if __UNIX__
static int lang_cpipe_file(RzLang *lang, const char *file) {
	char *a, *cc, *p, name[512];
	const char *libpath, *libname;

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
		free(cc);
		cc = rz_str_dup("gcc");
	}
	char *libdir = rz_path_libdir();
	char *pkgconf_path = rz_file_path_join(libdir, "pkgconfig");
	char *file_esc = rz_str_escape_sh(file);
	char *libpath_esc = rz_str_escape_sh(libpath);
	char *libname_esc = rz_str_escape_sh(libname);
	char *buf = rz_str_newf("%s \"%s\" -o \"%s/bin%s\""
				" $(PKG_CONFIG_PATH=%s pkg-config --cflags --libs rz_socket)",
		cc, file_esc, libpath_esc, libname_esc, pkgconf_path);
	free(libname_esc);
	free(libpath_esc);
	free(file_esc);
	free(pkgconf_path);
	free(cc);
	if (rz_sys_system(buf) == 0) {
		char *o_ld_path = rz_sys_getenv("LD_LIBRARY_PATH");
		rz_sys_setenv("LD_LIBRARY_PATH", libdir);
		char *binfile = rz_str_newf("%s/bin%s", libpath, libname);
		lang_pipe_run(lang, binfile, -1);
		rz_file_rm(binfile);
		rz_sys_setenv("LD_LIBRARY_PATH", o_ld_path);
		free(o_ld_path);
		free(binfile);
	}
	free(libdir);
	free(buf);
	return 0;
}

static int lang_cpipe_init(void *user) {
	// TODO: check if C compiler is found in path
	return true;
}

static int lang_cpipe_run(RzLang *lang, const char *code, int len) {
	FILE *fd = rz_sys_fopen(".tmp.c", "w");
	if (!fd) {
		eprintf("Cannot open .tmp.c\n");
		return false;
	}
	fputs("#include <rz_socket.h>\n\n"
	      "#define RZP(x,y...) rzpipe_cmdf(rzp,x,##y)\n"
	      "int main() {\n"
	      "  RzPipe *rzp = rzpipe_open(NULL);",
		fd);
	fputs(code, fd);
	fputs("\n}\n", fd);
	fclose(fd);
	lang_cpipe_file(lang, ".tmp.c");
	rz_file_rm(".tmp.c");
	return true;
}

RzLangPlugin rz_lang_plugin_cpipe = {
	.name = "cpipe",
	.ext = "c2",
	.desc = "rzpipe scripting in C",
	.license = "LGPL",
	.run = lang_cpipe_run,
	.init = (void *)lang_cpipe_init,
	.fini = NULL,
	.run_file = (void *)lang_cpipe_file,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_LANG,
	.data = &rz_lang_plugin_cpipe,
	.version = RZ_VERSION
};
#endif

#else
#ifdef _MSC_VER
#pragma message("Warning: cpipe RzLangPlugin is not implemented on this platform")
#else
#warning cpipe RzLangPlugin is not implemented on this platform
#endif
#endif
