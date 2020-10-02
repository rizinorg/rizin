/* radare - LGPL - Copyright 2012-2020 - pancake */

#include <stdio.h>
#include <string.h>
#include <rz_main.h>
#include <rz_util.h>

RZ_LIB_VERSION(rz_main);

static RzMain foo[] = {
	{ "r2", rz_main_rizin },
	{ "rz_ax", rz_main_rz_ax },
	{ "rz_diff", rz_main_rz_diff },
	{ "rz_find", rz_main_rz_find },
	{ "rz_run", rz_main_rz_run },
	{ "rz_asm", rz_main_rz_asm },
	{ "rz_gg", rz_main_rz_gg },
	{ "rz_bin", rz_main_rz_bin },
	{ "rizin", rz_main_rizin },
	{ NULL, NULL }
};

RZ_API RzMain *rz_main_new (const char *name) {
	int i = 0;
	while (foo[i].name) {
		if (!strcmp (name, foo[i].name)) {
			RzMain *m = RZ_NEW0 (RzMain);
			if (m) {
				m->name = strdup (foo[i].name);
				m->main = foo[i].main;
			}
			return m;
		}
		i++;
	}
	return NULL;
}

RZ_API void rz_main_free(RzMain *m) {
	free (m);
}

RZ_API int rz_main_run(RzMain *m, int argc, const char **argv) {
	rz_return_val_if_fail (m && m->main, -1);
	return m->main (argc, argv);
}

RZ_API int rz_main_version_print(const char *progname) {
	char *s = rz_str_version (progname);
	printf ("%s\n", s);
	free (s);
	return 0;
}
