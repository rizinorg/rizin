// SPDX-FileCopyrightText: 2011-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_main.h>
#include <rz_socket.h>

#if __UNIX__
static void fwd(int sig) {
	/* do nothing? send kill signal to remote process */
}

static void rz_run_tty(void) {
	/* TODO: Implement in native code */
	rz_sys_xsystem("tty");
	close(1);
	dup2(2, 1);
	rz_sys_signal(SIGINT, fwd);
	for (;;) {
		sleep(1);
	}
}
#endif

RZ_API int rz_main_rz_run(int argc, const char **argv) {
	RzRunProfile *p;
	int i, ret;
	if (argc == 1 || !strcmp(argv[1], "-h")) {
		printf("Usage: rz-run -v|-t|script.rr2 [directive ..]\n");
		printf("%s", rz_run_help());
		return 1;
	}
	if (!strcmp(argv[1], "-v")) {
		return rz_main_version_print("rz_run");
	}
	const char *file = argv[1];
	if (!strcmp(file, "-t")) {
#if __UNIX__
		rz_run_tty();
		return 0;
#else
		eprintf("Not supported\n");
		return 1;
#endif
	}
	if (*file && !strchr(file, '=')) {
		p = rz_run_new(file);
	} else {
		bool noMoreDirectives = false;
		int directiveIndex = 0;
		p = rz_run_new(NULL);
		for (i = *file ? 1 : 2; i < argc; i++) {
			if (!strcmp(argv[i], "--")) {
				noMoreDirectives = true;
				continue;
			}
			if (noMoreDirectives) {
				const char *word = argv[i];
				char *line = directiveIndex
					? rz_str_newf("arg%d=%s", directiveIndex, word)
					: rz_str_newf("program=%s", word);
				rz_run_parseline(p, line);
				directiveIndex++;
				free(line);
			} else {
				rz_run_parseline(p, argv[i]);
			}
		}
	}
	if (!p) {
		return 1;
	}
	ret = rz_run_config_env(p);
	if (ret) {
		printf("error while configuring the environment.\n");
		return 1;
	}
	ret = rz_run_start(p);
	rz_run_free(p);
	return ret;
}
