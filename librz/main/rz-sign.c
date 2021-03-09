// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_main.h>
#include <rz_core.h>

static void rasign_show_help(void) {
	printf("Usage: rz-sign [options] [file]\n"
	       " -a [-a]          add extra 'a' to analysis command\n"
	       " -f               interpret the file as a FLIRT .sig file and dump signatures\n"
	       " -h               help menu\n"
	       " -j               show signatures in json\n"
	       " -o sigs.sdb      add signatures to file, create if it does not exist\n"
	       " -q               quiet mode\n"
	       " -r               show output in rizin commands\n"
	       " -s signspace     save all signatures under this signspace\n"
	       " -v               show version information\n"
	       "Examples:\n"
	       "  rz_sign -o libc.sdb libc.so.6\n");
}

static RzCore *opencore(const char *fname) {
	RzCoreFile *rfile = NULL;
	RzCore *c = rz_core_new();
	if (!c) {
		eprintf("Count not get core\n");
		return NULL;
	}
	rz_core_loadlibs(c, RZ_CORE_LOADLIBS_ALL, NULL);
	rz_config_set_i(c->config, "scr.interactive", false);
	if (fname) {
#if __WINDOWS__
		char *winf = rz_acp_to_utf8(fname);
		rfile = rz_core_file_open(c, winf, 0, 0);
		free(winf);
#else
		rfile = rz_core_file_open(c, fname, 0, 0);
#endif

		if (!rfile) {
			eprintf("Could not open file %s\n", fname);
			rz_core_free(c);
			return NULL;
		}
		(void)rz_core_bin_load(c, NULL, UT64_MAX);
		(void)rz_core_bin_update_arch_bits(c);
		rz_cons_flush();
	}
	return c;
}

static void find_functions(RzCore *core, size_t count) {
	const char *cmd = NULL;
	switch (count) {
	case 0: cmd = "aa"; break;
	case 1: cmd = "aaa"; break;
	case 2: cmd = "aaaa"; break;
	}
	rz_core_cmd0(core, cmd);
}

RZ_API int rz_main_rz_sign(int argc, const char **argv) {
	const char *ofile = NULL;
	const char *space = NULL;
	int c;
	size_t a_cnt = 0;
	bool rad = false;
	bool quiet = false;
	bool json = false;
	bool flirt = false;
	RzGetopt opt;

	rz_getopt_init(&opt, argc, argv, "afhjo:qrs:v");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			a_cnt++;
			break;
		case 'o':
			ofile = opt.arg;
			break;
		case 's':
			space = opt.arg;
			break;
		case 'r':
			rad = true;
			break;
		case 'j':
			json = true;
			break;
		case 'q':
			quiet = true;
			break;
		case 'f':
			flirt = true;
			break;
		case 'v':
			return rz_main_version_print("rz_sign");
		case 'h':
			rasign_show_help();
			return 0;
		default:
			rasign_show_help();
			return -1;
		}
	}

	if (a_cnt > 2) {
		eprintf("Invalid analysis (too many -a's?)\n");
		rasign_show_help();
		return -1;
	}

	const char *ifile = NULL;
	if (opt.ind >= argc) {
		eprintf("must provide a file\n");
		rasign_show_help();
		return -1;
	}
	ifile = argv[opt.ind];

	RzCore *core = NULL;
	if (flirt) {
		if (rad || ofile || json) {
			eprintf("Only FLIRT output is supported for FLIRT files\n");
			return -1;
		}
		core = opencore(NULL);
		rz_sign_flirt_dump(core->analysis, ifile);
		rz_cons_flush();
		rz_core_free(core);
		return 0;
	} else {
		core = opencore(ifile);
	}

	if (!core) {
		eprintf("Could not get core\n");
		return -1;
	}

	// quiet mode
	if (quiet) {
		rz_config_set(core->config, "scr.interactive", "false");
		rz_config_set(core->config, "scr.prompt", "false");
		rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
	}

	if (space) {
		rz_spaces_set(&core->analysis->zign_spaces, space);
	}

	// run analysis to find functions
	find_functions(core, a_cnt);

	// create zignatures
	rz_core_cmd0(core, "zg");

	// write sigs to file
	if (ofile) {
		rz_core_cmdf(core, "\"zos %s\"", ofile);
	}

	if (rad) {
		rz_core_flush(core, "z*");
	}

	if (json) {
		rz_core_flush(core, "zj");
	}

	rz_core_free(core);
	return 0;
}
