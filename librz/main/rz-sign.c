// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only
#include <rz_main.h>
#include <rz_core.h>

enum rz_sign_option {
	RZ_SIGN_OPT_NONE = 0,
	RZ_SIGN_OPT_CONVERT_FLIRT,
	RZ_SIGN_OPT_CREATE_FLIRT,
	RZ_SIGN_OPT_DUMP_FLIRT,
};

static void rz_sign_show_help(void) {
	printf("%s%s%s", Color_CYAN, "Usage: ", Color_RESET);
	printf("rz-sign [-aqv] [-e k=v] (-c pat sig | -o sig bin | -d sig)\n");
	const char *options[] = {
		// clang-format off
		"-h",       "",                         "Show this help",
		"-a, -aa",  "",                         "Add extra 'a' to analysis command (available only with -o option)",
		"-e",       "k=v",                      "Set an evaluable config variable (available only with -o option)",
		"-c",       "output.pat input.sig",     "Parse a FLIRT signature and convert it to its other format",
		"-o",       "output.sig input.bin",     "Perform an analysis on the binary and generate the FLIRT signature",
		"-d",       "flirt.sig",                "Parse a FLIRT signature and dump its content",
		"-q",       "",                         "Quiet mode",
		"-v",       "",                         "Show version information",
		// clang-format on
	};
	rz_print_colored_help(options, RZ_ARRAY_SIZE(options), false);
	printf("Examples:\n"
	       "  rz-sign -d signature.sig\n"
	       "  rz-sign -c new_signature.pat old_signature.sig\n"
	       "  rz-sign -o libc.sig libc.so.6\n");
}

static void perform_analysis(RzCore *core, size_t complexity) {
	const char *cmd = NULL;
	switch (complexity) {
	case 0: cmd = "aa"; break;
	case 1: cmd = "aaa"; break;
	default: cmd = "aaaa"; break;
	}
	rz_core_cmd0(core, cmd);
}

RZ_API int rz_main_rz_sign(int argc, const char **argv) {
	RzListIter *it;
	const char *input_file = NULL;
	const char *output_file = NULL;
	char *config = NULL;
	RzCore *core = NULL;
	RzList *evars = NULL;
	bool quiet = false;
	RzGetopt opt;
	int ret = 0;
	ut32 n_nodes = 0;

	int c, option = RZ_SIGN_OPT_NONE;
	size_t complexity = 0;

	evars = rz_list_newf(free);
	if (!evars) {
		RZ_LOG_ERROR("rz-sign: cannot allocate RzList\n");
		return -1;
	}

	rz_getopt_init(&opt, argc, argv, "aqhdc:o:e:v");
	while ((c = rz_getopt_next(&opt)) != -1) {
		switch (c) {
		case 'a':
			complexity++;
			break;
		case 'c':
			if (option != RZ_SIGN_OPT_NONE) {
				RZ_LOG_ERROR("rz-sign: cannot combine option -%c with previous options\n", c);
				ret = -1;
				goto rz_sign_end;
			}
			option = RZ_SIGN_OPT_CONVERT_FLIRT;
			output_file = opt.arg;
			break;
		case 'o':
			if (option != RZ_SIGN_OPT_NONE) {
				RZ_LOG_ERROR("rz-sign: cannot combine option -%c with previous options\n", c);
				ret = -1;
				goto rz_sign_end;
			}
			option = RZ_SIGN_OPT_CREATE_FLIRT;
			output_file = opt.arg;
			break;
		case 'd':
			if (option != RZ_SIGN_OPT_NONE) {
				RZ_LOG_ERROR("rz-sign: cannot combine option -%c with previous options\n", c);
				ret = -1;
				goto rz_sign_end;
			}
			option = RZ_SIGN_OPT_DUMP_FLIRT;
			break;
		case 'e':
			if (!(config = rz_str_dup(opt.arg)) || !rz_list_append(evars, config)) {
				free(config);
				RZ_LOG_ERROR("rz-sign: cannot add evaluable config variable '%s' to RzList\n", opt.arg);
				ret = -1;
				goto rz_sign_end;
			}
			break;
		case 'q':
			quiet = true;
			break;
		case 'v': {
			RzPath *sys_path = rz_path_new();
			if (!sys_path) {
				ret = -1;
				goto rz_sign_end;
			}
			size_t print_val = rz_main_version_print(sys_path, "rz-sign");
			rz_path_free(sys_path);
			return print_val;
		}
		case 'h':
			rz_sign_show_help();
			goto rz_sign_end;
		default:
			RZ_LOG_ERROR("rz-sign: invalid option -%c\n", c);
			rz_sign_show_help();
			ret = -1;
			goto rz_sign_end;
		}
	}

	if (opt.ind >= argc) {
		RZ_LOG_ERROR("rz-sign: input file was not provided\n");
		rz_sign_show_help();
		ret = -1;
		goto rz_sign_end;
	}

	input_file = argv[opt.ind];

	if (option == RZ_SIGN_OPT_CREATE_FLIRT && complexity > 2) {
		RZ_LOG_ERROR("rz-sign: Invalid analysis complexity (too many -a defined, max -aa)\n");
		rz_sign_show_help();
		ret = -1;
		goto rz_sign_end;
	}

	core = rz_core_new();
	if (!core) {
		RZ_LOG_ERROR("rz-sign: Cannot allocate RzCore\n");
		ret = -1;
		goto rz_sign_end;
	}
	rz_config_set_b(core->config, "scr.interactive", false);
	rz_config_set_b(core->config, "analysis.apply.signature", false);
	rz_cons_reset();
	rz_cons_set_interactive(false);

	rz_core_loadlibs(core, RZ_CORE_LOADLIBS_ALL);

	if (!rz_core_file_open(core, input_file, 0, 0)) {
		RZ_LOG_ERROR("rz-sign: Could not open file %s\n", input_file);
		ret = -1;
		goto rz_sign_end;
	}

	(void)rz_core_bin_load(core, NULL, UT64_MAX);
	(void)rz_core_bin_update_arch_bits(core);

	// quiet mode
	if (quiet) {
		rz_config_set_b(core->config, "scr.prompt", false);
		rz_config_set_i(core->config, "scr.color", COLOR_MODE_DISABLED);
	}

	// set all evars
	rz_list_foreach (evars, it, config) {
		if (!rz_config_eval(core->config, config)) {
			RZ_LOG_ERROR("rz-sign: invalid option '%s'\n", config);
			ret = -1;
			goto rz_sign_end;
		}
	}

	switch (option) {
	case RZ_SIGN_OPT_CONVERT_FLIRT:
		// convert a flirt file from .pat to .sig or viceversa
		if (!rz_core_flirt_convert_file(core, input_file, output_file)) {
			ret = -1;
		} else if (!quiet) {
			rz_cons_printf("rz-sign: %s was converted to %s.\n", input_file, output_file);
		}
		break;
	case RZ_SIGN_OPT_CREATE_FLIRT:
		// run analysis to find functions
		perform_analysis(core, complexity);
		// create flirt file
		if (!rz_core_flirt_create_file(core, output_file, &n_nodes)) {
			ret = -1;
		} else if (!quiet) {
			rz_cons_printf("rz-sign: written %u signatures to %s.\n", n_nodes, output_file);
		}
		break;
	case RZ_SIGN_OPT_DUMP_FLIRT:
		if (!rz_core_flirt_dump_file(input_file)) {
			ret = -1;
		}
		break;
	default:
		RZ_LOG_ERROR("rz-sign: missing option, please set -c or -d or -o\n");
		ret = -1;
		break;
	}
	rz_cons_flush();

rz_sign_end:
	rz_list_free(evars);
	rz_core_free(core);
	return ret;
}
