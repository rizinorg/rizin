// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stddef.h>
#include <rz_core.h>

typedef void (*DigestHandler)(const char *name, const ut8 *block, int len);

typedef struct {
	const char *name;
	DigestHandler handler;
	RzMsgDigestPlugin *plugin;
} MsgDigestCaller;

static inline void hexprint(const ut8 *data, int len) {
	if (!data || len < 1) {
		return;
	}
	for (int i = 0; i < len; i++) {
		rz_cons_printf("%02x", data[i]);
	}
	rz_cons_newline();
}

static void handle_msg_digest(const char *name, const ut8 *block, int len) {
	RzMsgDigestSize digest_size = 0;
	ut8 *digest = rz_msg_digest_calculate_small_block(name, block, len, &digest_size);
	hexprint(digest, digest_size);
	free(digest);
}

static void handle_entropy(const char *name, const ut8 *block, int len) {
	RzMsgDigestSize digest_size = 0;
	ut8 *digest = rz_msg_digest_calculate_small_block(name, block, len, &digest_size);
	if (!digest) {
		return;
	}
	double entropy = rz_read_be_double(digest);
	rz_cons_printf("%f\n", entropy);
	free(digest);
}

static int cmd_hash_bang(RzCore *core, const char *input) {
	int ac;
	char **av = rz_str_argv(input + 1, &ac);
	RzCmdStateOutput state = { 0 };
	state.mode = RZ_OUTPUT_MODE_STANDARD;
	if (ac > 0) {
		RzLangPlugin *p = rz_lang_get_by_name(core->lang, av[0]);
		if (p) {
			// I see no point in using rz_lang_use here, as we already haz a ptr to the pluging in our handz
			// Maybe add rz_lang_use_plugin in rz_lang api?
			core->lang->cur = p;
			if (ac > 1) {
				if (!strcmp(av[1], "-e")) {
					char *run_str = strstr(input + 2, "-e") + 2;
					rz_lang_run_string(core->lang, run_str);
				} else {
					if (rz_lang_set_argv(core->lang, ac - 1, &av[1])) {
						rz_lang_run_file(core->lang, av[1]);
					} else {
						char *run_str = strstr(input + 2, av[1]);
						rz_lang_run_file(core->lang, run_str);
					}
				}
			} else {
				if (rz_cons_is_interactive()) {
					rz_lang_prompt(core->lang);
				} else {
					eprintf("Error: scr.interactive required to run the rlang prompt\n");
				}
			}
		} else if (av[0][0] == '?' || av[0][0] == '*') {
			rz_core_lang_plugins_print(core->lang, &state);
		}
	} else {
		rz_core_lang_plugins_print(core->lang, &state);
	}
	rz_str_argv_free(av);
	return true;
}

RZ_IPI int rz_cmd_hash(void *data, const char *input) {
	RzCore *core = (RzCore *)data;

	if (*input == '!') {
		return cmd_hash_bang(core, input);
	}
	if (*input == '?') {
		const char *helpmsg3[] = {
			"Usage #!interpreter [<args>] [<file] [<<eof]", "", "",
			" #", "", "comment - do nothing",
			" #!", "", "list all available interpreters",
			" #!python", "", "run python commandline",
			" #!python", " foo.py", "run foo.py python script (same as '. foo.py')",
			//" #!python <<EOF        get python code until 'EOF' mark\n"
			" #!python", " arg0 a1 <<q", "set arg0 and arg1 and read until 'q'",
			NULL
		};
		rz_core_cmd_help(core, helpmsg3);
		return false;
	}
	/* this should not be reached, see rz_core_cmd_subst() */
	return 0;
}

RZ_IPI RzCmdStatus rz_hash_bang_handler(RzCore *core, int argc, const char **argv) {
	RzCmdStateOutput state = { 0 };
	state.mode = RZ_OUTPUT_MODE_STANDARD;
	if (argc == 1) {
		rz_core_lang_plugins_print(core->lang, &state);
	} else {
		RzLangPlugin *p = rz_lang_get_by_name(core->lang, argv[1]);
		if (!p) {
			eprintf("No interpreter with name '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		core->lang->cur = p;
		if (argc > 2) {
			if (rz_lang_set_argv(core->lang, argc - 2, (char **)&argv[2])) {
				rz_lang_run_file(core->lang, argv[2]);
			} else {
				char *run_str = rz_str_array_join(argv + 2, argc - 2, " ");
				rz_lang_run_file(core->lang, run_str);
				free(run_str);
			}
		} else {
			if (rz_cons_is_interactive()) {
				rz_lang_prompt(core->lang);
			} else {
				eprintf("Error: scr.interactive required to run the rlang prompt\n");
				return RZ_CMD_STATUS_ERROR;
			}
		}
	}
	return RZ_CMD_STATUS_OK;
}
