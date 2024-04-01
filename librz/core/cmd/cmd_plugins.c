// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <cmd_descs.h>

RZ_IPI RzCmdStatus rz_plugins_load_handler(RzCore *core, int argc, const char **argv) {
	return rz_lib_open(core->lib, rz_str_trim_head_ro(argv[1])) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_plugins_unload_handler(RzCore *core, int argc, const char **argv) {
	return rz_lib_close(core->lib, rz_str_trim_head_ro(argv[1])) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI RzCmdStatus rz_plugins_lang_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_lang_plugins_print(core->lang, state);
}

RZ_IPI RzCmdStatus rz_plugins_asm_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_asm_plugins_print(core, NULL, state);
}

RZ_IPI RzCmdStatus rz_plugins_core_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_core_plugins_print(core, state);
}

RZ_IPI RzCmdStatus rz_plugins_crypto_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_crypto_plugins_print(core->crypto, state);
}

RZ_IPI RzCmdStatus rz_plugins_debug_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		return rz_config_set(core->config, "dbg.backend", argv[1]) ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
	}
	return rz_core_debug_plugins_print(core, state);
}

RZ_IPI RzCmdStatus rz_plugins_hash_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_hash_plugins_print(core->hash, state);
}

RZ_IPI RzCmdStatus rz_plugins_bin_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_bin_plugins_print(core->bin, state);
}

RZ_IPI RzCmdStatus rz_plugins_io_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	if (argc > 1) {
		if (!rz_lib_open(core->lib, argv[1])) {
			RZ_LOG_ERROR("Could not load an IO plugin from '%s'\n", argv[1]);
			return RZ_CMD_STATUS_ERROR;
		}
		return RZ_CMD_STATUS_OK;
	}
	return rz_core_io_plugins_print(core->io, state);
}

RZ_IPI RzCmdStatus rz_plugins_parser_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	return rz_core_parser_plugins_print(core->parser, state);
}

RZ_IPI RzCmdStatus rz_plugins_demanglers_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	// alias for iDl
	return rz_cmd_info_demangle_list_handler(core, argc, argv, state);
}
