// SPDX-FileCopyrightText: 2021 somebody <somebody@domain.tld>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file core_plugin_example.c
 * This file is an example on how to write core plugins for rizin.
 * 
 * Compilation:
 * - gcc -o core_plugin_example.so -O3 -std=c99 -Wall -fPIC `pkg-config --cflags --libs rz_core` core_plugin_example.c -shared

 * Installation via the RZ_USER_PLUGINS folder:
 * - mkdir -p ~/.local/share/rizin/plugins/
 * - rizin -H | grep RZ_USER_PLUGINS
 * - RZ_USER_PLUGINS=/home/username/.local/share/rizin/plugins
 * - mv core_plugin_example.so ~/.local/share/rizin/plugins/

 * Example of usage
 * - rizin =
 *   This init was called!
 * - [0x00000000]> example?
 *   Usage: example <number>   # example summary that contains some description
 * - [0x00000000]> example 1777
 *   WARNING: the parsed number is 1777
 * - [0x00000000]> example -777
 *   ERROR: only positive numbers are accepted -777
 *   Error while executing command: example -777
 * - [0x00000000]> q
 *   This fini was called!
 */

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI static

static const RzCmdDescArg cmd_example_args[] = {
	{
		.name = "number", /// Variable name when shown when called `example?` command
		.type = RZ_CMD_ARG_TYPE_NUM, /// The parser will ensure the variable is a number.
	},
	{ 0 },
};

static const RzCmdDescHelp cmd_example_help = {
	.summary = "example summary that contains some description",
	.args = cmd_example_args,
};

RZ_IPI RzCmdStatus rz_cmd_example_handler(RzCore *core, int argc, const char **argv) {
	/* This is the handler on when `example [args]` is called. */
	if (argc != 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}

	st32 index = rz_num_math(core->num, argv[1]);
	if (index < 1) {
		RZ_LOG_ERROR("only positive numbers are accepted %d\n", index);
		return RZ_CMD_STATUS_INVALID;
	}

	RZ_LOG_WARN("the parsed number is %d\n", index);
	return RZ_CMD_STATUS_OK;
}

static bool rz_cmd_example_init(RzCore *core) {
	/* Here you can initialize any aspect of the
	 * core plugin (like allocate memory or register
	 * the core plugin on the shell or create a socket) */
	eprintf("This init was called!\n");
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		return false;
	}

	/* Here you will add your custom command and add it into the root tree. */
	RzCmdDesc *cd = rz_cmd_desc_argv_new(rcmd, root_cd, "example", rz_cmd_example_handler, &cmd_example_help);
	if (!cd) {
		rz_warn_if_reached();
		return false;
	}

	return true;
}

static bool rz_cmd_example_fini(RzCore *core) {
	/* Here you can end any aspect of the core
	 * plugin (like free allocated memory, or
	 * end sockets, etc..) */
	eprintf("This fini was called!\n");
	return true;
}

RzCorePlugin rz_core_plugin_example = {
	.name = "test",
	.desc = "description of the example core plugin",
	.license = "LGPL",
	.author = "somebody",
	.version = "1.0",
	.init = rz_cmd_example_init,
	.fini = rz_cmd_example_fini,
};

#ifdef _MSC_VER
#define _RZ_API __declspec(dllexport)
#else
#define _RZ_API
#endif

#ifndef RZ_PLUGIN_INCORE
_RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_example,
	.version = RZ_VERSION,
	.pkgname = "example_package"
};
#endif
