// SPDX-License-Identifier: LGPL-3.0-only
#if 0
gcc -o core_plugin_example.so -O3 -std=c99 -Wall -fPIC `pkg-config --cflags --libs rz_core` core_plugin_example.c -shared
mkdir -p ~/.config/rizin/plugins
mv core_plugin_example.so ~/.config/rizin/plugins
#endif

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <string.h>
#include <rz_analysis.h>

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI static

static const RzCmdDescHelp example_usage = {
	.summary = "Example core plugin",
};

RZ_IPI RzCmdStatus rz_cmd_example_handler(RzCore *core, int argc,
	const char **argv) {
	if (argc < 2) {
		return RZ_CMD_STATUS_WRONG_ARGS;
	}
	eprintf("This example was called!\n")
	return RZ_CMD_STATUS_OK;
}

static bool rz_cmd_example_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}
	/* Here you can initialize any aspect of the
	 * core plugin (like allocate memory or register
	 * the core plugin on rzshell or create a socket) */
	eprintf("This init was called!\n");

	RzCmdDesc *example = rz_cmd_desc_argv_new(rcmd, root_cd, "example",
		rz_cmd_example_handler, &example_usage);
	if (!example) {
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
