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

static int rz_cmd_example_init(void *user /* RzCmd* */, const char *unused /* unused during init */) {
	RzCmd *cmd = (RzCmd *)user;
	(void)cmd;
	/* Here you can initialize any aspect of the
	 * core plugin (like allocate memory or register
	 * the core plugin on newshell or create a socket) */
	eprintf("This init was called!\n");
	return true;
}

static int rz_cmd_example_call(void *user /* RzCmd* */, const char *args) {
	/* This call is used by the old shell */
	eprintf("This command was called!\n");
	return false;
}

static int rz_cmd_example_fini(void *user /* RzCmd* */, const char *unused /* unused during fini */) {
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
	.call = rz_cmd_example_call,
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
