// SPDX-License-Identifier: LGPL-3.0-only
#if 0
gcc -o core_test.so -fPIC `pkg-config --cflags --libs rz_core` core_test.c -shared
mkdir -p ~/.config/rizin/plugins
mv core_test.so ~/.config/rizin/plugins
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

static int rz_cmd_test_call(void) {
	eprintf("Dummy!\n");
	return false;
}

RzCorePlugin rz_core_plugin_test = {
	.name = "test",
	.desc = "lalallala",
	.license = "MIT",
	.call = rz_cmd_test_call,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_test,
	.version = RZ_VERSION
};
#endif
