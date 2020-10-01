/* radare - LGPL - Copyright 2014 - pancake */
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
#include <rz_anal.h>

#undef RZ_API
#define RZ_API static
#undef R_IPI
#define R_IPI static

static int rz_cmd_test_call(void) {
	eprintf ("Dummy!\n");
	return false;
}

RzCorePlugin rz_core_plugin_test = {
	.name = "test",
	.desc = "lalallala",
	.license = "MIT",
	.call = rz_cmd_test_call,
};

#ifndef R2_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &rz_core_plugin_test,
	.version = R2_VERSION
};
#endif
