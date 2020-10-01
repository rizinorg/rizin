#include <rz_lib.h>

int mystuff = 31337;

struct rz_lib_struct_t radare_plugin = {
	.type = 1,
	.data = &mystuff,
	.version = R2_VERSION
};
