

#include <rz_core.h>
#define call_handler(fun, ...) \
	{ \
		if (core->rasm->bits == 64) { \
			return fun##_64(core, ##__VA_ARGS__); \
		} else { \
			return fun##_32(core, ##__VA_ARGS__); \
		} \
	}

RZ_IPI RzCmdStatus rz_cmd_jemalloc_print_narenas_handler(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_jemalloc_print_narenas_handler, argc, argv);
}

Rz_IPI RzCmdStatus rz_cmd_jemalloc_get_bins(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_jemalloc_get_bins, argc, argv);
}

Rz_IPI RzCmdStatus rz_cmd_jemalloc_get_chunks(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_jemalloc_get_chunks, argc, argv);
}