#include <rz_core.h>
RZ_IPI RzCmdStatus rz_cmd_heap_chunks_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_chunks_print_handler_64(core, argc, argv, mode);
	} else {
		return rz_cmd_heap_chunks_print_handler_32(core, argc, argv, mode);
	}
}
RZ_IPI RzCmdStatus rz_cmd_arena_print_handler(RzCore *core, int argc, const char **argv) {
	if (core->rasm->bits == 64) {
		return rz_cmd_arena_print_handler_64(core, argc, argv);
	} else {
		return rz_cmd_arena_print_handler_32(core, argc, argv);
	}
}

RZ_IPI RzCmdStatus rz_cmd_main_arena_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (core->rasm->bits == 64) {
		return rz_cmd_main_arena_print_handler_64(core, argc, argv, mode);
	} else {
		return rz_cmd_main_arena_print_handler_32(core, argc, argv, mode);
	}
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunk_print_handler(RzCore *core, int argc, const char **argv) {
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_chunk_print_handler_64(core, argc, argv);
	} else {
		return rz_cmd_heap_chunk_print_handler_32(core, argc, argv);
	}
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunks_graph_handler(RzCore *core, int argc, const char **argv) {
	// RZ_OUTPUT_MODE_LONG_JSON mode workaround for graph
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_chunks_print_handler_64(core, argc, argv, RZ_OUTPUT_MODE_LONG_JSON);
	} else {
		return rz_cmd_heap_chunks_print_handler_32(core, argc, argv, RZ_OUTPUT_MODE_LONG_JSON);
	}
}

RZ_IPI RzCmdStatus rz_cmd_heap_info_print_handler(RzCore *core, int argc, const char **argv) {
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_info_print_handler_64(core, argc, argv);
	} else {
		return rz_cmd_heap_info_print_handler_32(core, argc, argv);
	}
}

RZ_IPI RzCmdStatus rz_cmd_heap_tcache_print_handler(RzCore *core, int argc, const char **argv) {
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_tcache_print_handler_64(core, argc, argv);
	} else {
		return rz_cmd_heap_tcache_print_handler_32(core, argc, argv);
	}
}

RZ_IPI int rz_cmd_heap_bins_list_print(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_bins_list_print_64(data, input);
	} else {
		return rz_cmd_heap_bins_list_print_32(data, input);
	}
}

RZ_IPI int rz_cmd_heap_fastbins_print(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_fastbins_print_64(data, input);
	} else {
		return rz_cmd_heap_fastbins_print_32(data, input);
	}
}

RZ_IPI RzCmdStatus rz_cmd_heap_arena_bins_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	if (core->rasm->bits == 64) {
		return rz_cmd_heap_arena_bins_print_handler_64(core, argc, argv, mode);
	} else {
		return rz_cmd_heap_arena_bins_print_handler_32(core, argc, argv, mode);
	}
}