#include <rz_core.h>
#define call_handler(fun, ...) \
	{ \
		if (core->rasm->bits == 64) { \
			return fun##_64(core, ##__VA_ARGS__); \
		} else { \
			return fun##_32(core, ##__VA_ARGS__); \
		} \
	}
RZ_IPI RzCmdStatus rz_cmd_heap_chunks_print_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state) {
	call_handler(rz_cmd_heap_chunks_print_handler, argc, argv, state);
}

RZ_IPI RzCmdStatus rz_cmd_arena_print_handler(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_arena_print_handler, argc, argv);
}

RZ_IPI RzCmdStatus rz_cmd_main_arena_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	call_handler(rz_cmd_main_arena_print_handler, argc, argv, mode);
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunk_print_handler(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_heap_chunk_print_handler, argc, argv);
}

RZ_IPI RzCmdStatus rz_cmd_heap_chunks_graph_handler(RzCore *core, int argc, const char **argv) {
	// RZ_OUTPUT_MODE_LONG_JSON mode workaround for graph
	RzCmdStateOutput state = { 0 };
	state.mode = RZ_OUTPUT_MODE_LONG_JSON;
	call_handler(rz_cmd_heap_chunks_print_handler, argc, argv, &state);
}

RZ_IPI RzCmdStatus rz_cmd_heap_info_print_handler(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_heap_info_print_handler, argc, argv);
}

RZ_IPI RzCmdStatus rz_cmd_heap_tcache_print_handler(RzCore *core, int argc, const char **argv) {
	call_handler(rz_cmd_heap_tcache_print_handler, argc, argv);
}

RZ_IPI int rz_cmd_heap_bins_list_print(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	call_handler(rz_cmd_heap_bins_list_print, input);
}

RZ_IPI int rz_cmd_heap_fastbins_print(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	call_handler(rz_cmd_heap_fastbins_print, input);
}

RZ_IPI RzCmdStatus rz_cmd_heap_arena_bins_print_handler(RzCore *core, int argc, const char **argv, RzOutputMode mode) {
	call_handler(rz_cmd_heap_arena_bins_print_handler, argc, argv, mode);
}

/* API functions for Heap Viewer in Cutter */

RZ_API RzList *rz_heap_arenas_list(RzCore *core) {
	call_handler(rz_heap_arena_list_wrapper);
}

RZ_API RzList *rz_heap_chunks_list(RzCore *core, ut64 m_arena) {
	call_handler(rz_heap_chunks_list_wrapper, m_arena);
}

RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr) {
	call_handler(rz_heap_chunk_wrapper, addr);
}