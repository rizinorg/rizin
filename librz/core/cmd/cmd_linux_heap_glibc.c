// SPDX-FileCopyrightText: 2021 Pulak Malhotra <pulakmalhotra2000@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_core.h>
#include <rz_heap_glibc.h>
#include "cmd_descs.h"
#include "../linux_heap_glibc.h"
#include "../linux_heap_glibc64.h"

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
	if (!rz_cmd_state_output_init(&state, RZ_OUTPUT_MODE_LONG)) {
		return RZ_CMD_STATUS_ERROR;
	}
	RzCmdStatus res;
	if (core->rasm->bits == 64) {
		res = rz_cmd_heap_chunks_print_handler_64(core, argc, argv, &state);
	} else {
		res = rz_cmd_heap_chunks_print_handler_32(core, argc, argv, &state);
	}
	rz_cmd_state_output_print(&state);
	rz_cmd_state_output_fini(&state);
	return res;
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

/**
 * \brief Returns RzList* for a list of arenas. Each arena is represented by RzArenaListItem struct
 * \param core RzCore pointer
 * \return RzList of arenas
 */
RZ_API RzList *rz_heap_arenas_list(RzCore *core) {
	call_handler(rz_heap_arena_list_wrapper);
}

/**
 * \brief Returns RzList* for a list of chunks from the arena. Each chunk is represented by RzHeapChunkListItem struct
 * \param core RzCore pointer
 * \param m_arena Base Address of the arena
 * \return RzList of heap chunks
 */
RZ_API RzList *rz_heap_chunks_list(RzCore *core, ut64 m_arena) {
	call_handler(rz_heap_chunks_list_wrapper, m_arena);
}

/**
 * \brief Returns detailed information about a heap chunk. The chunk is represented by RzHeapChunkSimple struct
 * \param core RzCore pointer
 * \param addr Base address of the heap chunk
 * \return RzHeapChunkSimple struct pointer for the chunk
 */
RZ_API RzHeapChunkSimple *rz_heap_chunk(RzCore *core, ut64 addr) {
	call_handler(rz_heap_chunk_wrapper, addr);
}

/**
 * \brief Returns information about a heap bin. The information is represented as RzHeapBin struct
 * The bins covered by this are unsorted, small and large bins Bin num is zero indexed i.e unsorted bin starts from number 0
 * \param core RzCore pointer
 * \param arena Malloc state struct for the arena
 * \param bin_num Bin number from NBINS array
 * \return RzHeapBin struct for the bin
 */
RZ_API RzHeapBin *rz_heap_bin_content(RzCore *core, MallocState *arena, int bin_num, ut64 m_arena) {
	call_handler(rz_heap_bin_content, arena, bin_num, m_arena);
}

/**
 * \brief Returns information about a fastbin. The information is represented as RzHeapBin struct.
 * \param core RzCore pointer
 * \param arena Malloc state struct for the arena
 * \param bin_num Bin number from Fastbins array
 * \return RzHeapBin struct for the bin
 */
RZ_API RzHeapBin *rz_heap_fastbin_content(RzCore *core, MallocState *arena, int bin_num) {
	call_handler(rz_heap_fastbin_content, arena, bin_num);
}

/**
 * \brief Returns MallocState struct for given base address of the arena.
 * This function checks if the arena is valid and then returns the MallocState.
 * If the base address provided is zero it returns the malloc state for the main arena
 * \param core RzCore pointer
 * \param m_state Base address of the arena
 * \return MallocState struct for the arena
 */
RZ_API MallocState *rz_heap_get_arena(RzCore *core, ut64 m_state) {
	call_handler(rz_heap_get_arena, m_state);
}

/**
 * \brief Get a list of bins for the tcache associated with an arena
 * The list is in form of RzList and the bins are of the form of RzHeapBin
 * Arena has the base address arena_base
 * \param core RzCore pointer
 * \param arena_base Base address of the arena
 * \return RzList of RzHeapBin pointers
 */
RZ_API RzList *rz_heap_tcache_content(RzCore *core, ut64 arena_base) {
	call_handler(rz_heap_tcache_content, arena_base);
}

/**
 * \brief Write a heap chunk header to memory
 * \param core RzCore pointer
 * \param chunk_simple RzHeapChunkSimple pointer to the heap chunk data
 * \return bool if the write succeeded or not
 */
RZ_API bool rz_heap_write_chunk(RzCore *core, RzHeapChunkSimple *chunk_simple) {
	call_handler(rz_heap_write_heap_chunk, chunk_simple);
}
