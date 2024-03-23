// SPDX-FileCopyrightText: 2024 rockrid3r <rockrid3r@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_core.h>
#include <rz_heap_glibc.h>
#include "cmd_descs.h"
#include "../linux_heap_slub.h"
#include "../linux_heap_slub64.h"

#define call_handler(fun, ...) \
	{ \
		if (core->rasm->bits == 64) { \
			return fun##_64(core, ##__VA_ARGS__); \
		} else { \
			return fun##_32(core, ##__VA_ARGS__); \
		} \
	}

RZ_IPI RzCmdStatus rz_cmd_debug_slub_dump_lockless_freelist_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	call_handler(rz_cmd_debug_slub_dump_lockless_freelist_handler, argc, argv, output_state);
}

RZ_IPI RzCmdStatus rz_cmd_debug_slub_dump_regular_freelist_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	call_handler(rz_cmd_debug_slub_dump_regular_freelist_handler, argc, argv, output_state);
}

RZ_IPI RzCmdStatus rz_cmd_debug_slub_dump_partial_freelist_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	call_handler(rz_cmd_debug_slub_dump_partial_freelist_handler, argc, argv, output_state);
}

RZ_IPI RzCmdStatus rz_cmd_debug_slub_dump_node_freelist_handler(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state) {
	call_handler(rz_cmd_debug_slub_dump_node_freelist_handler, argc, argv, output_state);
}