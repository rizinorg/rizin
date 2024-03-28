// SPDX-FileCopyrightText: 2024 rockrid3r <rockrid3r@outlook.com>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Provides interface for dumping SLUB cmd handlers.
 */

#include <rz_core.h>

#undef GH
#undef GH_
#undef GHT
#undef GHT_MAX
#undef GHFMTx
#undef read_le

#ifdef KHEAP64

#define GH_(x)     x##_64
#define GH(x)      x##64
#define GHT        ut64
#define GHT_MAX    UT64_MAX
#define read_le(x) rz_read_le##64(x)
#define GHFMTx     PFMT64x

#else

#define GH_(x)     x##_32
#define GH(x)      x##32
#define GHT        ut32
#define GHT_MAX    UT32_MAX
#define read_le(x) rz_read_le##32(x)
#define GHFMTx     PFMT32x

#endif

RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_lockless_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state);
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_regular_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state);
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_partial_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state);
RZ_IPI RzCmdStatus GH_(rz_cmd_debug_slub_dump_node_freelist_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *output_state);