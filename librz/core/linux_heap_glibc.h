// SPDX-FileCopyrightText: 2021 ret2libc <rschirone91@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_types.h>

#undef GH
#undef GHT
#undef GHT_MAX
#undef GHT_MIN
#undef read_le

#if HEAP64
#define GH(x)      x##_64
#define GHT        ut64
#define GHT_MAX    UT64_MAX
#define GHT_MIN    UT64_MIN
#define read_le(x) rz_read_le##64(x)
#else
#define GH(x)      x##_32
#define GHT        ut32
#define GHT_MAX    UT32_MAX
#define GHT_MIN    UT32_MIN
#define read_le(x) rz_read_le##32(x)
#endif

RZ_IPI RzCmdStatus GH(rz_cmd_arena_print_handler)(RzCore *core, int argc, const char **argv);
RZ_IPI RzCmdStatus GH(rz_cmd_heap_chunks_print_handler)(RzCore *core, int argc, const char **argv, RzCmdStateOutput *state);
RZ_IPI RzCmdStatus GH(rz_cmd_main_arena_print_handler)(RzCore *core, int argc, const char **argv, RzOutputMode mode);
RZ_IPI RzCmdStatus GH(rz_cmd_heap_chunk_print_handler)(RzCore *core, int argc, const char **argv);
RZ_IPI RzCmdStatus GH(rz_cmd_heap_info_print_handler)(RzCore *core, int argc, const char **argv);
RZ_IPI RzCmdStatus GH(rz_cmd_heap_tcache_print_handler)(RzCore *core, int argc, const char **argv);
RZ_IPI RzCmdStatus GH(rz_cmd_heap_arena_bins_print_handler)(RzCore *core, int argc, const char **argv, RzOutputMode mode);