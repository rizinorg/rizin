// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_WINDOWS_HEAP_H
#define RZ_WINDOWS_HEAP_H

#include <rz_types.h>
#include <rz_list.h>
#include <rz_io.h>
#include <rz_windows/windows_heap_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __WINDOWS__
/* windows_heap_live_debug.c */
RZ_IPI RzList *rz_heap_blocks_list(RzCore *core);
RZ_IPI RzList *rz_heap_list(RzCore *core);
RZ_IPI void rz_heap_debug_block_win(RzCore *core, const char *addr, RzOutputMode mode, bool flag);
RZ_IPI void rz_heap_list_w32(RzCore *core, RzOutputMode mode);
#endif

void init_heap_config(RzCore *core, RzWindowsHeapConfig *config);
ut64 get_heap_base(RzIO *io, const RzWindowsHeapConfig *config);

RZ_OWN RzWindowsHeapInfo *rz_w32_heap_info_parse(RZ_NONNULL RzIO *io,
	ut64 heap_base, RZ_NONNULL const RzWindowsHeapConfig *config);

RZ_OWN RzList /*<RzWindowsHeapEntry *>*/ *rz_w32_heap_blocks_list(RZ_NONNULL RzIO *io,
	RZ_NONNULL const RzWindowsHeapInfo *heap_info, RZ_NONNULL const RzWindowsHeapConfig *config);

#ifdef __cplusplus
}
#endif

#endif /* RZ_WINDOWS_HEAP_H */
