// SPDX-FileCopyrightText: 2021 Pulak Malhotra <pulakmalhotra2000@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "core_private.h"

/* API calls of windows heap for Cutter */
#if __WINDOWS__
/**
 * \brief Get a list of heap blocks (Windows heap)
 * \param core RzCore Pointer
 * \return RzList of RzWindowsHeapBlock structs
 */
RZ_API RZ_OWN RzList /*<RzWindowsHeapBlock *>*/ *rz_heap_windows_blocks_list(RzCore *core) {
	return rz_heap_blocks_list(core);
}

/**
 * \brief Get a list of heaps (Windows heap)
 * \param core RzCore Pointer
 * \return RzList of RzWindowsHeapInfo structs
 */
RZ_API RZ_OWN RzList /*<RzWindowsHeapInfo *>*/ *rz_heap_windows_heap_list(RzCore *core) {
	return rz_heap_list(core);
}
#else

RZ_API RZ_OWN RzList /*<RzWindowsHeapBlock *>*/ *rz_heap_windows_blocks_list(RzCore *core) {
	return NULL;
}

RZ_API RZ_OWN RzList /*<RzWindowsHeapInfo *>*/ *rz_heap_windows_heap_list(RzCore *core) {
	return NULL;
}

#endif
