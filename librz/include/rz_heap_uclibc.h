// SPDX-FileCopyrightText: 2026 Abdallh abdallhdawi3@gmail.com
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_HEAP_UCLIBC_H
#define RZ_HEAP_UCLIBC_H

#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_types.h>

/**
 * uClibc heap free area structure.
 * Free chunks are linked in a global doubly-linked list.
 */
typedef struct heap_free_area {
	ut64 size; ///< size of the free area
	ut64 next; ///< pointer to next free area
	ut64 prev; ///< pointer to previous free area
} RzHeapFreeAreaUClibc;

RZ_IPI RzCmdStatus rz_heap_uclibc_print_handler(RzCore *core, int argc, const char **argv);

#endif // RZ_HEAP_UCLIBC_H