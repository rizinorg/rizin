// SPDX-FileCopyrightText: 2026 jemalloc <https://jemalloc.net/>
// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JEMALLOC_ARCH_H
#define RZ_JEMALLOC_ARCH_H

#include <rz_util.h>

typedef enum {
	RZ_JEMALLOC_ARCH_UNKNOWN = 0,
	RZ_JEMALLOC_ARCH_I386,
	RZ_JEMALLOC_ARCH_AMD64,
	RZ_JEMALLOC_ARCH_ARM32,
	RZ_JEMALLOC_ARCH_AARCH64,
	RZ_JEMALLOC_ARCH_RISCV32,
	RZ_JEMALLOC_ARCH_RISCV64,
} RzJemallocArch;

/**
 * Log2 of page size values
 */
typedef enum {
	RZ_JEMALLOC_PAGE_4K = 12,
	RZ_JEMALLOC_PAGE_16K = 14,
	RZ_JEMALLOC_PAGE_64K = 16,
} RzJemallocPageSize;

static inline const char *rz_jemalloc_page_size_name(ut8 lg_page) {
	switch (lg_page) {
	case 12:
		return "4KB";
	case 14:
		return "16KB";
	case 16:
		return "64KB";
	default:
		return "Unknown";
	}
}

#endif // RZ_JEMALLOC_ARCH_H
