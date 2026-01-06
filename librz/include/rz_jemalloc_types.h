// SPDX-FileCopyrightText: 2026 bubblepipe <bubblepipe42@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JEMALLOC_TYPES_H
#define RZ_JEMALLOC_TYPES_H

#include <rz_types.h>

// First pass: 64-bit structures
#define GH(x) x##_64
#define GHT   ut64
#define GHST  st64
#include <jemalloc.h>
#undef GH
#undef GHT
#undef GHST

// Second pass: 32-bit structures
#define GH(x) x##_32
#define GHT   ut32
#define GHST  st32
#include <jemalloc.h>
#undef GH
#undef GHT
#undef GHST

#endif // RZ_JEMALLOC_TYPES_H
