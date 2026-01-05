// SPDX-FileCopyrightText: 2024 Rizin Contributors
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Minimal jemalloc structure definitions for heap parsing.
 *
 * This file contains only the struct layouts needed to parse jemalloc
 * heap dumps. It is designed to be included twice - once for 64-bit
 * and once for 32-bit - generating both arena_t_64 and arena_t_32.
 *
 * Unlike the full jemalloc headers, this file:
 * - Contains NO function declarations
 * - Contains NO inline functions
 * - Uses GHT for all pointer-sized fields
 * - Can be safely included multiple times with different GH/GHT definitions
 */

#ifndef RZ_JEMALLOC_TYPES_H
#define RZ_JEMALLOC_TYPES_H

#include <rz_types.h>

// First pass: 64-bit structures
#define GH(x)   x##_64
#define GHT     ut64
#define GHST    st64
#include <jemalloc.h>
#undef GH
#undef GHT
#undef GHST

// Second pass: 32-bit structures
#define GH(x)   x##_32
#define GHT     ut32
#define GHST    st32
#include <jemalloc.h>
#undef GH
#undef GHT
#undef GHST

#endif // RZ_JEMALLOC_TYPES_H
