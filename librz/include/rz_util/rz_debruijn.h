// SPDX-FileCopyrightText: 2014 crowell <crowell@bu.edu>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DEBRUIJN_H
#define RZ_DEBRUIJN_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// For information about the algorithm, see Joe Sawada and Frank Ruskey, "An
// Efficient Algorithm for Generating Necklaces with Fixed Density"

// Generate a cyclic pattern of desired size, and charset, return with starting
// offset of start.
// The returned string is malloced, and it is the responsibility of the caller
// to free the memory.
RZ_API char *rz_debruijn_pattern(int size, int start, const char *charset);

// Finds the offset of a given value in a cyclic pattern of an integer.
RZ_API int rz_debruijn_offset(ut64 value, bool is_big_endian);

#ifdef __cplusplus
}
#endif

#endif // RZ_DEBRUIJN_H
