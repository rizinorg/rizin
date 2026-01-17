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

RZ_API RZ_OWN char *rz_debruijn_pattern(int size, int start, const char *charset);
RZ_API int rz_debruijn_offset(int start, const char *charset, ut64 value, bool is_big_endian);

#ifdef __cplusplus
}
#endif

#endif // RZ_DEBRUIJN_H
