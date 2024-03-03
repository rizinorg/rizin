// SPDX-FileCopyrightText: 2013-2021 th0rpe <josediazfer@yahoo.es>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef INS_H
#define INS_H

#include <rz_types.h>
#include "utils.h"

// instruction length
ut32 get_ins_len(ut8 opcode);

// gets instruction bytes from a position
ut32 get_ins_part(ut32 pos, ut32 len);

#endif
