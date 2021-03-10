// SPDX-License-Identifier: LGPL-3.0-only
// SPDX-FileCopyrightText: 2021 Heersin <teablearcher@gmail.com>


#ifndef BUILD_LUAC_DIS_H
#define BUILD_LUAC_DIS_H

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "opcode.h"

int luac_disasm(RzAsm *a, RzAsmOp *opstruct, const ut8 *buf, int len);


#endif //BUILD_LUAC_DIS_H
