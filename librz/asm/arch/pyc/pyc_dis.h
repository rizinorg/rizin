// SPDX-FileCopyrightText: 2016-2020 c0riolis
// SPDX-FileCopyrightText: 2016-2020 x0urc3
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PYC_DIS_H
#define PYC_DIS_H

#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>

#include "opcode.h"

#include "../../../bin/format/pyc/marshal.h"

int rz_pyc_disasm(RzAsmOp *op, const ut8 *buf, RzList /*<py_code_objects *>*/ *cobjs, ut64 pc, pyc_opcodes *opcodes);

#endif
