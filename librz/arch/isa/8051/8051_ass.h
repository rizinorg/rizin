// SPDX-FileCopyrightText: 2019 hmht
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef ASSEMBLE_8051_H
#define ASSEMBLE_8051_H

#include <rz_asm.h>

RZ_IPI int assemble_8051(RzAsmOp *op, ut64 pc, char const *user_asm);

#endif /* ASSEMBLE_8051_H */
