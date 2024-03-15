// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RISCV_INC_H
#define RISCV_INC_H

#include <rz_asm.h>

int riscv_dis(RzAsm *a, RzAsmOp *rop, const ut8 *buf, ut64 len);

#endif /* RISCV_INC_H */