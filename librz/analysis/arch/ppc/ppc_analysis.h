// SPDX-FileCopyrightText: 2022 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PPC_ANALYSIS_H
#define PPC_ANALYSIS_H

#define INSOPS   insn->detail->ppc.op_count
#define INSOP(n) insn->detail->ppc.operands[n]
#define IMM(x)   (ut64)(insn->detail->ppc.operands[x].imm)

#define IN_64BIT_MODE (mode & CS_MODE_64)
#define PPC_ARCH_BITS (IN_64BIT_MODE ? 64 : 32)

#endif /* PPC_ANALYSIS_H */