// SPDX-FileCopyrightText: 2022 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PPC_ANALYSIS_H
#define PPC_ANALYSIS_H

#define PPC_DETAIL(insn) insn->detail->ppc
#define INSOP(n)         insn->detail->ppc.operands[n]
#define OP_CNT           insn->detail->ppc.op_count
#define IMM(x)           (ut64)(insn->detail->ppc.operands[x].imm)

#define PPC_IN_BE_MODE (mode & CS_MODE_BIG_ENDIAN)
// Capstone does not extract the BO or BI fields of instructions. So we do it manually.
#define PPC_READ_BO_FIELD (((rz_read_ble32(insn->bytes, PPC_IN_BE_MODE)) & 0x03e00000) >> 21)
#define PPC_READ_BI_FIELD (((rz_read_ble32(insn->bytes, PPC_IN_BE_MODE)) & 0x001f0000) >> 16)
#define IN_BE_MODE        (mode & CS_MODE_BIG_ENDIAN)
#define IN_64BIT_MODE     (mode & CS_MODE_64)
#define PPC_ARCH_BITS     (IN_64BIT_MODE ? 64 : 32)

#endif /* PPC_ANALYSIS_H */