// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Common macros for easy access of capstone arm64 members when having:
 *     cs_insn *insn
 */

#include <capstone/capstone.h>

#define IMM64(x)   (ut64)(insn->detail->CS_aarch64().operands[x].imm)
#define INSOP64(x) insn->detail->CS_aarch64().operands[x]

#define REGID64(x)   insn->detail->CS_aarch64().operands[x].reg
#define REGBASE64(x) insn->detail->CS_aarch64().operands[x].mem.base
// s/index/base|reg/
#define HASMEMINDEX64(x) (insn->detail->CS_aarch64().operands[x].mem.index != CS_AARCH64(_REG_INVALID))
#define MEMDISP64(x)     (ut64) insn->detail->CS_aarch64().operands[x].mem.disp
#define ISIMM64(x)       (insn->detail->CS_aarch64().operands[x].type == CS_AARCH64(_OP_IMM))
#define ISREG64(x)       (insn->detail->CS_aarch64().operands[x].type == CS_AARCH64(_OP_REG))
#define ISMEM64(x)       (insn->detail->CS_aarch64().operands[x].type == CS_AARCH64(_OP_MEM))

#define LSHIFT2_64(x) insn->detail->CS_aarch64().operands[x].shift.value
#define OPCOUNT64()   insn->detail->CS_aarch64().op_count

#if CS_NEXT_VERSION < 6
#define ISWRITEBACK64() (insn->detail->arm64.writeback == true)
#else
#define ISWRITEBACK64() (insn->detail->writeback == true)
#endif
#define ISPREINDEX64()  (((OPCOUNT64() == 2) && (ISMEM64(1)) && (ISWRITEBACK64())) || ((OPCOUNT64() == 3) && (ISMEM64(2)) && (ISWRITEBACK64())))
#define ISPOSTINDEX64() (((OPCOUNT64() == 3) && (ISIMM64(2)) && (ISWRITEBACK64())) || ((OPCOUNT64() == 4) && (ISIMM64(3)) && (ISWRITEBACK64())))
