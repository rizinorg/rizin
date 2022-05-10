// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Common macros for easy access of capstone arm (32) members when having:
 *     cs_insn *insn
 */

#include <capstone/capstone.h>

#define REGID(x)   insn->detail->arm.operands[x].reg
#define IMM(x)     (ut32)(insn->detail->arm.operands[x].imm)
#define INSOP(x)   insn->detail->arm.operands[x]
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
// s/index/base|reg/
#define HASMEMINDEX(x)   (insn->detail->arm.operands[x].mem.index != ARM_REG_INVALID)
#define ISMEMINDEXSUB(x) insn->detail->arm.operands[x].subtracted
#define MEMDISP(x)       insn->detail->arm.operands[x].mem.disp
#define ISIMM(x)         (insn->detail->arm.operands[x].type == ARM_OP_IMM)
#define ISREG(x)         (insn->detail->arm.operands[x].type == ARM_OP_REG)
#define ISMEM(x)         (insn->detail->arm.operands[x].type == ARM_OP_MEM)

#if CS_API_MAJOR > 3
#define LSHIFT(x)  insn->detail->arm.operands[x].mem.lshift
#define LSHIFT2(x) insn->detail->arm.operands[x].shift.value // Dangerous, returns value even if isn't LSL
#else
#define LSHIFT(x)  0
#define LSHIFT2(x) 0
#endif
#define OPCOUNT()     insn->detail->arm.op_count
#define ISSHIFTED(x)  (insn->detail->arm.operands[x].shift.type != ARM_SFT_INVALID && insn->detail->arm.operands[x].shift.value != 0)
#define SHIFTTYPE(x)  insn->detail->arm.operands[x].shift.type
#define SHIFTVALUE(x) insn->detail->arm.operands[x].shift.value

#define ISWRITEBACK32() insn->detail->arm.writeback
#define ISPREINDEX32()  (((OPCOUNT() == 2) && (ISMEM(1)) && (ISWRITEBACK32())) || ((OPCOUNT() == 3) && (ISMEM(2)) && (ISWRITEBACK32())))
#define ISPOSTINDEX32() (((OPCOUNT() == 3) && (ISIMM(2) || ISREG(2)) && (ISWRITEBACK32())) || ((OPCOUNT() == 4) && (ISIMM(3) || ISREG(3)) && (ISWRITEBACK32())))
