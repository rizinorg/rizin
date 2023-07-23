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
#define FPIMM(x)   (double)(insn->detail->arm.operands[x].fp)
#define INSOP(x)   insn->detail->arm.operands[x]
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
// s/index/base|reg/
#define HASMEMINDEX(x)   (insn->detail->arm.operands[x].mem.index != ARM_REG_INVALID)
#define ISMEMINDEXSUB(x) insn->detail->arm.operands[x].subtracted
#define MEMDISP(x)       (ISMEMINDEXSUB(x) ? -insn->detail->arm.operands[x].mem.disp : insn->detail->arm.operands[x].mem.disp)
#define MEMDISP_BV(x)    (HASMEMINDEX(x) ? REG_VAL(insn->detail->arm.operands[x].mem.index) : U32(MEMDISP(x)))
#define ISIMM(x)         (insn->detail->arm.operands[x].type == ARM_OP_IMM || insn->detail->arm.operands[x].type == ARM_OP_FP)
#define ISREG(x)         (insn->detail->arm.operands[x].type == ARM_OP_REG)
#define ISPSRFLAGS(x)    (insn->detail->arm.operands[x].type == ARM_OP_CPSR || insn->detail->arm.operands[x].type == ARM_OP_SPSR)
#define ISMEM(x)         (insn->detail->arm.operands[x].type == ARM_OP_MEM)
#define ISFPIMM(x)       (insn->detail->arm.operands[x].type == ARM_OP_FP)

#if CS_API_MAJOR > 3
#define LSHIFT(x)  insn->detail->arm.operands[x].mem.lshift
#define LSHIFT2(x) insn->detail->arm.operands[x].shift.value // Dangerous, returns value even if isn't LSL
#else
#define LSHIFT(x)  0
#define LSHIFT2(x) 0
#endif
#define OPCOUNT()       insn->detail->arm.op_count
#define ISSHIFTED(x)    (insn->detail->arm.operands[x].shift.type != ARM_SFT_INVALID && insn->detail->arm.operands[x].shift.value != 0)
#define SHIFTTYPE(x)    insn->detail->arm.operands[x].shift.type
#define SHIFTTYPEREG(x) (SHIFTTYPE(x) == ARM_SFT_ASR_REG || SHIFTTYPE(x) == ARM_SFT_LSL_REG || \
	SHIFTTYPE(x) == ARM_SFT_LSR_REG || SHIFTTYPE(x) == ARM_SFT_ROR_REG || \
	SHIFTTYPE(x) == ARM_SFT_RRX_REG)
#define SHIFTVALUE(x) insn->detail->arm.operands[x].shift.value

#define ISPOSTINDEX()   insn->detail->arm.post_index
#define ISWRITEBACK32() insn->detail->writeback
#define ISPREINDEX32()  (((OPCOUNT() == 2) && (ISMEM(1)) && (ISWRITEBACK32()) && (!ISPOSTINDEX())) || \
	((OPCOUNT() == 3) && (ISMEM(2)) && (ISWRITEBACK32()) && (!ISPOSTINDEX())))
