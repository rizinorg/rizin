// SPDX-FileCopyrightText: 2013-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * \file
 * Common macros for easy access of capstone arm/arm64 members when having:
 *     cs_insn *insn
 */

#include <capstone.h>

/* arm64 */
#define IMM64(x)   (ut64)(insn->detail->arm64.operands[x].imm)
#define INSOP64(x) insn->detail->arm64.operands[x]

/* arm32 */
#define REG(x)       rz_str_get_null(cs_reg_name(*handle, insn->detail->arm.operands[x].reg))
#define REG64(x)     rz_str_get_null(cs_reg_name(*handle, insn->detail->arm64.operands[x].reg))
#define REGID64(x)   insn->detail->arm64.operands[x].reg
#define REGID(x)     insn->detail->arm.operands[x].reg
#define IMM(x)       (ut32)(insn->detail->arm.operands[x].imm)
#define INSOP(x)     insn->detail->arm.operands[x]
#define MEMBASE(x)   rz_str_get_null(cs_reg_name(*handle, insn->detail->arm.operands[x].mem.base))
#define MEMBASE64(x) rz_str_get_null(cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.base))
#define REGBASE(x)   insn->detail->arm.operands[x].mem.base
#define REGBASE64(x) insn->detail->arm64.operands[x].mem.base
// s/index/base|reg/
#define MEMINDEX(x)      rz_str_get_null(cs_reg_name(*handle, insn->detail->arm.operands[x].mem.index))
#define HASMEMINDEX(x)   (insn->detail->arm.operands[x].mem.index != ARM_REG_INVALID)
#define MEMINDEX64(x)    rz_str_get_null(cs_reg_name(*handle, insn->detail->arm64.operands[x].mem.index))
#define HASMEMINDEX64(x) (insn->detail->arm64.operands[x].mem.index != ARM64_REG_INVALID)
#define ISMEMINDEXSUB(x) insn->detail->arm.operands[x].subtracted
#define MEMDISP(x)       insn->detail->arm.operands[x].mem.disp
#define MEMDISP64(x)     (ut64) insn->detail->arm64.operands[x].mem.disp
#define ISIMM(x)         (insn->detail->arm.operands[x].type == ARM_OP_IMM)
#define ISIMM64(x)       (insn->detail->arm64.operands[x].type == ARM64_OP_IMM)
#define ISREG(x)         (insn->detail->arm.operands[x].type == ARM_OP_REG)
#define ISREG64(x)       (insn->detail->arm64.operands[x].type == ARM64_OP_REG)
#define ISMEM(x)         (insn->detail->arm.operands[x].type == ARM_OP_MEM)
#define ISMEM64(x)       (insn->detail->arm64.operands[x].type == ARM64_OP_MEM)
#define EXT64(x)         decode_sign_ext(insn->detail->arm64.operands[x].ext)

#if CS_API_MAJOR > 3
#define LSHIFT(x)     insn->detail->arm.operands[x].mem.lshift
#define LSHIFT2(x)    insn->detail->arm.operands[x].shift.value // Dangerous, returns value even if isn't LSL
#define LSHIFT2_64(x) insn->detail->arm64.operands[x].shift.value
#else
#define LSHIFT(x)     0
#define LSHIFT2(x)    0
#define LSHIFT2_64(x) 0
#endif
#define OPCOUNT()     insn->detail->arm.op_count
#define OPCOUNT64()   insn->detail->arm64.op_count
#define ISSHIFTED(x)  (insn->detail->arm.operands[x].shift.type != ARM_SFT_INVALID && insn->detail->arm.operands[x].shift.value != 0)
#define SHIFTTYPE(x)  insn->detail->arm.operands[x].shift.type
#define SHIFTVALUE(x) insn->detail->arm.operands[x].shift.value

#define ISWRITEBACK32() insn->detail->arm.writeback
#define ISPREINDEX32()  (((OPCOUNT() == 2) && (ISMEM(1)) && (ISWRITEBACK32())) || ((OPCOUNT() == 3) && (ISMEM(2)) && (ISWRITEBACK32())))
#define ISPOSTINDEX32() (((OPCOUNT() == 3) && (ISIMM(2) || ISREG(2)) && (ISWRITEBACK32())) || ((OPCOUNT() == 4) && (ISIMM(3) || ISREG(3)) && (ISWRITEBACK32())))
#define ISWRITEBACK64() (insn->detail->arm64.writeback == true)
#define ISPREINDEX64()  (((OPCOUNT64() == 2) && (ISMEM64(1)) && (ISWRITEBACK64())) || ((OPCOUNT64() == 3) && (ISMEM64(2)) && (ISWRITEBACK64())))
#define ISPOSTINDEX64() (((OPCOUNT64() == 3) && (ISIMM64(2)) && (ISWRITEBACK64())) || ((OPCOUNT64() == 4) && (ISIMM64(3)) && (ISWRITEBACK64())))
