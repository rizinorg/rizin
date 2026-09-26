// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef RZ_ARCH_P_ANALYSIS_RISCV_CS_H
#define RZ_ARCH_P_ANALYSIS_RISCV_CS_H

#include <capstone/capstone.h>
#include <capstone/riscv.h>
#include <rz_types.h>

ut8 riscv_operand_count(cs_insn *insn);
const cs_riscv_op *riscv_operand(cs_insn *insn, ut8 n);
bool riscv_operand_is(cs_insn *insn, ut8 n, riscv_op_type type);
const char *riscv_reg_name(csh handle, cs_insn *insn, ut8 n);
ut32 riscv_reg_id(cs_insn *insn, ut8 n);
st64 riscv_imm(cs_insn *insn, ut8 n);
const cs_riscv_op *riscv_memory_operand(cs_insn *insn, ut8 n);
bool riscv_memory_operand_is_based_on(cs_insn *insn, ut8 n, ut32 reg);

#endif // RZ_ARCH_P_ANALYSIS_RISCV_CS_H
