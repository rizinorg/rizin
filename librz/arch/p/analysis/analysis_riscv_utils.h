// SPDX-FileCopyrightText: 2024-2026 moste00 <ubermenchun@gmail.com>
// SPDX-License-Identifier: BSD-3-Clause

#ifndef ANALYSIS_RISCV_UTILS_H
#define ANALYSIS_RISCV_UTILS_H

#include <rz_types.h>
#include <capstone/capstone.h>
#include <capstone/riscv.h>

RZ_IPI ut8 riscv_operand_count(cs_insn *insn);
RZ_IPI const cs_riscv_op *riscv_operand(cs_insn *insn, ut8 n);
RZ_IPI bool riscv_operand_is(cs_insn *insn, ut8 n, riscv_op_type type);
RZ_IPI const char *riscv_reg_name(csh handle, cs_insn *insn, ut8 n);
RZ_IPI ut32 riscv_reg_id(cs_insn *insn, ut8 n);
RZ_IPI st64 riscv_imm(cs_insn *insn, ut8 n);
RZ_IPI const cs_riscv_op *riscv_memory_operand(cs_insn *insn, ut8 n);
RZ_IPI bool riscv_memory_operand_is_based_on(cs_insn *insn, ut8 n, ut32 reg);

#endif /* ANALYSIS_RISCV_UTILS_H */
