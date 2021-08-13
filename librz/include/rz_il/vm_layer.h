// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_CORE_THEORY_CMDS_H
#define RZ_IL_CORE_THEORY_CMDS_H
#include "rzil_vm.h"

// VM high level operations
RZ_API bool rz_il_vm_init(RzILVM vm, ut64 start_addr, int addr_size, int data_size);
RZ_API void rz_il_vm_close(RzILVM vm);
void rz_il_vm_step(RzILVM vm, RzILOp op);
RZ_API void rz_il_vm_list_step(RzILVM vm, RzPVector *op_list);
int rz_il_vm_printer_step(RzILOp op, char **helper);
void rz_il_vm_list_printer_step(RzPVector *op_list);

// Memory operations
RZ_API RzILMem rz_il_vm_add_mem(RzILVM vm, int min_unit_size);
RZ_API RzILBitVector rz_il_vm_mem_load(RzILVM vm, int mem_index, RzILBitVector key);
RZ_API RzILMem rz_il_vm_mem_store(RzILVM vm, int mem_index, RzILBitVector key, RzILBitVector value);

// utils
RZ_API RzILBitVector rz_il_ut64_addr_to_bv(ut64 addr);
RZ_API ut64 rz_il_bv_addr_to_ut64(RzILBitVector addr);
RZ_API void rz_il_free_bv_addr(RzILBitVector addr);
RZ_API char *rz_il_op2str(RzILOPCode opcode);

#endif // RZ_IL_CORE_THEORY_CMDS_H
