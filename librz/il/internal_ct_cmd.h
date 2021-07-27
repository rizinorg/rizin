#ifndef BUILD_CORE_THEORY_CMDS_H
#define BUILD_CORE_THEORY_CMDS_H
#include "core_theory_vm.h"

// VM high level operations
RZ_API void rz_il_vm_init(RzILVM vm, ut64 start_addr, int addr_size, int data_size);
RZ_API void rz_il_vm_close(RzILVM vm);
void rz_il_vm_step(RzILVM vm, RzILOp op);
RZ_API void rz_il_vm_list_step(RzILVM vm, RzPVector *op_list);
int rz_il_vm_printer_step(RzILOp op, string *helper);
void rz_il_vm_list_printer_step(RzPVector *op_list);

// Memory operations
RZ_API Mem rz_il_vm_add_mem(RzILVM vm, int min_unit_size);
RZ_API BitVector rz_il_vm_mem_load(RzILVM vm, int mem_index, BitVector key);
RZ_API Mem rz_il_vm_mem_store(RzILVM vm, int mem_index, BitVector key, BitVector value);

// utils
RZ_API BitVector rz_il_ut64_addr_to_bv(ut64 addr);
RZ_API ut64 rz_il_bv_addr_to_ut64(BitVector addr);
RZ_API void rz_il_free_bv_addr(BitVector addr);

#endif //BUILD_CORE_THEORY_CMDS_H
