#ifndef BUILD_CORE_THEORY_CMDS_H
#define BUILD_CORE_THEORY_CMDS_H
#include "core_theory_vm.h"

// VM high level operations
void rz_il_vm_init(RzILVM vm, ut64 start_addr, int addr_size, int data_size);
void rz_il_vm_close(RzILVM vm);
void rz_il_vm_step(RzILVM vm, RzILOp op);
void rz_il_vm_list_step(RzILVM vm, RzPVector *op_list);
int rz_il_vm_printer_step(RzILOp op, string *helper);
void rz_il_vm_list_printer_step(RzPVector *op_list);

#endif //BUILD_CORE_THEORY_CMDS_H
