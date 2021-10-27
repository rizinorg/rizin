// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VM_LAYER_H
#define RZ_IL_VM_LAYER_H
#include <rz_il/rzil_vm.h>

#ifdef __cplusplus
extern "C" {
#endif

// VM high level operations
RZ_API RzILVM *rz_il_vm_new(ut64 start_addr, ut32 addr_size, ut32 data_size);
RZ_API void rz_il_vm_free(RzILVM *vm);
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, ut32 data_size);
RZ_API void rz_il_vm_fini(RzILVM *vm);
RZ_API void rz_il_vm_step(RzILVM *vm, RzILOp *root);
RZ_API void rz_il_vm_list_step(RzILVM *vm, RzPVector *op_list, ut32 op_size);

// Memory operations
RZ_API RzILMem *rz_il_vm_add_mem(RzILVM *vm, ut32 min_unit_size);
RZ_API RzILBitVector *rz_il_vm_mem_load(RzILVM *vm, ut32 mem_index, RzILBitVector *key);
RZ_API RzILMem *rz_il_vm_mem_store(RzILVM *vm, ut32 mem_index, RzILBitVector *key, RzILBitVector *value);

// utils
RZ_API RzILBitVector *rz_il_ut64_addr_to_bv(ut64 addr);
RZ_API ut64 rz_il_bv_addr_to_ut64(RzILBitVector *addr);
RZ_API void rz_il_free_bv_addr(RzILBitVector *addr);
RZ_API char *rz_il_op2str(RzILOPCode opcode);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VM_LAYER_H
