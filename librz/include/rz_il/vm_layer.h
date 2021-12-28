// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_VM_LAYER_H
#define RZ_IL_VM_LAYER_H
#include <rz_il/rzil_vm.h>
#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

// VM high level operations
RZ_API RzILVM *rz_il_vm_new(ut64 start_addr, ut32 addr_size, bool big_endian);
RZ_API void rz_il_vm_free(RzILVM *vm);
RZ_API bool rz_il_vm_init(RzILVM *vm, ut64 start_addr, ut32 addr_size, bool big_endian);
RZ_API void rz_il_vm_fini(RzILVM *vm);
RZ_API void rz_il_vm_add_mem(RzILVM *vm, RzILMemIndex index, RZ_OWN RzILMem *mem);
RZ_API RzILMem *rz_il_vm_get_mem(RzILVM *vm, RzILMemIndex index);
RZ_API bool rz_il_vm_list_step(RzILVM *vm, RzILOpEffect *op, ut32 op_size);

// VM Event operations
RZ_API void rz_il_vm_event_add(RzILVM *vm, RzILEvent *evt);

// Memory operations
RZ_API RzBitVector *rz_il_vm_mem_load(RzILVM *vm, RzILMemIndex index, RzBitVector *key);
RZ_API void rz_il_vm_mem_store(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value);
RZ_API RzBitVector *rz_il_vm_mem_loadw(RzILVM *vm, RzILMemIndex index, RzBitVector *key, ut32 n_bits);
RZ_API void rz_il_vm_mem_storew(RzILVM *vm, RzILMemIndex index, RzBitVector *key, RzBitVector *value);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_VM_LAYER_H
