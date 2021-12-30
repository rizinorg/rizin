// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZIL_REG_H
#define RZIL_REG_H

#include <rz_reg.h>

typedef struct rz_il_reg_binding_item_t {
	char *name; ///< name of both the register and the variable that binds to it
	ut32 size; ///< number of bits of the register and variable
} RzILRegBindingItem;

/**
 * An object that describes what registers are bound to variables in an RzILVM.
 */
typedef struct rz_il_reg_binding_t {
	size_t regs_count;
	RzILRegBindingItem *regs; ///< regs_count registers that are bound to variables
} RzILRegBinding;

struct rz_il_vm_t;

RZ_API RzILRegBinding *rz_il_reg_binding_derive(RZ_NONNULL RzReg *reg);
RZ_API RzILRegBinding *rz_il_reg_binding_exactly(RZ_NONNULL RzReg *reg, size_t regs_count, RZ_NONNULL RZ_BORROW const char **regs);
RZ_API void rz_il_reg_binding_free(RzILRegBinding *rb);

RZ_API void rz_il_vm_setup_reg_binding(RZ_NONNULL struct rz_il_vm_t *vm, RZ_NONNULL RZ_OWN RzILRegBinding *rb);
RZ_API bool rz_il_vm_sync_to_reg(RZ_NONNULL struct rz_il_vm_t *vm, RZ_NONNULL RzReg *reg);
RZ_API void rz_il_vm_sync_from_reg(RZ_NONNULL struct rz_il_vm_t *vm, RZ_NONNULL RzReg *reg);

#endif
