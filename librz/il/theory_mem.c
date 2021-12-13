// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>
#include <rz_il/rzil_opcodes.h>
#include <rz_il/vm_layer.h>

void *rz_il_handler_load(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpLoad *op_load = op->op.load;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_load->key, type);
	RzBitVector *ret = rz_il_vm_mem_load(vm, op_load->mem, addr);
	if (ret == NULL) {
		// empty address --> first access
		// assume it's empty
		rz_il_vm_mem_store_zero(vm, op_load->mem, addr, &ret);
	}

	rz_bv_free(addr);
	*type = RZIL_OP_ARG_BITV;
	return ret;
}

void *rz_il_handler_store(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpStore *op_store = op->op.store;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_store->key, type);
	RzBitVector *value = rz_il_evaluate_bitv(vm, op_store->value, type);

	RzILMem *m = rz_il_vm_mem_store(vm, op_store->mem, addr, value);
	rz_bv_free(addr);
	rz_bv_free(value);

	*type = RZIL_OP_ARG_MEM;
	return m;
}
