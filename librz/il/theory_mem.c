// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>
#include <rz_il/rzil_opcodes.h>
#include <rz_il/vm_layer.h>

void *rz_il_handler_load(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsLoad *op_load = op->op.load;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_load->key, type);
	RzBitVector *ret = rz_il_vm_mem_load(vm, op_load->mem, addr);
	rz_bv_free(addr);
	*type = RZIL_OP_ARG_BITV;
	return ret;
}

void *rz_il_handler_store(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsStore *op_store = op->op.store;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_store->key, type);
	RzBitVector *value = rz_il_evaluate_bitv(vm, op_store->value, type);

	rz_il_vm_mem_store(vm, op_store->mem, addr, value);
	rz_bv_free(addr);
	rz_bv_free(value);

	*type = RZIL_OP_ARG_MEM;
	return NULL;
}

void *rz_il_handler_loadw(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsLoadW *op_loadw = op->op.loadw;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_loadw->key, type);
	RzBitVector *ret = rz_il_vm_mem_loadw(vm, op_loadw->mem, addr, op_loadw->n_bits);
	rz_bv_free(addr);
	*type = RZIL_OP_ARG_BITV;
	return ret;
}

void *rz_il_handler_storew(RzILVM *vm, RzILOp *op, RzILOpArgType *type) {
	rz_return_val_if_fail(vm && op && type, NULL);

	RzILOpArgsStoreW *op_storew = op->op.storew;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_storew->key, type);
	RzBitVector *value = rz_il_evaluate_bitv(vm, op_storew->value, type);

	rz_il_vm_mem_storew(vm, op_storew->mem, addr, value);
	rz_bv_free(addr);
	rz_bv_free(value);

	*type = RZIL_OP_ARG_MEM;
	return NULL;
}
