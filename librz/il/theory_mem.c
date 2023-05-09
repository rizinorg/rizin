// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rz_il_vm.h>
#include <rz_il/rz_il_opcodes.h>

void *rz_il_handler_load(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsLoad *op_load = &op->op.load;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_load->key);
	if (!addr) {
		return NULL;
	}
	RzBitVector *ret = rz_il_vm_mem_load(vm, op_load->mem, addr);
	rz_bv_free(addr);
	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

bool rz_il_handler_store(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);

	RzILOpArgsStore *op_store = &op->op.store;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_store->key);
	RzBitVector *value = rz_il_evaluate_bitv(vm, op_store->value);

	bool ret = false;
	if (addr && value) {
		ret = true;
		rz_il_vm_mem_store(vm, op_store->mem, addr, value);
	}
	rz_bv_free(addr);
	rz_bv_free(value);

	return ret;
}

void *rz_il_handler_loadw(RzILVM *vm, RzILOpBitVector *op, RzILTypePure *type) {
	rz_return_val_if_fail(vm && op && type, NULL);
	RzILOpArgsLoadW *op_loadw = &op->op.loadw;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_loadw->key);
	if (!addr) {
		return NULL;
	}
	RzBitVector *ret = rz_il_vm_mem_loadw(vm, op_loadw->mem, addr, op_loadw->n_bits);
	rz_bv_free(addr);
	*type = RZ_IL_TYPE_PURE_BITVECTOR;
	return ret;
}

bool rz_il_handler_storew(RzILVM *vm, RzILOpEffect *op) {
	rz_return_val_if_fail(vm && op, false);

	RzILOpArgsStoreW *op_storew = &op->op.storew;

	RzBitVector *addr = rz_il_evaluate_bitv(vm, op_storew->key);
	RzBitVector *value = rz_il_evaluate_bitv(vm, op_storew->value);

	bool ret = false;
	if (addr && value) {
		ret = true;
		rz_il_vm_mem_storew(vm, op_storew->mem, addr, value);
	}

	rz_bv_free(addr);
	rz_bv_free(value);

	return ret;
}
