// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>
#include <rz_il/rzil_opcodes.h>

void rz_il_handler_load(RzILVM *vm, RzILOp *op) {
	RzILOpLoad *op_load = op->op.load;
	RzILMem m = vm->mems[op_load->mem];

	RzILBitVector *addr = rz_il_get_bv_temp(vm, op_load->key);
	RzILBitVector *ret = rz_il_mem_load(m, addr);
	if (ret == NULL) {
		// empty address --> first access
		// assume it's empty
		RzILBitVector *empty = rz_il_bv_new(m->min_unit_size);
		rz_il_mem_store(m, addr, empty);
		ret = empty;
	}
	rz_il_make_bv_temp(vm, op_load->ret, ret);
}

void rz_il_handler_store(RzILVM *vm, RzILOp *op) {
	RzILOpStore *op_store = op->op.store;
	RzILMem m = vm->mems[op_store->mem];

	RzILBitVector *addr = rz_il_get_bv_temp(vm, op_store->key);
	RzILBitVector *value = rz_il_get_bv_temp(vm, op_store->value);

	rz_il_mem_store(m, addr, value);

	// drop the return, it's `mem` type but we don't need it now
}
