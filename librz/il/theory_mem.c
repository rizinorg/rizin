// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/rzil_vm.h>
#include <rz_il/rzil_opcodes.h>

void *rz_il_handler_load(RzILVM *vm, RzILOp *op, RZIL_OP_ARG_TYPE *type) {
	rz_return_val_if_fail(op, NULL);
	RzILOpLoad *op_load = op->op.load;
	RzILMem *m = vm->mems[op_load->mem];

	RzILBitVector *addr = rz_il_evaluate_bitv(vm, op_load->key, type);
	RzILBitVector *ret = rz_il_mem_load(m, addr);
	if (ret == NULL) {
		// empty address --> first access
		// assume it's empty
		RzILBitVector *empty = rz_il_bv_new(m->min_unit_size);
		rz_il_mem_store(m, addr, empty);
		ret = empty;
	}

	rz_il_bv_free(addr);
	*type = RZIL_OP_ARG_BITV;
	return ret;
}

void *rz_il_handler_store(RzILVM *vm, RzILOp *op, RZIL_OP_ARG_TYPE *type) {
	rz_return_val_if_fail(op, NULL);

	RzILOpStore *op_store = op->op.store;
	RzILMem *m = vm->mems[op_store->mem];

	RzILBitVector *addr = rz_il_evaluate_bitv(vm, op_store->key, type);
	RzILBitVector *value = rz_il_evaluate_bitv(vm, op_store->value, type);

	rz_il_mem_store(m, addr, value);
	rz_il_bv_free(addr);

	*type = RZIL_OP_ARG_MEM;
	return m;
}
