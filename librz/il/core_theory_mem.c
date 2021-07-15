#include "core_theory_vm.h"
#include "core_theory_opcodes.h"

void rz_il_handler_load(RzILVM vm, RzILOp op) {
	RzILOpLoad op_load = op->op.load;
	Mem m = vm->mems[op_load->mem];

	BitVector addr = rz_il_get_bv_temp(vm, op_load->key);
	BitVector ret = rz_il_mem_load(m, addr);
	rz_il_make_bv_temp(vm, op_load->ret, ret);
}

void rz_il_handler_store(RzILVM vm, RzILOp op) {
	RzILOpStore op_store = op->op.store;
	Mem m = vm->mems[op_store->mem];

	BitVector addr = rz_il_get_bv_temp(vm, op_store->key);
	BitVector value = rz_il_get_bv_temp(vm, op_store->value);

	rz_il_mem_store(m, addr, value);

	// drop the return, it's `mem` type but we don't need it now
}
