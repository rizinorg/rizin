#include "internal_ct_cmd.h"

static void free_label_kv(HtPPKv *kv) {
	free(kv->key);
	EffectLabel lbl = kv->value;

	if (lbl->type == EFFECT_LABEL_HOOK || lbl->type == EFFECT_LABEL_SYSCALL) {
		lbl->addr = NULL;
	}
	bv_free(lbl->addr);
	free(lbl->label_id);
	free(lbl);
}

static void free_opcode_kv(HtPPKv *kv) {
	bv_free(kv->key);
	rz_pvector_free(kv->value);
}

static void free_bind_var_val(HtPPKv *kv) {
	free(kv->key);
}

void rz_il_vm_init(RzILVM vm, ut64 start_addr, int addr_size, int data_size) {
	vm->addr_size = addr_size;
	vm->data_size = data_size;

	vm->vm_global_variable_list = (RzILVar *)calloc(VM_MAX_VAR, sizeof(RzILVar));
	vm->vm_global_value_set = rz_il_new_bag(VM_MAX_VAL, (RzILBagFreeFunc)rz_il_free_value);

	// Key : string
	// Val : EffectLabel
	// Do not dump it since its single signed here, and will be free in `close`
	HtPPOptions lbl_options = { 0 };
	lbl_options.cmp = (HtPPListComparator)strcmp;
	lbl_options.hashfn = (HtPPHashFunction)sdb_hash;
	lbl_options.dupkey = (HtPPDupKey)strdup;
	lbl_options.dupvalue = NULL;
	lbl_options.freefn = (HtPPKvFreeFunc)free_label_kv;
	lbl_options.elem_size = sizeof(HtPPKv);
	lbl_options.calcsizeK = (HtPPCalcSizeK)strlen;
	vm->vm_global_label_table = ht_pp_new_opt(&lbl_options);

	// Binding Table for Variable and Value
	HtPPOptions bind_options = { 0 };
	bind_options.cmp = (HtPPListComparator)strcmp;
	bind_options.hashfn = (HtPPHashFunction)sdb_hash;
	bind_options.dupkey = (HtPPDupKey)strdup;
	bind_options.dupvalue = NULL;
	bind_options.freefn = (HtPPKvFreeFunc)free_bind_var_val;
	bind_options.elem_size = sizeof(HtPPKv);
	bind_options.calcsizeK = (HtPPCalcSizeK)strlen;
	vm->vm_global_bind_table = ht_pp_new_opt(&bind_options);

	// Temporary Value for core theory execution
	vm->temp_value_list = (RzILTemp *)calloc(VM_MAX_TEMP, sizeof(RzILTemp));
	for (int i = 0; i < VM_MAX_TEMP; ++i) {
		vm->temp_value_list[i] = rz_il_new_temp();
	}

	// TODO : More Arguments for vm init to control
	//      1. Minimal unit size in memory
	//      2. Multiple Memory
	//      3. pc length
	vm->mems = (Mem *)calloc(VM_MAX_TEMP, sizeof(Mem));
	vm->pc = bv_new_from_ut64(addr_size, start_addr);

	// Table for storing the core theory opcodes
	HtPPOptions ops_options = { 0 };
	ops_options.cmp = (HtPPListComparator)bv_cmp;
	ops_options.hashfn = (HtPPHashFunction)bv_hash;
	ops_options.dupkey = (HtPPDupKey)bv_dump;
	ops_options.dupvalue = NULL; // dump key only, since the opcode used in hash map only
	ops_options.freefn = free_opcode_kv;
	ops_options.elem_size = sizeof(HtPPKv);
	vm->ct_opcodes = ht_pp_new_opt(&ops_options);

	// init jump table of labels
	vm->op_handler_table = (RzILOpHandler *)malloc(sizeof(RzILOpHandler) * RZIL_OP_INVALID);
	memset(vm->op_handler_table, 0, RZIL_OP_INVALID);
	vm->op_handler_table[RZIL_OP_VAR] = &rz_il_handler_var;
	vm->op_handler_table[RZIL_OP_ITE] = &rz_il_handler_ite;
	vm->op_handler_table[RZIL_OP_UNK] = &rz_il_handler_unk;

	vm->op_handler_table[RZIL_OP_B0] = &rz_il_handler_b0;
	vm->op_handler_table[RZIL_OP_B1] = &rz_il_handler_b1;
	vm->op_handler_table[RZIL_OP_AND_] = &rz_il_handler_and_;
	vm->op_handler_table[RZIL_OP_OR_] = &rz_il_handler_or_;
	vm->op_handler_table[RZIL_OP_INV] = &rz_il_handler_inv;

	vm->op_handler_table[RZIL_OP_LOAD] = &rz_il_handler_load;
	vm->op_handler_table[RZIL_OP_STORE] = &rz_il_handler_store;

	vm->op_handler_table[RZIL_OP_INT] = &rz_il_handler_int;
	vm->op_handler_table[RZIL_OP_NEG] = &rz_il_handler_neg;
	vm->op_handler_table[RZIL_OP_NOT] = &rz_il_handler_not;
	vm->op_handler_table[RZIL_OP_LSB] = &rz_il_handler_lsb;
	vm->op_handler_table[RZIL_OP_MSB] = &rz_il_handler_msb;
	vm->op_handler_table[RZIL_OP_SHIFTL] = &rz_il_handler_shiftl;
	vm->op_handler_table[RZIL_OP_SHIFTR] = &rz_il_handler_shiftr;
	vm->op_handler_table[RZIL_OP_ADD] = &rz_il_handler_add;
	vm->op_handler_table[RZIL_OP_SUB] = &rz_il_handler_sub;
	vm->op_handler_table[RZIL_OP_MUL] = &rz_il_handler_mul;
	vm->op_handler_table[RZIL_OP_DIV] = &rz_il_handler_div;
	vm->op_handler_table[RZIL_OP_MOD] = &rz_il_handler_mod;
	vm->op_handler_table[RZIL_OP_SDIV] = &rz_il_handler_sdiv;
	vm->op_handler_table[RZIL_OP_SMOD] = &rz_il_handler_smod;

	vm->op_handler_table[RZIL_OP_PERFORM] = &rz_il_handler_perform;
	vm->op_handler_table[RZIL_OP_SET] = &rz_il_handler_set;
	vm->op_handler_table[RZIL_OP_GOTO] = &rz_il_handler_goto;
	vm->op_handler_table[RZIL_OP_BRANCH] = &rz_il_handler_branch;
	vm->op_handler_table[RZIL_OP_SEQ] = &rz_il_handler_seq;

	// TODO : Add More

	vm->var_count = 0;
	vm->val_count = 0;
	vm->mem_count = 0;
	vm->easy_debug = 0;
}

void rz_il_vm_close(RzILVM vm) {
	RzILVar var;

	rz_il_free_bag(vm->vm_global_value_set);

	for (int i = 0; i < VM_MAX_VAR; ++i) {
		if (vm->vm_global_variable_list[i] != NULL) {
			var = vm->vm_global_variable_list[i];
			rz_il_free_variable(var);
			vm->vm_global_variable_list[i] = NULL;
		}
	}
	free(vm->vm_global_variable_list);

	if (vm->ct_opcodes) {
		ht_pp_free(vm->ct_opcodes);
	}

	if (vm->mems) {
		for (int i = 0; i < vm->mem_count; ++i) {
			rz_il_free_mem(vm->mems[i]);
		}
		free(vm->mems);
	}

	if (vm->temp_value_list != NULL) {
		for (int i = 0; i < VM_MAX_TEMP; ++i) {
			free(vm->temp_value_list[i]);
		}
		free(vm->temp_value_list);
	}

	if (vm->vm_global_bind_table != NULL) {
		ht_pp_free(vm->vm_global_bind_table);
	}

	if (vm->vm_global_label_table != NULL) {
		ht_pp_free(vm->vm_global_label_table);
	}

	if (vm->op_handler_table != NULL) {
		free(vm->op_handler_table);
	}
	bv_free(vm->pc);
	free(vm);
}

// Step on core theory opcode
void rz_il_vm_step(RzILVM vm, RzILOp op) {
	vm->easy_debug += 1;
	RzILOpHandler handler = vm->op_handler_table[op->code];
	handler(vm, op);
}

// Step on original instruction
void rz_il_vm_list_step(RzILVM vm, RzPVector *op_list) {
	void **iter;
	RzILOp cur_op;

	rz_pvector_foreach (op_list, iter) {
		cur_op = *iter;
		rz_il_vm_step(vm, cur_op);
	}

	BitVector one = bv_new(vm->pc->len);
	bv_set(one, vm->pc->len - 1, true);
	BitVector next_pc = bv_add(vm->pc, one);
	bv_free(vm->pc);
	bv_free(one);
	vm->pc = next_pc;
}

const string op2str(RzILOp op) {
	char *ctops[64] = {
		"VAR",
		"UNK",
		"ITE",
		"B0",
		"B1",
		"INV",
		"AND_",
		"OR_",
		"INT",
		"MSB",
		"LSB",
		"NEG",
		"NOT",
		"ADD",
		"SUB",
		"MUL",
		"DIV",
		"SDIV",
		"MOD",
		"SMOD",
		"LOGAND",
		"LOGOR",
		"LOGXOR",
		"SHIFTR",
		"SHIFTL",
		"SLE",
		"ULE",
		"CAST",
		"CONCAT",
		"APPEND",
		"LOAD",
		"STORE",
		"PERFORM",
		"SET",
		"JMP",
		"GOTO",
		"SEQ",
		"BLK",
		"REPEAT",
		"BRANCH",
		"INVALID",
	};
	return ctops[op->code];
}

// create string for single core theory opcode
int rz_il_vm_printer_step(RzILOp op, string *helper) {
	string cur_op_str;
	string arg1, arg2, arg3;
	int ret;

	switch (op->code) {
	// tricky approach
	// Handle Special Opcode First
	case RZIL_OP_VAR:
		cur_op_str = rz_str_newf("(%s %s)", op2str(op), op->op.var->v);
		helper[op->op.var->ret] = cur_op_str;
		ret = op->op.var->ret;
		break;
	case RZIL_OP_SET:
		arg1 = helper[op->op.set->x];
		cur_op_str = rz_str_newf("(%s %s %s)", op2str(op), op->op.set->v, arg1);
		helper[op->op.set->ret] = cur_op_str;
		ret = op->op.set->ret;
		break;
	case RZIL_OP_GOTO:
		cur_op_str = rz_str_newf("(%s %s)", op2str(op), op->op.goto_->lbl);
		helper[op->op.goto_->ret_ctrl_eff] = cur_op_str;
		ret = op->op.goto_->ret_ctrl_eff;
		break;
		// 4 Int memebers
	case RZIL_OP_INT:
		cur_op_str = rz_str_newf("(%s %d)", op2str(op), op->op.int_->value);
		helper[op->op.int_->ret] = cur_op_str;
		ret = op->op.int_->ret;
		break;
	case RZIL_OP_STORE:
		arg1 = helper[op->op.store->key];
		arg2 = helper[op->op.store->value];
		cur_op_str = rz_str_newf("(%s %s %s)", op2str(op), arg1, arg2);
		helper[VM_MAX_TEMP - 1] = cur_op_str; // op_store->ret == -1
		ret = VM_MAX_TEMP - 1;
		break;
	case RZIL_OP_LOAD:
		arg1 = helper[op->op.load->key];
		cur_op_str = rz_str_newf("(%s %s)", op2str(op), arg1);
		helper[op->op.load->ret] = cur_op_str;
		ret = op->op.load->ret;
		break;
	case RZIL_OP_BRANCH:
		// true or false may be an empty one,
		// then true/false == -1
		arg1 = helper[op->op.branch->condition];
		arg2 = (op->op.branch->true_eff == -1) ? "<NOP>" : helper[op->op.branch->true_eff];
		arg3 = (op->op.branch->false_eff == -1) ? "<NOP>" : helper[op->op.branch->false_eff];
		cur_op_str = rz_str_newf("(%s %s %s %s)", op2str(op), arg1, arg2, arg3);
		helper[op->op.branch->ret] = cur_op_str;
		ret = op->op.branch->ret;
		break;
	case RZIL_OP_UNK:
	case RZIL_OP_B0:
	case RZIL_OP_B1:
		cur_op_str = rz_str_newf("%s", op2str(op));
		helper[op->op.unk->ret] = cur_op_str;
		ret = op->op.unk->ret;
		break;
	case RZIL_OP_ITE:
	case RZIL_OP_SHIFTR:
	case RZIL_OP_SHIFTL:
		arg1 = helper[op->op.ite->condition];
		arg2 = helper[op->op.ite->x];
		arg3 = helper[op->op.ite->y];
		cur_op_str = rz_str_newf("(%s %s %s %s)", op2str(op), arg1, arg2, arg3);
		helper[op->op.ite->ret] = cur_op_str;
		ret = op->op.ite->ret;
		break;
		// 3 Int members
	case RZIL_OP_ADD:
	case RZIL_OP_SUB:
	case RZIL_OP_MUL:
	case RZIL_OP_DIV:
	case RZIL_OP_MOD:
	case RZIL_OP_SDIV:
	case RZIL_OP_SMOD:
	case RZIL_OP_LOGXOR:
	case RZIL_OP_LOGAND:
	case RZIL_OP_LOGOR:
	case RZIL_OP_ULE:
	case RZIL_OP_SLE:
	case RZIL_OP_SEQ:
	case RZIL_OP_BLK:
	case RZIL_OP_AND_:
	case RZIL_OP_OR_:
		arg1 = helper[op->op.add->x];
		arg2 = helper[op->op.add->y];
		cur_op_str = rz_str_newf("(%s %s %s)", op2str(op), arg1, arg2);
		helper[op->op.add->ret] = cur_op_str;
		ret = op->op.add->ret;
		break;
	case RZIL_OP_MSB:
	case RZIL_OP_LSB:
	case RZIL_OP_NEG:
	case RZIL_OP_NOT:
	case RZIL_OP_JMP:
	case RZIL_OP_INV:
		arg1 = helper[op->op.inv->x];
		cur_op_str = rz_str_newf("(%s %s)", op2str(op), arg1);
		helper[op->op.inv->ret] = cur_op_str;
		ret = op->op.inv->ret;
		break;
	// Perform !! ---> Print !!
	case RZIL_OP_PERFORM:
		ret = op->op.perform->eff;
		break;
	default:
		ret = 0;
		printf("[WIP]\n");
		break;
	}

	return ret;
}

void rz_il_vm_list_printer_step(RzPVector *op_list) {
	string helper[32] = { NULL };

	void **iter;
	RzILOp cur_op;
	int ret;
	rz_pvector_foreach (op_list, iter) {
		cur_op = *iter;
		ret = rz_il_vm_printer_step(cur_op, helper);
	}

	printf("%s\n", helper[ret]);
	for (int i = 0; i < 32; ++i) {
		if (helper[i]) {
			free(helper[i]);
		}
	}
}
