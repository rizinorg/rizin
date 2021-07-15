#include "core_theory_vm.h"

RzILVar rz_il_vm_create_variable(RzILVM vm, string name) {
	if (vm->var_count >= VM_MAX_VAR) {
		printf("No More Vars here\n");
		return NULL;
	}

	// create , store, update count
	RzILVar var = rz_il_new_variable(name);
	vm->vm_global_variable_list[vm->var_count] = var;
	vm->var_count += 1;

	return var;
}
/************
 * Make a value in temporary array as a persistent value
 * Every persistent value must bind to a variable
 */
RzILVal rz_il_vm_create_value(RzILVM vm, RZIL_VAR_TYPE type) {
	if (vm->val_count >= VM_MAX_VAL) {
		printf("No More Values\n");
		return NULL;
	}

	RzILVal val = rz_il_new_value();
	val->type = type;

	rz_il_add_to_bag(vm->vm_global_value_set, val);
	return val;
}

void rz_il_vm_add_reg(RzILVM vm, string name, int length) {
	RzILVar var = rz_il_vm_create_variable(vm, name);
	RzILVal val = rz_il_vm_create_value(vm, RZVAR_TYPE_BV);
	val->data.bv = bv_new(length);
	rz_il_hash_bind(vm, var, val);
}

// Move a bind value to global list instead of keeping it in temp list
// Save memory
RzILVal rz_il_vm_fortify_val(RzILVM vm, int temp_val_index) {
	RzILVal val = rz_il_get_val_temp(vm, temp_val_index);
	rz_il_add_to_bag(vm->vm_global_value_set, val);

	rz_il_empty_temp(vm, temp_val_index);
	return val;
}

RzILVal rz_il_vm_fortify_bitv(RzILVM vm, int temp_val_index) {
	RzILVal val = rz_il_new_value();
	val->type = RZVAR_TYPE_BV;
	val->data.bv = rz_il_get_bv_temp(vm, temp_val_index);
	rz_il_add_to_bag(vm->vm_global_value_set, val);

	rz_il_empty_temp(vm, temp_val_index);
	return val;
}

RzILVal rz_il_vm_fortify_bool(RzILVM vm, int temp_val_index) {
	RzILVal val = rz_il_new_value();
	val->type = RZVAR_TYPE_BOOL;
	val->data.b = rz_il_get_bool_temp(vm, temp_val_index);
	rz_il_add_to_bag(vm->vm_global_value_set, val);

	rz_il_empty_temp(vm, temp_val_index);
	return val;
}

RzILVal rz_il_hash_find_val_by_var(RzILVM vm, RzILVar var) {
	string var_name = var->var_name;
	RzILVal ret = rz_il_hash_find_val_by_name(vm, var_name);
	return ret;
}

// return the pointer in global_value_list
// should dump if use
RzILVal rz_il_hash_find_val_by_name(RzILVM vm, string var_name) {
	RzILVal ret = ht_pp_find(vm->vm_global_bind_table, var_name, NULL);
	return ret;
}

RzILVar rz_il_find_var_by_name(RzILVM vm, string var_name) {
	RzILVar var;
	for (int i = 0; i < vm->var_count; ++i) {
		var = vm->vm_global_variable_list[i];
		if (strcmp(var_name, var->var_name) == 0) {
			return var;
		}
	}
	return NULL;
}

void rz_il_hash_cancel_binding(RzILVM vm, RzILVar var) {
	string var_id = var->var_name;
	RzILVal val = rz_il_hash_find_val_by_name(vm, var_id);
	rz_il_rm_from_bag(vm->vm_global_value_set, val);
	ht_pp_delete(vm->vm_global_bind_table, var_id);
}

void rz_il_hash_bind(RzILVM vm, RzILVar var, RzILVal val) {
	string var_id = var->var_name;
	ht_pp_update(vm->vm_global_bind_table, var_id, val);
}

BitVector rz_il_hash_find_addr_by_lblname(RzILVM vm, string lbl_name) {
	HtPP *lbl_table = vm->vm_global_label_table;
	BitVector ret;
	bool found = false;

	EffectLabel label = ht_pp_find(lbl_table, lbl_name, &found);
	if (found) {
		ret = label->addr;
		return ret;
	}
	return NULL;
}

EffectLabel rz_il_vm_find_label_by_name(RzILVM vm, string lbl_name) {
	EffectLabel lbl = ht_pp_find(vm->vm_global_label_table, lbl_name, NULL);
	return lbl;
}

EffectLabel rz_il_vm_create_label(RzILVM vm, string name, BitVector addr) {
	HtPP *lbl_table = vm->vm_global_label_table;

	EffectLabel lbl = effect_new_label(name, EFFECT_LABEL_ADDR);
	lbl->addr = bv_dump(addr);
	ht_pp_insert(lbl_table, name, lbl);

	return lbl;
}

EffectLabel rz_il_vm_create_label_lazy(RzILVM vm, string name) {
	HtPP *lbl_table = vm->vm_global_label_table;

	EffectLabel lbl = effect_new_label(name, EFFECT_LABEL_ADDR);
	lbl->addr = NULL;
	ht_pp_insert(lbl_table, name, lbl);

	return lbl;
}

EffectLabel rz_il_vm_update_label(RzILVM vm, string name, BitVector addr) {
	EffectLabel lbl = ht_pp_find(vm->vm_global_label_table, name, NULL);
	if (lbl->addr) {
		bv_free(lbl->addr);
	}
	lbl->addr = bv_dump(addr);

	return lbl;
}

void rz_il_make_bool_temp(RzILVM vm, int store_index, Bool b) {
	RzILTemp temp = vm->temp_value_list[store_index];
	temp->data = b;
	temp->type = RZIL_TEMP_BOOL;
}

void rz_il_make_val_temp(RzILVM vm, int store_index, RzILVal val) {
	RzILTemp temp = vm->temp_value_list[store_index];
	temp->data = val;
	temp->type = RZIL_TEMP_VAL;
}

void rz_il_make_bv_temp(RzILVM vm, int store_index, BitVector bv) {
	RzILTemp temp = vm->temp_value_list[store_index];
	temp->data = bv;
	temp->type = RZIL_TEMP_BV;
}

void rz_il_make_eff_temp(RzILVM vm, int store_index, Effect eff) {
	RzILTemp temp = vm->temp_value_list[store_index];
	temp->data = eff;
	temp->type = RZIL_TEMP_EFF;
}

void *rz_il_get_temp(RzILVM vm, int index) {
	RzILTemp temp = vm->temp_value_list[index];
	if (temp->type != RZIL_TEMP_EMPTY) {
		return temp->data;
	}
	return NULL;
}

BitVector rz_il_get_bv_temp(RzILVM vm, int index) {
	RzILTemp temp = vm->temp_value_list[index];
	if (temp->type == RZIL_TEMP_BV) {
		return temp->data;
	}

	if (temp->type == RZIL_TEMP_VAL) {
		RzILVal val = temp->data;
		if (val->type == RZVAR_TYPE_BV) {
			return val->data.bv;
		}
		if (val->type == RZVAR_TYPE_BOOL) {
			printf("TODO: BOOL -> BITVECTOR\n");
			return NULL;
		}
	}

	if (temp->type == RZIL_TEMP_BOOL) {
		printf("TODO: BOOL -> BITVECTOR\n");
		return NULL;
	}

	printf("TYPES CANNOT CONVERT TO BITVECTOR\n");
	return NULL;
}

Bool rz_il_get_bool_temp(RzILVM vm, int index) {
	RzILTemp temp = vm->temp_value_list[index];
	if (temp->type == RZIL_TEMP_BOOL) {
		return temp->data;
	}

	if (temp->type == RZIL_TEMP_BV) {
		if (bv_is_zero_vector(temp->data)) {
			// TODO : I don't know if there is any potential
			//        bad case for converting
			//        the same to bitv/val -> bool in the following
			bv_free(temp->data);
			temp->data = rz_il_new_bool(false);
			temp->type = RZIL_TEMP_BOOL;
		} else {
			bv_free(temp->data);
			temp->data = rz_il_new_bool(true);
			temp->type = RZIL_TEMP_BOOL;
		}
		return temp->data;
	}

	if (temp->type == RZIL_TEMP_VAL) {
		RzILVal val = temp->data;
		if (val->type == RZVAR_TYPE_BOOL) {
			return val->data.b;
		}

		if (val->type == RZVAR_TYPE_BV) {
			if (bv_is_zero_vector(val->data.bv)) {
				bv_free(val->data.bv);
				val->data.b = rz_il_new_bool(false);
				val->type = RZVAR_TYPE_BOOL;
			} else {
				bv_free(val->data.bv);
				val->data.b = rz_il_new_bool(true);
				val->type = RZVAR_TYPE_BOOL;
			}
			return val->data.b;
		}
	}
	printf("TYPES CANNOT CONVERT TO BOOL\n");
	return NULL;
}

RzILVal rz_il_get_val_temp(RzILVM vm, int index) {
	RzILTemp temp = vm->temp_value_list[index];
	if (temp->type == RZIL_TEMP_VAL) {
		return temp->data;
	}

	RzILVal val = rz_il_new_value();
	if (temp->type == RZIL_TEMP_BOOL) {
		Bool b = temp->data;
		val->data.b = b;
		val->type = RZVAR_TYPE_BOOL;
		temp->type = RZIL_TEMP_VAL;
		temp->data = val;
		return val;
	}

	if (temp->type == RZIL_TEMP_BV) {
		BitVector bv = temp->data;
		val->data.bv = bv;
		val->type = RZVAR_TYPE_BV;
		temp->type = RZIL_TEMP_VAL;
		temp->data = val;
		return val;
	}

	// other types
	printf("TYPES CANNOT CONVERT TO RZVAL\n");
	return NULL;
}

// simply set data to NULL
void rz_il_empty_temp(RzILVM vm, int index) {
	if (index < 0) {
		return; // do nothing
	}
	RzILTemp temp = vm->temp_value_list[index];
	temp->data = NULL;
	temp->type = RZIL_TEMP_EMPTY;
}

// free the memory and empty it (set data to NULL)
void rz_il_clean_temp(RzILVM vm, RzILTemp temp) {
	RZIL_TEMP_TYPE type = temp->type;
	switch (type) {
	case RZIL_TEMP_VAL:
		rz_il_free_value(temp->data);
		break;
	case RZIL_TEMP_BOOL:
		rz_il_free_bool(temp->data);
		break;
	case RZIL_TEMP_BV:
		bv_free(temp->data);
		break;
	case RZIL_TEMP_EFF:
		effect_free(temp->data);
		break;
	default:
		break;
	}

	temp->data = NULL;
	temp->type = RZIL_TEMP_EMPTY;
}

// Clean temporary value, called after step out current instruction
void rz_il_clean_temps(RzILVM vm) {
	RzILTemp *temps = vm->temp_value_list;
	for (int i = 0; i < VM_MAX_TEMP; ++i) {
		if (temps[i]) {
			rz_il_clean_temp(vm, temps[i]);
		}
	}
}

// Make a RzILOp list for a single instructions
RzPVector *rz_il_make_oplist(int num, ...) {
	va_list args;
	RzILOp cur_op;
	RzPVector *oplist = rz_pvector_new((RzPVectorFree)rz_il_free_op);

	va_start(args, num);
	for (int i = 0; i < num; ++i) {
		cur_op = va_arg(args, RzILOp);
		rz_pvector_push(oplist, cur_op);
	}
	va_end(args);

	return oplist;
}

RzPVector *rz_il_make_oplist_with_id(ut64 id, int num, ...) {
	va_list args;
	RzILOp cur_op;
	RzPVector *oplist = rz_pvector_new((RzPVectorFree)rz_il_free_op);

	va_start(args, num);
	for (int i = 0; i < num; ++i) {
		cur_op = va_arg(args, RzILOp);
		cur_op->id = id;
		rz_pvector_push(oplist, cur_op);
	}
	va_end(args);

	return oplist;
}

// Add binding of address and core theory opcodes
void rz_il_vm_store_opcodes_to_addr(RzILVM vm, BitVector addr, RzPVector *oplist) {
	ht_pp_insert(vm->ct_opcodes, addr, oplist);
}

RzPVector *rz_il_vm_load_opcodes(RzILVM vm, BitVector addr) {
	return ht_pp_find(vm->ct_opcodes, addr, NULL);
}

static void print_val(RzILVal val) {
	RZIL_VAR_TYPE type = val->type;
	BitVector bv = val->data.bv;
	Bool b = val->data.b;

	if (type == RZVAR_TYPE_BV) {
		printf("[BV] -> %d -> ", bv_to_ut32(bv));
		print_bv(bv);
		return;
	}

	if (type == RZVAR_TYPE_BOOL) {
		printf("[BOOL]");
		printf("%s\n", b->b ? "TRUE" : "FALSE");
		return;
	}

	if (type == RZVAR_TYPE_UNK) {
		printf("[UNK]\n");
	}
}

bool print_bind(void *user, const void *k, const void *v) {
	printf("[Var-%d] : %s\n", *(int *)user, (string)k);
	printf("[Val-%d] : ", *(int *)user);
	print_val((RzILVal)v);
	*(int *)user += 1;
	return true;
}

void rz_il_print_vm(RzILVM vm) {
	int count = 0;
	HtPP *var_val_bind_table = vm->vm_global_bind_table;
	ht_pp_foreach(var_val_bind_table, (HtPPForeachCallback)print_bind, &count);
}

static bool print_vm_mem_callback(void *user, const void *k, const void *v) {
	printf("[%d] : ", *(int *)user);
	printf("[%d] -- [%p] -> ", bv_to_ut32((BitVector)k), v);
	print_bv((BitVector)v);
	*(int *)user += 1;
	return true;
}

static bool print_vm_label_callback(void *user, const void *k, const void *v) {
	printf("[%d] : ", *(int *)user);
	*(int *)user += 1;

	EffectLabel label = (EffectLabel)v;
	if (label == NULL) {
		printf("None Label : <key> %p -- <value> %p\n", k, v);
		return false;
	}
	if (label->type == EFFECT_LABEL_ADDR) {
		if (label->addr) {
			printf("<%s> -> Addr *%p = %d\n", (char *)k, (void *)label->addr, bv_to_ut32(label->addr));
		} else {
			printf("<%s> -> Addr (NULL)\n", (char *)k);
		}
		return true;
	}

	printf("<%s> -> Addr(function) %p\n", (char *)k, (void *)label->addr);
	return true;
}

void rz_il_print_vm_mem(RzILVM vm) {
	int count = 0;
	ht_pp_foreach(vm->mems[0]->kv_map, print_vm_mem_callback, &count);
}

void rz_il_print_vm_labels(RzILVM vm) {
	int count = 0;
	printf(">>>>>>>>>>>>>>>>>>>>>>>>>\n");
	ht_pp_foreach(vm->vm_global_label_table, print_vm_label_callback, &count);
}

void rz_il_print_vm_temps(RzILVM vm) {
	int i = 0;
	RzILTemp cur;
	for (i = 0; i < VM_MAX_TEMP; ++i) {
		cur = vm->temp_value_list[i];
		if (cur) {
			printf("[TEMP-%d] -> ", i);
			if (cur->type == RZIL_TEMP_EMPTY) {
				printf("[EMPTY TEMP]\n");
				continue;
			}

			if (cur->type == RZIL_TEMP_BV) {
				printf("[BITV]");
				print_bv(cur->data);
				continue;
			}

			if (cur->type == RZIL_TEMP_BOOL) {
				printf("[BOOL]");
				printf("%s\n", ((Bool)cur->data)->b ? "TRUE" : "FALSE");
				continue;
			}

			if (cur->type == RZIL_TEMP_VAL) {
				printf("[VAL] TYPE-%d\n", ((RzILVal)cur)->type);
				continue;
			}

			if (cur->type == RZIL_TEMP_EFF) {
				printf("[EFF] TYPE-%d\n", ((Effect)cur)->effect_type);
				continue;
			}
		}
	}
}

void rz_il_vm_debug_easy(RzILVM vm) {
	int i = 1;
}
