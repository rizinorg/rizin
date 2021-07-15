#include "vm_defines.h"
#include <string.h>
#include <stdlib.h>

RzILVar rz_il_new_variable(string name) {
	RzILVar ret;

	ret = (RzILVar)malloc(sizeof(struct rz_il_var_t));
	ret->var_name = strdup(name);
	ret->type = RZVAR_TYPE_UNK;

	return ret;
}

RzILVal rz_il_new_value(void) {
	RzILVal ret;
	ret = (RzILVal)malloc(sizeof(struct rz_il_val_t));
	memset(ret, 0, sizeof(struct rz_il_val_t));
	ret->type = RZVAR_TYPE_UNK;
	return ret;
}

RzILVal rz_il_dump_value(RzILVal val) {
	RzILVal ret = rz_il_new_value();
	ret->type = val->type;

	if (ret->type == RZVAR_TYPE_BOOL) {
		ret->data.b = rz_il_new_bool(val->data.b->b);
	}

	if (ret->type == RZVAR_TYPE_BV) {
		ret->data.bv = bv_dump(val->data.bv);
	}

	if (ret->type == RZVAR_TYPE_UNK) {
		ret->data.b = NULL;
		ret->data.bv = NULL;
	}

	return ret;
}

RzILTemp rz_il_new_temp(void) {
	RzILTemp temp = RZ_NEW0(struct rz_il_tempv_t);
	temp->data = NULL;
	temp->type = RZIL_TEMP_EMPTY;
	return temp;
}

void rz_il_free_temp(RzILTemp temp) {
	free(temp);
}

void rz_il_free_value(RzILVal val) {
	if (!val) {
		return;
	}

	RZIL_VAR_TYPE type = val->type;
	switch (type) {
	case RZVAR_TYPE_BOOL:
		rz_il_free_bool(val->data.b);
		break;
	case RZVAR_TYPE_BV:
		bv_free(val->data.bv);
		break;
	case RZVAR_TYPE_UNK:
	default:
		break;
	}

	free(val);
}

void rz_il_free_variable(RzILVar var) {
	free(var->var_name);
	free(var);
}

RzILBag rz_il_new_bag(int capcity, RzILBagFreeFunc func) {
	RzILBag bag = RZ_NEW0(struct rz_il_bag_t);

	bag->capcity = capcity;
	bag->data_list = RZ_NEWS0(void *, capcity);
	bag->item_count = 0;
	bag->next_pos = 0;
	bag->next_pos_stack = RZ_NEWS0(int, capcity);
	bag->sp = 0; // sp point to first empty
	bag->free_func = func;

	// init stack
	for (int i = 0; i < capcity; ++i) {
		bag->next_pos_stack[i] = i; // empty 1 2 3 4 ......
	}

	return bag;
}

int rz_il_find_in_bag(RzILBag bag, void *item) {
	void *cur_item;
	for (int i = 0; i < bag->capcity; ++i) {
		cur_item = bag->data_list[i];
		if (cur_item == item) {
			return i;
		}
	}

	// not found
	return -1;
}

bool rz_il_rm_from_bag(RzILBag bag, void *item) {
	int pos = rz_il_find_in_bag(bag, item);
	if (pos == -1) {
		// not in bag
		return false;
	}

	// in bag, remove it
	if (bag->free_func) {
		bag->free_func(bag->data_list[pos]);
	}
	bag->data_list[pos] = NULL;

	// there is a new spare space
	// record it (push this position to stack)
	bag->next_pos_stack[bag->sp] = pos;
	bag->sp -= 1;

	// item count
	bag->item_count -= 1;

	return true;
}

bool rz_il_add_to_bag(RzILBag bag, void *item) {
	if (bag->item_count >= bag->capcity) {
		printf("[Cannot Carry More Values]\n");
		return false;
	}

	if (rz_il_find_in_bag(bag, item) != -1) {
		// already in bag
		return false;
	}

	// not in bag, add it
	bag->data_list[bag->next_pos] = item;

	// pop next_pos
	bag->sp += 1;
	bag->next_pos = bag->next_pos_stack[bag->sp];

	// item count
	bag->item_count += 1;

	return true;
}

void rz_il_free_bag(RzILBag bag) {
	void *cur_item;

	// free data
	for (int i = 0; i < bag->capcity; ++i) {
		cur_item = bag->data_list[i];
		if (cur_item) {
			if (bag->free_func) {
				bag->free_func(cur_item);
			}
			bag->data_list[i] = NULL;
		}
	}
	free(bag->data_list);

	// free stack
	free(bag->next_pos_stack);

	// free bag
	free(bag);
}
