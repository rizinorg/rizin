// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/bag.h>

RZ_API RzILBag rz_il_new_bag(int capcity, RzILBagFreeFunc func) {
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

RZ_API bool rz_il_rm_from_bag(RzILBag bag, void *item) {
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

RZ_API bool rz_il_add_to_bag(RzILBag bag, void *item) {
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

RZ_API void rz_il_free_bag(RzILBag bag) {
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
