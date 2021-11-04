// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/bag.h>

/**
 * Create a bag to store all RzILValue instances
 * Only used in VM to clean garbage values (unused RzILVal)
 * \param capacity max size of bag
 * \param func function pointer to free element
 * \return RzILBag pointer
 */
RZ_API RzILBag *rz_il_new_bag(int capacity, RzILBagFreeFunc func) {
	RzILBag *bag = RZ_NEW0(RzILBag);
	if (!bag) {
		return NULL;
	}

	bag->capacity = capacity;
	bag->data_list = RZ_NEWS0(void *, capacity);
	bag->item_count = 0;
	bag->next_pos = 0;
	bag->next_pos_stack = RZ_NEWS0(int, capacity);
	bag->sp = 0; // sp point to first empty
	bag->free_func = func;

	// init stack
	for (int i = 0; i < capacity; ++i) {
		bag->next_pos_stack[i] = i; // empty 1 2 3 4 ......
	}

	return bag;
}

int rz_il_find_in_bag(RzILBag *bag, void *item) {
	void *cur_item;
	for (int i = 0; i < bag->capacity; ++i) {
		cur_item = bag->data_list[i];
		if (cur_item == item) {
			return i;
		}
	}

	// not found
	return -1;
}

/**
 * Remove an element from bag
 * \param bag RzILBag instance
 * \param item pointer pointed to the item you want to remove from current bag
 * \return true if successfully removed
 */
RZ_API bool rz_il_rm_from_bag(RZ_NONNULL RzILBag *bag, RZ_NONNULL void *item) {
	rz_return_val_if_fail(bag && item, false);
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

/**
 * Store an item into bag
 * \param bag RzILBag, point to the bag
 * \param item A pointer to an element you want to store
 * \return true if store successfully
 */
RZ_API bool rz_il_add_to_bag(RZ_NONNULL RzILBag *bag, RZ_NONNULL void *item) {
	rz_return_val_if_fail(bag && item, false);
	if (bag->item_count >= bag->capacity) {
		RZ_LOG_ERROR("[Cannot Carry More Values]\n");
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

/**
 * Destroy the bag
 * \param bag RzILBag, point to the bag
 */
RZ_API void rz_il_free_bag(RzILBag *bag) {
	if (!bag) {
		return;
	}

	// free data
	for (int i = 0; i < bag->capacity; ++i) {
		void *cur_item = bag->data_list[i];
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
