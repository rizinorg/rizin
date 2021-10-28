// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_BAG_H
#define RZ_IL_BAG_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*RzILBagFreeFunc)(void *);
/**
 *  \struct rz_il_bag_t
 *  \brief structure of RzILBag, used to store RzILVal instances and manage them
 *
 *  The main purpose of introducing RzILBag is to prevent excessive growth in the number of RzILVal
 *  It's mainly used to clean up unused values during VM execution, and clean up values at the end
 */
typedef struct rz_il_bag_t {
	void **data_list; ///< Space to carry pointers
	int item_count; ///< count current items
	int capcity; ///< maximum size
	int *next_pos_stack; ///< internal variable, used for managing space
	int next_pos; ///< internal variable, used for managing space
	int sp; ///< internal variable, used for managing space
	RzILBagFreeFunc free_func; ///< Function pointer to free RzILVal
} RzILBag;

RZ_API RzILBag *rz_il_new_bag(int capcity, RzILBagFreeFunc func);
RZ_API bool rz_il_rm_from_bag(RzILBag *bag, void *item);
RZ_API bool rz_il_add_to_bag(RzILBag *bag, void *item);
RZ_API void rz_il_free_bag(RzILBag *bag);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_BAG_H
