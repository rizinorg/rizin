// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CORE_THEORY_VM_DEFINITIONS_H
#define CORE_THEORY_VM_DEFINITIONS_H

#include "bitvector.h"
#include "bool.h"
#include "rz_lib.h"

/// The following RzIL_* is only a mark
/// to remind developer the argument type in opcode struct
#define RzIL_PURE_VAL
#define RzIL_BITV
#define RzIL_BOOL
#define RzIL_VAR
#define RzIL_EFF
#define RzIL_LABLE
#define RzIL_MEM

typedef enum {
	RZIL_VAR_TYPE_BV,
	RZIL_VAR_TYPE_BOOL,
	RZIL_VAR_TYPE_UNK, // Unkown value
} RZIL_VAR_TYPE;

typedef union {
	BitVector bv;
	Bool b;
} RzValUnion;

/**
 *  \struct rz_il_var_t
 *  \brief structure of RzILVar
 */
struct rz_il_var_t {
	string var_name; ///< name of variable
	RZIL_VAR_TYPE type; ///< data type of variable
};

/**
 *  \struct rz_il_val_t
 *  \brief structure of RzILVal
 */
struct rz_il_val_t {
	RZIL_VAR_TYPE type; ///< type of value
	RzValUnion data; ///< data pointer
};

typedef void (*RzILBagFreeFunc)(void *);
/**
 *  \struct rz_il_bag_t
 *  \brief structure of RzILBag, used to store RzILVal instances and manage them
 *
 *  The main purpose of introducing RzILBag is to prevent excessive growth in the number of RzILVal
 *  It's mainly used to clean up unused values during VM execution, and clean up values at the end
 */
struct rz_il_bag_t {
	void **data_list; ///< Space to carry pointers
	int item_count; ///< count current items
	int capcity; ///< maximum size
	int *next_pos_stack; ///< internal variable, used for managing space
	int next_pos; ///< internal variable, used for managing space
	int sp; ///< internal variable, used for managing space
	RzILBagFreeFunc free_func; ///< Function pointer to free RzILVal
};

typedef struct rz_il_bag_t *RzILBag;
typedef struct rz_il_val_t *RzILVal;
typedef struct rz_il_var_t *RzILVar;

typedef enum {
	RZIL_TEMP_BV,
	RZIL_TEMP_BOOL,
	RZIL_TEMP_VAL,
	RZIL_TEMP_EFF,

	RZIL_TEMP_EMPTY
} RZIL_TEMP_TYPE;

/**
 *  \struct rz_il_tempv_t
 *  \brief structure for RzIL Temporary
 *
 *  It's a container to carry BitVector/RzILVal/Bool/Effect temporarily
 */
struct rz_il_tempv_t {
	void *data; ///< Pointer to the carried data
	RZIL_TEMP_TYPE type; ///< Type of carried data
};
typedef struct rz_il_tempv_t *RzILTemp;

RZ_API RzILVar rz_il_new_variable(string name);
RZ_API RzILVal rz_il_new_value(void);
RZ_API RzILTemp rz_il_new_temp(void);
RZ_API RzILVal rz_il_dump_value(RzILVal val);
RZ_API void rz_il_free_temp(RzILTemp temp);
RZ_API void rz_il_free_value(RzILVal val);
RZ_API void rz_il_free_variable(RzILVar var);

RzILBag rz_il_new_bag(int capcity, RzILBagFreeFunc func);
bool rz_il_rm_from_bag(RzILBag bag, void *item);
bool rz_il_add_to_bag(RzILBag bag, void *item);
void rz_il_free_bag(RzILBag bag);

#endif //CORE_THEORY_VM_DEFINITIONS_H
