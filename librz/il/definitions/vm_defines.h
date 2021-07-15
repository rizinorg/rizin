#ifndef CORE_THEORY_VM_DEFINITIONS_H
#define CORE_THEORY_VM_DEFINITIONS_H

#include "bitvector.h"
#include "bool.h"
#include "rz_lib.h"

// ========= Basic Struct ============
// RzIL_PURE is only a mark to remind the developer
#define RzIL_PURE_VAL
#define RzIL_BITV
#define RzIL_BOOL
#define RzIL_VAR
#define RzIL_EFF
#define RzIL_LABLE
#define RzIL_MEM

typedef enum {
	RZVAR_TYPE_BV,
	RZVAR_TYPE_BOOL,
	RZVAR_TYPE_UNK, // Unkown value
} RZIL_VAR_TYPE;

typedef union {
	BitVector bv;
	Bool b;
} RzValUnion;

struct rz_il_var_t {
	string var_name;
	RZIL_VAR_TYPE type;
};

struct rz_il_val_t {
	RZIL_VAR_TYPE type;
	RzValUnion data;
};

// This structure used to store value instances
typedef void (*RzILBagFreeFunc)(void *);
struct rz_il_bag_t {
	void **data_list;
	int item_count;
	int capcity;
	int *next_pos_stack;
	int next_pos;
	int sp;
	RzILBagFreeFunc free_func;
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

struct rz_il_tempv_t {
	void *data;
	RZIL_TEMP_TYPE type;
};
typedef struct rz_il_tempv_t *RzILTemp;

RzILVar rz_il_new_variable(string name);
RzILVal rz_il_new_value(void);
RzILTemp rz_il_new_temp(void);
RzILVal rz_il_dump_value(RzILVal val);
void rz_il_free_temp(RzILTemp temp);
void rz_il_free_value(RzILVal val);
void rz_il_free_variable(RzILVar var);

RzILBag rz_il_new_bag(int capcity, RzILBagFreeFunc func);
bool rz_il_rm_from_bag(RzILBag bag, void *item);
bool rz_il_add_to_bag(RzILBag bag, void *item);
void rz_il_free_bag(RzILBag bag);

#endif //CORE_THEORY_VM_DEFINITIONS_H
