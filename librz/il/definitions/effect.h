#ifndef CORE_THEORY_VM_EFFECT_H
#define CORE_THEORY_VM_EFFECT_H

#include <stdlib.h>
#include <stdio.h>
#include <rz_util.h>
#include <rz_types.h>
#include "common.h"
#include "bitvector.h"
/*** ***************************
 * Effect definitions
 * *******************************/
typedef enum {
	EFFECT_TYPE_NON, // perform none effect will not affect data / control, used for passing info
	EFFECT_TYPE_DATA,
	EFFECT_TYPE_CTRL,
} EFFECT_TYPE;

typedef enum {
	EFFECT_NOTATION_NON = 0x0,
	EFFECT_NOTATION_GOTO_SYS = 0x1,
	EFFECT_NOTATION_GOTO_HOOK = 0x2
} EFFECT_NOTATION;

typedef enum {
	EFFECT_LABEL_ADDR,
	EFFECT_LABEL_SYSCALL,
	EFFECT_LABEL_HOOK
	// more
} EFFECT_LABEL_TYPE;

typedef enum {
	DATA_EFF_NON,
	DATA_EFF_ASSIGN,
	DATA_EFF_INC
	// maybe more
} DATA_EFF_OPERATION;

struct effect_label_t {
	string label_id;
	BitVector addr;
	EFFECT_LABEL_TYPE type;
};

struct control_effect_t {
	BitVector pc;
};

struct data_effect_t {
	string var_name;
	int val_index;
	DATA_EFF_OPERATION operation;
};

typedef struct control_effect_t *CtrlEffect;
typedef struct data_effect_t *DataEffect;
typedef struct effect_label_t *EffectLabel;

typedef struct effect_union_t *Effect;
struct effect_union_t {
	ut8 effect_type;
	EFFECT_NOTATION notation;
	Effect next_eff;
	union {
		CtrlEffect ctrl_eff;
		DataEffect data_eff;
	};
};

// a chain off effects
// should use something like rz_vector / rz_list
Effect effect_new(EFFECT_TYPE type);
DataEffect effect_new_data(void);
CtrlEffect effect_new_ctrl(void);
Effect wrap_ctrl_effect(CtrlEffect eff);
Effect wrap_data_effect(DataEffect eff);
EffectLabel effect_new_label(string name, EFFECT_LABEL_TYPE type);
void effect_free(Effect effect);
void effect_free_ctrl(CtrlEffect eff);
void effect_free_data(DataEffect eff);
void print_effect(Effect effect);
void print_ctrl_effect(CtrlEffect eff);
void print_data_effect(DataEffect eff);

#endif //CORE_THEORY_VM_EFFECT_H
