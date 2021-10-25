// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_EFFECT_H
#define RZ_IL_EFFECT_H

#include <stdlib.h>
#include <stdio.h>
#include <rz_util.h>
#include <rz_type.h>
#include <rz_il/definitions/value.h>

#ifdef __cplusplus
extern "C" {
#endif

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

struct rzil_effect_label_t {
	char *label_id; ///< Label name
	RzILBitVector *addr; ///< RzILBitVector address if EFFECT_LABEL_ADDR
		///< Function pointer if EFFECT_LABEL_SYSCALL / EFFECT_LABEL_HOOK
	EFFECT_LABEL_TYPE type; ///< type of label
};

struct rzil_control_effect_t {
	RzILBitVector *pc; ///< New Program Counter
};

struct rzil_data_effect_t {
	const char *var_name; ///< Name of variable, const one
	RzILVal *val;
	DATA_EFF_OPERATION operation; ///< operation to value and variable
};

typedef struct rzil_control_effect_t RzILCtrlEffect;
typedef struct rzil_data_effect_t RzILDataEffect;
typedef struct rzil_effect_label_t RzILEffectLabel;

typedef struct rzil_effect_union_t RzILEffect;
/**
 *  \struct rzil_effect_union_t
 *  \brief structure of data/control effect
 */
struct rzil_effect_union_t {
	ut8 effect_type; ///< effect type
	EFFECT_NOTATION notation; ///< Marks for carring additional info
	RzILEffect *next_eff; ///< pointer to next effect, used in packed effect
	union {
		RzILCtrlEffect *ctrl_eff; ///< pointer to ctrl effect
		RzILDataEffect *data_eff; ///< pointer to data effect
	};
};

// a chain of effects
// should use something like rz_vector / rz_list
RZ_API RzILEffect *rz_il_effect_new(EFFECT_TYPE type);
RZ_API RzILDataEffect *rz_il_effect_data_new(void);
RZ_API RzILCtrlEffect *rz_il_effect_ctrl_new(void);
RZ_API RzILEffect *rz_il_wrap_ctrl_effect(RzILCtrlEffect *eff);
RZ_API RzILEffect *rz_il_wrap_data_effect(RzILDataEffect *eff);
RZ_API RzILEffectLabel *rz_il_effect_label_new(const char *name, EFFECT_LABEL_TYPE type);
RZ_API void rz_il_effect_free(RzILEffect *effect);
RZ_API void rz_il_effect_ctrl_free(RzILCtrlEffect *eff);
RZ_API void rz_il_effect_data_free(RzILDataEffect *eff);
RZ_API char *rz_il_effect_as_string(RzILEffect *effect);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_EFFECT_H
