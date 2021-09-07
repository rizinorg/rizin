// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/effect.h>

/**
 * Create a data effect
 * \return Data effect instance
 */
RZ_API RzILDataEffect rz_il_effect_new_data(void) {
	RzILDataEffect ret;
	ret = (RzILDataEffect)malloc(sizeof(struct rzil_data_effect_t));
	if (!ret) {
		return NULL;
	}
	ret->operation = 0;
	ret->var_name = NULL;
	ret->val_index = -1;
	return ret;
}

/**
 * Create a control effect
 * \return Control effect
 */
RZ_API RzILCtrlEffect rz_il_effect_new_ctrl(void) {
	RzILCtrlEffect ret;
	ret = (RzILCtrlEffect)malloc(sizeof(struct rzil_control_effect_t));
	if (!ret) {
		return NULL;
	}
	ret->pc = 0;
	return ret;
}

/**
 * Pack a control effect to a general effect
 * \param eff control effect
 * \return general effect
 */
RZ_API RzILEffect rz_il_wrap_ctrl_effect(RzILCtrlEffect eff) {
	RzILEffect ret;
	ret = (RzILEffect)malloc(sizeof(struct rzil_effect_union_t));
	if (!ret) {
		return NULL;
	}
	ret->effect_type = EFFECT_TYPE_CTRL;
	ret->ctrl_eff = eff;
	ret->notation = 0;
	ret->next_eff = NULL;
	return ret;
}

/**
 * Pack a data effect to a general effect
 * \param eff data effect
 * \return general effect
 */
RZ_API RzILEffect rz_il_wrap_data_effect(RzILDataEffect eff) {
	RzILEffect ret;
	ret = (RzILEffect)malloc(sizeof(struct rzil_effect_union_t));
	if (!ret) {
		return NULL;
	}
	ret->effect_type = EFFECT_TYPE_DATA;
	ret->data_eff = eff;
	ret->notation = 0;
	ret->next_eff = NULL;
	return ret;
}

/**
 * Free a control effect
 * \param eff control effect to be free
 */
RZ_API void rz_il_effect_free_ctrl(RzILCtrlEffect eff) {
	if (!eff) {
		return;
	}
	free(eff);
}

/**
 * Free a data effect
 * \param eff data effect to be free
 */
RZ_API void rz_il_effect_free_data(RzILDataEffect eff) {
	if (!eff) {
		return;
	}
	free(eff);
}

/**
 * Create a general effect with effect type
 * \param type effect type, can be CONTROL or DATA, see EFFECT_TYPE_* enums
 * \return General effect
 */
RZ_API RzILEffect rz_il_effect_new(EFFECT_TYPE type) {
	RzILEffect ret;

	// can only be data or ctrl
	switch (type) {
	case EFFECT_TYPE_CTRL:
		ret = rz_il_wrap_ctrl_effect(rz_il_effect_new_ctrl());
		break;
	case EFFECT_TYPE_DATA:
		ret = rz_il_wrap_data_effect(rz_il_effect_new_data());
		break;
	case EFFECT_TYPE_NON:
		ret = (RzILEffect)malloc(sizeof(struct rzil_effect_union_t));
		ret->effect_type = EFFECT_TYPE_NON;
		ret->notation = EFFECT_NOTATION_NON;
		ret->data_eff = NULL;
		ret->ctrl_eff = NULL;
		ret->next_eff = NULL;
		break;
	default:
		// not handled in init
		eprintf("error: Unknown type");
		ret = NULL;
		break;
	}
	return ret;
}

/**
 * Free a general effect
 * \param effect a general effect to be free
 */
RZ_API void rz_il_effect_free(RzILEffect effect) {
	if (!effect) {
		return;
	}

	EFFECT_TYPE type = effect->effect_type;
	switch (type) {
	case EFFECT_TYPE_CTRL:
		rz_il_effect_free_ctrl(effect->ctrl_eff);
		effect->ctrl_eff = NULL;
		break;
	case EFFECT_TYPE_DATA:
		rz_il_effect_free_data(effect->data_eff);
		effect->data_eff = NULL;
		break;
	case EFFECT_TYPE_NON:
		break;
	default:
		// not handled
		eprintf("error: Unknown type");
		break;
	}
	free(effect);
}

static char *ctrl_effect_as_string(RzILCtrlEffect eff) {
	if (!eff) {
		return NULL;
	}
	return rz_str_newf("[Ctrl Eff] pc -> %" PFMT64u "\n", rz_il_bv_to_ut64(eff->pc));
}

static char *data_effect_as_string(RzILDataEffect eff) {
	if (!eff) {
		return NULL;
	}
	return rz_str_newf("[Data Eff] varname A: %s, valindex : %d\n", eff->var_name, eff->val_index);
}

/**
 * Make effect info as a string for print
 * \param effect RzILEffect
 * \return char *, effect info string
 */
RZ_API RZ_OWN char *rz_il_effect_as_string(RzILEffect effect) {
	if (!effect) {
		return NULL;
	}

	EFFECT_TYPE type = effect->effect_type;
	switch (type) {
	case EFFECT_TYPE_CTRL:
		return ctrl_effect_as_string(effect->ctrl_eff);
		break;
	case EFFECT_TYPE_DATA:
		return data_effect_as_string(effect->data_eff);
		break;
	case EFFECT_TYPE_NON:
		return rz_str_new("[Non Effect]\n");
		break;
	default:
		// not handled
		eprintf("error: Unknown type when print");
		return NULL;
		break;
	}
}

/**
 * Create an effect label
 * \param name label name
 * \param type Label type
 * \return Pointer to label
 */
RZ_API RzILEffectLabel rz_il_effect_new_label(char *name, EFFECT_LABEL_TYPE type) {
	RzILEffectLabel lbl = (RzILEffectLabel)RZ_NEW0(struct rzil_effect_label_t);
	if (!lbl) {
		return NULL;
	}
	lbl->label_id = strdup(name);
	lbl->type = type;
	return lbl;
}
