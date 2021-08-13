// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/effect.h>

RZ_API RzILDataEffect effect_new_data(void) {
	RzILDataEffect ret;
	ret = (RzILDataEffect)malloc(sizeof(struct rzil_data_effect_t));
	ret->operation = 0;
	ret->var_name = NULL;
	ret->val_index = -1;
	return ret;
}

RZ_API RzILCtrlEffect effect_new_ctrl(void) {
	RzILCtrlEffect ret;
	ret = (RzILCtrlEffect)malloc(sizeof(struct rzil_control_effect_t));
	ret->pc = 0;
	return ret;
}

RZ_API RzILEffect wrap_ctrl_effect(RzILCtrlEffect eff) {
	RzILEffect ret;
	ret = (RzILEffect)malloc(sizeof(struct rzil_effect_union_t));
	ret->effect_type = EFFECT_TYPE_CTRL;
	ret->ctrl_eff = eff;
	ret->notation = 0;
	ret->next_eff = NULL;
	return ret;
}

RZ_API RzILEffect wrap_data_effect(RzILDataEffect eff) {
	RzILEffect ret;
	ret = (RzILEffect)malloc(sizeof(struct rzil_effect_union_t));
	ret->effect_type = EFFECT_TYPE_DATA;
	ret->data_eff = eff;
	ret->notation = 0;
	ret->next_eff = NULL;
	return ret;
}

RZ_API void effect_free_ctrl(RzILCtrlEffect eff) {
	if (!eff) {
		return;
	}
	free(eff);
}

RZ_API void effect_free_data(RzILDataEffect eff) {
	if (!eff) {
		return;
	}
	free(eff);
}

RZ_API void print_ctrl_effect(RzILCtrlEffect eff) {
	if (!eff) {
		return;
	}
	printf("[Ctrl Eff] pc : \n");
	rz_il_print_bv(eff->pc);
}

RZ_API void print_data_effect(RzILDataEffect eff) {
	if (!eff) {
		return;
	}
	printf("[Data Eff] varname A: %s, valindex : %d\n", eff->var_name, eff->val_index);
}

RZ_API RzILEffect effect_new(EFFECT_TYPE type) {
	RzILEffect ret;

	// can only be data or ctrl
	switch (type) {
	case EFFECT_TYPE_CTRL:
		ret = wrap_ctrl_effect(effect_new_ctrl());
		break;
	case EFFECT_TYPE_DATA:
		ret = wrap_data_effect(effect_new_data());
		break;
	case EFFECT_TYPE_NON:
		ret = (RzILEffect)malloc(sizeof(struct rzil_effect_union_t));
		ret->effect_type = EFFECT_TYPE_NON;
		ret->notation = EFFECT_NOTATION_NON;
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

RZ_API void effect_free(RzILEffect effect) {
	if (!effect) {
		return;
	}

	EFFECT_TYPE type = effect->effect_type;
	switch (type) {
	case EFFECT_TYPE_CTRL:
		effect_free_ctrl(effect->ctrl_eff);
		effect->ctrl_eff = NULL;
		break;
	case EFFECT_TYPE_DATA:
		effect_free_data(effect->data_eff);
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

RZ_API void print_effect(RzILEffect effect) {
	if (!effect) {
		return;
	}

	EFFECT_TYPE type = effect->effect_type;
	switch (type) {
	case EFFECT_TYPE_CTRL:
		print_ctrl_effect(effect->ctrl_eff);
		break;
	case EFFECT_TYPE_DATA:
		print_data_effect(effect->data_eff);
		break;
	case EFFECT_TYPE_NON:
		printf("[Non Effect]\n");
		break;
	default:
		// not handled
		eprintf("error: Unknown type when print");
		break;
	}

	printf("\t");

	EFFECT_NOTATION notation = effect->notation;
	if (notation == EFFECT_NOTATION_NON) {
		printf("NO NOTATION | ");
	}
	if (notation & EFFECT_NOTATION_GOTO_SYS) {
		printf("SYSCALL | ");
	}
	if (notation & EFFECT_NOTATION_GOTO_HOOK) {
		printf("HOOK | ");
	}

	printf("\n");
}

RZ_API RzILEffectLabel effect_new_label(char *name, EFFECT_LABEL_TYPE type) {
	RzILEffectLabel lbl = (RzILEffectLabel)RZ_NEW0(struct rzil_effect_label_t);
	lbl->label_id = strdup(name);
	lbl->type = type;
	return lbl;
}
