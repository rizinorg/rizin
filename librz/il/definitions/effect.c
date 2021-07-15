#include "effect.h"
/*** ***************************
 * Effect definitions
 * *******************************/

DataEffect effect_new_data(void) {
	DataEffect ret;
	ret = (DataEffect)malloc(sizeof(struct data_effect_t));
	ret->operation = 0;
	ret->var_name = NULL;
	ret->val_index = -1;
	return ret;
}

CtrlEffect effect_new_ctrl(void) {
	CtrlEffect ret;
	ret = (CtrlEffect)malloc(sizeof(struct control_effect_t));
	ret->pc = 0;
	return ret;
}

Effect wrap_ctrl_effect(CtrlEffect eff) {
	Effect ret;
	ret = (Effect)malloc(sizeof(struct effect_union_t));
	ret->effect_type = EFFECT_TYPE_CTRL;
	ret->ctrl_eff = eff;
	ret->notation = 0;
	ret->next_eff = NULL;
	return ret;
}

Effect wrap_data_effect(DataEffect eff) {
	Effect ret;
	ret = (Effect)malloc(sizeof(struct effect_union_t));
	ret->effect_type = EFFECT_TYPE_DATA;
	ret->data_eff = eff;
	ret->notation = 0;
	ret->next_eff = NULL;
	return ret;
}

void effect_free_ctrl(CtrlEffect eff) {
	if (!eff) {
		return;
	}
	free(eff);
}

void effect_free_data(DataEffect eff) {
	if (!eff) {
		return;
	}
	free(eff);
}

void print_ctrl_effect(CtrlEffect eff) {
	if (!eff) {
		return;
	}
	printf("[Ctrl Eff] pc : + 0x%llx\n", eff->pc);
}
void print_data_effect(DataEffect eff) {
	if (!eff) {
		return;
	}
	printf("[Data Eff] varname A: %s, valindex : %d\n", eff->var_name, eff->val_index);
}

Effect effect_new(EFFECT_TYPE type) {
	Effect ret;

	// can only be data or ctrl
	switch (type) {
	case EFFECT_TYPE_CTRL:
		ret = wrap_ctrl_effect(effect_new_ctrl());
		break;
	case EFFECT_TYPE_DATA:
		ret = wrap_data_effect(effect_new_data());
		break;
	case EFFECT_TYPE_NON:
		ret = (Effect)malloc(sizeof(struct effect_union_t));
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

void effect_free(Effect effect) {
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

// effect A <- effect B <- effect C <- NULL
// if A then B else C
// in MIPS will be
void print_effect(Effect effect) {
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

EffectLabel effect_new_label(string name, EFFECT_LABEL_TYPE type) {
	EffectLabel lbl = (EffectLabel)RZ_NEW0(struct effect_label_t);
	lbl->label_id = strdup(name);
	lbl->type = type;
	return lbl;
}
