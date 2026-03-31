// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/label.h>

RZ_API RzILEffectLabel *rz_il_effect_label_new(RZ_NONNULL const char *name, RzILEffectLabelType type) {
	RzILEffectLabel *lbl = RZ_NEW0(RzILEffectLabel);
	if (!lbl) {
		return NULL;
	}
	lbl->label_id = rz_str_dup(name);
	lbl->type = type;
	return lbl;
}

RZ_API void rz_il_effect_label_free(RzILEffectLabel *lbl) {
	if (!lbl) {
		return;
	}
	free(lbl->label_id);
	if (lbl->type == EFFECT_LABEL_ADDR) {
		rz_bv_free(lbl->addr);
	}
	free(lbl);
	return;
}

RZ_API RzILEffectLabel *rz_il_effect_label_dup(RZ_NONNULL RzILEffectLabel *lbl) {
	rz_return_val_if_fail(lbl, NULL);
	RzILEffectLabel *r = rz_il_effect_label_new(lbl->label_id, lbl->type);
	if (!r) {
		return NULL;
	}
	if (lbl->type == EFFECT_LABEL_ADDR) {
		r->addr = rz_bv_dup(lbl->addr);
	} else {
		r->hook = lbl->hook;
	}
	return r;
}
