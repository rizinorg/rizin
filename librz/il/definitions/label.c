// SPDX-FileCopyrightText: 2021 heersin <teablearcher@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_il/definitions/label.h>

/**
 * Create an effect label
 * \param name label name
 * \param type Label type
 * \return Pointer to label
 */
RZ_API RzILEffectLabel *rz_il_effect_label_new(RZ_NONNULL const char *name, RzILEffectLabelType type) {
	RzILEffectLabel *lbl = RZ_NEW0(RzILEffectLabel);
	if (!lbl) {
		return NULL;
	}
	lbl->label_id = strdup(name);
	lbl->type = type;
	return lbl;
}
