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
	EFFECT_LABEL_ADDR,
	EFFECT_LABEL_SYSCALL,
	EFFECT_LABEL_HOOK
	// more
} RzILEffectLabelType;

typedef struct rz_il_effect_label_t {
	char *label_id; ///< Label name
	union {
		RzBitVector *addr; ///< RzBitVector address if EFFECT_LABEL_ADDR
		void *hook; ///< Function pointer if EFFECT_LABEL_SYSCALL / EFFECT_LABEL_HOOK
	};
	RzILEffectLabelType type; ///< type of label
} RzILEffectLabel;

RZ_API RzILEffectLabel *rz_il_effect_label_new(RZ_NONNULL const char *name, RzILEffectLabelType type);
RZ_API void rz_il_effect_label_free(RzILEffectLabel *lbl);
RZ_API RzILEffectLabel *rz_il_effect_label_dup(RZ_NONNULL RzILEffectLabel *lbl);

#ifdef __cplusplus
}
#endif

#endif // RZ_IL_EFFECT_H
