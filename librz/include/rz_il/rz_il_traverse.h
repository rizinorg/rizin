// SPDX-FileCopyrightText: 2026 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_IL_TRAVERSE_H
#define RZ_IL_TRAVERSE_H

#include <rz_il/rz_il_opcodes.h>

typedef enum rz_il_recurse_cont {
	RZ_IL_RECURSE_BREAK,
	RZ_IL_RECURSE_STEP_INTO,
	RZ_IL_RECURSE_STEP_OVER
} RzILRecurseCont;

typedef RzILRecurseCont (*RzILRecursePureCB)(RzILOpPure *op, void *user);
typedef RzILRecurseCont (*RzILRecurseEffectCB)(RzILOpEffect *op, void *user);

RZ_API bool rz_il_op_pure_recurse(RZ_NONNULL RzILOpPure *op, RZ_NONNULL RzILRecursePureCB cb, void *user);
RZ_API bool rz_il_op_effect_recurse(RZ_NONNULL RzILOpEffect *op,
	RZ_NULLABLE RzILRecurseEffectCB effect_cb, void *effect_user,
	RZ_NULLABLE RzILRecursePureCB pure_cb, void *pure_user);

#endif // RZ_IL_TRAVERSE_H
