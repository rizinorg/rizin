// SPDX-FileCopyrightText: 2022 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2013-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_ARM_IT_H
#define RZ_ARM_IT_H

/**
 * \file
 * Tracking of Arm thumb IT blocks during disassembly.
 * Note: all of this is really just a best guess approach.
 */

#include <rz_util.h>
#include <rz_util/ht_uu.h>
#include <capstone/capstone.h>

typedef struct rz_arm_it_context_t {
	HtUU *ht_itblock; ///< addr -> ArmCSITBlock
	HtUU *ht_itcond; ///< addr -> ArmCSITCond
} RzArmITContext;

RZ_API void rz_arm_it_context_init(RzArmITContext *ctx);
RZ_API void rz_arm_it_context_fini(RzArmITContext *ctx);
RZ_API void rz_arm_it_update_block(RzArmITContext *ctx, cs_insn *insn);
RZ_API void rz_arm_it_update_nonblock(RzArmITContext *ctx, cs_insn *insn);
RZ_API bool rz_arm_it_apply_cond(RzArmITContext *ctx, cs_insn *insn);

#endif /* RZ_ARM_IT_H */
