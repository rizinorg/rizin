// SPDX-FileCopyrightText: 2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2021 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>

/**
 * \brief Get the currently relevant RzReg
 *
 * Depending on whether or not the core is in debug mode, this returns the RzReg
 * from debug or analysis (emulation).
 * Before using this function, think twice whether it would not make more sense
 * to use core->dbg->reg or analysis->dbg->reg directly, depending on what you want
 * to do with it.
 */
RZ_API RzReg *rz_core_reg_default(RzCore *core) {
	return rz_core_is_debug(core) ? core->dbg->reg : core->analysis->reg;
}

/// Construct the list of registers that should be applied as flags by default
/// (e.g. because their size matches the pointer size)
RZ_IPI RzList /*<RzRegItem>*/ *rz_core_reg_flags_candidates(RzCore *core, RzReg *reg) {
	const RzList *l = rz_reg_get_list(reg, RZ_REG_TYPE_GPR);
	if (!l) {
		return NULL;
	}
	int size = rz_analysis_get_address_bits(core->analysis);
	RzList *ret = rz_list_new();
	if (!ret) {
		return NULL;
	}
	RzListIter *iter;
	RzRegItem *item;
	rz_list_foreach (l, iter, item) {
		if (size != 0 && size != item->size) {
			continue;
		}
		rz_list_push(ret, item);
	}
	return ret;
}

static void regs_to_flags(RzCore *core, RzReg *regs) {
	rz_return_if_fail(core && regs);
	RzList *l = rz_core_reg_flags_candidates(core, regs);
	if (!l) {
		return;
	}
	rz_flag_space_push(core->flags, RZ_FLAGS_FS_REGISTERS);
	RzListIter *iter;
	RzRegItem *reg;
	rz_list_foreach (l, iter, reg) {
		ut64 regval = rz_reg_get_value(regs, reg);
		rz_flag_set(core->flags, reg->name, regval, reg->size / 8);
	}
	rz_flag_space_pop(core->flags);
	rz_list_free(l);
}

/**
 * \brief Update or create flags for all registers where it makes sense
 *
 * Registers are taken either from rz_core_reg_default().
 * "makes sens" currently means regs that have the same size as an address,
 * but this may change in case a better heuristic is found.
 */
RZ_IPI void rz_core_reg_update_flags(RzCore *core) {
	if (rz_core_is_debug(core) && !rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false)) {
		return;
	}
	regs_to_flags(core, rz_core_reg_default(core));
}
