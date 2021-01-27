// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_debug.h>

RZ_API bool rz_core_debug_step_one(RzCore *core, int times) {
	if (rz_config_get_i(core->config, "cfg.debug")) {
		rz_reg_arena_swap(core->dbg->reg, true);
		// sync registers for BSD PT_STEP/PT_CONT
		rz_debug_reg_sync(core->dbg, RZ_REG_TYPE_GPR, false);
		ut64 pc = rz_debug_reg_get(core->dbg, "PC");
		rz_debug_trace_pc(core->dbg, pc);
		if (!rz_debug_step(core->dbg, times)) {
			eprintf("Step failed\n");
			core->break_loop = true;
			return false;
		}
	} else {
		int i = 0;
		do {
			rz_core_esil_step(core, UT64_MAX, NULL, NULL, false);
			rz_core_cmd0(core, ".ar*");
			i++;
		} while (i < times);
	}
	return true;
}
