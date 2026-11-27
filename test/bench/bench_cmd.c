// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "bench_utils.h"
#include <rz_core.h>

/**
 * \file bench_cmd.c
 * \brief Benchmark for command parsing and execution via rz_core_cmd0().
 */

static void bench_cmd_exec(RzTable *t_out, const char *title, RzCore *core, const char *cmd, ut64 iterations) {
	RZ_BENCH_RUN(title, t_out, iterations, {
		int rc = rz_core_cmd0(core, cmd);
		RZ_DONT_OPTIMIZE(int, rc);
	});
}

int main() {
	RzCore *core = rz_core_new();
	if (!core) {
		return 1;
	}
	rz_config_set_b(core->config, "scr.null", true);
	rz_core_cmd0(core, "o malloc://64");
	rz_core_cmd0(core, "(m_inner x; %v ${x}+1)");
	rz_core_cmd0(core, "(m_outer a; .(m_inner ${a}); %v ${a}+2)");

	RzTable *t = rz_table_new();
	RZ_BENCH_TABLE_INIT(t);

	bench_cmd_exec(t, "rz_core_cmd0: %v 1+2", core, "%v 1+2", 2000);
	bench_cmd_exec(t, "rz_core_cmd0: %v 1+2 @ 0x10", core, "%v 1+2 @ 0x10", 2000);
	bench_cmd_exec(t, "rz_core_cmd0: nested macro .(m_outer 5)", core, ".(m_outer 5)", 500);

	RZ_BENCH_TABLE_PRINT_AND_FREE(t);
	rz_core_free(core);
	return 0;
}
