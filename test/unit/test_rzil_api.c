#include <rz_core.h>
#include "minunit.h"

bool test_rzil_api_public_exposure(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "rz_core_new failed");

	rz_core_analysis_il_reinit(core);
	mu_assert_notnull(core->analysis->il_vm, "il_vm should be initialized");

	rz_core_analysis_il_init_mem(core, NULL, 0x1000, 0x1000);

	bool res = rz_core_analysis_il_vm_set(core, "PC", 0x1234);
	mu_assert(res, "vm_set failed");

	ut8 op_nop = 0x90;
	rz_core_write_at(core, 0x1234, &op_nop, 1);

	rz_core_analysis_il_vm_status(core, "PC", RZ_OUTPUT_MODE_QUIET);

	rz_core_il_step(core, 1);

	rz_core_il_step_until(core, 0x1235);

	rz_core_analysis_il_step_with_events(core, NULL);

	rz_core_free(core);
	mu_end;
}

int main(int argc, char **argv) {
	mu_run_test(test_rzil_api_public_exposure);
	return 0;
}
