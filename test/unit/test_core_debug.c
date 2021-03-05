#include <rz_core.h>
#include "minunit.h"

#define BACKEND "native"

const char *aux_dir;

bool test_debug(void) {
	char *exe = rz_file_path_join(aux_dir, "subprocess-helloworld");
	char *uri = rz_str_newf("dbg://%s", exe);
	free(exe);
	eprintf("open %s\n", uri);
	RzCore *core = rz_core_new();
	rz_core_task_sync_begin(&core->tasks);
	rz_config_set(core->config, "cfg.debug", "true");
	int perms = RZ_PERM_RWX;
	rz_core_file_open(core, uri, perms, 0);
	rz_debug_use(core->dbg, BACKEND);
	ut64 baddr = rz_debug_get_baddr(core->dbg, uri);
	rz_core_bin_load(core, uri, baddr);
	rz_core_cmd0(core, ".dm*");
	rz_core_cmd0(core, "dr? thumb;?? e asm.bits=16");
	rz_core_cmd0(core, "=!");
	rz_core_setup_debugger(core, BACKEND, baddr == UT64_MAX);
	rz_flag_space_set(core->flags, NULL);
	rz_core_cmd0(core, "omfg+w");

	rz_cons_push();
	rz_core_cmd0(core, "dm");
	rz_cons_flush();
	rz_cons_pop();

	rz_core_task_sync_end(&core->tasks);
	rz_core_free(core);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_debug);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	if (argc != 2) {
		eprintf("Usage: %s [path-to-auxiliary-binaries]\n", argv[0]);
		return -1;
	}
	aux_dir = argv[1];
	return all_tests();
}
