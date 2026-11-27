// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

typedef struct {
	bool attached;
	bool fail_attach;
	bool premature_read;
	unsigned attaches;
	unsigned reads;
} DebugSetupMock;

static bool setup_mock_init(RzDebug *dbg, void **user) {
	*user = RZ_NEW0(DebugSetupMock);
	return *user != NULL;
}

static void setup_mock_fini(RzDebug *dbg, void *user) {
	free(user);
}

static int setup_mock_attach(RzDebug *dbg, int pid) {
	DebugSetupMock *mock = dbg->plugin_data;
	mock->attaches++;
	dbg->pid = pid;
	dbg->tid = pid;
	if (mock->fail_attach) {
		return -1;
	}
	mock->attached = true;
	return pid;
}

static char *setup_mock_profile(RzDebug *dbg) {
	return rz_str_dup("=PC pc\ngpr pc .64 0 0\n");
}

static int setup_mock_read(RzDebug *dbg, int type, ut8 *buf, int size) {
	DebugSetupMock *mock = dbg->plugin_data;
	mock->reads++;
	if (!mock->attached) {
		mock->premature_read = true;
		return 0;
	}
	if (type != RZ_REG_TYPE_GPR || size < sizeof(ut64)) {
		return 0;
	}
	rz_write_le64(buf, 0x20);
	return sizeof(ut64);
}

static RzDebugPlugin setup_mock_plugin = {
	.name = "setup-mock",
	.arch = "x86",
	.bits = RZ_SYS_BITS_64,
	.init = setup_mock_init,
	.fini = setup_mock_fini,
	.attach = setup_mock_attach,
	.reg_profile = setup_mock_profile,
	.reg_read = setup_mock_read,
};

static int setup_mock_pid(RzIODesc *desc) {
	return 42;
}

static char *setup_mock_system(RzIO *io, RzIODesc *desc, const char *command) {
	return NULL;
}

bool test_core_debug_setup(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core");
	mu_assert_true(rz_debug_plugin_add(core->dbg, &setup_mock_plugin), "add plugin");
	mu_assert_notnull(rz_config_set(core->config, "dbg.backend", "setup-mock"), "backend");
	RzCoreFile *file = rz_core_file_open(core, "malloc://256", RZ_PERM_RW, 0);
	mu_assert_notnull(file, "file");
	RzIODesc *desc = rz_io_desc_get(core->io, file->fd);
	mu_assert_notnull(desc, "descriptor");
	// Retain the memory descriptor's allocation and cleanup, but expose a mock process.
	RzIOPlugin io_plugin = *desc->plugin;
	io_plugin.isdbg = true;
	io_plugin.getpid = setup_mock_pid;
	io_plugin.gettid = setup_mock_pid;
	io_plugin.system = setup_mock_system;
	desc->plugin = &io_plugin;
	DebugSetupMock *mock = core->dbg->plugin_data;
	mu_assert_notnull(mock, "mock context");

	mu_assert_notnull(rz_config_set_b(core->config, "cfg.debug", true), "debug mode");
	mu_assert_eq(mock->reads, 0, "enabling debug mode must not read unattached registers");
	mock->fail_attach = true;
	mu_assert_false(rz_core_setup_debugger(core, "setup-mock", true), "failed attach");
	mu_assert_eq(mock->attaches, 1, "one attach attempt");
	mu_assert_eq(core->dbg->pid, -1, "failed target must not be killed during exit cleanup");
	mu_assert_eq(core->dbg->tid, -1, "failed thread is not selected");
	mu_assert_eq(core->dbg->main_pid, -1, "failed process is not selected");
	mu_assert_eq(mock->reads, 0, "failed attach must not read registers");
	mu_assert_false(mock->premature_read, "no read before attach");

	mock->fail_attach = false;
	mu_assert_true(rz_core_setup_debugger(core, "setup-mock", true), "successful attach");
	mu_assert_eq(mock->attaches, 2, "retry attach");
	mu_assert_true(mock->reads > 0, "read registers after attach");
	mu_assert_false(mock->premature_read, "attach precedes register reads");
	mu_assert_eq(core->offset, 0x20, "seek to attached PC");

	unsigned reads = mock->reads;
	mu_assert_true(rz_core_setup_debugger(core, "setup-mock", false), "already attached");
	mu_assert_eq(mock->attaches, 2, "do not attach when not requested");
	mu_assert_true(mock->reads > reads, "refresh existing target's registers");
	rz_core_free(core);
	mu_end;
}

bool all_tests(void) {
	mu_run_test(test_core_debug_setup);
	return tests_passed != tests_run;
}

mu_main(all_tests)
