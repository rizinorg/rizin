// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include "minunit.h"

typedef struct test_core_plugin_context_t {
	int magic;
} TestCorePluginContext;

static int context_init_count = 0;
static int context_fini_count = 0;
static int legacy_init_count = 0;
static int legacy_fini_count = 0;

static bool test_context_init(RzCore *core, void **user) {
	(void)core;
	TestCorePluginContext *ctx = RZ_NEW0(TestCorePluginContext);
	if (!ctx) {
		return false;
	}
	ctx->magic = 0x1337;
	*user = ctx;
	context_init_count++;
	return true;
}

static bool test_context_fini(RzCore *core, void *user) {
	(void)core;
	TestCorePluginContext *ctx = user;
	if (!ctx || ctx->magic != 0x1337) {
		return false;
	}
	free(ctx);
	context_fini_count++;
	return true;
}

static bool test_legacy_init(RzCore *core) {
	(void)core;
	legacy_init_count++;
	return true;
}

static bool test_legacy_fini(RzCore *core) {
	(void)core;
	legacy_fini_count++;
	return true;
}

static bool test_core_plugin_context_lifecycle(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");

	RzCorePlugin plugin = {
		.name = "context-test",
		.desc = "context test plugin",
		.license = "LGPL-3.0-only",
		.author = "RizinOrg",
		.version = "1.0",
		.init_context = test_context_init,
		.fini_context = test_context_fini,
	};

	context_init_count = 0;
	context_fini_count = 0;
	mu_assert_true(rz_core_plugin_add(core, &plugin), "context plugin should be added");
	mu_assert_eq(context_init_count, 1, "context init should be called once");

	TestCorePluginContext *ctx = rz_core_plugin_context_get(core, "context-test");
	mu_assert_notnull(ctx, "context should be stored on the core");
	mu_assert_eq(ctx->magic, 0x1337, "context should preserve plugin state");

	mu_assert_true(rz_core_plugin_del(core, &plugin), "context plugin should be deleted");
	mu_assert_eq(context_fini_count, 1, "context fini should be called once");
	mu_assert_null(rz_core_plugin_context_get(core, "context-test"), "context should be removed after plugin deletion");

	rz_core_free(core);
	mu_end;
}

static bool test_core_plugin_legacy_lifecycle(void) {
	RzCore *core = rz_core_new();
	mu_assert_notnull(core, "core should be created");

	RzCorePlugin plugin = {
		.name = "legacy-test",
		.desc = "legacy test plugin",
		.license = "LGPL-3.0-only",
		.author = "RizinOrg",
		.version = "1.0",
		.init = test_legacy_init,
		.fini = test_legacy_fini,
	};

	legacy_init_count = 0;
	legacy_fini_count = 0;
	mu_assert_true(rz_core_plugin_add(core, &plugin), "legacy plugin should be added");
	mu_assert_eq(legacy_init_count, 1, "legacy init should be called once");
	mu_assert_null(rz_core_plugin_context_get(core, "legacy-test"), "legacy plugin should not get implicit context");

	mu_assert_true(rz_core_plugin_del(core, &plugin), "legacy plugin should be deleted");
	mu_assert_eq(legacy_fini_count, 1, "legacy fini should be called once");

	rz_core_free(core);
	mu_end;
}

int all_tests(void) {
	mu_run_test(test_core_plugin_context_lifecycle);
	mu_run_test(test_core_plugin_legacy_lifecycle);
	return tests_passed != tests_run;
}

mu_main(all_tests)
