// SPDX-FileCopyrightText: 2022 Riccardo Schirone <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include "minunit.h"

static int small_check(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	mu_assert_streq(output, "ERROR: 3", "small check msg should be correct");
	return 0;
}

static int bind_check(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	mu_assert_streq(output, "ERROR: 3", "bind check msg should be correct");
	return 0;
}

static int large_check(const char *output, const char *funcname, const char *filename,
	ut32 lineno, RzLogLevel level, const char *tag, const char *fmtstr, ...) {
	char *exp_msg = RZ_NEWS0(char, 2000);
	strcpy(exp_msg, "ERROR: ");
	for (size_t i = 0; i < 999; i++) {
		exp_msg[strlen("ERROR: ") + i] = 'A';
	}
	mu_assert_streq(output, exp_msg, "large check msg should be correct");
	free(exp_msg);
	return 0;
}

bool test_log_small(void) {
	rz_log_del_callback((RzLogCallback)large_check);
	rz_log_del_callback((RzLogCallback)bind_check);
	rz_log_add_callback((RzLogCallback)small_check);
	rz_log("func", "file", 1, RZ_LOGLVL_ERROR, NULL, "%d", 3);
	mu_end;
}

bool test_log_binding(void) {
	rz_log_del_callback((RzLogCallback)large_check);
	rz_log_del_callback((RzLogCallback)small_check);
	rz_log_add_callback((RzLogCallback)bind_check);
	rz_log_str("func", "file", 1, RZ_LOGLVL_ERROR, NULL, "3");
	mu_end;
}

bool test_log_large(void) {
	rz_log_del_callback((RzLogCallback)small_check);
	rz_log_del_callback((RzLogCallback)bind_check);
	rz_log_add_callback((RzLogCallback)large_check);
	char *buf = RZ_NEWS(char, 1000);
	memset(buf, 0x41, 999);
	buf[999] = '\0';
	rz_log("func", "file", 1, RZ_LOGLVL_ERROR, NULL, "%s", buf);
	free(buf);
	mu_end;
}

bool test_log_set_get(void) {
	rz_log_del_callback((RzLogCallback)small_check);
	rz_log_del_callback((RzLogCallback)bind_check);
	rz_log_set_level(RZ_LOGLVL_FATAL);
	mu_assert_eq(rz_log_get_level(), RZ_LOGLVL_FATAL, "Setter/Getter");
	rz_log_set_level(RZ_LOGLVL_DEBUG);
	mu_assert_eq(rz_log_get_level(), RZ_LOGLVL_DEBUG, "Setter/Getter");
	mu_end;
}

typedef struct {
	int count;
	RzLogLevel last_level;
	char last_msg[64];
} TestLogObserverCtx;

static void test_log_observer_cb(RzLogLevel level, const char *msg, void *user) {
	TestLogObserverCtx *ctx = user;
	ctx->count++;
	ctx->last_level = level;
	rz_str_ncpy(ctx->last_msg, msg ? msg : "", sizeof(ctx->last_msg));
}

static void test_log_observer_cb2(RzLogLevel level, const char *msg, void *user) {
	TestLogObserverCtx *ctx = user;
	ctx->count++;
	ctx->last_level = level;
	rz_str_ncpy(ctx->last_msg, msg ? msg : "", sizeof(ctx->last_msg));
}

static void call_vlog_out(const char **out, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	rz_vlog("func", "file", 1, RZ_LOGLVL_WARN, NULL, out, fmt, ap);
	va_end(ap);
}

bool test_log_observer(void) {
	rz_log_del_callback((RzLogCallback)large_check);
	rz_log_del_callback((RzLogCallback)small_check);
	rz_log_del_callback((RzLogCallback)bind_check);
	TestLogObserverCtx ctx1 = { 0 };
	TestLogObserverCtx ctx2 = { 0 };
	TestLogObserverCtx ctx3 = { 0 };

	rz_log_add_observer(NULL, NULL);
	rz_log_del_observer(NULL, NULL);
	rz_log_del_observer(test_log_observer_cb, &ctx1);

	rz_log_add_observer(test_log_observer_cb, &ctx1);
	rz_log_add_observer(test_log_observer_cb, &ctx1); // duplicate ignored
	rz_log_add_observer(test_log_observer_cb, &ctx2);
	rz_log_add_observer(test_log_observer_cb2, &ctx3);

	RZ_LOG_WARN("obs-both\n");
	mu_assert_eq(ctx1.count, 1, "first observer should fire once");
	mu_assert_eq(ctx2.count, 1, "second observer should fire once");
	mu_assert_eq(ctx3.count, 1, "distinct callback observer should fire once");
	mu_assert_eq(ctx1.last_level, RZ_LOGLVL_WARN, "observer level should match");
	mu_assert_streq(ctx1.last_msg, "obs-both\n", "observer message should match");

	// Source prefixes must be stripped from observer messages
	rz_log_set_show_sources(true);
	RZ_LOG_WARN("obs-nosrc\n");
	rz_log_set_show_sources(false);
	mu_assert_streq(ctx3.last_msg, "obs-nosrc\n", "observer must receive unprefixed message");

	// Captured out != NULL must not notify observers
	const char *captured = NULL;
	call_vlog_out(&captured, "obs-skip-%d", 1);
	mu_assert_notnull(captured, "rz_vlog out should capture formatted message");
	free((char *)captured);
	mu_assert_eq(ctx1.count, 2, "observer must not fire when out != NULL");
	mu_assert_eq(ctx2.count, 2, "second observer must not fire when out != NULL");
	mu_assert_eq(ctx3.count, 2, "third observer must not fire when out != NULL");

	// Removing non-existent observer leaves registered observers intact
	rz_log_del_observer(test_log_observer_cb, &ctx3);
	rz_log_del_observer(test_log_observer_cb2, &ctx3);
	rz_log_del_observer(test_log_observer_cb, &ctx1);
	RZ_LOG_ERROR("obs-second-only\n");
	mu_assert_eq(ctx1.count, 2, "removed observer must not fire");
	mu_assert_eq(ctx2.count, 3, "remaining observer must still fire");
	mu_assert_eq(ctx3.count, 2, "removed distinct observer must not fire");
	mu_assert_eq(ctx2.last_level, RZ_LOGLVL_ERROR, "second observer level should match");

	rz_log_del_observer(test_log_observer_cb, &ctx2);
	RZ_LOG_WARN("obs-none\n");
	mu_assert_eq(ctx2.count, 3, "all removed observers must stay silent");

	// Quiet log.level suppresses stderr/callbacks while still delivering WARN+ to observers
	RzLogLevel prev_lvl = rz_log_get_level();
	rz_log_set_level(RZ_LOGLVL_NONE);
	RZ_LOG_WARN("obs-quiet-no-obs\n");
	rz_log_add_observer(test_log_observer_cb, &ctx1);
	RZ_LOG_INFO("obs-quiet-info\n");
	mu_assert_eq(ctx1.count, 2, "INFO below WARN must stay suppressed when log.level is NONE");
	RZ_LOG_WARN("obs-quiet-warn\n");
	mu_assert_eq(ctx1.count, 3, "WARN must reach observer even when log.level is NONE");
	mu_assert_streq(ctx1.last_msg, "obs-quiet-warn\n", "quiet observer message should match");
	rz_log_del_observer(test_log_observer_cb, &ctx1);
	rz_log_set_level(prev_lvl);
	mu_end;
}

bool all_tests() {
	mu_run_test(test_log_small);
	mu_run_test(test_log_binding);
	mu_run_test(test_log_large);
	mu_run_test(test_log_set_get);
	mu_run_test(test_log_observer);
	return tests_passed != tests_run;
}

mu_main(all_tests)
