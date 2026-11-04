// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test_ui.h"
#include "../rz-test/rz_test.h"

void rz_test_ui_result_free(RZ_NULLABLE RzTestUiResult *result) {
	if (!result) {
		return;
	}
	free(result->actual_screen);
	free(result->fail_diag);
	if (result->fixups) {
		void **it;
		rz_pvector_foreach (result->fixups, it) {
			RzTestUiScreenFixup *fix = *it;
			free(fix->text);
			free(fix);
		}
		rz_pvector_free(result->fixups);
	}
	free(result);
}

static const RzJson *json_field(const RzJson *json, const char *key, RzJsonType type) {
	const RzJson *value = rz_json_get(json, key);
	return value && value->type == type ? value : NULL;
}

static bool load_result(RzTestUiResult *result, char *text) {
	RzJson *json = rz_json_parse(text);
	if (!json) {
		return false;
	}
	bool ok = false;
	const RzJson *version = json_field(json, "version", RZ_JSON_INTEGER);
	const RzJson *completed = json_field(json, "completed", RZ_JSON_BOOLEAN);
	const RzJson *failure = json_field(json, "failed", RZ_JSON_BOOLEAN);
	const RzJson *assertion = json_field(json, "assertion_failed", RZ_JSON_BOOLEAN);
	const RzJson *line = json_field(json, "fail_line", RZ_JSON_INTEGER);
	const RzJson *diag = json_field(json, "diagnostic", RZ_JSON_STRING);
	const RzJson *screen = json_field(json, "screen", RZ_JSON_STRING);
	const RzJson *fixups = json_field(json, "fixups", RZ_JSON_ARRAY);
	if (json->type != RZ_JSON_OBJECT || !version || version->num.u_value != 1 || !completed || !completed->num.u_value ||
		!failure || !assertion || !line || !diag || !screen || !fixups) {
		goto cleanup;
	}
	if (assertion->num.u_value && !failure->num.u_value) {
		goto cleanup;
	}
	result->failed = failure->num.u_value;
	result->assertion_failed = assertion->num.u_value;
	result->fail_line = line->num.u_value;
	result->fail_diag = *diag->str_value ? rz_str_dup(diag->str_value) : NULL;
	result->actual_screen = rz_str_dup(screen->str_value);
	result->fixups = rz_pvector_new(NULL);
	if (!result->actual_screen || (*diag->str_value && !result->fail_diag) || !result->fixups) {
		goto cleanup;
	}
	const RzJson *item = fixups->children.first;
	void **it;
	rz_pvector_foreach (&result->test->steps, it) {
		RzTestUiStep *step = *it;
		if (step->kind != RZ_UI_STEP_EXPECT_SCR) {
			continue;
		}
		const RzJson *begin = item ? json_field(item, "begin", RZ_JSON_INTEGER) : NULL;
		const RzJson *end = item ? json_field(item, "end", RZ_JSON_INTEGER) : NULL;
		const RzJson *capture = item ? json_field(item, "text", RZ_JSON_STRING) : NULL;
		if (!begin || !end || !capture || begin->num.u_value != step->line_begin || end->num.u_value != step->line_end) {
			goto cleanup;
		}
		RzTestUiScreenFixup *fix = RZ_NEW0(RzTestUiScreenFixup);
		if (!fix) {
			goto cleanup;
		}
		fix->line_begin = step->line_begin;
		fix->line_end = step->line_end;
		fix->text = rz_str_dup(capture->str_value);
		if (!fix->text || !rz_pvector_push(result->fixups, fix)) {
			free(fix->text);
			free(fix);
			goto cleanup;
		}
		item = item->next;
	}
	ok = !item;
	result->completed = ok;
cleanup:
	rz_json_free(json);
	return ok;
}

/** \brief Reuse rz-test's portable subprocess lifecycle and executable lookup. */
RZ_OWN RzTestUiResult *rz_test_ui_run(RZ_NONNULL const RzTestUiRunConfig *cfg, RZ_NONNULL RzTestUi *test) {
	RzTestUiResult *result = RZ_NEW0(RzTestUiResult);
	if (!result) {
		return NULL;
	}
	result->test = test;
	ut64 start = rz_time_now_mono();
	char *exe = rz_test_find_executable(cfg->worker_exe ? cfg->worker_exe : "rz-test-ui", cfg->bin_path);
	char *path = NULL;
	int fd = rz_file_mkstemp("rz-test-ui", &path);
	if (fd >= 0) {
		close(fd);
	}
	if (!exe || fd < 0 || !path) {
		result->run_failed = true;
		result->fail_diag = rz_str_dup("could not prepare UI worker");
		goto cleanup;
	}
	char index[32];
	snprintf(index, sizeof(index), "%zu", test->index);
	const char *args[] = { "--worker", test->path, index, path };
	const char *vars[] = { "TZ", "LC_ALL", "TERM", "RZ_NOPLUGINS" };
	const char *vals[] = { "UTC", "C", "xterm-256color", "1" };
	RzSubprocess *proc = rz_subprocess_start(exe, args, RZ_ARRAY_SIZE(args), vars, vals, RZ_ARRAY_SIZE(vars));
	if (!proc) {
		result->run_failed = true;
		result->fail_diag = rz_str_newf("could not start UI worker %s", exe);
		goto cleanup;
	}
	ut64 timeout = test->timeout_ms ? test->timeout_ms : cfg->timeout_ms;
	RzSubprocessWaitReason reason = rz_subprocess_wait(proc, timeout ? timeout : RZ_TEST_UI_TIMEOUT_DEFAULT * 1000);
	if (reason != RZ_SUBPROCESS_DEAD) {
		result->timeout = true;
		rz_subprocess_kill(proc);
	}
	RzSubprocessOutput *out = rz_subprocess_drain(proc);
	char *text = rz_test_ui_read_text(path, RZ_TEST_UI_MAX_RESULT_SIZE);
	if (result->timeout || !out || out->ret != 0 || !text || !load_result(result, text)) {
		result->run_failed = !result->timeout;
		result->completed = false;
		free(result->fail_diag);
		result->fail_diag = rz_str_newf("%s (exit %d)\n%s", result->timeout ? "UI worker timed out" : "UI worker did not complete the script", out ? out->ret : -1, out && out->err ? (char *)out->err : "");
	}
	free(text);
	rz_subprocess_output_free(out);
	rz_subprocess_free(proc);
cleanup:
	if (path) {
		rz_file_rm(path);
	}
	free(path);
	free(exe);
	result->time_elapsed = rz_time_now_mono() - start;
	bool failed = result->run_failed || result->timeout || result->failed;
	// Infrastructure failures are never hidden behind BROKEN.
	result->result = result->run_failed || result->timeout ? RZ_TEST_RESULT_FAILED : failed ? (test->broken ? RZ_TEST_RESULT_BROKEN : RZ_TEST_RESULT_FAILED)
												: (test->broken ? RZ_TEST_RESULT_FIXED : RZ_TEST_RESULT_OK);
	return result;
}
