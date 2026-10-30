// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test_ui.h"
#include <rz_main.h>
#include <rz_diff.h>

static bool resolve_col(RzVScreen *scr, st64 col, ut32 *out) {
	st64 cols = (st64)rz_vscreen_cols(scr);
	st64 c = col < 0 ? cols + col : col;
	if (c < 0 || c >= cols) {
		return false;
	}
	*out = (ut32)c;
	return true;
}

// Render a code point for diagnostics: printable ASCII as 'x', otherwise U+XXXX.
static char *fmt_cp(ut32 cp) {
	if (cp >= 0x20 && cp < 0x7f) {
		return rz_str_newf("'%c'", (char)cp);
	}
	return rz_str_newf("U+%04X", cp);
}

// Decode the first UTF-8 code point of s (' ' if empty / undecodable).
static ut32 decode_first(const char *s) {
	if (RZ_STR_ISEMPTY(s)) {
		return ' ';
	}
	RzCodePoint cp = ' ';
	size_t adv = rz_utf8_decode((const ut8 *)s, strlen(s), &cp, false);
	if (!adv) {
		cp = (ut8)s[0];
	}
	return (ut32)cp;
}

/** \brief Trim only terminal padding; interior blank rows are significant. */
static char *normalize_screen(const char *input) {
	if (!input) {
		return NULL;
	}
	RzStrBuf output;
	rz_strbuf_init(&output);
	const char *line = input;
	while (*line) {
		const char *next = strchr(line, '\n');
		size_t len = next ? (size_t)(next - line) : strlen(line);
		while (len && (line[len - 1] == ' ' || line[len - 1] == '\r')) {
			len--;
		}
		if (!rz_strbuf_append_n(&output, line, len) || !rz_strbuf_append(&output, "\n")) {
			rz_strbuf_fini(&output);
			return NULL;
		}
		line = next ? next + 1 : line + strlen(line);
	}
	char *text = rz_strbuf_drain_nofree(&output);
	if (text) {
		size_t len = strlen(text);
		while (len && text[len - 1] == '\n') {
			text[--len] = 0;
		}
	}
	return text;
}

static void fail(RzTestUiResult *res, ut64 line, const char *fmt, ...) {
	res->failed = true;
	res->assertion_failed = true;
	if (res->fail_diag) {
		return; // keep the first failure
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vappendf(&sb, fmt, ap);
	va_end(ap);
	res->fail_diag = rz_strbuf_drain_nofree(&sb);
	res->fail_line = line;
}

/** \brief A regex engine failure is not evidence that a pattern is absent. */
static void check_regex(RzTestUiResult *result, RzTestUiStep *step, const char *text, bool negative) {
	RzRegex *regex = text ? rz_regex_new(step->arg_s, RZ_REGEX_DEFAULT, RZ_REGEX_DEFAULT, NULL) : NULL;
	if (!regex) {
		result->run_failed = true;
		fail(result, step->line_begin, "could not prepare regex assertion");
		return;
	}
	RzRegexStatus status = rz_regex_match(regex, text, RZ_REGEX_ZERO_TERMINATED, 0, RZ_REGEX_DEFAULT);
	rz_regex_free(regex);
	if (status < RZ_REGEX_ERROR_NOMATCH) {
		result->run_failed = true;
		fail(result, step->line_begin, "regex evaluation failed (%d)", (int)status);
	} else if ((status >= 0) == negative) {
		fail(result, step->line_begin, "%s regex /%s/", negative ? "unexpected match for" : "no match for", step->arg_s);
	}
}

static void check_at(RzTestUiResult *res, RzVScreen *scr, RzTestUiStep *st) {
	ut32 col0;
	if (!resolve_col(scr, st->arg_col, &col0)) {
		fail(res, st->line_begin, "column %" PFMT64d " is out of range (width %u)",
			(st64)st->arg_col, rz_vscreen_cols(scr));
		return;
	}
	const ut8 *p = (const ut8 *)st->arg_s;
	size_t len = st->arg_s ? strlen(st->arg_s) : 0;
	size_t i = 0;
	ut32 cx = col0;
	bool mism = false;
	ut32 want = 0, got = 0, at = col0;
	while (i < len) {
		RzCodePoint cp = 0;
		size_t adv = rz_utf8_decode(p + i, len - i, &cp, false);
		if (!adv) {
			adv = 1;
			cp = p[i];
		}
		if (cx >= rz_vscreen_cols(scr)) {
			fail(res, st->line_begin, "text extends past the right edge");
			break;
		}
		got = rz_vscreen_cell(scr, (ut32)st->arg_n, cx);
		if (got != (ut32)cp) {
			mism = true;
			want = cp;
			at = cx;
			break;
		}
		i += adv;
		cx += rz_str_char_fullwidth((const char *)p + i - adv, adv) ? 2 : 1;
	}
	if (mism) {
		char *ws = fmt_cp(want), *gs = fmt_cp(got);
		const char *line = rz_vscreen_line(scr, (ut32)st->arg_n);
		fail(res, st->line_begin,
			"expected %s at (row %" PFMT64u ", col %u) but found %s\n  row: \"%s\"",
			ws, st->arg_n, at, gs, line);
		free(ws);
		free(gs);
	}
}

static void check_vline(RzTestUiResult *res, RzVScreen *scr, RzTestUiStep *st) {
	ut32 col = (ut32)st->arg_n;
	ut32 want = decode_first(st->arg_s);
	bool bad = false;
	ut64 badrow = 0;
	ut32 got = 0;
	for (ut64 r = st->arg_b; r <= st->arg_e; r++) {
		got = rz_vscreen_cell(scr, (ut32)r, col);
		if (got != want) {
			bad = true;
			badrow = r;
			break;
		}
	}
	if (bad) {
		char *ws = fmt_cp(want), *gs = fmt_cp(got);
		fail(res, st->line_begin,
			"vertical run of %s at col %u breaks at row %" PFMT64u " (found %s)",
			ws, col, badrow, gs);
		free(ws);
		free(gs);
	}
}

static void check_hline(RzTestUiResult *res, RzVScreen *scr, RzTestUiStep *st) {
	ut32 row = (ut32)st->arg_n;
	ut32 want = decode_first(st->arg_s);
	bool bad = false;
	ut64 badcol = 0;
	ut32 got = 0;
	for (ut64 c = st->arg_b; c <= st->arg_e; c++) {
		got = rz_vscreen_cell(scr, row, (ut32)c);
		if (got != want) {
			bad = true;
			badcol = c;
			break;
		}
	}
	if (bad) {
		char *ws = fmt_cp(want), *gs = fmt_cp(got);
		fail(res, st->line_begin,
			"horizontal run of %s at row %u breaks at col %" PFMT64u " (found %s)",
			ws, row, badcol, gs);
		free(ws);
		free(gs);
	}
}

static void check_snapshot(RzTestUiResult *res, RzVScreen *scr, RzTestUiStep *st) {
	char *flat = rz_vscreen_to_str(scr);
	char *got = normalize_screen(flat);
	char *want = normalize_screen(st->arg_s);
	// record the observed screen so --accept can regenerate the block
	if (!res->fixups) {
		res->fixups = rz_pvector_new(NULL);
	}
	RzTestUiScreenFixup *fx = RZ_NEW0(RzTestUiScreenFixup);
	if (!flat || !got || !want || !res->fixups || !fx) {
		free(flat);
		free(got);
		free(want);
		free(fx);
		res->run_failed = true;
		fail(res, st->line_begin, "out of memory capturing screen");
		return;
	}
	fx->line_begin = st->line_begin;
	fx->line_end = st->line_end;
	size_t capture_size = strlen(got);
	if (capture_size > RZ_TEST_UI_MAX_FILE_SIZE - res->capture_size) {
		free(flat);
		free(got);
		free(want);
		free(fx);
		res->run_failed = true;
		fail(res, st->line_begin, "snapshot captures exceed the fixture size limit");
		return;
	}
	res->capture_size += capture_size;
	fx->text = rz_str_dup(got);
	if (!fx->text || !rz_pvector_push(res->fixups, fx)) {
		free(fx->text);
		free(fx);
		res->run_failed = true;
		fail(res, st->line_begin, "out of memory recording snapshot");
	}
	if (!RZ_STR_EQ(got, want)) {
		char *diff = NULL;
		RzDiff *d = rz_diff_lines_new(want, got, NULL);
		if (d) {
			diff = rz_diff_unified_text(d, "expected", "actual", false, false);
			rz_diff_free(d);
		}
		bool previous_failure = res->assertion_failed;
		fail(res, st->line_begin, "screen mismatch\n%s", diff ? diff : "(no diff)");
		res->assertion_failed = previous_failure;
		free(diff);
	}
	free(flat);
	free(got);
	free(want);
}

static void check_step(RzTestUiResult *res, RzVScreen *scr, RzTestUiStep *st) {
	ut32 rows = rz_vscreen_rows(scr), cols = rz_vscreen_cols(scr);
	bool row_step = st->kind == RZ_UI_STEP_EXPECT_LINE || st->kind == RZ_UI_STEP_EXPECT_NOLINE ||
		st->kind == RZ_UI_STEP_EXPECT_AT || st->kind == RZ_UI_STEP_EXPECT_CELL ||
		st->kind == RZ_UI_STEP_EXPECT_REGEX_AT || st->kind == RZ_UI_STEP_EXPECT_HLINE;
	if ((row_step && st->arg_n >= rows) ||
		(st->kind == RZ_UI_STEP_EXPECT_VLINE && (st->arg_n >= cols || st->arg_e >= rows)) ||
		(st->kind == RZ_UI_STEP_EXPECT_HLINE && st->arg_e >= cols)) {
		fail(res, st->line_begin, "assertion coordinates exceed the %ux%u screen", cols, rows);
		return;
	}
	switch (st->kind) {
	case RZ_UI_STEP_EXPECT_LINE: {
		const char *line = rz_vscreen_line(scr, (ut32)st->arg_n);
		if (!strstr(line, st->arg_s)) {
			fail(res, st->line_begin,
				"row %" PFMT64u " does not contain \"%s\"\n  actual: \"%s\"",
				st->arg_n, st->arg_s, line);
		}
		break;
	}
	case RZ_UI_STEP_EXPECT_NOLINE: {
		const char *line = rz_vscreen_line(scr, (ut32)st->arg_n);
		if (strstr(line, st->arg_s)) {
			fail(res, st->line_begin,
				"row %" PFMT64u " unexpectedly contains \"%s\"\n  actual: \"%s\"",
				st->arg_n, st->arg_s, line);
		}
		break;
	}
	case RZ_UI_STEP_EXPECT_REGEX:
	case RZ_UI_STEP_EXPECT_NOREGEX: {
		char *flat = rz_vscreen_to_str(scr);
		check_regex(res, st, flat, st->kind == RZ_UI_STEP_EXPECT_NOREGEX);
		free(flat);
		break;
	}
	case RZ_UI_STEP_EXPECT_AT:
		check_at(res, scr, st);
		break;
	case RZ_UI_STEP_EXPECT_CELL: {
		ut32 col0;
		if (!resolve_col(scr, st->arg_col, &col0)) {
			fail(res, st->line_begin, "column %" PFMT64d " is out of range (width %u)",
				(st64)st->arg_col, rz_vscreen_cols(scr));
			break;
		}
		ut32 want = decode_first(st->arg_s);
		ut32 got = rz_vscreen_cell(scr, (ut32)st->arg_n, col0);
		if (got != want) {
			char *ws = fmt_cp(want), *gs = fmt_cp(got);
			fail(res, st->line_begin, "cell (row %" PFMT64u ", col %u) is %s, expected %s",
				st->arg_n, col0, gs, ws);
			free(ws);
			free(gs);
		}
		break;
	}
	case RZ_UI_STEP_EXPECT_VLINE:
		check_vline(res, scr, st);
		break;
	case RZ_UI_STEP_EXPECT_HLINE:
		check_hline(res, scr, st);
		break;
	case RZ_UI_STEP_EXPECT_REGEX_AT:
		check_regex(res, st, rz_vscreen_line(scr, st->arg_n), false);
		break;
	case RZ_UI_STEP_EXPECT_SCR:
		check_snapshot(res, scr, st);
		break;
	case RZ_UI_STEP_CAPTURE:
		free(res->actual_screen);
		res->actual_screen = rz_vscreen_to_str(scr);
		if (!res->actual_screen) {
			res->run_failed = true;
			fail(res, st->line_begin, "out of memory capturing screen");
		}
		break;

	default:
		break;
	}
}

typedef struct {
	RzTestUiResult result;
	RzVScreen *screen;
	const char *result_path;
	size_t next_step;
	const ut8 *input;
} UiWorker;

/**
 * \brief Finish only at an input boundary, where all preceding frames exist.
 *
 * A worker is deliberately process-scoped. Exiting here avoids guessing how
 * many nested menus need a 'q', or unwinding C library frames with longjmp.
 * The parent still requires both this complete record and the expected exit
 * status; early exits, crashes and timeouts cannot become accepted snapshots.
 */
static void finish_worker(UiWorker *worker) {
	RzTestUiResult *res = &worker->result;
	if (res->run_failed) {
		eprintf("%s:%" PFMT64u ": %s\n", res->test->path, res->fail_line, res->fail_diag ? res->fail_diag : "worker error");
	}
	PJ *json = pj_new();
	if (!json) {
		exit(2);
	}
	char *screen = rz_vscreen_to_str(worker->screen);
	if (!screen) {
		pj_free(json);
		exit(2);
	}
	pj_o(json);
	pj_ki(json, "version", 1);
	pj_kb(json, "completed", !res->run_failed);
	pj_kb(json, "failed", res->failed);
	pj_kb(json, "assertion_failed", res->assertion_failed);
	pj_kn(json, "fail_line", res->fail_line);
	pj_ks(json, "diagnostic", res->fail_diag ? res->fail_diag : "");
	pj_ks(json, "screen", res->actual_screen ? res->actual_screen : screen);
	pj_ka(json, "fixups");
	if (res->fixups) {
		void **it;
		rz_pvector_foreach (res->fixups, it) {
			RzTestUiScreenFixup *fix = *it;
			pj_o(json);
			pj_kn(json, "begin", fix->line_begin);
			pj_kn(json, "end", fix->line_end);
			pj_ks(json, "text", fix->text);
			pj_end(json);
		}
	}
	pj_end(json);
	pj_end(json);
	bool saved = rz_file_dump(worker->result_path, (const ut8 *)pj_string(json), strlen(pj_string(json)), false);
	free(screen);
	pj_free(json);
	exit(saved ? 0 : 2);
}

static void worker_write(void *user, const char *data, size_t length) {
	UiWorker *worker = user;
	// Native TTYs translate LF to CRLF. Model that terminal setting explicitly.
	for (size_t start = 0, i = 0; i < length; i++) {
		if (data[i] == '\n') {
			rz_vscreen_feed(worker->screen, (const ut8 *)data + start, i - start);
			rz_vscreen_feed(worker->screen, (const ut8 *)"\r\n", 2);
			start = i + 1;
		}
		if (i + 1 == length) {
			rz_vscreen_feed(worker->screen, (const ut8 *)data + start, length - start);
		}
	}
}

static bool worker_size(void *user, int *cols, int *rows) {
	UiWorker *worker = user;
	*cols = rz_vscreen_cols(worker->screen);
	*rows = rz_vscreen_rows(worker->screen);
	return true;
}

static int worker_read(void *user, RzCons *cons, ut32 timeout_ms) {
	UiWorker *worker = user;
	if (worker->input && *worker->input) {
		return *worker->input++;
	}
	// A timed read probes the continuation of the current escape sequence.
	// Do not consume the next scripted key (or execute assertions) during it.
	if (timeout_ms) {
		return -1;
	}
	if (!rz_vscreen_valid(worker->screen)) {
		worker->result.run_failed = true;
		fail(&worker->result, 0, "unsupported or incomplete terminal output");
		finish_worker(worker);
	}
	RzTestUi *test = worker->result.test;
	while (worker->next_step < rz_pvector_len(&test->steps)) {
		RzTestUiStep *step = rz_pvector_at(&test->steps, worker->next_step++);
		switch (step->kind) {
		case RZ_UI_STEP_KEY:
			worker->input = (const ut8 *)step->arg_s;
			return *worker->input++;
		case RZ_UI_STEP_RESIZE:
			if (!rz_vscreen_resize(worker->screen, step->arg_w, step->arg_h)) {
				worker->result.run_failed = true;
				fail(&worker->result, step->line_begin, "could not resize screen");
				finish_worker(worker);
			}
			rz_cons_get_size(cons, NULL);
			if (cons->event_resize) {
				cons->event_resize(cons->event_data);
			}
			// Ctrl-L requests the same redraw on platforms without SIGWINCH.
			return 12;
		case RZ_UI_STEP_WAIT:
			// Kept for old fixtures. Input boundaries already synchronize frames.
			break;
		case RZ_UI_STEP_QUIT:
			finish_worker(worker);
			return -1;
		default:
			check_step(&worker->result, worker->screen, step);
			if (worker->result.run_failed) {
				finish_worker(worker);
			}
			break;
		}
	}
	finish_worker(worker);
	return -1;
}

/** \brief Preserve rz-test's argv semantics without invoking a shell. */
int rz_test_ui_worker(const char *path, size_t index, const char *result_path) {
	RzPVector *tests = rz_test_ui_load_file(path);
	if (!tests || index >= rz_pvector_len(tests)) {
		rz_pvector_free(tests);
		return 2;
	}
	RzTestUi *test = rz_pvector_at(tests, index);
	UiWorker worker = { 0 };
	worker.result.test = test;
	worker.result_path = result_path;
	worker.screen = rz_vscreen_new(test->cols, test->rows);
	int extra_count = 0;
	char **extra = rz_str_argv(test->args ? test->args : "", &extra_count);
	const char **args = RZ_NEWS0(const char *, extra_count + 24);
	if (!worker.screen || !extra || !args) {
		free(args);
		rz_str_argv_free(extra);
		rz_vscreen_free(worker.screen);
		rz_pvector_free(tests);
		return 2;
	}
	int n = 0;
	args[n++] = "rizin";
	args[n++] = "-N";
	args[n++] = "-e";
	args[n++] = "scr.interactive=true";
	args[n++] = "-e";
	args[n++] = "scr.prompt=true";
	args[n++] = "-e";
	args[n++] = "scr.confirmquit=false";
	args[n++] = "-e";
	args[n++] = test->color ? "scr.color=1" : "scr.color=0";
	args[n++] = "-e";
	args[n++] = test->utf8 ? "scr.utf8=true" : "scr.utf8=false";
	for (int i = 0; i < extra_count; i++) {
		args[n++] = extra[i];
	}
	args[n++] = "--";
	args[n++] = test->file ? test->file : "malloc://128";
	RzConsBackend backend = { worker_read, worker_write, worker_size };
	rz_main_rizin_with_cons(n, args, &backend, &worker);
	// Reaching here means Rizin exited without consuming the complete script.
	free(args);
	rz_str_argv_free(extra);
	rz_vscreen_free(worker.screen);
	rz_pvector_free(tests);
	return 2;
}
