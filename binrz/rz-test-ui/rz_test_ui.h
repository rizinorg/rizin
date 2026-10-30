// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TEST_UI_H
#define RZ_TEST_UI_H

#include <rz_util.h>
#include "../rz-test/rz_test_result.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RZ_TEST_UI_DEFAULT_COLS    80
#define RZ_TEST_UI_DEFAULT_ROWS    24
#define RZ_TEST_UI_TIMEOUT_DEFAULT 60
#define RZ_TEST_UI_MAX_COLS        1024
#define RZ_TEST_UI_MAX_ROWS        512
#define RZ_TEST_UI_MAX_FILE_SIZE   (16 * 1024 * 1024)
#define RZ_TEST_UI_MAX_STEPS       65536
#define RZ_TEST_UI_MAX_RESULT_SIZE (128 * 1024 * 1024)

/**
 * A single directive inside a STEPS block.
 */
typedef enum {
	RZ_UI_STEP_KEY, ///< press one key (literal char or named: <UP>, <ENTER>, <ESC>, <TAB>, ...)
	RZ_UI_STEP_WAIT, ///< legacy synchronization point; does not sleep
	RZ_UI_STEP_RESIZE, ///< resize the virtual terminal to WxH and request redraw
	RZ_UI_STEP_EXPECT_SCR, ///< the whole screen snapshot must match a heredoc block
	RZ_UI_STEP_EXPECT_LINE, ///< a given row must contain a literal substring
	RZ_UI_STEP_EXPECT_REGEX, ///< the flattened screen must match a regular expression
	RZ_UI_STEP_EXPECT_NOLINE, ///< a given row must NOT contain a literal substring
	RZ_UI_STEP_EXPECT_NOREGEX, ///< the flattened screen must NOT match a regular expression
	RZ_UI_STEP_EXPECT_AT, ///< text must start at an exact (row, col); col<0 counts from the right
	RZ_UI_STEP_EXPECT_CELL, ///< the single cell (row, col) must hold a given character (col<0 from right)
	RZ_UI_STEP_EXPECT_VLINE, ///< a column must hold one character across a row range (vertical run)
	RZ_UI_STEP_EXPECT_HLINE, ///< a row must hold one character across a column range (horizontal run)
	RZ_UI_STEP_EXPECT_REGEX_AT, ///< a single row must match a regular expression (per-row anchored)
	RZ_UI_STEP_CAPTURE, ///< capture a screen for diagnostics
	RZ_UI_STEP_QUIT, ///< finish the isolated worker at this input boundary
} RzTestUiStepKind;

typedef struct {
	RzTestUiStepKind kind;
	char *arg_s; ///< payload (key sequence, regex, expected text, ...)
	ut64 arg_n; ///< numeric payload (wait ms, row index, or column for EXPECT_VLINE)
	ut32 arg_w, arg_h; ///< RESIZE target dimensions
	st64 arg_col; ///< signed column for EXPECT_AT / EXPECT_CELL (negative counts from the right)
	ut64 arg_b, arg_e; ///< inclusive range (EXPECT_VLINE rows, EXPECT_HLINE columns)
	ut64 line_begin; ///< first source line of this step (inclusive), for diagnostics & -a
	ut64 line_end; ///< last source line of this step (inclusive)
} RzTestUiStep;

typedef struct {
	size_t index;
	char *name; ///< human readable test name (NAME=)
	char *file; ///< binary/URI to open (FILE=), may be NULL
	char *args; ///< extra rizin arguments (ARGS=), may be NULL
	ut32 cols; ///< virtual terminal width (COLS=, default 80)
	ut32 rows; ///< virtual terminal height (ROWS=, default 24)
	ut64 timeout_ms; ///< per-test timeout (TIMEOUT= seconds), 0 = use global
	bool color; ///< run rizin with scr.color=1 (COLOR=1)
	bool utf8; ///< run rizin with scr.utf8=1 (UTF8=1)
	bool broken; ///< test is known to fail (BROKEN=1)
	RzPVector /*<RzTestUiStep *>*/ steps;
	const char *path; ///< source file path (owned)
	ut64 run_line; ///< line of the RUN directive (for diagnostics)
} RzTestUi;

typedef struct {
	ut64 line_begin; ///< first content line of the EXPECT_SCREEN block (inclusive)
	ut64 line_end; ///< last content line of the EXPECT_SCREEN block (inclusive)
	char *text; ///< the screen actually observed at that step (owned)
} RzTestUiScreenFixup;

typedef struct {
	RzTestUi *test;
	RzTestResult result;
	bool completed;
	bool failed;
	bool assertion_failed;
	bool timeout; ///< the test hit its timeout
	bool run_failed; ///< worker or terminal emulation error
	ut64 time_elapsed; ///< wall clock time in microseconds
	char *actual_screen; ///< final/captured screen as text (owned)
	char *fail_diag; ///< human readable failure reason (owned), or NULL
	ut64 fail_line; ///< source line of the step that failed, or 0
	size_t capture_size; ///< total snapshot text, bounded by the fixture size limit
	RzPVector /*<RzTestUiScreenFixup *>*/ *fixups; ///< per EXPECT_SCREEN captures (for --accept)
} RzTestUiResult;

typedef struct {
	const char *bin_path; ///< directory containing rz-test-ui, or NULL for $PATH
	const char *worker_exe; ///< worker executable, default "rz-test-ui"
	ut64 timeout_ms; ///< global per-test timeout
} RzTestUiRunConfig;

int rz_test_ui_worker(const char *path, size_t index, const char *result_path);

// ---- Loader (load.c) -------------------------------------------------------

RZ_OWN RzPVector /*<RzTestUi *>*/ *rz_test_ui_load(RZ_NONNULL const char *path, RZ_NONNULL const char *text);
RZ_OWN RzPVector /*<RzTestUi *>*/ *rz_test_ui_load_file(RZ_NONNULL const char *path);
RZ_OWN char *rz_test_ui_read_text(RZ_NONNULL const char *path, size_t limit);
void rz_test_ui_free(RZ_NULLABLE RzTestUi *t);

// ---- Runner (run.c) --------------------------------------------------------

RZ_OWN RzTestUiResult *rz_test_ui_run(RZ_NONNULL const RzTestUiRunConfig *cfg, RZ_NONNULL RzTestUi *t);
void rz_test_ui_result_free(RZ_NULLABLE RzTestUiResult *r);

// ---- Virtual screen / ANSI parser (vscreen.c) ------------------------------

typedef struct rz_vscreen_t RzVScreen;

RZ_OWN RzVScreen *rz_vscreen_new(ut32 cols, ut32 rows);
void rz_vscreen_free(RZ_NULLABLE RzVScreen *s);
bool rz_vscreen_resize(RZ_NONNULL RzVScreen *s, ut32 cols, ut32 rows);
bool rz_vscreen_valid(const RzVScreen *s);
void rz_vscreen_feed(RZ_NONNULL RzVScreen *s, RZ_NONNULL const ut8 *buf, size_t n);
RZ_BORROW const char *rz_vscreen_line(RZ_NONNULL RzVScreen *s, ut32 row);
RZ_OWN char *rz_vscreen_to_str(RZ_NONNULL RzVScreen *s);

ut32 rz_vscreen_cell(RZ_NONNULL RzVScreen *s, ut32 row, ut32 col);
ut32 rz_vscreen_cols(RZ_NONNULL RzVScreen *s);
ut32 rz_vscreen_rows(RZ_NONNULL RzVScreen *s);

#ifdef __cplusplus
}
#endif

#endif // RZ_TEST_UI_H
