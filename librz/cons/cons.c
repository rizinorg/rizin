// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 Jody Frankowski <jody.frankowski@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>
#include <rz_util.h>
#include <rz_util/rz_print.h>
#include <rz_windows.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "i/private.h"

#define COUNT_LINES 1

RZ_LIB_VERSION(rz_cons);

static RzConsContext rz_cons_context_default = { { { { 0 } } } };

#if __WINDOWS__
// restore only the console flags rizin owns instead of replaying the whole host mode word
#define RZ_CONS_OUTPUT_MODE_MASK (ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
#define RZ_CONS_INPUT_MODE_MASK  (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_MOUSE_INPUT | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS | ENABLE_VIRTUAL_TERMINAL_INPUT)
#endif

// this structure goes into cons_stack when rz_cons_push/pop
typedef struct {
	RzCons *cons;
	char *buf;
	int buf_len;
	int buf_size;
	RzConsGrep *grep;
	bool noflush;
} RzConsStack;

static void cons_grep_reset(RzConsGrep *grep);

static void ctx_rowcol_calc_reset(RzCons *cons) {
	cons->context->row = 0;
	cons->context->col = 0;
	cons->context->rowcol_calc_start = 0;
}

static void cons_stack_free(void *ptr) {
	RzConsStack *s = (RzConsStack *)ptr;
	RzCons *cons = s->cons;
	free(s->buf);
	if (s->grep) {
		if (cons->context->grep.str == s->grep->str) {
			cons->context->grep.str = NULL;
		}
		RZ_FREE(s->grep->str);
		if (cons->context->grep.json_path == s->grep->json_path) {
			cons->context->grep.json_path = NULL;
		}
		RZ_FREE(s->grep->json_path);
	}
	free(s->grep);
	free(s);
}

static RzConsStack *cons_stack_dump(RzCons *cons, bool recreate) {
	RzConsStack *data = RZ_NEW0(RzConsStack);
	if (data) {
		if (cons->context->buffer) {
			data->buf = cons->context->buffer;
			data->buf_len = cons->context->buffer_len;
			data->buf_size = cons->context->buffer_sz;
		}
		data->noflush = cons->context->noflush;
		data->grep = RZ_NEW0(RzConsGrep);
		if (data->grep) {
			memcpy(data->grep, &cons->context->grep, sizeof(RzConsGrep));
			if (cons->context->grep.str) {
				data->grep->str = rz_str_dup(cons->context->grep.str);
			}
			if (cons->context->grep.json_path) {
				data->grep->json_path = rz_str_dup(cons->context->grep.json_path);
			}
		}
		if (recreate && cons->context->buffer_sz > 0) {
			cons->context->buffer = malloc(cons->context->buffer_sz);
			ctx_rowcol_calc_reset(cons);
			if (!cons->context->buffer) {
				cons->context->buffer = data->buf;
				free(data);
				return NULL;
			}
		} else {
			cons->context->buffer = NULL;
		}
	}
	return data;
}

static void cons_stack_load(RzConsStack *data, bool free_current) {
	rz_return_if_fail(data && data->cons);
	RzCons *cons = data->cons;
	if (free_current) {
		free(cons->context->buffer);
	}
	cons->context->buffer = data->buf;
	data->buf = NULL;
	cons->context->buffer_len = data->buf_len;
	cons->context->buffer_sz = data->buf_size;
	if (data->grep) {
		free(cons->context->grep.str);
		free(cons->context->grep.json_path);
		memcpy(&cons->context->grep, data->grep, sizeof(RzConsGrep));
	}
	cons->context->noflush = data->noflush;
	ctx_rowcol_calc_reset(cons);
}

static void cons_context_init(RzConsContext *context, RZ_NULLABLE RzConsContext *parent) {
	context->cmd_depth = RZ_CONS_CMD_DEPTH + 1;
	context->buffer = NULL;
	context->buffer_sz = 0;
	context->lastEnabled = true;
	context->buffer_len = 0;
	context->is_interactive = false;
	context->cons_stack = rz_stack_newf(6, cons_stack_free);
	context->pageable = true;
	context->log_callback = NULL;
	context->noflush = false;

	if (parent) {
		context->color_mode = parent->color_mode;
		rz_cons_pal_copy(context, parent);
	} else {
		context->color_mode = COLOR_MODE_DISABLED;
		rz_cons_pal_init(context);
	}

	cons_grep_reset(&context->grep);
}

static void cons_context_deinit(RzConsContext *context) {
	rz_stack_free(context->cons_stack);
	context->cons_stack = NULL;
	rz_cons_pal_free(context);
	cons_grep_reset(&context->grep);
	free(context->buffer);
	context->buffer = NULL;
	context->buffer_sz = 0;
	context->buffer_len = 0;
	free(context->lastOutput);
	context->lastOutput = NULL;
	context->lastLength = 0;
}

static inline void __cons_write_ll(RzCons *cons, const char *buf, int len) {
#if __WINDOWS__
	if (cons->vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
		rz_xwrite(cons->fdout, buf, len);
	} else {
		if (cons->fdout == 1) {
			rz_cons_w32_print(cons, buf, len, false);
		} else {
			rz_xwrite(cons->fdout, buf, len);
		}
	}
#else
	if (cons->fdout < 1) {
		cons->fdout = 1;
	}
	rz_xwrite(cons->fdout, buf, len);
#endif
}

static inline void __cons_write(RzCons *cons, const char *obuf, int olen) {
	const size_t bucket = 64 * 1024;
	size_t i;
	if (olen < 0) {
		olen = strlen(obuf);
	}
	for (i = 0; (i + bucket) < olen; i += bucket) {
		__cons_write_ll(cons, obuf + i, bucket);
	}
	if (i < olen) {
		__cons_write_ll(cons, obuf + i, olen - i);
	}
}

RZ_API RzColor rz_cons_color_random(RZ_NONNULL RZ_BORROW RzCons *cons, ut8 alpha) {
	RzColor rcolor = { 0 };
	if (cons->context->color_mode > COLOR_MODE_16) {
		rcolor.r = rz_num_rand32(0xff);
		rcolor.g = rz_num_rand32(0xff);
		rcolor.b = rz_num_rand32(0xff);
		rcolor.a = alpha;
		return rcolor;
	}
	int r = rz_num_rand32(16);
	switch (r) {
	case 0:
	case 1: rcolor = (RzColor)RzColor_RED; break;
	case 2:
	case 3: rcolor = (RzColor)RzColor_WHITE; break;
	case 4:
	case 5: rcolor = (RzColor)RzColor_GREEN; break;
	case 6:
	case 7: rcolor = (RzColor)RzColor_MAGENTA; break;
	case 8:
	case 9: rcolor = (RzColor)RzColor_YELLOW; break;
	case 10:
	case 11: rcolor = (RzColor)RzColor_CYAN; break;
	case 12:
	case 13: rcolor = (RzColor)RzColor_BLUE; break;
	case 14:
	case 15: rcolor = (RzColor)RzColor_GRAY; break;
	}
	if (r & 1) {
		rcolor.attr = RZ_CONS_ATTR_BOLD;
	}
	return rcolor;
}

RZ_API void rz_cons_color(RZ_NONNULL RZ_BORROW RzCons *cons, int fg, int r, int g, int b) {
	int k;
	r = RZ_DIM(r, 0, 255);
	g = RZ_DIM(g, 0, 255);
	b = RZ_DIM(b, 0, 255);
	if (r == g && g == b) { // b&w
		k = 232 + (int)(((r + g + b) / 3) / 10.3);
	} else {
		r = (int)(r / 42.6);
		g = (int)(g / 42.6);
		b = (int)(b / 42.6);
		k = 16 + (r * 36) + (g * 6) + b;
	}
	rz_cons_printf(cons, "\x1b[%d;5;%dm", fg ? 48 : 38, k);
}

RZ_API void rz_cons_println(RZ_NONNULL RZ_BORROW RzCons *cons, const char *str) {
	rz_cons_print(cons, str);
	rz_cons_newline(cons);
}

RZ_API void rz_cons_strcat_justify(RZ_NONNULL RZ_BORROW RzCons *cons, const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			rz_cons_memset(cons, ' ', j);
			if (c) {
				rz_cons_memset(cons, c, 1);
				rz_cons_memset(cons, ' ', 1);
			}
			rz_cons_memcat(cons, str + o, len);
			if (str[o + len] == '\n') {
				rz_cons_newline(cons);
			}
			o = i + 1;
			len = 0;
		}
	}
	if (len > 0) {
		rz_cons_memcat(cons, str + o, len);
	}
}

RZ_API void rz_cons_strcat_at(RZ_NONNULL RZ_BORROW RzCons *cons, const char *_str, int x, char y, int w, int h) {
	int i, o, len;
	int cols = 0;
	int rows = 0;
	if (x < 0 || y < 0) {
		int H, W = rz_cons_get_size(cons, &H);
		if (x < 0) {
			x += W;
		}
		if (y < 0) {
			y += H;
		}
	}
	char *str = rz_str_ansi_crop(_str, 0, 0, w + 1, h);
	rz_cons_strcat(cons, RZ_CONS_CURSOR_SAVE);
	for (o = i = len = 0; str[i]; i++, len++) {
		if (w < 0 || rows > w) {
			break;
		}
		if (str[i] == '\n') {
			rz_cons_gotoxy(cons, x, y + rows);
			int ansilen = rz_str_ansi_len(str + o);
			cols = RZ_MIN(w, ansilen);
			const char *end = rz_str_ansi_chrn(str + o, cols);
			cols = end - str + o;
			rz_cons_memcat(cons, str + o, RZ_MIN(len, cols));
			o = i + 1;
			len = 0;
			rows++;
		}
	}
	if (len > 0) {
		rz_cons_gotoxy(cons, x, y + rows);
		rz_cons_memcat(cons, str + o, len);
	}
	rz_cons_strcat(cons, Color_RESET);
	rz_cons_strcat(cons, RZ_CONS_CURSOR_RESTORE);
	free(str);
}

RZ_API void rz_cons_context_break_push(RzConsContext *context, RzInterruptEvent cb, void *user) {
	if (!context || !context->intr) {
		return;
	}
	rz_interrupt_break_push(context->intr, cb, user);
}

RZ_API void rz_cons_context_break_pop(RzConsContext *context) {
	if (!context || !context->intr) {
		return;
	}
	rz_interrupt_break_pop(context->intr);
}

RZ_API bool rz_cons_is_interactive(RZ_NONNULL RZ_BORROW RzCons *cons) {
	return cons->context->is_interactive;
}

RZ_API bool rz_cons_default_context_is_interactive() {
	return rz_cons_context_default.is_interactive;
}

RZ_API int rz_cons_get_cur_line() {
	int curline = 0;
#if __WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO info;
	if (!GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
		return 0;
	}
	curline = info.dwCursorPosition.Y - info.srWindow.Top;
#endif
#if __UNIX__
	char buf[8];
	struct termios save, raw;
	// flush the Arrow keys escape keys which was messing up the output
	fflush(stdout);
	(void)tcgetattr(0, &save);
	cfmakeraw(&raw);
	(void)tcsetattr(0, TCSANOW, &raw);
	if (isatty(fileno(stdin))) {
		if (write(1, RZ_CONS_GET_CURSOR_POSITION, sizeof(RZ_CONS_GET_CURSOR_POSITION)) != -1) {
			if (read(0, buf, sizeof(buf)) != sizeof(buf)) {
				if (isdigit(buf[2])) {
					curline = (buf[2] - '0');
				}
				if (isdigit(buf[3])) {
					curline = curline * 10 + (buf[3] - '0');
				}
			}
		}
	}
	(void)tcsetattr(0, TCSANOW, &save);
#endif
	return curline;
}

#if __WINDOWS__
static BOOL __w32_control(DWORD type) {
	if (type == CTRL_C_EVENT) {
		__break_signal(2); // SIGINT
		eprintf("{ctrl+c} pressed.\n");
		return true;
	}
	return false;
}
#elif __UNIX__
volatile sig_atomic_t sigwinchFlag;
static void resize(int sig) {
	sigwinchFlag = 1;
}
#endif
void resizeWin(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (cons->event_resize) {
		cons->event_resize(cons->event_data);
	}
}

/**
 * \brief Set the property of the click event
 * \param cons The cons reference
 * \param x The x coordinate of the position
 * \param y The y coordinate of the position
 * \param event The type of the click
 */
RZ_API void rz_cons_set_click(RZ_NONNULL RZ_BORROW RzCons *cons, int x, int y, MouseEvent event) {
	cons->click_x = x;
	cons->click_y = y;
	cons->click_set = true;
	cons->mouse_event = event;
}

RZ_API bool rz_cons_get_click(RZ_NONNULL RZ_BORROW RzCons *cons, int *x, int *y) {
	if (x) {
		*x = cons->click_x;
	}
	if (y) {
		*y = cons->click_y;
	}
	bool set = cons->click_set;
	cons->click_set = false;
	return set;
}

RZ_API void rz_cons_enable_highlight(RZ_NONNULL RZ_BORROW RzCons *cons, const bool enable) {
	cons->enable_highlight = enable;
}

RZ_API bool rz_cons_enable_mouse(RZ_NONNULL RZ_BORROW RzCons *cons, const bool enable) {
	if ((cons->mouse && enable) || (!cons->mouse && !enable)) {
		return cons->mouse;
	}
#if __WINDOWS__
	if (cons->vtmode == RZ_VIRT_TERM_MODE_COMPLETE) {
#endif
		const char *click = enable
			? "\x1b[?1000;1006;1015h"
			: "\x1b[?1000;1006;1015l";
		// const char *old = enable ? "\x1b[?1001s" "\x1b[?1000h" : "\x1b[?1001r" "\x1b[?1000l";
		bool enabled = cons->mouse;
		const size_t click_len = strlen(click);
		if (write(2, click, click_len) != click_len) {
			return false;
		}
		cons->mouse = enable;
		return enabled;
#if __WINDOWS__
	}
	DWORD mode;
	HANDLE h;
	bool enabled = cons->mouse;
	h = GetStdHandle(STD_INPUT_HANDLE);
	if (!GetConsoleMode(h, &mode)) {
		return enabled;
	}
	mode |= ENABLE_EXTENDED_FLAGS;
	mode = enable
		? (mode | ENABLE_MOUSE_INPUT) & ~ENABLE_QUICK_EDIT_MODE
		: (mode & ~ENABLE_MOUSE_INPUT) | ENABLE_QUICK_EDIT_MODE;
	if (SetConsoleMode(h, mode)) {
		cons->mouse = enable;
	}
	return enabled;
#else
	return false;
#endif
}

#if __WINDOWS__
static void set_console_codepage_to_utf8(void) {
	if (IsValidCodePage(CP_UTF8)) {
		if (!SetConsoleOutputCP(CP_UTF8)) {
			rz_sys_perror("SetConsoleCP");
		}
		if (!SetConsoleCP(CP_UTF8)) {
			rz_sys_perror("SetConsoleCP");
		}
	} else {
		RZ_LOG_INFO("UTF-8 Codepage not installed.\n");
	}
}

static void save_console_state(RzCons *cons) {
	// Snapshot the exact std handles and their current console modes before any probing mutates them.
	cons->saved_input_handle = GetStdHandle(STD_INPUT_HANDLE);
	cons->saved_output_handle = GetStdHandle(STD_OUTPUT_HANDLE);
	cons->saved_input_console = GetConsoleMode((HANDLE)cons->saved_input_handle, &cons->old_input_mode);
	cons->saved_output_console = GetConsoleMode((HANDLE)cons->saved_output_handle, &cons->old_output_mode);
	if (cons->saved_output_console) {
		if (!(cons->old_ocp = GetConsoleOutputCP())) {
			rz_sys_perror("GetConsoleOutputCP");
		}
	}
	if (cons->saved_input_console) {
		if (!(cons->old_cp = GetConsoleCP())) {
			rz_sys_perror("GetConsoleCP");
		}
	}
}

static inline DWORD restore_console_mode_bits(DWORD mode, DWORD saved_mode, DWORD mask) {
	return (mode & ~mask) | (saved_mode & mask);
}

static void restore_console_state(RzCons *cons) {
	DWORD mode;
	if (cons->saved_output_console && GetConsoleMode((HANDLE)cons->saved_output_handle, &mode)) {
		if (!SetConsoleOutputCP(cons->old_ocp)) {
			rz_sys_perror("SetConsoleOutputCP");
		}
		// Keep unrelated host-owned bits intact and restore only the output flags we changed.
		mode = restore_console_mode_bits(mode, cons->old_output_mode, RZ_CONS_OUTPUT_MODE_MASK);
		if (!SetConsoleMode((HANDLE)cons->saved_output_handle, mode)) {
			rz_sys_perror("SetConsoleMode");
		}
	}
	if (cons->saved_input_console && GetConsoleMode((HANDLE)cons->saved_input_handle, &mode)) {
		if (!SetConsoleCP(cons->old_cp)) {
			rz_sys_perror("SetConsoleCP");
		}
		// Input teardown mirrors output teardown for the subset of flags Rizin manages.
		mode = restore_console_mode_bits(mode, cons->old_input_mode, RZ_CONS_INPUT_MODE_MASK);
		if (!SetConsoleMode((HANDLE)cons->saved_input_handle, mode)) {
			rz_sys_perror("SetConsoleMode");
		}
	}
}
#endif

// Stub function that cb_main_output gets pointed to in util/log.c by rz_cons_new
// This allows Cutter to set per-task logging redirection
RZ_NONNULL RZ_BORROW RZ_API RzCons *rz_cons_new() {
	RzCons *cons = RZ_NEW0(RzCons);
#if __WINDOWS__
	// Save the console state before rz_line_new() runs VT detection on Windows.
	save_console_state(cons);
#endif
	cons->rgbstr = rz_cons_rgb_str_off;
	cons->line = rz_line_new();
	cons->enable_highlight = true;
	cons->highlight = NULL;
	cons->is_wine = -1;
	cons->blankline = true;
	cons->teefile = NULL;
	cons->fix_columns = 0;
	cons->fix_rows = 0;
	cons->mouse_event = MOUSE_NONE;
	cons->force_rows = 0;
	cons->force_columns = 0;
	cons->event_resize = NULL;
	cons->event_data = NULL;
	cons->linesleep = 0;
	cons->fdin = stdin;
	cons->fdout = 1;
	cons->break_lines = false;
	cons->lines = 0;
	cons->oldraw = -1;

	cons->input = RZ_NEW0(RzConsInputContext);
	cons->input->bufactive = true;
	cons->context = &rz_cons_context_default;
	cons_context_init(cons->context, NULL);

	rz_cons_get_size(cons, &cons->pagesize);
	cons->num = NULL;
	cons->null = 0;
#if __WINDOWS__
	cons->vtmode = rz_cons_detect_vt_mode(cons);
	// Keep line editing on the same VT mode that the main console instance selected.
	cons->line->vtmode = cons->vtmode;
	set_console_codepage_to_utf8();
#else
	cons->vtmode = RZ_VIRT_TERM_MODE_COMPLETE;
#endif
#if EMSCRIPTEN
	/* do nothing here :? */
#elif __UNIX__
	tcgetattr(0, &cons->term_buf);
	memcpy(&cons->term_raw, &cons->term_buf, sizeof(cons->term_raw));
	cons->term_raw.c_iflag &= ~(BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	cons->term_raw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	cons->term_raw.c_cflag &= ~(CSIZE | PARENB);
	cons->term_raw.c_cflag |= CS8;
	cons->term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	rz_sys_signal(SIGWINCH, resize);
#elif __WINDOWS__
	if (cons->saved_input_console) {
		// Raw/buffered mode masks must be derived from the saved console input mode.
		cons->term_buf = cons->old_input_mode | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT;
		cons->term_raw = ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
	}
	if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		eprintf("rz_cons: Cannot set control console handler\n");
	}
#endif
	cons->pager = NULL; /* no pager by default */
	cons->mouse = 0;
	cons->show_vals = false;
	rz_cons_reset(cons);
	rz_cons_rgb_init();

	rz_print_set_is_interrupted_cb(rz_interrupt_is_breaked);

	return cons;
}

RZ_API RzCons *rz_cons_free(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (!cons) {
		return NULL;
	}
#if __WINDOWS__
	restore_console_state(cons);
#endif
	if (cons->line) {
		rz_line_free(cons->line);
		cons->line = NULL;
	}
	RZ_FREE(cons->input->readbuffer);
	RZ_FREE(cons->input);
	RZ_FREE(cons->break_word);
	cons_context_deinit(cons->context);
	if (cons->context != &rz_cons_context_default) {
		RZ_FREE(cons->context);
	}
	cons->context = NULL;
	rz_strbuf_free(cons->echobuf);
	cons->echobuf = NULL;
	RZ_FREE(cons->pager);
	RZ_FREE(cons);
	return NULL;
}

#define MOAR (4096 * 8)
static bool palloc(RzCons *cons, int moar) {
	void *temp;
	if (moar <= 0) {
		return false;
	}
	if (!cons->context->buffer) {
		int new_sz;
		if ((INT_MAX - MOAR) < moar) {
			return false;
		}
		new_sz = moar + MOAR;
		temp = calloc(1, new_sz);
		if (temp) {
			cons->context->buffer_sz = new_sz;
			cons->context->buffer = temp;
			(cons->context->buffer)[0] = '\0';
		}
	} else if (moar + cons->context->buffer_len > cons->context->buffer_sz) {
		char *new_buffer;
		int old_buffer_sz = cons->context->buffer_sz;
		if ((INT_MAX - MOAR - moar) < cons->context->buffer_sz) {
			return false;
		}
		cons->context->buffer_sz += moar + MOAR;
		new_buffer = realloc(cons->context->buffer, cons->context->buffer_sz);
		if (new_buffer) {
			cons->context->buffer = new_buffer;
		} else {
			cons->context->buffer_sz = old_buffer_sz;
			return false;
		}
	}
	return true;
}

RZ_API int rz_cons_eof(RZ_NONNULL RZ_BORROW RzCons *cons) {
	return feof(cons->fdin);
}

RZ_API void rz_cons_gotoxy(RZ_NONNULL RZ_BORROW RzCons *cons, int x, int y) {
#if __WINDOWS__
	rz_cons_w32_gotoxy(cons, 1, x, y);
#else
	rz_cons_printf(cons, "\x1b[%d;%dH", y, x);
#endif
}

RZ_API void rz_cons_goto_origin_reset(RZ_NONNULL RZ_BORROW RzCons *cons) {
	rz_cons_gotoxy(cons, 0, 0);
	rz_cons_strcat(cons, Color_RESET);
}

RZ_API void rz_cons_fill_line(RZ_NONNULL RZ_BORROW RzCons *cons) {
	char *p, white[1024];
	int cols = cons->columns - 1;
	if (cols < 1) {
		return;
	}
	p = (cols >= sizeof(white))
		? malloc(cols + 1)
		: white;
	if (p) {
		memset(p, ' ', cols);
		p[cols] = 0;
		rz_cons_strcat(cons, p);
		if (white != p) {
			free(p);
		}
	}
}

/**
 * \brief Print on `stream` the ANSI escape sequence to clear the current line.
 * \param stream Either stdout or stderr. Only 2 possible stream values are accepted.
 */
RZ_API void rz_cons_clear_line(RZ_NONNULL RZ_BORROW RzCons *cons, FILE *stream) {
	rz_return_if_fail(stream == stdout || stream == stderr);
#if __WINDOWS__
	if (cons->vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
		fprintf(stream, "%s", RZ_CONS_CLEAR_LINE);
	} else {
		char white[1024];
		memset(&white, ' ', sizeof(white));
		if (cons->columns > 0 && cons->columns < sizeof(white)) {
			white[cons->columns - 1] = 0;
		} else if (cons->columns == 0) {
			white[0] = 0;
		} else {
			white[sizeof(white) - 1] = 0; // HACK
		}
		fprintf(stream, "\r%s\r", white);
	}
#else
	fprintf(stream, "%s", RZ_CONS_CLEAR_LINE);
#endif
	fflush(stream);
}

RZ_API void rz_cons_clear00(RZ_NONNULL RZ_BORROW RzCons *cons) {
	rz_cons_clear(cons);
	rz_cons_gotoxy(cons, 0, 0);
}

RZ_API void rz_cons_reset_colors(RZ_NONNULL RZ_BORROW RzCons *cons) {
	rz_cons_strcat(cons, Color_RESET_BG Color_RESET);
}

RZ_API void rz_cons_clear(RZ_NONNULL RZ_BORROW RzCons *cons) {
	cons->lines = 0;
#if __WINDOWS__
	rz_cons_w32_clear(cons);
#else
	rz_cons_strcat(cons, Color_RESET RZ_CONS_CLEAR_SCREEN);
#endif
}

static void cons_grep_reset(RzConsGrep *grep) {
	RZ_FREE(grep->str);
	RZ_FREE(grep->json_path);
	RZ_FREE(grep->sorted_lines);
	RZ_FREE(grep->unsorted_lines);
	ZERO_FILL(*grep);
	grep->line = -1;
	grep->sort = -1;
	grep->sorted_column = -1;
	grep->sort_invert = false;
}

RZ_API void rz_cons_reset(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (cons->context->buffer) {
		(cons->context->buffer)[0] = '\0';
	}
	cons->context->buffer_len = 0;
	cons->lines = 0;
	cons_grep_reset(&cons->context->grep);
	cons->context->pageable = true;
	ctx_rowcol_calc_reset(cons);
}

/**
 * \brief Return the current RzCons buffer
 */
RZ_API const char *rz_cons_get_buffer(RZ_NONNULL RZ_BORROW RzCons *cons) {
	// check len otherwise it will return trash
	return cons->context->buffer_len ? cons->context->buffer : NULL;
}

/**
 * \brief Return a newly allocated buffer containing what's currently in RzCons buffer
 */
RZ_API RZ_OWN char *rz_cons_get_buffer_dup(RZ_NONNULL RZ_BORROW RzCons *cons) {
	const char *s = rz_cons_get_buffer(cons);
	return rz_str_dup(s);
}

RZ_API int rz_cons_get_buffer_len(RZ_NONNULL RZ_BORROW RzCons *cons) {
	return cons->context->buffer_len;
}

RZ_API void rz_cons_filter(RZ_NONNULL RZ_BORROW RzCons *cons) {
	/* grep */
	if (cons->filter || cons->context->grep.nstrings > 0 || cons->context->grep.tokens_used || cons->context->grep.less || cons->context->grep.json) {
		(void)rz_cons_grepbuf(cons);
		cons->filter = false;
	}
	/* html */
	if (cons->is_html) {
		int newlen = 0;
		char *input = rz_str_ndup(cons->context->buffer, cons->context->buffer_len);
		char *res = rz_cons_html_filter(cons, input, &newlen);
		free(cons->context->buffer);
		cons->context->buffer = res;
		cons->context->buffer_len = newlen;
		cons->context->buffer_sz = newlen;
		ctx_rowcol_calc_reset(cons);
		free(input);
	}
	if (cons->was_html) {
		cons->is_html = true;
		cons->was_html = false;
	}
}

RZ_API void rz_cons_push(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (!cons->context->cons_stack) {
		return;
	}
	RzConsStack *data = cons_stack_dump(cons, true);
	if (!data) {
		return;
	}
	rz_stack_push(cons->context->cons_stack, data);
	cons->context->buffer_len = 0;
	if (cons->context->buffer) {
		memset(cons->context->buffer, 0, cons->context->buffer_sz);
	}
	cons->context->noflush = true;
}

RZ_API void rz_cons_pop(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (!cons->context->cons_stack) {
		return;
	}
	RzConsStack *data = (RzConsStack *)rz_stack_pop(cons->context->cons_stack);
	data->cons = cons;
	if (!data) {
		return;
	}
	cons_stack_load(data, true);
	cons_stack_free((void *)data);
}

RZ_API RzConsContext *rz_cons_context_new(RZ_NULLABLE RzConsContext *parent) {
	RzConsContext *context = RZ_NEW0(RzConsContext);
	if (!context) {
		return NULL;
	}
	cons_context_init(context, parent);
	return context;
}

RZ_API void rz_cons_context_free(RzConsContext *context) {
	if (!context) {
		return;
	}
	cons_context_deinit(context);
	free(context);
}

RZ_API void rz_cons_context_load(RZ_NONNULL RZ_BORROW RzCons *cons, RzConsContext *context) {
	cons->context = context;
}

RZ_API void rz_cons_context_reset(RZ_NONNULL RZ_BORROW RzCons *cons) {
	cons->context = &rz_cons_context_default;
}

RZ_API bool rz_cons_context_is_main(RZ_NONNULL RZ_BORROW RzCons *cons) {
	return cons->context == &rz_cons_context_default;
}

RZ_API void rz_cons_context_break(RzConsContext *context) {
	if (!context || !context->intr) {
		return;
	}
	rz_interrupt_raise(context->intr);
}

RZ_API void rz_cons_last(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (!cons->context->lastEnabled) {
		return;
	}
	cons->context->lastMode = true;
	rz_cons_memcat(cons, cons->context->lastOutput, cons->context->lastLength);
}

static bool lastMatters(RzCons *cons) {
	return (cons->context->buffer_len > 0) && (cons->context->lastEnabled && !cons->filter && cons->context->grep.nstrings < 1 && !cons->context->grep.tokens_used && !cons->context->grep.less && !cons->context->grep.json && !cons->is_html);
}

RZ_API void rz_cons_echo(RZ_NONNULL RZ_BORROW RzCons *cons, const char *msg) {
	if (msg) {
		if (cons->echobuf) {
			rz_strbuf_append(cons->echobuf, msg);
			rz_strbuf_append(cons->echobuf, "\n");
		} else {
			cons->echobuf = rz_strbuf_new(msg);
		}
	} else {
		if (cons->echobuf) {
			char *data = rz_strbuf_drain(cons->echobuf);
			rz_cons_strcat(cons, data);
			rz_cons_newline(cons);
			cons->echobuf = NULL;
			free(data);
		}
	}
}

RZ_API void rz_cons_flush(RZ_NONNULL RZ_BORROW RzCons *cons) {
	const char *tee = cons->teefile;
	if (cons->context->noflush) {
		return;
	}
	if (cons->null) {
		rz_cons_reset(cons);
		return;
	}
	if (lastMatters(cons) && !cons->context->lastMode) {
		// snapshot of the output
		if (cons->context->buffer_len > cons->context->lastLength || !cons->context->lastOutput) {
			free(cons->context->lastOutput);
			cons->context->lastOutput = malloc(cons->context->buffer_len + 1);
		}
		cons->context->lastLength = cons->context->buffer_len;
		if (cons->context->lastOutput) {
			memcpy(cons->context->lastOutput, cons->context->buffer, cons->context->buffer_len);
		}
	} else {
		cons->context->lastMode = false;
	}
	rz_cons_filter(cons);
	if (rz_cons_is_interactive(cons) && cons->fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (cons->context->pageable && cons->context->buffer && cons->pager && *cons->pager && cons->context->buffer_len > 0 && rz_str_char_count(cons->context->buffer, '\n') >= cons->rows) {
			(cons->context->buffer)[cons->context->buffer_len - 1] = 0;
			if (!strcmp(cons->pager, "..")) {
				char *str = rz_str_ndup(cons->context->buffer, cons->context->buffer_len);
				cons->context->pageable = false;
				rz_cons_less_str(cons, str, NULL);
				rz_cons_reset(cons);
				free(str);
				return;
			} else {
				rz_sys_cmd_str_full(cons->pager, cons->context->buffer, NULL, NULL, NULL);
				rz_cons_reset(cons);
			}
		} else if (cons->context->buffer_len > CONS_MAX_USER) {
#if COUNT_LINES
			int i, lines = 0;
			for (i = 0; cons->context->buffer[i]; i++) {
				if (cons->context->buffer[i] == '\n') {
					lines++;
				}
			}
			if (lines > 0 && !rz_cons_yesno(cons, 'n', "Do you want to print %d lines? (y/N)", lines)) {
				rz_cons_reset(cons);
				return;
			}
#else
			char buf[8];
			rz_num_units(buf, sizeof(buf), cons->context->buffer_len);
			if (!rz_cons_yesno(cons, 'n', "Do you want to print %s chars? (y/N)", buf)) {
				rz_cons_reset(cons);
				return;
			}
#endif
			// fix | more | less problem
			rz_cons_set_raw(cons, true);
		}
	}
	if (tee && *tee) {
		FILE *d = rz_sys_fopen(tee, "a+");
		if (d) {
			if (cons->context->buffer_len != fwrite(cons->context->buffer, 1, cons->context->buffer_len, d)) {
				eprintf("rz_cons_flush: fwrite: error (%s)\n", tee);
			}
			fclose(d);
		} else {
			eprintf("Cannot write on '%s'\n", tee);
		}
	}
	rz_cons_highlight(cons, cons->highlight);

	// is_html must be a filter, not a write endpoint
	if (rz_cons_is_interactive(cons)) {
		if (cons->linesleep > 0 && cons->linesleep < 1000) {
			int i = 0;
			int pagesize = RZ_MAX(1, cons->pagesize);
			char *ptr = cons->context->buffer;
			char *nl = strchr(ptr, '\n');
			int len = cons->context->buffer_len;
			(cons->context->buffer)[cons->context->buffer_len] = 0;
			rz_interrupt_break_push(cons->intr, NULL, NULL);
			while (nl && !rz_interrupt_is_breaked(cons->intr)) {
				__cons_write(cons, ptr, nl - ptr + 1);
				if (cons->linesleep && !(i % pagesize)) {
					rz_sys_usleep(cons->linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr(ptr, '\n');
				i++;
			}
			__cons_write(cons, ptr, cons->context->buffer + len - ptr);
			rz_interrupt_break_pop(cons->intr);
		} else {
			__cons_write(cons, cons->context->buffer, cons->context->buffer_len);
		}
	} else {
		__cons_write(cons, cons->context->buffer, cons->context->buffer_len);
	}

	rz_cons_reset(cons);
	if (cons->newline) {
		eprintf("\n");
		cons->newline = false;
	}
}

RZ_API void rz_cons_visual_flush(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (cons->context->noflush) {
		return;
	}
	rz_cons_highlight(cons, cons->highlight);
	if (!cons->null) {
/* TODO: this ifdef must go in the function body */
#if __WINDOWS__
		if (cons->vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
			rz_cons_visual_write(cons, cons->context->buffer);
		} else {
			rz_cons_w32_print(cons, cons->context->buffer, cons->context->buffer_len, true);
		}
#else
		rz_cons_visual_write(cons, cons->context->buffer);
#endif
	}
	rz_cons_reset(cons);
}

static int real_strlen(const char *ptr, int len) {
	int utf8len = rz_str_utf8_cols(ptr);
	int ansilen = rz_str_ansi_len(ptr);
	int diff = len - utf8len;
	if (diff > 0) {
		diff--;
	}
	return ansilen - diff;
}

RZ_API void rz_cons_visual_write(RZ_NONNULL RZ_BORROW RzCons *cons, char *buffer) {
	char white[1024];
	int alen, plen, lines = cons->rows;
	bool break_lines = cons->break_lines;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;

	if (cons->null) {
		return;
	}
	rz_return_if_fail(cons->columns > 0); // modulo by 0 is UB
	unsigned int cols = cons->columns;

	memset(&white, ' ', sizeof(white));
	while ((nl = strchr(ptr, '\n'))) {
		int len = ((int)(size_t)(nl - ptr)) + 1;
		int lines_needed = 0;

		*nl = 0;
		alen = real_strlen(ptr, len);
		*nl = '\n';
		pptr = ptr > buffer ? ptr - 1 : ptr;
		plen = ptr > buffer ? len : len - 1;

		if (break_lines) {
			lines_needed = alen / cols + (alen % cols == 0 ? 0 : 1);
		}
		if ((break_lines && lines < lines_needed && lines > 0) || (!break_lines && alen > cols)) {
			int olen = len;
			endptr = rz_str_ansi_chrn(ptr, (break_lines ? cols * lines : cols) + 1);
			endptr++;
			len = endptr - ptr;
			plen = ptr > buffer ? len : len - 1;
			if (lines > 0) {
				__cons_write(cons, pptr, plen);
				if (len != olen) {
					__cons_write(cons, RZ_CONS_CLEAR_FROM_CURSOR_TO_END, -1);
					__cons_write(cons, Color_RESET, strlen(Color_RESET));
				}
			}
		} else {
			if (lines > 0) {
				unsigned int w = cols - (alen % cols == 0 ? cols : alen % cols);
				__cons_write(cons, pptr, plen);
				if (cons->blankline && w > 0) {
					if (w > sizeof(white) - 1) {
						w = sizeof(white) - 1;
					}
					__cons_write(cons, white, w);
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (rz_mem_mem((const ut8 *)ptr, len, (const ut8 *)"\x1b[0;0H", 6)) {
				lines = cons->rows;
				__cons_write(cons, pptr, plen);
			}
		}
		if (break_lines) {
			lines -= lines_needed;
		} else {
			lines--; // do not use last line
		}
		ptr = nl + 1;
	}
	/* fill the rest of screen */
	if (lines > 0) {
		if (cols > sizeof(white)) {
			cols = sizeof(white);
		}
		while (--lines >= 0) {
			__cons_write(cons, white, cols);
		}
	}
}

RZ_API void rz_cons_printf_list(RZ_NONNULL RZ_BORROW RzCons *cons, const char *format, va_list ap) {
	size_t size, written;
	va_list ap2, ap3;

	va_copy(ap2, ap);
	va_copy(ap3, ap);
	if (cons->null || !format) {
		va_end(ap2);
		va_end(ap3);
		return;
	}
	if (strchr(format, '%')) {
		if (palloc(cons, MOAR + strlen(format) * 20)) {
		club:
			size = cons->context->buffer_sz - cons->context->buffer_len; /* remaining space in cons->context->buffer */
			written = vsnprintf(cons->context->buffer + cons->context->buffer_len, size, format, ap3);
			if (written >= size) { /* not all bytes were written */
				if (palloc(cons, written + 1)) { /* + 1 byte for \0 termination */
					va_end(ap3);
					va_copy(ap3, ap2);
					goto club;
				}
			}
			cons->context->buffer_len += written;
		}
	} else {
		rz_cons_strcat(cons, format);
	}
	va_end(ap2);
	va_end(ap3);
}

RZ_API int rz_cons_printf(RZ_NONNULL RZ_BORROW RzCons *cons, const char *format, ...) {
	va_list ap;
	if (!format || !*format) {
		return -1;
	}
	va_start(ap, format);
	rz_cons_printf_list(cons, format, ap);
	va_end(ap);

	return 0;
}

RZ_API int rz_cons_get_column(RZ_NONNULL RZ_BORROW RzCons *cons) {
	char *line = strrchr(cons->context->buffer, '\n');
	if (!line) {
		line = cons->context->buffer;
	}
	(cons->context->buffer)[cons->context->buffer_len] = 0;
	return rz_str_ansi_len(line);
}

/* final entrypoint for adding stuff in the buffer screen */
RZ_API int rz_cons_memcat(RZ_NONNULL RZ_BORROW RzCons *cons, const char *str, int len) {
	if (len < 0) {
		return -1;
	}
	if (cons->echo) {
		// Here to silent pedantic meson flags ...
		int rlen;
		if ((rlen = write(2, str, len)) != len) {
			return rlen;
		}
	}
	if (str && len > 0 && !cons->null) {
		if (palloc(cons, len + 1)) {
			memcpy(cons->context->buffer + cons->context->buffer_len, str, len);
			cons->context->buffer_len += len;
			(cons->context->buffer)[cons->context->buffer_len] = 0;
		}
	}
	if (cons->flush) {
		rz_cons_flush(cons);
	}
	if (cons->break_word && str && len > 0) {
		if (rz_mem_mem((const ut8 *)str, len, (const ut8 *)cons->break_word, cons->break_word_len)) {
			rz_interrupt_set_breaked(cons->intr, true);
		}
	}
	return len;
}

RZ_API void rz_cons_memset(RZ_NONNULL RZ_BORROW RzCons *cons, char ch, int len) {
	if (!cons->null && len > 0) {
		if (palloc(cons, len + 1)) {
			memset(cons->context->buffer + cons->context->buffer_len, ch, len);
			cons->context->buffer_len += len;
			(cons->context->buffer)[cons->context->buffer_len] = 0;
		}
	}
}

RZ_API void rz_cons_strcat(RZ_NONNULL RZ_BORROW RzCons *cons, const char *str) {
	int len;
	if (!str || cons->null) {
		return;
	}
	len = strlen(str);
	if (len > 0) {
		rz_cons_memcat(cons, str, len);
	}
}

RZ_API void rz_cons_newline(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (!cons->null) {
		rz_cons_strcat(cons, "\n");
	}
#if 0
	// This place is wrong to manage the color reset, can interfire with rzpipe output sending resetchars
	// and break json output appending extra chars.
	// this code now is managed into output.c:118 at function rz_cons_w32_print
	// now the console color is reset with each \n (same stuff do it here but in correct place ... i think)

#if __WINDOWS__
	rz_cons_reset_colors(cons);
#else
	rz_cons_strcat (cons, Color_RESET_ALL"\n");
#endif
	if (cons->is_html) rz_cons_strcat (cons, "<br />\n");
#endif
}

/**
 * \brief Calculates the aproximated x,y coordinates of the cursor before flushing
 * \param[out] rows Row number of the cursor
 * \return Column number of the cursor
 */
RZ_API int rz_cons_get_cursor(RZ_NONNULL RZ_BORROW RzCons *cons, RZ_NONNULL int *rows) {
	rz_return_val_if_fail(cons && rows, 0);
	int col = cons->context->col;
	int row = cons->context->row;
	if (cons->context->rowcol_calc_start > cons->context->buffer_len) {
		rz_warn_if_reached();
		cons->context->rowcol_calc_start = 0;
	}
	if (!cons->context->buffer) {
		*rows = 0;
		return 0;
	}
	const char *last_line = cons->context->buffer + cons->context->rowcol_calc_start;
	const char *ptr;
	while ((ptr = strchr(last_line, '\n'))) {
		last_line = ++ptr;
		row++;
	};
	const char *last_escape = last_line;
	while ((ptr = strchr(last_escape, '\x1b'))) {
		// ignore ansi chars, copypasta from rz_str_ansi_len
		col += ptr - last_escape;
		char ch2 = *++ptr;
		if (ch2 == '\\') {
			ptr++;
		} else if (ch2 == ']') {
			if (!strncmp(ptr + 2 + 5, "rgb:", 4)) {
				ptr += 18;
			}
		} else if (ch2 == '[') {
			for (++ptr; *ptr && *ptr != 'J' && *ptr != 'm' && *ptr != 'H'; ptr++) {
				;
			}
		}
		last_escape = ptr;
	}
	*rows = row;
	cons->context->row = row;
	cons->context->col = col;
	cons->context->rowcol_calc_start = cons->context->buffer_len;
	return col;
}

RZ_API bool rz_cons_isatty() {
#if __UNIX__
	struct winsize win = { 0 };
	const char *tty;
	struct stat sb;

	if (!isatty(1)) {
		return false;
	}
	if (ioctl(1, TIOCGWINSZ, &win)) {
		return false;
	}
	if (!win.ws_col || !win.ws_row) {
		return false;
	}
	tty = ttyname(1);
	if (!tty) {
		return false;
	}
	if (stat(tty, &sb) || !S_ISCHR(sb.st_mode)) {
		return false;
	}
	return true;
#elif __WINDOWS__
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	if (GetFileType(hOut) == FILE_TYPE_CHAR) {
		DWORD unused;
		return GetConsoleMode(hOut, &unused);
	}
#endif
	/* non-UNIX do not have ttys */
	return false;
}

#if __WINDOWS__
static int __pty_get_cur_pos(RzCons *cons, int *xpos) {
	int ypos = 0;
	const char *get_pos = RZ_CONS_GET_CURSOR_POSITION;
	if (write(cons->fdout, get_pos, sizeof(get_pos)) < 1) {
		return 0;
	}
	int ch;
	char pos[16];
	size_t i;
	bool is_reply;
	do {
		is_reply = true;
		ch = rz_cons_readchar(cons);
		if (ch != 0x1b) {
			while ((ch = rz_cons_readchar_timeout(cons, 25))) {
				if (ch < 1) {
					return 0;
				}
				if (ch == 0x1b) {
					break;
				}
			}
		}
		(void)rz_cons_readchar(cons);
		for (i = 0; i < RZ_ARRAY_SIZE(pos) - 1; i++) {
			ch = rz_cons_readchar(cons);
			if ((!i && !IS_DIGIT(ch)) || // dumps arrow keys etc.
				(i == 1 && ch == '~')) { // dumps PgUp, PgDn etc.
				is_reply = false;
				break;
			}
			if (ch == ';') {
				pos[i] = 0;
				break;
			}
			pos[i] = ch;
		}
	} while (!is_reply);
	pos[RZ_ARRAY_SIZE(pos) - 1] = 0;
	ypos = atoi(pos);
	for (i = 0; i < RZ_ARRAY_SIZE(pos) - 1; i++) {
		if ((ch = rz_cons_readchar(cons)) == 'R') {
			pos[i] = 0;
			break;
		}
		pos[i] = ch;
	}
	pos[RZ_ARRAY_SIZE(pos) - 1] = 0;
	*xpos = atoi(pos);

	return ypos;
}

static bool __pty_get_size(RzCons *cons) {
	if (write(cons->fdout, RZ_CONS_CURSOR_SAVE, sizeof(RZ_CONS_CURSOR_SAVE)) < 1) {
		return false;
	}
	int rows, columns;
	rz_xwrite(cons->fdout, "\x1b[999;999H", sizeof("\x1b[999;999H"));
	rows = __pty_get_cur_pos(cons, &columns);
	if (rows) {
		cons->rows = rows;
		cons->columns = columns;
	} // otherwise reuse previous values
	rz_xwrite(cons->fdout, RZ_CONS_CURSOR_RESTORE, sizeof(RZ_CONS_CURSOR_RESTORE));
	return true;
}

#endif

// XXX: if this function returns <0 in rows or cols expect MAYHEM
RZ_API int rz_cons_get_size(RZ_NONNULL RZ_BORROW RzCons *cons, int *rows) {
#if __WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	bool ret = GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	if (ret) {
		cons->columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		cons->rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	} else {
		if (cons->term_pty) {
			ret = __pty_get_size();
		}
		if (!ret || (cons->columns == -1 && cons->rows == 0)) {
			// Stdout is probably redirected so we set default values
			cons->columns = 80;
			cons->rows = 23;
		}
	}
#elif EMSCRIPTEN
	cons->columns = 80;
	cons->rows = 23;
#elif __UNIX__
	struct winsize win = { 0 };
	if (isatty(0) && !ioctl(0, TIOCGWINSZ, &win)) {
		if ((!win.ws_col) || (!win.ws_row)) {
			const char *tty = isatty(1) ? ttyname(1) : NULL;
			int fd = open(tty ? tty : "/dev/tty", O_RDONLY);
			if (fd != -1) {
				int ret = ioctl(fd, TIOCGWINSZ, &win);
				if (ret || !win.ws_col || !win.ws_row) {
					win.ws_col = 80;
					win.ws_row = 23;
				}
				close(fd);
			}
		}
		cons->columns = win.ws_col;
		cons->rows = win.ws_row;
	} else {
		cons->columns = 80;
		cons->rows = 23;
	}
#else
	char *str = rz_sys_getenv("COLUMNS");
	if (str) {
		cons->columns = atoi(str);
		cons->rows = 23; // XXX. windows must get console size
		free(str);
	} else {
		cons->columns = 80;
		cons->rows = 23;
	}
#endif
#if SIMULATE_ADB_SHELL
	cons->rows = 0;
	cons->columns = 0;
#endif
#if SIMULATE_MAYHEM
	// expect tons of crashes
	cons->rows = -1;
	cons->columns = -1;
#endif
	if (cons->rows < 0) {
		cons->rows = 0;
	}
	if (cons->columns < 0) {
		cons->columns = 0;
	}
	if (cons->force_columns) {
		cons->columns = cons->force_columns;
	}
	if (cons->force_rows) {
		cons->rows = cons->force_rows;
	}
	if (cons->fix_columns) {
		cons->columns += cons->fix_columns;
	}
	if (cons->fix_rows) {
		cons->rows += cons->fix_rows;
	}
	if (rows) {
		*rows = cons->rows;
	}
	cons->rows = RZ_MAX(0, cons->rows);
	return RZ_MAX(0, cons->columns);
}

#if __WINDOWS__

typedef DWORD(WINAPI *GetFileInformationByHandleEx_t)(
	_In_ HANDLE hFile,
	_In_ FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
	_Out_writes_bytes_(dwBufferSize) LPVOID lpFileInformation,
	_In_ DWORD dwBufferSize);

static GetFileInformationByHandleEx_t w32_GetFileInformationByHandleEx;

static inline bool is_win_10_creators_or_above(DWORD major, DWORD minor, DWORD release) {
	return major > 10 || (major == 10 && minor > 0) || (major == 10 && minor == 0 && release >= 1703);
}

RZ_API RzVirtTermMode rz_cons_detect_vt_mode(RZ_NONNULL RZ_BORROW RzCons *cons) {
	DWORD major;
	DWORD minor;
	DWORD release = 0;
	char *wt_session = rz_sys_getenv("WT_SESSION");
	if (wt_session) {
		free(wt_session);
		return RZ_VIRT_TERM_MODE_COMPLETE;
	}
	char *alacritty = rz_sys_getenv("ALACRITTY_LOG");
	if (alacritty) {
		free(alacritty);
		return RZ_VIRT_TERM_MODE_OUTPUT_ONLY;
	}
	const bool is_console = rz_cons_isatty(cons);
	HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
	if (!is_console) {
#if NTDDI_VERSION >= NTDDI_VISTA
		if (!w32_GetFileInformationByHandleEx) {
			HMODULE k32 = GetModuleHandleA("kernel32");
			if (k32) {
				w32_GetFileInformationByHandleEx = (GetFileInformationByHandleEx_t)GetProcAddress(k32, "GetFileInformationByHandleEx");
			}
		}
		if (w32_GetFileInformationByHandleEx) {
			struct {
				FILE_NAME_INFO fi;
				wchar_t buf[MAX_PATH];
			} buf;
			if (w32_GetFileInformationByHandleEx(in, FileNameInfo, &buf, sizeof(buf))) {
				buf.fi.FileName[buf.fi.FileNameLength / sizeof(WCHAR)] = 0;
				if ((wcsstr(buf.fi.FileName, L"msys-") || wcsstr(buf.fi.FileName, L"cygwin-")) &&
					wcsstr(buf.fi.FileName, L"-pty")) {
					cons->term_pty = 1;
				}
			}
		}
#endif
		return RZ_VIRT_TERM_MODE_COMPLETE;
	}
	char *ansicon = rz_sys_getenv("ANSICON");
	if (ansicon) {
		free(ansicon);
		return RZ_VIRT_TERM_MODE_OUTPUT_ONLY;
	}
	RzVirtTermMode win_support = RZ_VIRT_TERM_MODE_DISABLE;
	RSysInfo *info = rz_sys_info();
	if (info && info->version) {
		char *dot = strtok(info->version, ".");
		major = atoi(dot);
		dot = strtok(NULL, ".");
		minor = atoi(dot);
		if (info->release) {
			release = atoi(info->release);
		}
		// VT output processing was first introduced in Windows 10 Creators Update
		if (ENABLE_VIRTUAL_TERMINAL_PROCESSING && is_win_10_creators_or_above(major, minor, release)) {
			win_support = RZ_VIRT_TERM_MODE_OUTPUT_ONLY;
			if (ENABLE_VIRTUAL_TERMINAL_INPUT && is_console) {
				DWORD mode;
				if (GetConsoleMode(in, &mode)) {
					if (SetConsoleMode(in, mode | ENABLE_VIRTUAL_TERMINAL_INPUT)) {
						win_support = RZ_VIRT_TERM_MODE_COMPLETE;
					}
					SetConsoleMode(in, mode);
				}
			}
		}
	}
	rz_sys_info_free(info);
	return win_support;
}
#endif

RZ_API void rz_cons_show_cursor(RZ_NONNULL RZ_BORROW RzCons *cons, int cursor) {
#if __WINDOWS__
	if (cons->vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
#endif
		rz_xwrite(1, cursor ? "\x1b[?25h" : "\x1b[?25l", 6);
#if __WINDOWS__
	} else {
		static HANDLE hStdout = NULL;
		static DWORD size = -1;
		CONSOLE_CURSOR_INFO cursor_info;
		if (!hStdout) {
			hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
		}
		if (size == -1) {
			GetConsoleCursorInfo(hStdout, &cursor_info);
			size = cursor_info.dwSize;
		}
		cursor_info.dwSize = size;
		cursor_info.bVisible = cursor ? TRUE : FALSE;
		SetConsoleCursorInfo(hStdout, &cursor_info);
	}
#endif
}

/**
 * void rz_cons_set_raw(cons,  [0,1] )
 *
 *   Change canonicality of the terminal
 *
 * For optimization reasons, there's no initialization flag, so you need to
 * ensure that the make the first call to rz_cons_set_raw(cons) with '1' and
 * the next calls ^=1, so: 1, 0, 1, 0, 1, ...
 *
 * If you doesn't use this order you'll probably loss your terminal properties.
 *
 */
RZ_API void rz_cons_set_raw(RZ_NONNULL RZ_BORROW RzCons *cons, bool is_raw) {
	if (cons->oldraw != -1) {
		if (is_raw == cons->oldraw) {
			return;
		}
	}
#if EMSCRIPTEN
	/* do nothing here */
#elif __UNIX__
	// enforce echo off
	if (is_raw) {
		cons->term_raw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
		tcsetattr(0, TCSANOW, &cons->term_raw);
	} else {
		tcsetattr(0, TCSANOW, &cons->term_buf);
	}
#elif __WINDOWS__
	DWORD mode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	if (!GetConsoleMode(h, &mode)) {
		// non console stdin is valid in batch mode.. just track state and leave the handle untouched
		fflush(stdout);
		cons->oldraw = is_raw;
		return;
	}
	if (is_raw) {
		if (cons->term_pty) {
			rz_sys_xsystem("stty raw -echo");
		} else {
			SetConsoleMode(h, mode & cons->term_raw);
		}
	} else {
		if (cons->term_pty) {
			rz_sys_xsystem("stty -raw echo");
		} else {
			SetConsoleMode(h, mode | cons->term_buf);
		}
	}
#else
#warning No raw console supported for this platform
#endif
	fflush(stdout);
	cons->oldraw = is_raw;
}

RZ_API void rz_cons_set_utf8(RZ_NONNULL RZ_BORROW RzCons *cons, bool b) {
	cons->use_utf8 = b;
}

RZ_API void rz_cons_invert(RZ_NONNULL RZ_BORROW RzCons *cons, int set, int color) {
	rz_cons_strcat(cons, RZ_CONS_INVERT(set, color));
}

/*
  Enable/Disable scrolling in terminal:
    FMI: cd librz/cons/t ; make ti ; ./ti
  smcup: disable terminal scrolling (fullscreen mode)
  rmcup: enable terminal scrolling (normal mode)
*/
RZ_API bool rz_cons_set_cup(RZ_NONNULL RZ_BORROW RzCons *cons, bool enable) {
#if __UNIX__
	const char *code = enable
		? "\x1b[?1049h"
		  "\x1b"
		  "7\x1b[?47h"
		: "\x1b[?1049l"
		  "\x1b[?47l"
		  "\x1b"
		  "8";
	const size_t code_len = strlen(code);
	if (write(2, code, code_len) != code_len) {
		return false;
	}
	fflush(stdout);
#elif __WINDOWS__
	if (cons->vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
		if (enable) {
			const char *code = enable // xterm + xterm-color
				? "\x1b[?1049h\x1b"
				  "7\x1b[?47h"
				: "\x1b[?1049l\x1b[?47l"
				  "\x1b"
				  "8";
			const size_t code_len = strlen(code);
			if (write(2, code, code_len) != code_len) {
				return false;
			}
		}
		fflush(stdout);
	}
#endif
	return true;
}

RZ_API void rz_cons_column(RZ_NONNULL RZ_BORROW RzCons *cons, int c) {
	char *b = malloc(cons->context->buffer_len + 1);
	if (!b) {
		return;
	}
	memcpy(b, cons->context->buffer, cons->context->buffer_len);
	b[cons->context->buffer_len] = 0;
	rz_cons_reset(cons);
	// align current buffer N chars right
	rz_cons_strcat_justify(cons, b, c, 0);
	rz_cons_gotoxy(cons, 0, 0);
	free(b);
}

RZ_API void rz_cons_set_interactive(RZ_NONNULL RZ_BORROW RzCons *cons, bool x) {
	cons->context->last_interactive_option = cons->context->is_interactive;
	cons->context->is_interactive = x;
}

RZ_API void rz_cons_set_last_interactive(RZ_NONNULL RZ_BORROW RzCons *cons) {
	cons->context->is_interactive = cons->context->last_interactive_option;
}

RZ_API void rz_cons_set_title(RZ_NONNULL RZ_BORROW RzCons *cons, const char *str) {
#if __WINDOWS__
#if defined(_UNICODE)
	wchar_t *wstr = rz_utf8_to_utf16_l(str, strlen(str));
	if (wstr) {
		SetConsoleTitleW(wstr);
		RZ_FREE(wstr);
	}
#else // defined(_UNICODE)
	SetConsoleTitle(str);
#endif // defined(_UNICODE)
#else
	rz_cons_printf(cons, "\x1b]0;%s\007", str);
#endif
}

RZ_API void rz_cons_zero(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (cons->line) {
		cons->line->zerosep = true;
	}
	rz_xwrite(1, "", 1);
}

RZ_API void rz_cons_highlight(RZ_NONNULL RZ_BORROW RzCons *cons, const char *word) {
	int l, *cpos = NULL;
	char *rword = NULL, *res, *clean = NULL;
	char *inv[2] = {
		RZ_CONS_INVERT(true, true),
		RZ_CONS_INVERT(false, true)
	};
	int linv[2] = {
		strlen(inv[0]),
		strlen(inv[1])
	};

	if (!cons->enable_highlight) {
		rz_cons_enable_highlight(cons, true);
		return;
	}
	if (word && *word && cons->context->buffer) {
		int word_len = strlen(word);
		char *orig;
		clean = rz_str_ndup(cons->context->buffer, cons->context->buffer_len);
		l = rz_str_ansi_filter(clean, &orig, &cpos, -1);
		free(cons->context->buffer);
		cons->context->buffer = orig;
		if (cons->highlight) {
			if (strcmp(word, cons->highlight)) {
				free(cons->highlight);
				cons->highlight = rz_str_dup(word);
			}
		} else {
			cons->highlight = rz_str_dup(word);
		}
		rword = malloc(word_len + linv[0] + linv[1] + 1);
		if (!rword) {
			free(cpos);
			free(clean);
			return;
		}
		strcpy(rword, inv[0]);
		strcpy(rword + linv[0], word);
		strcpy(rword + linv[0] + word_len, inv[1]);
		res = rz_str_replace_thunked(cons->context->buffer, clean, cpos,
			l, word, rword, 1);
		if (res) {
			cons->context->buffer = res;
			cons->context->buffer_len = cons->context->buffer_sz = strlen(res);
		}
		free(rword);
		free(clean);
		free(cpos);
		ctx_rowcol_calc_reset(cons);
		/* don't free orig - it's assigned
		 * to cons->context->buffer and possibly realloc'd */
	} else {
		RZ_FREE(cons->highlight);
	}
}

RZ_API char *rz_cons_lastline(RZ_NONNULL RZ_BORROW RzCons *cons, int *len) {
	char *b = cons->context->buffer + cons->context->buffer_len;
	while (b > cons->context->buffer) {
		if (*b == '\n') {
			b++;
			break;
		}
		b--;
	}
	if (len) {
		int delta = b - cons->context->buffer;
		*len = cons->context->buffer_len - delta;
	}
	return b;
}

// same as rz_cons_lastline(RzCons *cons), but len will be the number of
// utf-8 characters excluding ansi escape sequences as opposed to just bytes
RZ_API char *rz_cons_lastline_utf8_ansi_len(RZ_NONNULL RZ_BORROW RzCons *cons, int *len) {
	if (!len) {
		return rz_cons_lastline(cons, 0);
	}

	char *b = cons->context->buffer + cons->context->buffer_len;
	int l = 0;
	int last_possible_ansi_end = 0;
	char ch = '\0';
	char ch2;
	while (b > cons->context->buffer) {
		ch2 = ch;
		ch = *b;

		if (ch == '\n') {
			b++;
			l--;
			break;
		}

		// utf-8
		if ((ch & 0xc0) != 0x80) {
			l++;
		}

		// ansi
		if (ch == 'J' || ch == 'm' || ch == 'H') {
			last_possible_ansi_end = l - 1;
		} else if (ch == '\x1b' && ch2 == '[') {
			l = last_possible_ansi_end;
		}

		b--;
	}

	*len = l;
	return b;
}

/* swap color from foreground to background, returned value must be freed */
RZ_API char *rz_cons_swap_ground(const char *col) {
	if (!col) {
		return NULL;
	}
	if (!strncmp(col, "\x1b[48;5;", 7)) {
		/* rgb background */
		return rz_str_newf("\x1b[38;5;%s", col + 7);
	} else if (!strncmp(col, "\x1b[38;5;", 7)) {
		/* rgb foreground */
		return rz_str_newf("\x1b[48;5;%s", col + 7);
	} else if (!strncmp(col, "\x1b[4", 3)) {
		/* is background */
		return rz_str_newf("\x1b[3%s", col + 3);
	} else if (!strncmp(col, "\x1b[3", 3)) {
		/* is foreground */
		return rz_str_newf("\x1b[4%s", col + 3);
	}
	return rz_str_dup(col);
}

RZ_API bool rz_cons_drop(RZ_NONNULL RZ_BORROW RzCons *cons, int n) {
	if (n > cons->context->buffer_len) {
		cons->context->buffer_len = 0;
		return false;
	}
	cons->context->buffer_len -= n;
	return true;
}

RZ_API void rz_cons_chop(RZ_NONNULL RZ_BORROW RzCons *cons) {
	while (cons->context->buffer_len > 0) {
		char ch = cons->context->buffer[cons->context->buffer_len - 1];
		if (ch != '\n' && !IS_WHITESPACE(ch)) {
			break;
		}
		(cons->context->buffer_len)--;
	}
}

RZ_API void rz_cons_bind(RzConsBind *bind) {
	if (!bind) {
		return;
	}
	bind->get_size = (RzConsGetSize)rz_cons_get_size;
	bind->get_cursor = (RzConsGetCursor)rz_cons_get_cursor;
	bind->cb_printf = (PrintfCallback)rz_cons_printf;
	bind->cb_flush = (RzConsFlush)rz_cons_flush;
	bind->cb_grep = (RzConsGrepCallback)rz_cons_grep;
	bind->is_breaked = (RzConsIsBreaked)rz_interrupt_is_breaked;
}

RZ_API const char *rz_cons_get_rune(const ut8 ch) {
	switch (ch) {
	case RUNECODE_LINE_HORIZ: return RUNE_LINE_HORIZ;
	case RUNECODE_LINE_VERT: return RUNE_LINE_VERT;
	case RUNECODE_LINE_CROSS: return RUNE_LINE_CROSS;
	case RUNECODE_CORNER_TL: return RUNE_CORNER_TL;
	case RUNECODE_CORNER_TR: return RUNE_CORNER_TR;
	case RUNECODE_CORNER_BR: return RUNE_CORNER_BR;
	case RUNECODE_CORNER_BL: return RUNE_CORNER_BL;
	case RUNECODE_CURVE_CORNER_TL: return RUNE_CURVE_CORNER_TL;
	case RUNECODE_CURVE_CORNER_TR: return RUNE_CURVE_CORNER_TR;
	case RUNECODE_CURVE_CORNER_BR: return RUNE_CURVE_CORNER_BR;
	case RUNECODE_CURVE_CORNER_BL: return RUNE_CURVE_CORNER_BL;
	}
	return NULL;
}

RZ_API void rz_cons_breakword(RZ_NONNULL RZ_BORROW RzCons *cons, RZ_NULLABLE const char *s) {
	free(cons->break_word);
	if (s) {
		cons->break_word = rz_str_dup(s);
		cons->break_word_len = strlen(s);
	} else {
		cons->break_word = NULL;
		cons->break_word_len = 0;
	}
}

/* Prints a coloured help message.
 * help should be an array of the following form:
 * {"command", "args", "description",
 * "command2", "args2", "description"}; */
RZ_API void rz_cons_cmd_help(RZ_NONNULL RZ_BORROW RzCons *cons, const char *help[], bool use_color) {
	const char *pal_args_color = use_color ? cons->context->pal.args : "",
		   *pal_help_color = use_color ? cons->context->pal.help : "",
		   *pal_input_color = use_color ? cons->context->pal.input : "",
		   *pal_reset = use_color ? cons->context->pal.reset : "";
	int i, max_length = 0;
	const char *usage_str = "Usage:";

	for (i = 0; help[i]; i += 3) {
		int len0 = strlen(help[i]);
		int len1 = strlen(help[i + 1]);
		if (i) {
			max_length = RZ_MAX(max_length, len0 + len1);
		}
	}

	for (i = 0; help[i]; i += 3) {
		if (!strncmp(help[i], usage_str, strlen(usage_str))) {
			// Lines matching Usage: should always be the first in inline doc
			rz_cons_printf(cons, "%s%s %s  %s%s\n", pal_args_color,
				help[i], help[i + 1], help[i + 2], pal_reset);
			continue;
		}
		if (!help[i + 1][0] && !help[i + 2][0]) {
			// no need to indent the sections lines
			rz_cons_printf(cons, "%s%s%s\n", pal_help_color, help[i], pal_reset);
		} else {
			// these are the normal lines
			int str_length = strlen(help[i]) + strlen(help[i + 1]);
			int padding = (str_length < max_length) ? (max_length - str_length) : 0;
			rz_cons_printf(cons, "| %s%s%s%s%*s  %s%s%s\n",
				pal_input_color, help[i], pal_args_color, help[i + 1],
				padding, "", pal_help_color, help[i + 2], pal_reset);
		}
	}
}

RZ_API void rz_cons_clear_buffer(RZ_NONNULL RZ_BORROW RzCons *cons) {
	if (cons->vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
		rz_xwrite(1, "\x1b"
			     "c\x1b[3J",
			6);
	}
}

/**
 * \brief Set whether RzCons should flush content to screen or not
 *
 * \param flush If true, calls to \p rz_cons_flush and \p rz_cons_visual_flush
 *              would flush cons content to the screen, otherwise they will not.
 */
RZ_API void rz_cons_set_flush(RZ_NONNULL RZ_BORROW RzCons *cons, bool flush) {
	cons->context->noflush = !flush;
}
