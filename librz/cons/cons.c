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

#define COUNT_LINES 1
#define CTX(x)      I.context->x

RZ_LIB_VERSION(rz_cons);

static RzConsContext rz_cons_context_default = { { { { 0 } } } };
static RzCons rz_cons_instance = { 0 };
#define I rz_cons_instance

// this structure goes into cons_stack when rz_cons_push/pop
typedef struct {
	char *buf;
	int buf_len;
	int buf_size;
	RzConsGrep *grep;
	bool noflush;
} RzConsStack;

typedef struct {
	bool breaked;
	RzConsEvent event_interrupt;
	void *event_interrupt_data;
} RzConsBreakStack;

static void cons_grep_reset(RzConsGrep *grep);

static void ctx_rowcol_calc_reset(void) {
	CTX(row) = 0;
	CTX(col) = 0;
	CTX(rowcol_calc_start) = 0;
}

static void break_stack_free(void *ptr) {
	RzConsBreakStack *b = (RzConsBreakStack *)ptr;
	free(b);
}

static void cons_stack_free(void *ptr) {
	RzConsStack *s = (RzConsStack *)ptr;
	free(s->buf);
	if (s->grep) {
		RZ_FREE(s->grep->str);
		CTX(grep.str) = NULL;
	}
	free(s->grep);
	free(s);
}

static RzConsStack *cons_stack_dump(bool recreate) {
	RzConsStack *data = RZ_NEW0(RzConsStack);
	if (data) {
		if (CTX(buffer)) {
			data->buf = CTX(buffer);
			data->buf_len = CTX(buffer_len);
			data->buf_size = CTX(buffer_sz);
		}
		data->noflush = CTX(noflush);
		data->grep = RZ_NEW0(RzConsGrep);
		if (data->grep) {
			memcpy(data->grep, &CTX(grep), sizeof(RzConsGrep));
			if (CTX(grep).str) {
				data->grep->str = strdup(CTX(grep).str);
			}
		}
		if (recreate && CTX(buffer_sz) > 0) {
			CTX(buffer) = malloc(CTX(buffer_sz));
			ctx_rowcol_calc_reset();
			if (!CTX(buffer)) {
				CTX(buffer) = data->buf;
				free(data);
				return NULL;
			}
		} else {
			CTX(buffer) = NULL;
		}
	}
	return data;
}

static void cons_stack_load(RzConsStack *data, bool free_current) {
	rz_return_if_fail(data);
	if (free_current) {
		free(CTX(buffer));
	}
	CTX(buffer) = data->buf;
	data->buf = NULL;
	CTX(buffer_len) = data->buf_len;
	CTX(buffer_sz) = data->buf_size;
	if (data->grep) {
		free(CTX(grep).str);
		memcpy(&CTX(grep), data->grep, sizeof(RzConsGrep));
	}
	CTX(noflush) = data->noflush;
	ctx_rowcol_calc_reset();
}

static void cons_context_init(RzConsContext *context, RZ_NULLABLE RzConsContext *parent) {
	context->breaked = false;
	context->cmd_depth = RZ_CONS_CMD_DEPTH + 1;
	context->buffer = NULL;
	context->buffer_sz = 0;
	context->lastEnabled = true;
	context->buffer_len = 0;
	context->is_interactive = false;
	context->cons_stack = rz_stack_newf(6, cons_stack_free);
	context->break_stack = rz_stack_newf(6, break_stack_free);
	context->event_interrupt = NULL;
	context->event_interrupt_data = NULL;
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
	rz_stack_free(context->break_stack);
	context->break_stack = NULL;
	rz_cons_pal_free(context);
}

static void __break_signal(int sig) {
	rz_cons_context_break(&rz_cons_context_default);
}

static inline void __cons_write_ll(const char *buf, int len) {
#if __WINDOWS__
	if (I.vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
		rz_xwrite(I.fdout, buf, len);
	} else {
		if (I.fdout == 1) {
			rz_cons_w32_print(buf, len, false);
		} else {
			rz_xwrite(I.fdout, buf, len);
		}
	}
#else
	if (I.fdout < 1) {
		I.fdout = 1;
	}
	rz_xwrite(I.fdout, buf, len);
#endif
}

static inline void __cons_write(const char *obuf, int olen) {
	const size_t bucket = 64 * 1024;
	size_t i;
	if (olen < 0) {
		olen = strlen(obuf);
	}
	for (i = 0; (i + bucket) < olen; i += bucket) {
		__cons_write_ll(obuf + i, bucket);
	}
	if (i < olen) {
		__cons_write_ll(obuf + i, olen - i);
	}
}

RZ_API RzColor rz_cons_color_random(ut8 alpha) {
	RzColor rcolor = { 0 };
	if (CTX(color_mode) > COLOR_MODE_16) {
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

RZ_API void rz_cons_color(int fg, int r, int g, int b) {
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
	rz_cons_printf("\x1b[%d;5;%dm", fg ? 48 : 38, k);
}

RZ_API void rz_cons_println(const char *str) {
	rz_cons_print(str);
	rz_cons_newline();
}

RZ_API void rz_cons_strcat_justify(const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			rz_cons_memset(' ', j);
			if (c) {
				rz_cons_memset(c, 1);
				rz_cons_memset(' ', 1);
			}
			rz_cons_memcat(str + o, len);
			if (str[o + len] == '\n') {
				rz_cons_newline();
			}
			o = i + 1;
			len = 0;
		}
	}
	if (len > 1) {
		rz_cons_memcat(str + o, len);
	}
}

RZ_API void rz_cons_strcat_at(const char *_str, int x, char y, int w, int h) {
	int i, o, len;
	int cols = 0;
	int rows = 0;
	if (x < 0 || y < 0) {
		int H, W = rz_cons_get_size(&H);
		if (x < 0) {
			x += W;
		}
		if (y < 0) {
			y += H;
		}
	}
	char *str = rz_str_ansi_crop(_str, 0, 0, w + 1, h);
	rz_cons_strcat(RZ_CONS_CURSOR_SAVE);
	for (o = i = len = 0; str[i]; i++, len++) {
		if (w < 0 || rows > w) {
			break;
		}
		if (str[i] == '\n') {
			rz_cons_gotoxy(x, y + rows);
			int ansilen = rz_str_ansi_len(str + o);
			cols = RZ_MIN(w, ansilen);
			const char *end = rz_str_ansi_chrn(str + o, cols);
			cols = end - str + o;
			rz_cons_memcat(str + o, RZ_MIN(len, cols));
			o = i + 1;
			len = 0;
			rows++;
		}
	}
	if (len > 1) {
		rz_cons_gotoxy(x, y + rows);
		rz_cons_memcat(str + o, len);
	}
	rz_cons_strcat(Color_RESET);
	rz_cons_strcat(RZ_CONS_CURSOR_RESTORE);
	free(str);
}

RZ_API RzCons *rz_cons_singleton(void) {
	return &I;
}

RZ_API void rz_cons_break_clear(void) {
	CTX(breaked) = false;
}

RZ_API void rz_cons_context_break_push(RzConsContext *context, RzConsBreak cb, void *user, bool sig) {
	if (!context->break_stack) {
		return;
	}

	// if we don't have any element in the stack start the signal
	RzConsBreakStack *b = RZ_NEW0(RzConsBreakStack);
	if (!b) {
		return;
	}
	if (rz_stack_is_empty(context->break_stack)) {
#if __UNIX__
		if (sig && rz_cons_context_is_main()) {
			rz_sys_signal(SIGINT, __break_signal);
		}
#endif
		context->breaked = false;
	}
	// save the actual state
	b->event_interrupt = context->event_interrupt;
	b->event_interrupt_data = context->event_interrupt_data;
	rz_stack_push(context->break_stack, b);
	// configure break
	context->event_interrupt = cb;
	context->event_interrupt_data = user;
}

RZ_API void rz_cons_context_break_pop(RzConsContext *context, bool sig) {
	if (!context->break_stack) {
		return;
	}
	// restore old state
	RzConsBreakStack *b = NULL;
	b = rz_stack_pop(context->break_stack);
	if (b) {
		context->event_interrupt = b->event_interrupt;
		context->event_interrupt_data = b->event_interrupt_data;
		break_stack_free(b);
	} else {
		// there is not more elements in the stack
#if __UNIX__
		if (sig && rz_cons_context_is_main()) {
			rz_sys_signal(SIGINT, SIG_IGN);
		}
#endif
		context->breaked = false;
	}
}

RZ_API void rz_cons_break_push(RzConsBreak cb, void *user) {
	rz_cons_context_break_push(I.context, cb, user, true);
}

RZ_API void rz_cons_break_pop(void) {
	rz_cons_context_break_pop(I.context, true);
}

RZ_API bool rz_cons_is_interactive(void) {
	return CTX(is_interactive);
}

RZ_API bool rz_cons_default_context_is_interactive(void) {
	return rz_cons_context_default.is_interactive;
}

RZ_API bool rz_cons_is_breaked(void) {
	if (I.cb_break) {
		I.cb_break(I.user);
	}
	if (I.timeout) {
		if (rz_time_now_mono() > I.timeout) {
			CTX(breaked) = true;
			eprintf("\nTimeout!\n");
			I.timeout = 0;
		}
	}
	return CTX(breaked);
}

RZ_API int rz_cons_get_cur_line(void) {
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

RZ_API void rz_cons_break_timeout(int timeout) {
	I.timeout = (timeout && !I.timeout)
		? rz_time_now_mono() + ((ut64)timeout << 20)
		: 0;
}

RZ_API void rz_cons_break_end(void) {
	CTX(breaked) = false;
	I.timeout = 0;
#if __UNIX__
	rz_sys_signal(SIGINT, SIG_IGN);
#endif
	if (!rz_stack_is_empty(CTX(break_stack))) {
		// free all the stack
		rz_stack_free(CTX(break_stack));
		// create another one
		CTX(break_stack) = rz_stack_newf(6, break_stack_free);
		CTX(event_interrupt_data) = NULL;
		CTX(event_interrupt) = NULL;
	}
}

RZ_API void *rz_cons_sleep_begin(void) {
	if (!I.cb_sleep_begin) {
		return NULL;
	}
	return I.cb_sleep_begin(I.user);
}

RZ_API void rz_cons_sleep_end(void *user) {
	if (I.cb_sleep_end) {
		I.cb_sleep_end(I.user, user);
	}
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
void resizeWin(void) {
	if (I.event_resize) {
		I.event_resize(I.event_data);
	}
}

/**
 * \brief Set the property of the click event
 * \param x The x coordinate of the position
 * \param y The y coordinate of the position
 * \param event The type of the click
 */
RZ_API void rz_cons_set_click(int x, int y, MouseEvent event) {
	I.click_x = x;
	I.click_y = y;
	I.click_set = true;
	I.mouse_event = event;
}

RZ_API bool rz_cons_get_click(int *x, int *y) {
	if (x) {
		*x = I.click_x;
	}
	if (y) {
		*y = I.click_y;
	}
	bool set = I.click_set;
	I.click_set = false;
	return set;
}

RZ_API void rz_cons_enable_highlight(const bool enable) {
	I.enable_highlight = enable;
}

RZ_API bool rz_cons_enable_mouse(const bool enable) {
	if ((I.mouse && enable) || (!I.mouse && !enable)) {
		return I.mouse;
	}
#if __WINDOWS__
	if (I.vtmode == RZ_VIRT_TERM_MODE_COMPLETE) {
#endif
		const char *click = enable
			? "\x1b[?1000;1006;1015h"
			: "\x1b[?1000;1006;1015l";
		// const char *old = enable ? "\x1b[?1001s" "\x1b[?1000h" : "\x1b[?1001r" "\x1b[?1000l";
		bool enabled = I.mouse;
		const size_t click_len = strlen(click);
		if (write(2, click, click_len) != click_len) {
			return false;
		}
		I.mouse = enable;
		return enabled;
#if __WINDOWS__
	}
	DWORD mode;
	HANDLE h;
	bool enabled = I.mouse;
	h = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &mode);
	mode |= ENABLE_EXTENDED_FLAGS;
	mode = enable
		? (mode | ENABLE_MOUSE_INPUT) & ~ENABLE_QUICK_EDIT_MODE
		: (mode & ~ENABLE_MOUSE_INPUT) | ENABLE_QUICK_EDIT_MODE;
	if (SetConsoleMode(h, mode)) {
		I.mouse = enable;
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

static void save_console_state(void) {
	if (rz_cons_isatty()) {
		if (!(I.old_ocp = GetConsoleOutputCP())) {
			rz_sys_perror("GetConsoleOutputCP");
		}
		if (!(I.old_cp = GetConsoleCP())) {
			rz_sys_perror("GetConsoleCP");
		}
		if (!GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &I.old_output_mode)) {
			rz_sys_perror("GetConsoleMode");
		}
		if (!GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &I.old_input_mode)) {
			rz_sys_perror("GetConsoleCP");
		}
	}
}

static void restore_console_state(void) {
	if (rz_cons_isatty()) {
		if (!SetConsoleCP(I.old_cp)) {
			rz_sys_perror("SetConsoleCP");
		}
		if (!SetConsoleOutputCP(I.old_ocp)) {
			rz_sys_perror("SetConsoleOutputCP");
		}
		if (!SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), I.old_output_mode)) {
			rz_sys_perror("SetConsoleMode");
		}
		if (!SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), I.old_input_mode)) {
			rz_sys_perror("SetConsoleMode");
		}
	}
}
#endif

// Stub function that cb_main_output gets pointed to in util/log.c by rz_cons_new
// This allows Cutter to set per-task logging redirection
RZ_API RzCons *rz_cons_new(void) {
	I.refcnt++;
	if (I.refcnt != 1) {
		return &I;
	}
	I.rgbstr = rz_cons_rgb_str_off;
	I.line = rz_line_new();
	I.enable_highlight = true;
	I.highlight = NULL;
	I.is_wine = -1;
	I.blankline = true;
	I.teefile = NULL;
	I.fix_columns = 0;
	I.fix_rows = 0;
	I.mouse_event = MOUSE_NONE;
	I.force_rows = 0;
	I.force_columns = 0;
	I.event_resize = NULL;
	I.event_data = NULL;
	I.linesleep = 0;
	I.fdin = stdin;
	I.fdout = 1;
	I.break_lines = false;
	I.lines = 0;

	I.input = RZ_NEW0(RzConsInputContext);
	I.input->bufactive = true;
	I.context = &rz_cons_context_default;
	cons_context_init(I.context, NULL);

	rz_cons_get_size(&I.pagesize);
	I.num = NULL;
	I.null = 0;
#if __WINDOWS__
	save_console_state();
	I.vtmode = rz_cons_detect_vt_mode();
	set_console_codepage_to_utf8();
#else
	I.vtmode = RZ_VIRT_TERM_MODE_COMPLETE;
#endif
#if EMSCRIPTEN
	/* do nothing here :? */
#elif __UNIX__
	tcgetattr(0, &I.term_buf);
	memcpy(&I.term_raw, &I.term_buf, sizeof(I.term_raw));
	I.term_raw.c_iflag &= ~(BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	I.term_raw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
	I.term_raw.c_cflag &= ~(CSIZE | PARENB);
	I.term_raw.c_cflag |= CS8;
	I.term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	rz_sys_signal(SIGWINCH, resize);
#elif __WINDOWS__
	I.term_buf = I.old_input_mode | ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT;
	I.term_raw = ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);
	if (!SetConsoleCtrlHandler((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		eprintf("rz_cons: Cannot set control console handler\n");
	}
#endif
	I.pager = NULL; /* no pager by default */
	I.mouse = 0;
	I.show_vals = false;
	rz_cons_reset();
	rz_cons_rgb_init();

	rz_print_set_is_interrupted_cb(rz_cons_is_breaked);

	return &I;
}

RZ_API RzCons *rz_cons_free(void) {
	if (I.refcnt <= 0) {
		return NULL;
	}
	I.refcnt--;
	if (I.refcnt != 0) {
		return &I;
	}
#if __WINDOWS__
	restore_console_state();
#endif
	if (I.line) {
		rz_line_free(I.line);
		I.line = NULL;
	}
	RZ_FREE(I.input->readbuffer);
	RZ_FREE(I.input);
	RZ_FREE(CTX(buffer));
	RZ_FREE(I.break_word);
	cons_context_deinit(I.context);
	RZ_FREE(CTX(lastOutput));
	CTX(lastLength) = 0;
	RZ_FREE(I.pager);
	return NULL;
}

#define MOAR (4096 * 8)
static bool palloc(int moar) {
	void *temp;
	if (moar <= 0) {
		return false;
	}
	if (!CTX(buffer)) {
		int new_sz;
		if ((INT_MAX - MOAR) < moar) {
			return false;
		}
		new_sz = moar + MOAR;
		temp = calloc(1, new_sz);
		if (temp) {
			CTX(buffer_sz) = new_sz;
			CTX(buffer) = temp;
			(CTX(buffer))[0] = '\0';
		}
	} else if (moar + CTX(buffer_len) > CTX(buffer_sz)) {
		char *new_buffer;
		int old_buffer_sz = CTX(buffer_sz);
		if ((INT_MAX - MOAR - moar) < CTX(buffer_sz)) {
			return false;
		}
		CTX(buffer_sz) += moar + MOAR;
		new_buffer = realloc(CTX(buffer), CTX(buffer_sz));
		if (new_buffer) {
			CTX(buffer) = new_buffer;
		} else {
			CTX(buffer_sz) = old_buffer_sz;
			return false;
		}
	}
	return true;
}

RZ_API int rz_cons_eof(void) {
	return feof(I.fdin);
}

RZ_API void rz_cons_gotoxy(int x, int y) {
#if __WINDOWS__
	rz_cons_w32_gotoxy(1, x, y);
#else
	rz_cons_printf("\x1b[%d;%dH", y, x);
#endif
}

RZ_API void rz_cons_goto_origin_reset(void) {
	rz_cons_gotoxy(0, 0);
	rz_cons_strcat(Color_RESET);
}

RZ_API void rz_cons_fill_line(void) {
	char *p, white[1024];
	int cols = I.columns - 1;
	if (cols < 1) {
		return;
	}
	p = (cols >= sizeof(white))
		? malloc(cols + 1)
		: white;
	if (p) {
		memset(p, ' ', cols);
		p[cols] = 0;
		rz_cons_strcat(p);
		if (white != p) {
			free(p);
		}
	}
}

RZ_API void rz_cons_clear_line(int std_err) {
#if __WINDOWS__
	if (I.vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
		fprintf(std_err ? stderr : stdout, "%s", RZ_CONS_CLEAR_LINE);
	} else {
		char white[1024];
		memset(&white, ' ', sizeof(white));
		if (I.columns > 0 && I.columns < sizeof(white)) {
			white[I.columns - 1] = 0;
		} else if (I.columns == 0) {
			white[0] = 0;
		} else {
			white[sizeof(white) - 1] = 0; // HACK
		}
		fprintf(std_err ? stderr : stdout, "\r%s\r", white);
	}
#else
	fprintf(std_err ? stderr : stdout, "%s", RZ_CONS_CLEAR_LINE);
#endif
	fflush(std_err ? stderr : stdout);
}

RZ_API void rz_cons_clear00(void) {
	rz_cons_clear();
	rz_cons_gotoxy(0, 0);
}

RZ_API void rz_cons_reset_colors(void) {
	rz_cons_strcat(Color_RESET_BG Color_RESET);
}

RZ_API void rz_cons_clear(void) {
	I.lines = 0;
#if __WINDOWS__
	rz_cons_w32_clear();
#else
	rz_cons_strcat(Color_RESET RZ_CONS_CLEAR_SCREEN);
#endif
}

static void cons_grep_reset(RzConsGrep *grep) {
	RZ_FREE(grep->str);
	RZ_FREE(grep->sorted_lines);
	RZ_FREE(grep->unsorted_lines);
	ZERO_FILL(*grep);
	grep->line = -1;
	grep->sort = -1;
	grep->sorted_column = -1;
	grep->sort_invert = false;
}

RZ_API void rz_cons_reset(void) {
	if (CTX(buffer)) {
		(CTX(buffer))[0] = '\0';
	}
	CTX(buffer_len) = 0;
	I.lines = 0;
	cons_grep_reset(&CTX(grep));
	CTX(pageable) = true;
	ctx_rowcol_calc_reset();
}

/**
 * \brief Return the current RzCons buffer
 */
RZ_API const char *rz_cons_get_buffer(void) {
	// check len otherwise it will return trash
	return CTX(buffer_len) ? CTX(buffer) : NULL;
}

/**
 * \brief Return a newly allocated buffer containing what's currently in RzCons buffer
 */
RZ_API RZ_OWN char *rz_cons_get_buffer_dup(void) {
	const char *s = rz_cons_get_buffer();
	return s ? strdup(s) : NULL;
}

RZ_API int rz_cons_get_buffer_len(void) {
	return CTX(buffer_len);
}

RZ_API void rz_cons_filter(void) {
	/* grep */
	if (I.filter || CTX(grep).nstrings > 0 || CTX(grep).tokens_used || CTX(grep).less || CTX(grep).json) {
		(void)rz_cons_grepbuf();
		I.filter = false;
	}
	/* html */
	if (I.is_html) {
		int newlen = 0;
		char *input = rz_str_ndup(CTX(buffer), CTX(buffer_len));
		char *res = rz_cons_html_filter(input, &newlen);
		free(CTX(buffer));
		CTX(buffer) = res;
		CTX(buffer_len) = newlen;
		CTX(buffer_sz) = newlen;
		ctx_rowcol_calc_reset();
		free(input);
	}
	if (I.was_html) {
		I.is_html = true;
		I.was_html = false;
	}
}

RZ_API void rz_cons_push(void) {
	if (!CTX(cons_stack)) {
		return;
	}
	RzConsStack *data = cons_stack_dump(true);
	if (!data) {
		return;
	}
	rz_stack_push(CTX(cons_stack), data);
	CTX(buffer_len) = 0;
	if (CTX(buffer)) {
		memset(CTX(buffer), 0, CTX(buffer_sz));
	}
	CTX(noflush) = true;
}

RZ_API void rz_cons_pop(void) {
	if (!CTX(cons_stack)) {
		return;
	}
	RzConsStack *data = (RzConsStack *)rz_stack_pop(CTX(cons_stack));
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

RZ_API void rz_cons_context_load(RzConsContext *context) {
	I.context = context;
}

RZ_API void rz_cons_context_reset(void) {
	I.context = &rz_cons_context_default;
}

RZ_API bool rz_cons_context_is_main(void) {
	return I.context == &rz_cons_context_default;
}

RZ_API void rz_cons_context_break(RzConsContext *context) {
	if (!context) {
		context = &rz_cons_context_default;
	}
	context->breaked = true;
	if (context->event_interrupt) {
		context->event_interrupt(context->event_interrupt_data);
	}
}

RZ_API void rz_cons_last(void) {
	if (!CTX(lastEnabled)) {
		return;
	}
	CTX(lastMode) = true;
	rz_cons_memcat(CTX(lastOutput), CTX(lastLength));
}

static bool lastMatters(void) {
	return (CTX(buffer_len) > 0) && (CTX(lastEnabled) && !I.filter && CTX(grep).nstrings < 1 && !CTX(grep).tokens_used && !CTX(grep).less && !CTX(grep).json && !I.is_html);
}

RZ_API void rz_cons_echo(const char *msg) {
	static RzStrBuf *echodata = NULL; // TODO: move into RzConsInstance? maybe nope
	if (msg) {
		if (echodata) {
			rz_strbuf_append(echodata, msg);
			rz_strbuf_append(echodata, "\n");
		} else {
			echodata = rz_strbuf_new(msg);
		}
	} else {
		if (echodata) {
			char *data = rz_strbuf_drain(echodata);
			rz_cons_strcat(data);
			rz_cons_newline();
			echodata = NULL;
			free(data);
		}
	}
}

RZ_API void rz_cons_flush(void) {
	const char *tee = I.teefile;
	if (CTX(noflush)) {
		return;
	}
	if (I.null) {
		rz_cons_reset();
		return;
	}
	if (lastMatters() && !CTX(lastMode)) {
		// snapshot of the output
		if (CTX(buffer_len) > CTX(lastLength)) {
			free(CTX(lastOutput));
			CTX(lastOutput) = malloc(CTX(buffer_len) + 1);
		}
		CTX(lastLength) = CTX(buffer_len);
		memcpy(CTX(lastOutput), CTX(buffer), CTX(buffer_len));
	} else {
		CTX(lastMode) = false;
	}
	rz_cons_filter();
	if (rz_cons_is_interactive() && I.fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (CTX(pageable) && CTX(buffer) && I.pager && *I.pager && CTX(buffer_len) > 0 && rz_str_char_count(CTX(buffer), '\n') >= I.rows) {
			(CTX(buffer))[CTX(buffer_len) - 1] = 0;
			if (!strcmp(I.pager, "..")) {
				char *str = rz_str_ndup(CTX(buffer), CTX(buffer_len));
				CTX(pageable) = false;
				rz_cons_less_str(str, NULL);
				rz_cons_reset();
				free(str);
				return;
			} else {
				rz_sys_cmd_str_full(I.pager, CTX(buffer), NULL, NULL, NULL);
				rz_cons_reset();
			}
		} else if (CTX(buffer_len) > CONS_MAX_USER) {
#if COUNT_LINES
			int i, lines = 0;
			for (i = 0; CTX(buffer)[i]; i++) {
				if (CTX(buffer)[i] == '\n') {
					lines++;
				}
			}
			if (lines > 0 && !rz_cons_yesno('n', "Do you want to print %d lines? (y/N)", lines)) {
				rz_cons_reset();
				return;
			}
#else
			char buf[8];
			rz_num_units(buf, sizeof(buf), CTX(buffer_len));
			if (!rz_cons_yesno('n', "Do you want to print %s chars? (y/N)", buf)) {
				rz_cons_reset();
				return;
			}
#endif
			// fix | more | less problem
			rz_cons_set_raw(true);
		}
	}
	if (tee && *tee) {
		FILE *d = rz_sys_fopen(tee, "a+");
		if (d) {
			if (CTX(buffer_len) != fwrite(CTX(buffer), 1, CTX(buffer_len), d)) {
				eprintf("rz_cons_flush: fwrite: error (%s)\n", tee);
			}
			fclose(d);
		} else {
			eprintf("Cannot write on '%s'\n", tee);
		}
	}
	rz_cons_highlight(I.highlight);

	// is_html must be a filter, not a write endpoint
	if (rz_cons_is_interactive()) {
		if (I.linesleep > 0 && I.linesleep < 1000) {
			int i = 0;
			int pagesize = RZ_MAX(1, I.pagesize);
			char *ptr = CTX(buffer);
			char *nl = strchr(ptr, '\n');
			int len = CTX(buffer_len);
			(CTX(buffer))[CTX(buffer_len)] = 0;
			rz_cons_break_push(NULL, NULL);
			while (nl && !rz_cons_is_breaked()) {
				__cons_write(ptr, nl - ptr + 1);
				if (I.linesleep && !(i % pagesize)) {
					rz_sys_usleep(I.linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr(ptr, '\n');
				i++;
			}
			__cons_write(ptr, CTX(buffer) + len - ptr);
			rz_cons_break_pop();
		} else {
			__cons_write(CTX(buffer), CTX(buffer_len));
		}
	} else {
		__cons_write(CTX(buffer), CTX(buffer_len));
	}

	rz_cons_reset();
	if (I.newline) {
		eprintf("\n");
		I.newline = false;
	}
}

RZ_API void rz_cons_visual_flush(void) {
	if (CTX(noflush)) {
		return;
	}
	rz_cons_highlight(I.highlight);
	if (!I.null) {
/* TODO: this ifdef must go in the function body */
#if __WINDOWS__
		if (I.vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
			rz_cons_visual_write(CTX(buffer));
		} else {
			rz_cons_w32_print(CTX(buffer), CTX(buffer_len), true);
		}
#else
		rz_cons_visual_write(CTX(buffer));
#endif
	}
	rz_cons_reset();
}

static int real_strlen(const char *ptr, int len) {
	int utf8len = rz_str_len_utf8(ptr);
	int ansilen = rz_str_ansi_len(ptr);
	int diff = len - utf8len;
	if (diff > 0) {
		diff--;
	}
	return ansilen - diff;
}

RZ_API void rz_cons_visual_write(char *buffer) {
	char white[1024];
	int alen, plen, lines = I.rows;
	bool break_lines = I.break_lines;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;

	if (I.null) {
		return;
	}
	rz_return_if_fail(I.columns > 0); // modulo by 0 is UB
	unsigned int cols = I.columns;

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
				__cons_write(pptr, plen);
				if (len != olen) {
					__cons_write(RZ_CONS_CLEAR_FROM_CURSOR_TO_END, -1);
					__cons_write(Color_RESET, strlen(Color_RESET));
				}
			}
		} else {
			if (lines > 0) {
				unsigned int w = cols - (alen % cols == 0 ? cols : alen % cols);
				__cons_write(pptr, plen);
				if (I.blankline && w > 0) {
					if (w > sizeof(white) - 1) {
						w = sizeof(white) - 1;
					}
					__cons_write(white, w);
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (rz_mem_mem((const ut8 *)ptr, len, (const ut8 *)"\x1b[0;0H", 6)) {
				lines = I.rows;
				__cons_write(pptr, plen);
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
			__cons_write(white, cols);
		}
	}
}

RZ_API void rz_cons_printf_list(const char *format, va_list ap) {
	size_t size, written;
	va_list ap2, ap3;

	va_copy(ap2, ap);
	va_copy(ap3, ap);
	if (I.null || !format) {
		va_end(ap2);
		va_end(ap3);
		return;
	}
	if (strchr(format, '%')) {
		if (palloc(MOAR + strlen(format) * 20)) {
		club:
			size = CTX(buffer_sz) - CTX(buffer_len); /* remaining space in CTX(buffer) */
			written = vsnprintf(CTX(buffer) + CTX(buffer_len), size, format, ap3);
			if (written >= size) { /* not all bytes were written */
				if (palloc(written + 1)) { /* + 1 byte for \0 termination */
					va_end(ap3);
					va_copy(ap3, ap2);
					goto club;
				}
			}
			CTX(buffer_len) += written;
		}
	} else {
		rz_cons_strcat(format);
	}
	va_end(ap2);
	va_end(ap3);
}

RZ_API int rz_cons_printf(const char *format, ...) {
	va_list ap;
	if (!format || !*format) {
		return -1;
	}
	va_start(ap, format);
	rz_cons_printf_list(format, ap);
	va_end(ap);

	return 0;
}

RZ_API int rz_cons_get_column(void) {
	char *line = strrchr(CTX(buffer), '\n');
	if (!line) {
		line = CTX(buffer);
	}
	(CTX(buffer))[CTX(buffer_len)] = 0;
	return rz_str_ansi_len(line);
}

/* final entrypoint for adding stuff in the buffer screen */
RZ_API int rz_cons_memcat(const char *str, int len) {
	if (len < 0) {
		return -1;
	}
	if (I.echo) {
		// Here to silent pedantic meson flags ...
		int rlen;
		if ((rlen = write(2, str, len)) != len) {
			return rlen;
		}
	}
	if (str && len > 0 && !I.null) {
		if (palloc(len + 1)) {
			memcpy(CTX(buffer) + CTX(buffer_len), str, len);
			CTX(buffer_len) += len;
			(CTX(buffer))[CTX(buffer_len)] = 0;
		}
	}
	if (I.flush) {
		rz_cons_flush();
	}
	if (I.break_word && str && len > 0) {
		if (rz_mem_mem((const ut8 *)str, len, (const ut8 *)I.break_word, I.break_word_len)) {
			CTX(breaked) = true;
		}
	}
	return len;
}

RZ_API void rz_cons_memset(char ch, int len) {
	if (!I.null && len > 0) {
		if (palloc(len + 1)) {
			memset(CTX(buffer) + CTX(buffer_len), ch, len);
			CTX(buffer_len) += len;
			(CTX(buffer))[CTX(buffer_len)] = 0;
		}
	}
}

RZ_API void rz_cons_strcat(const char *str) {
	int len;
	if (!str || I.null) {
		return;
	}
	len = strlen(str);
	if (len > 0) {
		rz_cons_memcat(str, len);
	}
}

RZ_API void rz_cons_newline(void) {
	if (!I.null) {
		rz_cons_strcat("\n");
	}
#if 0
This place is wrong to manage the color reset, can interfire with rzpipe output sending resetchars
and break json output appending extra chars.
this code now is managed into output.c:118 at function rz_cons_w32_print
now the console color is reset with each \n (same stuff do it here but in correct place ... i think)

#if __WINDOWS__
	rz_cons_reset_colors();
#else
	rz_cons_strcat (Color_RESET_ALL"\n");
#endif
	if (I.is_html) rz_cons_strcat ("<br />\n");
#endif
}

/**
 * \brief Calculates the aproximated x,y coordinates of the cursor before flushing
 * \param[out] rows Row number of the cursor
 * \return Column number of the cursor
 */
RZ_API int rz_cons_get_cursor(RZ_NONNULL int *rows) {
	rz_return_val_if_fail(rows, 0);
	int col = CTX(col);
	int row = CTX(row);
	if (CTX(rowcol_calc_start) > CTX(buffer_len)) {
		rz_warn_if_reached();
		CTX(rowcol_calc_start) = 0;
	}
	if (!CTX(buffer)) {
		*rows = 0;
		return 0;
	}
	const char *last_line = CTX(buffer) + CTX(rowcol_calc_start);
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
	CTX(row) = row;
	CTX(col) = col;
	CTX(rowcol_calc_start) = CTX(buffer_len);
	return col;
}

RZ_API bool rz_cons_isatty(void) {
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
static int __pty_get_cur_pos(int *xpos) {
	int ypos = 0;
	const char *get_pos = RZ_CONS_GET_CURSOR_POSITION;
	if (write(I.fdout, get_pos, sizeof(get_pos)) < 1) {
		return 0;
	}
	int ch;
	char pos[16];
	size_t i;
	bool is_reply;
	do {
		is_reply = true;
		ch = rz_cons_readchar();
		if (ch != 0x1b) {
			while ((ch = rz_cons_readchar_timeout(25))) {
				if (ch < 1) {
					return 0;
				}
				if (ch == 0x1b) {
					break;
				}
			}
		}
		(void)rz_cons_readchar();
		for (i = 0; i < RZ_ARRAY_SIZE(pos) - 1; i++) {
			ch = rz_cons_readchar();
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
		if ((ch = rz_cons_readchar()) == 'R') {
			pos[i] = 0;
			break;
		}
		pos[i] = ch;
	}
	pos[RZ_ARRAY_SIZE(pos) - 1] = 0;
	*xpos = atoi(pos);

	return ypos;
}

static bool __pty_get_size(void) {
	if (write(I.fdout, RZ_CONS_CURSOR_SAVE, sizeof(RZ_CONS_CURSOR_SAVE)) < 1) {
		return false;
	}
	int rows, columns;
	rz_xwrite(I.fdout, "\x1b[999;999H", sizeof("\x1b[999;999H"));
	rows = __pty_get_cur_pos(&columns);
	if (rows) {
		I.rows = rows;
		I.columns = columns;
	} // otherwise reuse previous values
	rz_xwrite(I.fdout, RZ_CONS_CURSOR_RESTORE, sizeof(RZ_CONS_CURSOR_RESTORE));
	return true;
}

#endif

// XXX: if this function returns <0 in rows or cols expect MAYHEM
RZ_API int rz_cons_get_size(int *rows) {
#if __WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	bool ret = GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
	if (ret) {
		I.columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		I.rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	} else {
		if (I.term_pty) {
			ret = __pty_get_size();
		}
		if (!ret || (I.columns == -1 && I.rows == 0)) {
			// Stdout is probably redirected so we set default values
			I.columns = 80;
			I.rows = 23;
		}
	}
#elif EMSCRIPTEN
	I.columns = 80;
	I.rows = 23;
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
		I.columns = win.ws_col;
		I.rows = win.ws_row;
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#else
	char *str = rz_sys_getenv("COLUMNS");
	if (str) {
		I.columns = atoi(str);
		I.rows = 23; // XXX. windows must get console size
		free(str);
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#endif
#if SIMULATE_ADB_SHELL
	I.rows = 0;
	I.columns = 0;
#endif
#if SIMULATE_MAYHEM
	// expect tons of crashes
	I.rows = -1;
	I.columns = -1;
#endif
	if (I.rows < 0) {
		I.rows = 0;
	}
	if (I.columns < 0) {
		I.columns = 0;
	}
	if (I.force_columns) {
		I.columns = I.force_columns;
	}
	if (I.force_rows) {
		I.rows = I.force_rows;
	}
	if (I.fix_columns) {
		I.columns += I.fix_columns;
	}
	if (I.fix_rows) {
		I.rows += I.fix_rows;
	}
	if (rows) {
		*rows = I.rows;
	}
	I.rows = RZ_MAX(0, I.rows);
	return RZ_MAX(0, I.columns);
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

RZ_API RzVirtTermMode rz_cons_detect_vt_mode(void) {
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
	const bool is_console = rz_cons_isatty();
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
					I.term_pty = 1;
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

RZ_API void rz_cons_show_cursor(int cursor) {
#if __WINDOWS__
	if (I.vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
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
 * void rz_cons_set_raw( [0,1] )
 *
 *   Change canonicality of the terminal
 *
 * For optimization reasons, there's no initialization flag, so you need to
 * ensure that the make the first call to rz_cons_set_raw() with '1' and
 * the next calls ^=1, so: 1, 0, 1, 0, 1, ...
 *
 * If you doesn't use this order you'll probably loss your terminal properties.
 *
 */
RZ_API void rz_cons_set_raw(bool is_raw) {
	static int oldraw = -1;
	if (oldraw != -1) {
		if (is_raw == oldraw) {
			return;
		}
	}
#if EMSCRIPTEN
	/* do nothing here */
#elif __UNIX__
	// enforce echo off
	if (is_raw) {
		I.term_raw.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
		tcsetattr(0, TCSANOW, &I.term_raw);
	} else {
		tcsetattr(0, TCSANOW, &I.term_buf);
	}
#elif __WINDOWS__
	DWORD mode;
	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	GetConsoleMode(h, &mode);
	if (is_raw) {
		if (I.term_pty) {
			rz_sys_xsystem("stty raw -echo");
		} else {
			SetConsoleMode(h, mode & I.term_raw);
		}
	} else {
		if (I.term_pty) {
			rz_sys_xsystem("stty -raw echo");
		} else {
			SetConsoleMode(h, mode | I.term_buf);
		}
	}
#else
#warning No raw console supported for this platform
#endif
	fflush(stdout);
	oldraw = is_raw;
}

RZ_API void rz_cons_set_utf8(bool b) {
	I.use_utf8 = b;
}

RZ_API void rz_cons_invert(int set, int color) {
	rz_cons_strcat(RZ_CONS_INVERT(set, color));
}

/*
  Enable/Disable scrolling in terminal:
    FMI: cd librz/cons/t ; make ti ; ./ti
  smcup: disable terminal scrolling (fullscreen mode)
  rmcup: enable terminal scrolling (normal mode)
*/
RZ_API bool rz_cons_set_cup(bool enable) {
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
	if (I.vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
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

RZ_API void rz_cons_column(int c) {
	char *b = malloc(CTX(buffer_len) + 1);
	if (!b) {
		return;
	}
	memcpy(b, CTX(buffer), CTX(buffer_len));
	b[CTX(buffer_len)] = 0;
	rz_cons_reset();
	// align current buffer N chars right
	rz_cons_strcat_justify(b, c, 0);
	rz_cons_gotoxy(0, 0);
	free(b);
}

//  XXX deprecate must be push/pop context state
static bool lasti = false; /* last interactive mode */

RZ_API void rz_cons_set_interactive(bool x) {
	lasti = rz_cons_singleton()->context->is_interactive;
	rz_cons_singleton()->context->is_interactive = x;
}

RZ_API void rz_cons_set_last_interactive(void) {
	rz_cons_singleton()->context->is_interactive = lasti;
}

RZ_API void rz_cons_set_title(const char *str) {
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
	rz_cons_printf("\x1b]0;%s\007", str);
#endif
}

RZ_API void rz_cons_zero(void) {
	if (I.line) {
		I.line->zerosep = true;
	}
	rz_xwrite(1, "", 1);
}

RZ_API void rz_cons_highlight(const char *word) {
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

	if (!I.enable_highlight) {
		rz_cons_enable_highlight(true);
		return;
	}
	if (word && *word && CTX(buffer)) {
		int word_len = strlen(word);
		char *orig;
		clean = rz_str_ndup(CTX(buffer), CTX(buffer_len));
		l = rz_str_ansi_filter(clean, &orig, &cpos, -1);
		free(CTX(buffer));
		CTX(buffer) = orig;
		if (I.highlight) {
			if (strcmp(word, I.highlight)) {
				free(I.highlight);
				I.highlight = strdup(word);
			}
		} else {
			I.highlight = strdup(word);
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
		res = rz_str_replace_thunked(CTX(buffer), clean, cpos,
			l, word, rword, 1);
		if (res) {
			CTX(buffer) = res;
			CTX(buffer_len) = CTX(buffer_sz) = strlen(res);
		}
		free(rword);
		free(clean);
		free(cpos);
		ctx_rowcol_calc_reset();
		/* don't free orig - it's assigned
		 * to CTX(buffer) and possibly realloc'd */
	} else {
		RZ_FREE(I.highlight);
	}
}

RZ_API char *rz_cons_lastline(int *len) {
	char *b = CTX(buffer) + CTX(buffer_len);
	while (b > CTX(buffer)) {
		if (*b == '\n') {
			b++;
			break;
		}
		b--;
	}
	if (len) {
		int delta = b - CTX(buffer);
		*len = CTX(buffer_len) - delta;
	}
	return b;
}

// same as rz_cons_lastline(), but len will be the number of
// utf-8 characters excluding ansi escape sequences as opposed to just bytes
RZ_API char *rz_cons_lastline_utf8_ansi_len(int *len) {
	if (!len) {
		return rz_cons_lastline(0);
	}

	char *b = CTX(buffer) + CTX(buffer_len);
	int l = 0;
	int last_possible_ansi_end = 0;
	char ch = '\0';
	char ch2;
	while (b > CTX(buffer)) {
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
	return strdup(col);
}

RZ_API bool rz_cons_drop(int n) {
	if (n > CTX(buffer_len)) {
		CTX(buffer_len) = 0;
		return false;
	}
	CTX(buffer_len) -= n;
	return true;
}

RZ_API void rz_cons_chop(void) {
	while (CTX(buffer_len) > 0) {
		char ch = CTX(buffer)[CTX(buffer_len) - 1];
		if (ch != '\n' && !IS_WHITESPACE(ch)) {
			break;
		}
		(CTX(buffer_len))--;
	}
}

RZ_API void rz_cons_bind(RzConsBind *bind) {
	if (!bind) {
		return;
	}
	bind->get_size = rz_cons_get_size;
	bind->get_cursor = rz_cons_get_cursor;
	bind->cb_printf = rz_cons_printf;
	bind->cb_flush = rz_cons_flush;
	bind->cb_grep = rz_cons_grep;
	bind->is_breaked = rz_cons_is_breaked;
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

RZ_API void rz_cons_breakword(RZ_NULLABLE const char *s) {
	free(I.break_word);
	if (s) {
		I.break_word = strdup(s);
		I.break_word_len = strlen(s);
	} else {
		I.break_word = NULL;
		I.break_word_len = 0;
	}
}

/* Prints a coloured help message.
 * help should be an array of the following form:
 * {"command", "args", "description",
 * "command2", "args2", "description"}; */
RZ_API void rz_cons_cmd_help(const char *help[], bool use_color) {
	RzCons *cons = rz_cons_singleton();
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
			rz_cons_printf("%s%s %s  %s%s\n", pal_args_color,
				help[i], help[i + 1], help[i + 2], pal_reset);
			continue;
		}
		if (!help[i + 1][0] && !help[i + 2][0]) {
			// no need to indent the sections lines
			rz_cons_printf("%s%s%s\n", pal_help_color, help[i], pal_reset);
		} else {
			// these are the normal lines
			int str_length = strlen(help[i]) + strlen(help[i + 1]);
			int padding = (str_length < max_length) ? (max_length - str_length) : 0;
			rz_cons_printf("| %s%s%s%s%*s  %s%s%s\n",
				pal_input_color, help[i], pal_args_color, help[i + 1],
				padding, "", pal_help_color, help[i + 2], pal_reset);
		}
	}
}

RZ_API void rz_cons_clear_buffer(void) {
	if (I.vtmode != RZ_VIRT_TERM_MODE_DISABLE) {
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
RZ_API void rz_cons_set_flush(bool flush) {
	CTX(noflush) = !flush;
}
