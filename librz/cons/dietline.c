// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only
/* dietline is a lightweight and portable library similar to GNU readline */

#include <rz_cons.h>
#include <rz_core.h>
#include <string.h>
#include <stdlib.h>

#if __WINDOWS__
#include <windows.h>
#define printf(...) rz_cons_win_printf(false, __VA_ARGS__)
#define USE_UTF8    1
static int rz_line_readchar_win(ut8 *s, int slen);
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#define USE_UTF8 1
#endif

static char *rz_line_nullstr = "";
static const char word_break_characters[] = "\t\n ~`!@#$%^&*()-_=+[]{}\\|;:\"'<>,./";

typedef enum {
	MINOR_BREAK,
	MAJOR_BREAK
} BreakMode;

bool enable_yank_pop = false;

static inline bool is_word_break_char(char ch, bool mode) {
	int i;
	if (mode == MAJOR_BREAK) {
		return ch == ' ';
	}
	for (i = 0; i < RZ_ARRAY_SIZE(word_break_characters); i++) {
		if (ch == word_break_characters[i]) {
			return true;
		}
	}
	return false;
}

/* https://www.gnu.org/software/bash/manual/html_node/Commands-For-Killing.html */
static void backward_kill_word(BreakMode mode) {
	int i, len;
	if (I.buffer.index <= 0) {
		return;
	}
	for (i = I.buffer.index; i > 0 && is_word_break_char(I.buffer.data[i], mode); i--) {
		/* Move the cursor index back until we hit a non-word-break-character */
	}
	for (; i > 0 && !is_word_break_char(I.buffer.data[i], mode); i--) {
		/* Move the cursor index back until we hit a word-break-character */
	}
	if (i > 0) {
		i++;
	} else if (i < 0) {
		i = 0;
	}
	if (I.buffer.index > I.buffer.length) {
		I.buffer.length = I.buffer.index;
	}
	len = I.buffer.index - i;
	free(I.clipboard);
	I.clipboard = rz_str_ndup(I.buffer.data + i, len);
	rz_line_clipboard_push(I.clipboard);
	memmove(I.buffer.data + i, I.buffer.data + I.buffer.index,
		I.buffer.length - I.buffer.index + 1);
	I.buffer.length = strlen(I.buffer.data);
	I.buffer.index = i;
}

static void kill_word(BreakMode mode) {
	int i, len;
	for (i = I.buffer.index; i < I.buffer.length && is_word_break_char(I.buffer.data[i], mode); i++) {
		/* Move the cursor index forward until we hit a non-word-break-character */
	}
	for (; i < I.buffer.length && !is_word_break_char(I.buffer.data[i], mode); i++) {
		/* Move the cursor index forward until we hit a word-break-character */
	}
	len = i - I.buffer.index;
	free(I.clipboard);
	I.clipboard = rz_str_ndup(I.buffer.data + I.buffer.index, len);
	rz_line_clipboard_push(I.clipboard);
	memmove(I.buffer.data + I.buffer.index, I.buffer.data + i, I.buffer.length - i + 1);
	I.buffer.length -= len;
}

static void paste(void) {
	if (I.clipboard) {
		char *cursor = I.buffer.data + I.buffer.index;
		int dist = (I.buffer.data + I.buffer.length) - cursor;
		int len = strlen(I.clipboard);
		I.buffer.length += len;
		memmove(cursor + len, cursor, dist);
		memcpy(cursor, I.clipboard, len);
		I.buffer.index += len;
		enable_yank_pop = true;
	}
}

static void unix_word_rubout(void) {
	int i, len;
	if (I.buffer.index > 0) {
		for (i = I.buffer.index - 1; i > 0 && I.buffer.data[i] == ' '; i--) {
			/* Move cursor backwards until we hit a non-space character or EOL */
			/* This removes any trailing spaces from the input */
		}
		for (; i > 0 && I.buffer.data[i] != ' '; i--) {
			/* Move cursor backwards until we hit a space character or EOL */
			/* This deletes everything back to the previous space character */
		}
		if (i > 0) {
			i++;
		} else if (i < 0) {
			i = 0;
		}
		if (I.buffer.index > I.buffer.length) {
			I.buffer.length = I.buffer.index;
		}
		len = I.buffer.index - i + 1;
		free(I.clipboard);
		I.clipboard = rz_str_ndup(I.buffer.data + i, len);
		rz_line_clipboard_push(I.clipboard);
		memmove(I.buffer.data + i,
			I.buffer.data + I.buffer.index,
			I.buffer.length - I.buffer.index + 1);
		I.buffer.length = strlen(I.buffer.data);
		I.buffer.index = i;
	}
}

static int inithist(void) {
	ZERO_FILL(I.history);
	if ((I.history.size + 1024) * sizeof(char *) < I.history.size) {
		return false;
	}
	I.history.data = (char **)calloc((I.history.size + 1024), sizeof(char *));
	if (!I.history.data) {
		return false;
	}
	I.history.size = RZ_LINE_HISTSIZE;
	return true;
}

/* initialize history stuff */
RZ_API int rz_line_dietline_init(void) {
	ZERO_FILL(I.completion);
	if (!inithist()) {
		return false;
	}
	I.echo = true;
	return true;
}

#if USE_UTF8
/* read utf8 char into 's', return the length in bytes */
static int rz_line_readchar_utf8(ut8 *s, int slen) {
#if __WINDOWS__
	return rz_line_readchar_win(s, slen);
#else
	// TODO: add support for w32
	ssize_t len, i;
	if (slen < 1) {
		return 0;
	}
	int ch = rz_cons_readchar();
	if (ch == -1) {
		return -1;
	}
	*s = ch;
#if 0
	if ((t = read (0, s, 1)) != 1) {
		return t;
	}
#endif
	*s = rz_cons_controlz(*s);
	if (*s < 0x80) {
		len = 1;
	} else if ((s[0] & 0xe0) == 0xc0) {
		len = 2;
	} else if ((s[0] & 0xf0) == 0xe0) {
		len = 3;
	} else if ((s[0] & 0xf8) == 0xf0) {
		len = 4;
	} else {
		return -1;
	}
	if (len > slen) {
		return -1;
	}
	for (i = 1; i < len; i++) {
		int ch = rz_cons_readchar();
		if (ch != -1) {
			s[i] = ch;
		}
		if ((s[i] & 0xc0) != 0x80) {
			return -1;
		}
	}
	return len;
#endif
}
#endif

#if __WINDOWS__
static int rz_line_readchar_win(ut8 *s, int slen) { // this function handle the input in console mode
	if (slen > 0 && rz_cons_readbuffer_readchar(s)) {
		if (s[0] == '\x1b' && rz_cons_readbuffer_readchar(s + 1)) {
			if (s[1] == '\x31' && rz_cons_readbuffer_readchar(s + 2)) {
				return 3;
			}
			return 2;
		}
		return 1;
	}
	INPUT_RECORD irInBuf = { { 0 } };
	BOOL ret, bCtrl = FALSE;
	DWORD mode, out;
	char buf[5] = { 0 };
	HANDLE h;
	void *bed;

	h = GetStdHandle(STD_INPUT_HANDLE);
	DWORD new_mode = I.vtmode == 2 ? ENABLE_VIRTUAL_TERMINAL_INPUT : 0;
	GetConsoleMode(h, &mode);
	SetConsoleMode(h, new_mode);
	if (I.zerosep) {
		bed = rz_cons_sleep_begin();
		DWORD rsz = 0;
		BOOL ret = ReadFile(h, s, 1, &rsz, NULL);
		rz_cons_sleep_end(bed);
		SetConsoleMode(h, mode);
		if (!ret || rsz != 1) {
			return 0;
		}
		return 1;
	}
do_it_again:
	bed = rz_cons_sleep_begin();
	if (rz_cons_singleton()->term_xterm) {
		ret = ReadFile(h, buf, 1, &out, NULL);
	} else {
		ret = ReadConsoleInput(h, &irInBuf, 1, &out);
	}
	rz_cons_sleep_end(bed);
	if (ret < 1) {
		return 0;
	}
	if (irInBuf.EventType == KEY_EVENT) {
		if (irInBuf.Event.KeyEvent.bKeyDown) {
			if (irInBuf.Event.KeyEvent.uChar.UnicodeChar) {
				char *tmp = rz_sys_conv_win_to_utf8_l((PTCHAR)&irInBuf.Event.KeyEvent.uChar, 1);
				if (!tmp) {
					return 0;
				}
				strncpy_s(buf, sizeof(buf), tmp, strlen(tmp));
				free(tmp);
			} else {
				int idx = 0;
				buf[idx++] = 27;
				buf[idx++] = '['; // Simulate escaping
				bCtrl = irInBuf.Event.KeyEvent.dwControlKeyState & 8;
				if (bCtrl) {
					buf[idx++] = 0x31;
				}
				switch (irInBuf.Event.KeyEvent.wVirtualKeyCode) {
				case VK_UP: buf[idx++] = 'A'; break;
				case VK_DOWN: buf[idx++] = 'B'; break;
				case VK_RIGHT: buf[idx++] = 'C'; break;
				case VK_LEFT: buf[idx++] = 'D'; break;
				case VK_PRIOR: buf[idx++] = '5'; break; // PAGE UP
				case VK_NEXT: buf[idx++] = '6'; break; // PAGE DOWN
				case VK_DELETE: buf[idx++] = '3'; break; // SUPR KEY
				case VK_HOME: buf[idx++] = 'H'; break; // HOME KEY
				case VK_END: buf[idx++] = 'F'; break; // END KEY
				default: buf[0] = 0; break;
				}
			}
		}
	}
	if (!buf[0]) {
		goto do_it_again;
	}
	strncpy_s((char *)s, slen, buf, sizeof(buf));
	SetConsoleMode(h, mode);
	return strlen((char *)s);
}

#endif

RZ_API int rz_line_set_hist_callback(RzLine *line, RzLineHistoryUpCb up, RzLineHistoryDownCb down) {
	line->cb_history_up = up;
	line->cb_history_down = down;
	line->offset_hist_index = 0;
	line->file_hist_index = 0;
	line->sdbshell_hist_iter = rz_list_head(line->sdbshell_hist);
	return 1;
}

static inline bool match_hist_line(char *hist_line, char *cur_line) {
	// Starts with but not equal to
	return rz_str_startswith(hist_line, cur_line) && strcmp(hist_line, cur_line);
}

static void setup_hist_match(RzLine *line) {
	if (line->history.do_setup_match) {
		RZ_FREE(line->history.match);
		if (*line->buffer.data) {
			line->history.match = strdup(line->buffer.data);
		}
	}
	line->history.do_setup_match = false;
}

RZ_API int rz_line_hist_cmd_up(RzLine *line) {
	if (line->hist_up) {
		return line->hist_up(line->user);
	}
	if (!line->history.data) {
		inithist();
	}
	if (line->history.index > 0 && line->history.data) {
		setup_hist_match(line);
		if (line->history.match) {
			int i;
			for (i = line->history.index - 1; i >= 0; i--) {
				if (match_hist_line(line->history.data[i], line->history.match)) {
					line->history.index = i;
					break;
				}
			}
			if (i < 0) {
				return false;
			}
		} else {
			line->history.index--;
		}
		strncpy(line->buffer.data, line->history.data[line->history.index], RZ_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen(line->buffer.data);
		return true;
	}
	return false;
}

RZ_API int rz_line_hist_cmd_down(RzLine *line) {
	if (line->hist_down) {
		return line->hist_down(line->user);
	}
	if (!line->history.data) {
		inithist();
	}
	setup_hist_match(line);
	if (line->history.match) {
		int i;
		for (i = line->history.index + 1; i < line->history.top; i++) {
			if (match_hist_line(line->history.data[i], line->history.match)) {
				break;
			}
		}
		line->history.index = i;
	} else {
		line->history.index++;
	}
	if (line->history.index >= line->history.top) {
		line->history.index = line->history.top;
		if (line->history.match) {
			strncpy(line->buffer.data, line->history.match, RZ_LINE_BUFSIZE - 1);
		} else {
			line->buffer.data[0] = '\0';
		}
		line->buffer.index = line->buffer.length = strlen(line->buffer.data);
		return false;
	}
	if (line->history.data && line->history.data[line->history.index]) {
		strncpy(line->buffer.data, line->history.data[line->history.index], RZ_LINE_BUFSIZE - 1);
		line->buffer.index = line->buffer.length = strlen(line->buffer.data);
	}
	return true;
}

RZ_API int rz_line_hist_add(const char *line) {
	if (!line || !*line) {
		return false;
	}
	if (!I.history.data) {
		inithist();
	}
	/* ignore dup */
	if (I.history.top > 0) {
		const char *data = I.history.data[I.history.top - 1];
		if (data && !strcmp(line, data)) {
			I.history.index = I.history.top;
			return false;
		}
	}
	if (I.history.top == I.history.size) {
		int i;
		free(I.history.data[0]);
		for (i = 0; i <= I.history.size - 2; i++) {
			I.history.data[i] = I.history.data[i + 1];
		}
		I.history.top--;
	}
	I.history.data[I.history.top++] = strdup(line);
	I.history.index = I.history.top;
	return true;
}

static int rz_line_hist_up(void) {
	if (!I.cb_history_up) {
		rz_line_set_hist_callback(&I, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	return I.cb_history_up(&I);
}

static int rz_line_hist_down(void) {
	if (!I.cb_history_down) {
		rz_line_set_hist_callback(&I, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	return I.cb_history_down(&I);
}

RZ_API const char *rz_line_hist_get(int n) {
	int i = 0;
	if (!I.history.data) {
		inithist();
	}
	n--;
	if (I.history.data) {
		for (i = 0; i < I.history.size && I.history.data[i]; i++) {
			if (n == i) {
				return I.history.data[i];
			}
		}
	}
	return NULL;
}

RZ_API int rz_line_hist_list(void) {
	int i = 0;
	if (!I.history.data) {
		inithist();
	}
	if (I.history.data) {
		for (i = 0; i < I.history.size && I.history.data[i]; i++) {
			// when you execute a command, you always move the history
			// by 1 before actually printing it.
			rz_cons_printf("%5d  %s\n", i + 1, I.history.data[i]);
		}
	}
	return i;
}

RZ_API void rz_line_hist_free(void) {
	int i;
	if (I.history.data) {
		for (i = 0; i < I.history.size; i++) {
			RZ_FREE(I.history.data[i]);
		}
	}
	RZ_FREE(I.history.data);
	RZ_FREE(I.sdbshell_hist);
	I.history.index = 0;
}

/* load history from file. TODO: if file == NULL load from ~/.<prg>.history or so */
RZ_API int rz_line_hist_load(const char *file) {
	FILE *fd;
	char buf[RZ_LINE_BUFSIZE], *path = rz_str_home(file);
	if (!path) {
		return false;
	}
	if (!(fd = rz_sys_fopen(path, "r"))) {
		free(path);
		return false;
	}
	while (fgets(buf, sizeof(buf), fd) != NULL) {
		rz_str_trim_tail(buf);
		rz_line_hist_add(buf);
	}
	fclose(fd);
	free(path);
	return true;
}

RZ_API int rz_line_hist_save(const char *file) {
	FILE *fd;
	int i, ret = false;
	if (!file || !*file) {
		return false;
	}
	char *p, *path = rz_str_home(file);
	if (path != NULL) {
		p = (char *)rz_str_lastbut(path, RZ_SYS_DIR[0], NULL); // TODO: use fs
		if (p) {
			*p = 0;
			if (!rz_sys_mkdirp(path)) {
				eprintf("could not save history into %s\n", path);
				goto end;
			}
			*p = RZ_SYS_DIR[0];
		}
		fd = rz_sys_fopen(path, "w");
		if (fd != NULL) {
			if (I.history.data) {
				for (i = 0; i < I.history.index; i++) {
					fputs(I.history.data[i], fd);
					fputs("\n", fd);
				}
				fclose(fd);
				ret = true;
			} else {
				fclose(fd);
			}
		}
	}
end:
	free(path);
	return ret;
}

RZ_API int rz_line_hist_chop(const char *file, int limit) {
	/* TODO */
	return 0;
}

static void selection_widget_draw(void) {
	RzCons *cons = rz_cons_singleton();
	RzSelWidget *sel_widget = I.sel_widget;
	int y, pos_y, pos_x = rz_str_ansi_len(I.prompt);
	sel_widget->h = RZ_MIN(sel_widget->h, RZ_SELWIDGET_MAXH);
	for (y = 0; y < sel_widget->options_len; y++) {
		sel_widget->w = RZ_MAX(sel_widget->w, strlen(sel_widget->options[y]));
	}
	if (sel_widget->direction == RZ_SELWIDGET_DIR_UP) {
		pos_y = cons->rows;
	} else {
		pos_y = rz_cons_get_cur_line();
		if (pos_y + sel_widget->h > cons->rows) {
			printf("%s\n", rz_str_pad('\n', sel_widget->h));
			pos_y = cons->rows - sel_widget->h - 1;
		}
	}
	sel_widget->w = RZ_MIN(sel_widget->w, RZ_SELWIDGET_MAXW);

	char *background_color = cons->context->color_mode ? cons->context->pal.widget_bg : Color_INVERT_RESET;
	char *selected_color = cons->context->color_mode ? cons->context->pal.widget_sel : Color_INVERT;
	bool scrollbar = sel_widget->options_len > RZ_SELWIDGET_MAXH;
	int scrollbar_y = 0, scrollbar_l = 0;
	if (scrollbar) {
		scrollbar_y = (RZ_SELWIDGET_MAXH * (sel_widget->selection - sel_widget->scroll)) / sel_widget->options_len;
		scrollbar_l = (RZ_SELWIDGET_MAXH * RZ_SELWIDGET_MAXH) / sel_widget->options_len;
	}

	for (y = 0; y < sel_widget->h; y++) {
		if (sel_widget->direction == RZ_SELWIDGET_DIR_UP) {
			rz_cons_gotoxy(pos_x + 1, pos_y - y - 1);
		} else {
			rz_cons_gotoxy(pos_x + 1, pos_y + y + 1);
		}
		int scroll = RZ_MAX(0, sel_widget->selection - sel_widget->scroll);
		const char *option = y < sel_widget->options_len ? sel_widget->options[y + scroll] : "";
		rz_cons_printf("%s", sel_widget->selection == y + scroll ? selected_color : background_color);
		rz_cons_printf("%-*.*s", sel_widget->w, sel_widget->w, option);
		if (scrollbar && RZ_BETWEEN(scrollbar_y, y, scrollbar_y + scrollbar_l)) {
			rz_cons_memcat(Color_INVERT " " Color_INVERT_RESET, 10);
		} else {
			rz_cons_memcat(" ", 1);
		}
	}

	rz_cons_gotoxy(pos_x + I.buffer.length, pos_y);
	rz_cons_memcat(Color_RESET_BG, 5);
	rz_cons_flush();
}

static void selection_widget_up(int steps) {
	RzSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		if (sel_widget->direction == RZ_SELWIDGET_DIR_UP) {
			int height = RZ_MIN(sel_widget->h, RZ_SELWIDGET_MAXH - 1);
			sel_widget->selection = RZ_MIN(sel_widget->selection + steps, sel_widget->options_len - 1);
			if (steps == 1) {
				sel_widget->scroll = RZ_MIN(sel_widget->scroll + 1, RZ_SELWIDGET_MAXH - 1);
			} else if (sel_widget->selection + (height - sel_widget->scroll) > sel_widget->options_len - 1) {
				sel_widget->scroll = height - (sel_widget->options_len - 1 - sel_widget->selection);
			}
		} else {
			sel_widget->selection = RZ_MAX(sel_widget->selection - steps, 0);
			if (steps == 1) {
				sel_widget->scroll = RZ_MAX(sel_widget->scroll - 1, 0);
			} else if (sel_widget->selection - sel_widget->scroll <= 0) {
				sel_widget->scroll = sel_widget->selection;
			}
		}
	}
}

static void selection_widget_down(int steps) {
	RzSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		if (sel_widget->direction == RZ_SELWIDGET_DIR_UP) {
			sel_widget->selection = RZ_MAX(sel_widget->selection - steps, 0);
			if (steps == 1) {
				sel_widget->scroll = RZ_MAX(sel_widget->scroll - 1, 0);
			} else if (sel_widget->selection - sel_widget->scroll <= 0) {
				sel_widget->scroll = sel_widget->selection;
			}
		} else {
			int height = RZ_MIN(sel_widget->h, RZ_SELWIDGET_MAXH - 1);
			sel_widget->selection = RZ_MIN(sel_widget->selection + steps, sel_widget->options_len - 1);
			if (steps == 1) {
				sel_widget->scroll = RZ_MIN(sel_widget->scroll + 1, RZ_SELWIDGET_MAXH - 1);
			} else if (sel_widget->selection + (height - sel_widget->scroll) > sel_widget->options_len - 1) {
				sel_widget->scroll = height - (sel_widget->options_len - 1 - sel_widget->selection);
			}
		}
	}
}

static void print_rline_task(void *_core) {
	RzCore *core = (RzCore *)_core;
	if (core->cons->context->color_mode) {
		rz_cons_clear_line(0);
	}
	rz_cons_printf("%s%s%s", Color_RESET, I.prompt, I.buffer.data);
	rz_cons_flush();
}

static void selection_widget_erase(void) {
	RzSelWidget *sel_widget = I.sel_widget;
	if (sel_widget) {
		sel_widget->options_len = 0;
		sel_widget->selection = -1;
		selection_widget_draw();
		RZ_FREE(I.sel_widget);
		RzCons *cons = rz_cons_singleton();
		if (cons->event_resize && cons->event_data) {
			cons->event_resize(cons->event_data);
			RzCore *core = (RzCore *)(cons->user);
			if (core) {
				cons->cb_task_oneshot(&core->tasks, print_rline_task, core);
			}
		}
		printf("%s", RZ_CONS_CLEAR_FROM_CURSOR_TO_END);
	}
}

static void selection_widget_select(void) {
	RzSelWidget *sel_widget = I.sel_widget;
	if (sel_widget && sel_widget->selection < sel_widget->options_len) {
		char *sp = strchr(I.buffer.data, ' ');
		if (sp) {
			int delta = sp - I.buffer.data + 1;
			I.buffer.length = RZ_MIN(delta + strlen(sel_widget->options[sel_widget->selection]), RZ_LINE_BUFSIZE - 1);
			memcpy(I.buffer.data + delta, sel_widget->options[sel_widget->selection], strlen(sel_widget->options[sel_widget->selection]));
			I.buffer.index = I.buffer.length;
			return;
		}
		I.buffer.length = RZ_MIN(strlen(sel_widget->options[sel_widget->selection]), RZ_LINE_BUFSIZE - 1);
		memcpy(I.buffer.data, sel_widget->options[sel_widget->selection], I.buffer.length);
		I.buffer.data[I.buffer.length] = '\0';
		I.buffer.index = I.buffer.length;
		selection_widget_erase();
	}
}

static void selection_widget_update(void) {
	int argc = rz_pvector_len(&I.completion.args);
	const char **argv = (const char **)rz_pvector_data(&I.completion.args);
	if (argc == 0 || (argc == 1 && I.buffer.length >= strlen(argv[0]))) {
		selection_widget_erase();
		return;
	}
	if (!I.sel_widget) {
		RzSelWidget *sel_widget = RZ_NEW0(RzSelWidget);
		I.sel_widget = sel_widget;
	}
	I.sel_widget->scroll = 0;
	I.sel_widget->selection = 0;
	I.sel_widget->options_len = argc;
	I.sel_widget->options = argv;
	I.sel_widget->h = RZ_MAX(I.sel_widget->h, I.sel_widget->options_len);

	if (I.prompt_type == RZ_LINE_PROMPT_DEFAULT) {
		I.sel_widget->direction = RZ_SELWIDGET_DIR_DOWN;
	} else {
		I.sel_widget->direction = RZ_SELWIDGET_DIR_UP;
	}
	selection_widget_draw();
	rz_cons_flush();
	return;
}

static bool is_valid_buffer_limits(RzLineBuffer *buf, size_t start, size_t end, size_t s_len) {
	if (start > end || s_len < end - start) {
		return false;
	}
	if (start > buf->length || start + s_len >= RZ_LINE_BUFSIZE - 1) {
		return false;
	}
	if (end > buf->length || end + s_len >= RZ_LINE_BUFSIZE - 1) {
		return false;
	}
	return true;
}

static void replace_buffer_text(RzLineBuffer *buf, size_t start, size_t end, const char *s) {
	size_t s_len = strlen(s);
	if (!is_valid_buffer_limits(buf, start, end, s_len)) {
		return;
	}

	size_t diff = end - start;
	// FIXME: escape s
	memmove(buf->data + start + s_len, buf->data + end, buf->length - end);
	memmove(buf->data + start, s, s_len);
	buf->length += s_len - diff;
	buf->index += s_len - diff;
	buf->data[buf->length] = '\0';
}

static char *get_max_common_pfx(RzPVector *options) {
	const char *ref = rz_pvector_at(options, 0);
	size_t min_common_len = strlen(ref);
	void **it;
	bool first = true;
	rz_pvector_foreach (options, it) {
		if (first) {
			first = false;
			continue;
		}
		char *s = *(char **)it;
		size_t j;
		for (j = 0; s[j] && ref[j] && s[j] == ref[j]; j++)
			;
		if (j < min_common_len) {
			min_common_len = j;
		}
	}
	return rz_str_ndup(ref, min_common_len);
}

static void print_options(int argc, const char **argv) {
	int cols = (int)(rz_cons_get_size(NULL) * 0.82);
	size_t i, len;
	const int sep = 3;
	int slen, col = 10;

	for (i = 0; i < argc && argv[i]; i++) {
		int l = strlen(argv[i]);
		if (sep + l > col) {
			col = sep + l;
		}
		if (col > (cols >> 1)) {
			col = (cols >> 1);
			break;
		}
	}
	for (len = i = 0; i < argc && argv[i]; i++) {
		if (len + col > cols) {
			rz_cons_printf("\n");
			len = 0;
		}
		rz_cons_printf("%-*s   ", col - sep, argv[i]);
		slen = strlen(argv[i]);
		len += (slen > col) ? (slen + sep) : (col + sep);
	}
	rz_cons_printf("\n");
}

RZ_API void rz_line_autocomplete(void) {
	char *p;
	const char **argv = NULL;
	int argc = 0, i, j, plen;
	bool opt = false;
	RzCons *cons = rz_cons_singleton();

	if (I.ns_completion.run) {
		RzLineNSCompletionResult *res = I.ns_completion.run(&I.buffer, I.prompt_type, I.ns_completion.run_user);
		if (!res || rz_pvector_empty(&res->options)) {
			// do nothing
		} else if (rz_pvector_len(&res->options) == 1) {
			// if there is just one option, just use it
			bool is_at_end = I.buffer.length == I.buffer.index;
			replace_buffer_text(&I.buffer, res->start, res->end, rz_pvector_at(&res->options, 0));
			if (is_at_end && res->end_string) {
				replace_buffer_text(&I.buffer, I.buffer.length, I.buffer.length, res->end_string);
			}
		} else {
			// otherwise find maxcommonprefix, print it, and then print options
			char *max_common_pfx = get_max_common_pfx(&res->options);
			replace_buffer_text(&I.buffer, res->start, res->end, max_common_pfx);
			free(max_common_pfx);

			rz_cons_printf("%s%s\n", I.prompt, I.buffer.data);
			print_options(rz_pvector_len(&res->options), (const char **)rz_pvector_data(&res->options));
		}

		rz_line_ns_completion_result_free(res);
		return;
	}

	/* prepare argc and argv */
	if (I.completion.run) {
		I.completion.opt = false;
		I.completion.run(&I.completion, &I.buffer, I.prompt_type, I.completion.run_user);
		argc = rz_pvector_len(&I.completion.args);
		argv = (const char **)rz_pvector_data(&I.completion.args);
		opt = I.completion.opt;
	}
	if (I.sel_widget && !I.sel_widget->complete_common) {
		selection_widget_update();
		return;
	}

	if (opt) {
		p = (char *)rz_sub_str_lchr(I.buffer.data, 0, I.buffer.index, '=');
	} else {
		p = (char *)rz_sub_str_lchr(I.buffer.data, 0, I.buffer.index, ' ');
	}
	if (!p) {
		p = (char *)rz_sub_str_lchr(I.buffer.data, 0, I.buffer.index, '@'); // HACK FOR r2
	}
	if (p) {
		p++;
		plen = sizeof(I.buffer.data) - (int)(size_t)(p - I.buffer.data);
	} else {
		p = I.buffer.data; // XXX: removes current buffer
		plen = sizeof(I.buffer.data);
	}
	/* autocomplete */
	if (argc == 1) {
		const char *end_word = rz_sub_str_rchr(I.buffer.data,
			I.buffer.index, strlen(I.buffer.data), ' ');
		const char *t = end_word != NULL ? end_word : I.buffer.data + I.buffer.index;
		int largv0 = strlen(argv[0] ? argv[0] : "");
		size_t len_t = strlen(t);
		p[largv0] = '\0';

		if ((p - I.buffer.data) + largv0 + 1 + len_t < plen) {
			if (len_t > 0) {
				int tt = largv0;
				if (*t != ' ') {
					p[tt++] = ' ';
				}
				memmove(p + tt, t, len_t);
			}
			memcpy(p, argv[0], largv0);

			if (p[largv0 - 1] != RZ_SYS_DIR[0]) {
				p[largv0] = ' ';
				if (!len_t) {
					p[largv0 + 1] = '\0';
				}
			}
			I.buffer.length = strlen(I.buffer.data);
			I.buffer.index = I.buffer.length;
		}
	} else if (argc > 0) {
		if (*p) {
			// TODO: avoid overflow
			const char *t = I.buffer.data + I.buffer.index;
			const char *root = argv[0];
			int min_common_len = strlen(root);
			size_t len_t = strlen(t);

			// try to autocomplete argument
			for (i = 0; i < argc; i++) {
				j = 0;
				if (!argv[i]) {
					break;
				}
				while (argv[i][j] == root[j] && root[j] != '\0')
					j++;
				if (j < min_common_len) {
					min_common_len = j;
				}
				root = argv[i];
			}
			if (len_t > 0) {
				int tt = min_common_len;
				memmove(p + tt, t, len_t);
				p[tt + len_t] = '\0';
			}
			memmove(p, root, min_common_len);
			if (!len_t) {
				p[min_common_len] = '\0';
			}
			I.buffer.length = strlen(I.buffer.data);
			I.buffer.index = (p - I.buffer.data) + min_common_len;
		}
	}

	if (I.prompt_type != RZ_LINE_PROMPT_DEFAULT || cons->show_autocomplete_widget) {
		selection_widget_update();
		if (I.sel_widget) {
			I.sel_widget->complete_common = false;
		}
		return;
	}

	/* show options */
	if (argc > 1 && I.echo) {
		rz_cons_printf("%s%s\n", I.prompt, I.buffer.data);
		print_options(argc, argv);
	}
}

RZ_API const char *rz_line_readline(void) {
	return rz_line_readline_cb(NULL, NULL);
}

static inline void rotate_kill_ring(void) {
	if (enable_yank_pop) {
		I.buffer.index -= strlen(rz_list_get_n(I.kill_ring, I.kill_ring_ptr));
		I.buffer.data[I.buffer.index] = 0;
		I.kill_ring_ptr -= 1;
		if (I.kill_ring_ptr < 0) {
			I.kill_ring_ptr = I.kill_ring->length - 1;
		}
		I.clipboard = rz_list_get_n(I.kill_ring, I.kill_ring_ptr);
		paste();
	}
}

static inline void __delete_next_char(void) {
	if (I.buffer.index < I.buffer.length) {
		int len = rz_str_utf8_charsize(I.buffer.data + I.buffer.index);
		memmove(I.buffer.data + I.buffer.index,
			I.buffer.data + I.buffer.index + len,
			strlen(I.buffer.data + I.buffer.index + 1) + 1);
		I.buffer.length -= len;
	}
}

static inline void __delete_prev_char(void) {
	if (I.buffer.index < I.buffer.length) {
		if (I.buffer.index > 0) {
			size_t len = rz_str_utf8_charsize_prev(I.buffer.data + I.buffer.index, I.buffer.index);
			I.buffer.index -= len;
			memmove(I.buffer.data + I.buffer.index,
				I.buffer.data + I.buffer.index + len,
				strlen(I.buffer.data + I.buffer.index));
			I.buffer.length -= len;
		}
	} else {
		I.buffer.length -= rz_str_utf8_charsize_last(I.buffer.data);
		I.buffer.index = I.buffer.length;
		if (I.buffer.length < 0) {
			I.buffer.length = 0;
		}
	}
	I.buffer.data[I.buffer.length] = '\0';
	if (I.buffer.index < 0) {
		I.buffer.index = 0;
	}
}

static inline void delete_till_end(void) {
	I.buffer.data[I.buffer.index] = '\0';
	I.buffer.length = I.buffer.index;
	I.buffer.index = I.buffer.index > 0 ? I.buffer.index - 1 : 0;
}

static void __print_prompt(void) {
	RzCons *cons = rz_cons_singleton();
	int columns = rz_cons_get_size(NULL) - 2;
	int chars = RZ_MAX(1, strlen(I.buffer.data));
	int len, i, cols = RZ_MAX(1, columns - rz_str_ansi_len(I.prompt) - 2);
	if (cons->line->prompt_type == RZ_LINE_PROMPT_OFFSET) {
		rz_cons_gotoxy(0, cons->rows);
		rz_cons_flush();
	}
	if (cons->context->color_mode > 0) {
		rz_cons_clear_line(0);
		printf("\r%s%s", Color_RESET, I.prompt);
	} else {
		printf("\r%s", I.prompt);
	}
	fwrite(I.buffer.data, 1, RZ_MIN(cols, chars), stdout);
	printf("\r%s", I.prompt);
	if (I.buffer.index > cols) {
		printf("< ");
		i = I.buffer.index - cols;
		if (i > sizeof(I.buffer.data)) {
			i = sizeof(I.buffer.data) - 1;
		}
	} else {
		i = 0;
	}
	len = I.buffer.index - i;
	if (len > 0 && (i + len) <= I.buffer.length) {
		fwrite(I.buffer.data + i, 1, len, stdout);
	}
	fflush(stdout);
}

static inline void __move_cursor_right(void) {
	I.buffer.index = I.buffer.index < I.buffer.length
		? I.buffer.index + rz_str_utf8_charsize(I.buffer.data + I.buffer.index)
		: I.buffer.length;
}

static inline void __move_cursor_left(void) {
	I.buffer.index = I.buffer.index
		? I.buffer.index - rz_str_utf8_charsize_prev(I.buffer.data + I.buffer.index, I.buffer.index)
		: 0;
}

static inline void vi_cmd_b(void) {
	int i;
	for (i = I.buffer.index - 2; i >= 0; i--) {
		if ((is_word_break_char(I.buffer.data[i], MINOR_BREAK) && !is_word_break_char(I.buffer.data[i], MAJOR_BREAK)) || (is_word_break_char(I.buffer.data[i - 1], MINOR_BREAK) && !is_word_break_char(I.buffer.data[i], MINOR_BREAK))) {
			I.buffer.index = i;
			break;
		}
	}
	if (i < 0) {
		I.buffer.index = 0;
	}
}

static inline void vi_cmd_B(void) {
	int i;
	for (i = I.buffer.index - 2; i >= 0; i--) {
		if ((!is_word_break_char(I.buffer.data[i], MAJOR_BREAK) && is_word_break_char(I.buffer.data[i - 1], MAJOR_BREAK))) {
			I.buffer.index = i;
			break;
		}
	}
	if (i < 0) {
		I.buffer.index = 0;
	}
}

static inline void vi_cmd_W(void) {
	int i;
	for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
		if ((!is_word_break_char(I.buffer.data[i], MAJOR_BREAK) && is_word_break_char(I.buffer.data[i - 1], MAJOR_BREAK))) {
			I.buffer.index = i;
			break;
		}
	}
	if (i >= I.buffer.length) {
		I.buffer.index = I.buffer.length - 1;
	}
}

static inline void vi_cmd_w(void) {
	int i;
	for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
		if ((!is_word_break_char(I.buffer.data[i], MINOR_BREAK) && is_word_break_char(I.buffer.data[i - 1], MINOR_BREAK)) || (is_word_break_char(I.buffer.data[i], MINOR_BREAK) && !is_word_break_char(I.buffer.data[i], MAJOR_BREAK))) {
			I.buffer.index = i;
			break;
		}
	}
	if (i >= I.buffer.length) {
		I.buffer.index = I.buffer.length - 1;
	}
}

static inline void vi_cmd_E(void) {
	int i;
	for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
		if ((!is_word_break_char(I.buffer.data[i], MAJOR_BREAK) && is_word_break_char(I.buffer.data[i + 1], MAJOR_BREAK))) {
			I.buffer.index = i;
			break;
		}
	}
	if (i >= I.buffer.length) {
		I.buffer.index = I.buffer.length - 1;
	}
}

static inline void vi_cmd_e(void) {
	int i;
	for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
		if ((!is_word_break_char(I.buffer.data[i], MINOR_BREAK) && is_word_break_char(I.buffer.data[i + 1], MINOR_BREAK)) || (is_word_break_char(I.buffer.data[i], MINOR_BREAK) && !is_word_break_char(I.buffer.data[i], MAJOR_BREAK))) {
			I.buffer.index = i;
			break;
		}
	}
	if (i >= I.buffer.length) {
		I.buffer.index = I.buffer.length - 1;
	}
}

static void __update_prompt_color(void) {
	RzCons *cons = rz_cons_singleton();
	const char *BEGIN = "", *END = "";
	if (cons->context->color_mode) {
		if (I.prompt_mode) {
			switch (I.vi_mode) {
			case CONTROL_MODE:
				BEGIN = cons->context->pal.invalid;
				break;
			case INSERT_MODE:
			default:
				BEGIN = cons->context->pal.prompt;
				break;
			}
		} else {
			BEGIN = cons->context->pal.prompt;
		}
		END = cons->context->pal.reset;
	}
	char *prompt = rz_str_escape(I.prompt); // remote the color
	free(I.prompt);
	I.prompt = rz_str_newf("%s%s%s", BEGIN, prompt, END);
}

static void __vi_mode(void) {
	char ch;
	I.vi_mode = CONTROL_MODE;
	__update_prompt_color();
	const char *gcomp_line = "";
	static int gcomp = 0;
	for (;;) {
		int rep = 0;
		if (I.echo) {
			__print_prompt();
		}
		if (I.vi_mode != CONTROL_MODE) { // exit if insert mode is selected
			__update_prompt_color();
			break;
		}
		bool o_do_setup_match = I.history.do_setup_match;
		I.history.do_setup_match = true;
		ch = rz_cons_readchar();
		while (IS_DIGIT(ch)) { // handle commands like 3b
			if (ch == '0' && rep == 0) { // to handle the command 0
				break;
			}
			int tmp = ch - '0';
			rep = (rep * 10) + tmp;
			ch = rz_cons_readchar();
		}
		rep = rep > 0 ? rep : 1;

		switch (ch) {
		case 3:
			if (I.hud) {
				I.hud->activate = false;
				I.hud->current_entry_n = -1;
			}
			if (I.echo) {
				eprintf("^C\n");
			}
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			gcomp = 0;
			return;
		case 'D':
			delete_till_end();
			break;
		case 'r': {
			char c = rz_cons_readchar();
			I.buffer.data[I.buffer.index] = c;
		} break;
		case 'x':
			while (rep--) {
				__delete_next_char();
			}
			break;
		case 'c':
			I.vi_mode = INSERT_MODE; // goto insert mode
			/* fall through */
		case 'd': {
			char c = rz_cons_readchar();
			while (rep--) {
				switch (c) {
				case 'i': {
					char t = rz_cons_readchar();
					if (t == 'w') { // diw
						kill_word(MINOR_BREAK);
						backward_kill_word(MINOR_BREAK);
					} else if (t == 'W') { // diW
						kill_word(MAJOR_BREAK);
						backward_kill_word(MINOR_BREAK);
					}
					if (I.hud) {
						I.hud->vi = false;
					}
				} break;
				case 'W':
					kill_word(MAJOR_BREAK);
					break;
				case 'w':
					kill_word(MINOR_BREAK);
					break;
				case 'B':
					backward_kill_word(MAJOR_BREAK);
					break;
				case 'b':
					backward_kill_word(MINOR_BREAK);
					break;
				case 'h':
					__delete_prev_char();
					break;
				case 'l':
					__delete_next_char();
					break;
				case '$':
					delete_till_end();
					break;
				case '^':
				case '0':
					strncpy(I.buffer.data, I.buffer.data + I.buffer.index, I.buffer.length);
					I.buffer.length -= I.buffer.index;
					I.buffer.index = 0;
					break;
				}
				__print_prompt();
			}
		} break;
		case 'I':
			if (I.hud) {
				I.hud->vi = false;
			}
			I.vi_mode = INSERT_MODE;
			/* fall through */
		case '^':
		case '0':
			if (gcomp) {
				strcpy(I.buffer.data, gcomp_line);
				I.buffer.length = strlen(I.buffer.data);
				I.buffer.index = 0;
				gcomp = false;
			}
			I.buffer.index = 0;
			break;
		case 'A':
			I.vi_mode = INSERT_MODE;
			/* fall through */
		case '$':
			if (gcomp) {
				strcpy(I.buffer.data, gcomp_line);
				I.buffer.index = strlen(I.buffer.data);
				I.buffer.length = I.buffer.index;
				gcomp = false;
			} else {
				I.buffer.index = I.buffer.length;
			}
			break;
		case 'p':
			while (rep--) {
				paste();
			}
			break;
		case 'a':
			__move_cursor_right();
			/* fall through */
		case 'i':
			I.vi_mode = INSERT_MODE;
			if (I.hud) {
				I.hud->vi = false;
			}
			break;
		case 'h':
			while (rep--) {
				__move_cursor_left();
			}
			break;
		case 'l':
			while (rep--) {
				__move_cursor_right();
			}
			break;
		case 'E':
			while (rep--) {
				vi_cmd_E();
			}
			break;
		case 'e':
			while (rep--) {
				vi_cmd_e();
			}
			break;
		case 'B':
			while (rep--) {
				vi_cmd_B();
			}
			break;
		case 'b':
			while (rep--) {
				vi_cmd_b();
			}
			break;
		case 'W':
			while (rep--) {
				vi_cmd_W();
			}
			break;
		case 'w':
			while (rep--) {
				vi_cmd_w();
			}
			break;
		default: // escape key
			ch = tolower(rz_cons_arrow_to_hjkl(ch));
			switch (ch) {
			case 'k': // up
				I.history.do_setup_match = o_do_setup_match;
				rz_line_hist_up();
				break;
			case 'j': // down
				I.history.do_setup_match = o_do_setup_match;
				rz_line_hist_down();
				break;
			case 'l': // right
				__move_cursor_right();
				break;
			case 'h': // left
				__move_cursor_left();
				break;
			}
			break;
		}
		if (I.hud) {
			return;
		}
	}
}

RZ_API const char *rz_line_readline_cb(RzLineReadCallback cb, void *user) {
	int rows;
	const char *gcomp_line = "";
	static int gcomp_idx = 0;
	static bool yank_flag = 0;
	static int gcomp = 0;
	char buf[10];
#if USE_UTF8
	int utflen;
#endif
	int ch = 0, key, i = 0; /* grep completion */
	char *tmp_ed_cmd, prev = 0;
	int prev_buflen = -1;
	RzCons *cons = rz_cons_singleton();

	if (!I.hud || (I.hud && !I.hud->activate)) {
		I.buffer.index = I.buffer.length = 0;
		I.buffer.data[0] = '\0';
		if (I.hud) {
			I.hud->activate = true;
		}
	}
	int mouse_status = cons->mouse;
	if (I.hud && I.hud->vi) {
		__vi_mode();
		goto _end;
	}
	if (I.contents) {
		memmove(I.buffer.data, I.contents,
			RZ_MIN(strlen(I.contents) + 1, RZ_LINE_BUFSIZE - 1));
		I.buffer.data[RZ_LINE_BUFSIZE - 1] = '\0';
		I.buffer.index = I.buffer.length = strlen(I.contents);
	}
	if (I.disable) {
		if (!fgets(I.buffer.data, RZ_LINE_BUFSIZE, stdin)) {
			return NULL;
		}
		return (*I.buffer.data) ? I.buffer.data : rz_line_nullstr;
	}

	memset(&buf, 0, sizeof buf);
	rz_cons_set_raw(1);

	if (I.echo) {
		__print_prompt();
	}
	rz_cons_break_push(NULL, NULL);
	rz_cons_enable_mouse(I.hud);
	for (;;) {
		yank_flag = 0;
		if (rz_cons_is_breaked()) {
			break;
		}
		I.buffer.data[I.buffer.length] = '\0';
		if (cb) {
			int cbret = cb(user, I.buffer.data);
			if (cbret == 0) {
				I.buffer.data[0] = 0;
				I.buffer.length = 0;
			}
		}
#if USE_UTF8
		utflen = rz_line_readchar_utf8((ut8 *)buf, sizeof(buf));
		if (utflen < 1) {
			rz_cons_break_pop();
			return NULL;
		}
		buf[utflen] = 0;
#else
#if __WINDOWS__
		{
			int len = rz_line_readchar_win((ut8 *)buf, sizeof(buf));
			if (len < 1) {
				rz_cons_break_pop();
				return NULL;
			}
			buf[len] = 0;
		}
#else
		ch = rz_cons_readchar();
		if (ch == -1) {
			rz_cons_break_pop();
			return NULL;
		}
		buf[0] = ch;
#endif
#endif
		bool o_do_setup_match = I.history.do_setup_match;
		I.history.do_setup_match = true;
		if (I.echo && cons->context->color_mode) {
			rz_cons_clear_line(0);
		}
		(void)rz_cons_get_size(&rows);
		switch (*buf) {
		case 0: // control-space
			/* ignore atm */
			break;
		case 1: // ^A
			if (gcomp) {
				strcpy(I.buffer.data, gcomp_line);
				I.buffer.length = strlen(I.buffer.data);
				I.buffer.index = 0;
				gcomp = false;
			}
			I.buffer.index = 0;
			break;
		case 2: // ^b // emacs left
			__move_cursor_left();
			break;
		case 5: // ^E
			if (gcomp) {
				strcpy(I.buffer.data, gcomp_line);
				I.buffer.index = strlen(I.buffer.data);
				I.buffer.length = I.buffer.index;
				gcomp = false;
			} else if (prev == 24) { // ^X = 0x18
				I.buffer.data[I.buffer.length] = 0; // probably unnecessary
				tmp_ed_cmd = I.cb_editor(I.user, I.buffer.data);
				if (tmp_ed_cmd) {
					/* copied from yank (case 25) */
					I.buffer.length = strlen(tmp_ed_cmd);
					if (I.buffer.length < RZ_LINE_BUFSIZE) {
						I.buffer.index = I.buffer.length;
						strncpy(I.buffer.data, tmp_ed_cmd, RZ_LINE_BUFSIZE - 1);
						I.buffer.data[RZ_LINE_BUFSIZE - 1] = '\0';
					} else {
						I.buffer.length -= strlen(tmp_ed_cmd);
					}
					free(tmp_ed_cmd);
				}
			} else {
				I.buffer.index = I.buffer.length;
			}
			break;
		case 3: // ^C
			if (I.hud) {
				I.hud->activate = false;
				I.hud->current_entry_n = -1;
			}
			if (I.echo) {
				eprintf("^C\n");
			}
			I.buffer.index = I.buffer.length = 0;
			*I.buffer.data = '\0';
			gcomp = 0;
			goto _end;
		case 4: // ^D
			if (!I.buffer.data[0]) { /* eof */
				if (I.echo) {
					printf("^D\n");
				}
				rz_cons_set_raw(false);
				rz_cons_break_pop();
				return NULL;
			}
			if (I.buffer.index < I.buffer.length) {
				__delete_next_char();
			}
			break;
		case 11: // ^K
			I.buffer.data[I.buffer.index] = '\0';
			I.buffer.length = I.buffer.index;
			break;
		case 6: // ^f // emacs right
			__move_cursor_right();
			break;
		case 12: // ^L -- right
			__move_cursor_right();
			if (I.echo) {
				eprintf("\x1b[2J\x1b[0;0H");
			}
			fflush(stdout);
			break;
		case 18: // ^R -- autocompletion
			if (gcomp) {
				gcomp_idx++;
			}
			gcomp = 1;
			break;
		case 19: // ^S -- backspace
			if (gcomp) {
				gcomp--;
			} else {
				__move_cursor_left();
			}
			break;
		case 21: // ^U - cut
			free(I.clipboard);
			I.clipboard = strdup(I.buffer.data);
			rz_line_clipboard_push(I.clipboard);
			I.buffer.data[0] = '\0';
			I.buffer.length = 0;
			I.buffer.index = 0;
			break;
#if __WINDOWS__
		case 22: // ^V - Paste from windows clipboard
		{
			HANDLE hClipBoard;
			PTCHAR clipText;
			if (OpenClipboard(NULL)) {
#if UNICODE
				hClipBoard = GetClipboardData(CF_UNICODETEXT);
#else
				hClipBoard = GetClipboardData(CF_TEXT);
#endif
				if (hClipBoard) {
					clipText = GlobalLock(hClipBoard);
					if (clipText) {
						char *txt = rz_sys_conv_win_to_utf8(clipText);
						if (!txt) {
							RZ_LOG_ERROR("Failed to allocate memory\n");
							break;
						}
						int len = strlen(txt);
						I.buffer.length += len;
						if (I.buffer.length < RZ_LINE_BUFSIZE) {
							I.buffer.index = I.buffer.length;
							strcat(I.buffer.data, txt);
						} else {
							I.buffer.length -= len;
						}
						free(txt);
					}
					GlobalUnlock(hClipBoard);
				}
				CloseClipboard();
			}
		} break;
#endif
		case 23: // ^W ^w unix-word-rubout
			unix_word_rubout();
			break;
		case 24: // ^X
			if (I.buffer.index > 0) {
				strncpy(I.buffer.data, I.buffer.data + I.buffer.index, I.buffer.length);
				I.buffer.length -= I.buffer.index;
				I.buffer.index = 0;
			}
			break;
		case 25: // ^Y - paste
			paste();
			yank_flag = 1;
			break;
		case 29: // ^^ - rotate kill ring
			rotate_kill_ring();
			yank_flag = enable_yank_pop ? 1 : 0;
			break;
		case 20: // ^t Kill from point to the end of the current word,
			kill_word(MINOR_BREAK);
			break;
		case 15: // ^o kill backward
			backward_kill_word(MINOR_BREAK);
			break;
		case 14: // ^n
			if (I.hud) {
				if (I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
					I.hud->top_entry_n++;
				}
			} else if (I.sel_widget) {
				selection_widget_down(1);
				selection_widget_draw();
			} else if (gcomp) {
				if (gcomp_idx > 0) {
					gcomp_idx--;
				}
			} else {
				I.history.do_setup_match = o_do_setup_match;
				rz_line_hist_down();
			}
			break;
		case 16: // ^p
			if (I.hud) {
				if (I.hud->top_entry_n >= 0) {
					I.hud->top_entry_n--;
				}
			} else if (I.sel_widget) {
				selection_widget_up(1);
				selection_widget_draw();
			} else if (gcomp) {
				gcomp_idx++;
			} else {
				I.history.do_setup_match = o_do_setup_match;
				rz_line_hist_up();
			}
			break;
		case 27: // esc-5b-41-00-00 alt/meta key
#if __WINDOWS__
			if (I.vtmode != 2) {
				memmove(buf, buf + 1, strlen(buf));
				if (!buf[0]) {
					buf[0] = -1;
				}
			} else {
#endif
				buf[0] = rz_cons_readchar_timeout(50);
#if __WINDOWS__
			}
#endif
			switch (buf[0]) {
			case 127: // alt+bkspace
				backward_kill_word(MINOR_BREAK);
				break;
			case -1: // escape key, goto vi mode
				if (I.enable_vi_mode) {
					if (I.hud) {
						I.hud->vi = true;
					}
					__vi_mode();
				};
				if (I.sel_widget) {
					selection_widget_erase();
				}
				break;
			case 1: // begin
				I.buffer.index = 0;
				break;
			case 5: // end
				I.buffer.index = I.buffer.length;
				break;
			case 'B':
			case 'b':
				for (i = I.buffer.index - 2; i >= 0; i--) {
					if (is_word_break_char(I.buffer.data[i], MINOR_BREAK) && !is_word_break_char(I.buffer.data[i + 1], MINOR_BREAK)) {
						I.buffer.index = i + 1;
						break;
					}
				}
				if (i < 0) {
					I.buffer.index = 0;
				}
				break;
			case 'D':
			case 'd':
				kill_word(MINOR_BREAK);
				break;
			case 'F':
			case 'f':
				// next word
				for (i = I.buffer.index + 1; i < I.buffer.length; i++) {
					if (!is_word_break_char(I.buffer.data[i], MINOR_BREAK) && is_word_break_char(I.buffer.data[i - 1], MINOR_BREAK)) {
						I.buffer.index = i;
						break;
					}
				}
				if (i >= I.buffer.length) {
					I.buffer.index = I.buffer.length;
				}
				break;
			default:
				if (I.vtmode == 2) {
					buf[1] = rz_cons_readchar_timeout(50);
					if (buf[1] == -1) { // alt+e
						rz_cons_break_pop();
						__print_prompt();
						continue;
					}
				}
				if (buf[0] == 0x5b) { // [
					switch (buf[1]) {
					case '3': // supr
						__delete_next_char();
						if (I.vtmode == 2) {
							buf[1] = rz_cons_readchar();
							if (buf[1] == -1) {
								rz_cons_break_pop();
								return NULL;
							}
						}
						break;
					case '5': // pag up
						if (I.vtmode == 2) {
							buf[1] = rz_cons_readchar();
						}
						if (I.hud) {
							I.hud->top_entry_n -= (rows - 1);
							if (I.hud->top_entry_n < 0) {
								I.hud->top_entry_n = 0;
							}
						}
						if (I.sel_widget) {
							selection_widget_up(RZ_MIN(I.sel_widget->h, RZ_SELWIDGET_MAXH));
							selection_widget_draw();
						}
						break;
					case '6': // pag down
						if (I.vtmode == 2) {
							buf[1] = rz_cons_readchar();
						}
						if (I.hud) {
							I.hud->top_entry_n += (rows - 1);
							if (I.hud->top_entry_n >= I.hud->current_entry_n) {
								I.hud->top_entry_n = I.hud->current_entry_n - 1;
							}
						}
						if (I.sel_widget) {
							selection_widget_down(RZ_MIN(I.sel_widget->h, RZ_SELWIDGET_MAXH));
							selection_widget_draw();
						}
						break;
					case '9': // handle mouse wheel
						key = rz_cons_readchar();
						cons->mouse_event = 1;
						if (key == '6') { // up
							if (I.hud && I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
								I.hud->top_entry_n--;
							}
						} else if (key == '7') { // down
							if (I.hud && I.hud->top_entry_n >= 0) {
								I.hud->top_entry_n++;
							}
						}
						while (rz_cons_readchar() != 'M') {
						}
						break;
					/* arrows */
					case 'A': // up arrow
						if (I.hud) {
							if (I.hud->top_entry_n > 0) {
								I.hud->top_entry_n--;
							}
						} else if (I.sel_widget) {
							selection_widget_up(1);
							selection_widget_draw();
						} else if (gcomp) {
							gcomp_idx++;
						} else {
							I.history.do_setup_match = o_do_setup_match;
							if (rz_line_hist_up() == -1) {
								rz_cons_break_pop();
								return NULL;
							}
						}
						break;
					case 'B': // down arrow
						if (I.hud) {
							if (I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
								I.hud->top_entry_n++;
							}
						} else if (I.sel_widget) {
							selection_widget_down(1);
							selection_widget_draw();
						} else if (gcomp) {
							if (gcomp_idx > 0) {
								gcomp_idx--;
							}
						} else {
							I.history.do_setup_match = o_do_setup_match;
							if (rz_line_hist_down() == -1) {
								rz_cons_break_pop();
								return NULL;
							}
						}
						break;
					case 'C': // right arrow
						__move_cursor_right();
						break;
					case 'D': // left arrow
						__move_cursor_left();
						break;
					case 0x31: // control + arrow
						if (I.vtmode == 2) {
							ch = rz_cons_readchar();
							if (ch == 0x7e) { // HOME in screen/tmux
								// corresponding END is 0x34 below (the 0x7e is ignored there)
								I.buffer.index = 0;
								break;
							}
							rz_cons_readchar();
						}
#if __WINDOWS__
						else {
							ch = buf[2];
						}
#endif
						int fkey = ch - '0';
						switch (ch) {
						case 0x41:
							// first
							I.buffer.index = 0;
							break;
						case 0x44:
							// previous word
							for (i = I.buffer.index; i > 0; i--) {
								if (I.buffer.data[i] == ' ') {
									I.buffer.index = i - 1;
									break;
								}
							}
							if (I.buffer.data[i] != ' ') {
								I.buffer.index = 0;
							}
							break;
						case 0x42:
							// end
							I.buffer.index = I.buffer.length;
							break;
						case 0x43:
							// next word
							for (i = I.buffer.index; i < I.buffer.length; i++) {
								if (I.buffer.data[i] == ' ') {
									I.buffer.index = i + 1;
									break;
								}
							}
							if (I.buffer.data[i] != ' ') {
								I.buffer.index = I.buffer.length;
							}
							break;
						default:
							if (I.vtmode == 2) {
								if (I.cb_fkey) {
									I.cb_fkey(I.user, fkey);
								}
							}
							break;
						}
						rz_cons_set_raw(1);
						break;
					case 0x37: // HOME xrvt-unicode
						rz_cons_readchar();
						/* fall through */
					case 0x48: // HOME
						if (I.sel_widget) {
							selection_widget_up(I.sel_widget->options_len - 1);
							selection_widget_draw();
							break;
						}
						I.buffer.index = 0;
						break;
					case 0x34: // END
					case 0x38: // END xrvt-unicode
						rz_cons_readchar();
					case 0x46: // END
						if (I.sel_widget) {
							selection_widget_down(I.sel_widget->options_len - 1);
							selection_widget_draw();
							break;
						}
						I.buffer.index = I.buffer.length;
						break;
					}
				}
			}
			break;
		case 8:
		case 127:
			if (I.hud && (I.buffer.index == 0)) {
				I.hud->activate = false;
				I.hud->current_entry_n = -1;
			}
			__delete_prev_char();
			break;
		case 9: // TAB tab
			if (I.buffer.length > 0 && I.buffer.data[I.buffer.length - 1] == '@') {
				strcpy(I.buffer.data + I.buffer.length, " ");
				I.buffer.length++;
				I.buffer.index++;
			}
			if (I.sel_widget) {
				selection_widget_down(1);
				I.sel_widget->complete_common = true;
				selection_widget_draw();
			}
			if (I.hud) {
				if (I.hud->top_entry_n + 1 < I.hud->current_entry_n) {
					I.hud->top_entry_n++;
				} else {
					I.hud->top_entry_n = 0;
				}
			} else {
				rz_line_autocomplete();
				rz_cons_flush();
			}
			break;
		case 10: // ^J -- ignore
		case 13: // enter
			if (I.hud) {
				I.hud->activate = false;
				break;
			}
			if (I.sel_widget) {
				selection_widget_select();
				break;
			}
			if (gcomp && I.buffer.length > 0) {
				strncpy(I.buffer.data, gcomp_line, RZ_LINE_BUFSIZE - 1);
				I.buffer.data[RZ_LINE_BUFSIZE - 1] = '\0';
				I.buffer.length = strlen(gcomp_line);
			}
			gcomp_idx = gcomp = 0;
			goto _end;
		default:
			if (gcomp) {
				gcomp++;
			}
			{
#if USE_UTF8
				int size = utflen;
#else
				int size = 1;
#endif
				if (I.buffer.length + size >= RZ_LINE_BUFSIZE) {
					break;
				}
			}
			if (I.buffer.index < I.buffer.length) {
#if USE_UTF8
				if ((I.buffer.length + utflen) < sizeof(I.buffer.data)) {
					I.buffer.length += utflen;
					for (i = I.buffer.length; i > I.buffer.index; i--) {
						I.buffer.data[i] = I.buffer.data[i - utflen];
					}
					memcpy(I.buffer.data + I.buffer.index, buf, utflen);
				}
#else
				for (i = ++I.buffer.length; i > I.buffer.index; i--) {
					I.buffer.data[i] = I.buffer.data[i - 1];
				}
				I.buffer.data[I.buffer.index] = buf[0];
#endif
			} else {
#if USE_UTF8
				if ((I.buffer.length + utflen) < sizeof(I.buffer.data)) {
					memcpy(I.buffer.data + I.buffer.length, buf, utflen);
					I.buffer.length += utflen;
				}
				I.buffer.data[I.buffer.length] = '\0';
#else
				I.buffer.data[I.buffer.length] = buf[0];
				I.buffer.length++;
				if (I.buffer.length > (RZ_LINE_BUFSIZE - 1)) {
					I.buffer.length--;
				}
				I.buffer.data[I.buffer.length] = '\0';
#endif
			}
#if USE_UTF8
			if ((I.buffer.index + utflen) <= I.buffer.length) {
				I.buffer.index += utflen;
			}
#else
			if (I.buffer.index < I.buffer.length) {
				I.buffer.index++;
			}
#endif
			break;
		}
		if (I.sel_widget && I.buffer.length != prev_buflen) {
			prev_buflen = I.buffer.length;
			rz_line_autocomplete();
			rz_cons_flush();
		}
		prev = buf[0];
		if (I.echo) {
			if (gcomp) {
				gcomp_line = "";
				int counter = 0;
				if (I.history.data != NULL) {
					for (i = I.history.size - 1; i >= 0; i--) {
						if (!I.history.data[i]) {
							continue;
						}
						if (strstr(I.history.data[i], I.buffer.data)) {
							gcomp_line = I.history.data[i];
							if (++counter > gcomp_idx) {
								break;
							}
						}
						if (i == 0) {
							gcomp_idx--;
						}
					}
				}
				printf("\r (reverse-i-search (%s)): %s\r", I.buffer.data, gcomp_line);
			} else {
				__print_prompt();
			}
			fflush(stdout);
		}
		enable_yank_pop = yank_flag ? 1 : 0;
		if (I.hud) {
			goto _end;
		}
	}
_end:
	rz_cons_break_pop();
	rz_cons_set_raw(0);
	rz_cons_enable_mouse(mouse_status);
	if (I.echo) {
		printf("\r%s%s\n", I.prompt, I.buffer.data);
		fflush(stdout);
	}

	RZ_FREE(I.sel_widget);

	// should be here or not?
	if (!memcmp(I.buffer.data, "!history", 8)) {
		// if (I.buffer.data[0]=='!' && I.buffer.data[1]=='\0') {
		rz_line_hist_list();
		return rz_line_nullstr;
	}
	return I.buffer.data[0] != '\0' ? I.buffer.data : rz_line_nullstr;
}
