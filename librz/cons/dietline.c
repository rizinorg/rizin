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
#else
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#endif

static const char *rz_line_nullstr = "";
static const char word_break_characters[] = "\t\n ~`!@#$%^&*()-_=+[]{}\\|;:\"'<>,./";

typedef enum {
	MINOR_BREAK,
	MAJOR_BREAK
} BreakMode;

/**
 * an entry of undo. it represents either a text insertion, deletion, or both.
 * \see undo_add_entry
 */
struct rz_line_undo_entry_t {
	int offset; ///< the beginning index of buffer edit.
	char *deleted_text; ///< text to be deleted. null-terminated
	int deleted_len; ///< the length of deleted text
	char *inserted_text; ///< text to be inserted. null-terminated.
	int inserted_len; ///< the length of inserted text.
	bool continuous_next; ///< if true, redo function will continuously process the next entry.
	bool continuous_prev; ///< if true, undo function will continuously process the previous entry.
};

static inline bool is_undo_entry_valid(const RzLineUndoEntry *e) {
	if (!e) {
		return false;
	}
	if (e->offset < 0) {
		return false;
	}
	if (!e->deleted_len && !e->inserted_len) {
		return false;
	}
	return true;
}

static void undo_entry_free(RzLineUndoEntry *e, void *user) {
	(void)user;
	RZ_FREE(e->deleted_text);
	RZ_FREE(e->inserted_text);
}

static bool undo_reset(RzLine *line) {
	if (line->enable_vi_mode || line->hud) {
		// FIXME: Undo functionality doesn't support vi_mode yet.
		return true;
	}
	if (line->undo_vec) {
		rz_vector_free(line->undo_vec);
	}
	line->undo_cursor = 0;
	line->undo_continue = false;
	line->undo_vec = rz_vector_new(sizeof(RzLineUndoEntry), (RzVectorFree)undo_entry_free, NULL);
	return !!line->undo_vec;
}

/* If possible, concatenate input characters according to the behavior of bash. (Others such as zsh don't do that) */
static bool undo_concat_entry(RzLine *line, const char *diff, const int diff_len) {
	if (!line->undo_vec->len) {
		return false;
	}
	// undo_vector has one or more entries.
	if (line->undo_cursor != line->undo_vec->len) {
		return false;
	}
	// cursor is at tail
	RzLineUndoEntry *e = rz_vector_tail(line->undo_vec);
	if (!is_undo_entry_valid(e)) {
		// entry broken
		undo_reset(line);
		return false;
	}
	if (e->deleted_len || !e->inserted_len) {
		// concat only works for inserted text, not deleted or replaced.
		return false;
	}
	if (e->offset + e->inserted_len != line->buffer.index) {
		return false;
	}
	if (e->inserted_len + diff_len > 20) {
		return false;
	}
	e->inserted_text = rz_str_append(e->inserted_text, diff);
	e->inserted_len += diff_len;
	if (!e->inserted_text) {
		// realloc broken
		undo_reset(line);
		return false;
	}
	return true;
}

/**
 * \brief Add an entry to undo vector.
 * \param line RzLine instance
 * \param offset The beginning index of buffer edit
 * \param deleted_text Text to be deleted. need to be allocated beforehand. Either deleted_text or inserted_text should be non-empty.
 * \param inserted_text Text to be inserted. need to be allocated beforehand. Either deleted_text or inserted_text should be non-empty.
 * \return true if success and false if failed. when failed, arg texts are freed.
 * **/
static bool undo_add_entry(RzLine *line, int offset, RZ_OWN char *deleted_text, RZ_OWN char *inserted_text) {
	if (line->enable_vi_mode || line->hud) {
		// Undo functionality does not yet support vi_mode.
		RZ_FREE(deleted_text);
		RZ_FREE(inserted_text);
		return false;
	}
	if (!line->undo_vec || line->undo_vec->len > RZ_LINE_UNDOSIZE) {
		undo_reset(line);
	}
	RzLineUndoEntry new_entry = {
		offset,
		deleted_text,
		deleted_text ? rz_str_nlen(deleted_text, RZ_LINE_BUFSIZE) : 0,
		inserted_text,
		inserted_text ? rz_str_nlen(inserted_text, RZ_LINE_BUFSIZE) : 0,
		line->undo_continue,
		false
	};
	if (!is_undo_entry_valid(&new_entry)) {
		// new entry invalid
		RZ_FREE(deleted_text);
		RZ_FREE(inserted_text);
		return false;
	}
	if (line->undo_vec->len) {
		RzLineUndoEntry *prev_entry = rz_vector_tail(line->undo_vec);
		if (line->undo_continue) {
			new_entry.continuous_prev = prev_entry->continuous_next;
		}
	}
	if (line->undo_cursor < line->undo_vec->len) {
		// remove all entries after undo_cursor
		for (int i = line->undo_cursor; i < line->undo_vec->len; ++i) {
			// free entries to avoid memory leak
			RzLineUndoEntry *e = rz_vector_index_ptr(line->undo_vec, i);
			undo_entry_free(e, NULL);
		}
		rz_vector_remove_range(line->undo_vec, line->undo_cursor, line->undo_vec->len - line->undo_cursor, NULL);
	}
	rz_vector_push(line->undo_vec, &new_entry);
	line->undo_cursor++;
	return true;
}

/* To group several entries into one undo action, call undo_continuous_entries_begin/end before and after the sequence of operations. */
static void undo_continuous_entries_begin(RzLine *line) {
	line->undo_continue = true;
}
static void undo_continuous_entries_end(RzLine *line) {
	line->undo_continue = false;
	if (!line->undo_vec->len) {
		return;
	}
	RzLineUndoEntry *e = rz_vector_tail(line->undo_vec);
	// terminate
	e->continuous_next = false;
}

static bool undo_nothing_to_do(RzLine *line, bool is_redo) {
	if (is_redo && line->undo_cursor == line->undo_vec->len) {
		return true;
	} else if (!is_redo && line->undo_cursor == 0) {
		return true;
	}
	return false;
}

static void line_do(RzLine *line, const bool is_redo) {
	RzLineUndoEntry *e = NULL;
	bool is_continuous;
	if (!line->undo_vec) {
		undo_reset(line);
		return;
	}
	do {
		char *deleting_text = NULL;
		int deleting_len = 0;
		char *inserting_text = NULL;
		int inserting_len = 0;
		int start, end;

		if (undo_nothing_to_do(line, is_redo)) {
			break;
		}

		// obtain entry and set is_continuous
		if (!is_redo) {
			// undo
			e = rz_vector_index_ptr(line->undo_vec, line->undo_cursor - 1);
			line->undo_cursor--;
			is_continuous = e->continuous_prev;
		} else {
			// redo
			e = rz_vector_index_ptr(line->undo_vec, line->undo_cursor);
			line->undo_cursor++;
			is_continuous = e->continuous_next;
		}

		if (!is_undo_entry_valid(e)) {
			// undo_vec broken
			undo_reset(line);
			break;
		}

		// prepare text and length
		if (!is_redo) {
			// When undoing, we delete inserted text, and insert deleted text.
			if (e->deleted_text) {
				inserting_text = e->deleted_text;
				inserting_len = e->deleted_len;
			}
			if (e->inserted_text) {
				deleting_text = e->inserted_text;
				deleting_len = e->inserted_len;
			}
		} else {
			// When redoing, we insert inserted text, and delete deleted text.
			if (e->deleted_text) {
				deleting_text = e->deleted_text;
				deleting_len = e->deleted_len;
			}
			if (e->inserted_text) {
				inserting_text = e->inserted_text;
				inserting_len = e->inserted_len;
			}
		}

		// action
		if (deleting_text) {
			// delete text
			start = e->offset;
			end = e->offset + deleting_len;
			if (start < 0 || end > line->buffer.length) {
				undo_reset(line);
				break;
			}
			memmove(line->buffer.data + start, line->buffer.data + end, line->buffer.length - end);
			line->buffer.length -= deleting_len;
			line->buffer.data[line->buffer.length] = '\0';
			line->buffer.index = start;
		}
		if (inserting_text) {
			// insert text
			start = e->offset;
			end = e->offset + inserting_len;
			if (start < 0 || start > line->buffer.length) {
				undo_reset(line);
				break;
			}
			memmove(line->buffer.data + end, line->buffer.data + start, line->buffer.length - start);
			memcpy(line->buffer.data + start, inserting_text, inserting_len);
			line->buffer.length += inserting_len;
			line->buffer.data[line->buffer.length] = '\0';
			line->buffer.index = end;
		}

	} while (is_continuous);
	return;
}

static void line_undo(RzLine *line) {
	line_do(line, false);
}

static void line_redo(RzLine *line) {
	line_do(line, true);
}

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
static void backward_kill_word(RzLine *line, BreakMode mode) {
	int i, len;
	if (line->buffer.index <= 0) {
		return;
	}
	for (i = line->buffer.index; i > 0 && is_word_break_char(line->buffer.data[i], mode); i--) {
		/* Move the cursor index back until we hit a non-word-break-character */
	}
	for (; i > 0 && !is_word_break_char(line->buffer.data[i], mode); i--) {
		/* Move the cursor index back until we hit a word-break-character */
	}
	if (i > 0) {
		i++;
	} else if (i < 0) {
		i = 0;
	}
	if (line->buffer.index > line->buffer.length) {
		line->buffer.length = line->buffer.index;
	}
	len = line->buffer.index - i;
	free(line->clipboard);
	line->clipboard = rz_str_ndup(line->buffer.data + i, len);
	rz_line_clipboard_push(line, line->clipboard);
	memmove(line->buffer.data + i, line->buffer.data + line->buffer.index,
		line->buffer.length - line->buffer.index + 1);
	undo_add_entry(line, i, rz_str_ndup(line->clipboard, len), NULL);
	line->buffer.length = strlen(line->buffer.data);
	line->buffer.index = i;
}

static void kill_word(RzLine *line, BreakMode mode) {
	int i, len;
	for (i = line->buffer.index; i < line->buffer.length && is_word_break_char(line->buffer.data[i], mode); i++) {
		/* Move the cursor index forward until we hit a non-word-break-character */
	}
	for (; i < line->buffer.length && !is_word_break_char(line->buffer.data[i], mode); i++) {
		/* Move the cursor index forward until we hit a word-break-character */
	}
	len = i - line->buffer.index;
	free(line->clipboard);
	line->clipboard = rz_str_ndup(line->buffer.data + line->buffer.index, len);
	rz_line_clipboard_push(line, line->clipboard);
	memmove(line->buffer.data + line->buffer.index, line->buffer.data + i, line->buffer.length - i + 1);
	undo_add_entry(line, i, rz_str_ndup(line->clipboard, len), NULL);
	line->buffer.length -= len;
}

static void paste(RzLine *line, bool *enable_yank_pop) {
	if (!line->clipboard) {
		return;
	}
	char *cursor = line->buffer.data + line->buffer.index;
	int dist = (line->buffer.data + line->buffer.length) - cursor;
	int len = strlen(line->clipboard);
	line->buffer.length += len;
	memmove(cursor + len, cursor, dist);
	memcpy(cursor, line->clipboard, len);
	undo_add_entry(line, line->buffer.index, NULL, rz_str_ndup(line->clipboard, len));
	line->buffer.index += len;
	*enable_yank_pop = true;
}

static void unix_word_rubout(RzLine *line) {
	int i, len;
	if (line->buffer.index < 1) {
		return;
	}
	for (i = line->buffer.index - 1; i > 0 && line->buffer.data[i] == ' '; i--) {
		/* Move cursor backwards until we hit a non-space character or EOL */
		/* This removes any trailing spaces from the input */
	}
	for (; i > 0 && line->buffer.data[i] != ' '; i--) {
		/* Move cursor backwards until we hit a space character or EOL */
		/* This deletes everything back to the previous space character */
	}
	if (i > 0) {
		i++;
	} else if (i < 0) {
		i = 0;
	}
	if (line->buffer.index > line->buffer.length) {
		line->buffer.length = line->buffer.index;
	}
	len = line->buffer.index - i;
	line->clipboard = rz_str_ndup(line->buffer.data + i, len);
	rz_line_clipboard_push(line, line->clipboard);
	undo_add_entry(line, i, rz_str_ndup(line->clipboard, len), NULL);
	memmove(line->buffer.data + i,
		line->buffer.data + line->buffer.index,
		line->buffer.length - line->buffer.index + 1);
	line->buffer.length = strlen(line->buffer.data);
	line->buffer.index = i;
}

static int inithist(RzLine *line) {
	ZERO_FILL(line->history);
	if ((line->history.size + 1024) * sizeof(char *) < line->history.size) {
		return false;
	}
	line->history.data = (char **)calloc((line->history.size + 1024), sizeof(char *));
	if (!line->history.data) {
		return false;
	}
	line->history.size = RZ_LINE_HISTSIZE;
	return true;
}

/* initialize history stuff */
RZ_API bool rz_line_dietline_init(RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line, false);
	ZERO_FILL(line->completion);
	if (!inithist(line)) {
		return false;
	}
	if (!undo_reset(line)) {
		return false;
	}
	line->echo = true;
	return true;
}

/* \brief Reads UTF-8 char into \p s with maximum expected bytelength \p maxlen
 * \return The length in bytes
 */
static int rz_line_readchar_utf8(ut8 *s, int maxlen) {
	ssize_t len, i;
	if (maxlen < 1) {
		return 0;
	}
	int ch = rz_cons_readchar();
	if (ch == -1) {
		return -1;
	}
	*s = ch;
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
	if (len > maxlen) {
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
}

RZ_API int rz_line_set_hist_callback(RZ_NONNULL RzLine *line, RzLineHistoryUpCb up, RzLineHistoryDownCb down) {
	rz_return_val_if_fail(line, -1);
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
			line->history.match = rz_str_dup(line->buffer.data);
		}
	}
	line->history.do_setup_match = false;
}

RZ_API int rz_line_hist_cmd_up(RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line, -1);
	if (line->hist_up) {
		return line->hist_up(line->user);
	}
	if (!line->history.data) {
		inithist(line);
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

RZ_API int rz_line_hist_cmd_down(RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line, -1);
	if (line->hist_down) {
		return line->hist_down(line->user);
	}
	if (!line->history.data) {
		inithist(line);
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

RZ_API bool rz_line_hist_add(RZ_NONNULL RzLine *line, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(line && str, -1);
	if (RZ_STR_ISEMPTY(str)) {
		return false;
	}
	if (!line->history.data) {
		inithist(line);
	}
	/* ignore dup */
	if (line->history.top > 0) {
		const char *data = line->history.data[line->history.top - 1];
		if (data && !strcmp(str, data)) {
			line->history.index = line->history.top;
			return false;
		}
	}
	if (line->history.top == line->history.size) {
		int i;
		free(line->history.data[0]);
		for (i = 0; i <= line->history.size - 2; i++) {
			line->history.data[i] = line->history.data[i + 1];
		}
		line->history.top--;
	}
	line->history.data[line->history.top++] = rz_str_dup(str);
	line->history.index = line->history.top;
	return true;
}

static int rz_line_hist_up(RzLine *line) {
	if (!line->cb_history_up) {
		rz_line_set_hist_callback(line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	return line->cb_history_up(line);
}

static int rz_line_hist_down(RzLine *line) {
	if (!line->cb_history_down) {
		rz_line_set_hist_callback(line, &rz_line_hist_cmd_up, &rz_line_hist_cmd_down);
	}
	return line->cb_history_down(line);
}

RZ_API const char *rz_line_hist_get(RZ_NONNULL RzLine *line, int n) {
	rz_return_val_if_fail(line, NULL);
	int i = 0;
	if (!line->history.data) {
		inithist(line);
	}
	n--;
	if (line->history.data) {
		for (i = 0; i < line->history.size && line->history.data[i]; i++) {
			if (n == i) {
				return line->history.data[i];
			}
		}
	}
	return NULL;
}

RZ_API int rz_line_hist_list(RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line, -1);
	int i = 0;
	if (!line->history.data) {
		inithist(line);
	}
	if (line->history.data) {
		for (i = 0; i < line->history.size && line->history.data[i]; i++) {
			// when you execute a command, you always move the history
			// by 1 before actually printing it.
			rz_cons_printf("%5d  %s\n", i + 1, line->history.data[i]);
		}
	}
	return i;
}

RZ_API void rz_line_hist_free(RZ_NULLABLE RzLine *line) {
	if (!line) {
		return;
	}
	int i;
	if (line->history.data) {
		for (i = 0; i < line->history.size; i++) {
			RZ_FREE(line->history.data[i]);
		}
	}
	RZ_FREE(line->history.data);
	RZ_FREE(line->sdbshell_hist);
	line->history.index = 0;
}

/**
 * \brief Load the history of commands from \p path.
 *
 * \param path Path of the history file, where commands executed in the shell
 *             were saved in a previous session
 * \return false(0) if it fails, true(!0) otherwise
 */
RZ_API bool rz_line_hist_load(RZ_NONNULL RzLine *line, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(path, false);

	FILE *fd;
	char buf[RZ_LINE_BUFSIZE];
	if (!(fd = rz_sys_fopen(path, "r"))) {
		return false;
	}
	while (fgets(buf, sizeof(buf), fd) != NULL) {
		rz_str_trim_tail(buf);
		rz_line_hist_add(line, buf);
	}
	fclose(fd);
	return true;
}

/**
 * \brief Save the history of commands executed until now to file \p path.
 *
 * \param path Path of the history file, where commands executed in the shell
 *             will be saved
 * \return false(0) if it fails, true(!0) otherwise
 */
RZ_API bool rz_line_hist_save(RZ_NONNULL RzLine *line, const char *path) {
	rz_return_val_if_fail(line, false);
	FILE *fd;
	int i, ret = false;
	if (RZ_STR_ISEMPTY(path)) {
		return false;
	}
	char *p = (char *)rz_str_lastbut(path, RZ_SYS_DIR[0], NULL);
	if (p) {
		*p = 0;
		if (!rz_sys_mkdirp(path)) {
			RZ_LOG_ERROR("Could not save history into %s\n", path);
			return false;
		}
		*p = RZ_SYS_DIR[0];
	}
	fd = rz_sys_fopen(path, "w");
	if (fd != NULL) {
		if (line->history.data) {
			for (i = 0; i < line->history.index; i++) {
				fputs(line->history.data[i], fd);
				fputs("\n", fd);
			}
			fclose(fd);
			ret = true;
		} else {
			fclose(fd);
		}
	}
	return ret;
}

RZ_API int rz_line_hist_chop(RZ_NONNULL RzLine *line, const char *file, int limit) {
	rz_return_val_if_fail(line, -1);
	/* TODO */
	return 0;
}

static void selection_widget_draw(RzLine *line) {
	RzCons *cons = rz_cons_singleton();
	RzSelWidget *sel_widget = line->sel_widget;
	int y, pos_y, pos_x = rz_str_ansi_len(line->prompt);
	sel_widget->h = RZ_MIN(sel_widget->h, RZ_SELWIDGET_MAXH);
	for (y = 0; y < sel_widget->options_len; y++) {
		sel_widget->w = RZ_MAX(sel_widget->w, strlen(sel_widget->options[y]));
	}
	if (sel_widget->direction == RZ_SELWIDGET_DIR_UP) {
		pos_y = cons->rows;
	} else {
		pos_y = rz_cons_get_cur_line();
		if (pos_y + sel_widget->h > cons->rows) {
			char *pad = rz_str_pad('\n', sel_widget->h);
			printf("%s\n", pad);
			free(pad);
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

	rz_cons_gotoxy(pos_x + line->buffer.length, pos_y);
	rz_cons_memcat(Color_RESET_BG, 5);
	rz_cons_flush();
}

static void selection_widget_up(RzLine *line, int steps) {
	RzSelWidget *sel_widget = line->sel_widget;
	if (!sel_widget) {
		return;
	}
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

static void selection_widget_down(RzLine *line, int steps) {
	RzSelWidget *sel_widget = line->sel_widget;
	if (!sel_widget) {
		return;
	}
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

static void selection_widget_erase(RzLine *line) {
	RzSelWidget *sel_widget = line->sel_widget;
	if (sel_widget) {
		return;
	}
	sel_widget->options_len = 0;
	sel_widget->selection = -1;
	selection_widget_draw(line);
	RZ_FREE(line->sel_widget);
	RzCons *cons = rz_cons_singleton();
	if (cons->event_resize && cons->event_data) {
		cons->event_resize(cons->event_data);
		RzCore *core = (RzCore *)(cons->user);
		if (core) {
			cons->cb_task_oneshot(line, NULL, &core->tasks);
		}
	}
	printf("%s", RZ_CONS_CLEAR_FROM_CURSOR_TO_END);
}

static void selection_widget_select(RzLine *line) {
	RzSelWidget *sel_widget = line->sel_widget;
	if (sel_widget && sel_widget->selection < sel_widget->options_len) {
		char *sp = strchr(line->buffer.data, ' ');
		if (sp) {
			int delta = sp - line->buffer.data + 1;
			line->buffer.length = RZ_MIN(delta + strlen(sel_widget->options[sel_widget->selection]), RZ_LINE_BUFSIZE - 1);
			memcpy(line->buffer.data + delta, sel_widget->options[sel_widget->selection], strlen(sel_widget->options[sel_widget->selection]));
			line->buffer.index = line->buffer.length;
			return;
		}
		char *del_text = rz_str_dup(line->buffer.data);
		line->buffer.length = RZ_MIN(strlen(sel_widget->options[sel_widget->selection]), RZ_LINE_BUFSIZE - 1);
		memcpy(line->buffer.data, sel_widget->options[sel_widget->selection], line->buffer.length);
		line->buffer.data[line->buffer.length] = '\0';
		line->buffer.index = line->buffer.length;
		undo_add_entry(line, 0, del_text, rz_str_dup(line->buffer.data));
		selection_widget_erase(NULL);
	}
}

static void selection_widget_update(RzLine *line) {
	int argc = rz_pvector_len(&line->completion.args);
	const char **argv = (const char **)rz_pvector_data(&line->completion.args);
	if (argc == 0 || (argc == 1 && line->buffer.length >= strlen(argv[0]))) {
		selection_widget_erase(line);
		return;
	}
	if (!line->sel_widget) {
		RzSelWidget *sel_widget = RZ_NEW0(RzSelWidget);
		line->sel_widget = sel_widget;
	}
	line->sel_widget->scroll = 0;
	line->sel_widget->selection = 0;
	line->sel_widget->options_len = argc;
	line->sel_widget->options = argv;
	line->sel_widget->h = RZ_MAX(line->sel_widget->h, line->sel_widget->options_len);

	if (line->prompt_type == RZ_LINE_PROMPT_DEFAULT) {
		line->sel_widget->direction = RZ_SELWIDGET_DIR_DOWN;
	} else {
		line->sel_widget->direction = RZ_SELWIDGET_DIR_UP;
	}
	selection_widget_draw(line);
	rz_cons_flush();
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

static void replace_buffer_text(RzLine *line, RzLineBuffer *buf, size_t start, size_t end, const char *s) {
	size_t s_len = strlen(s);
	if (!is_valid_buffer_limits(buf, start, end, s_len)) {
		return;
	}

	size_t diff = end - start;
	if (diff || s_len) {
		char *del_text = rz_str_ndup(buf->data + start, diff);
		char *ins_text = rz_str_ndup(s, s_len);
		if (diff != s_len || rz_str_cmp(del_text, ins_text, diff)) {
			undo_add_entry(line, start, del_text, ins_text);
		} else {
			RZ_FREE(del_text);
			RZ_FREE(ins_text);
		}
	}
	// FIXME: escape s
	memmove(buf->data + start + s_len, buf->data + end, buf->length - end);
	memmove(buf->data + start, s, s_len);
	buf->length += s_len - diff;
	buf->index += s_len - diff;
	buf->data[buf->length] = '\0';
}

static char *get_max_common_pfx(RzPVector /*<char *>*/ *options) {
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

RZ_API void rz_line_autocomplete(RZ_NONNULL RzLine *line) {
	rz_return_if_fail(line);
	char *p;
	char *del_text = NULL;
	const char **argv = NULL;
	int argc = 0, i, j, plen;
	bool opt = false;
	RzCons *cons = rz_cons_singleton();

	if (line->ns_completion.run) {
		RzLineNSCompletionResult *res = line->ns_completion.run(&line->buffer, line->prompt_type, line->ns_completion.run_user);
		undo_continuous_entries_begin(line);
		if (!res || rz_pvector_empty(&res->options)) {
			// do nothing
		} else if (rz_pvector_len(&res->options) == 1) {
			// if there is just one option, just use it
			bool is_at_end = line->buffer.length == line->buffer.index;
			replace_buffer_text(line, &line->buffer, res->start, res->end, rz_pvector_at(&res->options, 0));
			if (is_at_end && res->end_string) {
				replace_buffer_text(line, &line->buffer, line->buffer.length, line->buffer.length, res->end_string);
			}

		} else {
			// otherwise find maxcommonprefix, print it, and then print options
			char *max_common_pfx = get_max_common_pfx(&res->options);
			replace_buffer_text(line, &line->buffer, res->start, res->end, max_common_pfx);
			free(max_common_pfx);

			rz_cons_printf("%s%s\n", line->prompt, line->buffer.data);
			print_options(rz_pvector_len(&res->options), (const char **)rz_pvector_data(&res->options));
		}
		undo_continuous_entries_end(line);
		rz_line_ns_completion_result_free(res);
		return;
	}

	/* prepare argc and argv */
	if (line->completion.run) {
		line->completion.opt = false;
		line->completion.run(&line->completion, &line->buffer, line->prompt_type, line->completion.run_user);
		argc = rz_pvector_len(&line->completion.args);
		argv = (const char **)rz_pvector_data(&line->completion.args);
		opt = line->completion.opt;
	}
	if (line->sel_widget && !line->sel_widget->complete_common) {
		selection_widget_update(line);
		return;
	}

	if (opt) {
		p = (char *)rz_sub_str_lchr(line->buffer.data, 0, line->buffer.index, '=');
	} else {
		p = (char *)rz_sub_str_lchr(line->buffer.data, 0, line->buffer.index, ' ');
	}
	if (!p) {
		p = (char *)rz_sub_str_lchr(line->buffer.data, 0, line->buffer.index, '@'); // HACK FOR r2
	}
	if (p) {
		p++;
		plen = sizeof(line->buffer.data) - (int)(size_t)(p - line->buffer.data);
	} else {
		p = line->buffer.data; // XXX: removes current buffer
		plen = sizeof(line->buffer.data);
	}
	if (plen) {
		del_text = rz_str_ndup(line->buffer.data, line->buffer.length);
	}
	/* autocomplete */
	if (argc == 1) {
		const char *end_word = rz_sub_str_rchr(line->buffer.data,
			line->buffer.index, strlen(line->buffer.data), ' ');
		const char *t = end_word != NULL ? end_word : line->buffer.data + line->buffer.index;
		int largv0 = strlen(argv[0] ? argv[0] : "");
		size_t len_t = strlen(t);
		p[largv0] = '\0';

		if ((p - line->buffer.data) + largv0 + 1 + len_t < plen) {
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
			line->buffer.length = strlen(line->buffer.data);
			line->buffer.index = line->buffer.length;
		}
	} else if (argc > 0) {
		if (*p) {
			// TODO: avoid overflow
			const char *t = line->buffer.data + line->buffer.index;
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
			line->buffer.length = strlen(line->buffer.data);
			line->buffer.index = (p - line->buffer.data) + min_common_len;
		}
	}

	if (rz_str_cmp(del_text, line->buffer.data, line->buffer.length)) {
		undo_add_entry(line, 0, del_text, rz_str_ndup(line->buffer.data, line->buffer.length));
	} else {
		RZ_FREE(del_text);
	}

	if (line->prompt_type != RZ_LINE_PROMPT_DEFAULT || cons->show_autocomplete_widget) {
		selection_widget_update(line);
		if (line->sel_widget) {
			line->sel_widget->complete_common = false;
		}
		return;
	}

	/* show options */
	if (argc > 1 && line->echo) {
		rz_cons_printf("%s%s\n", line->prompt, line->buffer.data);
		print_options(argc, argv);
	}
}

RZ_API const char *rz_line_readline(RZ_NONNULL RzLine *line) {
	rz_return_val_if_fail(line, NULL);
	return rz_line_readline_cb(line, NULL, NULL);
}

static inline void rotate_kill_ring(RzLine *line, bool *enable_yank_pop) {
	if (!*enable_yank_pop) {
		return;
	}
	line->buffer.index -= strlen(rz_list_get_n(line->kill_ring, line->kill_ring_ptr));
	undo_continuous_entries_begin(line);
	undo_add_entry(line, line->buffer.index, rz_str_ndup(line->buffer.data + line->buffer.index, line->buffer.length - line->buffer.index), NULL);
	line->buffer.data[line->buffer.index] = 0;
	line->kill_ring_ptr -= 1;
	if (line->kill_ring_ptr < 0) {
		line->kill_ring_ptr = line->kill_ring->length - 1;
	}
	line->clipboard = rz_list_get_n(line->kill_ring, line->kill_ring_ptr);
	paste(line, enable_yank_pop);
	undo_continuous_entries_end(line);
}

static inline void __delete_next_char(RzLine *line) {
	if (line->buffer.index < line->buffer.length) {
		undo_add_entry(line, line->buffer.index, rz_str_ndup(line->buffer.data + line->buffer.index, 1), NULL);
		int len = rz_str_utf8_charsize(line->buffer.data + line->buffer.index);
		memmove(line->buffer.data + line->buffer.index,
			line->buffer.data + line->buffer.index + len,
			strlen(line->buffer.data + line->buffer.index + 1) + 1);
		line->buffer.length -= len;
	}
}

static inline void __delete_prev_char(RzLine *line) {
	if (line->buffer.index > 0) {
		undo_add_entry(line, line->buffer.index - 1, rz_str_ndup(line->buffer.data + line->buffer.index - 1, 1), NULL);
	}
	if (line->buffer.index < line->buffer.length) {
		if (line->buffer.index > 0) {
			size_t len = rz_str_utf8_charsize_prev(line->buffer.data + line->buffer.index, line->buffer.index);
			line->buffer.index -= len;
			memmove(line->buffer.data + line->buffer.index,
				line->buffer.data + line->buffer.index + len,
				strlen(line->buffer.data + line->buffer.index));
			line->buffer.length -= len;
		}
	} else {
		line->buffer.length -= rz_str_utf8_charsize_last(line->buffer.data);
		line->buffer.index = line->buffer.length;
		if (line->buffer.length < 0) {
			line->buffer.length = 0;
		}
	}
	line->buffer.data[line->buffer.length] = '\0';
	if (line->buffer.index < 0) {
		line->buffer.index = 0;
	}
}

static inline void delete_till_end(RzLine *line) {
	if (line->buffer.index < line->buffer.length) {
		undo_add_entry(line, line->buffer.index, rz_str_dup(line->buffer.data + line->buffer.index), NULL);
	}
	line->buffer.data[line->buffer.index] = '\0';
	line->buffer.length = line->buffer.index;
	line->buffer.index = line->buffer.index > 0 ? line->buffer.index - 1 : 0;
}

static void __print_prompt(RzLine *line) {
	RzCons *cons = rz_cons_singleton();
	int columns = rz_cons_get_size(NULL) - 2;
	int chars = strlen(line->buffer.data);
	int len, i, cols = RZ_MAX(1, columns - rz_str_ansi_len(line->prompt) - 2);
	if (cons->line->prompt_type == RZ_LINE_PROMPT_OFFSET) {
		rz_cons_gotoxy(0, cons->rows);
		rz_cons_flush();
	}
	rz_cons_clear_line(0);
	if (cons->context->color_mode > 0) {
		printf("\r%s%s", Color_RESET, line->prompt);
	} else {
		printf("\r%s", line->prompt);
	}
	fwrite(line->buffer.data, 1, RZ_MIN(cols, chars), stdout);
	printf("\r%s", line->prompt);
	if (line->buffer.index > cols) {
		printf("< ");
		i = line->buffer.index - cols;
		if (i > sizeof(line->buffer.data)) {
			i = sizeof(line->buffer.data) - 1;
		}
	} else {
		i = 0;
	}
	len = line->buffer.index - i;
	if (len > 0 && (i + len) <= line->buffer.length) {
		fwrite(line->buffer.data + i, 1, len, stdout);
	}
	fflush(stdout);
}

static inline void __move_cursor_right(RzLine *line) {
	line->buffer.index = line->buffer.index < line->buffer.length
		? line->buffer.index + rz_str_utf8_charsize(line->buffer.data + line->buffer.index)
		: line->buffer.length;
}

static inline void __move_cursor_left(RzLine *line) {
	line->buffer.index = line->buffer.index
		? line->buffer.index - rz_str_utf8_charsize_prev(line->buffer.data + line->buffer.index, line->buffer.index)
		: 0;
}

static inline void vi_cmd_b(RzLine *line) {
	int i;
	for (i = line->buffer.index - 2; i >= 0; i--) {
		if ((is_word_break_char(line->buffer.data[i], MINOR_BREAK) && !is_word_break_char(line->buffer.data[i], MAJOR_BREAK)) || (is_word_break_char(line->buffer.data[i - 1], MINOR_BREAK) && !is_word_break_char(line->buffer.data[i], MINOR_BREAK))) {
			line->buffer.index = i;
			break;
		}
	}
	if (i < 0) {
		line->buffer.index = 0;
	}
}

static inline void vi_cmd_B(RzLine *line) {
	int i;
	for (i = line->buffer.index - 2; i >= 0; i--) {
		if ((!is_word_break_char(line->buffer.data[i], MAJOR_BREAK) && is_word_break_char(line->buffer.data[i - 1], MAJOR_BREAK))) {
			line->buffer.index = i;
			break;
		}
	}
	if (i < 0) {
		line->buffer.index = 0;
	}
}

static inline void vi_cmd_W(RzLine *line) {
	int i;
	for (i = line->buffer.index + 1; i < line->buffer.length; i++) {
		if ((!is_word_break_char(line->buffer.data[i], MAJOR_BREAK) && is_word_break_char(line->buffer.data[i - 1], MAJOR_BREAK))) {
			line->buffer.index = i;
			break;
		}
	}
	if (i >= line->buffer.length) {
		line->buffer.index = line->buffer.length - 1;
	}
}

static inline void vi_cmd_w(RzLine *line) {
	int i;
	for (i = line->buffer.index + 1; i < line->buffer.length; i++) {
		if ((!is_word_break_char(line->buffer.data[i], MINOR_BREAK) && is_word_break_char(line->buffer.data[i - 1], MINOR_BREAK)) || (is_word_break_char(line->buffer.data[i], MINOR_BREAK) && !is_word_break_char(line->buffer.data[i], MAJOR_BREAK))) {
			line->buffer.index = i;
			break;
		}
	}
	if (i >= line->buffer.length) {
		line->buffer.index = line->buffer.length - 1;
	}
}

static inline void vi_cmd_E(RzLine *line) {
	int i;
	for (i = line->buffer.index + 1; i < line->buffer.length; i++) {
		if ((!is_word_break_char(line->buffer.data[i], MAJOR_BREAK) && is_word_break_char(line->buffer.data[i + 1], MAJOR_BREAK))) {
			line->buffer.index = i;
			break;
		}
	}
	if (i >= line->buffer.length) {
		line->buffer.index = line->buffer.length - 1;
	}
}

static inline void vi_cmd_e(RzLine *line) {
	int i;
	for (i = line->buffer.index + 1; i < line->buffer.length; i++) {
		if ((!is_word_break_char(line->buffer.data[i], MINOR_BREAK) && is_word_break_char(line->buffer.data[i + 1], MINOR_BREAK)) || (is_word_break_char(line->buffer.data[i], MINOR_BREAK) && !is_word_break_char(line->buffer.data[i], MAJOR_BREAK))) {
			line->buffer.index = i;
			break;
		}
	}
	if (i >= line->buffer.length) {
		line->buffer.index = line->buffer.length - 1;
	}
}

static void __update_prompt_color(RzLine *line) {
	RzCons *cons = rz_cons_singleton();
	const char *BEGIN = "", *END = "";
	if (cons->context->color_mode) {
		if (line->prompt_mode) {
			switch (line->vi_mode) {
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
	char *prompt = rz_str_escape(line->prompt); // remote the color
	free(line->prompt);
	line->prompt = rz_str_newf("%s%s%s", BEGIN, prompt, END);
	free(prompt);
}

static void __vi_mode(RzLine *line, bool *enable_yank_pop) {
	char ch;
	line->vi_mode = CONTROL_MODE;
	__update_prompt_color(line);
	const char *gcomp_line = "";
	for (;;) {
		int rep = 0;
		if (line->echo) {
			__print_prompt(line);
		}
		if (line->vi_mode != CONTROL_MODE) { // exit if insert mode is selected
			__update_prompt_color(line);
			break;
		}
		bool o_do_setup_match = line->history.do_setup_match;
		line->history.do_setup_match = true;
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
			if (line->hud) {
				line->hud->activate = false;
				line->hud->current_entry_n = -1;
			}
			if (line->echo) {
				eprintf("^C\n");
			}
			line->buffer.index = line->buffer.length = 0;
			*line->buffer.data = '\0';
			line->gcomp = 0;
			return;
		case 'D':
			delete_till_end(line);
			break;
		case 'r': {
			char c = rz_cons_readchar();
			line->buffer.data[line->buffer.index] = c;
		} break;
		case 'x':
			while (rep--) {
				__delete_next_char(line);
			}
			break;
		case 'c':
			line->vi_mode = INSERT_MODE; // goto insert mode
			/* fall through */
		case 'd': {
			char c = rz_cons_readchar();
			while (rep--) {
				switch (c) {
				case 'i': {
					char t = rz_cons_readchar();
					if (t == 'w') { // diw
						kill_word(line, MINOR_BREAK);
						backward_kill_word(line, MINOR_BREAK);
					} else if (t == 'W') { // diW
						kill_word(line, MAJOR_BREAK);
						backward_kill_word(line, MINOR_BREAK);
					}
					if (line->hud) {
						line->hud->vi = false;
					}
				} break;
				case 'W':
					kill_word(line, MAJOR_BREAK);
					break;
				case 'w':
					kill_word(line, MINOR_BREAK);
					break;
				case 'B':
					backward_kill_word(line, MAJOR_BREAK);
					break;
				case 'b':
					backward_kill_word(line, MINOR_BREAK);
					break;
				case 'h':
					__delete_prev_char(line);
					break;
				case 'l':
					__delete_next_char(line);
					break;
				case '$':
					delete_till_end(line);
					break;
				case '^':
				case '0':
					strncpy(line->buffer.data, line->buffer.data + line->buffer.index, line->buffer.length);
					line->buffer.length -= line->buffer.index;
					line->buffer.index = 0;
					break;
				}
				__print_prompt(line);
			}
		} break;
		case 'I':
			if (line->hud) {
				line->hud->vi = false;
			}
			line->vi_mode = INSERT_MODE;
			/* fall through */
		case '^':
		case '0':
			if (line->gcomp) {
				strcpy(line->buffer.data, gcomp_line);
				line->buffer.length = strlen(line->buffer.data);
				line->buffer.index = 0;
				line->gcomp = 0;
			}
			line->buffer.index = 0;
			break;
		case 'A':
			line->vi_mode = INSERT_MODE;
			/* fall through */
		case '$':
			if (line->gcomp) {
				strcpy(line->buffer.data, gcomp_line);
				line->buffer.index = strlen(line->buffer.data);
				line->buffer.length = line->buffer.index;
				line->gcomp = 0;
			} else {
				line->buffer.index = line->buffer.length;
			}
			break;
		case 'p':
			while (rep--) {
				paste(line, enable_yank_pop);
			}
			break;
		case 'a':
			__move_cursor_right(line);
			/* fall through */
		case 'i':
			line->vi_mode = INSERT_MODE;
			if (line->hud) {
				line->hud->vi = false;
			}
			break;
		case 'h':
			while (rep--) {
				__move_cursor_left(line);
			}
			break;
		case 'l':
			while (rep--) {
				__move_cursor_right(line);
			}
			break;
		case 'E':
			while (rep--) {
				vi_cmd_E(line);
			}
			break;
		case 'e':
			while (rep--) {
				vi_cmd_e(line);
			}
			break;
		case 'B':
			while (rep--) {
				vi_cmd_B(line);
			}
			break;
		case 'b':
			while (rep--) {
				vi_cmd_b(line);
			}
			break;
		case 'W':
			while (rep--) {
				vi_cmd_W(line);
			}
			break;
		case 'w':
			while (rep--) {
				vi_cmd_w(line);
			}
			break;
		default: // escape key
			ch = tolower(rz_cons_arrow_to_hjkl(ch));
			switch (ch) {
			case 'k': // up
				line->history.do_setup_match = o_do_setup_match;
				rz_line_hist_up(line);
				break;
			case 'j': // down
				line->history.do_setup_match = o_do_setup_match;
				rz_line_hist_down(line);
				break;
			case 'l': // right
				__move_cursor_right(line);
				break;
			case 'h': // left
				__move_cursor_left(line);
				break;
			}
			break;
		}
		if (line->hud) {
			return;
		}
	}
}

RZ_API const char *rz_line_readline_cb(RZ_NONNULL RzLine *line, RzLineReadCallback cb, void *user) {
	rz_return_val_if_fail(line, NULL);
	int rows;
	const char *gcomp_line = "";
	char buf[10];
	int utflen;
	int ch = 0, key, i = 0; /* grep completion */
	char *tmp_ed_cmd, prev = 0;
	int prev_buflen = -1;
	bool enable_yank_pop = false;
	bool gcomp_is_rev = true;

	RzCons *cons = rz_cons_singleton();

	if (!line->hud || (line->hud && !line->hud->activate)) {
		line->buffer.index = line->buffer.length = 0;
		line->buffer.data[0] = '\0';
		if (line->hud) {
			line->hud->activate = true;
		}
	}
	int mouse_status = cons->mouse;
	if (line->hud && line->hud->vi) {
		__vi_mode(NULL, &enable_yank_pop);
		goto _end;
	}
	if (line->contents) {
		memmove(line->buffer.data, line->contents,
			RZ_MIN(strlen(line->contents) + 1, RZ_LINE_BUFSIZE - 1));
		line->buffer.data[RZ_LINE_BUFSIZE - 1] = '\0';
		line->buffer.index = line->buffer.length = strlen(line->contents);
	}
	if (line->disable) {
		if (!fgets(line->buffer.data, RZ_LINE_BUFSIZE, stdin)) {
			return NULL;
		}
		return (*line->buffer.data) ? line->buffer.data : rz_line_nullstr;
	}

	memset(&buf, 0, sizeof buf);
	rz_cons_set_raw(1);

	if (line->echo) {
		__print_prompt(line);
	}
	rz_cons_break_push(NULL, NULL);
	for (;;) {
		line->yank_flag = false;
		if (rz_cons_is_breaked()) {
			break;
		}
		line->buffer.data[line->buffer.length] = '\0';
		if (cb) {
			int cbret = cb(user, line->buffer.data);
			if (cbret == 0) {
				line->buffer.data[0] = 0;
				line->buffer.length = 0;
			}
		}
		utflen = rz_line_readchar_utf8((ut8 *)buf, sizeof(buf));
		if (utflen < 1) {
			rz_cons_break_pop();
			return NULL;
		}
		buf[utflen] = 0;
		bool o_do_setup_match = line->history.do_setup_match;
		line->history.do_setup_match = true;
		if (line->echo) {
			rz_cons_clear_line(0);
		}
		switch (*buf) {

		case 0: // control-space
			/* ignore atm */
			break;
		case 1: // ^A
			if (line->gcomp) {
				strcpy(line->buffer.data, gcomp_line);
				line->buffer.length = strlen(line->buffer.data);
				line->buffer.index = 0;
				line->gcomp = 0;
			}
			line->buffer.index = 0;
			break;
		case 2: // ^b // emacs left
			__move_cursor_left(line);
			break;
		case 5: // ^E
			if (line->gcomp) {
				strcpy(line->buffer.data, gcomp_line);
				line->buffer.index = strlen(line->buffer.data);
				line->buffer.length = line->buffer.index;
				line->gcomp = 0;
			} else if (prev == 24) { // ^X = 0x18
				line->buffer.data[line->buffer.length] = 0; // probably unnecessary
				tmp_ed_cmd = line->cb_editor(line->user, line->buffer.data);
				if (tmp_ed_cmd) {
					/* copied from yank (case 25) */
					line->buffer.length = strlen(tmp_ed_cmd);
					if (line->buffer.length < RZ_LINE_BUFSIZE) {
						line->buffer.index = line->buffer.length;
						strncpy(line->buffer.data, tmp_ed_cmd, RZ_LINE_BUFSIZE - 1);
						line->buffer.data[RZ_LINE_BUFSIZE - 1] = '\0';
						undo_add_entry(line, 0, NULL, rz_str_dup(tmp_ed_cmd));
					} else {
						line->buffer.length -= strlen(tmp_ed_cmd);
					}
					free(tmp_ed_cmd);
				}
			} else {
				line->buffer.index = line->buffer.length;
			}
			break;
		case 3: // ^C
			if (line->hud) {
				line->hud->activate = false;
				line->hud->current_entry_n = -1;
			}
			if (line->echo) {
				eprintf("^C\n");
			}
			line->buffer.index = line->buffer.length = 0;
			*line->buffer.data = '\0';
			line->gcomp = 0;
			goto _end;
		case 4: // ^D
			if (!line->buffer.data[0]) { /* eof */
				if (line->echo) {
					__print_prompt(line);
					printf("\n");
				}
				rz_cons_set_raw(false);
				rz_cons_break_pop();
				return NULL;
			}
			if (line->buffer.index < line->buffer.length) {
				__delete_next_char(line);
			}
			break;
		case 11: // ^K
			if (line->buffer.index != line->buffer.length) {
				undo_add_entry(line, line->buffer.index, rz_str_dup(line->buffer.data + line->buffer.index), NULL);
			}
			line->buffer.data[line->buffer.index] = '\0';
			line->buffer.length = line->buffer.index;
			break;
		case 6: // ^f // emacs right
			__move_cursor_right(line);
			break;
		case 12: // ^L -- clear screen
			if (line->echo) {
				eprintf("\x1b[2J\x1b[0;0H");
			}
			fflush(stdout);
			break;
		case 18: // ^R -- reverse-search
			if (line->gcomp) {
				line->gcomp_idx++;
			}
			gcomp_is_rev = true;
			line->gcomp = 1;
			break;
		case 19: // ^S -- forward-search
			if (line->gcomp) {
				if (line->gcomp_idx > 0) {
					line->gcomp_idx--;
				}
				gcomp_is_rev = false;
			} else {
				__move_cursor_left(line);
			}
			break;
		case 21: // ^U - cut
			free(line->clipboard);
			line->clipboard = rz_str_dup(line->buffer.data);
			rz_line_clipboard_push(line, line->clipboard);
			if (line->buffer.length) {
				undo_add_entry(line, 0, rz_str_dup(line->clipboard), NULL);
			}
			line->buffer.data[0] = '\0';
			line->buffer.length = 0;
			line->buffer.index = 0;
			break;
#if __WINDOWS__
		case 22: // ^V - Paste from windows clipboard
		{
			HANDLE hClipBoard;
			PTCHAR clipText;
			if (OpenClipboard(NULL)) {
				hClipBoard = GetClipboardData(CF_UNICODETEXT);
				if (hClipBoard) {
					clipText = GlobalLock(hClipBoard);
					if (clipText) {
						char *txt = rz_utf16_to_utf8(clipText);
						if (!txt) {
							RZ_LOG_ERROR("Failed to allocate memory\n");
							break;
						}
						int len = strlen(txt);
						line->buffer.length += len;
						if (line->buffer.length < RZ_LINE_BUFSIZE) {
							undo_add_entry(line, line->buffer.index, NULL, rz_str_dup(txt));
							line->buffer.index = line->buffer.length;
							strcat(line->buffer.data, txt);
						} else {
							line->buffer.length -= len;
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
			unix_word_rubout(line);
			break;
		case 24: // ^X
			if (line->buffer.index > 0) {
				undo_add_entry(line, 0, rz_str_ndup(line->buffer.data, line->buffer.index), NULL);
				strncpy(line->buffer.data, line->buffer.data + line->buffer.index, line->buffer.length);
				line->buffer.length -= line->buffer.index;
				line->buffer.index = 0;
			}
			break;
		case 25: // ^Y - paste
			paste(line, &enable_yank_pop);
			line->yank_flag = true;
			break;
		case 29: // ^^ - rotate kill ring
			rotate_kill_ring(line, &enable_yank_pop);
			line->yank_flag = enable_yank_pop;
			break;
		case 20: // ^t Kill from point to the end of the current word,
			kill_word(line, MINOR_BREAK);
			break;
		case 15: // ^o kill backward
			backward_kill_word(line, MINOR_BREAK);
			break;
		case 14: // ^n
			if (line->hud) {
				if (line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
					line->hud->top_entry_n++;
				}
			} else if (line->sel_widget) {
				selection_widget_down(line, 1);
				selection_widget_draw(line);
			} else if (line->gcomp) {
				if (line->gcomp_idx > 0) {
					line->gcomp_idx--;
				}
			} else {
				undo_reset(line);
				line->history.do_setup_match = o_do_setup_match;
				rz_line_hist_down(line);
			}
			break;
		case 16: // ^p
			if (line->hud) {
				if (line->hud->top_entry_n >= 0) {
					line->hud->top_entry_n--;
				}
			} else if (line->sel_widget) {
				selection_widget_up(line, 1);
				selection_widget_draw(line);
			} else if (line->gcomp) {
				line->gcomp_idx++;
			} else {
				undo_reset(line);
				line->history.do_setup_match = o_do_setup_match;
				rz_line_hist_up(line);
			}
			break;
		case 31: // ^_ ctrl-/ or ctrl-_
			if (!line->gcomp && !line->hud && !line->sel_widget) {
				line_undo(line);
			}
			break;
		case 27: // esc-5b-41-00-00 alt/meta key
			buf[0] = rz_cons_readchar_timeout(50);
			switch ((signed char)buf[0]) {
			case 127: // alt+bkspace
				backward_kill_word(line, MINOR_BREAK);
				break;
			case -1: // escape key, goto vi mode
				if (line->enable_vi_mode) {
					if (line->hud) {
						line->hud->vi = true;
					}
					__vi_mode(line, &enable_yank_pop);
				};
				if (line->sel_widget) {
					selection_widget_erase(line);
				}
				break;
			case 1: // begin
				line->buffer.index = 0;
				break;
			case 5: // end
				line->buffer.index = line->buffer.length;
				break;
			case 'B':
			case 'b':
				for (i = line->buffer.index - 2; i >= 0; i--) {
					if (is_word_break_char(line->buffer.data[i], MINOR_BREAK) && !is_word_break_char(line->buffer.data[i + 1], MINOR_BREAK)) {
						line->buffer.index = i + 1;
						break;
					}
				}
				if (i < 0) {
					line->buffer.index = 0;
				}
				break;
			case 'D':
			case 'd':
				kill_word(line, MINOR_BREAK);
				break;
			case 'F':
			case 'f':
				// next word
				for (i = line->buffer.index + 1; i < line->buffer.length; i++) {
					if (!is_word_break_char(line->buffer.data[i], MINOR_BREAK) && is_word_break_char(line->buffer.data[i - 1], MINOR_BREAK)) {
						line->buffer.index = i;
						break;
					}
				}
				if (i >= line->buffer.length) {
					line->buffer.index = line->buffer.length;
				}
				break;
			case 63: // ^[? Meta-/
			case 95: // ^[_ Meta-_
				if (!line->gcomp && !line->hud && !line->sel_widget) {
					line_redo(line);
				}
				break;
			default:
				buf[1] = rz_cons_readchar_timeout(50);
				if (buf[1] == -1) { // alt+e
					rz_cons_break_pop();
					__print_prompt(line);
					continue;
				}
				if (buf[0] == 'O' && strchr("ABCDFH", buf[1]) != NULL) { // O
					buf[0] = '['; // 0x5b
				}
				if (buf[0] == 0x5b) { // [
					switch (buf[1]) {
					case '3': // supr
						__delete_next_char(line);
						buf[1] = rz_cons_readchar();
						if (buf[1] == -1) {
							rz_cons_break_pop();
							return NULL;
						}
						break;
					case '5': // pag up
						buf[1] = rz_cons_readchar();
						if (line->hud) {
							rz_cons_get_size(&rows);
							line->hud->top_entry_n -= (rows - 1);
							if (line->hud->top_entry_n < 0) {
								line->hud->top_entry_n = 0;
							}
						}
						if (line->sel_widget) {
							selection_widget_up(line, RZ_MIN(line->sel_widget->h, RZ_SELWIDGET_MAXH));
							selection_widget_draw(line);
						}
						break;
					case '6': // pag down
						buf[1] = rz_cons_readchar();
						if (line->hud) {
							rz_cons_get_size(&rows);
							line->hud->top_entry_n += (rows - 1);
							if (line->hud->top_entry_n >= line->hud->current_entry_n) {
								line->hud->top_entry_n = line->hud->current_entry_n - 1;
							}
						}
						if (line->sel_widget) {
							selection_widget_down(line, RZ_MIN(line->sel_widget->h, RZ_SELWIDGET_MAXH));
							selection_widget_draw(line);
						}
						break;
					case '9': // handle mouse wheel
						key = rz_cons_readchar();
						cons->mouse_event = MOUSE_DEFAULT;
						if (key == '6') { // up
							if (line->hud && line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
								line->hud->top_entry_n--;
							}
						} else if (key == '7') { // down
							if (line->hud && line->hud->top_entry_n >= 0) {
								line->hud->top_entry_n++;
							}
						}
						while (rz_cons_readchar() != 'M') {
						}
						break;
					/* arrows */
					case 'A': // up arrow
						if (line->hud) {
							if (line->hud->top_entry_n > 0) {
								line->hud->top_entry_n--;
							}
						} else if (line->sel_widget) {
							selection_widget_up(line, 1);
							selection_widget_draw(line);
						} else if (line->gcomp) {
							line->gcomp_idx++;
						} else {
							undo_reset(line);
							line->history.do_setup_match = o_do_setup_match;
							if (rz_line_hist_up(line) == -1) {
								rz_cons_break_pop();
								return NULL;
							}
						}
						break;
					case 'B': // down arrow
						if (line->hud) {
							if (line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
								line->hud->top_entry_n++;
							}
						} else if (line->sel_widget) {
							selection_widget_down(line, 1);
							selection_widget_draw(line);
						} else if (line->gcomp) {
							if (line->gcomp_idx > 0) {
								line->gcomp_idx--;
							}
						} else {
							undo_reset(line);
							line->history.do_setup_match = o_do_setup_match;
							if (rz_line_hist_down(line) == -1) {
								rz_cons_break_pop();
								return NULL;
							}
						}
						break;
					case 'C': // right arrow
						__move_cursor_right(line);
						break;
					case 'D': // left arrow
						__move_cursor_left(line);
						break;
					case 0x31: // control + arrow
						ch = rz_cons_readchar();
						if (ch == 0x7e) { // HOME in screen/tmux
							// corresponding END is 0x34 below (the 0x7e is ignored there)
							line->buffer.index = 0;
							break;
						}
						rz_cons_readchar();
						ch = rz_cons_readchar();
						int fkey = ch - '0';
						switch (ch) {
						case 0x41:
							// first
							line->buffer.index = 0;
							break;
						case 0x44:
							// previous word
							for (i = line->buffer.index; i > 0; i--) {
								if (line->buffer.data[i] == ' ') {
									line->buffer.index = i - 1;
									break;
								}
							}
							if (line->buffer.data[i] != ' ') {
								line->buffer.index = 0;
							}
							break;
						case 0x42:
							// end
							line->buffer.index = line->buffer.length;
							break;
						case 0x43:
							// next word
							for (i = line->buffer.index; i < line->buffer.length; i++) {
								if (line->buffer.data[i] == ' ') {
									line->buffer.index = i + 1;
									break;
								}
							}
							if (line->buffer.data[i] != ' ') {
								line->buffer.index = line->buffer.length;
							}
							break;
						default:
							if (line->cb_fkey) {
								line->cb_fkey(line->user, fkey);
							}
							break;
						}
						rz_cons_set_raw(1);
						break;
					case 0x37: // HOME xrvt-unicode
						rz_cons_readchar();
						/* fall through */
					case 0x48: // HOME
						if (line->sel_widget) {
							selection_widget_up(line, line->sel_widget->options_len - 1);
							selection_widget_draw(line);
							break;
						}
						line->buffer.index = 0;
						break;
					case 0x34: // END
					case 0x38: // END xrvt-unicode
						rz_cons_readchar();
						/* fall through */
					case 0x46: // END
						if (line->sel_widget) {
							selection_widget_down(line, line->sel_widget->options_len - 1);
							selection_widget_draw(line);
							break;
						}
						line->buffer.index = line->buffer.length;
						break;
					}
				}
			}
			break;
		case 8:
		case 127:
			if (line->hud && (line->buffer.index == 0)) {
				line->hud->activate = false;
				line->hud->current_entry_n = -1;
			}
			__delete_prev_char(line);
			break;
		case 9: // TAB tab
			if (line->sel_widget) {
				selection_widget_down(line, 1);
				line->sel_widget->complete_common = true;
				selection_widget_draw(line);
			}
			if (line->hud) {
				if (line->hud->top_entry_n + 1 < line->hud->current_entry_n) {
					line->hud->top_entry_n++;
				} else {
					line->hud->top_entry_n = 0;
				}
			} else {
				rz_line_autocomplete(line);
				rz_cons_flush();
			}
			break;
		case 10: // ^J -- ignore
		case 13: // enter
			if (line->hud) {
				line->hud->activate = false;
				break;
			}
			if (line->sel_widget) {
				selection_widget_select(line);
				break;
			}
			if (line->gcomp && line->buffer.length > 0) {
				strncpy(line->buffer.data, gcomp_line, RZ_LINE_BUFSIZE - 1);
				line->buffer.data[RZ_LINE_BUFSIZE - 1] = '\0';
				line->buffer.length = strlen(gcomp_line);
			}
			line->gcomp_idx = 0;
			line->gcomp = 0;
			goto _end;
		default:
			if (line->gcomp) {
				line->gcomp++;
			}
			{
				int size = utflen;
				if (line->buffer.length + size >= RZ_LINE_BUFSIZE) {
					break;
				}
			}
			if (line->buffer.index < line->buffer.length) {
				if ((line->buffer.length + utflen) < sizeof(line->buffer.data)) {
					line->buffer.length += utflen;
					for (i = line->buffer.length; i > line->buffer.index; i--) {
						line->buffer.data[i] = line->buffer.data[i - utflen];
					}
					memcpy(line->buffer.data + line->buffer.index, buf, utflen);
					undo_add_entry(line, line->buffer.index, NULL, rz_str_ndup(buf, utflen));
				}
			} else {
				if ((line->buffer.length + utflen) < sizeof(line->buffer.data)) {
					memcpy(line->buffer.data + line->buffer.length, buf, utflen);
					line->buffer.length += utflen;
					if (!undo_concat_entry(line, buf, utflen)) {
						undo_add_entry(line, line->buffer.index, NULL, rz_str_ndup(buf, utflen));
					}
				}
				line->buffer.data[line->buffer.length] = '\0';
			}
			if ((line->buffer.index + utflen) <= line->buffer.length) {
				line->buffer.index += utflen;
			}
			break;
		}
		if (line->sel_widget && line->buffer.length != prev_buflen) {
			prev_buflen = line->buffer.length;
			rz_line_autocomplete(line);
			rz_cons_flush();
		}
		prev = buf[0];
		if (line->echo) {
			if (line->gcomp) {
				gcomp_line = "";
				int counter = 0;
				if (line->history.data != NULL) {
					for (i = line->history.size - 1; i >= 0; i--) {
						if (!line->history.data[i]) {
							continue;
						}
						if (strstr(line->history.data[i], line->buffer.data)) {
							gcomp_line = line->history.data[i];
							if (++counter > line->gcomp_idx) {
								break;
							}
						}
						if (i == 0) {
							if (gcomp_is_rev) {
								line->gcomp_idx--;
							}
						}
					}
				}
				const char *prompt = gcomp_is_rev ? "reverse-i-search" : "forward-i-search";
				printf("\r (%s (%s)): %s\r", prompt, line->buffer.data, gcomp_line);
			} else {
				__print_prompt(line);
			}
			fflush(stdout);
		}
		enable_yank_pop = line->yank_flag;
		if (line->hud) {
			goto _end;
		}
	}
_end:
	undo_reset(line);
	rz_cons_break_pop();
	rz_cons_set_raw(0);
	rz_cons_enable_mouse(mouse_status);
	if (line->echo) {
		printf("\r%s%s\n", line->prompt, line->buffer.data);
		fflush(stdout);
	}

	RZ_FREE(line->sel_widget);

	// should be here or not?
	if (!memcmp(line->buffer.data, "!history", 8)) {
		// if (line->buffer.data[0]=='!' && line->buffer.data[1]=='\0') {
		rz_line_hist_list(line);
		return rz_line_nullstr;
	}
	return line->buffer.data[0] != '\0' ? line->buffer.data : rz_line_nullstr;
}
