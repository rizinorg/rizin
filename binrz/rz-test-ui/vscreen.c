// SPDX-FileCopyrightText: 2026 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_test_ui.h"

/* A streaming text terminal for RzCons, not a general terminal application.
 * Parser storage stays bounded even for unterminated control strings. */
typedef enum { VS_TEXT,
	VS_ESCAPE,
	VS_CSI,
	VS_STRING,
	VS_STRING_ESCAPE,
	VS_CHARSET } VsState;

struct rz_vscreen_t {
	ut32 cols, rows, cx, cy, saved_cx, saved_cy;
	ut32 top, bottom;
	ut32 *cells, *normal;
	ut32 normal_cx, normal_cy;
	bool wrap, pending_wrap, alternate, graphics, valid;
	VsState state;
	ut32 params[16];
	size_t param;
	bool private_mode, intermediate;
	ut8 utf8[4];
	size_t utf8_len, utf8_need;
	RzStrBuf linebuf;
};

static bool dimensions_valid(ut32 cols, ut32 rows) {
	return cols && rows && cols <= RZ_TEST_UI_MAX_COLS && rows <= RZ_TEST_UI_MAX_ROWS;
}

static void fill(ut32 *cells, size_t count) {
	for (size_t i = 0; i < count; i++) {
		cells[i] = ' ';
	}
}

static bool fullwidth(ut32 cp) {
	ut8 encoded[5] = { 0 };
	int length = rz_utf8_encode(encoded, cp);
	return rz_str_char_fullwidth((const char *)encoded, length);
}

/** \brief Erasing or clipping either half must not leave an orphan glyph. */
static void repair_row(ut32 *row, ut32 cols) {
	for (ut32 x = 0; x < cols; x++) {
		if (!row[x]) {
			row[x] = ' ';
		} else if (fullwidth(row[x])) {
			if (x + 1 < cols && !row[x + 1]) {
				x++;
			} else {
				row[x] = ' ';
			}
		}
	}
}

static void reset(RzVScreen *s) {
	fill(s->cells, (size_t)s->cols * s->rows);
	s->cx = s->cy = s->saved_cx = s->saved_cy = 0;
	s->top = 0;
	s->bottom = s->rows - 1;
	s->pending_wrap = false;
	s->wrap = true;
	s->graphics = false;
}

RZ_OWN RzVScreen *rz_vscreen_new(ut32 cols, ut32 rows) {
	if (!dimensions_valid(cols, rows)) {
		return NULL;
	}
	RzVScreen *s = RZ_NEW0(RzVScreen);
	if (!s) {
		return NULL;
	}
	s->cells = RZ_NEWS(ut32, (size_t)cols * rows);
	s->normal = RZ_NEWS(ut32, (size_t)cols * rows);
	if (!s->cells || !s->normal) {
		rz_vscreen_free(s);
		return NULL;
	}
	s->cols = cols;
	s->rows = rows;
	s->valid = true;
	rz_strbuf_init(&s->linebuf);
	reset(s);
	fill(s->normal, (size_t)cols * rows);
	return s;
}

void rz_vscreen_free(RZ_NULLABLE RzVScreen *s) {
	if (s) {
		free(s->cells);
		free(s->normal);
		rz_strbuf_fini(&s->linebuf);
		free(s);
	}
}

/** \brief Keep both buffers and all saved positions valid across shrinking. */
bool rz_vscreen_resize(RZ_NONNULL RzVScreen *s, ut32 cols, ut32 rows) {
	if (!s || !dimensions_valid(cols, rows)) {
		return false;
	}
	ut32 *cells = RZ_NEWS(ut32, (size_t)cols * rows);
	ut32 *normal = RZ_NEWS(ut32, (size_t)cols * rows);
	if (!cells || !normal) {
		free(cells);
		free(normal);
		return false;
	}
	fill(cells, (size_t)cols * rows);
	fill(normal, (size_t)cols * rows);
	for (ut32 y = 0; y < RZ_MIN(rows, s->rows); y++) {
		size_t bytes = RZ_MIN(cols, s->cols) * sizeof(ut32);
		memcpy(cells + (size_t)y * cols, s->cells + (size_t)y * s->cols, bytes);
		memcpy(normal + (size_t)y * cols, s->normal + (size_t)y * s->cols, bytes);
		repair_row(cells + (size_t)y * cols, cols);
		repair_row(normal + (size_t)y * cols, cols);
	}
	free(s->cells);
	free(s->normal);
	s->cells = cells;
	s->normal = normal;
	s->cols = cols;
	s->rows = rows;
	s->cx = RZ_MIN(s->cx, cols - 1);
	s->cy = RZ_MIN(s->cy, rows - 1);
	s->saved_cx = RZ_MIN(s->saved_cx, cols - 1);
	s->saved_cy = RZ_MIN(s->saved_cy, rows - 1);
	s->normal_cx = RZ_MIN(s->normal_cx, cols - 1);
	s->normal_cy = RZ_MIN(s->normal_cy, rows - 1);
	s->top = 0;
	s->bottom = rows - 1;
	s->pending_wrap = false;
	return true;
}

static void scroll(RzVScreen *s, ut32 top, ut32 bottom, ut32 count, bool down) {
	count = RZ_MIN(count, bottom - top + 1);
	ut32 *first = s->cells + (size_t)top * s->cols;
	size_t shift = (size_t)count * s->cols;
	size_t keep = (size_t)(bottom - top + 1 - count) * s->cols;
	if (down) {
		memmove(first + shift, first, keep * sizeof(ut32));
		fill(first, shift);
	} else {
		memmove(first, first + shift, keep * sizeof(ut32));
		fill(first + keep, shift);
	}
}

static void line_feed(RzVScreen *s) {
	if (s->cy == s->bottom) {
		scroll(s, s->top, s->bottom, 1, false);
	} else if (s->cy + 1 < s->rows) {
		s->cy++;
	}
	s->pending_wrap = false;
}

static void put_codepoint(RzVScreen *s, ut32 cp) {
	if (s->graphics && cp >= 0x60 && cp <= 0x7e) {
		static const ut32 dec[] = {
			0x25c6, 0x2592, 0x2409, 0x240c, 0x240d, 0x240a, 0x00b0, 0x00b1,
			0x2424, 0x240b, 0x2518, 0x2510, 0x250c, 0x2514, 0x253c, 0x23ba,
			0x23bb, 0x2500, 0x23bc, 0x23bd, 0x251c, 0x2524, 0x2534, 0x252c,
			0x2502, 0x2264, 0x2265, 0x03c0, 0x2260, 0x00a3, 0x00b7
		};
		cp = dec[cp - 0x60];
	}
	ut32 width = fullwidth(cp) ? 2 : 1;
	if (width > s->cols || (width == 2 && !s->wrap && s->cx + 1 >= s->cols)) {
		s->valid = false;
		return;
	}
	if (s->pending_wrap || (width == 2 && s->cx + 1 >= s->cols)) {
		if (s->wrap) {
			s->cx = 0;
			line_feed(s);
		}
	}
	ut32 *row = s->cells + (size_t)s->cy * s->cols;
	// Zero marks the trailing half of a wide glyph, never an out-of-range cell.
	if (!row[s->cx] && s->cx) {
		row[s->cx - 1] = ' ';
	}
	if (s->cx + 1 < s->cols && !row[s->cx + 1]) {
		row[s->cx + 1] = ' ';
	}
	row[s->cx] = cp;
	if (width == 2 && s->cx + 1 < s->cols) {
		if (s->cx + 2 < s->cols && !row[s->cx + 2]) {
			row[s->cx + 2] = ' ';
		}
		row[s->cx + 1] = 0;
	}
	s->pending_wrap = s->cx + width >= s->cols && s->wrap;
	s->cx = RZ_MIN(s->cx + width, s->cols - 1);
}

static void alternate(RzVScreen *s, bool enable) {
	if (s->alternate == enable) {
		return;
	}
	ut32 *swap = s->cells;
	s->cells = s->normal;
	s->normal = swap;
	s->alternate = enable;
	if (enable) {
		s->normal_cx = s->cx;
		s->normal_cy = s->cy;
		reset(s);
	} else {
		s->cx = s->normal_cx;
		s->cy = s->normal_cy;
		s->pending_wrap = false;
	}
}

static void csi(RzVScreen *s, ut8 command) {
	ut32 p = s->params[0], q = s->params[1], n = p ? p : 1;
	if (s->private_mode) {
		if (command == 'h' || command == 'l') {
			for (size_t i = 0; i <= s->param; i++) {
				if (s->params[i] == 7) {
					s->wrap = command == 'h';
					s->pending_wrap = false;
				} else if (s->params[i] == 1049) {
					alternate(s, command == 'h');
				} else {
					switch (s->params[i]) {
					case 1:
					case 12:
					case 25:
					case 1000:
					case 1001:
					case 1002:
					case 1003:
					case 1004:
					case 1005:
					case 1006:
					case 1015:
					case 2004:
					case 2026:
						break; // Input/reporting modes do not alter text cells.
					default:
						s->valid = false;
						break;
					}
				}
			}
		}
		return;
	}
	if (s->intermediate || command == 'm' || command == 'n' || command == 'c') {
		return;
	}
	ut32 *row = s->cells + (size_t)s->cy * s->cols;
	size_t offset = (size_t)s->cy * s->cols + s->cx;
	size_t total = (size_t)s->rows * s->cols;
	s->pending_wrap = false;
	switch (command) {
	case 'H':
	case 'f':
		s->cy = RZ_MIN(p ? p - 1 : 0, s->rows - 1);
		s->cx = RZ_MIN(q ? q - 1 : 0, s->cols - 1);
		break;
	case 'A': s->cy -= RZ_MIN(s->cy, n); break;
	case 'B':
	case 'e': s->cy += RZ_MIN(s->rows - 1 - s->cy, n); break;
	case 'C':
	case 'a': s->cx += RZ_MIN(s->cols - 1 - s->cx, n); break;
	case 'D': s->cx -= RZ_MIN(s->cx, n); break;
	case 'E':
		s->cy += RZ_MIN(s->rows - 1 - s->cy, n);
		s->cx = 0;
		break;
	case 'F':
		s->cy -= RZ_MIN(s->cy, n);
		s->cx = 0;
		break;
	case 'G':
	case '`': s->cx = RZ_MIN(n - 1, s->cols - 1); break;
	case 'd': s->cy = RZ_MIN(n - 1, s->rows - 1); break;
	case 'J':
		if (!p) {
			fill(s->cells + offset, total - offset);
		} else if (p == 1) {
			fill(s->cells, offset + 1);
		} else if (p == 2 || p == 3) {
			fill(s->cells, total);
		}
		break;
	case 'K':
		if (!p) {
			fill(row + s->cx, s->cols - s->cx);
		} else if (p == 1) {
			fill(row, s->cx + 1);
		} else if (p == 2) {
			fill(row, s->cols);
		}
		break;
	case 'X': fill(row + s->cx, RZ_MIN(n, s->cols - s->cx)); break;
	case '@':
		n = RZ_MIN(n, s->cols - s->cx);
		memmove(row + s->cx + n, row + s->cx, (s->cols - s->cx - n) * sizeof(ut32));
		fill(row + s->cx, n);
		break;
	case 'P':
		n = RZ_MIN(n, s->cols - s->cx);
		memmove(row + s->cx, row + s->cx + n, (s->cols - s->cx - n) * sizeof(ut32));
		fill(row + s->cols - n, n);
		break;
	case 'L':
	case 'M':
		if (s->cy >= s->top && s->cy <= s->bottom) {
			scroll(s, s->cy, s->bottom, n, command == 'L');
		}
		break;
	case 'S':
	case 'T': scroll(s, s->top, s->bottom, n, command == 'T'); break;
	case 's':
		s->saved_cx = s->cx;
		s->saved_cy = s->cy;
		break;
	case 'u':
		s->cx = s->saved_cx;
		s->cy = s->saved_cy;
		break;
	case 'r':
		p = p ? p - 1 : 0;
		q = q ? q - 1 : s->rows - 1;
		if (p < q && q < s->rows) {
			s->top = p;
			s->bottom = q;
			s->cx = s->cy = 0;
		}
		break;
	case 'h':
	case 'l': s->valid = false; break;
	default: s->valid = false; break;
	}
	if (command == 'J') {
		for (ut32 y = 0; y < s->rows; y++) {
			repair_row(s->cells + (size_t)y * s->cols, s->cols);
		}
	} else if (command == 'K' || command == 'X' || command == '@' || command == 'P') {
		repair_row(row, s->cols);
	}
}

static void feed_byte(RzVScreen *s, ut8 c) {
	if (s->state == VS_STRING || s->state == VS_STRING_ESCAPE) {
		if (c == 7 || (s->state == VS_STRING_ESCAPE && c == '\\')) {
			s->state = VS_TEXT;
		} else {
			s->state = c == 27 ? VS_STRING_ESCAPE : VS_STRING;
		}
		return;
	}
	if (c == 27) {
		s->state = VS_ESCAPE;
		s->utf8_len = 0;
		return;
	}
	if (s->state == VS_ESCAPE) {
		s->state = VS_TEXT;
		switch (c) {
		case '[':
			memset(s->params, 0, sizeof(s->params));
			s->param = 0;
			s->private_mode = false;
			s->intermediate = false;
			s->state = VS_CSI;
			break;
		case ']':
		case 'P':
		case '^':
		case '_': s->state = VS_STRING; break;
		case '(':
		case ')': s->state = VS_CHARSET; break;
		case '7':
			s->saved_cx = s->cx;
			s->saved_cy = s->cy;
			break;
		case '8':
			s->cx = s->saved_cx;
			s->cy = s->saved_cy;
			s->pending_wrap = false;
			break;
		case 'E':
			s->cx = 0;
			line_feed(s);
			break;
		case 'D': line_feed(s); break;
		case 'M':
			if (s->cy == s->top) {
				scroll(s, s->top, s->bottom, 1, true);
			} else if (s->cy) {
				s->cy--;
			}
			s->pending_wrap = false;
			break;
		case 'c': reset(s); break;
		case '=':
		case '>':
		case '\\': break;
		default: s->valid = false; break;
		}
		return;
	}
	if (s->state == VS_CHARSET) {
		s->graphics = c == '0';
		s->state = VS_TEXT;
		return;
	}
	if (s->state == VS_CSI) {
		if (c >= '0' && c <= '9') {
			ut32 value = s->params[s->param];
			s->params[s->param] = value > (UT32_MAX - 9) / 10 ? UT32_MAX : value * 10 + c - '0';
		} else if (c == ';' || c == ':') {
			if (s->param + 1 < RZ_ARRAY_SIZE(s->params)) {
				s->param++;
			} else {
				s->valid = false;
			}
		} else if (c == '?' || c == '>') {
			s->private_mode = true;
		} else if (c >= 0x20 && c <= 0x2f) {
			s->intermediate = true;
		} else if (c >= 0x40 && c <= 0x7e) {
			csi(s, c);
			s->state = VS_TEXT;
		} else {
			s->valid = false;
			s->state = VS_TEXT;
		}
		return;
	}
	if (s->utf8_len) {
		if ((c & 0xc0) != 0x80) {
			put_codepoint(s, 0xfffd);
			s->utf8_len = 0;
			feed_byte(s, c);
			return;
		}
		s->utf8[s->utf8_len++] = c;
		if (s->utf8_len == s->utf8_need) {
			RzCodePoint cp;
			if (!rz_utf8_decode(s->utf8, s->utf8_len, &cp, false)) {
				cp = 0xfffd;
			}
			put_codepoint(s, cp);
			s->utf8_len = 0;
		}
		return;
	}
	switch (c) {
	case '\r':
		s->cx = 0;
		s->pending_wrap = false;
		return;
	case '\n':
	case '\v':
	case '\f': line_feed(s); return;
	case '\b':
		if (s->cx) {
			s->cx--;
		}
		s->pending_wrap = false;
		return;
	case '\t':
		s->cx = RZ_MIN((s->cx + 8) & ~7u, s->cols - 1);
		s->pending_wrap = false;
		return;
	default: break;
	}
	if (c < 32 || c == 127) {
		return;
	}
	if (c < 128) {
		put_codepoint(s, c);
	} else if (c >= 0xc2 && c <= 0xf4) {
		s->utf8[0] = c;
		s->utf8_len = 1;
		s->utf8_need = c < 0xe0 ? 2 : c < 0xf0 ? 3
						       : 4;
	} else {
		put_codepoint(s, 0xfffd);
	}
}

void rz_vscreen_feed(RZ_NONNULL RzVScreen *s, RZ_NONNULL const ut8 *buf, size_t length) {
	rz_return_if_fail(s && buf);
	for (size_t i = 0; i < length; i++) {
		feed_byte(s, buf[i]);
	}
}

bool rz_vscreen_valid(const RzVScreen *s) {
	return s && s->valid && s->state == VS_TEXT && !s->utf8_len;
}

/** \brief Return a code point; zero marks a wide-cell continuation or invalid coordinate. */
ut32 rz_vscreen_cell(RZ_NONNULL RzVScreen *s, ut32 row, ut32 col) {
	return s && row < s->rows && col < s->cols ? s->cells[(size_t)row * s->cols + col] : 0;
}

ut32 rz_vscreen_cols(RZ_NONNULL RzVScreen *s) {
	return s ? s->cols : 0;
}
ut32 rz_vscreen_rows(RZ_NONNULL RzVScreen *s) {
	return s ? s->rows : 0;
}

static bool row_into(RzVScreen *s, ut32 row, RzStrBuf *text) {
	if (row >= s->rows) {
		return false;
	}
	ut32 *cells = s->cells + (size_t)row * s->cols;
	ut32 end = s->cols;
	while (end && cells[end - 1] == ' ') {
		end--;
	}
	for (ut32 x = 0; x < end; x++) {
		if (!cells[x]) {
			continue;
		}
		ut8 encoded[5] = { 0 };
		int len = rz_utf8_encode(encoded, cells[x]);
		if (!len || !rz_strbuf_append_n(text, (const char *)encoded, len)) {
			return false;
		}
	}
	return true;
}

/**
 * \brief Render a row with trailing spaces removed.
 * \return Text borrowed until the next line request, or an empty string on error.
 */
RZ_BORROW const char *rz_vscreen_line(RZ_NONNULL RzVScreen *s, ut32 row) {
	rz_strbuf_set(&s->linebuf, "");
	return row_into(s, row, &s->linebuf) ? rz_strbuf_get(&s->linebuf) : "";
}

/** \brief Render all rows separated by newlines; the caller owns the result. */
RZ_OWN char *rz_vscreen_to_str(RZ_NONNULL RzVScreen *s) {
	RzStrBuf text;
	rz_strbuf_init(&text);
	for (ut32 row = 0; row < s->rows; row++) {
		if (!row_into(s, row, &text) || !rz_strbuf_append(&text, "\n")) {
			rz_strbuf_fini(&text);
			return NULL;
		}
	}
	return rz_strbuf_drain_nofree(&text);
}
