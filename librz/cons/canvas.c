// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <math.h>
#include <rz_cons.h>
#include <rz_util/rz_assert.h>

#define USE_UTF8       (rz_cons_singleton()->use_utf8)
#define USE_UTF8_CURVY (rz_cons_singleton()->use_utf8_curvy)

#define W(y)    rz_cons_canvas_write(c, y)
#define G(x, y) rz_cons_canvas_gotoxy(c, x, y)

static inline bool __isAnsiSequence(const char *s) {
	return s && s[0] == 033 && s[1] == '[';
}

static int __getAnsiPiece(const char *p, char *chr) {
	const char *q = p;
	if (!p) {
		return 0;
	}
	while (p && *p && *p != '\n' && !__isAnsiSequence(p)) {
		p++;
	}
	if (chr) {
		*chr = *p;
	}
	return p - q;
}

static const char *__attributeAt(RzConsCanvas *c, int loc) {
	if (!c->color) {
		return NULL;
	}
	return ht_up_find(c->attrs, loc, NULL);
}

static void __stampAttribute(RzConsCanvas *c, int loc, int length) {
	if (!c->color) {
		return;
	}
	int i;
	ht_up_update(c->attrs, loc, (void *)c->attr);
	for (i = 1; i < length; i++) {
		ht_up_delete(c->attrs, loc + i);
	}
}

/* check for ANSI sequences and use them as attr */
static const char *set_attr(RzConsCanvas *c, const char *s) {
	if (!c || !s) {
		return NULL;
	}
	const char *p = s;

	while (__isAnsiSequence(p)) {
		p += 2;
		while (*p && *p != 'J' && *p != 'm' && *p != 'H') {
			p++;
		}
		p++;
	}

	const int slen = p - s;
	if (slen > 0) {
		RzStrBuf tmp;
		rz_strbuf_init(&tmp);
		rz_strbuf_append_n(&tmp, s, slen);
		c->attr = rz_str_constpool_get(&c->constpool, rz_strbuf_get(&tmp));
		rz_strbuf_fini(&tmp);
	}
	return p;
}

static int __getUtf8Length(const char *s, int n) {
	int i = 0, j = 0, fullwidths = 0;
	while (s[i] && n > 0) {
		if ((s[i] & 0xc0) != 0x80) {
			j++;
			if (rz_str_char_fullwidth(s + i, n)) {
				fullwidths++;
			}
		}
		n--;
		i++;
	}
	return j + fullwidths;
}

static int __getUtf8Length2(const char *s, int n, int left) {
	int i = 0, fullwidths = 0;
	while (n > -1 && i < left && s[i]) {
		if (rz_str_char_fullwidth(s + i, left - i)) {
			fullwidths++;
		}
		if ((s[i] & 0xc0) != 0x80) {
			n--;
		}
		i++;
	}
	i -= fullwidths;
	return n == -1 ? i - 1 : i;
}

static bool __expandLine(RzConsCanvas *c, int real_len, int utf8_len) {
	if (real_len == 0) {
		return true;
	}
	int buf_utf8_len = __getUtf8Length2(c->b[c->y] + c->x, utf8_len, c->blen[c->y] - c->x);
	int goback = RZ_MAX(0, (buf_utf8_len - utf8_len));
	int padding = (real_len - utf8_len) - goback;

	if (padding) {
		if (padding > 0 && c->blen[c->y] + padding > c->bsize[c->y]) {
			int newsize = RZ_MAX(c->bsize[c->y] * 1.5, c->blen[c->y] + padding);
			char *newline = realloc(c->b[c->y], sizeof(*c->b[c->y]) * (newsize));
			if (!newline) {
				return false;
			}
			memset(newline + c->bsize[c->y], 0, newsize - c->bsize[c->y]);
			c->b[c->y] = newline;
			c->bsize[c->y] = newsize;
		}
		int size = RZ_MAX(c->blen[c->y] - c->x - goback, 0);
		char *start = c->b[c->y] + c->x + goback;
		char *tmp = malloc(size);
		if (!tmp) {
			return false;
		}
		memcpy(tmp, start, size);
		if (padding < 0) {
			int lap = RZ_MAX(0, c->b[c->y] - (start + padding));
			memcpy(start + padding + lap, tmp + lap, size - lap);
			free(tmp);
			c->blen[c->y] += padding;
			return true;
		}
		memcpy(start + padding, tmp, size);
		free(tmp);
		c->blen[c->y] += padding;
	}
	return true;
}

RZ_API void rz_cons_canvas_free(RzConsCanvas *c) {
	if (!c) {
		return;
	}
	if (c->b) {
		int y;
		for (y = 0; y < c->h; y++) {
			free(c->b[y]);
		}
		free(c->b);
	}
	free(c->bsize);
	free(c->blen);
	ht_up_free(c->attrs);
	rz_str_constpool_fini(&c->constpool);
	free(c);
}

static bool attribute_delete_cb(void *user, const ut64 key, const void *value) {
	HtUP *ht = (HtUP *)user;
	ht_up_delete(ht, key);
	return true;
}

RZ_API void rz_cons_canvas_clear(RzConsCanvas *c) {
	rz_return_if_fail(c && c->b);
	for (size_t y = 0; y < c->h; y++) {
		memset(c->b[y], '\n', c->bsize[y]);
	}

	ht_up_foreach(c->attrs, attribute_delete_cb, c->attrs);
}

RZ_API bool rz_cons_canvas_gotoxy(RzConsCanvas *c, int x, int y) {
	bool ret = true;
	if (!c) {
		return 0;
	}
	y += c->sy;
	x += c->sx;

	if (y > c->h * 2) {
		return false;
	}
	if (y >= c->h) {
		y = c->h - 1;
		ret = false;
	}
	if (y < 0) {
		y = 0;
		ret = false;
	}
	if (x < 0) {
		// c->x = 0;
		ret = false;
	}
	if (x > c->blen[y] * 2) {
		return false;
	}
	if (x >= c->blen[y]) {
		c->x = c->blen[y];
		ret = false;
	}
	if (x < c->blen[y] && x >= 0) {
		c->x = x;
	}
	if (y < c->h) {
		c->y = y;
	}
	return ret;
}

RZ_API RzConsCanvas *rz_cons_canvas_new(int w, int h) {
	if (w < 1 || h < 1) {
		return NULL;
	}
	RzConsCanvas *c = RZ_NEW0(RzConsCanvas);
	if (!c) {
		return NULL;
	}
	c->bsize = NULL;
	c->blen = NULL;
	int i = 0;
	c->color = 0;
	c->sx = 0;
	c->sy = 0;
	c->b = RZ_NEWS(char *, h);
	if (!c->b) {
		goto beach;
	}
	c->blen = RZ_NEWS(int, h);
	if (!c->blen) {
		goto beach;
	}
	c->bsize = RZ_NEWS(int, h);
	if (!c->bsize) {
		goto beach;
	}
	for (i = 0; i < h; i++) {
		c->b[i] = malloc(w + 1);
		c->blen[i] = w;
		c->bsize[i] = w + 1;
		if (!c->b[i]) {
			goto beach;
		}
	}
	c->w = w;
	c->h = h;
	c->x = c->y = 0;
	if (!rz_str_constpool_init(&c->constpool)) {
		goto beach;
	}
	c->attrs = ht_up_new((HtUPDupValue)rz_str_dup, free);
	if (!c->attrs) {
		goto beach;
	}
	c->attr = Color_RESET;
	rz_cons_canvas_clear(c);
	return c;
beach:
	rz_str_constpool_fini(&c->constpool);
	int j;
	for (j = 0; j < i; j++) {
		free(c->b[j]);
	}
	free(c->bsize);
	free(c->blen);
	free(c->b);
	free(c);
	return NULL;
}

RZ_API void rz_cons_canvas_write(RzConsCanvas *c, const char *s) {
	if (!c || !s || !*s || !RZ_BETWEEN(0, c->y, c->h - 1) || !RZ_BETWEEN(0, c->x, c->w - 1)) {
		return;
	}

	char ch;
	int left, slen, attr_len, piece_len;
	int orig_x = c->x, attr_x = c->x;

	c->x = __getUtf8Length2(c->b[c->y], c->x, c->blen[c->y]);

	/* split the string into pieces of non-ANSI chars and print them normally,
	** using the ANSI chars to set the attr of the canvas */
	rz_cons_break_push(NULL, NULL);
	do {
		const char *s_part = set_attr(c, s);
		ch = 0;
		piece_len = __getAnsiPiece(s_part, &ch);
		if (piece_len == 0 && ch == '\0' && s_part == s) {
			break;
		}
		left = c->blen[c->y] - c->x;
		slen = piece_len;

		if (piece_len > left) {
			int utf8_piece_len = __getUtf8Length(s_part, piece_len);
			if (utf8_piece_len > c->w - attr_x) {
				slen = left;
			}
		}

		int real_len = rz_str_nlen(s_part, slen);
		int utf8_len = __getUtf8Length(s_part, slen);

		if (!__expandLine(c, real_len, utf8_len)) {
			break;
		}

		if (G(c->x - c->sx, c->y - c->sy)) {
			memcpy(c->b[c->y] + c->x, s_part, slen);
		}

		attr_len = slen <= 0 && s_part != s ? 1 : utf8_len;
		if (attr_len > 0 && attr_x < c->blen[c->y]) {
			__stampAttribute(c, c->y * c->w + attr_x, attr_len);
		}

		s = s_part;
		if (ch == '\n') {
			c->attr = Color_RESET;
			__stampAttribute(c, c->y * c->w + attr_x, 0);
			c->y++;
			s++;
			if (*s == '\0' || c->y >= c->h) {
				break;
			}
			c->x = __getUtf8Length2(c->b[c->y], orig_x, c->blen[c->y]);
			attr_x = orig_x;
		} else {
			c->x += slen;
			attr_x += utf8_len;
		}
		s += piece_len;
	} while (*s && !rz_cons_is_breaked());
	rz_cons_break_pop();
	c->x = orig_x;
}

RZ_API RZ_OWN char *rz_cons_canvas_to_string(RzConsCanvas *c) {
	rz_return_val_if_fail(c, NULL);

	int x, y, olen = 0, attr_x = 0;
	bool is_first = true;

	for (y = 0; y < c->h; y++) {
		olen += c->blen[y] + 1;
	}
	char *o = calloc(1, olen * 4 * CONS_MAX_ATTR_SZ);
	if (!o) {
		return NULL;
	}
	if (!olen) {
		free(o);
		return NULL;
	}

	olen = 0;
	for (y = 0; y < c->h; y++) {
		if (!is_first) {
			o[olen++] = '\n';
		}
		is_first = false;
		attr_x = 0;
		for (x = 0; x < c->blen[y]; x++) {
			if ((c->b[y][x] & 0xc0) != 0x80) {
				const char *atr = __attributeAt(c, y * c->w + attr_x);
				if (atr) {
					size_t len = strlen(atr);
					memcpy(o + olen, atr, len);
					olen += len;
				}
				attr_x++;
				if (rz_str_char_fullwidth(c->b[y] + x, c->blen[y] - x)) {
					attr_x++;
				}
			}
			if (!c->b[y][x] || c->b[y][x] == '\n') {
				o[olen++] = ' ';
				continue;
			}
			const char *rune = rz_cons_get_rune((const ut8)c->b[y][x]);
			if (rune) {
				size_t rune_len = strlen(rune);
				memcpy(o + olen, rune, rune_len + 1);
				olen += rune_len;
			} else {
				o[olen++] = c->b[y][x];
			}
		}
		while (olen > 0 && o[olen - 1] == ' ') {
			o[--olen] = '\0';
		}
	}
	o[olen] = '\0';
	return o;
}

RZ_API void rz_cons_canvas_print_region(RzConsCanvas *c) {
	char *o = rz_cons_canvas_to_string(c);
	if (RZ_STR_ISEMPTY(o)) {
		free(o);
		return;
	}
	rz_str_trim_tail(o);
	if (RZ_STR_ISNOTEMPTY(o)) {
		rz_cons_strcat(o);
	}
	free(o);
}

RZ_API void rz_cons_canvas_print(RzConsCanvas *c) {
	char *o = rz_cons_canvas_to_string(c);
	if (!o) {
		return;
	}
	rz_cons_strcat(o);
	free(o);
}

RZ_API int rz_cons_canvas_resize(RzConsCanvas *c, int w, int h) {
	if (!c || w < 0 || h <= 0) {
		return false;
	}
	// If new height is smaller than the old one - free unnecessary lines
	if (h < c->h) {
		for (size_t i = h; i < c->h; i++) {
			free(c->b[i]);
			c->b[i] = NULL;
		}
	}
	int *newblen = realloc(c->blen, sizeof(int) * h);
	if (!newblen) {
		rz_cons_canvas_free(c);
		return false;
	}
	c->blen = newblen;
	int *newbsize = realloc(c->bsize, sizeof(int) * h);
	if (!newbsize) {
		rz_cons_canvas_free(c);
		return false;
	}
	c->bsize = newbsize;
	char **newb = realloc(c->b, sizeof(char *) * h);
	if (!newb) {
		rz_cons_canvas_free(c);
		return false;
	}
	c->b = newb;
	char *newline = NULL;
	for (size_t i = 0; i < h; i++) {
		if (i < c->h) {
			newline = realloc(c->b[i], sizeof(char) * (w + 1));
		} else {
			newline = RZ_NEWS(char, w + 1);
		}
		c->blen[i] = w;
		c->bsize[i] = w + 1;
		c->b[i] = newline;
		if (!newline) {
			rz_cons_canvas_free(c);
			return false;
		}
	}
	c->w = w;
	c->h = h;
	c->x = 0;
	c->y = 0;
	rz_cons_canvas_clear(c);
	return true;
}

RZ_API void rz_cons_canvas_box(RzConsCanvas *c, int x, int y, int w, int h, const char *color) {
	rz_return_if_fail(c && w && h);

	if (color) {
		c->attr = color;
	}
	if (!c->color) {
		c->attr = Color_RESET;
	}
	char *row = malloc(w + 1);
	if (!row) {
		return;
	}

	const char *hline = USE_UTF8 ? RUNECODESTR_LINE_HORIZ : "-";
	const char *vtmp = USE_UTF8 ? RUNECODESTR_LINE_VERT : "|";
	const char *tl_corner = USE_UTF8 ? (USE_UTF8_CURVY ? RUNECODESTR_CURVE_CORNER_TL : RUNECODESTR_CORNER_TL) : ".";
	const char *tr_corner = USE_UTF8 ? (USE_UTF8_CURVY ? RUNECODESTR_CURVE_CORNER_TR : RUNECODESTR_CORNER_TR) : ".";
	const char *bl_corner = USE_UTF8 ? (USE_UTF8_CURVY ? RUNECODESTR_CURVE_CORNER_BL : RUNECODESTR_CORNER_BL) : "`";
	const char *br_corner = USE_UTF8 ? (USE_UTF8_CURVY ? RUNECODESTR_CURVE_CORNER_BR : RUNECODESTR_CORNER_BR) : "'";
	int i, x_mod;
	int roundcorners = 0;
	char *row_ptr;

	RzStrBuf *vline = rz_strbuf_new(NULL);
	rz_strbuf_appendf(vline, Color_RESET "%s%s", color, vtmp);

	row[0] = roundcorners ? '.' : tl_corner[0];
	if (w > 2) {
		memset(row + 1, hline[0], w - 2);
	}
	if (w > 1) {
		row[w - 1] = roundcorners ? '.' : tr_corner[0];
	}
	row[w] = 0;

	row_ptr = row;
	x_mod = x;
	if (x < -c->sx) {
		x_mod = RZ_MIN(-c->sx, x_mod + w);
		row_ptr += x_mod - x;
	}
	if (G(x_mod, y)) {
		W(row_ptr);
	}
	if (G(x_mod, y + h - 1)) {
		row[0] = roundcorners ? '\'' : bl_corner[0];
		row[w - 1] = roundcorners ? '\'' : br_corner[0];
		W(row_ptr);
	}
	for (i = 1; i < h - 1; i++) {
		if (G(x, y + i)) {
			W(rz_strbuf_get(vline));
		}
		if (G(x + w - 1, y + i)) {
			W(rz_strbuf_get(vline));
		}
	}
	free(row);
	rz_strbuf_free(vline);
	if (color) {
		c->attr = Color_RESET;
	}
}

RZ_API void rz_cons_canvas_fill(RzConsCanvas *c, int x, int y, int w, int h, char ch) {
	int i;
	if (w < 0) {
		return;
	}
	char *row = malloc(w + 1);
	if (!row) {
		return;
	}
	memset(row, ch, w);
	row[w] = 0;
	for (i = 0; i < h; i++) {
		if (G(x, y + i)) {
			W(row);
		}
	}
	free(row);
}

RZ_API void rz_cons_canvas_line(RzConsCanvas *c, int x, int y, int x2, int y2, RzCanvasLineStyle *style) {
	if (c->linemode) {
		rz_cons_canvas_line_square(c, x, y, x2, y2, style);
	} else {
		rz_cons_canvas_line_diagonal(c, x, y, x2, y2, style);
	}
}
