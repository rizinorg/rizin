// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <ctype.h>
#include <rz_util/rz_str.h>
#include <rz_list.h>
#include <rz_util/rz_regex.h>
#include <rz_types.h>
#include <rz_util/rz_assert.h>
#include <rz_util/rz_log.h>
#include <rz_util/rz_strbuf.h>
#include <rz_vector.h>
#include <rz_util/rz_print.h>
#include <rz_analysis.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DFLT_ROWS 16

static const char hex[16] = "0123456789ABCDEF";

static int nullprinter(const char *a, ...) {
	return 0;
}

static int libc_printf(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
	return 0;
}

static RzPrintIsInterruptedCallback is_interrupted_cb = NULL;

RZ_API bool rz_print_is_interrupted(void) {
	if (is_interrupted_cb) {
		return is_interrupted_cb();
	}
	return false;
}

RZ_API void rz_print_set_is_interrupted_cb(RzPrintIsInterruptedCallback cb) {
	is_interrupted_cb = cb;
}

RZ_API RzPrint *rz_print_new(void) {
	RzPrint *p = RZ_NEW0(RzPrint);
	if (!p) {
		return NULL;
	}
	strcpy(p->datefmt, "%Y-%m-%d %H:%M:%S %z");
	rz_io_bind_init(p->iob);
	p->pairs = true;
	p->resetbg = true;
	p->cb_printf = libc_printf;
	p->oprintf = nullprinter;
	p->bits = 32;
	p->stride = 0;
	p->bytespace = 0;
	p->big_endian = false;
	p->datezone = 0;
	p->col = 0;
	p->width = 78;
	p->cols = 16;
	p->cur_enabled = false;
	p->cur = p->ocur = -1;
	p->addrmod = 4;
	p->flags =
		RZ_PRINT_FLAGS_COLOR |
		RZ_PRINT_FLAGS_OFFSET |
		RZ_PRINT_FLAGS_HEADER |
		RZ_PRINT_FLAGS_ADDRMOD;
	p->seggrn = 4;
	p->zoom = RZ_NEW0(RzPrintZoom);
	p->reg = NULL;
	p->get_register = NULL;
	p->get_register_value = NULL;
	p->calc_row_offsets = true;
	p->row_offsets_sz = 0;
	p->row_offsets = NULL;
	p->vflush = true;
	p->screen_bounds = 0;
	p->esc_bslash = false;
	p->strconv_mode = NULL;
	memset(&p->consbind, 0, sizeof(p->consbind));
	p->io_unalloc_ch = '.';
	return p;
}

RZ_API RzPrint *rz_print_free(RzPrint *p) {
	if (!p) {
		return NULL;
	}
	RZ_FREE(p->strconv_mode);
	if (p->zoom) {
		free(p->zoom->buf);
		free(p->zoom);
		p->zoom = NULL;
	}
	RZ_FREE(p->row_offsets);
	free(p);
	return NULL;
}

// dummy setter can be removed
RZ_API void rz_print_set_flags(RzPrint *p, int _flags) {
	p->flags = _flags;
}

RZ_API void rz_print_set_cursor(RzPrint *p, int enable, int ocursor, int cursor) {
	if (!p) {
		return;
	}
	p->cur_enabled = enable;
	p->ocur = ocursor;
	if (cursor < 0) {
		cursor = 0;
	}
	p->cur = cursor;
}

RZ_API bool rz_print_have_cursor(RzPrint *p, int cur, int len) {
	if (!p || !p->cur_enabled) {
		return false;
	}
	if (p->ocur != -1) {
		int from = p->ocur;
		int to = p->cur;
		rz_num_minmax_swap_i(&from, &to);
		do {
			if (cur + len - 1 >= from && cur + len - 1 <= to) {
				return true;
			}
		} while (--len);
	} else if (p->cur >= cur && p->cur <= cur + len - 1) {
		return true;
	}
	return false;
}

RZ_API bool rz_print_cursor_pointer(RzPrint *p, int cur, int len) {
	rz_return_val_if_fail(p, false);
	if (!p->cur_enabled) {
		return false;
	}
	int to = p->cur;
	do {
		if (cur + len - 1 == to) {
			return true;
		}
	} while (--len);
	return false;
}

RZ_API void rz_print_cursor(RzPrint *p, int cur, int len, int set) {
	if (rz_print_have_cursor(p, cur, len)) {
		p->cb_printf("%s", RZ_CONS_INVERT(set, 1));
	}
}

RZ_API char *rz_print_hexpair(RzPrint *p, const char *str, int n) {
	const char *s, *lastcol = Color_WHITE;
	char *d, *dst = (char *)calloc((strlen(str) + 2), 32);
	int colors = p->flags & RZ_PRINT_FLAGS_COLOR;
	const char *color_0x00 = "";
	const char *color_0x7f = "";
	const char *color_0xff = "";
	const char *color_text = "";
	const char *color_other = "";
	int bs = p->bytespace;
	/* XXX That is hacky but it partially works */
	/* TODO: Use rz_print_set_cursor for win support */
	int cur = RZ_MIN(p->cur, p->ocur);
	int ocur = RZ_MAX(p->cur, p->ocur);
	int ch, i;

	if (colors) {
#define P(x) (p->cons && p->cons->context->pal.x) ? p->cons->context->pal.x
		color_0x00 = P(b0x00)
		    : Color_GREEN;
		color_0x7f = P(b0x7f)
		    : Color_YELLOW;
		color_0xff = P(b0xff)
		    : Color_RED;
		color_text = P(btext)
		    : Color_MAGENTA;
		color_other = P(other)
		    : "";
	}
	if (p->cur_enabled && cur == -1) {
		cur = ocur;
	}
	ocur++;
	d = dst;
// XXX: overflow here
// TODO: Use rz_cons primitives here
#define memcat(x, y) \
	{ \
		memcpy(x, y, strlen(y)); \
		(x) += strlen(y); \
	}
	for (s = str, i = 0; s[0]; i++) {
		int d_inc = 2;
		if (p->cur_enabled) {
			if (i == ocur - n) {
				memcat(d, Color_RESET);
			}
			if (colors) {
				memcat(d, lastcol);
			}
			if (i >= cur - n && i < ocur - n) {
				memcat(d, Color_INVERT);
			}
		}
		if (colors) {
			if (s[0] == '0' && s[1] == '0') {
				lastcol = color_0x00;
			} else if (s[0] == '7' && s[1] == 'f') {
				lastcol = color_0x7f;
			} else if (s[0] == 'f' && s[1] == 'f') {
				lastcol = color_0xff;
			} else {
				ch = rz_hex_pair2bin(s);
				if (ch == -1) {
					break;
				}
				if (IS_PRINTABLE(ch)) {
					lastcol = color_text;
				} else {
					lastcol = color_other;
				}
			}
			memcat(d, lastcol);
		}
		if (s[0] == '.') {
			d_inc = 1;
		}
		memcpy(d, s, d_inc);
		d += d_inc;
		s += d_inc;
		if (bs) {
			memcat(d, " ");
		}
	}
	if (colors || p->cur_enabled) {
		if (p->resetbg) {
			memcat(d, Color_RESET);
		} else {
			memcat(d, Color_RESET_NOBG);
		}
	}
	*d = '\0';
	return dst;
}

#define P(x) (p->cons && p->cons->context->pal.x) ? p->cons->context->pal.x
RZ_API const char *rz_print_byte_color(RzPrint *p, int ch) {
	const bool use_color = p->flags & RZ_PRINT_FLAGS_COLOR;
	if (!use_color) {
		return NULL;
	}
	switch (ch) {
	case 0x00: return P(b0x00)
	    : Color_GREEN;
	case 0x7F: return P(b0x7f)
	    : Color_YELLOW;
	case 0xFF: return P(b0xff)
	    : Color_RED;
	default: return IS_PRINTABLE(ch) ? P(btext) : Color_MAGENTA : P(other)
	    : Color_WHITE;
	}
	return NULL;
}

static bool checkSparse(const ut8 *p, int len, int ch) {
	int i;
	ut8 q = *p;
	if (ch && ch != q) {
		return false;
	}
	for (i = 1; i < len; i++) {
		if (p[i] != q) {
			return false;
		}
	}
	return true;
}

static bool isAllZeros(const ut8 *buf, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != 0) {
			return false;
		}
	}
	return true;
}

#define Pal(x, y) (x->cons && x->cons->context->pal.y) ? x->cons->context->pal.y
RZ_API void rz_print_hexii(RzPrint *rp, ut64 addr, const ut8 *buf, int len, int step) {
	PrintfCallback p = (PrintfCallback)rp->cb_printf;
	bool c = rp->flags & RZ_PRINT_FLAGS_COLOR;
	const char *color_0xff = c ? (Pal(rp, b0xff)
					     : Color_RED)
				   : "";
	const char *color_text = c ? (Pal(rp, btext)
					     : Color_MAGENTA)
				   : "";
	const char *color_other = c ? (Pal(rp, other)
					      : Color_WHITE)
				    : "";
	const char *color_reset = c ? Color_RESET : "";
	int i, j;
	bool show_offset = rp->show_offset;

	if (rp->flags & RZ_PRINT_FLAGS_HEADER) {
		p("         ");
		for (i = 0; i < step; i++) {
			p("%3X", i);
		}
		p("\n");
	}

	for (i = 0; i < len; i += step) {
		int inc = RZ_MIN(step, (len - i));
		if (isAllZeros(buf + i, inc)) {
			continue;
		}
		if (show_offset) {
			p("%8" PFMT64x ":", addr + i);
		}
		for (j = 0; j < inc; j++) {
			ut8 ch = buf[i + j];
			if (ch == 0x00) {
				p("   ");
			} else if (ch == 0xff) {
				p("%s ##%s", color_0xff, color_reset);
			} else if (IS_PRINTABLE(ch)) {
				p("%s .%c%s", color_text, ch, color_reset);
			} else {
				p("%s %02x%s", color_other, ch, color_reset);
			}
		}
		p("\n");
	}
	p("%8" PFMT64x " ]\n", addr + i);
}

/**
 * \brief Sets screen_bounds member of \p p to \p addr if the cursor is not visible on the screen.
 * \param p RzPrint instance
 * \param addr Address to set screen_bounds if not visible
 *
 * This function will only calculate the screen_bounds if the current value of screen_bounds is 1.
 * It caches the number of rows visible on the first call to this function. The cache is invalidated when
 * screen_bounds is set.
 */
RZ_API void rz_print_set_screenbounds(RzPrint *p, ut64 addr) {
	rz_return_if_fail(p);

	if (!p->screen_bounds) {
		return;
	}
	if (!p->consbind.get_size) {
		return;
	}
	if (!p->consbind.get_cursor) {
		return;
	}

	if (p->screen_bounds == 1) {
		int rc;
		if (!p->rows) {
			(void)p->consbind.get_size(&p->rows);
		}
		(void)p->consbind.get_cursor(&rc);

		if (rc > p->rows - 1) {
			p->screen_bounds = addr;
			p->rows = 0;
		}
	}
}

static inline void print_addr(RzStrBuf *sb, RzPrint *p, ut64 addr) {
	char space[32] = {
		0
	};
	const char *white = "";
	char *allocated = NULL;
#define PREOFF(x) (p && p->cons && p->cons->context && p->cons->context->pal.x) ? p->cons->context->pal.x
	bool use_segoff = p ? (p->flags & RZ_PRINT_FLAGS_SEGOFF) : false;
	bool use_color = p ? (p->flags & RZ_PRINT_FLAGS_COLOR) : false;
	bool dec = p ? (p->flags & RZ_PRINT_FLAGS_ADDRDEC) : false;
	bool mod = p ? (p->flags & RZ_PRINT_FLAGS_ADDRMOD) : false;
	char ch = p ? ((p->addrmod && mod) ? ((addr % p->addrmod) ? ' ' : ',') : ' ') : ' ';
	if (p && p->flags & RZ_PRINT_FLAGS_COMPACT && p->col == 1) {
		ch = '|';
	}
	if (p && p->pava) {
		ut64 va = p->iob.p2v(p->iob.io, addr);
		if (va != UT64_MAX) {
			addr = va;
		}
	}
	if (use_segoff) {
		ut32 s, a;
		a = addr & 0xffff;
		s = (addr - a) >> (p ? p->seggrn : 0);
		if (dec) {
			rz_strf(space, "%d:%d", s & 0xffff, a & 0xffff);
			white = allocated = rz_str_pad(' ', 9 - strlen(space));
		}
		if (use_color) {
			const char *pre = PREOFF(offset)
			    : Color_GREEN;
			const char *fin = Color_RESET;
			if (dec) {
				rz_strbuf_appendf(sb, "%s%s%s%s%c", pre, white, space, fin, ch);
			} else {
				rz_strbuf_appendf(sb, "%s%04x:%04x%s%c", pre, s & 0xffff, a & 0xffff, fin, ch);
			}
		} else {
			if (dec) {
				rz_strbuf_appendf(sb, "%s%s%c", white, space, ch);
			} else {
				rz_strbuf_appendf(sb, "%04x:%04x%c", s & 0xffff, a & 0xffff, ch);
			}
		}
	} else {
		if (dec) {
			rz_strf(space, "%" PFMT64d, addr);
			int w = RZ_MAX(10 - strlen(space), 0);
			white = allocated = rz_str_pad(' ', w);
		}
		if (use_color) {
			const char *pre = PREOFF(offset)
			    : Color_GREEN;
			const char *fin = Color_RESET;
			if (dec) {
				rz_strbuf_appendf(sb, "%s%s%" PFMT64d "%s%c", pre, white, addr, fin, ch);
			} else {
				if (p && p->wide_offsets) {
					// TODO: make %016 depend on asm.bits
					rz_strbuf_appendf(sb, "%s0x%016" PFMT64x "%s%c", pre, addr, fin, ch);
				} else {
					rz_strbuf_appendf(sb, "%s0x%08" PFMT64x "%s%c", pre, addr, fin, ch);
				}
			}
		} else {
			if (dec) {
				rz_strbuf_appendf(sb, "%s%" PFMT64d "%c", white, addr, ch);
			} else {
				if (p && p->wide_offsets) {
					// TODO: make %016 depend on asm.bits
					rz_strbuf_appendf(sb, "0x%016" PFMT64x "%c", addr, ch);
				} else {
					rz_strbuf_appendf(sb, "0x%08" PFMT64x "%c", addr, ch);
				}
			}
		}
	}
	free(allocated);
}

RZ_API void rz_print_addr(RzPrint *p, ut64 addr) {
	rz_return_if_fail(p);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	print_addr(&sb, p, addr);
	char *s = rz_strbuf_drain_nofree(&sb);
	p->cb_printf("%s", s);
	free(s);
}

static inline void print_section(RzStrBuf *sb, RzPrint *p, ut64 at) {
	bool use_section = p && p->flags & RZ_PRINT_FLAGS_SECTION;
	if (!use_section) {
		return;
	}
	const char *s = p->get_section_name(p->user, at);
	if (!s) {
		s = "";
	}
	rz_strbuf_appendf(sb, "%20s ", s);
}

RZ_API char *rz_print_section_str(RzPrint *p, ut64 at) {
	rz_return_val_if_fail(p, NULL);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	print_section(&sb, p, at);
	return rz_strbuf_drain_nofree(&sb);
}

static inline void print_cursor_l(RzStrBuf *sb, RzPrint *p, int cur, int len) {
	if (rz_print_have_cursor(p, cur, len)) {
		rz_strbuf_append(sb, RZ_CONS_INVERT(1, 1));
	}
}

static inline void print_cursor_r(RzStrBuf *sb, RzPrint *p, int cur, int len) {
	if (rz_print_have_cursor(p, cur, len)) {
		rz_strbuf_append(sb, RZ_CONS_INVERT(0, 1));
	}
}

static inline void print_byte(RzStrBuf *sb, RzPrint *p, const char *fmt, int idx, ut8 ch) {
	ut8 rch = ch;
	if (!IS_PRINTABLE(ch) && fmt[0] == '%' && fmt[1] == 'c') {
		rch = '.';
	}
	print_cursor_l(sb, p, idx, 1);
	if (p && p->flags & RZ_PRINT_FLAGS_COLOR) {
		const char *bytecolor = rz_print_byte_color(p, ch);
		if (bytecolor) {
			rz_strbuf_append(sb, bytecolor);
		}
		rz_strbuf_appendf(sb, fmt, rch);
		if (bytecolor) {
			rz_strbuf_append(sb, Color_RESET);
		}
	} else {
		rz_strbuf_appendf(sb, fmt, rch);
	}
	print_cursor_r(sb, p, idx, 1);
}

RZ_API void rz_print_byte(RzPrint *p, const char *fmt, int idx, ut8 ch) {
	rz_return_if_fail(p && fmt);
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	print_byte(&sb, p, fmt, idx, ch);
	char *s = rz_strbuf_drain_nofree(&sb);
	p->cb_printf("%s", s);
	free(s);
}

/**
 * \brief Prints a hexdump of \p buf at \p addr.
 * \param p RzPrint instance
 * \param addr Address of the buffer
 * \param buf Buffer to print
 * \param len Print only this many bytes
 * \param base Byte print format ? (-10,-1,8,10,16,32,64)
 * \param step Word size ?
 * \param zoomsz Zoom size ?
 * \return Hexdump string
 */
RZ_API RZ_OWN char *rz_print_hexdump_str(RZ_NONNULL RzPrint *p, ut64 addr, RZ_NONNULL const ut8 *buf,
	int len, int base, int step, size_t zoomsz) {
	rz_return_val_if_fail(p && buf && len > 0, NULL);
	RzStrBuf *sb = rz_strbuf_new(NULL);
	if (!sb) {
		return NULL;
	}
	bool pairs = p->pairs;
	bool use_sparse = p->flags & RZ_PRINT_FLAGS_SPARSE;
	bool use_header = p->flags & RZ_PRINT_FLAGS_HEADER;
	bool use_hdroff = p->flags & RZ_PRINT_FLAGS_HDROFF;
	bool use_segoff = p->flags & RZ_PRINT_FLAGS_SEGOFF;
	bool use_align = p->flags & RZ_PRINT_FLAGS_ALIGN;
	bool use_offset = p->flags & RZ_PRINT_FLAGS_OFFSET;
	bool hex_style = p->flags & RZ_PRINT_FLAGS_STYLE;
	bool use_hexa = !(p->flags & RZ_PRINT_FLAGS_NONHEX);
	bool use_unalloc = p->flags & RZ_PRINT_FLAGS_UNALLOC;
	bool compact = p->flags & RZ_PRINT_FLAGS_COMPACT;
	int inc = p->cols; // row width
	int col = p->col; // selected column (0=none, 1=hex, 2=ascii)
	int stride = p->stride;

	size_t i, j;
	int sparse_char = 0;
	const char *bytefmt = "%02x";
	const char *pre = "";
	int last_sparse = 0;
	const char *a, *b;

	if (step < len) {
		len = len - (len % step);
	}
	if (!use_hexa) {
		inc *= 4;
	}
	if (step < 1) {
		step = 1;
	}
	if (inc < 1) {
		inc = 1;
	}
	if (zoomsz < 1) {
		zoomsz = 1;
	}
	switch (base) {
	case -10:
		bytefmt = "0x%08x ";
		pre = " ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case -1:
		bytefmt = "0x%08x ";
		pre = "  ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case 8:
		bytefmt = "%03o";
		pre = " ";
		break;
	case 10:
		bytefmt = "%3d";
		pre = " ";
		break;
	case 16:
		if (inc < 2) {
			inc = 2;
			use_header = false;
		}
		break;
	case 32:
		bytefmt = "0x%08x ";
		pre = " ";
		if (inc < 4) {
			inc = 4;
		}
		break;
	case 64:
		bytefmt = "0x%016x ";
		pre = " ";
		if (inc < 8) {
			inc = 8;
		}
		break;
	}
	const char *space = hex_style ? "." : " ";
	// TODO: Use base to change %03o and so on
	if (step == 1 && base < 0) {
		use_header = false;
	}
	if (use_header) {
		bool c = p->flags & RZ_PRINT_FLAGS_COLOR;
		if (c) {
			const char *color_title = Pal(p, offset)
			    : Color_MAGENTA;
			rz_strbuf_append(sb, color_title);
		}
		if (base < 32) {
			{ // XXX: use rz_print_addr_header
				int i, delta;
				char soff[32];
				if (hex_style) {
					rz_strbuf_append(sb, "..offset..");
				} else {
					rz_strbuf_append(sb, "- offset -");
					if (p->wide_offsets) {
						rz_strbuf_append(sb, "       ");
					}
				}
				if (use_segoff) {
					ut32 s, a;
					a = addr & 0xffff;
					s = ((addr - a) >> p->seggrn) & 0xffff;
					snprintf(soff, sizeof(soff), "%04x:%04x ", s, a);
					delta = strlen(soff) - 10;
				} else {
					snprintf(soff, sizeof(soff), "0x%08" PFMT64x, addr);
					delta = strlen(soff) - 9;
				}
				if (compact) {
					delta--;
				}
				for (i = 0; i < delta; i++) {
					rz_strbuf_append(sb, space);
				}
			}
			ut32 K = 0;
			ut32 k = 0;
			/* column after number, before hex data */
			rz_strbuf_append(sb, (col == 1) ? "|" : space);
			if (use_hdroff) {
				k = addr & 0xf;
				K = (addr >> 4) & 0xf;
			} else {
				k = 0; // TODO: ??? SURE??? config.seek & 0xF;
			}
			if (use_hexa) {
				/* extra padding for offsets > 8 digits */
				for (i = 0; i < inc; i++) {
					rz_strbuf_append(sb, pre);
					if (base < 0) {
						if (i & 1) {
							rz_strbuf_append(sb, space);
						}
					}
					if (use_hdroff) {
						if (pairs) {
							rz_strbuf_appendf(sb, "%c%c",
								hex[(((i + k) >> 4) + K) % 16],
								hex[(i + k) % 16]);
						} else {
							rz_strbuf_appendf(sb, " %c", hex[(i + k) % 16]);
						}
					} else {
						rz_strbuf_appendf(sb, " %c", hex[(i + k) % 16]);
					}
					if (i & 1 || !pairs) {
						if (!compact) {
							rz_strbuf_append(sb, col != 1 ? space : ((i + 1) < inc) ? space
														: "|");
						}
					}
				}
			}
			/* ascii column */
			if (compact) {
				rz_strbuf_append(sb, col > 0 ? "|" : space);
			} else {
				rz_strbuf_append(sb, col == 2 ? "|" : space);
			}
			if (!(p->flags & RZ_PRINT_FLAGS_NONASCII)) {
				for (i = 0; i < inc; i++) {
					rz_strbuf_appendf(sb, "%c", hex[(i + k) % 16]);
				}
			}
			if (col == 2) {
				rz_strbuf_append(sb, "|");
			}
			/* print comment header*/
			if (p->use_comments && !compact) {
				if (col != 2) {
					rz_strbuf_append(sb, " ");
				}
				if (!hex_style) {
					rz_strbuf_append(sb, " comment");
				}
			}
			rz_strbuf_append(sb, "\n");
		}

		if (c) {
			rz_strbuf_append(sb, Color_RESET);
		}
	}

	// is this necessary?
	rz_print_set_screenbounds(p, addr);
	int rowbytes;
	int rows = 0;
	int bytes = 0;
	bool printValue = true;
	bool oPrintValue = true;
	bool isPxr = p->flags & RZ_PRINT_FLAGS_REFS;

	for (i = j = 0; i < len; i += (stride ? stride : inc)) {
		if (p->cons && p->cons->context && p->cons->context->breaked) {
			break;
		}
		rowbytes = inc;
		if (use_align) {
			int sz = p->offsize ? p->offsize(p->user, addr + j) : -1;
			if (sz > 0) { // flags with size 0 dont work
				rowbytes = sz;
			}
		}

		if (use_sparse) {
			if (checkSparse(buf + i, inc, sparse_char)) {
				if (i + inc >= len || checkSparse(buf + i + inc, inc, sparse_char)) {
					if (i + inc + inc >= len ||
						checkSparse(buf + i + inc + inc, inc, sparse_char)) {
						sparse_char = buf[j];
						last_sparse++;
						if (last_sparse == 2) {
							rz_strbuf_append(sb, " ...\n");
							continue;
						}
						if (last_sparse > 2) {
							continue;
						}
					}
				}
			} else {
				last_sparse = 0;
			}
		}
		ut64 at = addr + (j * zoomsz);
		if (use_offset && (!isPxr || inc < 4)) {
			print_section(sb, p, at);
			print_addr(sb, p, at);
		}
		int row_have_cursor = -1;
		ut64 row_have_addr = UT64_MAX;
		if (use_hexa) {
			if (!compact && !isPxr) {
				rz_strbuf_append(sb, (col == 1) ? "|" : " ");
			}
			for (j = i; j < i + inc; j++) {
				if (j != i && use_align && rowbytes == inc) {
					int sz = p->offsize ? p->offsize(p->user, addr + j) : -1;
					if (sz >= 0) {
						rowbytes = bytes;
					}
				}
				if (row_have_cursor == -1) {
					if (rz_print_cursor_pointer(p, j, 1)) {
						row_have_cursor = j - i;
						row_have_addr = addr + j;
					}
				}
				if (!compact && ((j >= len) || bytes >= rowbytes)) {
					if (col == 1) {
						if (j + 1 >= inc + i) {
							rz_strbuf_append(sb, j % 2 ? "  |" : "| ");
						} else {
							rz_strbuf_append(sb, j % 2 ? "   " : "  ");
						}
					} else {
						if (base == 32) {
							rz_strbuf_append(sb, (j % 4) ? "   " : "  ");
						} else if (base == 10) {
							rz_strbuf_append(sb, j % 2 ? "     " : "  ");
						} else {
							rz_strbuf_append(sb, j % 2 ? "   " : "  ");
						}
					}
					continue;
				}
				const char *hl = (hex_style && p->offname(p->user, addr + j)) ? Color_INVERT : NULL;
				if (hl) {
					rz_strbuf_append(sb, hl);
				}
				if ((base == 32 || base == 64)) {
					int left = len - i;
					/* TODO: check step. it should be 2/4 for base(32) and 8 for
					 *       base(64) */
					size_t sz_n = (base == 64)
						? sizeof(ut64)
						: (step == 2)
						? sizeof(ut16)
						: sizeof(ut32);
					sz_n = RZ_MIN(left, sz_n);
					if (j + sz_n > len) {
						// oob
						j += sz_n;
						continue;
					}
					ut64 n = rz_read_ble(buf + j, p->big_endian, sz_n * 8);
					print_cursor_l(sb, p, j, sz_n);
					// stub for colors
					if (p->colorfor) {
						if (!p->iob.addr_is_mapped(p->iob.io, addr + j)) {
							a = p->cons->context->pal.ai_unmap;
						} else {
							a = p->colorfor(p->user, n, true);
						}
						if (a && *a) {
							b = Color_RESET;
						} else {
							a = b = "";
						}
					} else {
						a = b = "";
					}
					printValue = true;
					bool hasNull = false;
					if (isPxr) {
						if (n == 0) {
							if (oPrintValue) {
								hasNull = true;
							}
							printValue = false;
						}
					}
					if (printValue) {
						if (use_offset && !hasNull && isPxr) {
							print_section(sb, p, at);
							print_addr(sb, p, addr + j * zoomsz);
						}
						if (base == 64) {
							rz_strbuf_appendf(sb, "%s0x%016" PFMT64x "%s  ", a, (ut64)n, b);
						} else if (step == 2) {
							rz_strbuf_appendf(sb, "%s0x%04x%s ", a, (ut16)n, b);
						} else {
							rz_strbuf_appendf(sb, "%s0x%08x%s ", a, (ut32)n, b);
						}
					} else {
						if (hasNull) {
							const char *n = p->offname(p->user, addr + j);
							print_section(sb, p, at);
							print_addr(sb, p, addr + j * zoomsz);
							rz_strbuf_appendf(sb, "..[ null bytes ]..   00000000 %s\n", n ? n : "");
						}
					}
					print_cursor_r(sb, p, j, sz_n);
					oPrintValue = printValue;
					j += step - 1;
				} else if (base == -8) {
					long long w = rz_read_ble64(buf + j, p->big_endian);
					print_cursor_l(sb, p, j, 8);
					rz_strbuf_appendf(sb, "%23" PFMT64d " ", w);
					print_cursor_r(sb, p, j, 8);
					j += 7;
				} else if (base == -1) {
					st8 w = rz_read_ble8(buf + j);
					print_cursor_l(sb, p, j, 1);
					rz_strbuf_appendf(sb, "%4d ", w);
					print_cursor_r(sb, p, j, 1);
				} else if (base == -10) {
					if (j + 1 < len) {
						st16 w = rz_read_ble16(buf + j, p->big_endian);
						print_cursor_l(sb, p, j, 2);
						rz_strbuf_appendf(sb, "%7d ", w);
						print_cursor_r(sb, p, j, 2);
					}
					j += 1;
				} else if (base == 10) { // "pxd"
					if (j + 3 < len) {
						int w = rz_read_ble32(buf + j, p->big_endian);
						print_cursor_l(sb, p, j, 4);
						rz_strbuf_appendf(sb, "%13d ", w);
						print_cursor_r(sb, p, j, 4);
					}
					j += 3;
				} else {
					if (j >= len) {
						break;
					}
					if (use_unalloc && !p->iob.is_valid_offset(p->iob.io, addr + j, false)) {
						char ch = p->io_unalloc_ch;
						char dbl_ch_str[] = { ch, ch, 0 };
						rz_strbuf_appendf(sb, "%s", dbl_ch_str);
					} else {
						print_byte(sb, p, bytefmt, j, buf[j]);
					}
					if (pairs && !compact && (inc & 1)) {
						bool mustspace = (rows % 2) ? !(j & 1) : (j & 1);
						if (mustspace) {
							rz_strbuf_append(sb, " ");
						}
					} else if (bytes % 2 || !pairs) {
						if (col == 1) {
							if (j + 1 < inc + i) {
								if (!compact) {
									rz_strbuf_append(sb, " ");
								}
							} else {
								rz_strbuf_append(sb, "|");
							}
						} else {
							if (!compact) {
								rz_strbuf_append(sb, " ");
							}
						}
					}
				}
				if (hl) {
					rz_strbuf_append(sb, Color_RESET);
				}
				bytes++;
			}
		}
		if (printValue) {
			if (compact) {
				if (col == 0) {
					rz_strbuf_append(sb, " ");
				} else if (col == 1) {
					// print (" ");
				} else {
					rz_strbuf_append(sb, (col == 2) ? "|" : "");
				}
			} else {
				rz_strbuf_append(sb, (col == 2) ? "|" : " ");
			}
			if (!p || !(p->flags & RZ_PRINT_FLAGS_NONASCII)) {
				bytes = 0;
				size_t end = i + inc;
				for (j = i; j < end; j++) {
					if (j != i && use_align && bytes >= rowbytes) {
						int sz = (p->offsize) ? p->offsize(p->user, addr + j) : -1;
						if (sz >= 0) {
							rz_strbuf_append(sb, " ");
							break;
						}
					}
					if (j >= len || (use_align && bytes >= rowbytes)) {
						break;
					}
					ut8 ch = (use_unalloc && !p->iob.is_valid_offset(p->iob.io, addr + j, false))
						? ' '
						: buf[j];
					print_byte(sb, p, "%c", j, ch);
					bytes++;
				}
			}
			/* ascii column */
			if (col == 2) {
				rz_strbuf_append(sb, "|");
			}
			bool eol = false;
			if (!eol && p->flags & RZ_PRINT_FLAGS_REFS) {
				ut64 off = UT64_MAX;
				if (inc == 8) {
					if (i + sizeof(ut64) - 1 < len) {
						off = rz_read_le64(buf + i);
					}
				} else if (inc == 4) {
					if (i + sizeof(ut32) - 1 < len) {
						off = rz_read_le32(buf + i);
					}
				} else if (inc == 2 && base == 16) {
					if (i + sizeof(ut16) - 1 < len) {
						off = rz_read_le16(buf + i);
						if (off == 0) {
							off = UT64_MAX;
						}
					}
				}
				if (p->hasrefs && off != UT64_MAX) {
					char *rstr = p->hasrefs(p->user, addr + i, false);
					if (rstr && *rstr) {
						rz_strbuf_appendf(sb, " @ %s", rstr);
					}
					free(rstr);
					rstr = p->hasrefs(p->user, off, true);
					if (rstr && *rstr) {
						rz_strbuf_appendf(sb, " %s", rstr);
					}
					free(rstr);
				}
			}
			if (!eol && p->use_comments) {
				for (; j < i + inc; j++) {
					rz_strbuf_append(sb, " ");
				}
				for (j = i; j < i + inc; j++) {
					if (use_align && (j - i) >= rowbytes) {
						break;
					}
					if (p->offname) {
						a = p->offname(p->user, addr + j);
						if (p->colorfor && a && *a) {
							const char *color = p->colorfor(p->user, addr + j, true);
							rz_strbuf_appendf(sb, "%s  ; %s%s", color ? color : "", a,
								color ? Color_RESET : "");
						}
					}
					char *comment = p->get_comments(p->user, addr + j);
					if (comment) {
						if (p->colorfor) {
							a = p->colorfor(p->user, addr + j, true);
							if (!a || !*a) {
								a = "";
							}
						} else {
							a = "";
						}
						rz_strbuf_appendf(sb, "%s  ; %s", a, comment);
						free(comment);
					}
				}
			}
			if (use_align && rowbytes < inc && bytes >= rowbytes) {
				i -= (inc - bytes);
			}
			rz_strbuf_append(sb, "\n");
		}
		rows++;
		bytes = 0;
		if (p->cfmt && *p->cfmt) {
			if (row_have_cursor != -1) {
				int i = 0;
				rz_strbuf_append(sb, " _________");
				if (!compact) {
					rz_strbuf_append(sb, "_");
				}
				for (i = 0; i < row_have_cursor; i++) {
					if (!pairs || (!compact && i % 2)) {
						rz_strbuf_append(sb, "___");
					} else {
						rz_strbuf_append(sb, "__");
					}
				}
				rz_strbuf_append(sb, "__|\n");
				rz_strbuf_appendf(sb, "| cmd.hexcursor = %s\n", p->cfmt);
				p->coreb.cmdf(p->coreb.core,
					"%s @ 0x%08" PFMT64x, p->cfmt, row_have_addr);
			}
		}
	}
	return rz_strbuf_drain(sb);
}

static const char *getbytediff(RzPrint *p, char *fmt, ut8 a, ut8 b) {
	if (*fmt) {
		if (a == b) {
			sprintf(fmt, "%s%02x" Color_RESET, p->cons->context->pal.graph_true, a);
		} else {
			sprintf(fmt, "%s%02x" Color_RESET, p->cons->context->pal.graph_false, a);
		}
	} else {
		sprintf(fmt, "%02x", a);
	}
	return fmt;
}

static const char *getchardiff(RzPrint *p, char *fmt, ut8 a, ut8 b) {
	char ch = IS_PRINTABLE(a) ? a : '.';
	if (*fmt) {
		if (a == b) {
			sprintf(fmt, "%s%c" Color_RESET, p->cons->context->pal.graph_true, ch);
		} else {
			sprintf(fmt, "%s%c" Color_RESET, p->cons->context->pal.graph_false, ch);
		}
	} else {
		sprintf(fmt, "%c", ch);
	}
	// else { fmt[0] = ch; fmt[1]=0; }
	return fmt;
}

#define BD(a, b) getbytediff(p, fmt, (a)[i + j], (b)[i + j])
#define CD(a, b) getchardiff(p, fmt, (a)[i + j], (b)[i + j])

static ut8 *M(const ut8 *b, int len) {
	ut8 *r = malloc(len + 16);
	if (r) {
		memset(r, 0xff, len + 16);
		memcpy(r, b, len);
	}
	return r;
}

/**
 * \brief Print hexdump diff between \p _a and \p _b.
 * \param p RzPrint instance.
 * \param aa Address of first buffer.
 * \param _a First buffer.
 * \param ba Address of second buffer.
 * \param _b Second buffer.
 * \param len Diff length.
 * \param scndcol True If core->cons->columns > 123 ?
 * \return Hexdump diff string.
 */
// TODO: add support for cursor
RZ_API RZ_OWN char *rz_print_hexdiff_str(RZ_NONNULL RzPrint *p, ut64 aa, RZ_NONNULL const ut8 *_a,
	ut64 ba, RZ_NONNULL const ut8 *_b, int len, int scndcol) {
	rz_return_val_if_fail(p && _a && _b && len > 0, NULL);
	ut8 *a, *b;
	char linediff, fmt[64];
	int color = p->flags & RZ_PRINT_FLAGS_COLOR;
	int diffskip = p->flags & RZ_PRINT_FLAGS_DIFFOUT;
	int i, j, min;
	if (!((a = M(_a, len)))) {
		return NULL;
	}
	if (!((b = M(_b, len)))) {
		free(a);
		return NULL;
	}
	RzStrBuf *sb = rz_strbuf_new(NULL);
	for (i = 0; i < len; i += 16) {
		min = RZ_MIN(16, len - i);
		linediff = (memcmp(a + i, b + i, min)) ? '!' : '|';
		if (diffskip && linediff == '|') {
			continue;
		}
		rz_strbuf_appendf(sb, "0x%08" PFMT64x " ", aa + i);
		for (j = 0; j < min; j++) {
			*fmt = color;
			print_cursor_l(sb, p, i + j, 1);
			rz_strbuf_appendf(sb, "%s", BD(a, b));
			print_cursor_r(sb, p, i + j, 1);
		}
		rz_strbuf_append(sb, " ");
		for (j = 0; j < min; j++) {
			*fmt = color;
			print_cursor_l(sb, p, i + j, 1);
			rz_strbuf_appendf(sb, "%s", CD(a, b));
			print_cursor_r(sb, p, i + j, 1);
		}
		if (scndcol) {
			rz_strbuf_appendf(sb, " %c 0x%08" PFMT64x " ", linediff, ba + i);
			for (j = 0; j < min; j++) {
				*fmt = color;
				print_cursor_r(sb, p, i + j, 1);
				rz_strbuf_appendf(sb, "%s", BD(b, a));
				print_cursor_r(sb, p, i + j, 1);
			}
			rz_strbuf_append(sb, " ");
			for (j = 0; j < min; j++) {
				*fmt = color;
				print_cursor_r(sb, p, i + j, 1);
				rz_strbuf_appendf(sb, "%s", CD(b, a));
				print_cursor_r(sb, p, i + j, 1);
			}
			rz_strbuf_append(sb, "\n");
		} else {
			rz_strbuf_appendf(sb, " %c\n", linediff);
		}
	}
	free(a);
	free(b);
	return rz_strbuf_drain(sb);
}

RZ_API void rz_print_bytes(RzPrint *p, const ut8 *buf, int len, const char *fmt) {
	rz_return_if_fail(fmt);
	int i;
	if (p) {
		for (i = 0; i < len; i++) {
			p->cb_printf(fmt, buf[i]);
		}
		p->cb_printf("\n");
	} else {
		for (i = 0; i < len; i++) {
			printf(fmt, buf[i]);
		}
		printf("\n");
	}
}

RZ_API void rz_print_raw(RzPrint *p, ut64 addr, const ut8 *buf, int len) {
	p->write(buf, len);
}

/* TODO: handle screen width */
// Probably move somewhere else. RzPrint doesn't need to know about the RZ_ANALYSIS_ enums
RZ_API const char *rz_print_color_op_type(RZ_NONNULL RzPrint *p, ut32 /* RzAnalaysisOpType */ analysis_type) {
	rz_return_val_if_fail(p, NULL);
	RzConsPrintablePalette *pal = &p->cons->context->pal;
	switch (analysis_type & RZ_ANALYSIS_OP_TYPE_MASK) {
	case RZ_ANALYSIS_OP_TYPE_NOP:
		return pal->nop;
	case RZ_ANALYSIS_OP_TYPE_ADD:
	case RZ_ANALYSIS_OP_TYPE_SUB:
	case RZ_ANALYSIS_OP_TYPE_MUL:
	case RZ_ANALYSIS_OP_TYPE_DIV:
	case RZ_ANALYSIS_OP_TYPE_MOD:
	case RZ_ANALYSIS_OP_TYPE_LENGTH:
		return pal->math;
	case RZ_ANALYSIS_OP_TYPE_AND:
	case RZ_ANALYSIS_OP_TYPE_OR:
	case RZ_ANALYSIS_OP_TYPE_XOR:
	case RZ_ANALYSIS_OP_TYPE_NOT:
	case RZ_ANALYSIS_OP_TYPE_SHL:
	case RZ_ANALYSIS_OP_TYPE_SAL:
	case RZ_ANALYSIS_OP_TYPE_SAR:
	case RZ_ANALYSIS_OP_TYPE_SHR:
	case RZ_ANALYSIS_OP_TYPE_ROL:
	case RZ_ANALYSIS_OP_TYPE_ROR:
	case RZ_ANALYSIS_OP_TYPE_CPL:
		return pal->bin;
	case RZ_ANALYSIS_OP_TYPE_IO:
		return pal->swi;
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
		return pal->ujmp;
	case RZ_ANALYSIS_OP_TYPE_IJMP:
	case RZ_ANALYSIS_OP_TYPE_RJMP:
	case RZ_ANALYSIS_OP_TYPE_IRJMP:
	case RZ_ANALYSIS_OP_TYPE_MJMP:
		return pal->jmp;
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_UCJMP:
	case RZ_ANALYSIS_OP_TYPE_SWITCH:
		return pal->cjmp;
	case RZ_ANALYSIS_OP_TYPE_CMP:
	case RZ_ANALYSIS_OP_TYPE_ACMP:
		return pal->cmp;
	case RZ_ANALYSIS_OP_TYPE_UCALL:
		return pal->ucall;
	case RZ_ANALYSIS_OP_TYPE_ICALL:
	case RZ_ANALYSIS_OP_TYPE_RCALL:
	case RZ_ANALYSIS_OP_TYPE_IRCALL:
	case RZ_ANALYSIS_OP_TYPE_UCCALL:
	case RZ_ANALYSIS_OP_TYPE_CALL:
	case RZ_ANALYSIS_OP_TYPE_CCALL:
		return pal->call;
	case RZ_ANALYSIS_OP_TYPE_NEW:
	case RZ_ANALYSIS_OP_TYPE_SWI:
		return pal->swi;
	case RZ_ANALYSIS_OP_TYPE_ILL:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
		return pal->trap;
	case RZ_ANALYSIS_OP_TYPE_CRET:
	case RZ_ANALYSIS_OP_TYPE_RET:
		return pal->ret;
	case RZ_ANALYSIS_OP_TYPE_CAST:
	case RZ_ANALYSIS_OP_TYPE_MOV:
	case RZ_ANALYSIS_OP_TYPE_LEA:
	case RZ_ANALYSIS_OP_TYPE_CMOV: // TODO: add cmov cathegory?
		return pal->mov;
	case RZ_ANALYSIS_OP_TYPE_PUSH:
	case RZ_ANALYSIS_OP_TYPE_UPUSH:
	case RZ_ANALYSIS_OP_TYPE_RPUSH:
	case RZ_ANALYSIS_OP_TYPE_LOAD:
		return pal->push;
	case RZ_ANALYSIS_OP_TYPE_POP:
	case RZ_ANALYSIS_OP_TYPE_STORE:
		return pal->pop;
	case RZ_ANALYSIS_OP_TYPE_CRYPTO:
		return pal->crypto;
	case RZ_ANALYSIS_OP_TYPE_NULL:
		return pal->other;
	case RZ_ANALYSIS_OP_TYPE_UNK:
	default:
		return pal->invalid;
	}
}

// reset the status of row_offsets
RZ_API void rz_print_init_rowoffsets(RzPrint *p) {
	if (p->calc_row_offsets) {
		RZ_FREE(p->row_offsets);
		p->row_offsets_sz = 0;
	}
}

// set the offset, from the start of the printing, of the i-th row
RZ_API void rz_print_set_rowoff(RzPrint *p, int i, ut32 offset, bool overwrite) {
	if (!overwrite) {
		return;
	}
	if (i < 0) {
		return;
	}
	if (!p->row_offsets || !p->row_offsets_sz) {
		p->row_offsets_sz = RZ_MAX(i + 1, DFLT_ROWS);
		p->row_offsets = RZ_NEWS(ut32, p->row_offsets_sz);
	}
	if (i >= p->row_offsets_sz) {
		size_t new_size;
		p->row_offsets_sz *= 2;
		// XXX dangerous
		while (i >= p->row_offsets_sz) {
			p->row_offsets_sz *= 2;
		}
		new_size = sizeof(ut32) * p->row_offsets_sz;
		p->row_offsets = realloc(p->row_offsets, new_size);
	}
	p->row_offsets[i] = offset;
}

// return the offset, from the start of the printing, of the i-th row.
// if the line index is not valid, UT32_MAX is returned.
RZ_API ut32 rz_print_rowoff(RzPrint *p, int i) {
	if (i < 0 || i >= p->row_offsets_sz) {
		return UT32_MAX;
	}
	return p->row_offsets[i];
}

// return the index of the row that contains the given offset or -1 if
// that row doesn't exist.
RZ_API int rz_print_row_at_off(RzPrint *p, ut32 offset) {
	int i = 0;
	ut32 tt;
	while ((tt = rz_print_rowoff(p, i)) != UT32_MAX && tt <= offset) {
		i++;
	}
	return tt != UT32_MAX ? i - 1 : -1;
}

RZ_API int rz_print_get_cursor(RzPrint *p) {
	return p->cur_enabled ? p->cur : 0;
}

/**
 * \brief Print dump in json format
 * \param p RzPrint instance
 * \param buf Buffer to print to
 * \param len Print only this many bytes
 * \param wordsize Size of a word in bits
 * \return Dump JSON string
 */
RZ_API RZ_OWN char *rz_print_jsondump_str(RZ_NONNULL RzPrint *p, RZ_NONNULL const ut8 *buf, int len, int wordsize) {
	rz_return_val_if_fail(p && buf && len > 0 && wordsize > 0, 0);
	int bytesize = wordsize / 8;
	if (bytesize < 1) {
		bytesize = 8;
	}
	PJ *j = pj_new();
	if (!j) {
		return NULL;
	}
	pj_a(j);
	for (int i = 0; i + bytesize <= len; i += bytesize) {
		ut64 word = rz_read_ble(buf + i, p->big_endian, wordsize);
		pj_n(j, word);
	}
	pj_end(j);
	char *str = strdup(pj_string(j));
	pj_free(j);
	return str;
}

/**
 * \brief Colorizes a tokenized asm string.
 *
 * \param p The RzPrint struct. Used to retrieve the color palette.
 * \param toks The tokenized asm string.
 * \param opt Options for colorizing. E.g. reset background color, an address to highlight etc.
 *
 * \return The colorized asm string.
 */
RZ_API RZ_OWN RzStrBuf *rz_print_colorize_asm_str(RZ_BORROW RzPrint *p, const RzAsmTokenString *toks) {
	rz_return_val_if_fail(p && toks, NULL);
	// Color palette.
	RzConsPrintablePalette palette = p->cons->context->pal;
	// Black white asm string.
	char *bw_str = rz_strbuf_get(toks->str);
	rz_return_val_if_fail(bw_str, NULL);
	char *reset = p->colorize_opts.reset_bg ? Color_RESET_NOBG : Color_RESET;
	// mnemonic color
	const char *mnem_col = rz_print_color_op_type(p, toks->op_type);

	RzStrBuf *out = rz_strbuf_new("");
	rz_return_val_if_fail(out, NULL);

	const char *color;
	RzAsmToken *tok;
	rz_vector_foreach (toks->tokens, tok) {
		switch (tok->type) {
		default:
			rz_strbuf_free(out);
			rz_warn_if_reached();
			return NULL;
		case RZ_ASM_TOKEN_UNKNOWN:
			color = palette.other;
			break;
		case RZ_ASM_TOKEN_MNEMONIC:
			color = mnem_col;
			break;
		case RZ_ASM_TOKEN_NUMBER:
			if (tok->val.number == p->colorize_opts.hl_addr && tok->val.number != 0) {
				color = palette.func_var_type;
			} else {
				color = palette.num;
			}
			break;
		case RZ_ASM_TOKEN_OPERATOR:
		case RZ_ASM_TOKEN_SEPARATOR:
			color = palette.other;
			break;
		case RZ_ASM_TOKEN_REGISTER:
			color = palette.reg;
			break;
		case RZ_ASM_TOKEN_META:
			color = palette.meta;
			break;
		}

		rz_strbuf_append(out, color);
		rz_strbuf_append_n(out, bw_str + tok->start, tok->len);
		rz_strbuf_append(out, reset);
	}
	return out;
}

// Prints a help option with the option/arg strings colorized and aligned to a max length.
RZ_API void rz_print_colored_help_option(const char *option, const char *arg, const char *description, size_t maxOptionAndArgLength) {
	size_t optionWidth = strlen(option);
	size_t maxSpaces = maxOptionAndArgLength + 2;
	printf(Color_GREEN " %-.*s" Color_RESET, (int)optionWidth, option);
	size_t remainingSpaces = maxSpaces - optionWidth;
	if (RZ_STR_ISNOTEMPTY(arg)) {
		printf(Color_YELLOW " %-s " Color_RESET, arg);
		remainingSpaces -= strlen(arg) + 2;
	}
	printf("%-*.*s", (int)remainingSpaces, (int)remainingSpaces, "");
	printf(Color_RESET "%s\n", description);
}
