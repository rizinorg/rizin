// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <ctype.h>
#include <rz_util/rz_str.h>
#include <rz_list.h>
#include <rz_regex.h>
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

static int libc_eprintf(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
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
	p->cb_eprintf = libc_eprintf;
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

RZ_API void rz_print_addr(RzPrint *p, ut64 addr) {
	char space[32] = {
		0
	};
	const char *white = "";
#define PREOFF(x) (p && p->cons && p->cons->context && p->cons->context->pal.x) ? p->cons->context->pal.x
	PrintfCallback printfmt = (PrintfCallback)(p ? p->cb_printf : libc_printf);
#define print(x) printfmt("%s", x)
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
			snprintf(space, sizeof(space), "%d:%d", s & 0xffff, a & 0xffff);
			white = rz_str_pad(' ', 9 - strlen(space));
		}
		if (use_color) {
			const char *pre = PREOFF(offset)
			    : Color_GREEN;
			const char *fin = Color_RESET;
			if (dec) {
				printfmt("%s%s%s%s%c", pre, white, space, fin, ch);
			} else {
				printfmt("%s%04x:%04x%s%c", pre, s & 0xffff, a & 0xffff, fin, ch);
			}
		} else {
			if (dec) {
				printfmt("%s%s%c", white, space, ch);
			} else {
				printfmt("%04x:%04x%c", s & 0xffff, a & 0xffff, ch);
			}
		}
	} else {
		if (dec) {
			snprintf(space, sizeof(space), "%" PFMT64d, addr);
			int w = RZ_MAX(10 - strlen(space), 0);
			white = rz_str_pad(' ', w);
		}
		if (use_color) {
			const char *pre = PREOFF(offset)
			    : Color_GREEN;
			const char *fin = Color_RESET;
			if (p && p->flags & RZ_PRINT_FLAGS_RAINBOW) {
				// pre = rz_cons_rgb_str_off (rgbstr, addr);
				if (p->cons && p->cons->rgbstr) {
					static char rgbstr[32];
					pre = p->cons->rgbstr(rgbstr, sizeof(rgbstr), addr);
				}
			}
			if (dec) {
				printfmt("%s%s%" PFMT64d "%s%c", pre, white, addr, fin, ch);
			} else {
				if (p && p->wide_offsets) {
					// TODO: make %016 depend on asm.bits
					printfmt("%s0x%016" PFMT64x "%s%c", pre, addr, fin, ch);
				} else {
					printfmt("%s0x%08" PFMT64x "%s%c", pre, addr, fin, ch);
				}
			}
		} else {
			if (dec) {
				printfmt("%s%" PFMT64d "%c", white, addr, ch);
			} else {
				if (p && p->wide_offsets) {
					// TODO: make %016 depend on asm.bits
					printfmt("0x%016" PFMT64x "%c", addr, ch);
				} else {
					printfmt("0x%08" PFMT64x "%c", addr, ch);
				}
			}
		}
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

static char colorbuffer[64];
#define P(x) (p->cons && p->cons->context->pal.x) ? p->cons->context->pal.x
RZ_API const char *rz_print_byte_color(RzPrint *p, int ch) {
	if (p->flags & RZ_PRINT_FLAGS_RAINBOW) {
		// EXPERIMENTAL
		int bg = (p->flags & RZ_PRINT_FLAGS_NONHEX) ? 48 : 38;
		snprintf(colorbuffer, sizeof(colorbuffer), "\033[%d;5;%dm", bg, ch);
		return colorbuffer;
	}
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

RZ_API void rz_print_byte(RzPrint *p, const char *fmt, int idx, ut8 ch) {
	PrintfCallback printfmt = (PrintfCallback)(p ? p->cb_printf : libc_printf);
#define print(x) printfmt("%s", x)
	ut8 rch = ch;
	if (!IS_PRINTABLE(ch) && fmt[0] == '%' && fmt[1] == 'c') {
		rch = '.';
	}
	rz_print_cursor(p, idx, 1, 1);
	if (p && p->flags & RZ_PRINT_FLAGS_COLOR) {
		const char *bytecolor = rz_print_byte_color(p, ch);
		if (bytecolor) {
			print(bytecolor);
		}
		printfmt(fmt, rch);
		if (bytecolor) {
			print(Color_RESET);
		}
	} else {
		printfmt(fmt, rch);
	}
	rz_print_cursor(p, idx, 1, 0);
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

RZ_API void rz_print_section(RzPrint *p, ut64 at) {
	bool use_section = p && p->flags & RZ_PRINT_FLAGS_SECTION;
	if (use_section) {
		const char *s = p->get_section_name(p->user, at);
		if (!s) {
			s = "";
		}
		char *tail = rz_str_ndup(s, 19);
		p->cb_printf("%20s ", tail);
		free(tail);
	}
}

RZ_API void rz_print_hexdump(RzPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step, size_t zoomsz) {
	rz_return_if_fail(p && buf && len > 0);
	PrintfCallback printfmt = (PrintfCallback)printf;
#define print(x) printfmt("%s", x)
	bool c = p ? (p->flags & RZ_PRINT_FLAGS_COLOR) : false;
	const char *color_title = c ? (Pal(p, offset)
					      : Color_MAGENTA)
				    : "";
	int inc = p ? p->cols : 16;
	size_t i, j, k;
	int sparse_char = 0;
	int stride = 0;
	int col = 0; // selected column (0=none, 1=hex, 2=ascii)
	int use_sparse = 0;
	bool use_header = true;
	bool use_hdroff = true;
	bool use_pair = true;
	bool use_offset = true;
	bool compact = false;
	bool use_segoff = false;
	bool pairs = false;
	const char *bytefmt = "%02x";
	const char *pre = "";
	int last_sparse = 0;
	bool use_hexa = true;
	bool use_align = false;
	bool use_unalloc = false;
	const char *a, *b;
	int K = 0;
	bool hex_style = false;
	if (step < len) {
		len = len - (len % step);
	}
	if (p) {
		pairs = p->pairs;
		use_sparse = p->flags & RZ_PRINT_FLAGS_SPARSE;
		use_header = p->flags & RZ_PRINT_FLAGS_HEADER;
		use_hdroff = p->flags & RZ_PRINT_FLAGS_HDROFF;
		use_segoff = p->flags & RZ_PRINT_FLAGS_SEGOFF;
		use_align = p->flags & RZ_PRINT_FLAGS_ALIGN;
		use_offset = p->flags & RZ_PRINT_FLAGS_OFFSET;
		hex_style = p->flags & RZ_PRINT_FLAGS_STYLE;
		use_hexa = !(p->flags & RZ_PRINT_FLAGS_NONHEX);
		use_unalloc = p->flags & RZ_PRINT_FLAGS_UNALLOC;
		compact = p->flags & RZ_PRINT_FLAGS_COMPACT;
		inc = p->cols; // row width
		col = p->col;
		printfmt = (PrintfCallback)p->cb_printf;
		stride = p->stride;
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
		if (c) {
			print(color_title);
		}
		if (base < 32) {
			{ // XXX: use rz_print_addr_header
				int i, delta;
				char soff[32];
				if (hex_style) {
					print("..offset..");
				} else {
					print("- offset -");
					if (p->wide_offsets) {
						print("       ");
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
					print(space);
				}
			}
			/* column after number, before hex data */
			print((col == 1) ? "|" : space);
			if (use_hdroff) {
				k = addr & 0xf;
				K = (addr >> 4) & 0xf;
			} else {
				k = 0; // TODO: ??? SURE??? config.seek & 0xF;
			}
			if (use_hexa) {
				/* extra padding for offsets > 8 digits */
				for (i = 0; i < inc; i++) {
					print(pre);
					if (base < 0) {
						if (i & 1) {
							print(space);
						}
					}
					if (use_hdroff) {
						if (use_pair) {
							printfmt("%c%c",
								hex[(((i + k) >> 4) + K) % 16],
								hex[(i + k) % 16]);
						} else {
							printfmt(" %c", hex[(i + k) % 16]);
						}
					} else {
						printfmt(" %c", hex[(i + k) % 16]);
					}
					if (i & 1 || !pairs) {
						if (!compact) {
							print(col != 1 ? space : ((i + 1) < inc) ? space
												 : "|");
						}
					}
				}
			}
			/* ascii column */
			if (compact) {
				print(col > 0 ? "|" : space);
			} else {
				print(col == 2 ? "|" : space);
			}
			if (!p || !(p->flags & RZ_PRINT_FLAGS_NONASCII)) {
				for (i = 0; i < inc; i++) {
					printfmt("%c", hex[(i + k) % 16]);
				}
			}
			if (col == 2) {
				printfmt("|");
			}
			/* print comment header*/
			if (p && p->use_comments && !compact) {
				if (col != 2) {
					print(" ");
				}
				if (!hex_style) {
					print(" comment");
				}
			}
			print("\n");
		}

		if (c) {
			print(Color_RESET);
		}
	}

	// is this necessary?
	rz_print_set_screenbounds(p, addr);
	int rowbytes;
	int rows = 0;
	int bytes = 0;
	bool printValue = true;
	bool oPrintValue = true;
	bool isPxr = (p && p->flags & RZ_PRINT_FLAGS_REFS);

	for (i = j = 0; i < len; i += (stride ? stride : inc)) {
		if (p && p->cons && p->cons->context && p->cons->context->breaked) {
			break;
		}
		rowbytes = inc;
		if (use_align) {
			int sz = (p && p->offsize) ? p->offsize(p->user, addr + j) : -1;
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
							print(" ...\n");
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
			rz_print_section(p, at);
			rz_print_addr(p, at);
		}
		int row_have_cursor = -1;
		ut64 row_have_addr = UT64_MAX;
		if (use_hexa) {
			if (!compact && !isPxr) {
				print((col == 1) ? "|" : " ");
			}
			for (j = i; j < i + inc; j++) {
				if (j != i && use_align && rowbytes == inc) {
					int sz = (p && p->offsize) ? p->offsize(p->user, addr + j) : -1;
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
							print(j % 2 ? "  |" : "| ");
						} else {
							print(j % 2 ? "   " : "  ");
						}
					} else {
						if (base == 32) {
							print((j % 4) ? "   " : "  ");
						} else if (base == 10) {
							print(j % 2 ? "     " : "  ");
						} else {
							print(j % 2 ? "   " : "  ");
						}
					}
					continue;
				}
				const char *hl = (hex_style && p && p->offname(p->user, addr + j)) ? Color_INVERT : NULL;
				if (hl) {
					print(hl);
				}
				if (p && (base == 32 || base == 64)) {
					int left = len - i;
					/* TODO: check step. it should be 2/4 for base(32) and 8 for
					 *       base(64) */
					ut64 n = 0;
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
					rz_mem_swaporcopy((ut8 *)&n, buf + j, sz_n, p && p->big_endian);
					rz_print_cursor(p, j, sz_n, 1);
					// stub for colors
					if (p && p->colorfor) {
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
							rz_print_section(p, at);
							rz_print_addr(p, addr + j * zoomsz);
						}
						if (base == 64) {
							printfmt("%s0x%016" PFMT64x "%s  ", a, (ut64)n, b);
						} else if (step == 2) {
							printfmt("%s0x%04x%s ", a, (ut16)n, b);
						} else {
							printfmt("%s0x%08x%s ", a, (ut32)n, b);
						}
					} else {
						if (hasNull) {
							const char *n = p->offname(p->user, addr + j);
							rz_print_section(p, at);
							rz_print_addr(p, addr + j * zoomsz);
							printfmt("..[ null bytes ]..   00000000 %s\n", n ? n : "");
						}
					}
					rz_print_cursor(p, j, sz_n, 0);
					oPrintValue = printValue;
					j += step - 1;
				} else if (base == -8) {
					long long w = rz_read_ble64(buf + j, p && p->big_endian);
					rz_print_cursor(p, j, 8, 1);
					printfmt("%23" PFMT64d " ", w);
					rz_print_cursor(p, j, 8, 0);
					j += 7;
				} else if (base == -1) {
					st8 w = rz_read_ble8(buf + j);
					rz_print_cursor(p, j, 1, 1);
					printfmt("%4d ", w);
					rz_print_cursor(p, j, 1, 0);
				} else if (base == -10) {
					if (j + 1 < len) {
						st16 w = rz_read_ble16(buf + j, p && p->big_endian);
						rz_print_cursor(p, j, 2, 1);
						printfmt("%7d ", w);
						rz_print_cursor(p, j, 2, 0);
					}
					j += 1;
				} else if (base == 10) { // "pxd"
					if (j + 3 < len) {
						int w = rz_read_ble32(buf + j, p && p->big_endian);
						rz_print_cursor(p, j, 4, 1);
						printfmt("%13d ", w);
						rz_print_cursor(p, j, 4, 0);
					}
					j += 3;
				} else {
					if (j >= len) {
						break;
					}
					if (use_unalloc && !p->iob.is_valid_offset(p->iob.io, addr + j, false)) {
						char ch = p->io_unalloc_ch;
						char dbl_ch_str[] = { ch, ch, 0 };
						p->cb_printf("%s", dbl_ch_str);
					} else {
						rz_print_byte(p, bytefmt, j, buf[j]);
					}
					if (pairs && !compact && (inc & 1)) {
						bool mustspace = (rows % 2) ? !(j & 1) : (j & 1);
						if (mustspace) {
							print(" ");
						}
					} else if (bytes % 2 || !pairs) {
						if (col == 1) {
							if (j + 1 < inc + i) {
								if (!compact) {
									print(" ");
								}
							} else {
								print("|");
							}
						} else {
							if (!compact) {
								print(" ");
							}
						}
					}
				}
				if (hl) {
					print(Color_RESET);
				}
				bytes++;
			}
		}
		if (printValue) {
			if (compact) {
				if (col == 0) {
					print(" ");
				} else if (col == 1) {
					// print (" ");
				} else {
					print((col == 2) ? "|" : "");
				}
			} else {
				print((col == 2) ? "|" : " ");
			}
			if (!p || !(p->flags & RZ_PRINT_FLAGS_NONASCII)) {
				bytes = 0;
				size_t end = i + inc;
				for (j = i; j < end; j++) {
					if (j != i && use_align && bytes >= rowbytes) {
						int sz = (p && p->offsize) ? p->offsize(p->user, addr + j) : -1;
						if (sz >= 0) {
							print(" ");
							break;
						}
					}
					if (j >= len || (use_align && bytes >= rowbytes)) {
						break;
					}
					ut8 ch = (use_unalloc && p && !p->iob.is_valid_offset(p->iob.io, addr + j, false))
						? ' '
						: buf[j];
					rz_print_byte(p, "%c", j, ch);
					bytes++;
				}
			}
			/* ascii column */
			if (col == 2) {
				print("|");
			}
			bool eol = false;
			if (!eol && p && p->flags & RZ_PRINT_FLAGS_REFS) {
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
						printfmt(" @ %s", rstr);
					}
					free(rstr);
					rstr = p->hasrefs(p->user, off, true);
					if (rstr && *rstr) {
						printfmt(" %s", rstr);
					}
					free(rstr);
				}
			}
			if (!eol && p && p->use_comments) {
				for (; j < i + inc; j++) {
					print(" ");
				}
				for (j = i; j < i + inc; j++) {
					if (use_align && (j - i) >= rowbytes) {
						break;
					}
					if (p && p->offname) {
						a = p->offname(p->user, addr + j);
						if (p->colorfor && a && *a) {
							const char *color = p->colorfor(p->user, addr + j, true);
							printfmt("%s  ; %s%s", color ? color : "", a,
								color ? Color_RESET : "");
						}
					}
					char *comment = p->get_comments(p->user, addr + j);
					if (comment) {
						if (p && p->colorfor) {
							a = p->colorfor(p->user, addr + j, true);
							if (!a || !*a) {
								a = "";
							}
						} else {
							a = "";
						}
						printfmt("%s  ; %s", a, comment);
						free(comment);
					}
				}
			}
			if (use_align && rowbytes < inc && bytes >= rowbytes) {
				i -= (inc - bytes);
			}
			print("\n");
		}
		rows++;
		bytes = 0;
		if (p && p->cfmt && *p->cfmt) {
			if (row_have_cursor != -1) {
				int i = 0;
				print(" _________");
				if (!compact) {
					print("_");
				}
				for (i = 0; i < row_have_cursor; i++) {
					if (!pairs || (!compact && i % 2)) {
						print("___");
					} else {
						print("__");
					}
				}
				print("__|\n");
				printfmt("| cmd.hexcursor = %s\n", p->cfmt);
				p->coreb.cmdf(p->coreb.core,
					"%s @ 0x%08" PFMT64x, p->cfmt, row_have_addr);
			}
		}
	}
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

// TODO: add support for cursor
RZ_API void rz_print_hexdiff(RzPrint *p, ut64 aa, const ut8 *_a, ut64 ba, const ut8 *_b, int len, int scndcol) {
	ut8 *a, *b;
	char linediff, fmt[64];
	int color = p->flags & RZ_PRINT_FLAGS_COLOR;
	int diffskip = p->flags & RZ_PRINT_FLAGS_DIFFOUT;
	int i, j, min;
	if (!((a = M(_a, len)))) {
		return;
	}
	if (!((b = M(_b, len)))) {
		free(a);
		return;
	}
	for (i = 0; i < len; i += 16) {
		min = RZ_MIN(16, len - i);
		linediff = (memcmp(a + i, b + i, min)) ? '!' : '|';
		if (diffskip && linediff == '|') {
			continue;
		}
		p->cb_printf("0x%08" PFMT64x " ", aa + i);
		for (j = 0; j < min; j++) {
			*fmt = color;
			rz_print_cursor(p, i + j, 1, 1);
			p->cb_printf("%s", BD(a, b));
			rz_print_cursor(p, i + j, 1, 0);
		}
		p->cb_printf(" ");
		for (j = 0; j < min; j++) {
			*fmt = color;
			rz_print_cursor(p, i + j, 1, 1);
			p->cb_printf("%s", CD(a, b));
			rz_print_cursor(p, i + j, 1, 0);
		}
		if (scndcol) {
			p->cb_printf(" %c 0x%08" PFMT64x " ", linediff, ba + i);
			for (j = 0; j < min; j++) {
				*fmt = color;
				rz_print_cursor(p, i + j, 1, 1);
				p->cb_printf("%s", BD(b, a));
				rz_print_cursor(p, i + j, 1, 0);
			}
			p->cb_printf(" ");
			for (j = 0; j < min; j++) {
				*fmt = color;
				rz_print_cursor(p, i + j, 1, 1);
				p->cb_printf("%s", CD(b, a));
				rz_print_cursor(p, i + j, 1, 0);
			}
			p->cb_printf("\n");
		} else {
			p->cb_printf(" %c\n", linediff);
		}
	}
	free(a);
	free(b);
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

// HACK :D
static RzPrint staticp = {
	.cb_printf = libc_printf
};

/* TODO: handle screen width */
RZ_API void rz_print_progressbar(RzPrint *p, int pc, int _cols) {
	// TODO: add support for colors
	int i, cols = (_cols == -1) ? 78 : _cols;
	if (!p) {
		p = &staticp;
	}
	const char *h_line = p->cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = p->cons->use_utf8 ? UTF_BLOCK : "#";

	pc = RZ_MAX(0, RZ_MIN(100, pc));
	if (p->flags & RZ_PRINT_FLAGS_HEADER) {
		p->cb_printf("%4d%% ", pc);
	}
	cols -= 15;
	p->cb_printf("[");
	for (i = cols * pc / 100; i; i--) {
		p->cb_printf("%s", block);
	}
	for (i = cols - (cols * pc / 100); i; i--) {
		p->cb_printf("%s", h_line);
	}
	p->cb_printf("]");
}

RZ_API void rz_print_rangebar(RzPrint *p, ut64 startA, ut64 endA, ut64 min, ut64 max, int cols) {
	const char *h_line = p->cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = p->cons->use_utf8 ? UTF_BLOCK : "#";
	const bool show_colors = p->flags & RZ_PRINT_FLAGS_COLOR;
	int j = 0;
	p->cb_printf("|");
	if (cols < 1) {
		cols = 1;
	}
	int mul = (max - min) / cols;
	bool isFirst = true;
	for (j = 0; j < cols; j++) {
		ut64 startB = min + (j * mul);
		ut64 endB = min + ((j + 1) * mul);
		if (startA <= endB && endA >= startB) {
			if (show_colors & isFirst) {
				p->cb_printf(Color_GREEN);
				isFirst = false;
			}
			p->cb_printf("%s", block);
		} else {
			if (!isFirst) {
				p->cb_printf(Color_RESET);
			}
			p->cb_printf("%s", h_line);
		}
	}
	p->cb_printf("|");
}

static inline void printHistBlock(RzPrint *p, int k, int cols) {
	RzConsPrintablePalette *pal = &p->cons->context->pal;
	const char *h_line = p->cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = p->cons->use_utf8 ? UTF_BLOCK : "#";
	const char *kol[5];
	kol[0] = pal->nop;
	kol[1] = pal->mov;
	kol[2] = pal->cjmp;
	kol[3] = pal->jmp;
	kol[4] = pal->call;
	if (cols < 1) {
		cols = 1;
	}
	const bool show_colors = (p && (p->flags & RZ_PRINT_FLAGS_COLOR));
	if (show_colors) {
		int idx = (int)((k * 4) / cols);
		if (idx < 5) {
			const char *str = kol[idx];
			if (p->histblock) {
				p->cb_printf("%s%s%s", str, block, Color_RESET);
			} else {
				p->cb_printf("%s%s%s", str, h_line, Color_RESET);
			}
		}
	} else {
		if (p->histblock) {
			p->cb_printf("%s", block);
		} else {
			p->cb_printf("%s", h_line);
		}
	}
}

RZ_API void rz_print_fill(RzPrint *p, const ut8 *arr, int size, ut64 addr, int step) {
	rz_return_if_fail(p && arr);
	const bool show_colors = (p && (p->flags & RZ_PRINT_FLAGS_COLOR));
	const bool show_offset = (p && (p->flags & RZ_PRINT_FLAGS_OFFSET));
	bool useUtf8 = p->cons->use_utf8;
	const char *v_line = useUtf8 ? RUNE_LINE_VERT : "|";
	int i = 0, j;

#define INC 5
#if TOPLINE
	if (arr[0] > 1) {
		p->cb_printf("         ");
		if (addr != UT64_MAX && step > 0) {
			p->cb_printf("           ");
		}
		if (arr[0] > 1) {
			for (i = 0; i < arr[0]; i += INC) {
				p->cb_printf(h_line);
			}
		}
		p->cb_printf("\n");
	}
#endif
	// get the max of columns
	int cols = 0;
	for (i = 0; i < size; i++) {
		cols = arr[i] > cols ? arr[i] : cols;
	}
	cols /= 5;
	for (i = 0; i < size; i++) {
		ut8 next = (i + 1 < size) ? arr[i + 1] : 0;
		int base = 0, k = 0;
		if (addr != UT64_MAX && step > 0) {
			ut64 at = addr + (i * step);
			if (show_offset) {
				if (p->cur_enabled) {
					if (i == p->cur) {
						p->cb_printf(Color_INVERT "> 0x%08" PFMT64x " " Color_RESET, at);
						if (p->num) {
							p->num->value = at;
						}
					} else {
						p->cb_printf("  0x%08" PFMT64x " ", at);
					}
				} else {
					p->cb_printf("0x%08" PFMT64x " ", at);
				}
			}
			p->cb_printf("%03x %04x %s", i, arr[i], v_line);
		} else {
			p->cb_printf("%s", v_line);
		}
		if (next < INC) {
			base = 1;
		}
		if (next < arr[i]) {
			if (arr[i] > INC) {
				for (j = 0; j < next + base; j += INC) {
					printHistBlock(p, k, cols);
					k++;
				}
			}
			for (j = next + INC; j + base < arr[i]; j += INC) {
				printHistBlock(p, k, cols);
				k++;
			}
		} else {
			printHistBlock(p, k, cols);
			k++;
		}
		if (i + 1 == size) {
			for (j = arr[i] + INC + base; j + base < next; j += INC) {
				printHistBlock(p, k, cols);
				k++;
			}
		} else if (arr[i + 1] > arr[i]) {
			for (j = arr[i] + INC + base; j + base < next; j += INC) {
				printHistBlock(p, k, cols);
				k++;
			}
		}
		if (show_colors) {
			p->cb_printf("%s", Color_RESET);
		}
		p->cb_printf("\n");
	}
}

// probably move somewhere else. RzPrint doesnt needs to know about the RZ_ANALYSIS_ enums
RZ_API const char *rz_print_color_op_type(RzPrint *p, ut32 analysis_type) {
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

// Global buffer to speed up colorizing performance
#define COLORIZE_BUFSIZE 1024
static char o[COLORIZE_BUFSIZE];

static bool issymbol(char c) {
	switch (c) {
	case '+':
	case '-':
	/* case '/': not good for dalvik */
	case '>':
	case '<':
	case '(':
	case ')':
	case '*':
	case '%':
	case ']':
	case '[':
	case ',':
	case ' ':
	case '{':
	case '}':
		return true;
	default:
		return false;
	}
}

static bool check_arg_name(RzPrint *print, char *p, ut64 func_addr) {
	if (func_addr && print->exists_var) {
		int z;
		for (z = 0; p[z] && (isalpha((int)p[z]) || isdigit((int)p[z]) || p[z] == '_'); z++) {
			;
		}
		char tmp = p[z];
		p[z] = '\0';
		bool ret = print->exists_var(print, func_addr, p);
		p[z] = tmp;
		return ret;
	}
	return false;
}

static bool is_hex_prefix(const char *p) {
	rz_return_val_if_fail(p, false);
	if (!isascii(*p)) {
		return false; // UTF-8
	}
	return (p[0] == '0' && p[1] == 'x');
}

/**
 * \brief Checks if the first character of \p c is a digit character
 * OR if the first two chars are a hex prefix.
 *
 * \param c The character string.
 * \return true First char is a digit or the first two chars are a hex prefix.
 * \return false Otherwise.
 */
static bool is_num(const char *c) {
	rz_return_val_if_fail(c, false);
	if (!isascii(*c)) {
		return false; // UTF-8
	}
	return is_hex_prefix(c) || isxdigit(c[0]);
}

/**
 * \brief Checks if the first character of \p c is an alphanumeric character OR if it is a hex prefix.
 *
 * \param c The character string.
 * \return true If it is alphanumeric or a hex prefix.
 * \return false Otherwise.
 */
static bool is_alpha_num(const char *c) {
	rz_return_val_if_fail(c, false);
	if (!isascii(*c)) {
		return false; // UTF-8
	}
	return is_num(c) || isalpha(c[0]);
}

static bool is_separator(const char c) {
	if (!isascii(c)) {
		return false; // UTF-8
	}
	return (c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == ',' || c == '.' || c == '#' || c == ':' || c == ' ');
}

static bool is_operator(const char c) {
	if (!isascii(c)) {
		return false; // UTF-8
	}
	return (c == '+' || c == '-' || c == '/' || c == '>' || c == '<' || c == '*' || c == '%' || c == '|' || c == '&' || c == '=' || c == '!');
}

static bool is_register(const char *name, RZ_BORROW RzRegSet *regset) {
	rz_return_val_if_fail(name && regset, false);
	if (!regset) {
		return false;
	}

	bool found = false;
	for (ut32 i = 0; i < RZ_REG_TYPE_LAST; ++i) {
		if (regset[i].ht_regs) {
			ht_pp_find(regset[i].ht_regs, name, &found);
			if (found) {
				return true;
			}
		}
	}
	return false;
}

RZ_API char *rz_print_colorize_opcode(RzPrint *print, char *p, const char *reg, const char *num, bool partial_reset, ut64 func_addr) {
	int i, j, k, is_mod, is_float = 0, is_arg = 0;
	char *reset = partial_reset ? Color_RESET_NOBG : Color_RESET;
	ut32 c_reset = strlen(reset);
	int is_jmp = p && (*p == 'j' || ((*p == 'c') && (p[1] == 'a'))) ? 1 : 0;
	ut32 opcode_sz = p && *p ? strlen(p) * 10 + 1 : 0;
	char previous = '\0';
	const char *color_flag = print->cons->context->pal.flag;

	if (!p || !*p) {
		return NULL;
	}
	if (is_jmp) {
		return strdup(p);
	}
	if (opcode_sz > COLORIZE_BUFSIZE) {
		/* return same string in case of error */
		return strdup(p);
	}

	memset(o, 0, COLORIZE_BUFSIZE);
	for (i = j = 0; p[i]; i++, j++) {
		/* colorize numbers */
		if ((is_hex_prefix(&p[i]) && previous != ':') || (isdigit((ut8)p[i]) && issymbol(previous))) {
			const char *num2 = num;
			ut64 n = rz_num_get(NULL, p + i);
			const char *name = print->offname(print->user, n) ? color_flag : NULL;
			if (name) {
				num2 = name;
			}
			int nlen = strlen(num2);
			if (nlen + j >= sizeof(o)) {
				eprintf("Colorize buffer is too small\n");
				break;
			}
			memcpy(o + j, num2, nlen + 1);
			j += nlen;
		}
		previous = p[i];
		if (j + 100 >= COLORIZE_BUFSIZE) {
			eprintf("rz_print_colorize_opcode(): buffer overflow!\n");
			return strdup(p);
		}
		switch (p[i]) {
		// We dont need to skip ansi codes.
		// original colors must be preserved somehow
		case 0x1b:
#define STRIP_ANSI 1
#if STRIP_ANSI
			/* skip until 'm' */
			for (++i; p[i] && p[i] != 'm'; i++) {
				o[j] = p[i];
			}
			j--;
			continue;
#else
			/* copy until 'm' */
			for (; p[i] && p[i] != 'm'; i++) {
				o[j++] = p[i];
			}
			o[j++] = p[i++];
#endif
		case '+':
		case '-':
		case '/':
		case '>':
		case '<':
		case '(':
		case ')':
		case '*':
		case '%':
		case ']':
		case '[':
		case ',':
			/* ugly trick for dalvik */
			if (is_float) {
				/* do nothing, keep going until next */
				is_float = 0;
			} else if (is_arg) {
				if (c_reset + j + 10 >= COLORIZE_BUFSIZE) {
					eprintf("rz_print_colorize_opcode(): buffer overflow!\n");
					return strdup(p);
				}

				bool found_var = check_arg_name(print, p + i + 1, func_addr);
				strcpy(o + j, reset);
				j += strlen(reset);
				o[j] = p[i];
				if (!(p[i + 1] == '$' || ((p[i + 1] > '0') && (p[i + 1] < '9')))) {
					const char *color = found_var ? print->cons->context->pal.func_var_type : reg;
					ut32 color_len = strlen(color);
					if (color_len + j + 10 >= COLORIZE_BUFSIZE) {
						eprintf("rz_print_colorize_opcode(): buffer overflow!\n");
						return strdup(p);
					}
					strcpy(o + j + 1, color);
					j += strlen(color);
				}
				continue;
			}
			break;
		case ' ':
			is_arg = 1;
			// find if next ',' before ' ' is found
			is_mod = 0;
			is_float = 0;
			for (k = i + 1; p[k]; k++) {
				if (p[k] == 'e' && p[k + 1] == '+') {
					is_float = 1;
					break;
				}
				if (p[k] == ' ') {
					break;
				}
				if (p[k] == ',') {
					is_mod = 1;
					break;
				}
			}
			if (is_float) {
				strcpy(o + j, num);
				j += strlen(num);
			}
			if (!p[k]) {
				is_mod = 1;
			}
			if (is_mod) {
				// COLOR FOR REGISTER
				ut32 reg_len = strlen(reg);
				/* if (reg_len+j+10 >= opcode_sz) o = realloc_color_buffer (o, &opcode_sz, reg_len+100); */
				if (reg_len + j + 10 >= COLORIZE_BUFSIZE) {
					eprintf("rz_print_colorize_opcode(): buffer overflow!\n");
					return strdup(p);
				}
				strcpy(o + j, reg);
				j += strlen(reg);
			}
			break;
		case '0': /* address */
			if (p[i + 1] == 'x') {
				if (print->flags & RZ_PRINT_FLAGS_SECSUB) {
					RzIOMap *map = print->iob.map_get(print->iob.io, rz_num_get(NULL, p + i));
					if (map && map->name) {
						if (strlen(map->name) + j + 1 >= COLORIZE_BUFSIZE) {
							eprintf("stop before overflow\n");
							break;
						}
						strcpy(o + j, map->name);
						j += strlen(o + j);
						strcpy(o + j, ".");
						j++;
					}
				}
			}
			break;
		}
		o[j] = p[i];
	}
	// decolorize at the end
	if (j + 20 >= opcode_sz) {
		char *t_o = o;
		/* o = malloc (opcode_sz+21); */
		memmove(o, t_o, opcode_sz);
		/* free (t_o); */
	}
	strcpy(o + j, reset);
	// strcpy (p, o); // may overflow .. but shouldnt because asm.buf_asm is big enought
	return strdup(o);
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

RZ_API int rz_print_jsondump(RzPrint *p, const ut8 *buf, int len, int wordsize) {
	ut16 *buf16 = (ut16 *)buf;
	ut32 *buf32 = (ut32 *)buf;
	ut64 *buf64 = (ut64 *)buf;
	// TODDO: support p==NULL too
	if (!p || !buf || len < 1 || wordsize < 1) {
		return 0;
	}
	int bytesize = wordsize / 8;
	if (bytesize < 1) {
		bytesize = 8;
	}
	int i, words = (len / bytesize);
	p->cb_printf("[");
	for (i = 0; i < words; i++) {
		switch (wordsize) {
		case 8: {
			p->cb_printf("%s%d", i ? "," : "", buf[i]);
			break;
		}
		case 16: {
			ut16 w16 = rz_read_ble16(&buf16[i], p->big_endian);
			p->cb_printf("%s%hd", i ? "," : "", w16);
			break;
		}
		case 32: {
			ut32 w32 = rz_read_ble32(&buf32[i], p->big_endian);
			p->cb_printf("%s%d", i ? "," : "", w32);
			break;
		}
		case 64: {
			ut64 w64 = rz_read_ble64(&buf64[i], p->big_endian);
			p->cb_printf("%s%" PFMT64d, i ? "," : "", w64);
			break;
		}
		}
	}
	p->cb_printf("]\n");
	return words;
}

RZ_API RZ_OWN RzAsmTokenString *rz_asm_token_string_new(const char *asm_str) {
	RzAsmTokenString *s = RZ_NEW0(RzAsmTokenString);
	rz_return_val_if_fail(s, NULL);
	s->tokens = rz_vector_new(sizeof(RzAsmToken), NULL, NULL);
	s->str = rz_strbuf_new(asm_str);
	rz_return_val_if_fail(s->tokens && s->str, NULL);
	return s;
}

RZ_API void rz_asm_token_string_free(RZ_OWN RzAsmTokenString *toks) {
	if (!toks) {
		return;
	}
	rz_strbuf_free(toks->str);
	rz_vector_free(toks->tokens);
	free(toks);
}

RZ_API void rz_asm_token_pattern_free(void *p) {
	if (!p) {
		return;
	}
	RzAsmTokenPattern *pat = (RzAsmTokenPattern *)p;
	free(pat->pattern);
	rz_regex_free(pat->regex);
	free(p);
}

/**
 * \brief Creates a token and returns it.
 *
 * \param start Index in the asm string of the token.
 * \param len The length in bytes of the token.
 * \param type The token type.
 * \param val The value of the token (should be 0 if token has no value).
 * \return RzAsmToken* Pointer to the newly created token or NULL in case of failure.
 */
static RZ_OWN RzAsmToken *asm_token_create(const size_t start, const size_t len, const RzAsmTokenType type, const ut64 val) {
	rz_return_val_if_fail(len > 0, NULL);
	RzAsmToken *t = RZ_NEW0(RzAsmToken);
	rz_return_val_if_fail(t, NULL);

	t->start = start;
	t->type = type;
	t->len = len;
	switch (type) {
	default:
		break;
	case RZ_ASM_TOKEN_NUMBER:
		t->val.number = val;
		break;
	}
	return t;
}

/**
 * \brief Creates a token and adds it to the token string vector \p toks.
 *
 * \param toks The token string to which the token is added.
 * \param i The start index if the token.
 * \param l The length of the token.
 * \param type The type of the token.
 * \param token_val The token value if it was a number otherwise should be 0.
 */
static void add_token(RZ_OUT RzAsmTokenString *toks, const size_t i, const size_t l, const RzAsmTokenType type, const ut64 token_val) {
	rz_return_if_fail(toks);
	RzAsmToken *t = asm_token_create(i, l, type, token_val);
	if (!t) {
		RZ_LOG_WARN("Failed to create token. Asm strings will be flawed.\n");
		rz_warn_if_reached();
		return;
	}

	rz_vector_push(toks->tokens, t);
}

/**
 * \brief Checks if indicies s, e overlap with other tokens start/end.
 *
 * \param toks Tokens to compare to.
 * \param s Start index of token into asm string.
 * \param e End index of token into asm string (points to last char of token).
 * \return true Overlaps with token from token vector.
 * \return false Does not overap with other token.
 */
static bool overlaps_with_token(RZ_BORROW RzVector /* RzAsmTokenString */ *toks, const size_t s, const size_t e) {
	rz_return_val_if_fail(toks, false);
	size_t x, y; // Other tokens start/end
	RzAsmToken *it;
	rz_vector_foreach(toks, it) {
		x = it->start;
		y = it->start + it->len - 1;
		if ((e > x && e < y) // e within x:y
			|| (s > x && s < y) // s within x:y
			|| (x <= s && e <= y)) // s:e equal or in x:y
		{
			return true;
		}
	}
	return false;
}

static int cmp_tokens(const RzAsmToken *a, const RzAsmToken *b) {
	rz_return_val_if_fail(a && b, 0);
	if (a->start < b->start) {
		return -1;
	} else if (a->start > b->start) {
		return 1;
	}
	return 0;
}

static void check_token_coverage(RzAsmTokenString *toks) {
	rz_return_if_fail(toks);
	if (rz_vector_len(toks->tokens) == 0) {
		RZ_LOG_WARN("No tokens given.\n");
		return;
	}
	bool error = false;
	// Check if all characters belong to a token.
	RzAsmToken *cur, *prev = NULL;
	int i = 0;
	ut32 ci, cj, pi, pj; // Current and previous token indices.
	rz_vector_foreach(toks->tokens, cur) {
		if (i == cur->start) {
			prev = cur;
			i = cur->start + cur->len;
			continue;
		}
		ci = cur->start;
		cj = cur->start + cur->len;
		pi = prev ? prev->start : 0;
		pj = prev ? prev->start + prev->len : 0;
		if (i > cur->start) {
			RZ_LOG_WARN("i = %d Token at %d:%d overlaps with token %d:%d\n",
				i, pi, pj, ci, cj);
			error = true;
		} else {
			RZ_LOG_WARN("i = %d, Part of asm string is not covered by a token."
				    " Empty range between token %d:%d and token %d:%d\n",
				i, pi, pj, ci, cj);
			error = true;
		}
		i = cur->start + cur->len;
		prev = cur;
	}
	if (error) {
		RZ_LOG_WARN("Parsing errors in asm str: %s\n", rz_strbuf_get(toks->str));
	}
}

/**
 * \brief Splits an asm string into tokens by using the given patterns.
 *
 * \param str The asm string.
 * \param patterns RzList<RzAsmTokenPattern> with the regex patterns describing each token type.
 * \return RzAsmTokenString* The tokens.
 */
RZ_API RZ_OWN RzAsmTokenString *rz_print_tokenize_asm_custom(RZ_BORROW RzStrBuf *asm_str, RzList /* RzAsmTokenPattern */ *patterns) {
	rz_return_val_if_fail(asm_str && patterns, NULL);

	const char *str = rz_strbuf_get(asm_str);
	RzRegexMatch m[1];
	size_t j = 0; // Offset into str. Regex patterns are only searched in substring str[j:].
	st64 i = 0; // Start of token in str.
	st64 s = 0; // Start of matched token in str[j:]
	st64 l = 0; // Length of token.
	RzAsmTokenString *toks = rz_asm_token_string_new(str);
	RzAsmTokenPattern *pat;
	RzListIter *it;
	rz_list_foreach (patterns, it, pat) {
		rz_return_val_if_fail(pat && pat->regex, NULL);
		j = 0;
		if (!pat->regex) {
			continue;
		}
		while (rz_regex_exec(pat->regex, str + j, 1, m, 0) == 0) {
			s = m[0].rm_so; // Token start in str[j:]
			l = m[0].rm_eo - s; // End in str[j:] - start in str[j:] = Length of token.
			i = j + s; // Start of token in str.
			if (overlaps_with_token(toks->tokens, i, i + l - 1)) {
				// If this is true a token with higher priority was matched before.
				j = i + l;
				continue;
			}
			if (!is_num(str + i)) {
				add_token(toks, i, l, pat->type, 0);
				j = i + l;
				continue;
			}
			add_token(toks, i, l, pat->type, strtoull(str + i, NULL, 0));
			j = i + l;
		}
	}

	rz_vector_sort(toks->tokens, (RzVectorComparator)cmp_tokens, false);
#if RZ_CHECKS_LEVEL == 2
	check_token_coverage(toks);
#endif

	return toks;
}

/**
 * \brief Seeks to the end of the token at \p str + \p i and returns the length of it.
 *
 * \param str The asm string.
 * \param i Index into \p str where the token starts.
 * \param type Type of the token.
 * \return size_t Length of token
 */
static size_t seek_to_end_of_token(const char *str, size_t i, RzAsmTokenType type) {
	rz_return_val_if_fail(str, 0);
	size_t j = i;

	switch (type) {
	default:
		rz_warn_if_reached();
		break;
	case RZ_ASM_TOKEN_MNEMONIC:
	case RZ_ASM_TOKEN_REGISTER:
		do {
			++j;
		} while (is_alpha_num(str + j));
		break;
	case RZ_ASM_TOKEN_NUMBER:
		do {
			if (is_hex_prefix(str + j)) {
				j += 2;
			} else {
				++j;
			}
		} while (is_num(str + j));
		break;
	case RZ_ASM_TOKEN_SEPARATOR:
		do {
			++j;
		} while (is_separator(*(str + j)));
		break;
	case RZ_ASM_TOKEN_OPERATOR:
		do {
			++j;
		} while (is_operator(*(str + j)));
		break;
	case RZ_ASM_TOKEN_UNKNOWN:
		do {
			++j;
		} while (!isascii(*(str + j)) && !is_operator(*(str + j)) && !is_separator(*(str + j)) && !is_alpha_num(str + j));
	}
	return j - i;
}

/**
 * \brief Parses an asm string into tokens.
 *
 * \p param->regsets must be set if this function is expected to detect register names.
 *
 * \param asm_str The asm string.
 * \param param Several parameter which alter the parsing.
 * \return RzAsmTokenString* The asm tokens.
 */
static RZ_OWN RzAsmTokenString *tokenize_asm_generic(RZ_BORROW RzStrBuf *asm_str, RZ_NULLABLE const RzAsmParseParam *param) {
	rz_return_val_if_fail(asm_str, NULL);
	if (rz_strbuf_is_empty(asm_str)) {
		return NULL;
	}
	// Splitting the asm string into tokens is relatively straight forward.
	//
	// The target is to split an asm string into separate tokens of a given type.
	// For example:
	//
	// Asm string: `mov eax, 0x122`
	//
	// is split into:
	//   `mov`   : Mnemonic token
	//   ` `     : Separator token
	//   `eax`   : Register token
	//   `, `    : Separator token
	//   `0x122` : Number token
	//
	// In order to do this we associated a certain characters with a token type.
	//
	// E.g. alphanumeric characters are associated with numbers, registers and mnemonics.
	// Comma and brackets are interpreted as separators.
	// Plus, minus and pipe are associated with the operator token type and so forth.
	//
	// A sequence of characters of the same type are interpreted as a token.
	//
	// For example: `lr` could be a mnemonic or a special register.
	//
	// In this generic method we ignore these ambiguities and parse the first alphabetic token always as mnemonic
	// and alphabetic tokens after that as registers/unknowns.
	//
	// To extract the tokens we set the following variables:
	// `i = 0`				// Start of token
	// `l = 0`				// Length of token.
	// `i + l`				// Is the start of the next token.
	//
	// Parsing is done sequentially:
	// - The character at `str[i]` determines the token type.
	// - Iterate over characters from `i` on and stop if a character of another token type appears (char at `str[l]`).
	// - Create token from `i` to `l-1` with length `l`.
	// - Start again from `i + l`

	const char *str = rz_strbuf_get(asm_str);
	if (!str) {
		return NULL;
	}
	RzAsmTokenString *toks = rz_asm_token_string_new(str);
	if (!toks) {
		return NULL;
	}
	// Start of token.
	size_t i = 0;
	// Length of token.
	size_t l = 0;
	// Set flag once the mnemonic was parsed (the mnemonic is always the first alphabetic token in our string).
	bool mnemonic_parsed = false;

	while (str[i]) {
		// Alphanumeric tokens
		if (is_alpha_num(str + i)) {
			bool is_number = false;
			if (isxdigit(*(str + i))) {
				// Register/mnemonic names can be ambiguous in comparison to hex numbers.
				// E.g. "eax" could be parsed as hex number token "ea".
				// Here we check the character after the token.
				// If this char is an alphabetic char (like the "x" in "eax"), the token isn't a number.
				l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_NUMBER);
				if (!str[i + l]) { // End of asm string => token is number.
					is_number = true;
				} else if (!isalpha(str[i + l])) { // Next char is something non alphabetic => token is number.
					is_number = true;
				}
			}

			if (is_number) {
				add_token(toks, i, l, RZ_ASM_TOKEN_NUMBER, strtoull(str + i, NULL, 0));
			} else if (mnemonic_parsed) {
				l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_REGISTER);
				char *op_name = rz_str_ndup(str + i, l);
				if (param && is_register(op_name, param->reg_sets)) {
					add_token(toks, i, l, RZ_ASM_TOKEN_REGISTER, 0);
				} else {
					add_token(toks, i, l, RZ_ASM_TOKEN_UNKNOWN, 0);
				}
				free(op_name);
			} else {
				mnemonic_parsed = true;
				l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_MNEMONIC);
				add_token(toks, i, l, RZ_ASM_TOKEN_MNEMONIC, 0);
			}
		} else if (is_operator(str[i])) {
			l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_OPERATOR);
			add_token(toks, i, l, RZ_ASM_TOKEN_OPERATOR, 0);
		} else if (is_separator(str[i])) {
			l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_SEPARATOR);
			add_token(toks, i, l, RZ_ASM_TOKEN_SEPARATOR, 0);
		} else { // Unknown tokens. UTF-8 and others.
			l = seek_to_end_of_token(str, i, RZ_ASM_TOKEN_UNKNOWN);
			add_token(toks, i, l, RZ_ASM_TOKEN_UNKNOWN, 0);
		}
		i = i + l;
	}
	return toks;
}

/**
 * \brief Parses an asm string generically. It parses the string like: <mnemmonic> <op>, <op>.
 * Every <op> (which is not a number) is parsed as a register. Unless a register profile is given.
 * In this case <op> is only parsed as register if it occurs in the register profile. Otherwise as UNKNOWN.
 *
 * DEPRECATED: Please implement your custom parsing method and set RzArchOpcode.XXX.
 *
 */
RZ_DEPRECATE RZ_API RZ_OWN RzAsmTokenString *rz_print_tokenize_asm_string(RZ_BORROW RzStrBuf *asm_str, RZ_NULLABLE RzAsmParseParam *param) {
	rz_return_val_if_fail(asm_str, NULL);

	return tokenize_asm_generic(asm_str, param);
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
RZ_API RZ_OWN RzStrBuf *rz_print_colorize_asm_str(RZ_BORROW RzPrint *p, const RzAsmTokenString *toks, const RzAsmColorizeOptions opt) {
	// Color palette.
	RzConsPrintablePalette palette = p->cons->context->pal;
	// Black white asm string.
	char *bw_str = rz_strbuf_get(toks->str);
	rz_return_val_if_fail(bw_str, NULL);
	char *reset = opt.reset_bg ? Color_RESET_NOBG : Color_RESET;
	// mnemonic color
	const char *mnem_col = rz_print_color_op_type(p, opt.analysis_op_type);

	RzStrBuf *out = rz_strbuf_new("");
	rz_return_val_if_fail(out, NULL);

	const char *color;
	RzAsmToken *tok;
	rz_vector_foreach(toks->tokens, tok) {
		switch (tok->type) {
		default:
			rz_warn_if_reached();
			return NULL;
		case RZ_ASM_TOKEN_UNKNOWN:
			color = palette.other;
			break;
		case RZ_ASM_TOKEN_MNEMONIC:
			color = mnem_col;
			break;
		case RZ_ASM_TOKEN_NUMBER:
			if (tok->val.number == opt.hl_addr) {
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
	rz_strbuf_append(out, "\0");
	return out;
}

/**
 * \brief Converts a not colored asm string into a colored one. First it splits it into tokens, then colorizes it.
 *
 * DEPRECATED: Please implement your custom parsing method and set RzArchOpcode.XXX and use rz_print_colorize_asm_str on it.
 *
 * \param p The RzPrint struct.
 * \param str The plain asm string.
 * \param param Parameters for parsing.
 * \param opt Options for colorizing.
 *
 * \return char* The colorized asm string. NULL in case of failure.
 */
RZ_DEPRECATE RZ_API RZ_OWN RzStrBuf *rz_print_tokenize_colorize_asm_str(RZ_BORROW RzPrint *p, const char *str, RZ_NULLABLE const RzAsmParseParam *param, const RzAsmColorizeOptions opt) {
	rz_return_val_if_fail(p && str, NULL);
	RzStrBuf *asm_str = rz_strbuf_new(str);
	RzAsmTokenString *toks = tokenize_asm_generic(asm_str, param);
	rz_strbuf_free(asm_str);
	RzStrBuf *clr_asm = rz_print_colorize_asm_str(p, toks, opt);

	rz_asm_token_string_free(toks);
	return clr_asm;
}
