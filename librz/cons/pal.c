// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 sghctoma <sghctoma@gmail.com>
// SPDX-FileCopyrightText: 2013-2020 xarkes <antide.petit@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_cons.h>

#define RZCOLOR_AT(i) (RzColor *)(((ut8 *)&(rz_cons_singleton()->context->cpal)) + keys[i].coff)
#define COLOR_AT(i)   (char **)(((ut8 *)&(rz_cons_singleton()->context->pal)) + keys[i].off)

static struct {
	const char *name;
	int off; // RzConsPrintablePalette offset
	int coff; // RzConsPalette offset
} keys[] = {
	{ "comment", rz_offsetof(RzConsPrintablePalette, comment), rz_offsetof(RzConsPalette, comment) },
	{ "usrcmt", rz_offsetof(RzConsPrintablePalette, usercomment), rz_offsetof(RzConsPalette, usercomment) },
	{ "args", rz_offsetof(RzConsPrintablePalette, args), rz_offsetof(RzConsPalette, args) },
	{ "fname", rz_offsetof(RzConsPrintablePalette, fname), rz_offsetof(RzConsPalette, fname) },
	{ "floc", rz_offsetof(RzConsPrintablePalette, floc), rz_offsetof(RzConsPalette, floc) },
	{ "fline", rz_offsetof(RzConsPrintablePalette, fline), rz_offsetof(RzConsPalette, fline) },
	{ "flag", rz_offsetof(RzConsPrintablePalette, flag), rz_offsetof(RzConsPalette, flag) },
	{ "label", rz_offsetof(RzConsPrintablePalette, label), rz_offsetof(RzConsPalette, label) },
	{ "help", rz_offsetof(RzConsPrintablePalette, help), rz_offsetof(RzConsPalette, help) },
	{ "flow", rz_offsetof(RzConsPrintablePalette, flow), rz_offsetof(RzConsPalette, flow) },
	{ "flow2", rz_offsetof(RzConsPrintablePalette, flow2), rz_offsetof(RzConsPalette, flow2) },
	{ "prompt", rz_offsetof(RzConsPrintablePalette, prompt), rz_offsetof(RzConsPalette, prompt) },
	{ "offset", rz_offsetof(RzConsPrintablePalette, offset), rz_offsetof(RzConsPalette, offset) },
	{ "input", rz_offsetof(RzConsPrintablePalette, input), rz_offsetof(RzConsPalette, input) },
	{ "invalid", rz_offsetof(RzConsPrintablePalette, invalid), rz_offsetof(RzConsPalette, invalid) },
	{ "other", rz_offsetof(RzConsPrintablePalette, other), rz_offsetof(RzConsPalette, other) },
	{ "b0x00", rz_offsetof(RzConsPrintablePalette, b0x00), rz_offsetof(RzConsPalette, b0x00) },
	{ "b0x7f", rz_offsetof(RzConsPrintablePalette, b0x7f), rz_offsetof(RzConsPalette, b0x7f) },
	{ "b0xff", rz_offsetof(RzConsPrintablePalette, b0xff), rz_offsetof(RzConsPalette, b0xff) },
	{ "math", rz_offsetof(RzConsPrintablePalette, math), rz_offsetof(RzConsPalette, math) },
	{ "bin", rz_offsetof(RzConsPrintablePalette, bin), rz_offsetof(RzConsPalette, bin) },
	{ "btext", rz_offsetof(RzConsPrintablePalette, btext), rz_offsetof(RzConsPalette, btext) },
	{ "push", rz_offsetof(RzConsPrintablePalette, push), rz_offsetof(RzConsPalette, push) },
	{ "pop", rz_offsetof(RzConsPrintablePalette, pop), rz_offsetof(RzConsPalette, pop) },
	{ "crypto", rz_offsetof(RzConsPrintablePalette, crypto), rz_offsetof(RzConsPalette, crypto) },
	{ "jmp", rz_offsetof(RzConsPrintablePalette, jmp), rz_offsetof(RzConsPalette, jmp) },
	{ "cjmp", rz_offsetof(RzConsPrintablePalette, cjmp), rz_offsetof(RzConsPalette, cjmp) },
	{ "call", rz_offsetof(RzConsPrintablePalette, call), rz_offsetof(RzConsPalette, call) },
	{ "nop", rz_offsetof(RzConsPrintablePalette, nop), rz_offsetof(RzConsPalette, nop) },
	{ "ret", rz_offsetof(RzConsPrintablePalette, ret), rz_offsetof(RzConsPalette, ret) },
	{ "trap", rz_offsetof(RzConsPrintablePalette, trap), rz_offsetof(RzConsPalette, trap) },
	{ "ucall", rz_offsetof(RzConsPrintablePalette, ucall), rz_offsetof(RzConsPalette, ucall) },
	{ "ujmp", rz_offsetof(RzConsPrintablePalette, ujmp), rz_offsetof(RzConsPalette, ujmp) },
	{ "swi", rz_offsetof(RzConsPrintablePalette, swi), rz_offsetof(RzConsPalette, swi) },
	{ "cmp", rz_offsetof(RzConsPrintablePalette, cmp), rz_offsetof(RzConsPalette, cmp) },
	{ "reg", rz_offsetof(RzConsPrintablePalette, reg), rz_offsetof(RzConsPalette, reg) },
	{ "creg", rz_offsetof(RzConsPrintablePalette, creg), rz_offsetof(RzConsPalette, creg) },
	{ "num", rz_offsetof(RzConsPrintablePalette, num), rz_offsetof(RzConsPalette, num) },
	{ "mov", rz_offsetof(RzConsPrintablePalette, mov), rz_offsetof(RzConsPalette, mov) },
	{ "func_var", rz_offsetof(RzConsPrintablePalette, func_var), rz_offsetof(RzConsPalette, func_var) },
	{ "func_var_type", rz_offsetof(RzConsPrintablePalette, func_var_type), rz_offsetof(RzConsPalette, func_var_type) },
	{ "func_var_addr", rz_offsetof(RzConsPrintablePalette, func_var_addr), rz_offsetof(RzConsPalette, func_var_addr) },
	{ "widget_bg", rz_offsetof(RzConsPrintablePalette, widget_bg), rz_offsetof(RzConsPalette, widget_bg) },
	{ "widget_sel", rz_offsetof(RzConsPrintablePalette, widget_sel), rz_offsetof(RzConsPalette, widget_sel) },
	{ "meta", rz_offsetof(RzConsPrintablePalette, meta), rz_offsetof(RzConsPalette, meta) },

	{ "ai.read", rz_offsetof(RzConsPrintablePalette, ai_read), rz_offsetof(RzConsPalette, ai_read) },
	{ "ai.write", rz_offsetof(RzConsPrintablePalette, ai_write), rz_offsetof(RzConsPalette, ai_write) },
	{ "ai.exec", rz_offsetof(RzConsPrintablePalette, ai_exec), rz_offsetof(RzConsPalette, ai_exec) },
	{ "ai.seq", rz_offsetof(RzConsPrintablePalette, ai_seq), rz_offsetof(RzConsPalette, ai_seq) },
	{ "ai.ascii", rz_offsetof(RzConsPrintablePalette, ai_ascii), rz_offsetof(RzConsPalette, ai_ascii) },

	{ "graph.box", rz_offsetof(RzConsPrintablePalette, graph_box), rz_offsetof(RzConsPalette, graph_box) },
	{ "graph.box2", rz_offsetof(RzConsPrintablePalette, graph_box2), rz_offsetof(RzConsPalette, graph_box2) },
	{ "graph.box3", rz_offsetof(RzConsPrintablePalette, graph_box3), rz_offsetof(RzConsPalette, graph_box3) },
	{ "graph.box4", rz_offsetof(RzConsPrintablePalette, graph_box4), rz_offsetof(RzConsPalette, graph_box4) },
	{ "graph.true", rz_offsetof(RzConsPrintablePalette, graph_true), rz_offsetof(RzConsPalette, graph_true) },
	{ "graph.false", rz_offsetof(RzConsPrintablePalette, graph_false), rz_offsetof(RzConsPalette, graph_false) },
	{ "graph.ujump", rz_offsetof(RzConsPrintablePalette, graph_ujump), rz_offsetof(RzConsPalette, graph_ujump) },
	{ "graph.current", rz_offsetof(RzConsPrintablePalette, graph_current), rz_offsetof(RzConsPalette, graph_current) },
	{ "graph.traced", rz_offsetof(RzConsPrintablePalette, graph_traced), rz_offsetof(RzConsPalette, graph_traced) },

	{ "diff.unknown", rz_offsetof(RzConsPrintablePalette, diff_unknown), rz_offsetof(RzConsPalette, diff_unknown) },
	{ "diff.new", rz_offsetof(RzConsPrintablePalette, diff_new), rz_offsetof(RzConsPalette, diff_new) },
	{ "diff.match", rz_offsetof(RzConsPrintablePalette, diff_match), rz_offsetof(RzConsPalette, diff_match) },
	{ "diff.unmatch", rz_offsetof(RzConsPrintablePalette, diff_unmatch), rz_offsetof(RzConsPalette, diff_unmatch) },

	{ "gui.cflow", rz_offsetof(RzConsPrintablePalette, gui_cflow), rz_offsetof(RzConsPalette, gui_cflow) },
	{ "gui.dataoffset", rz_offsetof(RzConsPrintablePalette, gui_dataoffset), rz_offsetof(RzConsPalette, gui_dataoffset) },
	{ "gui.background", rz_offsetof(RzConsPrintablePalette, gui_background), rz_offsetof(RzConsPalette, gui_background) },
	{ "gui.alt_background", rz_offsetof(RzConsPrintablePalette, gui_alt_background), rz_offsetof(RzConsPalette, gui_alt_background) },
	{ "gui.border", rz_offsetof(RzConsPrintablePalette, gui_border), rz_offsetof(RzConsPalette, gui_border) },
	{ "wordhl", rz_offsetof(RzConsPrintablePalette, wordhl), rz_offsetof(RzConsPalette, wordhl) },
	{ "linehl", rz_offsetof(RzConsPrintablePalette, linehl), rz_offsetof(RzConsPalette, linehl) },

	{ NULL, 0, 0 }
};
static const int keys_len = sizeof(keys) / sizeof(keys[0]) - 1;

struct {
	const char *name;
	RzColor rcolor;
	const char *code;
	const char *bgcode;
} colors[] = {
	{ "black", RzColor_BLACK, Color_BLACK, Color_BGBLACK },
	{ "red", RzColor_RED, Color_RED, Color_BGRED },
	{ "white", RzColor_WHITE, Color_WHITE, Color_BGWHITE },
	{ "green", RzColor_GREEN, Color_GREEN, Color_BGGREEN },
	{ "magenta", RzColor_MAGENTA, Color_MAGENTA, Color_BGMAGENTA },
	{ "yellow", RzColor_YELLOW, Color_YELLOW, Color_BGYELLOW },
	{ "cyan", RzColor_CYAN, Color_CYAN, Color_BGCYAN },
	{ "blue", RzColor_BLUE, Color_BLUE, Color_BGBLUE },
	{ "gray", RzColor_GRAY, Color_GRAY, Color_BGGRAY },
	{ "bblack", RzColor_BBLACK, Color_BBLACK, Color_BBGBLACK },
	{ "bred", RzColor_BRED, Color_BRED, Color_BBGRED },
	{ "bwhite", RzColor_BWHITE, Color_BWHITE, Color_BBGWHITE },
	{ "bgreen", RzColor_BGREEN, Color_BGREEN, Color_BBGGREEN },
	{ "bmagenta", RzColor_BMAGENTA, Color_BMAGENTA, Color_BBGMAGENTA },
	{ "byellow", RzColor_BYELLOW, Color_BYELLOW, Color_BBGYELLOW },
	{ "bcyan", RzColor_BCYAN, Color_BCYAN, Color_BBGCYAN },
	{ "bblue", RzColor_BBLUE, Color_BBLUE, Color_BBGBLUE },
	{ "none", RzColor_NULL, Color_RESET, Color_RESET },
	{ NULL, RzColor_NULL, NULL, NULL }
};

static inline ut8 rgbnum(const char ch1, const char ch2) {
	ut8 r = 0, r2 = 0;
	rz_hex_to_byte(&r, ch1);
	rz_hex_to_byte(&r2, ch2);
	return r << 4 | r2;
}

static int compare_strings(const char *s1, const char *s2, void *user) {
	return strcmp(s1, s2);
}

static void __cons_pal_update_event(RzConsContext *ctx) {
	RzPVector sorter;
	rz_pvector_init(&sorter, NULL);
	/* Compute cons->pal values */
	for (int i = 0; keys[i].name; i++) {
		RzColor *rcolor = (RzColor *)(((ut8 *)&(ctx->cpal)) + keys[i].coff);
		char **color = (char **)(((ut8 *)&(ctx->pal)) + keys[i].off);
		// Color is dynamically allocated, needs to be freed
		RZ_FREE(*color);
		*color = rz_cons_rgb_str_mode(ctx->color_mode, NULL, 0, rcolor);
		char *rgb = rz_str_newf("rgb:%02x%02x%02x", rcolor->r, rcolor->g, rcolor->b);
		rz_pvector_push(&sorter, rgb);
	}
	rz_pvector_sort(&sorter, (RzPVectorComparator)compare_strings, NULL);
	rz_cons_rainbow_free(ctx);
	rz_cons_rainbow_new(ctx, rz_pvector_len(&sorter));
	int n = 0;
	void **iter;
	rz_pvector_foreach (&sorter, iter) {
		ctx->pal.rainbow[n++] = (char *)(*iter);
	}
	ctx->pal.rainbow_sz = n;
	rz_pvector_fini(&sorter);
}

RZ_API void rz_cons_pal_init(RzConsContext *ctx) {
	memset(&ctx->cpal, 0, sizeof(ctx->cpal));

	ctx->cpal.b0x00 = (RzColor)RzColor_GREEN;
	ctx->cpal.b0x7f = (RzColor)RzColor_CYAN;
	ctx->cpal.b0xff = (RzColor)RzColor_RED;
	ctx->cpal.args = (RzColor)RzColor_YELLOW;
	ctx->cpal.bin = (RzColor)RzColor_CYAN;
	ctx->cpal.btext = (RzColor)RzColor_YELLOW;
	ctx->cpal.call = (RzColor)RzColor_BGREEN;
	ctx->cpal.call.attr = RZ_CONS_ATTR_BOLD;
	ctx->cpal.ucall = (RzColor)RzColor_GREEN;
	ctx->cpal.ujmp = (RzColor)RzColor_GREEN;
	ctx->cpal.cjmp = (RzColor)RzColor_GREEN;
	ctx->cpal.cmp = (RzColor)RzColor_CYAN;
	ctx->cpal.comment = (RzColor)RzColor_RED;
	ctx->cpal.usercomment = (RzColor)RzColor_WHITE;
	ctx->cpal.creg = (RzColor)RzColor_CYAN;
	ctx->cpal.flag = (RzColor)RzColor_CYAN;
	ctx->cpal.fline = (RzColor)RzColor_CYAN;
	ctx->cpal.floc = (RzColor)RzColor_CYAN;
	ctx->cpal.flow = (RzColor)RzColor_CYAN;
	ctx->cpal.flow2 = (RzColor)RzColor_BLUE;
	ctx->cpal.fname = (RzColor)RzColor_RED;
	ctx->cpal.help = (RzColor)RzColor_GREEN;
	ctx->cpal.input = (RzColor)RzColor_WHITE;
	ctx->cpal.invalid = (RzColor)RzColor_BRED;
	ctx->cpal.invalid.attr = RZ_CONS_ATTR_BOLD;
	ctx->cpal.jmp = (RzColor)RzColor_GREEN;
	ctx->cpal.label = (RzColor)RzColor_CYAN;
	ctx->cpal.math = (RzColor)RzColor_YELLOW;
	ctx->cpal.mov = (RzColor)RzColor_WHITE;
	ctx->cpal.nop = (RzColor)RzColor_BLUE;
	ctx->cpal.num = (RzColor)RzColor_YELLOW;
	ctx->cpal.offset = (RzColor)RzColor_GREEN;
	ctx->cpal.other = (RzColor)RzColor_WHITE;
	ctx->cpal.pop = (RzColor)RzColor_BMAGENTA;
	ctx->cpal.pop.attr = RZ_CONS_ATTR_BOLD;
	ctx->cpal.prompt = (RzColor)RzColor_YELLOW;
	ctx->cpal.push = (RzColor)RzColor_MAGENTA;
	ctx->cpal.crypto = (RzColor)RzColor_BGBLUE;
	ctx->cpal.reg = (RzColor)RzColor_CYAN;
	ctx->cpal.ret = (RzColor)RzColor_RED;
	ctx->cpal.swi = (RzColor)RzColor_MAGENTA;
	ctx->cpal.trap = (RzColor)RzColor_BRED;
	ctx->cpal.trap.attr = RZ_CONS_ATTR_BOLD;

	ctx->cpal.ai_read = (RzColor)RzColor_GREEN;
	ctx->cpal.ai_write = (RzColor)RzColor_BLUE;
	ctx->cpal.ai_exec = (RzColor)RzColor_RED;
	ctx->cpal.ai_seq = (RzColor)RzColor_MAGENTA;
	ctx->cpal.ai_ascii = (RzColor)RzColor_YELLOW;

	ctx->cpal.gui_cflow = (RzColor)RzColor_YELLOW;
	ctx->cpal.gui_dataoffset = (RzColor)RzColor_YELLOW;
	ctx->cpal.gui_background = (RzColor)RzColor_BLACK;
	ctx->cpal.gui_alt_background = (RzColor)RzColor_WHITE;
	ctx->cpal.gui_border = (RzColor)RzColor_BLACK;
	ctx->cpal.wordhl = (RzColor)RzColor_BGRED;
	ctx->cpal.meta = (RzColor)RzColor_GRAY;
	// No good choice for fallback ansi16 color
#if __WINDOWS__
	ctx->cpal.linehl = (RzColor)RZCOLOR(ALPHA_BG, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 4);
#else
	ctx->cpal.linehl = (RzColor)RZCOLOR(ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 4);
#endif

	ctx->cpal.func_var = (RzColor)RzColor_WHITE;
	ctx->cpal.func_var_type = (RzColor)RzColor_BLUE;
	ctx->cpal.func_var_addr = (RzColor)RzColor_CYAN;

	ctx->cpal.widget_bg = (RzColor)RZCOLOR(ALPHA_BG, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0);
	ctx->cpal.widget_sel = (RzColor)RzColor_BGRED;

	ctx->cpal.graph_box = (RzColor)RzColor_NULL;
	ctx->cpal.graph_box2 = (RzColor)RzColor_BLUE;
	ctx->cpal.graph_box3 = (RzColor)RzColor_MAGENTA;
	ctx->cpal.graph_box4 = (RzColor)RzColor_GRAY;
	ctx->cpal.graph_true = (RzColor)RzColor_GREEN;
	ctx->cpal.graph_false = (RzColor)RzColor_RED;
	ctx->cpal.graph_ujump = (RzColor)RzColor_BLUE; // single jump
	ctx->cpal.graph_traced = (RzColor)RzColor_YELLOW;
	ctx->cpal.graph_current = (RzColor)RzColor_BLUE;
	ctx->cpal.diff_unknown = (RzColor)RzColor_MAGENTA;
	ctx->cpal.diff_new = (RzColor)RzColor_RED;
	ctx->cpal.diff_match = (RzColor)RzColor_GRAY;
	ctx->cpal.diff_unmatch = (RzColor)RzColor_YELLOW;

	rz_cons_pal_free(ctx);
	ctx->pal.reset = Color_RESET; // reset is not user accessible, const char* is ok
	__cons_pal_update_event(ctx);
}

RZ_API void rz_cons_pal_free(RzConsContext *ctx) {
	int i;
	for (i = 0; keys[i].name; i++) {
		char **color = (char **)(((ut8 *)&(ctx->pal)) + keys[i].off);
		if (color && *color) {
			RZ_FREE(*color);
		}
	}
	rz_cons_rainbow_free(ctx);
}

RZ_API void rz_cons_pal_copy(RzConsContext *dst, RzConsContext *src) {
	memcpy(&dst->cpal, &src->cpal, sizeof(src->cpal));
	memset(&dst->pal, 0, sizeof(dst->pal));

	dst->pal.rainbow = NULL;
	dst->pal.rainbow_sz = 0;

	dst->pal.reset = Color_RESET; // reset is not user accessible, const char* is ok

	__cons_pal_update_event(dst);
}

RZ_API void rz_cons_pal_random(void) {
	int i;
	RzColor *rcolor;
	for (i = 0; keys[i].name; i++) {
		rcolor = RZCOLOR_AT(i);
		*rcolor = rz_cons_color_random(ALPHA_FG);
	}
	rz_cons_pal_update_event();
}

/* Return NULL if outcol is given */
RZ_API char *rz_cons_pal_parse(const char *str, RzColor *outcol) {
	int i;
	RzColor rcolor = (RzColor)RzColor_BLACK;
	rcolor.id16 = -1;
	char *fgcolor;
	char *bgcolor;
	char *attr = NULL;
	char out[128];
	if (RZ_STR_ISEMPTY(str)) {
		return NULL;
	}
	fgcolor = strdup(str);
	if (!fgcolor) {
		return NULL;
	}
	bgcolor = strchr(fgcolor + 1, ' ');
	out[0] = 0;
	if (bgcolor) {
		*bgcolor++ = '\0';
		attr = strchr(bgcolor, ' ');
		if (attr) {
			*attr++ = '\0';
		}
	}

	// Handle first color (fgcolor)
	if (!strcmp(fgcolor, "random")) {
		rcolor = rz_cons_color_random(ALPHA_FG);
		if (!outcol) {
			rz_cons_rgb_str(out, sizeof(out), &rcolor);
		}
	} else if (!strncmp(fgcolor, "#", 1)) { // "#00ff00" HTML format
		if (strlen(fgcolor) == 7) {
			i = sscanf(fgcolor + 1, "%02hhx%02hhx%02hhx", &rcolor.r, &rcolor.g, &rcolor.b);
			if (i != 3) {
				eprintf("Error while parsing HTML color: %s\n", fgcolor);
			}
			if (!outcol) {
				rz_cons_rgb_str(out, sizeof(out), &rcolor);
			}
		} else {
			eprintf("Invalid html color code\n");
		}
	} else if (!strncmp(fgcolor, "rgb:", 4)) { // "rgb:123" rgb format
		if (strlen(fgcolor) == 7) {
			rcolor.r = rgbnum(fgcolor[4], '0');
			rcolor.g = rgbnum(fgcolor[5], '0');
			rcolor.b = rgbnum(fgcolor[6], '0');
			if (!outcol) {
				rz_cons_rgb_str(out, sizeof(out), &rcolor);
			}
		} else if (strlen(fgcolor) == 10) {
			rcolor.r = rgbnum(fgcolor[4], fgcolor[5]);
			rcolor.g = rgbnum(fgcolor[6], fgcolor[7]);
			rcolor.b = rgbnum(fgcolor[8], fgcolor[9]);
			if (!outcol) {
				rz_cons_rgb_str(out, sizeof(out), &rcolor);
			}
		}
	}
	// Handle second color (bgcolor)
	if (bgcolor && !strncmp(bgcolor, "rgb:", 4)) { // "rgb:123" rgb format
		if (strlen(bgcolor) == 7) {
			rcolor.a |= ALPHA_BG;
			rcolor.r2 = rgbnum(bgcolor[4], '0');
			rcolor.g2 = rgbnum(bgcolor[5], '0');
			rcolor.b2 = rgbnum(bgcolor[6], '0');
			if (!outcol) {
				size_t len = strlen(out);
				rz_cons_rgb_str(out + len, sizeof(out) - len, &rcolor);
			}
		} else if (strlen(bgcolor) == 10) {
			rcolor.a |= ALPHA_BG;
			rcolor.r2 = rgbnum(bgcolor[4], bgcolor[5]);
			rcolor.g2 = rgbnum(bgcolor[6], bgcolor[7]);
			rcolor.b2 = rgbnum(bgcolor[8], bgcolor[9]);
			if (!outcol) {
				size_t len = strlen(out);
				rz_cons_rgb_str(out + len, sizeof(out) - len, &rcolor);
			}
		}
	}
	// No suitable format, checking if colors are named
	for (i = 0; colors[i].name; i++) {
		if (!strcmp(fgcolor, colors[i].name)) {
			rcolor.r = colors[i].rcolor.r;
			rcolor.g = colors[i].rcolor.g;
			rcolor.b = colors[i].rcolor.b;
			rcolor.id16 = colors[i].rcolor.id16;
			if (!outcol) {
				strncat(out, colors[i].code,
					sizeof(out) - strlen(out) - 1);
			}
		}
		if (bgcolor && !strcmp(bgcolor, colors[i].name)) {
			rcolor.a |= ALPHA_BG;
			rcolor.r2 = colors[i].rcolor.r; // Initial color doesn't
			rcolor.g2 = colors[i].rcolor.g; // have r2, g2, b2
			rcolor.b2 = colors[i].rcolor.b;
			rcolor.id16 = colors[i].rcolor.id16;
			if (!outcol) {
				strncat(out, colors[i].bgcode,
					sizeof(out) - strlen(out) - 1);
			}
		}
	}
	if (attr) {
		// Parse extra attributes.
		const char *p = attr;
		while (p) {
			if (!strncmp(p, "bold", 4)) {
				rcolor.attr |= RZ_CONS_ATTR_BOLD;
			} else if (!strncmp(p, "dim", 3)) {
				rcolor.attr |= RZ_CONS_ATTR_DIM;
			} else if (!strncmp(p, "italic", 6)) {
				rcolor.attr |= RZ_CONS_ATTR_ITALIC;
			} else if (!strncmp(p, "underline", 9)) {
				rcolor.attr |= RZ_CONS_ATTR_UNDERLINE;
			} else if (!strncmp(p, "blink", 5)) {
				rcolor.attr |= RZ_CONS_ATTR_BLINK;
			} else {
				eprintf("Failed to parse terminal attributes: %s\n", p);
				break;
			}
			p = strchr(p, ' ');
			if (p) {
				p++;
			}
		}
	}
	if (outcol) {
		if (outcol->a == ALPHA_BG && !bgcolor) {
			rcolor.a = ALPHA_BG;
		}
		*outcol = rcolor;
	}
	free(fgcolor);
	return (*out && !outcol) ? strdup(out) : NULL;
}

static void rz_cons_pal_show_gs(void) {
	int i, n;
	rz_cons_print("\nGreyscale:\n");
	RzColor rcolor = RzColor_BLACK;
	for (i = 0x08, n = 0; i <= 0xee; i += 0xa) {
		char fg[32], bg[32];
		rcolor.r = i;
		rcolor.g = i;
		rcolor.b = i;

		if (i < 0x76) {
			strcpy(fg, Color_WHITE);
		} else {
			strcpy(fg, Color_BLACK);
		}
		rz_cons_rgb_str(bg, sizeof(bg), &rcolor);
		rz_cons_printf("%s%s rgb:%02x%02x%02x " Color_RESET,
			fg, bg, i, i, i);
		if (n++ == 5) {
			n = 0;
			rz_cons_newline();
		}
	}
}

static void rz_cons_pal_show_256(void) {
	RzColor rc = RzColor_BLACK;
	rz_cons_print("\n\nXTerm colors:\n");
	int r = 0;
	int g = 0;
	int b = 0;
	for (r = 0x00; r <= 0xff; r += 0x28) {
		rc.r = r;
		if (rc.r == 0x28) {
			rc.r = 0x5f;
		}
		for (b = 0x00; b <= 0xff; b += 0x28) {
			rc.b = b;
			if (rc.b == 0x28) {
				rc.b = 0x5f;
			}
			for (g = 0x00; g <= 0xff; g += 0x28) {
				rc.g = g;
				char bg[32];
				if (rc.g == 0x28) {
					rc.g = 0x5f;
				}
				const char *fg = ((rc.r <= 0x5f) && (rc.g <= 0x5f)) ? Color_WHITE : Color_BLACK;
				rz_cons_rgb_str(bg, sizeof(bg), &rc);
				rz_cons_printf("%s%s rgb:%02x%02x%02x " Color_RESET, fg, bg, rc.r, rc.g, rc.b);
			}
			rz_cons_newline();
		}
	}
}

static void rz_cons_pal_show_rgb(void) {
	const int inc = 3;
	int i, j, k, n = 0;
	RzColor rc = RzColor_BLACK;
	rz_cons_print("\n\nRGB:\n");
	for (i = n = 0; i <= 0xf; i += inc) {
		for (k = 0; k <= 0xf; k += inc) {
			for (j = 0; j <= 0xf; j += inc) {
				char fg[32], bg[32];
				rc.r = i * 16;
				rc.g = j * 16;
				rc.b = k * 16;
				strcpy(fg, ((i < 6) && (j < 5)) ? Color_WHITE : Color_BLACK);
				rz_cons_rgb_str(bg, sizeof(bg), &rc);
				rz_cons_printf("%s%s rgb:%02x%02x%02x " Color_RESET, fg, bg, rc.r, rc.g, rc.b);
				if (n++ == 5) {
					n = 0;
					rz_cons_newline();
				}
			}
		}
	}
}

RZ_API void rz_cons_pal_show(void) {
	int i;
	for (i = 0; colors[i].name; i++) {
		rz_cons_printf("%s%s__" Color_RESET " %s\n",
			colors[i].code,
			colors[i].bgcode,
			colors[i].name);
	}
	switch (rz_cons_singleton()->context->color_mode) {
	case COLOR_MODE_256: // 256 color palette
		rz_cons_pal_show_gs();
		rz_cons_pal_show_256();
		break;
	case COLOR_MODE_16M: // 16M (truecolor)
		rz_cons_pal_show_gs();
		rz_cons_pal_show_rgb();
		break;
	default:
		break;
	}
}

typedef struct {
	int val;
	const char *str;
} RAttrStr;

RZ_API void rz_cons_pal_list(int rad, const char *arg) {
	char *name, **color;
	const char *hasnext;
	int i;
	if (rad == 'j') {
		rz_cons_print("{");
	}
	for (i = 0; keys[i].name; i++) {
		RzColor *rcolor = RZCOLOR_AT(i);
		color = COLOR_AT(i);
		switch (rad) {
		case 'j':
			hasnext = (keys[i + 1].name) ? "," : "";
			rz_cons_printf("\"%s\":[%d,%d,%d]%s",
				keys[i].name, rcolor->r, rcolor->g, rcolor->b, hasnext);
			break;
		case 'c': {
			const char *prefix = rz_str_trim_head_ro(arg);
			if (!prefix) {
				prefix = "";
			}
			hasnext = (keys[i + 1].name) ? "\n" : "";
			// TODO Need to replace the '.' char because this is not valid CSS
			char *name = strdup(keys[i].name);
			int j, len = strlen(name);
			for (j = 0; j < len; j++) {
				if (name[j] == '.') {
					name[j] = '_';
				}
			}
			rz_cons_printf(".%s%s { color: rgb(%d, %d, %d); }%s",
				prefix, name, rcolor->r, rcolor->g, rcolor->b, hasnext);
			free(name);
		} break;
		case 'h':
			name = strdup(keys[i].name);
			rz_str_replace_char(name, '.', '_');
			rz_cons_printf(".%s { color:#%02x%02x%02x }\n",
				name, rcolor->r, rcolor->g, rcolor->b);
			free(name);
			break;
		case '*':
		case 'r':
		case 1:
			rz_cons_printf("ec %s rgb:%02x%02x%02x",
				keys[i].name, rcolor->r, rcolor->g, rcolor->b);
			if (rcolor->a == ALPHA_FGBG) {
				rz_cons_printf(" rgb:%02x%02x%02x",
					rcolor->r2, rcolor->g2, rcolor->b2);
			}
			if (rcolor->attr) {
				const RAttrStr attrs[] = {
					{ RZ_CONS_ATTR_BOLD, "bold" },
					{ RZ_CONS_ATTR_DIM, "dim" },
					{ RZ_CONS_ATTR_ITALIC, "italic" },
					{ RZ_CONS_ATTR_UNDERLINE, "underline" },
					{ RZ_CONS_ATTR_BLINK, "blink" }
				};
				int j;
				if (rcolor->a != ALPHA_FGBG) {
					rz_cons_strcat(" .");
				}
				for (j = 0; j < RZ_ARRAY_SIZE(attrs); j++) {
					if (rcolor->attr & attrs[j].val) {
						rz_cons_printf(" %s", attrs[j].str);
					}
				}
			}
			rz_cons_newline();
			break;
		default:
			rz_cons_printf(" %s##" Color_RESET "  %s\n", *color,
				keys[i].name);
		}
	}
	if (rad == 'j') {
		rz_cons_print("}\n");
	}
}

/* Modify the palette to set a color value.
 * rz_cons_pal_update_event () must be called after this function
 * so the changes take effect. */
RZ_API int rz_cons_pal_set(const char *key, const char *val) {
	int i;
	RzColor *rcolor;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp(key, keys[i].name)) {
			rcolor = RZCOLOR_AT(i);
			rz_cons_pal_parse(val, rcolor);
			return true;
		}
	}
	eprintf("rz_cons_pal_set: Invalid color %s\n", key);
	return false;
}

/* Get the named RzColor */
RZ_API RzColor rz_cons_pal_get(const char *key) {
	int i;
	RzColor *rcolor;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp(key, keys[i].name)) {
			rcolor = RZCOLOR_AT(i);
			return *rcolor;
		}
	}
	return (RzColor)RzColor_NULL;
}

/* Get the RzColor at specified index */
RZ_API RzColor rz_cons_pal_get_i(int index) {
	return *(RZCOLOR_AT(index));
}

/* Get color name at index */
RZ_API const char *rz_cons_pal_get_name(int index) {
	return (index >= 0 && index < keys_len) ? keys[index].name : NULL;
}

RZ_API int rz_cons_pal_len(void) {
	return keys_len;
}

RZ_API void rz_cons_pal_update_event(void) {
	__cons_pal_update_event(rz_cons_singleton()->context);
}

RZ_API void rz_cons_rainbow_new(RzConsContext *ctx, int sz) {
	ctx->pal.rainbow_sz = sz;
	free(ctx->pal.rainbow);
	ctx->pal.rainbow = calloc(sizeof(char *), sz);
}

RZ_API void rz_cons_rainbow_free(RzConsContext *ctx) {
	int i, sz = ctx->pal.rainbow_sz;
	if (ctx->pal.rainbow) {
		for (i = 0; i < sz; i++) {
			free(ctx->pal.rainbow[i]);
		}
	}
	ctx->pal.rainbow_sz = 0;
	RZ_FREE(ctx->pal.rainbow);
}

RZ_API char *rz_cons_rainbow_get(int idx, int last, bool bg) {
	RzCons *cons = rz_cons_singleton();
	if (last < 0) {
		last = cons->context->pal.rainbow_sz;
	}
	if (idx < 0 || idx >= last || !cons->context->pal.rainbow) {
		return NULL;
	}
	int x = (last == cons->context->pal.rainbow_sz)
		? idx
		: (cons->context->pal.rainbow_sz * idx) / (last + 1);
	const char *a = cons->context->pal.rainbow[x];
	if (bg) {
		char *dup = rz_str_newf("%s %s", a, a);
		char *res = rz_cons_pal_parse(dup, NULL);
		free(dup);
		return res;
	}
	return rz_cons_pal_parse(a, NULL);
}
