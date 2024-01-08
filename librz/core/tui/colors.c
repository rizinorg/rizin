// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

RZ_IPI void rz_core_visual_colors(RzCore *core) {
	char *color = calloc(1, 64), cstr[32];
	char preview_cmd[128] = "pd $r";
	int ch, opt = 0, oopt = -1;
	RzCons *cons = rz_cons_singleton();
	bool truecolor = cons->context->color_mode == COLOR_MODE_16M;
	char *rgb_xxx_fmt = truecolor ? "rgb:%2.2x%2.2x%2.2x " : "rgb:%x%x%x ";
	const char *k;
	RzColor rcolor;

	rz_cons_show_cursor(false);
	rcolor = rz_cons_pal_get_i(opt);
	for (;;) {
		rz_cons_clear();
		rz_cons_gotoxy(0, 0);
		k = rz_cons_pal_get_name(opt);
		if (!k) {
			opt = 0;
			k = rz_cons_pal_get_name(opt);
		}
		if (!truecolor) {
			rcolor.r &= 0xf;
			rcolor.g &= 0xf;
			rcolor.b &= 0xf;
			rcolor.r2 &= 0xf;
			rcolor.g2 &= 0xf;
			rcolor.b2 &= 0xf;
		} else {
			rcolor.r &= 0xff;
			rcolor.g &= 0xff;
			rcolor.b &= 0xff;
			rcolor.r2 &= 0xff;
			rcolor.g2 &= 0xff;
			rcolor.b2 &= 0xff;
		}
		sprintf(color, rgb_xxx_fmt, rcolor.r, rcolor.g, rcolor.b);
		if (rcolor.r2 || rcolor.g2 || rcolor.b2) {
			color = rz_str_appendf(color, rgb_xxx_fmt, rcolor.r2, rcolor.g2, rcolor.b2);
			rcolor.a = ALPHA_FGBG;
		} else {
			rcolor.a = ALPHA_FG;
		}
		rz_cons_rgb_str(cstr, sizeof(cstr), &rcolor);
		char *esc = strchr(cstr + 1, '\x1b');
		char *curtheme = rz_core_theme_get(core);

		rz_cons_printf("# Use '.' to randomize current color and ':' to randomize palette\n");
		rz_cons_printf("# Press '" Color_RED "rR" Color_GREEN "gG" Color_BLUE "bB" Color_RESET
			       "' or '" Color_BGRED "eE" Color_BGGREEN "fF" Color_BGBLUE "vV" Color_RESET
			       "' to change foreground/background color\n");
		rz_cons_printf("# Export colorscheme with command 'ec* > filename'\n");
		rz_cons_printf("# Preview command: '%s' - Press 'c' to change it\n", preview_cmd);
		rz_cons_printf("# Selected colorscheme : %s  - Use 'hl' or left/right arrow keys to change colorscheme\n", curtheme ? curtheme : "default");
		rz_cons_printf("# Selected element: %s  - Use 'jk' or up/down arrow keys to change element\n", k);
		rz_cons_printf("# ec %s %s # %d (\\x1b%.*s)",
			k, color, atoi(cstr + 7), esc ? (int)(esc - cstr - 1) : (int)strlen(cstr + 1), cstr + 1);
		if (esc) {
			rz_cons_printf(" (\\x1b%s)", esc + 1);
		}
		rz_cons_newline();

		rz_core_cmdf(core, "ec %s %s", k, color);
		char *res = rz_core_cmd_str(core, preview_cmd);
		int h, w = rz_cons_get_size(&h);
		char *body = rz_str_ansi_crop(res, 0, 0, w, h - 8);
		if (body) {
			rz_cons_printf("\n%s", body);
		}
		rz_cons_flush();
		ch = rz_cons_readchar();
		ch = rz_cons_arrow_to_hjkl(ch);
		switch (ch) {
#define CASE_RGB(x, X, y) \
	case x: \
		if ((y) > 0x00) { \
			(y)--; \
		} \
		break; \
	case X: \
		if ((y) < 0xff) { \
			(y)++; \
		} \
		break;
			CASE_RGB('R', 'r', rcolor.r);
			CASE_RGB('G', 'g', rcolor.g);
			CASE_RGB('B', 'b', rcolor.b);
			CASE_RGB('E', 'e', rcolor.r2);
			CASE_RGB('F', 'f', rcolor.g2);
			CASE_RGB('V', 'v', rcolor.b2);
		case 'Q':
		case 'q':
			free(body);
			free(color);
			return;
		case 'k':
			opt--;
			break;
		case 'j':
			opt++;
			break;
		case 'l':
			rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_NEXT);
			oopt = -1;
			break;
		case 'h':
			rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_PREVIOUS);
			oopt = -1;
			break;
		case 'K':
			opt = 0;
			break;
		case 'J':
			opt = rz_cons_pal_len() - 1;
			break;
		case ':':
			rz_cons_pal_random();
			break;
		case '.':
			rcolor.r = rz_num_rand32(0xff);
			rcolor.g = rz_num_rand32(0xff);
			rcolor.b = rz_num_rand32(0xff);
			break;
		case 'c':
			rz_line_set_prompt(cons->line, "Preview command> ");
			rz_cons_show_cursor(true);
			rz_cons_fgets(preview_cmd, sizeof(preview_cmd), 0, NULL);
			rz_cons_show_cursor(false);
		}
		if (opt != oopt) {
			rcolor = rz_cons_pal_get_i(opt);
			oopt = opt;
		}
		free(body);
	}
}
