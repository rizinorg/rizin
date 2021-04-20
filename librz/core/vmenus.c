// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "core_private.h"

#define MAX_FORMAT 3

enum {
	RZ_BYTE_DATA = 1,
	RZ_WORD_DATA = 2,
	RZ_DWORD_DATA = 4,
	RZ_QWORD_DATA = 8
};

enum {
	SORT_NONE,
	SORT_NAME,
	SORT_OFFSET
};

// TODO: move this helper into rz_cons
static char *prompt(const char *str, const char *txt) {
	char cmd[1024];
	char *res = NULL;
	char *oprompt = strdup(rz_cons_singleton()->line->prompt);
	rz_cons_show_cursor(true);
	if (txt && *txt) {
		free(rz_cons_singleton()->line->contents);
		rz_cons_singleton()->line->contents = strdup(txt);
	} else {
		RZ_FREE(rz_cons_singleton()->line->contents);
	}
	*cmd = '\0';
	rz_line_set_prompt(str);
	if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
		*cmd = '\0';
	}
	//line[strlen(line)-1]='\0';
	if (*cmd) {
		res = strdup(cmd);
	}
	rz_line_set_prompt(oprompt);
	free(oprompt);
	RZ_FREE(rz_cons_singleton()->line->contents);
	return res;
}

static char *colorize_asm_string(RzCore *core, const char *buf_asm, int optype, ut64 addr) {
	char *tmp, *spacer = NULL;
	char *source = (char *)buf_asm;
	bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	const char *color_num = core->cons->context->pal.num;
	const char *color_reg = core->cons->context->pal.reg;
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);

	if (!use_color) {
		return strdup(source);
	}
	// workaround dummy colorizer in case of paired commands (tms320 & friends)
	spacer = strstr(source, "||");
	if (spacer) {
		char *s1 = rz_str_ndup(source, spacer - source);
		char *s2 = strdup(spacer + 2);
		char *scol1 = rz_print_colorize_opcode(core->print, s1, color_reg, color_num, false, fcn ? fcn->addr : 0);
		char *scol2 = rz_print_colorize_opcode(core->print, s2, color_reg, color_num, false, fcn ? fcn->addr : 0);
		char *source = rz_str_newf("%s||%s", rz_str_get(scol1), rz_str_get(scol2));
		free(scol1);
		free(scol2);
		free(s1);
		free(s2);
		return source;
	}
	char *res = strdup("");
	res = rz_str_append(res, rz_print_color_op_type(core->print, optype));
	tmp = rz_print_colorize_opcode(core->print, source, color_reg, color_num, false, fcn ? fcn->addr : 0);
	res = rz_str_append(res, tmp);
	free(tmp);
	return res;
}

static int rotate_nibble(const ut8 b, int dir) {
	if (dir > 0) {
		bool high = b >> 7;
		return (b << 1) | high;
	}
	bool lower = b & 1;
	return (b >> 1) | (lower << 7);
}

static int wordpos(const char *esil, int n) {
	const char *w = esil;
	if (n < 1) {
		n = 0;
	}
	while (w && n--) {
		const char *nw = strchr(w + 1, ',');
		if (!nw) {
			return strlen(esil);
		}
		w = nw;
	}
	if (!w && n > 0) {
		return strlen(esil);
	}
	return (size_t)(w - esil);
}

static void showreg(RzAnalysisEsil *esil, const char *rn, const char *desc) {
	ut64 nm = 0;
	int sz = 0;
	rz_cons_printf("%s 0x%08" PFMT64x " (%d) ; %s\n", rn, nm, sz, desc);
}

RZ_API bool rz_core_visual_esil(RzCore *core) {
	const int nbits = sizeof(ut64) * 8;
	int analopType;
	char *word = NULL;
	int x = 0;
	RzAsmOp asmop;
	RzAnalysisOp analop;
	ut8 buf[sizeof(ut64)];
	unsigned int addrsize = rz_config_get_i(core->config, "esil.addr.size");

	if (core->blocksize < sizeof(ut64)) {
		return false;
	}
	memcpy(buf, core->block, sizeof(ut64));
	RzAnalysisEsil *esil = rz_analysis_esil_new(20, 0, addrsize);
	esil->analysis = core->analysis;
	rz_analysis_esil_set_pc(esil, core->offset);
	for (;;) {
		rz_cons_clear00();
		// bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
		(void)rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(ut64));
		analop.type = -1;
		(void)rz_analysis_op(core->analysis, &analop, core->offset, buf, sizeof(ut64), RZ_ANALYSIS_OP_MASK_ESIL);
		analopType = analop.type & RZ_ANALYSIS_OP_TYPE_MASK;
		rz_cons_printf("rizin's esil debugger:\n\n");
		rz_cons_printf("pos: %d\n", x);
		{
			char *op_hex = rz_asm_op_get_hex(&asmop);
			char *res = rz_print_hexpair(core->print, op_hex, -1);
			rz_cons_printf("hex: %s\n" Color_RESET, res);
			free(res);
			free(op_hex);
		}
		{
			char *op = colorize_asm_string(core, rz_asm_op_get_asm(&asmop), analopType, core->offset);
			rz_cons_printf(Color_RESET "asm: %s\n" Color_RESET, op);
			free(op);
		}
		{
			const char *expr = rz_strbuf_get(&analop.esil);
			rz_cons_printf(Color_RESET "esil: %s\n" Color_RESET, expr);
			int wp = wordpos(expr, x);
			char *pas = strdup(rz_str_pad(' ', wp ? wp + 1 : 0));
			int wp2 = wordpos(expr, x + 1);
			free(word);
			word = rz_str_ndup(expr + (wp ? (wp + 1) : 0), (wp2 - wp) - (wp ? 1 : 0));
			if (wp == wp2) {
				// x --;
				eprintf("Done\n");
				x = 0;
				rz_sys_sleep(1);
				free(pas);
				continue;
			}
			const char *pad = rz_str_pad('-', wp2 - ((wp > 0) ? wp + 1 : 0));
			rz_cons_printf(Color_RESET "      %s%s\n" Color_RESET, pas, pad);
			free(pas);
			// free (pad);
		}
		rz_cons_printf("esil regs:\n");
		showreg(esil, "$$", "address");
		showreg(esil, "$z", "zero");
		showreg(esil, "$b", "borrow");
		showreg(esil, "$c", "carry");
		showreg(esil, "$o", "overflow");
		showreg(esil, "$p", "parity");
		showreg(esil, "$r", "regsize");
		showreg(esil, "$s", "sign");
		showreg(esil, "$d", "delay");
		showreg(esil, "$j", "jump");

		rz_cons_printf("regs:\n");
		char *r = rz_core_cmd_str(core, "dr=");
		if (r) {
			rz_cons_printf("%s", r);
			free(r);
		}
		rz_cons_printf("esil stack:\n");
		rz_analysis_esil_dumpstack(esil);
		rz_analysis_op_fini(&analop);
		rz_cons_newline();
		rz_cons_visual_flush();

		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			break;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q':
		case 'q':
			goto beach;
		case 's':
			eprintf("step ((%s))\n", word);
			rz_sys_usleep(500);
			x = RZ_MIN(x + 1, nbits - 1);
			rz_analysis_esil_runword(esil, word);
			break;
		case 'S':
			eprintf("esil step over :D\n");
			rz_sys_usleep(500);
			break;
		case 'r':
		case 'h':
			x = 0; //RZ_MAX (x - 1, 0);
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"Vd1?: Visual Bit Editor Help:\n\n"
				" q     - quit the bit editor\n"
				" h/r   - reset / go back (reinitialize esil state)\n"
				" s     - esil step in\n"
				" j/k   - toggle bit value (same as space key)\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':': // TODO: move this into a separate helper function
		{
			char cmd[1024];
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			*cmd = 0;
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			rz_core_cmd0(core, cmd);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (cmd[0]) {
				rz_cons_any_key(NULL);
			}
			rz_cons_clear();
		} break;
		}
	}
beach:
	rz_analysis_esil_free(esil);
	free(word);
	return true;
}

RZ_API bool rz_core_visual_bit_editor(RzCore *core) {
	const int nbits = sizeof(ut64) * 8;
	bool colorBits = false;
	int analopType;
	int i, j, x = 0;
	RzAsmOp asmop;
	RzAnalysisOp analop;
	ut8 buf[sizeof(ut64)];
	bool bitsInLine = false;

	if (core->blocksize < sizeof(ut64)) {
		return false;
	}
	int cur = 0;
	if (core->print->cur != -1) {
		cur = core->print->cur;
	}
	memcpy(buf, core->block + cur, sizeof(ut64));
	for (;;) {
		rz_cons_clear00();
		bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
		(void)rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(ut64));
		analop.type = -1;
		(void)rz_analysis_op(core->analysis, &analop, core->offset, buf, sizeof(ut64), RZ_ANALYSIS_OP_MASK_ESIL);
		analopType = analop.type & RZ_ANALYSIS_OP_TYPE_MASK;
		rz_cons_printf("rizin's bit editor:\n\n");
		rz_cons_printf("offset: 0x%08" PFMT64x "\n" Color_RESET, core->offset + cur);
		{
			char *op_hex = rz_asm_op_get_hex(&asmop);
			char *res = rz_print_hexpair(core->print, op_hex, -1);
			rz_cons_printf("hex: %s\n" Color_RESET, res);
			free(res);
			free(op_hex);
		}
		rz_cons_printf("len: %d\n", asmop.size);
		{
			ut32 word = (x % 32);
			rz_cons_printf("shift: >> %d << %d\n", word, (asmop.size * 8) - word - 1);
		}
		{
			char *op = colorize_asm_string(core, rz_asm_op_get_asm(&asmop), analopType, core->offset);
			rz_cons_printf(Color_RESET "asm: %s\n" Color_RESET, op);
			free(op);
		}
		rz_cons_printf(Color_RESET "esl: %s\n" Color_RESET, rz_strbuf_get(&analop.esil));
		rz_analysis_op_fini(&analop);
		rz_cons_printf("chr:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			char ch = IS_PRINTABLE(*byte) ? *byte : '?';
			if (i == 4) {
				rz_cons_print(" |");
			}
			if (use_color) {
				rz_cons_printf(" %5s'%s%c" Color_RESET "'", " ", core->cons->context->pal.btext, ch);
			} else {
				rz_cons_printf(" %5s'%c'", " ", ch);
			}
		}
		rz_cons_printf("\ndec:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			if (i == 4) {
				rz_cons_print(" |");
			}
			rz_cons_printf(" %8d", *byte);
		}
		rz_cons_printf("\nhex:");
		for (i = 0; i < 8; i++) {
			const ut8 *byte = buf + i;
			if (i == 4) {
				rz_cons_print(" |");
			}
			rz_cons_printf("     0x%02x", *byte);
		}
		if (bitsInLine) {
			rz_cons_printf("\nbit: ");
			for (i = 0; i < 8; i++) {
				ut8 *byte = buf + i;
				if (i == 4) {
					rz_cons_print("| ");
				}
				if (colorBits && i >= asmop.size) {
					rz_cons_print(Color_RESET);
					colorBits = false;
				}
				for (j = 0; j < 8; j++) {
					bool bit = RZ_BIT_CHK(byte, 7 - j);
					rz_cons_printf("%d", bit ? 1 : 0);
				}
				rz_cons_print(" ");
			}
		} else {
			int set;
			const char *ws = rz_config_get_i(core->config, "scr.utf8") ? "·" : " ";
			for (set = 1; set >= 0; set--) {
				rz_cons_printf("\nbit: ");
				for (i = 0; i < 8; i++) {
					ut8 *byte = buf + i;
					if (i == 4) {
						rz_cons_print("| ");
					}
					if (colorBits && i >= asmop.size) {
						rz_cons_print(Color_RESET);
						colorBits = false;
					}
					for (j = 0; j < 8; j++) {
						bool bit = RZ_BIT_CHK(byte, 7 - j);
						if (set && bit) {
							rz_cons_print("1");
						} else if (!set && !bit) {
							rz_cons_print("0");
						} else {
							rz_cons_print(ws);
						}
					}
					rz_cons_print(" ");
				}
			}
		}
		rz_cons_newline();
		char str_pos[128];
		memset(str_pos, '-', nbits + 9);
		int pos = x;
		if (pos > 31) {
			pos += 2;
		}
		str_pos[pos + (x / 8)] = '^';
		str_pos[nbits + 9] = 0;
		str_pos[8] = ' ';
		str_pos[17] = ' ';
		str_pos[26] = ' ';
		str_pos[35] = ' ';
		str_pos[36] = ' ';
		str_pos[37] = ' ';
		str_pos[46] = ' ';
		str_pos[55] = ' ';
		str_pos[64] = ' ';
		rz_cons_printf("pos: %s\n", str_pos);
		rz_cons_newline();
		rz_cons_visual_flush();

		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			break;
		}
		if (ch != 10) {
			ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		}
		switch (ch) {
		case 'Q':
		case 'q': {
			char *op_hex = rz_asm_op_get_hex(&asmop);
			char *res = rz_print_hexpair(core->print, op_hex, -1);
			rz_core_write_at(core, core->offset, buf, 4);
			free(res);
			free(op_hex);
		}
			return false;
		case 'H': {
			int y = RZ_MAX(x - 8, 0);
			x = y - y % 8;
		} break;
		case 'L':
		case 9: {
			int y = RZ_MIN(x + 8, nbits - 8);
			x = y - y % 8;
		} break;
		case 'j':
		case 'k':
		case 10:
		case ' ':
			//togglebit();
			{
				const int nbyte = x / 8;
				const int nbit = 7 - (x - (nbyte * 8));
				ut8 *byte = buf + nbyte;
				bool bit = RZ_BIT_CHK(byte, nbit);
				if (bit) {
					RZ_BIT_UNSET(byte, nbit);
				} else {
					RZ_BIT_SET(byte, nbit);
				}
			}
			break;
		case '>':
			buf[x / 8] = rotate_nibble(buf[(x / 8)], -1);
			break;
		case '<':
			buf[x / 8] = rotate_nibble(buf[(x / 8)], 1);
			break;
		case 'i': {
			rz_line_set_prompt("> ");
			const char *line = rz_line_readline();
			ut64 num = rz_num_math(core->num, line);
			if (num || (!num && *line == '0')) {
				buf[x / 8] = num;
			}
		} break;
		case 'R':
			if (rz_config_get_b(core->config, "scr.randpal")) {
				rz_cons_pal_random();
			} else {
				rz_core_theme_nextpal(core, 'n');
			}
			break;
		case '+':
			buf[(x / 8)]++;
			break;
		case '-':
			buf[(x / 8)]--;
			break;
		case 'h':
			x = RZ_MAX(x - 1, 0);
			break;
		case 'l':
			x = RZ_MIN(x + 1, nbits - 1);
			break;
		case 'b':
			bitsInLine = !bitsInLine;
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"Vd1?: Visual Bit Editor Help:\n\n"
				" q     - quit the bit editor\n"
				" R     - randomize color palette\n"
				" b     - toggle bitsInLine\n"
				" j/k   - toggle bit value (same as space key)\n"
				" h/l   - select next/previous bit\n"
				" +/-   - increment or decrement byte value\n"
				" </>   - rotate left/right byte value\n"
				" i     - insert numeric value of byte\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':': // TODO: move this into a separate helper function
		{
			char cmd[1024];
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			cmd[0] = '\0';
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			rz_core_cmd(core, cmd, 1);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (cmd[0]) {
				rz_cons_any_key(NULL);
			}
			rz_cons_clear();
		} break;
		}
	}
	return true;
}

RZ_API bool rz_core_visual_hudclasses(RzCore *core) {
	RzListIter *iter, *iter2;
	RzBinClass *c;
	RzBinField *f;
	RzBinSymbol *m;
	ut64 addr;
	char *res;
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	list->free = free;
	RzList *classes = rz_bin_get_classes(core->bin);
	rz_list_foreach (classes, iter, c) {
		rz_list_foreach (c->fields, iter2, f) {
			rz_list_append(list, rz_str_newf("0x%08" PFMT64x "  %s %s", f->vaddr, c->name, f->name));
		}
		rz_list_foreach (c->methods, iter2, m) {
			const char *name = m->dname ? m->dname : m->name;
			rz_list_append(list, rz_str_newf("0x%08" PFMT64x "  %s %s", m->vaddr, c->name, name));
		}
	}
	res = rz_cons_hud(list, NULL);
	if (res) {
		char *p = strchr(res, ' ');
		if (p) {
			*p = 0;
		}
		addr = rz_num_get(NULL, res);
		rz_core_seek(core, addr, true);
		free(res);
	}
	rz_list_free(list);
	return res != NULL;
}

static bool hudstuff_append(RzFlagItem *fi, void *user) {
	RzList *list = (RzList *)user;
	char *s = rz_str_newf("0x%08" PFMT64x "  %s", fi->offset, fi->name);
	if (s) {
		rz_list_append(list, s);
	}
	return true;
}

RZ_API bool rz_core_visual_hudstuff(RzCore *core) {
	ut64 addr;
	char *res;
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	list->free = free;
	rz_flag_foreach(core->flags, hudstuff_append, list);
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *mi;
	rz_interval_tree_foreach (&core->analysis->meta, it, mi) {
		if (mi->type == RZ_META_TYPE_COMMENT) {
			char *s = rz_str_newf("0x%08" PFMT64x " %s", rz_interval_tree_iter_get(&it)->start, mi->str);
			if (s) {
				rz_list_push(list, s);
			}
		}
	}
	res = rz_cons_hud(list, NULL);
	if (res) {
		char *p = strchr(res, ' ');
		if (p) {
			*p = 0;
		}
		addr = rz_num_get(NULL, res);
		rz_core_seek(core, addr, true);
		free(res);
	}
	rz_list_free(list);
	return res != NULL;
}

static bool rz_core_visual_config_hud(RzCore *core) {
	RzListIter *iter;
	RzConfigNode *bt;
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	list->free = free;
	rz_list_foreach (core->config->nodes, iter, bt) {
		rz_list_append(list, rz_str_newf("%s %s", bt->name, bt->value));
	}
	char *res = rz_cons_hud(list, NULL);
	if (res) {
		const char *oldvalue = NULL;
		char cmd[512];
		char *p = strchr(res, ' ');
		if (p) {
			*p = 0;
		}
		oldvalue = rz_config_get(core->config, res);
		rz_cons_show_cursor(true);
		rz_cons_set_raw(false);
		cmd[0] = '\0';
		eprintf("Set new value for %s (old=%s)\n", res, oldvalue);
		rz_line_set_prompt(":> ");
		if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
			cmd[0] = '\0';
		}
		rz_config_set(core->config, res, cmd);
		rz_cons_set_raw(true);
		rz_cons_show_cursor(false);
	}
	rz_list_free(list);
	return true;
}

// TODO: skip N first elements
// TODO: show only N elements of the list
// TODO: wrap index when out of boundaries
// TODO: Add support to show class fields too
// Segfaults - stack overflow, because of recursion
static void *show_class(RzCore *core, int mode, int *idx, RzBinClass *_c, const char *grep, RzList *list) {
	bool show_color = rz_config_get_i(core->config, "scr.color");
	RzListIter *iter;
	RzBinClass *c, *cur = NULL;
	RzBinSymbol *m, *mur = NULL;
	RzBinField *f, *fur = NULL;
	int i = 0;
	int skip = *idx - 10;
	bool found = false;

	switch (mode) {
	case 'c':
		rz_cons_printf("[hjkl_/Cfm]> classes:\n\n");
		rz_list_foreach (list, iter, c) {
			if (grep) {
				if (!rz_str_casestr(c->name, grep)) {
					i++;
					continue;
				}
			} else {
				if (*idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}
			if (show_color) {
				if (i == *idx) {
					const char *clr = Color_BLUE;
					rz_cons_printf(Color_GREEN ">>" Color_RESET " %02d %s0x%08" PFMT64x Color_YELLOW "  %s\n" Color_RESET,
						i, clr, c->addr, c->name);
				} else {
					rz_cons_printf("-  %02d %s0x%08" PFMT64x Color_RESET "  %s\n",
						i, core->cons->context->pal.offset, c->addr, c->name);
				}
			} else {
				rz_cons_printf("%s %02d 0x%08" PFMT64x "  %s\n",
					(i == *idx) ? ">>" : "- ", i, c->addr, c->name);
			}
			if (i++ == *idx) {
				cur = c;
			}
			found = true;
		}
		if (!cur) {
			*idx = i - 1;
			if (!found) {
				return NULL;
			}
			//  rz_cons_clear00 ();
			return NULL; // show_class (core, mode, idx, _c, "", list);
		}
		return cur;
	case 'f':
		// show fields
		rz_cons_printf("[hjkl_/cFm]> fields of %s:\n\n", _c->name);
		rz_list_foreach (_c->fields, iter, f) {
			const char *name = f->name;
			if (grep) {
				if (!rz_str_casestr(name, grep)) {
					i++;
					continue;
				}
			} else {
				if (*idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}

			char *mflags = strdup("");

			if (rz_str_startswith(name, _c->name)) {
				name += strlen(_c->name);
			}
			if (show_color) {
				if (i == *idx) {
					const char *clr = Color_BLUE;
					rz_cons_printf(Color_GREEN ">>" Color_RESET " %02d %s0x%08" PFMT64x Color_YELLOW " %s %s\n" Color_RESET,
						i, clr, f->vaddr, mflags, name);
				} else {
					rz_cons_printf("-  %02d %s0x%08" PFMT64x Color_RESET " %s %s\n",
						i, core->cons->context->pal.offset, f->vaddr, mflags, name);
				}
			} else {
				rz_cons_printf("%s %02d 0x%08" PFMT64x " %s %s\n",
					(i == *idx) ? ">>" : "- ", i, f->vaddr, mflags, name);
			}

			RZ_FREE(mflags);

			if (i++ == *idx) {
				fur = f;
			}
		}
		if (!fur) {
			*idx = i - 1;
			if (rz_list_empty(_c->fields)) {
				return NULL;
			}
			// rz_cons_clear00 ();
			return NULL; // show_class (core, mode, idx, _c, grep, list);
		}
		return fur;
		break;
	case 'm':
		// show methods
		if (!_c) {
			eprintf("No class selected.\n");
			return mur;
		}
		rz_cons_printf("[hjkl_/cfM]> methods of %s\n\n", _c->name);
		rz_list_foreach (_c->methods, iter, m) {
			const char *name = m->dname ? m->dname : m->name;
			char *mflags;
			if (grep) {
				if (!rz_str_casestr(name, grep)) {
					i++;
					continue;
				}
			} else {
				if (*idx > 10) {
					skip--;
					if (skip > 0) {
						i++;
						continue;
					}
				}
			}

			mflags = rz_core_bin_method_flags_str(m->method_flags, 0);

			if (show_color) {
				if (rz_str_startswith(name, _c->name)) {
					name += strlen(_c->name);
				}
				if (i == *idx) {
					const char *clr = Color_BLUE;
					rz_cons_printf(Color_GREEN ">>" Color_RESET " %02d %s0x%08" PFMT64x Color_YELLOW " %s %s\n" Color_RESET,
						i, clr, m->vaddr, mflags, name);
				} else {
					rz_cons_printf("-  %02d %s0x%08" PFMT64x Color_RESET " %s %s\n",
						i, core->cons->context->pal.offset, m->vaddr, mflags, name);
				}
			} else {
				rz_cons_printf("%s %02d 0x%08" PFMT64x " %s %s\n",
					(i == *idx) ? ">>" : "- ", i, m->vaddr, mflags, name);
			}

			RZ_FREE(mflags);

			if (i++ == *idx) {
				mur = m;
			}
		}
		if (!mur) {
			*idx = i - 1;
			if (rz_list_empty(_c->methods)) {
				return NULL;
			}
			// rz_cons_clear00 ();
			return NULL; // show_class (core, mode, idx, _c, grep, list);
		}
		return mur;
	}
	return NULL;
}

RZ_API int rz_core_visual_classes(RzCore *core) {
	int ch, index = 0;
	char cmd[1024];
	int mode = 'c';
	RzBinClass *cur = NULL;
	RzBinSymbol *mur = NULL;
	RzBinField *fur = NULL;
	void *ptr;
	int oldcur = 0;
	char *grep = NULL;
	bool grepmode = false;
	RzList *list = rz_bin_get_classes(core->bin);
	if (rz_list_empty(list)) {
		rz_cons_message("No Classes");
		return false;
	}
	for (;;) {
		int cols;
		rz_cons_clear00();
		if (grepmode) {
			rz_cons_printf("Grep: %s\n", grep ? grep : "");
		}
		ptr = show_class(core, mode, &index, cur, grep, list);
		switch (mode) {
		case 'f':
			fur = (RzBinField *)ptr;
			break;
		case 'm':
			mur = (RzBinSymbol *)ptr;
			break;
		case 'c':
			cur = (RzBinClass *)ptr;
			break;
		}

		/* update terminal size */
		(void)rz_cons_get_size(&cols);
		rz_cons_visual_flush();
		ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			RZ_FREE(grep);
			return false;
		}

		if (grepmode) {
			switch (ch) {
			case 127:
				if (grep) {
					int len = strlen(grep);
					if (len < 1) {
						grepmode = false;
					} else {
						grep[len - 1] = 0;
					}
				}
				break;
			case ' ':
			case '\r':
			case '\n':
				RZ_FREE(grep);
				grepmode = false;
				break;
			default:
				grep = grep
					? rz_str_appendf(grep, "%c", ch)
					: rz_str_newf("%c", ch);
				break;
			}
			continue;
		}

		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'C':
			rz_config_toggle(core->config, "scr.color");
			break;
		case '_':
			if (rz_core_visual_hudclasses(core)) {
				return true;
			}
			break;
		case 'J': index += 10; break;
		case 'j': index++; break;
		case 'k':
			if (--index < 0) {
				index = 0;
			}
			break;
		case 'K':
			index -= 10;
			if (index < 0) {
				index = 0;
			}
			break;
		case 'g':
			index = 0;
			break;
		case 'G':
			index = rz_list_length(list) - 1;
			break;
		case 'i': {
			char *num = prompt("Index:", NULL);
			if (num) {
				index = atoi(num);
				free(num);
			}
		} break;
		case 'p':
			if (mode == 'm' && mur) {
				rz_core_seek(core, mur->vaddr, true);
				rz_core_analysis_function_add(core, NULL, core->offset, false);
				rz_core_cmd0(core, "pdf~..");
			}
			break;
		case 'm': // methods
			mode = 'm';
			break;
		case 'f': // fields
			mode = 'f';
			break;
		case 'h':
		case 127: // backspace
		case 'b': // back
		case 'Q':
		case 'c':
		case 'q':
			if (mode == 'c') {
				return true;
			}
			mode = 'c';
			index = oldcur;
			break;
		case '/':
			grepmode = true;
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			if (mur && mode == 'm') {
				rz_core_seek(core, mur->vaddr, true);
				return true;
			}
			if (fur) {
				rz_core_seek(core, fur->vaddr, true);
				return true;
			}
			if (cur) {
				oldcur = index;
				index = 0;
				mode = 'm';
			}
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"\nVF: Visual Classes help:\n\n"
				" q     - quit menu\n"
				" j/k   - down/up keys\n"
				" h/b   - go back\n"
				" g/G   - go first/last item\n"
				" i     - specify index\n"
				" /     - grep mode\n"
				" C     - toggle colors\n"
				" f     - show class fields\n"
				" m     - show class methods\n"
				" l/' ' - accept current selection\n"
				" p     - preview method disasm with less\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':':
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			cmd[0] = '\0';
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			//line[strlen(line)-1]='\0';
			rz_core_cmd(core, cmd, 1);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (cmd[0]) {
				rz_cons_any_key(NULL);
			}
			//cons_gotoxy(0,0);
			rz_cons_clear();
			break;
		}
	}
	return true;
}

static void analysis_class_print(RzAnalysis *analysis, const char *class_name) {
	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);

	rz_cons_print(class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		bool first = true;
		rz_vector_foreach(bases, base) {
			if (first) {
				rz_cons_print(": ");
				first = false;
			} else {
				rz_cons_print(", ");
			}
			rz_cons_print(base->class_name);
		}
		rz_vector_free(bases);
	}

	rz_cons_print("\n");

	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach(vtables, vtable) {
			rz_cons_printf("  %2s vtable 0x%" PFMT64x " @ +0x%" PFMT64x " size:+0x%" PFMT64x "\n", vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		rz_vector_free(vtables);
	}

	rz_cons_print("\n");

	if (methods) {
		RzAnalysisMethod *meth;
		rz_vector_foreach(methods, meth) {
			rz_cons_printf("  %s @ 0x%" PFMT64x, meth->name, meth->addr);
			if (meth->vtable_offset >= 0) {
				rz_cons_printf(" (vtable + 0x%" PFMT64x ")\n", (ut64)meth->vtable_offset);
			} else {
				rz_cons_print("\n");
			}
		}
		rz_vector_free(methods);
	}
}

static const char *show_analysis_classes(RzCore *core, char mode, int *idx, SdbList *list, const char *class_name) {
	bool show_color = rz_config_get_i(core->config, "scr.color");
	SdbListIter *iter;
	SdbKv *kv;
	int i = 0;
	int skip = *idx - 10;
	const char *cur_class = NULL;
	rz_cons_printf("[hjkl_/Cfm]> analysis classes:\n\n");

	if (mode == 'd' && class_name) {
		analysis_class_print(core->analysis, class_name);
		return class_name;
	}

	ls_foreach (list, iter, kv) {
		if (*idx > 10) {
			skip--;
			if (skip > 0) {
				i++;
				continue;
			}
		}
		class_name = sdbkv_key(kv);

		if (show_color) {
			const char *pointer = "- ";
			const char *txt_clr = "";

			if (i == *idx) {
				pointer = Color_GREEN ">>";
				txt_clr = Color_YELLOW;
				cur_class = class_name;
			}
			rz_cons_printf("%s" Color_RESET " %02d"
				       " %s%s\n" Color_RESET,
				pointer, i, txt_clr, class_name);
		} else {
			rz_cons_printf("%s %02d %s\n", (i == *idx) ? ">>" : "- ", i, class_name);
		}

		i++;
	}

	return cur_class;
}
// TODO add other commands that Vbc has
// Should the classes be refreshed after command execution with :
// in case new class information would be added?
// Add grep?
RZ_API int rz_core_visual_analysis_classes(RzCore *core) {
	int ch, index = 0;
	char command[1024];
	SdbList *list = rz_analysis_class_get_all(core->analysis, true);
	int oldcur = 0;
	char mode = ' ';
	const char *class_name = "";

	if (rz_list_empty(list)) {
		rz_cons_message("No Classes");
		goto cleanup;
	}
	for (;;) {
		int cols;
		rz_cons_clear00();

		class_name = show_analysis_classes(core, mode, &index, list, class_name);

		/* update terminal size */
		(void)rz_cons_get_size(&cols);
		rz_cons_visual_flush();
		ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			goto cleanup;
		}

		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'C':
			rz_config_toggle(core->config, "scr.color");
			break;
		case 'J':
			index += 10;
			if (index >= list->length) {
				index = list->length - 1;
			}
			break;
		case 'j':
			if (++index >= list->length) {
				index = 0;
			}
			break;
		case 'k':
			if (--index < 0) {
				index = list->length - 1;
			}
			break;
		case 'K':
			index -= 10;
			if (index < 0) {
				index = 0;
			}
			break;
		case 'g':
			index = 0;
			break;
		case 'G':
			index = list->length - 1;
			break;
		case 'h':
		case 127: // backspace
		case 'b': // back
		case 'Q':
		case 'c':
		case 'q':
			if (mode == ' ') {
				goto cleanup;
			}
			mode = ' ';
			index = oldcur;
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			mode = 'd';
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"\nVF: Visual Classes help:\n\n"
				" q     - quit menu\n"
				" j/k   - down/up keys\n"
				" h/b   - go back\n"
				" g/G   - go first/last item\n"
				" l/' ' - accept current selection\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':':
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			command[0] = '\0';
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(command, sizeof(command), 0, NULL) < 0) {
				command[0] = '\0';
			}
			//line[strlen(line)-1]='\0';
			rz_core_cmd(core, command, 1);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (command[0]) {
				rz_cons_any_key(NULL);
			}
			//cons_gotoxy(0,0);
			rz_cons_clear();
			break;
		}
	}
cleanup:
	ls_free(list);
	return true;
}

static int flag_name_sort(const void *a, const void *b) {
	const RzFlagItem *fa = (const RzFlagItem *)a;
	const RzFlagItem *fb = (const RzFlagItem *)b;
	return strcmp(fa->name, fb->name);
}

static int flag_offset_sort(const void *a, const void *b) {
	const RzFlagItem *fa = (const RzFlagItem *)a;
	const RzFlagItem *fb = (const RzFlagItem *)b;
	if (fa->offset < fb->offset) {
		return -1;
	}
	if (fa->offset > fb->offset) {
		return 1;
	}
	return 0;
}

static void sort_flags(RzList *l, int sort) {
	switch (sort) {
	case SORT_NAME:
		rz_list_sort(l, flag_name_sort);
		break;
	case SORT_OFFSET:
		rz_list_sort(l, flag_offset_sort);
		break;
	case SORT_NONE:
	default:
		break;
	}
}

// TODO: remove this statement, should be a separate .o

static char *print_rop(void *_core, void *_item, bool selected) {
	char *line = _item;
	// TODO: trim if too long
	return rz_str_newf("%c %s\n", selected ? '>' : ' ', line);
}

RZ_API int rz_core_visual_view_rop(RzCore *core) {
	RzListIter *iter;
	const int rows = 7;
	int cur = 0;

	rz_line_set_prompt("rop regexp: ");
	const char *line = rz_line_readline();

	int scr_h, scr_w = rz_cons_get_size(&scr_h);

	if (!line || !*line) {
		return false;
	}
	// maybe store in RzCore, so we can save it in project and use it outside visual

	eprintf("Searching ROP gadgets...\n");
	char *ropstr = rz_core_cmd_strf(core, "\"/Rl %s\" @e:scr.color=0", line);
	RzList *rops = rz_str_split_list(ropstr, "\n", 0);
	int delta = 0;
	bool show_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	bool forceaddr = false;
	ut64 addr = UT64_MAX;
	char *cursearch = strdup(line);
	while (true) {
		rz_cons_clear00();
		rz_cons_printf("[0x%08" PFMT64x "]-[visual-rzrop] %s (see pdp command)\n",
			(addr == UT64_MAX) ? 0 : addr + delta, cursearch);

		// compute chain
		RzStrBuf *sb = rz_strbuf_new("");
		char *msg;
		rz_list_foreach (core->ropchain, iter, msg) {
			if (core->rasm->bits == 64) {
				ut64 n = rz_num_get(NULL, msg);
				n = rz_read_be64(&n);
				rz_strbuf_appendf(sb, "%016" PFMT64x, n);
			} else {
				ut32 n = rz_num_get(NULL, msg);
				n = rz_read_be32(&n);
				rz_strbuf_appendf(sb, "%08x", n);
			}
		}
		char *chainstr = rz_strbuf_drain(sb);

		char *wlist = rz_str_widget_list(core, rops, rows, cur, print_rop);
		rz_cons_printf("%s", wlist);
		free(wlist);
		char *curline = rz_str_dup(NULL, rz_str_trim_head_ro(rz_str_widget_list(core, rops, rows, cur, print_rop)));
		if (curline) {
			char *sp = strchr(curline, ' ');
			if (sp) {
				*sp = 0;
				if (!forceaddr) {
					addr = rz_num_math(NULL, curline);
				}
				*sp = ' ';
			}
			if (addr != UT64_MAX) {
				rz_cons_printf("Gadget:");
				// get comment
				char *output = rz_core_cmd_strf(core, "piu 10 @ 0x%08" PFMT64x, addr + delta);
				if (output) {
					rz_cons_strcat_at(output, 0, 10, scr_w, 10);
					free(output);
				}
			}
		}
		int count = 0;
		rz_cons_flush();
		rz_cons_gotoxy(0, 20);
		rz_cons_printf("ROPChain:\n  %s\n", chainstr ? chainstr : "");
		int chainstrlen = chainstr ? strlen(chainstr) : 0;
		rz_list_foreach (core->ropchain, iter, msg) {
			int extra = chainstrlen / scr_w;
			rz_cons_gotoxy(0, extra + 22 + count);
			rz_cons_strcat(msg);
			const char *cmt = rz_meta_get_string(core->analysis, RZ_META_TYPE_COMMENT, rz_num_get(NULL, msg));
			if (cmt) {
				rz_cons_strcat(cmt);
			}
			count++;
		}
		rz_cons_flush();
		int ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			free(curline);
			free(cursearch);
			RZ_FREE(chainstr);
			return false;
		}
#define NEWTYPE(x, y) rz_mem_dup(&(y), sizeof(x));
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 127:
			free(rz_list_pop(core->ropchain));
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf("[rzrop-visual] Help\n"
				       " jk - select next/prev rop gadget\n"
				       " JK - scroll next/prev page from list\n"
				       " hl - increase/decrease delta offset in disasm\n"
				       " \\n - enter key or dot will add the current offset into the chain\n"
				       " i  - enter a number to be pushed into the chain\n"
				       " :  - run rizin command\n"
				       " ;  - add comment in current offset\n"
				       " <- - backspace - delete last gadget from the chain\n"
				       " /  - highlight given word\n"
				       " y  - yank current rop chain into the clipboard (y?)\n"
				       " o  - seek to given offset\n"
				       " r  - run /R again\n"
				       " ?  - show this help message\n"
				       " q  - quit this view\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':': // TODO: move this into a separate helper function
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			while (true) {
				char cmd[1024];
				cmd[0] = '\0';
				rz_line_set_prompt(":> ");
				if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				if (!*cmd || *cmd == 'q') {
					break;
				}
				ut64 oseek = core->offset;
				rz_core_seek(core, addr + delta, false);
				rz_core_cmd(core, cmd, 1);
				rz_core_seek(core, oseek, false);
				rz_cons_flush();
			}
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			break;
		case 'y':
			rz_core_yank_hexpair(core, chainstr);
			break;
		case 'o': {
			rz_line_set_prompt("offset: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				ut64 off = rz_num_math(core->num, line);
				rz_core_seek(core, off, true);
				addr = off;
				forceaddr = true;
				delta = 0;
			}
		} break;
		case 'r': {
			rz_line_set_prompt("rop regexp: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				free(cursearch);
				delta = 0;
				addr = UT64_MAX;
				cur = 0;
				cursearch = strdup(line);
				free(ropstr);
				ropstr = rz_core_cmd_strf(core, "\"/Rl %s\" @e:scr.color=0", line);
				rz_list_free(rops);
				rops = rz_str_split_list(ropstr, "\n", 0);
			}
		} break;
		case '/':
			rz_core_cmd0(core, "?i highlight;e scr.highlight=`yp`");
			break;
		case 'i': {
			rz_line_set_prompt("insert value: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				ut64 n = rz_num_math(core->num, line);
				rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x, n));
			}
		} break;
		case ';': {
			rz_line_set_prompt("comment: ");
			const char *line = rz_line_readline();
			if (line && *line) {
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr + delta, line);
			}
		} break;
		case '.':
		case '\n':
		case '\r':
			if (curline && *curline) {
				char *line = rz_core_cmd_strf(core, "piuq@0x%08" PFMT64x, addr + delta);
				rz_str_replace_char(line, '\n', ';');
				if (show_color) {
					// XXX parsing fails to read this ansi-offset
					// const char *offsetColor = rz_cons_singleton ()->context->pal.offset; // TODO etooslow. must cache
					// rz_list_push (core->ropchain, rz_str_newf ("%s0x%08"PFMT64x""Color_RESET"  %s", offsetColor, addr + delta, line));
					rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x "  %s", addr + delta, line));
				} else {
					rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x "  %s", addr + delta, line));
				}
				free(line);
			}
			break;
		case 'h':
			delta--;
			break;
		case 'l':
			delta++;
			break;
		case 'J':
			cur += 10;
			forceaddr = false;
			delta = 0;
			break;
		case 'K':
			delta = 0;
			forceaddr = false;
			if (cur > 10) {
				cur -= 10;
			} else {
				cur = 0;
			}
			break;
		case '0':
			delta = 0;
			cur = 0;
			break;
		case 'j':
			delta = 0;
			cur++;
			forceaddr = false;
			break;
		case 'k':
			delta = 0;
			forceaddr = false;
			if (cur > 0) {
				cur--;
			} else {
				cur = 0;
			}
			break;
		case 'q':
			free(curline);
			free(cursearch);
			RZ_FREE(chainstr);
			return true;
		}
		RZ_FREE(chainstr);
		free(curline);
	}
	free(cursearch);
	return false;
}

RZ_API int rz_core_visual_trackflags(RzCore *core) {
	const char *fs = NULL, *fs2 = NULL;
	int hit, i, j, ch;
	int _option = 0;
	int option = 0;
	char cmd[1024];
	int format = 0;
	int delta = 7;
	int menu = 0;
	int sort = SORT_NONE;

	if (rz_flag_space_is_empty(core->flags)) {
		menu = 1;
	}
	for (;;) {
		bool hasColor = rz_config_get_i(core->config, "scr.color");
		rz_cons_clear00();

		if (menu) {
			rz_cons_printf("Flags in flagspace '%s'. Press '?' for help.\n\n",
				rz_flag_space_cur_name(core->flags));
			hit = 0;
			i = j = 0;
			RzList *l = rz_flag_all_list(core->flags, true);
			RzListIter *iter;
			RzFlagItem *fi;
			sort_flags(l, sort);
			rz_list_foreach (l, iter, fi) {
				if (option == i) {
					fs2 = fi->name;
					hit = 1;
				}
				if ((i >= option - delta) && ((i < option + delta) || ((option < delta) && (i < (delta << 1))))) {
					bool cur = option == i;
					if (cur && hasColor) {
						rz_cons_printf(Color_INVERT);
					}
					rz_cons_printf(" %c  %03d 0x%08" PFMT64x " %4" PFMT64d " %s\n",
						cur ? '>' : ' ', i, fi->offset, fi->size, fi->name);
					if (cur && hasColor) {
						rz_cons_printf(Color_RESET);
					}
					j++;
				}
				i++;
			}
			rz_list_free(l);

			if (!hit && i > 0) {
				option = i - 1;
				continue;
			}
			if (fs2) {
				int cols, rows = rz_cons_get_size(&cols);
				//int rows = 20;
				rows -= 12;
				rz_cons_printf("\n Selected: %s\n\n", fs2);
				// Honor MAX_FORMATS here
				switch (format) {
				case 0:
					snprintf(cmd, sizeof(cmd), "px %d @ %s!64", rows * 16, fs2);
					core->printidx = 0;
					break;
				case 1:
					snprintf(cmd, sizeof(cmd), "pd %d @ %s!64", rows, fs2);
					core->printidx = 1;
					break;
				case 2:
					snprintf(cmd, sizeof(cmd), "ps @ %s!64", fs2);
					core->printidx = 5;
					break;
				case 3: strcpy(cmd, "f="); break;
				default: format = 0; continue;
				}
				if (*cmd) {
					rz_core_cmd(core, cmd, 0);
				}
			} else {
				rz_cons_printf("(no flags)\n");
			}
		} else {
			rz_cons_printf("Flag spaces:\n\n");
			hit = 0;
			RzSpaceIter it;
			const RzSpace *s, *cur = rz_flag_space_cur(core->flags);
			int i = 0;
			rz_flag_space_foreach(core->flags, it, s) {
				if (option == i) {
					fs = s->name;
					hit = 1;
				}
				if ((i >= option - delta) && ((i < option + delta) || ((option < delta) && (i < (delta << 1))))) {
					rz_cons_printf(" %c %c %s\n",
						(option == i) ? '>' : ' ',
						(s == cur) ? '*' : ' ',
						s->name);
				}
				i++;
			}
			if (option == i) {
				fs = "*";
				hit = 1;
			}
			rz_cons_printf(" %c %c %s\n", (option == i) ? '>' : ' ',
				!cur ? '*' : ' ', "*");
			i++;
			if (!hit && i > 0) {
				option = i - 1;
				continue;
			}
		}
		rz_cons_visual_flush();
		ch = rz_cons_readchar();
		if (ch == -1 || ch == 4) {
			return false;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'C':
			rz_config_toggle(core->config, "scr.color");
			break;
		case '_':
			if (rz_core_visual_hudstuff(core)) {
				return true;
			}
			break;
		case 'J': option += 10; break;
		case 'o': sort = SORT_OFFSET; break;
		case 'n': sort = SORT_NAME; break;
		case 'j': option++; break;
		case 'k':
			if (--option < 0) {
				option = 0;
			}
			break;
		case 'K':
			option -= 10;
			if (option < 0) {
				option = 0;
			}
			break;
		case 'h':
		case 'b': // back
		case 'Q':
		case 'q':
			if (menu <= 0) {
				return true;
			}
			menu--;
			option = _option;
			if (menu == 0) {
				rz_flag_space_set(core->flags, NULL);
				// if no flagspaces, just quit
				if (rz_flag_space_is_empty(core->flags)) {
					return true;
				}
			}
			break;
		case 'a':
			switch (menu) {
			case 0: // new flag space
				rz_cons_show_cursor(true);
				rz_line_set_prompt("add flagspace: ");
				strcpy(cmd, "fs ");
				if (rz_cons_fgets(cmd + 3, sizeof(cmd) - 3, 0, NULL) > 0) {
					rz_core_cmd(core, cmd, 0);
					rz_cons_set_raw(1);
					rz_cons_show_cursor(false);
				}
				break;
			case 1: // new flag
				rz_cons_show_cursor(true);
				rz_line_set_prompt("add flag: ");
				strcpy(cmd, "f ");
				if (rz_cons_fgets(cmd + 2, sizeof(cmd) - 2, 0, NULL) > 0) {
					rz_core_cmd(core, cmd, 0);
					rz_cons_set_raw(1);
					rz_cons_show_cursor(false);
				}
				break;
			}
			break;
		case 'd':
			rz_flag_unset_name(core->flags, fs2);
			break;
		case 'e':
			/* TODO: prompt for addr, size, name */
			eprintf("TODO\n");
			rz_sys_sleep(1);
			break;
		case '*':
			rz_core_block_size(core, core->blocksize + 16);
			break;
		case '/':
			rz_core_block_size(core, core->blocksize - 16);
			break;
		case '+':
			if (menu == 1) {
				rz_core_cmdf(core, "f %s=%s+1", fs2, fs2);
			} else {
				rz_core_block_size(core, core->blocksize + 1);
			}
			break;
		case '-':
			if (menu == 1) {
				rz_core_cmdf(core, "f %s=%s-1", fs2, fs2);
			} else {
				rz_core_block_size(core, core->blocksize - 1);
			}
			break;
		case 'r': // "Vtr"
			if (menu == 1) {
				int len;
				rz_cons_show_cursor(true);
				rz_cons_set_raw(0);
				// TODO: use rz_flag_rename or fail?..`fr` doesn't uses this..
				snprintf(cmd, sizeof(cmd), "fr %s ", fs2);
				len = strlen(cmd);
				eprintf("Rename flag '%s' as:\n", fs2);
				rz_line_set_prompt(":> ");
				if (rz_cons_fgets(cmd + len, sizeof(cmd) - len, 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				rz_core_cmd(core, cmd, 0);
				rz_cons_set_raw(1);
				rz_cons_show_cursor(false);
			}
			break;
		case 'R':
			if (menu == 1) {
				char line[1024];
				rz_cons_show_cursor(true);
				rz_cons_set_raw(0);
				eprintf("Rename function '%s' as:\n", fs2);
				rz_line_set_prompt(":> ");
				if (rz_cons_fgets(line, sizeof(line), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				int res = snprintf(cmd, sizeof(cmd), "afr %s %s", line, fs2);
				if (res < sizeof(cmd)) {
					rz_core_cmd(core, cmd, 0);
				}
				rz_cons_set_raw(1);
				rz_cons_show_cursor(false);
			}
			break;
		case 'P':
			if (--format < 0) {
				format = MAX_FORMAT;
			}
			break;
			// = (format<=0)? MAX_FORMAT: format-1; break;
		case 'p': format++; break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			if (menu == 1) {
				sprintf(cmd, "s %s", fs2);
				rz_core_cmd(core, cmd, 0);
				return true;
			}
			rz_flag_space_set(core->flags, fs);
			menu = 1;
			_option = option;
			option = 0;
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf(
				"\nVF: Visual Flags help:\n\n"
				" q     - quit menu\n"
				" j/k   - line down/up keys\n"
				" J/K   - page down/up keys\n"
				" h/b   - go back\n"
				" C     - toggle colors\n"
				" l/' ' - accept current selection\n"
				" a/d/e - add/delete/edit flag\n"
				" +/-   - increase/decrease block size\n"
				" o     - sort flags by offset\n"
				" r/R   - rename flag / Rename function\n"
				" n     - sort flags by name\n"
				" p/P   - rotate print format\n"
				" _     - hud for flags and comments\n"
				" :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':':
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			*cmd = 0;
			rz_line_set_prompt(":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				*cmd = 0;
			}
			cmd[sizeof(cmd) - 1] = 0;
			rz_core_cmd0(core, cmd);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (*cmd) {
				rz_cons_any_key(NULL);
			}
			//cons_gotoxy(0,0);
			rz_cons_clear();
			continue;
		}
	}
	return true;
}

RZ_API int rz_core_visual_comments(RzCore *core) {
	char *str;
	char cmd[512], *p = NULL;
	int ch, option = 0;
	int format = 0, i = 0;
	ut64 addr, from = 0, size = 0;

	for (;;) {
		rz_cons_clear00();
		rz_cons_strcat("Comments:\n");
		RzIntervalTreeIter it;
		RzAnalysisMetaItem *item;
		i = 0;
		rz_interval_tree_foreach (&core->analysis->meta, it, item) {
			if (item->type != RZ_META_TYPE_COMMENT) {
				continue;
			}
			str = item->str;
			addr = rz_interval_tree_iter_get(&it)->start;
			if (option == i) {
				from = addr;
				size = 1; // XXX: remove this thing size for comments is useless d->size;
				free(p);
				p = strdup(str);
				rz_cons_printf("  >  %s\n", str);
			} else {
				rz_cons_printf("     %s\n", str);
			}
			i++;
		}
		if (!i) {
			if (--option < 0) {
				rz_cons_any_key("No comments");
				break;
			}
			continue;
		}
		rz_cons_newline();

		switch (format) {
		case 0:
			sprintf(cmd, "px @ 0x%" PFMT64x ":64", from);
			core->printidx = 0;
			break;
		case 1:
			sprintf(cmd, "pd 12 @ 0x%" PFMT64x ":64", from);
			core->printidx = 1;
			break;
		case 2:
			sprintf(cmd, "ps @ 0x%" PFMT64x ":64", from);
			core->printidx = 5;
			break;
		default: format = 0; continue;
		}
		if (*cmd) {
			rz_core_cmd(core, cmd, 0);
		}
		rz_cons_visual_flush();
		ch = rz_cons_readchar();
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'a':
			//TODO
			break;
		case 'e':
			//TODO
			break;
		case 'd':
			if (p) {
				rz_meta_del(core->analysis, RZ_META_TYPE_ANY, from, size);
			}
			break;
		case 'P':
			if (--format < 0) {
				format = MAX_FORMAT;
			}
			break;
		case 'p':
			format++;
			break;
		case 'J':
			option += 10;
			break;
		case 'j':
			option++;
			break;
		case 'k':
			if (--option < 0) {
				option = 0;
			}
			break;
		case 'K':
			option -= 10;
			if (option < 0) {
				option = 0;
			}
			break;
		case 'l':
		case ' ':
		case '\r':
		case '\n':
			rz_core_seek_and_save(core, from, true);
			RZ_FREE(p);
			return true;
		case 'Q':
		case 'q':
			RZ_FREE(p);
			return true;
		case '?':
		case 'h':
			rz_cons_clear00();
			rz_cons_printf(
				"\nVT: Visual Comments/Analysis help:\n\n"
				" q     - quit menu\n"
				" j/k   - down/up keys\n"
				" h/b   - go back\n"
				" l/' ' - accept current selection\n"
				" a/d/e - add/delete/edit comment/analysis symbol\n"
				" p/P   - rotate print format\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		}
		RZ_FREE(p);
	}
	return true;
}

static void config_visual_hit_i(RzCore *core, const char *name, int delta) {
	struct rz_config_node_t *node;
	node = rz_config_node_get(core->config, name);
	if (node && rz_config_node_is_int(node)) {
		int hitDelta = rz_config_get_i(core->config, name) + delta;
		(void)rz_config_set_i(core->config, name, hitDelta);
	}
}

/* Visually activate the config variable */
static void config_visual_hit(RzCore *core, const char *name, int editor) {
	char buf[1024];
	RzConfigNode *node;

	if (!(node = rz_config_node_get(core->config, name))) {
		return;
	}
	if (rz_config_node_is_bool(node)) {
		rz_config_set_i(core->config, name, node->i_value ? 0 : 1);
	} else {
		// XXX: must use config_set () to run callbacks!
		if (editor) {
			char *buf = rz_core_editor(core, NULL, node->value);
			node->value = rz_str_dup(node->value, buf);
			free(buf);
		} else {
			// FGETS AND SO
			rz_cons_printf("New value (old=%s): \n", node->value);
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_cons_set_raw(0);
			rz_line_set_prompt(":> ");
			rz_cons_fgets(buf, sizeof(buf), 0, 0);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			rz_config_set(core->config, name, buf);
			//node->value = rz_str_dup (node->value, buf);
		}
	}
}

static void show_config_options(RzCore *core, const char *opt) {
	RzConfigNode *node = rz_config_node_get(core->config, opt);
	if (node && !rz_list_empty(node->options)) {
		int h, w = rz_cons_get_size(&h);
		const char *item;
		RzListIter *iter;
		RzStrBuf *sb = rz_strbuf_new(" Options: ");
		rz_list_foreach (node->options, iter, item) {
			rz_strbuf_appendf(sb, "%s%s", iter->p ? ", " : "", item);
			if (rz_strbuf_length(sb) + 5 >= w) {
				char *s = rz_strbuf_drain(sb);
				rz_cons_println(s);
				free(s);
				sb = rz_strbuf_new("");
			}
		}
		char *s = rz_strbuf_drain(sb);
		rz_cons_println(s);
		free(s);
	}
}

RZ_API void rz_core_visual_config(RzCore *core) {
	char *fs = NULL, *fs2 = NULL, *desc = NULL;
	int i, j, ch, hit, show;
	int option, _option = 0;
	RzListIter *iter;
	RzConfigNode *bt;
	char old[1024];
	int delta = 9;
	int menu = 0;
	old[0] = '\0';

	option = 0;
	for (;;) {
		rz_cons_clear00();
		rz_cons_get_size(&delta);
		delta /= 4;

		switch (menu) {
		case 0: // flag space
			rz_cons_printf("[EvalSpace]\n\n");
			hit = j = i = 0;
			rz_list_foreach (core->config->nodes, iter, bt) {
				if (option == i) {
					fs = bt->name;
				}
				if (!old[0]) {
					rz_str_ccpy(old, bt->name, '.');
					show = 1;
				} else if (rz_str_ccmp(old, bt->name, '.')) {
					rz_str_ccpy(old, bt->name, '.');
					show = 1;
				} else {
					show = 0;
				}
				if (show) {
					if (option == i) {
						hit = 1;
					}
					if ((i >= option - delta) && ((i < option + delta) || ((option < delta) && (i < (delta << 1))))) {
						rz_cons_printf(" %c  %s\n", (option == i) ? '>' : ' ', old);
						j++;
					}
					i++;
				}
			}
			if (!hit && j > 0) {
				option--;
				continue;
			}
			rz_cons_printf("\n Sel: %s \n\n", fs);
			break;
		case 1: // flag selection
			rz_cons_printf("[EvalSpace < Variables: %s]\n\n", fs);
			hit = 0;
			j = i = 0;
			// TODO: cut -d '.' -f 1 | sort | uniq !!!
			rz_list_foreach (core->config->nodes, iter, bt) {
				if (!rz_str_ccmp(bt->name, fs, '.')) {
					if (option == i) {
						fs2 = bt->name;
						desc = bt->desc;
						hit = 1;
					}
					if ((i >= option - delta) && ((i < option + delta) || ((option < delta) && (i < (delta << 1))))) {
						// TODO: Better align
						rz_cons_printf(" %c  %s = %s\n", (option == i) ? '>' : ' ', bt->name, bt->value);
						j++;
					}
					i++;
				}
			}
			if (!hit && j > 0) {
				option = i - 1;
				continue;
			}
			if (fs2) {
				// TODO: Break long lines.
				rz_cons_printf("\n Selected: %s (%s)\n", fs2, desc);
				show_config_options(core, fs2);
				rz_cons_newline();
			}
		}

		if (fs && !strncmp(fs, "asm.", 4)) {
			rz_core_cmd(core, "pd $r", 0);
		}
		rz_cons_visual_flush();
		ch = rz_cons_readchar();
		if (ch == 4 || ch == -1) {
			return;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char

		switch (ch) {
		case 'j': option++; break;
		case 'k': option = (option <= 0) ? 0 : option - 1; break;
		case 'J': option += 4; break;
		case 'K': option = (option <= 3) ? 0 : option - 4; break;
		case 'h':
		case 'b': // back
			menu = 0;
			option = _option;
			break;
		case '_':
			rz_core_visual_config_hud(core);
			break;
		case 'Q':
		case 'q':
			if (menu <= 0) {
				return;
			}
			menu--;
			option = _option;
			break;
		case '$':
			rz_core_help_vars_print(core);
			rz_cons_any_key(NULL);
			break;
		case '*':
		case '+':
			fs2 ? config_visual_hit_i(core, fs2, +1) : 0;
			continue;
		case '/':
		case '-':
			fs2 ? config_visual_hit_i(core, fs2, -1) : 0;
			continue;
		case 'l':
		case 'E': // edit value
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (menu == 1) {
				fs2 ? config_visual_hit(core, fs2, (ch == 'E')) : 0;
			} else {
				menu = 1;
				_option = option;
				option = 0;
			}
			break;
		case '?':
			rz_cons_clear00();
			rz_cons_printf("\nVe: Visual Eval help:\n\n"
				       " q     - quit menu\n"
				       " j/k   - down/up keys\n"
				       " h/b   - go back\n"
				       " $     - same as ?$ - show values of vars\n"
				       " e/' ' - edit/toggle current variable\n"
				       " E     - edit variable with 'cfg.editor' (vi?)\n"
				       " +/-   - increase/decrease numeric value (* and /, too)\n"
				       " :     - enter command\n");
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case ':':
			rz_cons_show_cursor(true);
			rz_cons_set_raw(0);
			{
				char *cmd = prompt(":> ", NULL);
				rz_core_cmd(core, cmd, 1);
				free(cmd);
			}
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			rz_cons_any_key(NULL);
			rz_cons_clear00();
			continue;
		}
	}
}

// helper
static void function_rename(RzCore *core, ut64 addr, const char *name) {
	RzListIter *iter;
	RzAnalysisFunction *fcn;

	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		if (fcn->addr == addr) {
			rz_flag_unset_name(core->flags, fcn->name);
			free(fcn->name);
			fcn->name = strdup(name);
			rz_flag_set(core->flags, name, addr, rz_analysis_function_size_from_entry(fcn));
			break;
		}
	}
}

static void variable_rename(RzCore *core, ut64 addr, int vindex, const char *name) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	ut64 a_tmp = core->offset;
	int i = 0;
	RzListIter *iter;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzAnalysisVar *var;

	rz_list_foreach (list, iter, var) {
		if (i == vindex) {
			rz_core_seek(core, addr, false);
			rz_core_analysis_var_rename(core, name, var->name);
			rz_core_seek(core, a_tmp, false);
			break;
		}
		++i;
	}
	rz_list_free(list);
}

static void variable_set_type(RzCore *core, ut64 addr, int vindex, const char *type) {
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzListIter *iter;
	RzAnalysisVar *var;

	RzType *ttype = rz_type_parse(core->analysis->typedb->parser, type, NULL);
	rz_list_foreach (list, iter, var) {
		if (vindex == 0) {
			rz_analysis_var_set_type(var, ttype);
			break;
		}
		vindex--;
	}
	rz_list_free(list);
}

// In visual mode, display function list
static ut64 var_functions_show(RzCore *core, int idx, int show, int cols) {
	int wdelta = (idx > 5) ? idx - 5 : 0;
	char *var_functions;
	ut64 seek = core->offset;
	ut64 addr = core->offset;
	RzAnalysisFunction *fcn;
	int window, i = 0, print_full_func;
	RzListIter *iter;

	// Adjust the windows size automaticaly
	(void)rz_cons_get_size(&window);
	window -= 8; // Size of printed things
	bool color = rz_config_get_i(core->config, "scr.color");
	const char *color_addr = core->cons->context->pal.offset;
	const char *color_fcn = core->cons->context->pal.fname;

	rz_list_foreach (core->analysis->fcns, iter, fcn) {
		print_full_func = true;
		if (i >= wdelta) {
			if (i > window + wdelta - 1) {
				rz_cons_printf("...\n");
				break;
			}
			if (idx == i) {
				addr = fcn->addr;
			}
			if (show) {
				char *tmp;
				if (color) {
					var_functions = rz_str_newf("%c%c %s0x%08" PFMT64x "" Color_RESET " %4" PFMT64d " %s%s" Color_RESET "",
						(seek == fcn->addr) ? '>' : ' ',
						(idx == i) ? '*' : ' ',
						color_addr, fcn->addr, rz_analysis_function_realsize(fcn),
						color_fcn, fcn->name);
				} else {
					var_functions = rz_str_newf("%c%c 0x%08" PFMT64x " %4" PFMT64d " %s",
						(seek == fcn->addr) ? '>' : ' ',
						(idx == i) ? '*' : ' ',
						fcn->addr, rz_analysis_function_realsize(fcn), fcn->name);
				}
				if (var_functions) {
					if (!rz_cons_singleton()->show_vals) {
						int fun_len = rz_str_ansi_len(var_functions);
						int columns = fun_len > cols ? cols - 2 : cols;
						tmp = rz_str_ansi_crop(var_functions, 0, 0, columns, window);
						if (rz_str_ansi_len(tmp) < fun_len) {
							rz_cons_printf("%s..%s\n", tmp, Color_RESET);
							print_full_func = false;
						}
						rz_free(tmp);
					}
					if (print_full_func) {
						rz_cons_println(var_functions);
					}
					rz_free(var_functions);
				}
			}
		}
		i++;
	}
	return addr;
}

// In visual mode, display the variables.
static ut64 var_variables_show(RzCore *core, int idx, int *vindex, int show, int cols) {
	int i = 0;
	const ut64 addr = var_functions_show(core, idx, 0, cols);
	RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	int window;
	int wdelta = (idx > 5) ? idx - 5 : 0;
	RzListIter *iter;
	RzList *list = rz_analysis_var_all_list(core->analysis, fcn);
	RzAnalysisVar *var;
	// Adjust the window size automatically.
	(void)rz_cons_get_size(&window);
	window -= 8; // Size of printed things.

	// A new line so this looks reasonable.
	rz_cons_newline();

	int llen = rz_list_length(list);
	if (*vindex >= llen) {
		*vindex = llen - 1;
	}

	rz_list_foreach (list, iter, var) {
		if (i >= wdelta) {
			if (i > window + wdelta) {
				rz_cons_printf("...\n");
				break;
			}
			if (show) {
				const char *vartype = rz_type_as_string(core->analysis->typedb, var->type);
				switch (var->kind & 0xff) {
				case 'r': {
					RzRegItem *r = rz_reg_index_get(core->analysis->reg, var->delta);
					if (!r) {
						eprintf("Register not found");
						break;
					}
					rz_cons_printf("%sarg %s %s @ %s\n",
						i == *vindex ? "* " : "  ",
						vartype, var->name,
						r->name);
				} break;
				case 'b':
					rz_cons_printf("%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* " : "  ",
						var->delta < 0 ? "var" : "arg",
						vartype, var->name,
						core->analysis->reg->name[RZ_REG_NAME_BP],
						(var->kind == 'v') ? "-" : "+",
						var->delta);
					break;
				case 's':
					rz_cons_printf("%s%s %s %s @ %s%s0x%x\n",
						i == *vindex ? "* " : "  ",
						var->delta < 0 ? "var" : "arg",
						vartype, var->name,
						core->analysis->reg->name[RZ_REG_NAME_BP],
						(var->kind == 'v') ? "-" : "+",
						var->delta);
					break;
				}
			}
		}
		++i;
	}
	rz_list_free(list);
	return addr;
}

static int level = 0;
static st64 delta = 0;
static int option = 0;
static int variable_option = 0;
static int printMode = 0;
static bool selectPanel = false;
#define lastPrintMode 6
static const char *printCmds[lastPrintMode] = {
	"pdf", "pd $r", "afi", "pdsf", "pdc", "pdr"
};

static void rz_core_visual_analysis_refresh_column(RzCore *core, int colpos) {
	const ut64 addr = (level != 0 && level != 1)
		? core->offset
		: var_functions_show(core, option, 0, colpos);
	// RzAnalysisFunction* fcn = rz_analysis_get_fcn_in(core->analysis, addr, RZ_ANALYSIS_FCN_TYPE_NULL);
	int h, w = rz_cons_get_size(&h);
	// int sz = (fcn)? RZ_MIN (rz_analysis_fcn_size (fcn), h * 15) : 16; // max instr is 15 bytes.

	const char *cmd;
	if (printMode > 0 && printMode < lastPrintMode) {
		cmd = printCmds[printMode];
	} else {
		cmd = printCmds[printMode = 0];
	}
	char *cmdf = rz_str_newf("%s @ 0x%" PFMT64x, cmd, addr + delta);
	if (!cmdf) {
		return;
	}
	char *output = rz_core_cmd_str(core, cmdf);
	if (output) {
		// 'h - 2' because we have two new lines in rz_cons_printf
		char *out = rz_str_ansi_crop(output, 0, 0, w - colpos, h - 2);
		rz_cons_printf("\n%s\n", out);
		free(out);
		RZ_FREE(output);
	}
	free(cmdf);
}

static const char *help_fun_visual[] = {
	"(a)", "analyze ", "(-)", "delete ", "(x)", "xrefs to", "(X)", "xrefs from  j/k next/prev\n",
	"(r)", "rename ", "(c)", "calls ", "(d)", "definetab column (_) hud\n",
	"(d)", "define ", "(v)", "vars ", "(?)", " help ", "(:)", "shell ", "(q)", "quit\n",
	"(s)", "edit function signature.  \n\n",
	NULL
};

static const char *help_var_visual[] = {
	"(a)", "add ", "(x)", "xrefs ", "(r)", "rename\n",
	"(t)", "type ", "(g)", "go ", "(-)", "delete\n",
	"(q)", "quit ", "(s)", "signature\n\n",
	NULL
};

static const char *help_vv_visual[] = {
	"j,k", "select next/prev item or scroll if tab pressed",
	"J,K", "scroll next/prev page \"\"",
	"h,q", "go back, quit",
	"p,P", "switch next/prev print mode",
	"v", "view selected function arguments and variables",
	"x,X", "see xrefs to the selected function",
	"tab", "toggle disasm column selection (to scroll in code)",
	"!", "run 'afls' to sort all functions by address",
	".", "seek to current function address",
	":", "run rizin commands",
	"_", "hud mode. same as: s $(afl~...)",
	"enter", "enter function view (variables), xrefs",
	NULL
};

static const char *help_vv_actions_visual[] = {
	" functions:", "Add, Modify, Delete, Xrefs Calls Vars",
	" variables:", "Add, Modify, Delete",
	NULL
};

static void rz_core_vmenu_append_help(RzStrBuf *p, const char **help) {
	int i;
	RzConsContext *cons_ctx = rz_cons_singleton()->context;
	const char *pal_args_color = cons_ctx->color_mode ? cons_ctx->pal.args : "",
		   *pal_help_color = cons_ctx->color_mode ? cons_ctx->pal.help : "",
		   *pal_reset = cons_ctx->color_mode ? cons_ctx->pal.reset : "";

	for (i = 0; help[i]; i += 2) {
		rz_strbuf_appendf(p, "%s%s %s%s%s",
			pal_args_color, help[i],
			pal_help_color, help[i + 1], pal_reset);
	}
}

static ut64 rz_core_visual_analysis_refresh(RzCore *core) {
	if (!core) {
		return 0LL;
	}
	ut64 addr;
	RzStrBuf *buf;
	char old[1024];
	bool color = rz_config_get_i(core->config, "scr.color");
	int h, cols = rz_cons_get_size(&h);
	old[0] = '\0';
	addr = core->offset;
	cols -= 50;
	if (cols > 60) {
		cols = 60;
	}

	rz_cons_clear00();
	rz_core_visual_analysis_refresh_column(core, cols);
	if (cols > 30) {
		rz_cons_column(cols);
	}
	switch (level) {
	// Show functions list help in visual mode
	case 0: {
		buf = rz_strbuf_new("");
		if (color) {
			rz_cons_strcat(core->cons->context->pal.prompt);
		}
		if (selectPanel) {
			rz_cons_printf("-- functions -----------------[ %s ]-->>", printCmds[printMode]);
		} else {
			rz_cons_printf("-[ functions ]----------------- %s ---", printCmds[printMode]);
		}
		if (color) {
			rz_cons_strcat("\n" Color_RESET);
		}
		rz_core_vmenu_append_help(buf, help_fun_visual);
		char *drained = rz_strbuf_drain(buf);
		rz_cons_printf("%s", drained);
		free(drained);
		addr = var_functions_show(core, option, 1, cols);
		break;
	}
	case 1: {
		buf = rz_strbuf_new("");
		if (color) {
			rz_cons_strcat(core->cons->context->pal.prompt);
		}
		rz_cons_printf("-[ variables ]----- 0x%08" PFMT64x "", addr);
		if (color) {
			rz_cons_strcat("\n" Color_RESET);
		}
		rz_core_vmenu_append_help(buf, help_var_visual);
		char *drained = rz_strbuf_drain(buf);
		rz_cons_printf("%s", drained);
		addr = var_variables_show(core, option, &variable_option, 1, cols);
		free(drained);
		// var_index_show (core->analysis, fcn, addr, option);
		break;
	}
	case 2: {
		rz_cons_printf("Press 'q' to quit call refs\n");
		if (color) {
			rz_cons_strcat(core->cons->context->pal.prompt);
		}
		rz_cons_printf("-[ calls ]----------------------- 0x%08" PFMT64x " (TODO)\n", addr);
		if (color) {
			rz_cons_strcat("\n" Color_RESET);
		}
		// TODO: filter only the callrefs. but we cant grep here
		sprintf(old, "afi @ 0x%08" PFMT64x, addr);
		char *output = rz_core_cmd_str(core, old);
		if (output) {
			// 'h - 2' because we have two new lines in rz_cons_printf
			if (!rz_cons_singleton()->show_vals) {
				char *out = rz_str_ansi_crop(output, 0, 0, cols, h - 2);
				rz_cons_printf("\n%s\n", out);
				free(out);
				RZ_FREE(output);
			} else {
				rz_cons_printf("\n%s\n", output);
				RZ_FREE(output);
			}
		}
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}
	rz_cons_flush();
	return addr;
}

static void rz_core_visual_analysis_refresh_oneshot(RzCore *core) {
	rz_core_task_enqueue_oneshot(&core->tasks, (RzCoreTaskOneShot)rz_core_visual_analysis_refresh, core);
}

static void rz_core_visual_debugtraces_help(RzCore *core) {
	rz_cons_clear00();
	rz_cons_printf(
		"vbd: Visual Browse Debugtraces:\n\n"
		" q     - quit the bit editor\n"
		" Q     - Quit (jump into the disasm view)\n"
		" j/k   - Select next/previous trace\n"
		" :     - enter command\n");
	rz_cons_flush();
	rz_cons_any_key(NULL);
}

RZ_API void rz_core_visual_debugtraces(RzCore *core, const char *input) {
	int i, delta = 0;
	for (;;) {
		char *trace_addr_str = rz_core_cmd_strf(core, "dtdq %d", delta);
		ut64 trace_addr = rz_num_get(NULL, trace_addr_str);
		free(trace_addr_str);
		rz_cons_printf("[0x%08" PFMT64x "]> %d dbg.trace\n", trace_addr, delta);
		for (i = 0; i < delta; i++) {
			rz_core_cmdf(core, ".dte %d", i);
		}
		rz_core_cmd0(core, "x 64@r:SP");
		rz_core_debug_ri(core, core->dbg->reg, 0);
		// limit by rows here
		//int rows = rz_cons_get_size (NULL);
		rz_core_cmdf(core, "dtd %d", delta);
		rz_cons_visual_flush();
		char ch;
		if (input && *input) {
			ch = *input;
			input++;
		} else {
			ch = rz_cons_readchar();
		}
		if (ch == 4 || ch == -1) {
			if (level == 0) {
				goto beach;
			}
			level--;
			continue;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case 'Q': // tab
		{
			ut64 oseek = core->offset;
			core->vmode = false;
			rz_core_seek(core, trace_addr, true);
			rz_core_visual(core, "");
			rz_core_seek(core, oseek, true);
		} break;
		case 'q':
			goto beach;
			break;
		case ']':
			rz_config_set_i(core->config, "hex.cols", rz_config_get_i(core->config, "hex.cols") + 1);
			break;
		case '[':
			rz_config_set_i(core->config, "hex.cols", rz_config_get_i(core->config, "hex.cols") - 1);
			break;
		case 'J':
			delta += 10;
			break;
		case 'K':
			delta -= 10;
			if (delta < 0) {
				delta = 0;
			}
		case 'j':
			delta++;
			break;
		case 'k':
			delta--;
			if (delta < 0) {
				delta = 0;
			}
			break;
		case ':':
			rz_core_visual_prompt(core);
			rz_cons_any_key(NULL);
			break;
		case '?':
			rz_core_visual_debugtraces_help(core);
			break;
		}
	}
beach:;
}

static char *__prompt(const char *msg, void *p) {
	char res[128];
	rz_cons_show_cursor(true);
	rz_cons_set_raw(false);
	rz_line_set_prompt(msg);
	res[0] = 0;
	if (!rz_cons_fgets(res, sizeof(res), 0, NULL)) {
		res[0] = 0;
	}
	return strdup(res);
}

static void addVar(RzCore *core, int ch, const char *msg) {
	char *src = __prompt(msg, NULL);
	char *name = __prompt("Variable Name: ", NULL);
	char *type = __prompt("Type of Variable (int32_t): ", NULL);
	char *cmd = rz_str_newf("afv%c %s %s %s", ch, src, name, type);
	rz_str_trim(cmd);
	rz_core_cmd0(core, cmd);
	free(cmd);
	free(src);
	free(name);
	free(type);
}

/* Like emenu but for real */
RZ_API void rz_core_visual_analysis(RzCore *core, const char *input) {
	char old[218];
	int nfcns, ch, _option = 0;

	RzConsEvent olde = core->cons->event_resize;
	void *olde_user = core->cons->event_data;
	ut64 addr = core->offset;

	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = core;
	core->cons->event_resize = (RzConsEvent)rz_core_visual_analysis_refresh_oneshot;

	level = 0;

	int asmbytes = rz_config_get_i(core->config, "asm.bytes");
	rz_config_set_i(core->config, "asm.bytes", 0);
	for (;;) {
		nfcns = rz_list_length(core->analysis->fcns);
		addr = rz_core_visual_analysis_refresh(core);
		if (input && *input) {
			ch = *input;
			input++;
		} else {
			ch = rz_cons_readchar();
		}
		if (ch == 4 || ch == -1) {
			if (level == 0) {
				goto beach;
			}
			level--;
			continue;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char
		switch (ch) {
		case '[':
			rz_cons_singleton()->show_vals = true;
			break;
		case ']':
			rz_cons_singleton()->show_vals = false;
			break;
		case '?':
			rz_cons_clear00();
			RzStrBuf *buf = rz_strbuf_new("");
			rz_cons_println("|Usage: vv");
			rz_core_visual_append_help(buf, "Actions supported", help_vv_actions_visual);
			rz_core_visual_append_help(buf, "Keys", help_vv_visual);
			rz_cons_printf("%s", rz_strbuf_drain(buf));
			rz_cons_flush();
			rz_cons_any_key(NULL);
			break;
		case 9:
			selectPanel = !selectPanel;
			if (!selectPanel) {
				delta = 0;
				printMode = 0;
			}
			break;
		case ':': {
			ut64 orig = core->offset;
			rz_core_seek(core, addr, false);
			while (rz_core_visual_prompt(core))
				;
			rz_core_seek(core, orig, false);
		}
			continue;
		case '/':
			rz_core_cmd0(core, "?i highlight;e scr.highlight=`yp`");
			break;
		case 'a':
			switch (level) {
			case 0:
				// Remove the old function information
				rz_core_analysis_undefine(core, core->offset);
				rz_analysis_fcn_del_locs(core->analysis, core->offset);
				rz_analysis_fcn_del(core->analysis, core->offset);
				// Reanalyze and create function from scratch
				rz_core_analysis_function_add(core, NULL, core->offset, false);
				break;
			case 1: {
				eprintf("Select variable source ('r'egister, 's'tackptr or 'b'aseptr): ");
				int type = rz_cons_readchar();
				switch (type) {
				case 'r':
					addVar(core, type, "Source Register Name: ");
					break;
				case 's':
					addVar(core, type, "BP Relative Delta: ");
					break;
				case 'b':
					addVar(core, type, "SP Relative Delta: ");
					break;
				}
			} break;
			}
			break;
		case 'r': {
			switch (level) {
			case 1:
				rz_cons_show_cursor(true);
				rz_cons_set_raw(false);
				rz_line_set_prompt("New name: ");
				if (rz_cons_fgets(old, sizeof(old), 0, NULL)) {
					if (*old) {
						//old[strlen (old)-1] = 0;
						variable_rename(core, addr, variable_option, old);
					}
				}
				break;
			default:
				rz_line_set_prompt("New name: ");
				if (rz_cons_fgets(old, sizeof(old), 0, NULL)) {
					if (*old) {
						//old[strlen (old)-1] = 0;
						function_rename(core, addr, old);
					}
				}
				break;
			}
			rz_cons_set_raw(true);
			rz_cons_show_cursor(false);
		} break;
		case 't':
			if (level == 1) {
				rz_cons_show_cursor(true);
				rz_cons_set_raw(false);
				rz_line_set_prompt("New type: ");
				if (rz_cons_fgets(old, sizeof(old), 0, NULL)) {
					if (*old) {
						//old[strlen (old)-1] = 0;
						variable_set_type(core, addr, variable_option, old);
					}
				}
				rz_cons_set_raw(true);
				rz_cons_show_cursor(false);
			}
			break;
		case '.':
			delta = 0;
			break;
		case 'R':
			rz_core_theme_nextpal(core, 'n');
			break;
		case 'p':
			printMode++;
			break;
		case 'P':
			if (printMode == 0) {
				printMode = lastPrintMode;
			} else {
				printMode--;
			}
			break;
		case 'd':
			rz_core_visual_define(core, "", 0);
			break;
		case '-':
			switch (level) {
			case 0:
				// Remove the old function information
				rz_core_analysis_undefine(core, addr);
				rz_analysis_fcn_del_locs(core->analysis, addr);
				rz_analysis_fcn_del(core->analysis, addr);
				break;
			}
			break;
		case 'x':
			rz_core_visual_xrefs(core, false, true);
			break;
		case 'X':
			rz_core_visual_xrefs(core, true, true);
			break;
		case 's':
			rz_core_analysis_function_signature_editor(core, addr);
			break;
		case 'c':
			level = 2;
			break;
		case 'v':
			level = 1;
			variable_option = 0;
			break;
		case '_': {
			rz_core_cmd0(core, "s $(afl~...)");
			int n = 0;
			RzListIter *iter;
			RzAnalysisFunction *fcn;
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				if (fcn->addr == core->offset) {
					option = n;
					break;
				}
				n++;
			}
		} break;
		case 'j':
			if (selectPanel) {
				printMode = 1;
				delta += 16;
			} else {
				delta = 0;
				switch (level) {
				case 1:
					variable_option++;
					break;
				default:
					option++;
					if (option >= nfcns) {
						--option;
					}
					break;
				}
			}
			break;
		case '!':
			// TODO: use aflsn/aflsb/aflss/...
			{
				static int sortMode = 0;
				const char *sortModes[4] = { "aflsa", "aflss", "aflsb", "aflsn" };
				rz_core_cmd0(core, sortModes[sortMode % 4]);
				sortMode++;
			}
			break;
		case 'k':
			if (selectPanel) {
				printMode = 1;
				delta -= 16;
			} else {
				delta = 0;
				switch (level) {
				case 1:
					variable_option = (variable_option <= 0) ? 0 : variable_option - 1;
					break;
				default:
					option = (option <= 0) ? 0 : option - 1;
					break;
				}
			}

			break;
		case 'J':
			if (selectPanel) {
				printMode = 1;
				delta += 40;
			} else {
				int rows = 0;
				rz_cons_get_size(&rows);
				option += (rows - 5);
				if (option >= nfcns) {
					option = nfcns - 1;
				}
			}
			break;
		case 'K':
			if (selectPanel) {
				printMode = 1;
				delta -= 40;
			} else {
				int rows = 0;
				rz_cons_get_size(&rows);
				option -= (rows - 5);
				if (option < 0) {
					option = 0;
				}
			}
			break;
		case 'g': {
			rz_core_visual_showcursor(core, true);
			rz_core_visual_offset(core); // change the seek to selected offset
			RzListIter *iter; // change the current option to selected seek
			RzAnalysisFunction *fcn;
			int i = 0;
			rz_list_foreach (core->analysis->fcns, iter, fcn) {
				if (core->offset == fcn->addr) {
					option = i;
				}
				i++;
			}
			rz_core_visual_showcursor(core, false);
		} break;
		case 'G':
			rz_core_seek(core, addr, SEEK_SET);
			goto beach;
		case ' ':
		case '\r':
		case '\n':
			level = 0;
			rz_core_seek(core, addr, SEEK_SET);
			goto beach;
			break;
		case 'l':
			level = 1;
			_option = option;
			break;
		case 'h':
		case 'b': // back
			level = 0;
			option = _option;
			break;
		case 'Q':
		case 'q':
			if (level == 0) {
				goto beach;
			}
			level--;
			break;
		}
	}
beach:
	core->cons->event_resize = NULL; // avoid running old event with new data
	core->cons->event_data = olde_user;
	core->cons->event_resize = olde;
	level = 0;
	rz_config_set_i(core->config, "asm.bytes", asmbytes);
}

//define the data at offset according to the type (byte, word...) n times
static void define_data_ntimes(RzCore *core, ut64 off, int times, int type) {
	int i = 0;
	rz_meta_del(core->analysis, RZ_META_TYPE_ANY, off, core->blocksize);
	if (times < 0) {
		times = 1;
	}
	for (i = 0; i < times; i++, off += type) {
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, off, type, "");
	}
}

static bool isDisasmPrint(int mode) {
	return (mode == 1 || mode == 2);
}

static void handleHints(RzCore *core) {
	//TODO extend for more analysis hints
	int i = 0;
	char ch[64] = RZ_EMPTY;
	const char *lines[] = { "[dh]- Define analysis hint:", " b [16,32,64]     set bits hint", NULL };
	for (i = 0; lines[i]; i++) {
		rz_cons_fill_line();
		rz_cons_printf("\r%s\n", lines[i]);
	}
	rz_cons_flush();
	rz_line_set_prompt("analysis hint: ");
	if (rz_cons_fgets(ch, sizeof(ch), 0, NULL) > 0) {
		switch (ch[0]) {
		case 'b': {
			char *arg = ch + 1;
			rz_str_trim(arg);
			int bits = atoi(arg);
			if (bits == 8 || bits == 16 || bits == 32 || bits == 64) {
				rz_analysis_hint_set_bits(core->analysis, core->offset, bits);
			}
		} break;
		default:
			break;
		}
	}
}

RZ_API void rz_core_visual_define(RzCore *core, const char *args, int distance) {
	int plen = core->blocksize;
	ut64 off = core->offset;
	int i, h = 0, n, ch, ntotal = 0;
	ut8 *p = core->block;
	int rep = -1;
	char *name;
	int delta = 0;
	if (core->print->cur_enabled) {
		int cur = core->print->cur;
		if (core->print->ocur != -1) {
			plen = RZ_ABS(core->print->cur - core->print->ocur) + 1;
			if (core->print->ocur < cur) {
				cur = core->print->ocur;
			}
		}
		off += cur;
		p += cur;
	}
	(void)rz_cons_get_size(&h);
	h -= 19;
	if (h < 0) {
		h = 0;
		rz_cons_clear00();
	} else {
		rz_cons_gotoxy(0, 3);
	}
	const char *lines[] = { "", "[Vd]- Define current block as:", " $    define flag size", " 1    edit bits", " a    assembly", " b    as byte (1 byte)", " B    define half word (16 bit, 2 byte size)", " c    as code (unset any data / string / format) in here", " C    define flag color (fc)", " d    set as data", " e    end of function", " f    analyze function", " F    format", " h    define hint (for half-word, see 'B')", " i    (ahi) immediate base (b(in), o(ct), d(ec), h(ex), s(tr))", " I    (ahi1) immediate base (b(in), o(ct), d(ec), h(ex), s(tr))", " j    merge down (join this and next functions)", " k    merge up (join this and previous function)", " h    define analysis hint", " m    manpage for current call", " n    rename flag used at cursor", " N    edit function signature (afs!)", " o    opcode string", " r    rename function", " R    find references /r", " s    set string", " S    set strings in current block", " t    set opcode type via aht hints (call, nop, jump, ...)", " u    undefine metadata here", " v    rename variable at offset that matches some hex digits", " x    find xrefs to current address (./r)", " w    set as 32bit word", " W    set as 64bit word", " q    quit menu", " z    zone flag", NULL };
	for (i = 0; lines[i]; i++) {
		rz_cons_fill_line();
		rz_cons_printf("\r%s\n", lines[i]);
	}
	rz_cons_flush();
	int wordsize = 0;
	// get ESC+char, return 'hjkl' char
repeat:
	if (*args) {
		ch = *args;
		args++;
	} else {
		ch = rz_cons_arrow_to_hjkl(rz_cons_readchar());
	}

onemoretime:
	wordsize = 4;
	switch (ch) {
	case 'N':
		rz_core_analysis_function_signature_editor(core, off);
		break;
	case 'F': {
		char cmd[128];
		rz_cons_show_cursor(true);
		rz_core_cmd0(core, "pf?");
		rz_cons_flush();
		rz_line_set_prompt("format: ");
		strcpy(cmd, "Cf 0 ");
		if (rz_cons_fgets(cmd + 5, sizeof(cmd) - 5, 0, NULL) > 0) {
			rz_core_cmdf(core, "%s @ 0x%08" PFMT64x, cmd, off);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
		}
	} break;
	case '1':
		rz_core_visual_bit_editor(core);
		break;
	case 't':
	case 'o': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt(ch == 't' ? "type: " : "opstr: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			rz_core_cmdf(core, "ah%c %s @ 0x%" PFMT64x, ch, str, off);
		}
	} break;
	case 'x':
		rz_core_cmd0(core, "/r $$");
		break;
	case 'i': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt("immbase: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			rz_core_cmdf(core, "ahi %s @ 0x%" PFMT64x, str, off);
		}
	} break;
	case 'I': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt("immbase: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			rz_core_cmdf(core, "ahi1 %s @ 0x%" PFMT64x, str, off);
		}
	} break;
	case 'a':
		rz_core_visual_asm(core, off);
		break;
	case 'b':
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		define_data_ntimes(core, off, rep, RZ_BYTE_DATA);
		wordsize = 1;
		break;
	case 'B': // "VdB"
		if (plen != core->blocksize) {
			rep = plen / 2;
		}
		define_data_ntimes(core, off, rep, RZ_WORD_DATA);
		wordsize = 2;
		break;
	case 'w':
		if (plen != core->blocksize) {
			rep = plen / 4;
		}
		define_data_ntimes(core, off, rep, RZ_DWORD_DATA);
		wordsize = 4;
		break;
	case 'W':
		if (plen != core->blocksize) {
			rep = plen / 8;
		}
		define_data_ntimes(core, off, rep, RZ_QWORD_DATA);
		wordsize = 8;
		break;
	case 'm': {
		char *man = NULL;
		/* check for manpage */
		RzAnalysisOp *op = rz_core_analysis_op(core, off, RZ_ANALYSIS_OP_MASK_BASIC);
		if (op) {
			if (op->jump != UT64_MAX) {
				RzFlagItem *item = rz_flag_get_i(core->flags, op->jump);
				if (item) {
					const char *ptr = rz_str_lchr(item->name, '.');
					if (ptr) {
						man = strdup(ptr + 1);
					}
				}
			}
			rz_analysis_op_free(op);
		}
		if (man) {
			char *p = strstr(man, "INODE");
			if (p) {
				*p = 0;
			}
			rz_cons_clear();
			rz_cons_flush();
			rz_sys_cmdf("man %s", man);
			free(man);
		}
		rz_cons_any_key(NULL);
	} break;
	case 'n': {
		RzAnalysisOp op;
		char *q = NULL;
		ut64 tgt_addr = UT64_MAX;
		if (!isDisasmPrint(core->printidx)) {
			break;
		}
		// TODO: get the aligned instruction even if the cursor is in the middle of it.
		rz_analysis_op(core->analysis, &op, off,
			core->block + off - core->offset, 32, RZ_ANALYSIS_OP_MASK_BASIC);

		tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
		RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, op.addr);
		if (var) {
			//			q = rz_str_newf ("?i Rename variable %s to;afvn %s `yp`", op.var->name, op.var->name);
			char *newname = rz_cons_input(sdb_fmt("New variable name for '%s': ", var->name));
			if (newname && *newname) {
				rz_analysis_var_rename(var, newname, true);
				free(newname);
			}
		} else if (tgt_addr != UT64_MAX) {
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, tgt_addr);
			RzFlagItem *f = rz_flag_get_i(core->flags, tgt_addr);
			if (fcn) {
				q = rz_str_newf("?i Rename function %s to;afn `yp` 0x%" PFMT64x,
					fcn->name, tgt_addr);
			} else if (f) {
				q = rz_str_newf("?i Rename flag %s to;fr %s `yp`",
					f->name, f->name);
			} else {
				q = rz_str_newf("?i Create flag at 0x%" PFMT64x " named;f `yp` @ 0x%" PFMT64x,
					tgt_addr, tgt_addr);
			}
		}

		if (q) {
			rz_core_cmd0(core, q);
			free(q);
		}
		rz_analysis_op_fini(&op);
		break;
	}
	case 'C': {
		RzFlagItem *item = rz_flag_get_i(core->flags, off);
		if (item) {
			char cmd[128];
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_line_set_prompt("color: ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) > 0) {
				rz_flag_item_set_color(item, cmd);
				rz_cons_set_raw(1);
				rz_cons_show_cursor(false);
			}
		} else {
			eprintf("Sorry. No flag here\n");
			rz_cons_any_key(NULL);
		}
	} break;
	case '$': {
		RzFlagItem *item = rz_flag_get_i(core->flags, off);
		if (item) {
			char cmd[128];
			rz_cons_printf("Current flag size is: %" PFMT64d "\n", item->size);
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_line_set_prompt("new size: ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) > 0) {
				item->size = rz_num_math(core->num, cmd);
				rz_cons_set_raw(1);
				rz_cons_show_cursor(false);
			}
		} else {
			eprintf("Sorry. No flag here\n");
			rz_cons_any_key(NULL);
		}
	} break;
	case 'e':
		// set function size
		{
			RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, off, 0);
			if (!fcn) {
				fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
			}
			if (fcn) {
				RzAnalysisOp op;
				ut64 size;
				if (rz_analysis_op(core->analysis, &op, off, core->block + delta,
					    core->blocksize - delta, RZ_ANALYSIS_OP_MASK_BASIC)) {
					size = off - fcn->addr + op.size;
					rz_analysis_function_resize(fcn, size);
				}
			}
		}
		break;
	case 'j':
		rz_core_cmdf(core, "afm $$+$F @0x%08" PFMT64x, off);
		break;
	case 'k':
		eprintf("TODO: merge up\n");
		rz_cons_any_key(NULL);
		break;
	// very weak and incomplete
	case 'h': // "Vdh"
		handleHints(core);
		break;
	case 'r': // "Vdr"
		rz_core_cmdf(core, "?i new function name;afn `yp` @ 0x%08" PFMT64x, off);
		break;
	case 'z': // "Vdz"
		rz_core_cmdf(core, "?i zone name;fz `yp` @ 0x%08" PFMT64x, off);
		break;
	case 'R': // "VdR"
		eprintf("Finding references to 0x%08" PFMT64x " ...\n", off);
		rz_core_cmdf(core, "./r 0x%08" PFMT64x " @ $S", off);
		break;
	case 'S': {
		int i, j;
		bool is_wide = false;
		do {
			n = rz_str_nlen_w((const char *)p + ntotal,
				    plen - ntotal) +
				1;
			if (n < 2) {
				break;
			}
			name = malloc(n + 10);
			strcpy(name, "str.");
			for (i = 0, j = 0; i < n; i++, j++) {
				name[4 + i] = p[j + ntotal];
				if (!p[j + ntotal]) {
					break;
				}
				if (!p[j + 1 + ntotal]) {
					//check if is still wide
					if (j + 3 + ntotal < n) {
						if (p[j + 3]) {
							break;
						}
					}
					is_wide = true;
					j++;
				}
			}
			name[4 + n] = '\0';
			if (is_wide) {
				rz_meta_set(core->analysis, RZ_META_TYPE_STRING,
					off + ntotal, (n * 2) + ntotal,
					(const char *)name + 4);
			} else {
				rz_meta_set(core->analysis, RZ_META_TYPE_STRING,
					off + ntotal, n + ntotal,
					(const char *)name + 4);
			}
			rz_name_filter(name, n + 10, true);
			rz_flag_set(core->flags, name, off + ntotal, n);
			free(name);
			if (is_wide) {
				ntotal += n * 2 - 1;
			} else {
				ntotal += n;
			}
		} while (ntotal < plen);
		wordsize = ntotal;
	} break;
	case 's': {
		int i, j;
		bool is_wide = false;
		if (core->print->ocur != -1) {
			n = plen;
		} else {
			n = rz_str_nlen_w((const char *)p, plen) + 1;
		}
		name = malloc(n + 10);
		if (!name) {
			break;
		}
		strcpy(name, "str.");
		for (i = 0, j = 0; i < n; i++, j++) {
			name[4 + i] = p[j];
			if (!p[j + 1]) {
				break;
			}
			if (!p[j + 1]) {
				if (j + 3 < n) {
					if (p[j + 3]) {
						break;
					}
				}
				is_wide = true;
				j++;
			}
		}
		name[4 + n] = '\0';
		//handle wide strings
		//memcpy (name + 4, (const char *)p, n);
		if (is_wide) {
			rz_meta_set(core->analysis, RZ_META_TYPE_STRING, off,
				n * 2, (const char *)name + 4);
		} else {
			rz_meta_set(core->analysis, RZ_META_TYPE_STRING, off,
				n, (const char *)name + 4);
		}
		rz_name_filter(name, n + 10, true);
		rz_flag_set(core->flags, name, off, n);
		wordsize = n;
		free(name);
	} break;
	case 'd': // TODO: check
		rz_meta_del(core->analysis, RZ_META_TYPE_ANY, off, plen);
		rz_meta_set(core->analysis, RZ_META_TYPE_DATA, off, plen, "");
		break;
	case 'c': // TODO: check
		rz_meta_del(core->analysis, RZ_META_TYPE_ANY, off, plen);
		rz_meta_set(core->analysis, RZ_META_TYPE_CODE, off, plen, "");
		break;
	case 'u':
		rz_core_analysis_undefine(core, off);
		break;
	case 'f': {
		RzAnalysisFunction *fcn = rz_analysis_get_fcn_in(core->analysis, core->offset, 0);
		if (fcn) {
			rz_analysis_function_resize(fcn, core->offset - fcn->addr);
		}
		rz_cons_break_push(NULL, NULL);
		// required for thumb autodetection
		rz_core_analysis_function_add(core, NULL, off, false);
		rz_cons_break_pop();
	} break;
	case 'v': {
		ut64 N;
		char *endptr = NULL;
		char *end_off = rz_cons_input("Last hexadecimal digits of instruction: ");
		if (end_off) {
			N = strtoull(end_off, &endptr, 16);
		}
		if (!end_off || end_off == endptr) {
			eprintf("Invalid numeric input\n");
			rz_cons_any_key(NULL);
			free(end_off);
			break;
		}
		free(end_off);

		ut64 incr = 0x10;
		ut64 tmp_N = N >> 4;
		while (tmp_N > 0) {
			tmp_N = tmp_N >> 4;
			incr = incr << 4;
		}
		ut64 mask = incr - 1;

		ut64 start_off = (off & ~mask) ^ N;
		if ((off & mask) > N) {
			if (start_off > incr) {
				start_off -= incr;
			} else {
				start_off = N;
			}
		}

		ut64 try_off;
		RzAnalysisOp *op = NULL;
		RzAnalysisVar *var = NULL;
		for (try_off = start_off; try_off < start_off + incr * 16; try_off += incr) {
			rz_analysis_op_free(op);
			op = rz_core_analysis_op(core, try_off, RZ_ANALYSIS_OP_MASK_ALL);
			if (!op) {
				break;
			}
			var = rz_analysis_get_used_function_var(core->analysis, op->addr);
			if (var) {
				break;
			}
		}

		if (var) {
			char *newname = rz_cons_input(sdb_fmt("New variable name for '%s': ", var->name));
			if (newname && *newname) {
				rz_analysis_var_rename(var, newname, true);
				free(newname);
			}
		} else {
			eprintf("Cannot find instruction with a variable\n");
			rz_cons_any_key(NULL);
		}

		rz_analysis_op_free(op);
		break;
	}
	case 'Q':
	case 'q':
	default:
		if (IS_DIGIT(ch)) {
			if (rep < 0) {
				rep = 0;
			}
			rep = rep * 10 + atoi((char *)&ch);
			goto repeat;
		}
		break;
	}
	if (distance > 0) {
		distance--;
		off += wordsize;
		goto onemoretime;
	}
}

RZ_API void rz_core_visual_colors(RzCore *core) {
	char *color = calloc(1, 64), cstr[32];
	char preview_cmd[128] = "pd $r";
	int ch, opt = 0, oopt = -1;
	bool truecolor = rz_cons_singleton()->context->color_mode == COLOR_MODE_16M;
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
		char *curtheme = rz_core_get_theme();

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
			rz_core_theme_nextpal(core, 'n');
			oopt = -1;
			break;
		case 'h':
			rz_core_theme_nextpal(core, 'p');
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
			rcolor.r = rz_num_rand(0xff);
			rcolor.g = rz_num_rand(0xff);
			rcolor.b = rz_num_rand(0xff);
			break;
		case 'c':
			rz_line_set_prompt("Preview command> ");
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
