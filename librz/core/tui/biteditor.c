// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

static int rotate_nibble(const ut8 b, int dir) {
	if (dir > 0) {
		bool high = b >> 7;
		return (b << 1) | high;
	}
	bool lower = b & 1;
	return (b >> 1) | (lower << 7);
}

RZ_IPI bool rz_core_visual_bit_editor(RzCore *core) {
	const int nbits = sizeof(ut64) * 8;
	bool colorBits = false;
	int i, j, x = 0;
	RzAnalysisOp aop = { 0 };
	ut8 buf[sizeof(ut64)];
	bool bitsInLine = false;
	RzLine *rzline = core->cons->line;

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
		RzAsmOp asmop = { 0 };
		(void)rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(ut64));
		aop.type = -1;
		rz_analysis_op_init(&aop);
		(void)rz_analysis_op(core->analysis, &aop, core->offset, buf, sizeof(ut64), RZ_ANALYSIS_OP_MASK_ESIL);
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
			RzAsmParseParam *param = rz_asm_get_parse_param(core->analysis->reg, aop.type);
			RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop.buf_asm, core->print, param, asmop.asm_toks);
			rz_asm_parse_param_free(param);
			rz_cons_printf(Color_RESET "asm: %s\n" Color_RESET, colored_asm ? rz_strbuf_get(colored_asm) : "");
			rz_strbuf_free(colored_asm);
		}
		rz_cons_printf(Color_RESET "esl: %s\n" Color_RESET, rz_strbuf_get(&aop.esil));
		rz_analysis_op_fini(&aop);
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
			// togglebit();
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
			rz_line_set_prompt(rzline, "> ");
			const char *line = rz_line_readline(rzline);
			ut64 num = rz_num_math(core->num, line);
			if (num || (!num && *line == '0')) {
				buf[x / 8] = num;
			}
		} break;
		case 'R':
			if (rz_config_get_b(core->config, "scr.randpal")) {
				rz_cons_pal_random();
			} else {
				rz_core_theme_nextpal(core, RZ_CONS_PAL_SEEK_NEXT);
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
			rz_line_set_prompt(rzline, ":> ");
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
		rz_asm_op_fini(&asmop);
	}
	return true;
}
