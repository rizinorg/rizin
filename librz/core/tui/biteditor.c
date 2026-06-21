// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <limits.h>
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

/// Single-column separator between the low/high 32-bit halves.
static void print_half_separator(RzCore *core, bool use_utf8, bool use_color) {
	const char *sep = use_utf8 ? RUNE_LINE_VERT : "|";
	if (use_color) {
		rz_cons_printf(" %s%s%s",
			core->cons->context->pal.comment, sep,
			core->cons->context->pal.reset);
	} else {
		rz_cons_printf(" %s", sep);
	}
}

/// Print one byte cell with px-style value-based coloring. \p fmt holds
/// exactly one conversion for \p byte.
static void print_byte_cell(RzCore *core, bool use_color, const char *fmt, ut8 byte) {
	if (use_color) {
		const char *bc = rz_print_byte_color(core->print, byte);
		if (bc) {
			rz_cons_print(bc);
		}
		rz_cons_printf(fmt, byte);
		if (bc) {
			rz_cons_print(Color_RESET);
		}
	} else {
		rz_cons_printf(fmt, byte);
	}
}

/// Print a stringified RzIL effect after `rzil: `, soft-wrapping at the
/// terminal width on depth-1 breakpoints and indenting continuations.
/// Coloring matches `plf` (skipped when \p use_color is false).
#define RZIL_LABEL     "rzil: "
#define RZIL_LABEL_LEN 6
static void print_rzil_wrapped(RzCore *core, bool use_color, const char *il) {
	const int cols = rz_cons_get_size(NULL);
	const int width = (cols > RZIL_LABEL_LEN + 20) ? cols - 2 : 0;
	const size_t avail_first = width > 0 ? (size_t)(width - RZIL_LABEL_LEN) : (size_t)-1;
	const size_t avail_cont = width > 0 ? (size_t)(width - RZIL_LABEL_LEN) : (size_t)-1;
	const size_t len = strlen(il);

	rz_cons_print(RZIL_LABEL);
	if (width <= 0 || len <= avail_first) {
		if (use_color) {
			rz_core_il_colorize_body(core->cons->context, il);
		} else {
			rz_cons_print(il);
		}
		rz_cons_newline();
		return;
	}

	// Emit one line at a time, breaking at a space at paren-depth >= 1.
	// Prefer the lowest-depth break that fits, so we split between
	// top-level children rather than inside sub-expressions.
	size_t start = 0;
	bool first_line = true;
	int depth = 0;
	while (start < len) {
		const size_t avail = first_line ? avail_first : avail_cont;
		size_t end;
		if (len - start <= avail) {
			end = len;
		} else {
			size_t best_break = 0;
			int best_depth = INT_MAX;
			int d = depth;
			for (size_t i = start; i < len; i++) {
				char c = il[i];
				if (c == '(') {
					d++;
				} else if (c == ')') {
					d--;
				} else if (c == ' ' && d >= 1 && (i - start) <= avail) {
					if (d < best_depth || (d == best_depth && i > best_break)) {
						best_break = i;
						best_depth = d;
					}
				}
				if (c != '(' && c != ')' && (i - start) > avail) {
					break;
				}
			}
			end = (best_break > start) ? best_break : len;
		}
		if (!first_line) {
			for (int k = 0; k < RZIL_LABEL_LEN; k++) {
				rz_cons_print(" ");
			}
		}
		size_t slice_len = end - start;
		char *slice = rz_str_ndup(il + start, slice_len);
		if (slice) {
			if (use_color) {
				rz_core_il_colorize_body(core->cons->context, slice);
			} else {
				rz_cons_print(slice);
			}
			free(slice);
		}
		rz_cons_newline();
		for (size_t i = start; i < end; i++) {
			if (il[i] == '(') {
				depth++;
			} else if (il[i] == ')') {
				depth--;
			}
		}
		start = end;
		while (start < len && il[start] == ' ') {
			start++;
		}
		first_line = false;
	}
}

RZ_IPI bool rz_core_visual_bit_editor(RzCore *core) {
	const int nbits = sizeof(ut64) * 8;
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
		const bool use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
		const bool use_utf8 = rz_config_get_b(core->config, "scr.utf8");
		const bool big_endian = rz_config_get_b(core->config, "cfg.bigendian");
		RzConsPrintablePalette *pal = &core->cons->context->pal;
		const char *col_reset = use_color ? Color_RESET : "";
		const char *col_comment = use_color ? pal->comment : "";

		// Map display byte index (0 = leftmost) to memory byte index.
		// BE displays buf[0..7] left-to-right; LE reverses it so the MSB
		// is on the left. Cursor and byte-write keys go through this.
#define MEM_BYTE(DISPLAY_IDX) (big_endian ? (DISPLAY_IDX) : (7 - (DISPLAY_IDX)))

		RzAsmOp asmop = { 0 };
		(void)rz_asm_disassemble(core->rasm, &asmop, buf, sizeof(ut64));
		aop.type = -1;
		rz_analysis_op_init(&aop);
		(void)rz_analysis_op(core->analysis, &aop, core->offset, buf, sizeof(ut64),
			RZ_ANALYSIS_OP_MASK_ESIL | RZ_ANALYSIS_OP_MASK_IL);

		// chr: printable char per byte, px-style colored.
		rz_cons_print("chr:");
		for (i = 0; i < 8; i++) {
			const ut8 byte = buf[MEM_BYTE(i)];
			char ch = IS_PRINTABLE(byte) ? byte : '?';
			if (i == 4) {
				print_half_separator(core, use_utf8, use_color);
			}
			rz_cons_print("      '");
			print_byte_cell(core, use_color, "%c", (ut8)ch);
			rz_cons_print("'");
		}

		// dec: decimal value per byte.
		rz_cons_newline();
		rz_cons_print("dec:");
		for (i = 0; i < 8; i++) {
			if (i == 4) {
				print_half_separator(core, use_utf8, use_color);
			}
			print_byte_cell(core, use_color, " %8d", buf[MEM_BYTE(i)]);
		}

		// hex: hex value per byte.
		rz_cons_newline();
		rz_cons_print("hex:");
		for (i = 0; i < 8; i++) {
			if (i == 4) {
				print_half_separator(core, use_utf8, use_color);
			}
			print_byte_cell(core, use_color, "     0x%02x", buf[MEM_BYTE(i)]);
		}
		rz_cons_newline();

		// bit: rows. Padding glyph for the opposite value is `·` when
		// colour or Unicode is on, else `.`. The cursor bit is reverse-
		// video highlighted (a graphics attribute, emitted regardless of
		// scr.color); other padding bits are dimmed via pal.comment.
		const char *ws = (use_color || use_utf8) ? "·" : ".";
		const char *bit_sep_glyph = use_utf8 ? RUNE_LINE_VERT : "|";

		// Emit one bit glyph. COMBINED shows both 0 and 1; otherwise only
		// bits matching SET_PASS are shown, the rest as padding.
#define EMIT_BIT(BYTE, BYTE_DISPLAY_IDX, BIT_IDX, COMBINED, SHOW_VALUE) \
	do { \
		const bool _bit = RZ_BIT_CHK((BYTE), 7 - (BIT_IDX)); \
		const bool _is_active = ((COMBINED) || (SHOW_VALUE) == _bit); \
		const bool _is_cursor = (((BYTE_DISPLAY_IDX) * 8 + (BIT_IDX)) == x); \
		if (_is_cursor) { \
			rz_cons_print(Color_INVERT); \
		} else if (use_color && !_is_active) { \
			rz_cons_print(col_comment); \
		} \
		rz_cons_print(_is_active ? (_bit ? "1" : "0") : ws); \
		if (_is_cursor || (use_color && !_is_active)) { \
			rz_cons_print(Color_RESET); \
		} \
	} while (0)

#define EMIT_BIT_ROW(SET_PASS, COMBINED) \
	do { \
		rz_cons_print("bit: "); \
		for (i = 0; i < 8; i++) { \
			ut8 *byte = buf + MEM_BYTE(i); \
			if (i == 4) { \
				if (use_color) { \
					rz_cons_printf("%s%s%s ", col_comment, bit_sep_glyph, col_reset); \
				} else { \
					rz_cons_printf("%s ", bit_sep_glyph); \
				} \
			} \
			for (j = 0; j < 8; j++) { \
				EMIT_BIT(byte, i, j, (COMBINED), (bool)(SET_PASS)); \
			} \
			rz_cons_print(" "); \
		} \
		rz_cons_newline(); \
	} while (0)

		// Body column of the cursor: 8 bits + 1 space per byte, plus 2 for
		// the half-separator past bit 31.
		int cursor_col = x + (x / 8);
		if (x > 31) {
			cursor_col += 2;
		}

		// Marker row. The `pos:` label is dropped; 5 leading spaces keep
		// the marker aligned with the bit cells. `↕` (split) points at
		// both rows; `▲` (bitsInLine) points at the single row above.
		const char *caret_split = use_utf8 ? "↕" : "|";
		const char *caret_below = use_utf8 ? "▲" : "^";
		const char *caret = bitsInLine ? caret_below : caret_split;

		if (bitsInLine) {
			EMIT_BIT_ROW(/*unused*/ 0, /*combined*/ true);
		} else {
			EMIT_BIT_ROW(/*set*/ 1, /*combined*/ false);
		}

		rz_cons_print("     ");
		for (int k = 0; k < cursor_col; k++) {
			rz_cons_print(" ");
		}
		rz_cons_print(caret);
		rz_cons_newline();

		if (!bitsInLine) {
			EMIT_BIT_ROW(/*set*/ 0, /*combined*/ false);
		}

#undef EMIT_BIT_ROW
#undef EMIT_BIT

		rz_cons_newline();

		// Cursor info, right-aligned: byte N · nibble H|L · bit B [P] · LE|BE
		// N=display byte 0..7, H/L=nibble half, B=bit in byte 0..7,
		// P=global bit 0..63, LE/BE from cfg.bigendian. See `?` for legend.
		{
			const int byte_idx = x / 8;
			const int bit_in_byte = x % 8;
			const char nibble_letter = (bit_in_byte < 4) ? 'H' : 'L';
			const char *endian_tag = big_endian ? "BE" : "LE";
			const char *sep_display = use_utf8 ? " · " : " | ";
			// Measure with ASCII separators: `·` is multi-byte but one
			// column, so byte length can't be used for alignment directly.
			char measure[160];
			int visual_len = snprintf(measure, sizeof(measure),
				"byte %d | nibble %c | bit %d [%d] | %s",
				byte_idx, nibble_letter, bit_in_byte, x, endian_tag);
			const int total_width = 78;
			int padding = total_width - visual_len;
			if (padding < 0) {
				padding = 0;
			}
			for (int k = 0; k < padding; k++) {
				rz_cons_print(" ");
			}
			rz_cons_printf("byte %d%snibble %c%sbit %d [%d]%s%s\n",
				byte_idx, sep_display,
				nibble_letter, sep_display,
				bit_in_byte, x, sep_display,
				endian_tag);
		}

		// Two blank lines between the cursor info and the byte information
		// block (per user request).
		rz_cons_newline();
		rz_cons_newline();

		// offset:
		rz_cons_printf("offset: 0x%08" PFMT64x "\n", core->offset + cur);

		// hex: (rz_print_hexpair applies px-style coloring)
		{
			char *op_hex = rz_asm_op_get_hex(&asmop);
			char *res = rz_print_hexpair(core->print, op_hex, -1);
			rz_cons_printf("hex: %s%s\n", res ? res : "", col_reset);
			free(res);
			free(op_hex);
		}

		// len:
		rz_cons_printf("len: %d\n", asmop.size);

		// shift:
		{
			ut32 word = (x % 32);
			rz_cons_printf("shift: >> %u << %d\n", word, (asmop.size * 8) - (int)word - 1);
		}

		// asm: (colored via rz_asm_colorize_asm_str, same as pd)
		{
			RzReg *rreg = rz_analysis_get_reg(core->analysis);
			RzAsmParseParam *param = rz_asm_get_parse_param(rreg, aop.type);
			RzStrBuf *colored_asm = rz_asm_colorize_asm_str(&asmop.buf_asm, core->print, param, asmop.asm_toks);
			rz_asm_parse_param_free(param);
			rz_cons_printf("asm: %s%s\n", colored_asm ? rz_strbuf_get(colored_asm) : "", col_reset);
			rz_strbuf_free(colored_asm);
		}

		// IL line: prefer RzIL, fall back to ESIL, else skip. Wrapped and
		// colored like `plf`.
		{
			const char *esilstr = rz_strbuf_get(&aop.esil);
			if (aop.il_op) {
				RzStrBuf *sbil = rz_strbuf_new("");
				rz_il_op_effect_stringify(aop.il_op, sbil, false);
				const char *ilstr = rz_strbuf_get(sbil);
				if (RZ_STR_ISNOTEMPTY(ilstr)) {
					print_rzil_wrapped(core, use_color, ilstr);
				}
				rz_strbuf_free(sbil);
			} else if (RZ_STR_ISNOTEMPTY(esilstr)) {
				rz_cons_printf("esil: %s\n", esilstr);
			}
		}
		rz_analysis_op_fini(&aop);

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
			rz_asm_op_fini(&asmop);
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
				const int nbyte = MEM_BYTE(x / 8);
				const int nbit = 7 - (x % 8);
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
			buf[MEM_BYTE(x / 8)] = rotate_nibble(buf[MEM_BYTE(x / 8)], -1);
			break;
		case '<':
			buf[MEM_BYTE(x / 8)] = rotate_nibble(buf[MEM_BYTE(x / 8)], 1);
			break;
		case 'i': {
			rz_line_set_prompt(rzline, "> ");
			const char *line = rz_line_readline(rzline);
			ut64 num = rz_num_math(core->num, line);
			if (num || (!num && *line == '0')) {
				buf[MEM_BYTE(x / 8)] = num;
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
			buf[MEM_BYTE(x / 8)]++;
			break;
		case '-':
			buf[MEM_BYTE(x / 8)]--;
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
		case '?': {
			static const char *help_msg[] = {
				"q", "", "quit the bit editor",
				"R", "", "rotate / randomize the color palette",
				"b", "", "toggle combined bit row (single row vs. split 1/0)",
				"j/k", "", "toggle bit value at cursor (same as space)",
				"h/l", "", "move cursor to previous / next bit",
				"H/L", "", "move cursor to previous / next byte (8 bits)",
				"+/-", "", "increment / decrement byte under cursor",
				"</>", "", "rotate left / right the byte under cursor",
				"i", "", "insert numeric value into byte under cursor",
				":", "", "enter a rizin command",
				"?", "", "show this help",
				NULL
			};
			RzStrBuf *help = rz_strbuf_new(NULL);
			rz_cons_clear00();
			rz_strbuf_append(help,
				"Visual bit editor: edit individual bits of the 64 bits at the\n"
				"current offset. The screen layout is, top to bottom:\n"
				"\n"
				"  chr/dec/hex  per-byte views, coloured by value the way `px` does\n"
				"  bit (1s)     the set bits of each byte, dimmed `·` where unset\n"
				"  marker       points at the column of the cursor (`↕` between rows)\n"
				"  bit (0s)     the unset bits of each byte, dimmed `·` where set\n"
				"  position     summary line (see legend below)\n"
				"  offset/hex/  the address, opcode bytes, length and shift; the\n"
				"  len/shift/   disassembly (`asm:`), and the symbolic semantics\n"
				"  asm/rzil     (`rzil:` if available, else `esil:`)\n"
				"\n"
				"Byte order on screen follows cfg.bigendian: in big-endian the\n"
				"leftmost byte is the byte at the current offset; in little-endian\n"
				"the displayed value is reordered so the most significant byte sits\n"
				"on the left. Cursor and byte-write keys honour the same mapping.\n"
				"\n");
			rz_core_visual_append_help(help, "Keys", help_msg);
			rz_strbuf_append(help,
				"\n"
				"Position legend (the line just below the bit grid):\n"
				"\n"
				"  byte N      display byte index, 0 (left) .. 7 (right)\n"
				"  nibble H|L  high (bits 0..3) or low (bits 4..7) nibble of that byte\n"
				"  bit B       bit index inside the byte, 0..7, MSB-first\n"
				"  [P]         global bit position across the 64-bit window, 0..63\n"
				"  LE / BE     little-endian / big-endian, from cfg.bigendian\n");
			rz_cons_print(rz_strbuf_get(help));
			rz_strbuf_free(help);
			rz_cons_flush();
			rz_cons_any_key(NULL);
		} break;
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
#undef MEM_BYTE
	return true;
}
