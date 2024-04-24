// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

enum {
	RZ_BYTE_DATA = 1,
	RZ_WORD_DATA = 2,
	RZ_DWORD_DATA = 4,
	RZ_QWORD_DATA = 8
};

// define the data at offset according to the type (byte, word...) n times
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
	// TODO extend for more analysis hints
	int i = 0;
	char ch[64] = RZ_EMPTY;
	const char *lines[] = { "[dh]- Define analysis hint:", " b [16,32,64]     set bits hint", NULL };
	for (i = 0; lines[i]; i++) {
		rz_cons_fill_line();
		rz_cons_printf("\r%s\n", lines[i]);
	}
	RzLine *line = core->cons->line;
	rz_cons_flush();
	rz_line_set_prompt(line, "analysis hint: ");
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

RZ_IPI void rz_core_visual_define(RzCore *core, const char *args, int distance) {
	RzCoreVisual *visual = core->visual;
	RzLine *line = core->cons->line;
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
		rz_line_set_prompt(line, "format: ");
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
		rz_line_set_prompt(line, ch == 't' ? "type: " : "opstr: ");
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
		rz_line_set_prompt(line, "immbase: ");
		if (rz_cons_fgets(str, sizeof(str), 0, NULL) > 0) {
			int base = rz_num_base_of_string(core->num, str);
			rz_analysis_hint_set_immbase(core->analysis, off, base);
		}
	} break;
	case 'I': {
		char str[128];
		rz_cons_show_cursor(true);
		rz_line_set_prompt(line, "immbase: ");
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
					const char *ptr = rz_str_lchr(rz_flag_item_get_name(item), '.');
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
		RzAnalysisOp op = { 0 };
		ut64 tgt_addr = UT64_MAX;
		if (!isDisasmPrint(visual->printidx)) {
			break;
		}
		// TODO: get the aligned instruction even if the cursor is in the middle of it.
		rz_analysis_op_init(&op);
		rz_analysis_op(core->analysis, &op, off,
			core->block + off - core->offset, 32, RZ_ANALYSIS_OP_MASK_BASIC);

		tgt_addr = op.jump != UT64_MAX ? op.jump : op.ptr;
		RzAnalysisVar *var = rz_analysis_get_used_function_var(core->analysis, op.addr);
		if (var) {
			char *inputstr = rz_str_newf("New variable name for '%s': ", var->name);
			char *newname = rz_cons_input(inputstr);
			if (RZ_STR_ISNOTEMPTY(newname)) {
				rz_analysis_var_rename(var, newname, true);
				free(newname);
			}
			free(inputstr);
		} else if (tgt_addr != UT64_MAX) {
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(core->analysis, tgt_addr);
			RzFlagItem *f = rz_flag_get_i(core->flags, tgt_addr);
			if (fcn) {
				char *msg = rz_str_newf("Rename function %s to: ", fcn->name);
				char *newname = rz_cons_input(msg);
				free(msg);
				rz_core_analysis_function_rename(core, tgt_addr, newname);
				free(newname);
			} else if (f) {
				char *msg = rz_str_newf("Rename flag %s to: ", rz_flag_item_get_name(f));
				char *newname = rz_cons_input(msg);
				free(msg);
				rz_flag_rename(core->flags, f, newname);
				free(newname);
			} else {
				char *msg = rz_str_newf("Create flag at 0x%" PFMT64x " named: ", tgt_addr);
				char *newname = rz_cons_input(msg);
				free(msg);
				rz_flag_set(core->flags, newname, tgt_addr, 1);
				free(newname);
			}
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
			rz_line_set_prompt(line, "color: ");
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
			rz_cons_printf("Current flag size is: %" PFMT64d "\n", rz_flag_item_get_size(item));
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_line_set_prompt(line, "new size: ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) > 0) {
				rz_flag_item_set_size(item, rz_num_math(core->num, cmd));
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
				RzAnalysisOp op = { 0 };
				ut64 size;
				rz_analysis_op_init(&op);
				if (rz_analysis_op(core->analysis, &op, off, core->block + delta,
					    core->blocksize - delta, RZ_ANALYSIS_OP_MASK_BASIC) > 0) {
					size = off - fcn->addr + op.size;
					rz_analysis_function_resize(fcn, size);
				}
				rz_analysis_op_fini(&op);
			}
		}
		break;
	case 'j': {
		ut64 addr = rz_num_math(core->num, "$$+$F");
		rz_core_analysis_fcn_merge(core, off, addr);
	} break;
	case 'k':
		eprintf("TODO: merge up\n");
		rz_cons_any_key(NULL);
		break;
	// very weak and incomplete
	case 'h': // "Vdh"
		handleHints(core);
		break;
	case 'r': // "Vdr"
		rz_core_cmdf(core, "%%i new function name;afn `yp` @ 0x%08" PFMT64x, off);
		break;
	case 'z': // "Vdz"
		rz_core_cmdf(core, "%%i zone name;fz `yp` @ 0x%08" PFMT64x, off);
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
					// check if is still wide
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
		// handle wide strings
		// memcpy (name + 4, (const char *)p, n);
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
			char *inputstr = rz_str_newf("New variable name for '%s': ", var->name);
			char *newname = rz_cons_input(inputstr);
			if (RZ_STR_ISNOTEMPTY(newname)) {
				rz_analysis_var_rename(var, newname, true);
				free(newname);
			}
			free(inputstr);
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
