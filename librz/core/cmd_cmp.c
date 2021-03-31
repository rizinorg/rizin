// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_core.h"

static const char *help_msg_c[] = {
	"Usage:", "c[?dfx] [argument]", " # Compare",
	"c", " [string]", "Compare a plain with escaped chars string",
	"c*", " [string]", "Same as above, but printing rizin commands instead",
	"c1", " [addr]", "Compare 8 bits from current offset",
	"c2", " [value]", "Compare a word from a math expression",
	"c4", " [value]", "Compare a doubleword from a math expression",
	"c8", " [value]", "Compare a quadword from a math expression",
	"cat", " [file]", "Show contents of file (see pwd, ls)",
	"cc", " [at]", "Compares in two hexdump columns of block size",
	"ccc", " [at]", "Same as above, but only showing different lines",
	"ccd", " [at]", "Compares in two disasm columns of block size",
	"cd", " [dir]", "chdir",
	// "cc", " [offset]", "code bindiff current block against offset"
	// "cD", " [file]", "like above, but using radiff -b",
	"cf", " [file]", "Compare contents of file at current seek",
	"cg", "[?] [o] [file]", "Graphdiff current file and [file]",
	"cl|cls|clear", "", "Clear screen, (clear0 to goto 0, 0 only)",
	"cu", "[?] [addr] @at", "Compare memory hexdumps of $$ and dst in unified diff",
	"cud", " [addr] @at", "Unified diff disasm from $$ and given address",
	"cv", "[1248] [hexpairs] @at", "Compare 1,2,4,8-byte (silent return in $?)",
	"cV", "[1248] [addr] @at", "Compare 1,2,4,8-byte address contents (silent, return in $?)",
	"cw", "[?] [us?] [...]", "Compare memory watchers",
	"cx", " [hexpair]", "Compare hexpair string (use '.' as nibble wildcard)",
	"cx*", " [hexpair]", "Compare hexpair string (output rizin commands)",
	"cX", " [addr]", "Like 'cc' but using hexdiff output",
	NULL
};

RZ_API void rz_core_cmpwatch_free(RzCoreCmpWatcher *w) {
	free(w->ndata);
	free(w->odata);
	free(w);
}

RZ_API RzCoreCmpWatcher *rz_core_cmpwatch_get(RzCore *core, ut64 addr) {
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr) {
			return w;
		}
	}
	return NULL;
}

RZ_API int rz_core_cmpwatch_add(RzCore *core, ut64 addr, int size, const char *cmd) {
	RzCoreCmpWatcher *cmpw;
	if (size < 1) {
		return false;
	}
	cmpw = rz_core_cmpwatch_get(core, addr);
	if (!cmpw) {
		cmpw = RZ_NEW(RzCoreCmpWatcher);
		if (!cmpw) {
			return false;
		}
		cmpw->addr = addr;
	}
	cmpw->size = size;
	snprintf(cmpw->cmd, sizeof(cmpw->cmd), "%s", cmd);
	cmpw->odata = NULL;
	cmpw->ndata = malloc(size);
	if (!cmpw->ndata) {
		free(cmpw);
		return false;
	}
	rz_io_read_at(core->io, addr, cmpw->ndata, size);
	rz_list_append(core->watchers, cmpw);
	return true;
}

RZ_API int rz_core_cmpwatch_del(RzCore *core, ut64 addr) {
	int ret = false;
	RzCoreCmpWatcher *w;
	RzListIter *iter, *iter2;
	rz_list_foreach_safe (core->watchers, iter, iter2, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			rz_list_delete(core->watchers, iter);
			ret = true;
		}
	}
	return ret;
}

RZ_API int rz_core_cmpwatch_show(RzCore *core, ut64 addr, int mode) {
	char cmd[128];
	RzListIter *iter;
	RzCoreCmpWatcher *w;
	rz_list_foreach (core->watchers, iter, w) {
		int is_diff = w->odata ? memcmp(w->odata, w->ndata, w->size) : 0;
		switch (mode) {
		case '*':
			rz_cons_printf("cw 0x%08" PFMT64x " %d %s%s\n",
				w->addr, w->size, w->cmd, is_diff ? " # differs" : "");
			break;
		case 'd': // diff
			if (is_diff) {
				rz_cons_printf("0x%08" PFMT64x " has changed\n", w->addr);
			}
		case 'o': // old contents
		// use tmpblocksize
		default:
			rz_cons_printf("0x%08" PFMT64x "%s\n", w->addr, is_diff ? " modified" : "");
			snprintf(cmd, sizeof(cmd), "%s@%" PFMT64d "!%d",
				w->cmd, w->addr, w->size);
			rz_core_cmd0(core, cmd);
			break;
		}
	}
	return false;
}

RZ_API int rz_core_cmpwatch_update(RzCore *core, ut64 addr) {
	RzCoreCmpWatcher *w;
	RzListIter *iter;
	rz_list_foreach (core->watchers, iter, w) {
		free(w->odata);
		w->odata = w->ndata;
		w->ndata = malloc(w->size);
		if (!w->ndata) {
			return false;
		}
		rz_io_read_at(core->io, w->addr, w->ndata, w->size);
	}
	return !rz_list_empty(core->watchers);
}

RZ_API int rz_core_cmpwatch_revert(RzCore *core, ut64 addr) {
	RzCoreCmpWatcher *w;
	int ret = false;
	RzListIter *iter;
	rz_list_foreach (core->watchers, iter, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			if (w->odata) {
				free(w->ndata);
				w->ndata = w->odata;
				w->odata = NULL;
				ret = true;
			}
		}
	}
	return ret;
}

static int rizin_compare_words(RzCore *core, ut64 of, ut64 od, int len, int ws) {
	int i;
	bool useColor = rz_config_get_i(core->config, "scr.color") != 0;
	utAny v0, v1;
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	for (i = 0; i < len; i += ws) {
		memset(&v0, 0, sizeof(v0));
		memset(&v1, 0, sizeof(v1));
		rz_io_read_at(core->io, of + i, (ut8 *)&v0, ws);
		rz_io_read_at(core->io, od + i, (ut8 *)&v1, ws);
		char ch = (v0.v64 == v1.v64) ? '=' : '!';
		const char *color = useColor ? ch == '=' ? "" : pal->graph_false : "";
		const char *colorEnd = useColor ? Color_RESET : "";

		if (useColor) {
			rz_cons_printf("%s0x%08" PFMT64x "  " Color_RESET, pal->offset, of + i);
		} else {
			rz_cons_printf("0x%08" PFMT64x "  ", of + i);
		}
		switch (ws) {
		case 1:
			rz_cons_printf("%s0x%02x %c 0x%02x%s\n", color,
				(ut32)(v0.v8 & 0xff), ch, (ut32)(v1.v8 & 0xff), colorEnd);
			break;
		case 2:
			rz_cons_printf("%s0x%04hx %c 0x%04hx%s\n", color,
				v0.v16, ch, v1.v16, colorEnd);
			break;
		case 4:
			rz_cons_printf("%s0x%08" PFMT32x " %c 0x%08" PFMT32x "%s\n", color,
				v0.v32, ch, v1.v32, colorEnd);
			//rz_core_cmdf (core, "fd@0x%"PFMT64x, v0.v32);
			if (v0.v32 != v1.v32) {
				//	rz_core_cmdf (core, "fd@0x%"PFMT64x, v1.v32);
			}
			break;
		case 8:
			rz_cons_printf("%s0x%016" PFMT64x " %c 0x%016" PFMT64x "%s\n",
				color, v0.v64, ch, v1.v64, colorEnd);
			//rz_core_cmdf (core, "fd@0x%"PFMT64x, v0.v64);
			if (v0.v64 != v1.v64) {
				//	rz_core_cmdf (core, "fd@0x%"PFMT64x, v1.v64);
			}
			break;
		}
	}
	return 0;
}

static int rizin_compare_unified(RzCore *core, ut64 of, ut64 od, int len) {
	int i, min, inc = 16;
	ut8 *f, *d;
	if (len < 1) {
		return false;
	}
	f = malloc(len);
	if (!f) {
		return false;
	}
	d = malloc(len);
	if (!d) {
		free(f);
		return false;
	}
	rz_io_read_at(core->io, of, f, len);
	rz_io_read_at(core->io, od, d, len);
	int headers = B_IS_SET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	if (headers) {
		B_UNSET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	}
	for (i = 0; i < len; i += inc) {
		min = RZ_MIN(16, (len - i));
		if (!memcmp(f + i, d + i, min)) {
			rz_cons_printf("  ");
			rz_print_hexdiff(core->print, of + i, f + i, of + i, f + i, min, 0);
		} else {
			rz_cons_printf("- ");
			rz_print_hexdiff(core->print, of + i, f + i, od + i, d + i, min, 0);
			rz_cons_printf("+ ");
			rz_print_hexdiff(core->print, od + i, d + i, of + i, f + i, min, 0);
		}
	}
	if (headers) {
		B_SET(core->print->flags, RZ_PRINT_FLAGS_HEADER);
	}
	return true;
}

static int rizin_compare(RzCore *core, const ut8 *f, const ut8 *d, int len, int mode) {
	int i, eq = 0;
	PJ *pj = NULL;
	if (len < 1) {
		return 0;
	}
	if (mode == 'j') {
		pj = pj_new();
		if (!pj) {
			return -1;
		}
		pj_o(pj);
		pj_k(pj, "diff_bytes");
		pj_a(pj);
	}
	for (i = 0; i < len; i++) {
		if (f[i] == d[i]) {
			eq++;
			continue;
		}
		switch (mode) {
		case 0:
			rz_cons_printf("0x%08" PFMT64x " (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
				core->offset + i, i + 1,
				f[i], (IS_PRINTABLE(f[i])) ? f[i] : ' ',
				d[i], (IS_PRINTABLE(d[i])) ? d[i] : ' ');
			break;
		case '*':
			rz_cons_printf("wx %02x @ 0x%08" PFMT64x "\n",
				d[i],
				core->offset + i);
			break;
		case 'j':
			pj_o(pj);
			pj_kn(pj, "offset", core->offset + i);
			pj_ki(pj, "rel_offset", i);
			pj_ki(pj, "value", (int)f[i]);
			pj_ki(pj, "cmp_value", (int)d[i]);
			pj_end(pj);
			break;
		}
	}
	if (mode == 0) {
		eprintf("Compare %d/%d equal bytes (%d%%)\n", eq, len, (eq / len) * 100);
	} else if (mode == 'j') {
		pj_end(pj);
		pj_ki(pj, "equal_bytes", eq);
		pj_ki(pj, "total_bytes", len);
		pj_end(pj); // End array
		pj_end(pj); // End object
		rz_cons_println(pj_string(pj));
	}
	return len - eq;
}

static void cmd_cmp_watcher(RzCore *core, const char *input) {
	char *p, *q, *r = NULL;
	int size = 0;
	ut64 addr = 0;
	switch (*input) {
	case ' ':
		p = strdup(input + 1);
		q = strchr(p, ' ');
		if (q) {
			*q++ = 0;
			addr = rz_num_math(core->num, p);
			r = strchr(q, ' ');
			if (r) {
				*r++ = 0;
				size = atoi(q);
			}
			rz_core_cmpwatch_add(core, addr, size, r);
			// eprintf ("ADD (%llx) %d (%s)\n", addr, size, r);
		} else {
			eprintf("Missing parameters\n");
		}
		free(p);
		break;
	case 'r':
		addr = input[1] ? rz_num_math(core->num, input + 1) : UT64_MAX;
		rz_core_cmpwatch_revert(core, addr);
		break;
	case 'u':
		addr = input[1] ? rz_num_math(core->num, input + 1) : UT64_MAX;
		rz_core_cmpwatch_update(core, addr);
		break;
	case '*':
		rz_core_cmpwatch_show(core, UT64_MAX, '*');
		break;
	case '\0':
		rz_core_cmpwatch_show(core, UT64_MAX, 0);
		break;
	case '?': {
		const char *help_message[] = {
			"Usage: cw", "", "Watcher commands",
			"cw", "", "List all compare watchers",
			"cw", " addr", "List all compare watchers",
			"cw", " addr sz cmd", "Add a memory watcher",
			// "cws", " [addr]", "Show watchers",
			"cw", "*", "List compare watchers in rizin cmds",
			"cwr", " [addr]", "Reset/revert watchers",
			"cwu", " [addr]", "Update watchers",
			NULL
		};
		rz_core_cmd_help(core, help_message);
	} break;
	}
}

static int cmd_cmp_disasm(RzCore *core, const char *input, int mode) {
	RzAsmOp op, op2;
	int i, j;
	char colpad[80];
	int hascolor = rz_config_get_i(core->config, "scr.color");
	int cols = rz_config_get_i(core->config, "hex.cols") * 2;
	ut64 off = rz_num_math(core->num, input);
	ut8 *buf = calloc(core->blocksize + 32, 1);
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	if (!buf) {
		return false;
	}
	rz_io_read_at(core->io, off, buf, core->blocksize + 32);
	switch (mode) {
	case 'c': // columns
		for (i = j = 0; i < core->blocksize && j < core->blocksize;) {
			// dis A
			rz_asm_set_pc(core->rasm, core->offset + i);
			(void)rz_asm_disassemble(core->rasm, &op,
				core->block + i, core->blocksize - i);

			// dis B
			rz_asm_set_pc(core->rasm, off + i);
			(void)rz_asm_disassemble(core->rasm, &op2,
				buf + j, core->blocksize - j);

			// show output
			bool iseq = rz_strbuf_equals(&op.buf_asm, &op2.buf_asm);
			memset(colpad, ' ', sizeof(colpad));
			{
				int pos = strlen(rz_strbuf_get(&op.buf_asm));
				pos = (pos > cols) ? 0 : cols - pos;
				colpad[pos] = 0;
			}
			if (hascolor) {
				rz_cons_print(iseq ? pal->graph_true : pal->graph_false);
			}
			rz_cons_printf(" 0x%08" PFMT64x "  %s %s",
				core->offset + i, rz_strbuf_get(&op.buf_asm), colpad);
			rz_cons_printf("%c 0x%08" PFMT64x "  %s\n",
				iseq ? '=' : '!', off + j, rz_strbuf_get(&op2.buf_asm));
			if (hascolor) {
				rz_cons_print(Color_RESET);
			}
			if (op.size < 1) {
				op.size = 1;
			}
			i += op.size;
			if (op2.size < 1) {
				op2.size = 1;
			}
			j += op2.size;
		}
		break;
	case 'u': // unified
		for (i = j = 0; i < core->blocksize && j < core->blocksize;) {
			// dis A
			rz_asm_set_pc(core->rasm, core->offset + i);
			(void)rz_asm_disassemble(core->rasm, &op,
				core->block + i, core->blocksize - i);

			// dis B
			rz_asm_set_pc(core->rasm, off + i);
			(void)rz_asm_disassemble(core->rasm, &op2,
				buf + j, core->blocksize - j);

			// show output
			bool iseq = rz_strbuf_equals(&op.buf_asm, &op2.buf_asm); // (!strcmp (op.buf_asm, op2.buf_asm));
			if (iseq) {
				rz_cons_printf(" 0x%08" PFMT64x "  %s\n",
					core->offset + i, rz_strbuf_get(&op.buf_asm));
			} else {
				if (hascolor) {
					rz_cons_print(pal->graph_false);
				}
				rz_cons_printf("-0x%08" PFMT64x "  %s\n",
					core->offset + i, rz_strbuf_get(&op.buf_asm));
				if (hascolor) {
					rz_cons_print(pal->graph_true);
				}
				rz_cons_printf("+0x%08" PFMT64x "  %s\n",
					off + j, rz_strbuf_get(&op2.buf_asm));
				if (hascolor) {
					rz_cons_print(Color_RESET);
				}
			}
			if (op.size < 1) {
				op.size = 1;
			}
			i += op.size;
			if (op2.size < 1) {
				op2.size = 1;
			}
			j += op2.size;
		}
		break;
	}
	return 0;
}

static int cmd_cp(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	if (input[1] == '.') {
		char *file = rz_core_cmd_strf(core, "ij~{core.file}");
		rz_str_trim(file);
		char *newfile = rz_str_newf("%s.%s", file, input + 2);
		rz_file_copy(file, newfile);
		free(file);
		free(newfile);
		return true;
	}
	if (strlen(input) < 3) {
		eprintf("Usage: cp src dst\n");
		eprintf("Usage: cp.orig  # cp $file $file.orig\n");
		return false;
	}
	char *cmd = strdup(input + 2);
	if (cmd) {
		char **files = rz_str_argv(cmd, NULL);
		if (files[0] && files[1]) {
			bool rc = rz_file_copy(files[0], files[1]);
			free(cmd);
			rz_str_argv_free(files);
			return rc;
		}
		rz_str_argv_free(files);
	}
	eprintf("Usage: cp src dst\n");
	return false;
}

static void __core_cmp_bits(RzCore *core, ut64 addr) {
	const bool scr_color = rz_config_get_i(core->config, "scr.color");
	int i;
	ut8 a, b;
	rz_io_read_at(core->io, core->offset, &a, 1);
	rz_io_read_at(core->io, addr, &b, 1);
	RzConsPrintablePalette *pal = &rz_cons_singleton()->context->pal;
	const char *color = scr_color ? pal->offset : "";
	const char *color_end = scr_color ? Color_RESET : "";
	if (rz_config_get_i(core->config, "hex.header")) {
		char *n = rz_str_newf("0x%08" PFMT64x, core->offset);
		const char *extra = rz_str_pad(' ', strlen(n) - 10);
		free(n);
		rz_cons_printf("%s- offset -%s  7 6 5 4 3 2 1 0%s\n", color, extra, color_end);
	}
	color = scr_color ? pal->graph_false : "";
	color_end = scr_color ? Color_RESET : "";

	rz_cons_printf("%s0x%08" PFMT64x "%s  ", color, core->offset, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (a & 1 << i) ? 1 : 0;
		bool b1 = (b & 1 << i) ? 1 : 0;
		color = scr_color ? (b0 == b1) ? "" : b0 ? pal->graph_true
							 : pal->graph_false
				  : "";
		color_end = scr_color ? Color_RESET : "";
		rz_cons_printf("%s%d%s ", color, b0, color_end);
	}
	color = scr_color ? pal->graph_true : "";
	color_end = scr_color ? Color_RESET : "";
	rz_cons_printf("\n%s0x%08" PFMT64x "%s  ", color, addr, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (a & 1 << i) ? 1 : 0;
		bool b1 = (b & 1 << i) ? 1 : 0;
		color = scr_color ? (b0 == b1) ? "" : b1 ? pal->graph_true
							 : pal->graph_false
				  : "";
		color_end = scr_color ? Color_RESET : "";
		rz_cons_printf("%s%d%s ", color, b1, color_end);
	}
	rz_cons_newline();
}

RZ_IPI int rz_cmd_cmp(void *data, const char *input) {
	static char *oldcwd = NULL;
	int ret = 0, i, mode = 0;
	RzCore *core = (RzCore *)data;
	ut64 val = UT64_MAX;
	char *filled;
	ut8 *buf;
	ut16 v16;
	ut32 v32;
	ut64 v64;
	FILE *fd;
	const ut8 *block = core->block;

	switch (*input) {
	case 'p':
		return cmd_cp(data, input);
		break;
	case 'a': // "cat"
		if (input[1] == 't') {
			const char *path = rz_str_trim_head_ro(input + 2);
			if (*path == '$') {
				const char *oldText = rz_cmd_alias_get(core->rcmd, path, 1);
				if (oldText) {
					rz_cons_printf("%s\n", oldText + 1);
				}
			} else {
				char *res = rz_syscmd_cat(path);
				if (res) {
					rz_cons_print(res);
					free(res);
				}
			}
		}
		break;
	case 'w':
		cmd_cmp_watcher(core, input + 1);
		break;
	case '*':
		if (!input[2]) {
			eprintf("Usage: cx* 00..22'\n");
			return 0;
		}

		val = rizin_compare(core, block, (ut8 *)input + 2,
			strlen(input + 2) + 1, '*');
		break;
	case ' ': {
		char *str = strdup(input + 1);
		int len = rz_str_unescape(str);
		val = rizin_compare(core, block, (ut8 *)str, len, 0);
		free(str);
	} break;
	case 'j': {
		if (input[1] != ' ') {
			eprintf("Usage: cj [string]\n");
		} else {
			char *str = strdup(input + 2);
			int len = rz_str_unescape(str);
			val = rizin_compare(core, block, (ut8 *)str, len, 'j');
			free(str);
		}
	} break;
	case 'x':
		switch (input[1]) {
		case ' ':
			mode = 0;
			input += 2;
			break;
		case '*':
			if (input[2] != ' ') {
				eprintf("Usage: cx* 00..22'\n");
				return 0;
			}
			mode = '*';
			input += 3;
			break;
		default:
			eprintf("Usage: cx 00..22'\n");
			return 0;
		}
		if (!(filled = (char *)malloc(strlen(input) + 1))) {
			return false;
		}
		memcpy(filled, input, strlen(input) + 1);
		if (!(buf = (ut8 *)malloc(strlen(input) + 1))) {
			free(filled);
			return false;
		}
		ret = rz_hex_bin2str(block, strlen(input) / 2, (char *)buf);
		for (i = 0; i < ret * 2; i++) {
			if (filled[i] == '.') {
				filled[i] = buf[i];
			}
		}

		ret = rz_hex_str2bin(filled, buf);
		if (ret < 1) {
			eprintf("Cannot parse hexpair\n");
		} else {
			val = rizin_compare(core, block, buf, ret, mode);
		}
		free(buf);
		free(filled);
		break;
	case 'X':
		buf = malloc(core->blocksize);
		if (buf) {
			if (!rz_io_read_at(core->io, rz_num_math(core->num, input + 1), buf, core->blocksize)) {
				eprintf("Cannot read hexdump\n");
			} else {
				rizin_compare(core, block, buf, ret, mode);
			}
			free(buf);
		}
		return false;
	case 'f':
		if (input[1] != ' ') {
			eprintf("Please. use 'cf [file]'\n");
			return false;
		}
		fd = rz_sys_fopen(input + 2, "rb");
		if (!fd) {
			eprintf("Cannot open file '%s'\n", input + 2);
			return false;
		}
		buf = (ut8 *)malloc(core->blocksize);
		if (buf) {
			if (fread(buf, 1, core->blocksize, fd) < 1) {
				eprintf("Cannot read file %s\n", input + 2);
			} else {
				val = rizin_compare(core, block, buf, core->blocksize, 0);
			}
			fclose(fd);
			free(buf);
		} else {
			fclose(fd);
			return false;
		}
		break;
	case 'd': // "cd"
		while (input[1] == ' ')
			input++;
		if (input[1]) {
			if (!strcmp(input + 1, "-")) {
				if (oldcwd) {
					char *newdir = oldcwd;
					oldcwd = rz_sys_getdir();
					if (chdir(newdir) == -1) {
						eprintf("Cannot chdir to %s\n", newdir);
						free(oldcwd);
						oldcwd = newdir;
					} else {
						free(newdir);
					}
				} else {
					// nothing to do here
				}
			} else if (input[1] == '~' && input[2] == '/') {
				char *homepath = rz_str_home(input + 3);
				if (homepath) {
					if (*homepath) {
						free(oldcwd);
						oldcwd = rz_sys_getdir();
						if (chdir(homepath) == -1) {
							eprintf("Cannot chdir to %s\n", homepath);
						}
					}
					free(homepath);
				} else {
					eprintf("Cannot find home\n");
				}
			} else {
				free(oldcwd);
				oldcwd = rz_sys_getdir();
				if (chdir(input + 1) == -1) {
					eprintf("Cannot chdir to %s\n", input + 1);
				}
			}
		} else {
			char *home = rz_sys_getenv(RZ_SYS_HOME);
			if (!home || chdir(home) == -1) {
				eprintf("Cannot find home.\n");
			}
			free(home);
		}
		break;
	case '1': // "c1"
		__core_cmp_bits(core, rz_num_math(core->num, input + 1));
		break;
	case '2': // "c2"
		v16 = (ut16)rz_num_math(core->num, input + 1);
		val = rizin_compare(core, block, (ut8 *)&v16, sizeof(v16), 0);
		break;
	case '4': // "c4"
		v32 = (ut32)rz_num_math(core->num, input + 1);
		val = rizin_compare(core, block, (ut8 *)&v32, sizeof(v32), 0);
		break;
	case '8': // "c8"
		v64 = (ut64)rz_num_math(core->num, input + 1);
		val = rizin_compare(core, block, (ut8 *)&v64, sizeof(v64), 0);
		break;
	case 'c': // "cc"
		if (input[1] == '?') { // "cc?"
			rz_core_cmd0(core, "c?~cc");
		} else if (input[1] == 'd') { // "ccd"
			if (input[2] == 'd') { // "ccdd"
				cmd_cmp_disasm(core, input + 3, 'd');
			} else {
				cmd_cmp_disasm(core, input + 2, 'c');
			}
		} else {
			ut32 oflags = core->print->flags;
			ut64 addr = 0; // TOTHINK: Not sure what default address should be
			if (input[1] == 'c') { // "ccc"
				core->print->flags |= RZ_PRINT_FLAGS_DIFFOUT;
				addr = rz_num_math(core->num, input + 2);
			} else {
				if (*input && input[1]) {
					addr = rz_num_math(core->num, input + 2);
				}
			}
			int col = core->cons->columns > 123;
			ut8 *b = malloc(core->blocksize);
			if (b != NULL) {
				memset(b, 0xff, core->blocksize);
				rz_io_read_at(core->io, addr, b, core->blocksize);
				rz_print_hexdiff(core->print, core->offset, block,
					addr, b, core->blocksize, col);
				free(b);
			}
			core->print->flags = oflags;
		}
		break;
	case 'g': // "cg"
	{ // XXX: this is broken
		int diffops = 0;
		RzCore *core2;
		char *file2 = NULL;
		switch (input[1]) {
		case 'o': // "cgo"
			file2 = (char *)rz_str_trim_head_ro(input + 2);
			rz_analysis_diff_setup(core->analysis, true, -1, -1);
			break;
		case 'f': // "cgf"
			eprintf("TODO: agf is experimental\n");
			rz_analysis_diff_setup(core->analysis, true, -1, -1);
			rz_core_gdiff_fcn(core, core->offset,
				rz_num_math(core->num, input + 2));
			return false;
		case ' ':
			file2 = (char *)rz_str_trim_head_ro(input + 2);
			rz_analysis_diff_setup(core->analysis, false, -1, -1);
			break;
		default: {
			const char *help_message[] = {
				"Usage: cg", "", "Graph code commands",
				"cg", "", "diff ratio among functions (columns: off-A, match-ratio, off-B)",
				"cgf", "[fcn]", "Compare functions (curseek vs fcn)",
				"cgo", "", "Opcode-bytes code graph diff",
				NULL
			};
			rz_core_cmd_help(core, help_message);
			return false;
		}
		}

		if (rz_file_size(file2) <= 0) {
			eprintf("Cannot compare with file %s\n", file2);
			return false;
		}

		if (!(core2 = rz_core_new())) {
			eprintf("Cannot init diff core\n");
			return false;
		}
		rz_core_loadlibs(core2, RZ_CORE_LOADLIBS_ALL, NULL);
		core2->io->va = core->io->va;
		if (!rz_core_file_open(core2, file2, 0, 0LL)) {
			eprintf("Cannot open diff file '%s'\n", file2);
			rz_core_free(core2);
			rz_core_bind_cons(core);
			return false;
		}
		// TODO: must replicate on core1 too
		rz_config_set_i(core2->config, "io.va", true);
		rz_analysis_diff_setup(core->analysis, diffops, -1, -1);
		rz_analysis_diff_setup(core2->analysis, diffops, -1, -1);

		rz_core_bin_load(core2, file2,
			rz_config_get_i(core->config, "bin.baddr"));
		rz_core_gdiff(core, core2);
		rz_core_diff_show(core, core2);
		/* exchange a segfault with a memleak */
		core2->config = NULL;
		rz_core_free(core2);
		rz_core_bind_cons(core);
	} break;
	case 'u': // "cu"
		switch (input[1]) {
		case '.':
		case ' ':
			rizin_compare_unified(core, core->offset,
				rz_num_math(core->num, input + 2),
				core->blocksize);
			break;
		case '1':
		case '2':
		case '4':
		case '8':
			rizin_compare_words(core, core->offset,
				rz_num_math(core->num, input + 2),
				core->blocksize, input[1] - '0');
			break;
		case 'd':
			cmd_cmp_disasm(core, input + 2, 'u');
			break;
		default: {
			const char *help_msg[] = {
				"Usage: cu", " [offset]", "# Prints unified comparison to make hexpatches",
				"cu", " $$+1 > p", "Compare hexpairs from  current seek and +1",
				"cu1", " $$+1 > p", "Compare bytes from current seek and +1",
				"cu2", " $$+1 > p", "Compare words (half, 16bit) from current seek and +1",
				"cu4", " $$+1 > p", "Compare dwords from current seek and +1",
				"cu8", " $$+1 > p", "Compare qwords from current seek and +1",
				"cud", " $$+1 > p", "Compare disasm current seek and +1",
				"wu", " p", "Apply unified hex patch (see output of cu)",
				NULL
			};
			rz_core_cmd_help(core, help_msg);
		}
		}
		break;
	case '?':
		rz_core_cmd_help(core, help_msg_c);
		break;
	case 'v': { // "cv"
		int sz = input[1];
		if (sz == ' ') {
			switch (rz_config_get_i(core->config, "asm.bits")) {
			case 8: sz = '1'; break;
			case 16: sz = '2'; break;
			case 32: sz = '4'; break;
			case 64: sz = '8'; break;
			default: sz = '4'; break; // default
			}
		}
		// TODO: honor endian
		switch (sz) {
		case '1': { // "cv1"
			ut8 n = (ut8)rz_num_math(core->num, input + 2);
			core->num->value = 1;
			if (block[0] == n) {
				rz_cons_printf("0x%08" PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		case '2': { // "cv2"
			ut16 n = (ut16)rz_num_math(core->num, input + 2);
			core->num->value = 1;
			if (core->blocksize >= 2 && *(ut16 *)block == n) {
				rz_cons_printf("0x%08" PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		case '4': { // "cv4"
			ut32 n = (ut32)rz_num_math(core->num, input + 2);
			core->num->value = 1;
			if (core->blocksize >= 4 && *(ut32 *)block == n) {
				rz_cons_printf("0x%08" PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		case '8': { // "cv8"
			ut64 n = (ut64)rz_num_math(core->num, input + 2);
			core->num->value = 1;
			if (core->blocksize >= 8 && *(ut64 *)block == n) {
				rz_cons_printf("0x%08" PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		default:
		case '?':
			eprintf("Usage: cv[1248] [num]\n"
				"Show offset if current value equals to the one specified\n"
				" /v 18312   # serch for a known value\n"
				" dc\n"
				" cv4 18312 @@ hit*\n"
				" dc\n");
			break;
		}
	} break;
	case 'V': { // "cV"
		int sz = input[1];
		if (sz == ' ') {
			switch (rz_config_get_i(core->config, "asm.bits")) {
			case 8: sz = '1'; break;
			case 16: sz = '2'; break;
			case 32: sz = '4'; break;
			case 64: sz = '8'; break;
			default: sz = '4'; break; // default
			}
		} else if (sz == '?') {
			eprintf("Usage: cV[1248] [addr] @ addr2\n"
				"Compare n bytes from one address to current one and return in $? 0 or 1\n");
		}
		sz -= '0';
		if (sz > 0) {
			ut64 at = rz_num_math(core->num, input + 2);
			ut8 buf[8] = { 0 };
			rz_io_read_at(core->io, at, buf, sizeof(buf));
			core->num->value = memcmp(buf, core->block, sz) ? 1 : 0;
		}
		break;
	}
	case 'l': // "cl"
		if (strchr(input, 'f')) {
			rz_cons_flush();
		} else if (input[1] == 0) {
			rz_cons_fill_line();
			// rz_cons_clear_line (0);
		} else if (!strchr(input, '0')) {
			rz_cons_clear00();
		}
		break;
	default:
		rz_core_cmd_help(core, help_msg_c);
	}
	if (val != UT64_MAX) {
		core->num->value = val;
	}
	return 0;
}
