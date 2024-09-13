// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

static char *print_rop(void *_core, void *_item, bool selected) {
	char *line = _item;
	// TODO: trim if too long
	return rz_str_newf("%c %s\n", selected ? '>' : ' ', line);
}

RZ_IPI int rz_core_visual_view_rop(RzCore *core) {
	RzListIter *iter;
	const int rows = 7;
	int cur = 0;
	RzLine *line = core->cons->line;

	rz_line_set_prompt(line, "rop regexp: ");
	const char *linestr = rz_line_readline(line);
	if (RZ_STR_ISEMPTY(linestr)) {
		return false;
	}

	int scr_h, scr_w = rz_cons_get_size(&scr_h);

	// maybe store in RzCore, so we can save it in project and use it outside visual

	eprintf("Searching ROP gadgets...\n");
	char *ropstr = rz_core_cmd_strf(core, "\"/Rq %s\" @e:scr.color=0", linestr);
	RzList *rops = rz_str_split_list(ropstr, "\n", 0);
	int delta = 0;
	bool show_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	bool forceaddr = false;
	ut64 addr = UT64_MAX;
	char *cursearch = rz_str_dup(linestr);
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
		char *curline = rz_str_dup(rz_str_trim_head_ro(rz_str_widget_list(core, rops, rows, cur, print_rop)));
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
				rz_line_set_prompt(line, ":> ");
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
			rz_line_set_prompt(line, "offset: ");
			const char *linestr = rz_line_readline(line);
			if (RZ_STR_ISNOTEMPTY(linestr)) {
				ut64 off = rz_num_math(core->num, linestr);
				rz_core_seek(core, off, true);
				addr = off;
				forceaddr = true;
				delta = 0;
			}
		} break;
		case 'r': {
			rz_line_set_prompt(line, "rop regexp: ");
			const char *linestr = rz_line_readline(line);
			if (RZ_STR_ISNOTEMPTY(linestr)) {
				free(cursearch);
				delta = 0;
				addr = UT64_MAX;
				cur = 0;
				cursearch = rz_str_dup(linestr);
				free(ropstr);
				ropstr = rz_core_cmd_strf(core, "\"/Rl %s\" @e:scr.color=0", linestr);
				rz_list_free(rops);
				rops = rz_str_split_list(ropstr, "\n", 0);
			}
		} break;
		case '/':
			rz_core_prompt_highlight(core);
			break;
		case 'i': {
			rz_line_set_prompt(line, "insert value: ");
			const char *linestr = rz_line_readline(line);
			if (RZ_STR_ISNOTEMPTY(linestr)) {
				ut64 n = rz_num_math(core->num, linestr);
				rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x, n));
			}
		} break;
		case ';': {
			rz_line_set_prompt(line, "comment: ");
			const char *linestr = rz_line_readline(line);
			if (RZ_STR_ISNOTEMPTY(linestr)) {
				rz_meta_set_string(core->analysis, RZ_META_TYPE_COMMENT, addr + delta, linestr);
			}
		} break;
		case '.':
		case '\n':
		case '\r':
			if (curline && *curline) {
				const ut64 limit = addr + delta > 1 ? addr + delta : 1024;
				RzStrBuf *line = rz_strbuf_new(NULL);
				if (!rz_core_disasm_until_ret(core, core->offset, limit, RZ_OUTPUT_MODE_QUIET, true, line)) {
					rz_strbuf_free(line);
					break;
				}
				if (show_color) {
					// XXX parsing fails to read this ansi-offset
					// const char *offsetColor = rz_cons_singleton ()->context->pal.offset; // TODO etooslow. must cache
					// rz_list_push (core->ropchain, rz_str_newf ("%s0x%08"PFMT64x""Color_RESET"  %s", offsetColor, addr + delta, line));
					rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x "  %s", addr + delta, rz_strbuf_get(line)));
				} else {
					rz_list_push(core->ropchain, rz_str_newf("0x%08" PFMT64x "  %s", addr + delta, rz_strbuf_get(line)));
				}
				rz_strbuf_free(line);
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
