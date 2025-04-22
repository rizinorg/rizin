// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

#define MAX_FORMAT 3

RZ_IPI int rz_core_visual_comments(RzCore *core) {
	RzCoreVisual *visual = core->visual;
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
				p = rz_str_dup(str);
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
			visual->printidx = 0;
			break;
		case 1:
			sprintf(cmd, "pd 12 @ 0x%" PFMT64x ":64", from);
			visual->printidx = 1;
			break;
		case 2:
			sprintf(cmd, "ps @ 0x%" PFMT64x ":64", from);
			visual->printidx = 5;
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
			// TODO
			break;
		case 'e':
			// TODO
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
