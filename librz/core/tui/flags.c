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

enum {
	SORT_NONE,
	SORT_NAME,
	SORT_OFFSET
};

static int flag_name_sort(const void *a, const void *b, void *user) {
	const RzFlagItem *fa = (const RzFlagItem *)a;
	const RzFlagItem *fb = (const RzFlagItem *)b;
	return strcmp(rz_flag_item_get_name(fa), rz_flag_item_get_name(fb));
}

static int flag_offset_sort(const void *a, const void *b, void *user) {
	const RzFlagItem *fa = (const RzFlagItem *)a;
	const RzFlagItem *fb = (const RzFlagItem *)b;
	if (rz_flag_item_get_offset(fa) < rz_flag_item_get_offset(fb)) {
		return -1;
	}
	if (rz_flag_item_get_offset(fa) > rz_flag_item_get_offset(fb)) {
		return 1;
	}
	return 0;
}

static void sort_flags(RzList /*<RzFlagItem *>*/ *l, int sort) {
	switch (sort) {
	case SORT_NAME:
		rz_list_sort(l, flag_name_sort, NULL);
		break;
	case SORT_OFFSET:
		rz_list_sort(l, flag_offset_sort, NULL);
		break;
	case SORT_NONE:
	default:
		break;
	}
}

RZ_IPI int rz_core_visual_trackflags(RzCore *core) {
	const char *fs = NULL, *fs2 = NULL;
	int hit, i, j, ch;
	int _option = 0;
	int option = 0;
	char cmd[1024];
	int format = 0;
	int delta = 7;
	int menu = 0;
	int sort = SORT_NONE;
	RzCoreVisual *visual = core->visual;
	RzLine *rzline = core->cons->line;

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
					fs2 = rz_flag_item_get_name(fi);
					hit = 1;
				}
				if ((i >= option - delta) && ((i < option + delta) || ((option < delta) && (i < (delta << 1))))) {
					bool cur = option == i;
					if (cur && hasColor) {
						rz_cons_printf(Color_INVERT);
					}
					rz_cons_printf(" %c  %03d 0x%08" PFMT64x " %4" PFMT64d " %s\n",
						cur ? '>' : ' ', i, rz_flag_item_get_offset(fi), rz_flag_item_get_size(fi), rz_flag_item_get_name(fi));
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
				// int rows = 20;
				rows -= 12;
				rz_cons_printf("\n Selected: %s\n\n", fs2);
				// Honor MAX_FORMATS here
				switch (format) {
				case 0:
					snprintf(cmd, sizeof(cmd), "px %d @ %s!64", rows * 16, fs2);
					visual->printidx = 0;
					break;
				case 1:
					snprintf(cmd, sizeof(cmd), "pd %d @ %s!64", rows, fs2);
					visual->printidx = 1;
					break;
				case 2:
					snprintf(cmd, sizeof(cmd), "ps @ %s!64", fs2);
					visual->printidx = 5;
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
				rz_line_set_prompt(rzline, "add flagspace: ");
				if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) > 0) {
					rz_flag_space_set(core->flags, cmd);
					rz_cons_set_raw(1);
					rz_cons_show_cursor(false);
				}
				break;
			case 1: // new flag
				rz_cons_show_cursor(true);
				rz_line_set_prompt(rzline, "add flag: ");
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
				rz_core_cmdf(core, "f %s @ %s+1", fs2, fs2);
			} else {
				rz_core_block_size(core, core->blocksize + 1);
			}
			break;
		case '-':
			if (menu == 1) {
				rz_core_cmdf(core, "f %s @ %s-1", fs2, fs2);
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
				rz_line_set_prompt(rzline, ":> ");
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
				rz_line_set_prompt(rzline, ":> ");
				if (rz_cons_fgets(line, sizeof(line), 0, NULL) < 0) {
					cmd[0] = '\0';
				}
				ut64 addr = rz_num_math(core->num, line);
				rz_core_analysis_function_add(core, fs2, addr, true);
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
				ut64 addr = rz_num_math(core->num, fs2);
				rz_core_seek_and_save(core, addr, true);
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
			rz_line_set_prompt(rzline, ":> ");
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
			// cons_gotoxy(0,0);
			rz_cons_clear();
			continue;
		}
	}
	return true;
}
