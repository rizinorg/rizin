// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>
#include <cmd_descs.h>

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
	RzLine *line = core->cons->line;

	if (!(node = rz_config_node_get(core->config, name))) {
		return;
	}
	if (rz_config_node_is_bool(node)) {
		rz_config_set_i(core->config, name, node->i_value ? 0 : 1);
	} else {
		// XXX: must use config_set () to run callbacks!
		if (editor) {
			char *buf = rz_core_editor(core, NULL, node->value);
			char *tmp = rz_str_dup(buf);
			free(node->value);
			node->value = tmp;
			free(buf);
		} else {
			// FGETS AND SO
			rz_cons_printf("New value (old=%s): \n", node->value);
			rz_cons_show_cursor(true);
			rz_cons_flush();
			rz_cons_set_raw(0);
			rz_line_set_prompt(line, ":> ");
			rz_cons_fgets(buf, sizeof(buf), 0, 0);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			rz_config_set(core->config, name, buf);
			// node->value = rz_str_dup (node->value, buf);
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
			rz_strbuf_appendf(sb, "%s%s", rz_list_has_prev(iter) ? ", " : "", item);
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

RZ_IPI void rz_core_visual_config(RzCore *core) {
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
			rz_list_rizin_vars_handler(core, 0, NULL);
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
				       " $     - same as %%$ - show values of vars\n"
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
				char *cmd = rz_cons_prompt(":> ", NULL);
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
