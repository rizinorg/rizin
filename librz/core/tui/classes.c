// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

// TODO: skip N first elements
// TODO: show only N elements of the list
// TODO: wrap index when out of boundaries
// TODO: Add support to show class fields too
// Segfaults - stack overflow, because of recursion
static void *show_class(RzCore *core, int mode, int *idx, RzBinClass *_c, const char *grep, const RzPVector /*<RzBinClass *>*/ *vec) {
	bool show_color = rz_config_get_i(core->config, "scr.color");
	RzListIter *iter;
	RzBinClass *c, *cur = NULL;
	RzBinSymbol *m, *mur = NULL;
	RzBinClassField *f, *fur = NULL;
	int i = 0;
	int skip = *idx - 10;
	bool found = false;

	switch (mode) {
	case 'c':
		rz_cons_printf("[hjkl_/Cfm]> classes:\n\n");
		void **vec_it;
		rz_pvector_foreach (vec, vec_it) {
			c = *vec_it;
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

RZ_IPI int rz_core_visual_classes(RzCore *core) {
	int ch, index = 0;
	char cmd[1024];
	int mode = 'c';
	RzBinClass *cur = NULL;
	RzBinSymbol *mur = NULL;
	RzBinClassField *fur = NULL;
	void *ptr;
	int oldcur = 0;
	char *grep = NULL;
	bool grepmode = false;
	RzLine *line = core->cons->line;
	RzBinObject *bin_obj = rz_bin_cur_object(core->bin);
	const RzPVector *vec = rz_bin_object_get_classes(bin_obj);
	if (!vec || rz_pvector_empty(vec)) {
		rz_cons_message("No Classes");
		return false;
	}
	for (;;) {
		int cols;
		rz_cons_clear00();
		if (grepmode) {
			rz_cons_printf("Grep: %s\n", grep ? grep : "");
		}
		ptr = show_class(core, mode, &index, cur, grep, vec);
		switch (mode) {
		case 'f':
			fur = (RzBinClassField *)ptr;
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
			index = rz_pvector_len(vec) - 1;
			break;
		case 'i': {
			char *num = rz_cons_prompt("Index:", NULL);
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
			rz_line_set_prompt(line, ":> ");
			if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
				cmd[0] = '\0';
			}
			// line[strlen(line)-1]='\0';
			rz_core_cmd(core, cmd, 1);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (cmd[0]) {
				rz_cons_any_key(NULL);
			}
			// cons_gotoxy(0,0);
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
		rz_vector_foreach (bases, base) {
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
		rz_vector_foreach (vtables, vtable) {
			rz_cons_printf("  %2s vtable 0x%" PFMT64x " @ +0x%" PFMT64x " size:+0x%" PFMT64x "\n", vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		rz_vector_free(vtables);
	}

	rz_cons_print("\n");

	if (methods) {
		RzAnalysisMethod *meth;
		rz_vector_foreach (methods, meth) {
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
RZ_IPI int rz_core_visual_analysis_classes(RzCore *core) {
	int ch, index = 0;
	char command[1024];
	SdbList *list = rz_analysis_class_get_all(core->analysis, true);
	int oldcur = 0;
	char mode = ' ';
	const char *class_name = "";
	RzLine *line = core->cons->line;

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
			rz_line_set_prompt(line, ":> ");
			if (rz_cons_fgets(command, sizeof(command), 0, NULL) < 0) {
				command[0] = '\0';
			}
			// line[strlen(line)-1]='\0';
			rz_core_cmd(core, command, 1);
			rz_cons_set_raw(1);
			rz_cons_show_cursor(false);
			if (command[0]) {
				rz_cons_any_key(NULL);
			}
			// cons_gotoxy(0,0);
			rz_cons_clear();
			break;
		}
	}
cleanup:
	ls_free(list);
	return true;
}
