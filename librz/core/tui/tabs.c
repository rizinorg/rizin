// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_core.h>
#include <rz_cons.h>
#include <rz_windows.h>
#include "../core_private.h"
#include "modes.h"

static void prompt_read(const char *p, char *buf, int buflen) {
	if (!buf || buflen < 1) {
		return;
	}
	*buf = 0;
	rz_line_set_prompt(rz_cons_singleton()->line, p);
	rz_core_visual_showcursor(NULL, true);
	rz_cons_fgets(buf, buflen, 0, NULL);
	rz_core_visual_showcursor(NULL, false);
}

RZ_IPI void rz_core_visual_tab_free(RzCoreVisualTab *tab) {
	free(tab);
}

RZ_IPI int rz_core_visual_tab_count(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	return visual->tabs ? rz_list_length(visual->tabs) : 0;
}

RZ_IPI RZ_OWN char *rz_core_visual_tab_string(RzCore *core, const char *kolor) {
	RzCoreVisual *visual = core->visual;
	int hex_cols = rz_config_get_i(core->config, "hex.cols");
	int scr_color = rz_config_get_i(core->config, "scr.color");
	if (hex_cols < 4) {
		return rz_str_dup("");
	}
	int i = 0;
	char *str = NULL;
	int tabs = rz_list_length(visual->tabs);
	if (scr_color > 0) {
		// TODO: use theme
		if (tabs > 0) {
			str = rz_str_appendf(str, "%s-+__", kolor);
		}
		for (i = 0; i < tabs; i++) {
			RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, i);
			const char *name = (tab && *tab->name) ? tab->name : NULL;
			if (i == visual->tab) {
				str = rz_str_appendf(str, Color_WHITE "_/ %s \\_%s", name ? name : "t=", kolor);
			} else {
				str = rz_str_appendf(str, "_%s(%d)_", name ? name : "", i + 1);
			}
		}
	} else {
		if (tabs > 0) {
			str = rz_str_append(str, "___");
		}
		for (i = 0; i < tabs; i++) {
			const char *name = NULL;
			RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, i);
			if (tab && *tab->name) {
				name = tab->name;
			}
			if (i == visual->tab) {
				str = rz_str_appendf(str, "_/ %d:%s \\_", i + 1, name ? name : "'=");
			} else {
				str = rz_str_appendf(str, "_(t%d%s%s)__", i + 1, name ? ":" : "", name ? name : "");
			}
		}
	}
	if (str) {
		int n = 79 - rz_str_ansi_len(str);
		if (n > 0) {
			char *pad = rz_str_pad('_', n);
			str = rz_str_append(str, pad);
			free(pad);
		}
		str = rz_str_append(str, "\n" Color_RESET);
	}
	return str;
}

RZ_IPI void rz_core_visual_tabset(RzCore *core, RzCoreVisualTab *tab) {
	rz_return_if_fail(core && tab);

	rz_core_seek(core, tab->offset, true);
	RzCoreVisual *visual = core->visual;
	visual->printidx = tab->printidx;
	core->print->cur_enabled = tab->cur_enabled;
	core->print->cur = tab->cur;
	core->print->ocur = tab->ocur;
	visual->disMode = tab->disMode;
	visual->hexMode = tab->hexMode;
	visual->printMode = tab->printMode;
	visual->current3format = tab->current3format;
	visual->current4format = tab->current4format;
	visual->current5format = tab->current5format;
	rz_core_visual_applyDisMode(core, visual->disMode);
	rz_core_visual_applyHexMode(core, visual->hexMode);
	rz_config_set_i(core->config, "asm.offset", tab->asm_offset);
	rz_config_set_i(core->config, "asm.instr", tab->asm_instr);
	rz_config_set_i(core->config, "asm.bytes", tab->asm_bytes);
	rz_config_set_i(core->config, "asm.indent", tab->asm_indent);
	rz_config_set_i(core->config, "asm.cmt.col", tab->asm_cmt_col);
	rz_config_set_i(core->config, "hex.cols", tab->cols);
	rz_config_set_i(core->config, "scr.dumpcols", tab->dumpCols);
	printfmtSingle[0] = printHexFormats[RZ_ABS(visual->hexMode) % PRINT_HEX_FORMATS];
	printfmtSingle[2] = print3Formats[RZ_ABS(visual->current3format) % PRINT_3_FORMATS];
	printfmtSingle[3] = print4Formats[RZ_ABS(visual->current4format) % PRINT_4_FORMATS];
	printfmtSingle[4] = print5Formats[RZ_ABS(visual->current5format) % PRINT_5_FORMATS];
}

RZ_IPI void rz_core_visual_tabget(RzCore *core, RzCoreVisualTab *tab) {
	rz_return_if_fail(core && tab);

	tab->offset = core->offset;
	RzCoreVisual *visual = core->visual;
	tab->printidx = visual->printidx;
	tab->asm_offset = rz_config_get_i(core->config, "asm.offset");
	tab->asm_instr = rz_config_get_i(core->config, "asm.instr");
	tab->asm_indent = rz_config_get_i(core->config, "asm.indent");
	tab->asm_bytes = rz_config_get_i(core->config, "asm.bytes");
	tab->asm_cmt_col = rz_config_get_i(core->config, "asm.cmt.col");
	tab->cur_enabled = core->print->cur_enabled;
	tab->cur = core->print->cur;
	tab->ocur = core->print->ocur;
	tab->cols = rz_config_get_i(core->config, "hex.cols");
	tab->dumpCols = rz_config_get_i(core->config, "scr.dumpcols");
	tab->disMode = visual->disMode;
	tab->hexMode = visual->hexMode;
	tab->printMode = visual->printMode;
	tab->current3format = visual->current3format;
	tab->current4format = visual->current4format;
	tab->current5format = visual->current5format;
	// tab->cols = core->print->cols;
}

RZ_IPI RZ_OWN RzCoreVisualTab *rz_core_visual_tab_new(RzCore *core) {
	RzCoreVisualTab *tab = RZ_NEW0(RzCoreVisualTab);
	if (tab) {
		rz_core_visual_tabget(core, tab);
	}
	return tab;
}

RZ_IPI void rz_core_visual_tab_update(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs) {
		return;
	}
	RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
	if (tab) {
		rz_core_visual_tabget(core, tab);
	}
}

RZ_IPI RZ_OWN RzCoreVisualTab *rz_core_visual_newtab(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs) {
		visual->tabs = rz_list_newf((RzListFree)rz_core_visual_tab_free);
		if (!visual->tabs) {
			return NULL;
		}
		visual->tab = -1;
		rz_core_visual_newtab(core);
	}
	visual->tab++;
	RzCoreVisualTab *tab = rz_core_visual_tab_new(core);
	if (tab) {
		rz_list_append(visual->tabs, tab);
		rz_core_visual_tabset(core, tab);
	}
	return tab;
}

RZ_IPI void rz_core_visual_nthtab(RzCore *core, int n) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs || n < 0 || n >= rz_list_length(visual->tabs)) {
		return;
	}
	visual->tab = n;
	RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
	if (tab) {
		rz_core_visual_tabset(core, tab);
	}
}

RZ_IPI void rz_core_visual_tabname_prompt(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs) {
		return;
	}
	char name[32] = { 0 };
	prompt_read("tab name: ", name, sizeof(name));
	RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
	if (tab) {
		strcpy(tab->name, name);
	}
}

RZ_IPI void rz_core_visual_nexttab(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs) {
		return;
	}
	if (visual->tab >= rz_list_length(visual->tabs) - 1) {
		visual->tab = -1;
	}
	visual->tab++;
	RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
	if (tab) {
		rz_core_visual_tabset(core, tab);
	}
}

RZ_IPI void rz_core_visual_prevtab(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs) {
		return;
	}
	if (visual->tab < 1) {
		visual->tab = rz_list_length(visual->tabs) - 1;
	} else {
		visual->tab--;
	}
	RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
	if (tab) {
		rz_core_visual_tabset(core, tab);
	}
}

RZ_IPI void rz_core_visual_closetab(RzCore *core) {
	RzCoreVisual *visual = core->visual;
	if (!visual->tabs) {
		return;
	}
	RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
	if (tab) {
		rz_list_delete_data(visual->tabs, tab);
		const int tabsCount = rz_list_length(visual->tabs);
		if (tabsCount > 0) {
			if (visual->tab > 0) {
				visual->tab--;
			}
			RzCoreVisualTab *tab = rz_list_get_n(visual->tabs, visual->tab);
			if (tab) {
				rz_core_visual_tabset(core, tab);
			}
		} else {
			rz_list_free(visual->tabs);
			visual->tabs = NULL;
		}
	}
}
