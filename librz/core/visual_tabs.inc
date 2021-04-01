// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

static void rz_core_visual_tab_free(RzCoreVisualTab *tab) {
	free(tab);
}

static int __core_visual_tab_count(RzCore *core) {
	return core->visual.tabs ? rz_list_length(core->visual.tabs) : 0;
}

static char *__core_visual_tab_string(RzCore *core, const char *kolor) {
	int hex_cols = rz_config_get_i(core->config, "hex.cols");
	int scr_color = rz_config_get_i(core->config, "scr.color");
	if (hex_cols < 4) {
		return strdup("");
	}
	int i = 0;
	char *str = NULL;
	int tabs = rz_list_length(core->visual.tabs);
	if (scr_color > 0) {
		// TODO: use theme
		if (tabs > 0) {
			str = rz_str_appendf(str, "%s-+__", kolor);
		}
		for (i = 0; i < tabs; i++) {
			RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, i);
			const char *name = (tab && *tab->name) ? tab->name : NULL;
			if (i == core->visual.tab) {
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
			RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, i);
			if (tab && *tab->name) {
				name = tab->name;
			}
			if (i == core->visual.tab) {
				str = rz_str_appendf(str, "_/ %d:%s \\_", i + 1, name ? name : "'=");
			} else {
				str = rz_str_appendf(str, "_(t%d%s%s)__", i + 1, name ? ":" : "", name ? name : "");
			}
		}
	}
	if (str) {
		int n = 79 - rz_str_ansi_len(str);
		if (n > 0) {
			str = rz_str_append(str, rz_str_pad('_', n));
		}
		str = rz_str_append(str, "\n" Color_RESET);
	}
	return str;
}

static void visual_tabset(RzCore *core, RzCoreVisualTab *tab) {
	rz_return_if_fail(core && tab);

	rz_core_seek(core, tab->offset, true);
	core->printidx = tab->printidx;
	core->print->cur_enabled = tab->cur_enabled;
	core->print->cur = tab->cur;
	core->print->ocur = tab->ocur;
	disMode = tab->disMode;
	hexMode = tab->hexMode;
	printMode = tab->printMode;
	current3format = tab->current3format;
	current4format = tab->current4format;
	current5format = tab->current5format;
	rz_core_visual_applyDisMode(core, disMode);
	rz_core_visual_applyHexMode(core, hexMode);
	rz_config_set_i(core->config, "asm.offset", tab->asm_offset);
	rz_config_set_i(core->config, "asm.instr", tab->asm_instr);
	rz_config_set_i(core->config, "asm.bytes", tab->asm_bytes);
	rz_config_set_i(core->config, "asm.indent", tab->asm_indent);
	rz_config_set_i(core->config, "asm.cmt.col", tab->asm_cmt_col);
	rz_config_set_i(core->config, "hex.cols", tab->cols);
	rz_config_set_i(core->config, "scr.dumpcols", tab->dumpCols);
	printfmtSingle[0] = printHexFormats[RZ_ABS(hexMode) % PRINT_HEX_FORMATS];
	printfmtSingle[2] = print3Formats[RZ_ABS(current3format) % PRINT_3_FORMATS];
	printfmtSingle[3] = print4Formats[RZ_ABS(current4format) % PRINT_4_FORMATS];
	printfmtSingle[4] = print5Formats[RZ_ABS(current5format) % PRINT_5_FORMATS];
}

static void visual_tabget(RzCore *core, RzCoreVisualTab *tab) {
	rz_return_if_fail(core && tab);

	tab->offset = core->offset;
	tab->printidx = core->printidx;
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
	tab->disMode = disMode;
	tab->hexMode = hexMode;
	tab->printMode = printMode;
	tab->current3format = current3format;
	tab->current4format = current4format;
	tab->current5format = current5format;
	// tab->cols = core->print->cols;
}

static RzCoreVisualTab *rz_core_visual_tab_new(RzCore *core) {
	RzCoreVisualTab *tab = RZ_NEW0(RzCoreVisualTab);
	if (tab) {
		visual_tabget(core, tab);
	}
	return tab;
}

static void rz_core_visual_tab_update(RzCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabget(core, tab);
	}
}

static RzCoreVisualTab *visual_newtab(RzCore *core) {
	if (!core->visual.tabs) {
		core->visual.tabs = rz_list_newf((RzListFree)rz_core_visual_tab_free);
		if (!core->visual.tabs) {
			return NULL;
		}
		core->visual.tab = -1;
		visual_newtab(core);
	}
	core->visual.tab++;
	RzCoreVisualTab *tab = rz_core_visual_tab_new(core);
	if (tab) {
		rz_list_append(core->visual.tabs, tab);
		visual_tabset(core, tab);
	}
	return tab;
}

static void visual_nthtab(RzCore *core, int n) {
	if (!core->visual.tabs || n < 0 || n >= rz_list_length(core->visual.tabs)) {
		return;
	}
	core->visual.tab = n;
	RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabset(core, tab);
	}
}

static void visual_tabname(RzCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	char name[32] = { 0 };
	prompt_read("tab name: ", name, sizeof(name));
	RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
	if (tab) {
		strcpy(tab->name, name);
	}
}

static void visual_nexttab(RzCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	if (core->visual.tab >= rz_list_length(core->visual.tabs) - 1) {
		core->visual.tab = -1;
	}
	core->visual.tab++;
	RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabset(core, tab);
	}
}

static void visual_prevtab(RzCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	if (core->visual.tab < 1) {
		core->visual.tab = rz_list_length(core->visual.tabs) - 1;
	} else {
		core->visual.tab--;
	}
	RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
	if (tab) {
		visual_tabset(core, tab);
	}
}

static void visual_closetab(RzCore *core) {
	if (!core->visual.tabs) {
		return;
	}
	RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
	if (tab) {
		rz_list_delete_data(core->visual.tabs, tab);
		const int tabsCount = rz_list_length(core->visual.tabs);
		if (tabsCount > 0) {
			if (core->visual.tab > 0) {
				core->visual.tab--;
			}
			RzCoreVisualTab *tab = rz_list_get_n(core->visual.tabs, core->visual.tab);
			if (tab) {
				visual_tabset(core, tab);
			}
		} else {
			rz_list_free(core->visual.tabs);
			core->visual.tabs = NULL;
		}
	}
}
