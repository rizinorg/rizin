// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>

#include <rz_core.h>
#include <rz_util.h>

#include "../core_private.h"
#include <rz_asm.h>
#include <rz_util/rz_print.h>
#include <rz_util/rz_strbuf.h>

RZ_IPI bool rz_core_visual_hud(RzCore *core) {
	const char *c = rz_config_get(core->config, "hud.path");
	char *system_hud_dir = rz_path_system(RZ_HUD);
	char *f = rz_file_path_join(system_hud_dir, "main");
	free(system_hud_dir);
	int use_color = core->print->flags & RZ_PRINT_FLAGS_COLOR;
	char *homehud = rz_path_home_prefix(RZ_HUD);
	char *res = NULL;
	char *p = 0;
	rz_cons_singleton()->context->color_mode = use_color;

	rz_core_visual_showcursor(core, true);
	if (c && *c && rz_file_exists(c)) {
		res = rz_cons_hud_file(c);
	}
	if (!res && homehud) {
		res = rz_cons_hud_file(homehud);
	}
	if (!res && rz_file_exists(f)) {
		res = rz_cons_hud_file(f);
	}
	if (!res) {
		rz_cons_message("Cannot find hud file");
		free(homehud);
		free(f);
		return false;
	}

	rz_cons_clear();
	if (res) {
		p = strchr(res, ';');
		rz_cons_println(res);
		rz_cons_flush();
		if (p) {
			rz_core_cmd0(core, p + 1);
		}
		free(res);
	}
	rz_core_visual_showcursor(core, false);
	rz_cons_flush();
	free(homehud);
	free(f);
	return true;
}

RZ_IPI bool rz_core_visual_hudclasses(RzCore *core) {
	void **iter;
	RzListIter *iter2;
	RzBinClass *c;
	RzBinClassField *f;
	RzBinSymbol *m;
	ut64 addr;
	char *res;
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	list->free = free;
	RzBinObject *bin_obj = rz_bin_cur_object(core->bin);
	const RzPVector *classes = rz_bin_object_get_classes(bin_obj);
	if (!classes) {
		return false;
	}
	rz_pvector_foreach (classes, iter) {
		c = *iter;
		rz_list_foreach (c->fields, iter2, f) {
			rz_list_append(list, rz_str_newf("0x%08" PFMT64x "  %s %s", f->vaddr, c->name, f->name));
		}
		rz_list_foreach (c->methods, iter2, m) {
			const char *name = m->dname ? m->dname : m->name;
			rz_list_append(list, rz_str_newf("0x%08" PFMT64x "  %s %s", m->vaddr, c->name, name));
		}
	}
	res = rz_cons_hud(list, NULL);
	if (res) {
		char *p = strchr(res, ' ');
		if (p) {
			*p = 0;
		}
		addr = rz_num_get(NULL, res);
		rz_core_seek(core, addr, true);
		free(res);
	}
	rz_list_free(list);
	return res != NULL;
}

static bool hudstuff_append(RzFlagItem *fi, void *user) {
	RzList *list = (RzList *)user;
	char *s = rz_str_newf("0x%08" PFMT64x "  %s", rz_flag_item_get_offset(fi), rz_flag_item_get_name(fi));
	if (s) {
		rz_list_append(list, s);
	}
	return true;
}

RZ_IPI bool rz_core_visual_hudstuff(RzCore *core) {
	ut64 addr;
	char *res;
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	list->free = free;
	rz_flag_foreach(core->flags, hudstuff_append, list);
	RzIntervalTreeIter it;
	RzAnalysisMetaItem *mi;
	rz_interval_tree_foreach (&core->analysis->meta, it, mi) {
		if (mi->type == RZ_META_TYPE_COMMENT) {
			char *s = rz_str_newf("0x%08" PFMT64x " %s", rz_interval_tree_iter_get(&it)->start, mi->str);
			if (s) {
				rz_list_push(list, s);
			}
		}
	}
	res = rz_cons_hud(list, NULL);
	if (res) {
		char *p = strchr(res, ' ');
		if (p) {
			*p = 0;
		}
		addr = rz_num_get(NULL, res);
		rz_core_seek(core, addr, true);
		free(res);
	}
	rz_list_free(list);
	return res != NULL;
}

RZ_IPI bool rz_core_visual_config_hud(RzCore *core) {
	RzListIter *iter;
	RzConfigNode *bt;
	RzList *list = rz_list_new();
	if (!list) {
		return false;
	}
	list->free = free;
	rz_list_foreach (core->config->nodes, iter, bt) {
		rz_list_append(list, rz_str_newf("%s %s", bt->name, bt->value));
	}
	char *res = rz_cons_hud(list, NULL);
	if (res) {
		const char *oldvalue = NULL;
		char cmd[512];
		char *p = strchr(res, ' ');
		if (p) {
			*p = 0;
		}
		oldvalue = rz_config_get(core->config, res);
		rz_cons_show_cursor(true);
		rz_cons_set_raw(false);
		cmd[0] = '\0';
		eprintf("Set new value for %s (old=%s)\n", res, oldvalue);
		rz_line_set_prompt(core->cons->line, ":> ");
		if (rz_cons_fgets(cmd, sizeof(cmd), 0, NULL) < 0) {
			cmd[0] = '\0';
		}
		rz_config_set(core->config, res, cmd);
		rz_cons_set_raw(true);
		rz_cons_show_cursor(false);
	}
	rz_list_free(list);
	return true;
}
