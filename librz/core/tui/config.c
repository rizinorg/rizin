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

typedef struct config_visual_ctx {
	const char *fs;
	const char *fs2;
	const char *desc;
	int i;
	int j;
	int hit;
	int show;
	int option;
	int _option;
	char old[1024];
	int delta;
	int menu;
	RzCore *core;
} ConfigVisualCtx;

static void config_visual_hit_i(RzCore *core, const char *name, int delta) {
	const ut32 flags = rz_config_get_flags(core->config, name);
	if (!(RZ_CONFIG_VAR_IS_TYPE(flags, RZ_CONFIG_VAR_TYPE_INT))) {
		return;
	}

	ut64 value = rz_config_get_i(core->config, name);
	value += delta;
	rz_config_set_i(core->config, name, value);
}

/* Visually activate the config variable */
static void config_visual_hit(RzCore *core, const char *name, int editor) {
	char buf[1024];
	RzLine *line = core->cons->line;
	const ut32 flags = rz_config_get_flags(core->config, name);
	if (!flags) {
		return;
	}

	if ((RZ_CONFIG_VAR_IS_TYPE(flags, RZ_CONFIG_VAR_TYPE_BOOL))) {
		rz_config_toggle_bool(core->config, name);
		return;
	}

	char *value = rz_config_get_as_string(core->config, name);
	if (editor) {
		char *buf = rz_core_editor(core, NULL, value);
		rz_config_set_any(core->config, name, buf);
		free(buf);
		free(value);
		return;
	}

	// FGETS AND SO
	rz_cons_printf("New value (old=%s): \n", value);
	rz_cons_show_cursor(true);
	rz_cons_flush();
	rz_cons_set_raw(0);
	rz_line_set_prompt(line, ":> ");
	rz_cons_fgets(buf, sizeof(buf), 0, 0);
	rz_cons_set_raw(1);
	rz_cons_show_cursor(false);
	rz_config_set_any(core->config, name, buf);
	free(value);
}

static void show_config_options(RzCore *core, const char *name) {
	const RzList *options = rz_config_get_options(core->config, name);
	if (rz_list_empty(options)) {
		return;
	}

	int h, w = rz_cons_get_size(&h);
	const char *item;
	const RzListIter *iter;
	RzStrBuf *sb = rz_strbuf_new(" Options: ");
	rz_list_foreach (options, iter, item) {
		rz_strbuf_appendf(sb, "%s%s", rz_list_val(iter) ? ", " : "", item);
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

static bool core_visual_config_flag_space(const RzConfigEntry *entry, void *user) {
	ConfigVisualCtx *ctx = (ConfigVisualCtx *)user;
	const char *name = rz_config_entry_get_name(entry);

	if (ctx->option == ctx->i) {
		ctx->fs = name;
	}
	if (!ctx->old[0]) {
		rz_str_ccpy(ctx->old, name, '.');
		ctx->show = 1;
	} else if (rz_str_ccmp(ctx->old, name, '.')) {
		rz_str_ccpy(ctx->old, name, '.');
		ctx->show = 1;
	} else {
		ctx->show = 0;
	}
	if (ctx->show) {
		if (ctx->option == ctx->i) {
			ctx->hit = 1;
		}
		if ((ctx->i >= ctx->option - ctx->delta) && ((ctx->i < ctx->option + ctx->delta) || ((ctx->option < ctx->delta) && (ctx->i < (ctx->delta << 1))))) {
			rz_cons_printf(" %c  %s\n", (ctx->option == ctx->i) ? '>' : ' ', ctx->old);
			ctx->j++;
		}
		ctx->i++;
	}
	return true;
}

static bool core_visual_config_flag_selection(const RzConfigEntry *entry, void *user) {
	ConfigVisualCtx *ctx = (ConfigVisualCtx *)user;
	const char *name = rz_config_entry_get_name(entry);
	const char *desc = rz_config_entry_get_desc(entry);

	if (!rz_str_ccmp(name, ctx->fs, '.')) {
		if (ctx->option == ctx->i) {
			ctx->fs2 = name;
			ctx->desc = desc;
			ctx->hit = 1;
		}
		if ((ctx->i >= ctx->option - ctx->delta) && ((ctx->i < ctx->option + ctx->delta) || ((ctx->option < ctx->delta) && (ctx->i < (ctx->delta << 1))))) {
			// TODO: Better align
			char *value = rz_config_get_as_string(ctx->core->config, name);
			rz_cons_printf(" %c  %s = %s\n", (ctx->option == ctx->i) ? '>' : ' ', name, value);
			free(value);
			ctx->j++;
		}
		ctx->i++;
	}
	return true;
}

RZ_IPI void rz_core_visual_config(RzCore *core) {
	int ch = 0;
	ConfigVisualCtx ctx = { 0 };
	ctx._option = 0;
	ctx.delta = 9;
	ctx.menu = 0;
	ctx.core = core;

	for (;;) {
		rz_cons_clear00();
		rz_cons_get_size(&ctx.delta);
		ctx.delta /= 4;

		switch (ctx.menu) {
		case 0: // flag space
			rz_cons_printf("[EvalSpace]\n\n");
			ctx.hit = ctx.j = ctx.i = 0;
			rz_config_iterate_over(core->config, core_visual_config_flag_space, &ctx);
			if (!ctx.hit && ctx.j > 0) {
				ctx.option--;
				continue;
			}
			rz_cons_printf("\n Sel: %s \n\n", ctx.fs);
			break;
		case 1: // flag selection
			rz_cons_printf("[EvalSpace < Variables: %s]\n\n", ctx.fs);
			ctx.hit = 0;
			ctx.j = ctx.i = 0;
			rz_config_iterate_over(core->config, core_visual_config_flag_selection, &ctx);

			if (!ctx.hit && ctx.j > 0) {
				ctx.option = ctx.i - 1;
				continue;
			}
			if (ctx.fs2) {
				// TODO: Break long lines.
				rz_cons_printf("\n Selected: %s (%s)\n", ctx.fs2, ctx.desc);
				show_config_options(core, ctx.fs2);
				rz_cons_newline();
			}
		}

		if (ctx.fs && !strncmp(ctx.fs, "asm.", 4)) {
			rz_core_cmd(core, "pd $r", 0);
		}
		rz_cons_visual_flush();
		ch = rz_cons_readchar();
		if (ch == 4 || ch == -1) {
			return;
		}
		ch = rz_cons_arrow_to_hjkl(ch); // get ESC+char, return 'hjkl' char

		switch (ch) {
		case 'j': ctx.option++; break;
		case 'k': ctx.option = (ctx.option <= 0) ? 0 : ctx.option - 1; break;
		case 'J': ctx.option += 4; break;
		case 'K': ctx.option = (ctx.option <= 3) ? 0 : ctx.option - 4; break;
		case 'h':
		case 'b': // back
			ctx.menu = 0;
			ctx.option = ctx._option;
			break;
		case '_':
			rz_core_visual_config_hud(core);
			break;
		case 'Q':
		case 'q':
			if (ctx.menu <= 0) {
				return;
			}
			ctx.menu--;
			ctx.option = ctx._option;
			break;
		case '$':
			rz_list_rizin_vars_handler(core, 0, NULL);
			rz_cons_any_key(NULL);
			break;
		case '*':
		case '+':
			ctx.fs2 ? config_visual_hit_i(core, ctx.fs2, +1) : 0;
			continue;
		case '/':
		case '-':
			ctx.fs2 ? config_visual_hit_i(core, ctx.fs2, -1) : 0;
			continue;
		case 'l':
		case 'E': // edit value
		case 'e': // edit value
		case ' ':
		case '\r':
		case '\n': // never happens
			if (ctx.menu == 1) {
				ctx.fs2 ? config_visual_hit(core, ctx.fs2, (ch == 'E')) : 0;
			} else {
				ctx.menu = 1;
				ctx._option = ctx.option;
				ctx.option = 0;
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
