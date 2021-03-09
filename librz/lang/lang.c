// SPDX-FileCopyrightText: 2009-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lang.h>
#include <rz_util.h>

RZ_LIB_VERSION(rz_lang);

#include "p/pipe.c" // hardcoded
#include "p/vala.c" // hardcoded
#include "p/rust.c" // hardcoded
#include "p/zig.c" // hardcoded
#include "p/spp.c" // hardcoded
#include "p/c.c" // hardcoded
#include "p/lib.c"
#if __UNIX__
#include "p/cpipe.c" // hardcoded
#endif

static RzLang *__lang = NULL;

RZ_API void rz_lang_plugin_free(RzLangPlugin *p) {
	if (p && p->fini) {
		p->fini(__lang);
	}
}

RZ_API RzLang *rz_lang_new(void) {
	RzLang *lang = RZ_NEW0(RzLang);
	if (!lang) {
		return NULL;
	}
	lang->user = NULL;
	lang->langs = rz_list_new();
	if (!lang->langs) {
		rz_lang_free(lang);
		return NULL;
	}
	lang->langs->free = (RzListFree)rz_lang_plugin_free;
	lang->defs = rz_list_new();
	if (!lang->defs) {
		rz_lang_free(lang);
		return NULL;
	}
	lang->defs->free = (RzListFree)rz_lang_def_free;
	lang->cb_printf = (PrintfCallback)printf;
#if __UNIX__
	rz_lang_add(lang, &rz_lang_plugin_c);
	rz_lang_add(lang, &rz_lang_plugin_cpipe);
#endif
	rz_lang_add(lang, &rz_lang_plugin_vala);
	rz_lang_add(lang, &rz_lang_plugin_rust);
	rz_lang_add(lang, &rz_lang_plugin_zig);
	rz_lang_add(lang, &rz_lang_plugin_spp);
	rz_lang_add(lang, &rz_lang_plugin_pipe);
	rz_lang_add(lang, &rz_lang_plugin_lib);

	return lang;
}

RZ_API void rz_lang_free(RzLang *lang) {
	if (lang) {
		__lang = NULL;
		rz_lang_undef(lang, NULL);
		rz_list_free(lang->langs);
		rz_list_free(lang->defs);
		// TODO: remove langs plugins
		free(lang);
	}
}

// XXX: This is only used actually to pass 'core' structure
// TODO: when language bindings are done we will need an api to
// define symbols from C to the language namespace
// XXX: Depcreate!!
RZ_API void rz_lang_set_user_ptr(RzLang *lang, void *user) {
	lang->user = user;
}

RZ_API bool rz_lang_define(RzLang *lang, const char *type, const char *name, void *value) {
	RzLangDef *def;
	RzListIter *iter;
	rz_list_foreach (lang->defs, iter, def) {
		if (!rz_str_casecmp(name, def->name)) {
			def->value = value;
			return true;
		}
	}
	def = RZ_NEW0(RzLangDef);
	if (!def) {
		return false;
	}
	def->type = strdup(type);
	def->name = strdup(name);
	def->value = value;
	rz_list_append(lang->defs, def);
	return true;
}

RZ_API void rz_lang_def_free(RzLangDef *def) {
	free(def->name);
	free(def->type);
	free(def);
}

RZ_API void rz_lang_undef(RzLang *lang, const char *name) {
	if (name && *name) {
		RzLangDef *def;
		RzListIter *iter;
		/* No _safe loop necessary because we return immediately after the delete. */
		rz_list_foreach (lang->defs, iter, def) {
			if (!name || !rz_str_casecmp(name, def->name)) {
				rz_list_delete(lang->defs, iter);
				break;
			}
		}
	} else {
		rz_list_free(lang->defs);
		lang->defs = NULL;
	}
}

RZ_API bool rz_lang_setup(RzLang *lang) {
	if (lang && lang->cur && lang->cur->setup) {
		return lang->cur->setup(lang);
	}
	return false;
}

RZ_API bool rz_lang_add(RzLang *lang, RzLangPlugin *foo) {
	if (foo && (!rz_lang_get_by_name(lang, foo->name))) {
		if (foo->init) {
			foo->init(lang);
		}
		rz_list_append(lang->langs, foo);
		return true;
	}
	return false;
}

/* TODO: deprecate all list methods */
RZ_API bool rz_lang_list(RzLang *lang) {
	RzListIter *iter;
	RzLangPlugin *h;
	if (!lang) {
		return false;
	}
	rz_list_foreach (lang->langs, iter, h) {
		const char *license = h->license
			? h->license
			: "???";
		lang->cb_printf("%s: (%s) %s\n",
			h->name, license, h->desc);
	}
	return true;
}

RZ_API RzLangPlugin *rz_lang_get_by_extension(RzLang *lang, const char *ext) {
	RzListIter *iter;
	RzLangPlugin *h;
	const char *p = rz_str_lchr(ext, '.');
	if (p) {
		ext = p + 1;
	}
	rz_list_foreach (lang->langs, iter, h) {
		if (!rz_str_casecmp(h->ext, ext)) {
			return h;
		}
	}
	return NULL;
}

RZ_API RzLangPlugin *rz_lang_get_by_name(RzLang *lang, const char *name) {
	RzListIter *iter;
	RzLangPlugin *h;
	rz_list_foreach (lang->langs, iter, h) {
		if (!rz_str_casecmp(h->name, name)) {
			return h;
		}
		if (h->alias && !rz_str_casecmp(h->alias, name)) {
			return h;
		}
	}
	return NULL;
}

RZ_API bool rz_lang_use(RzLang *lang, const char *name) {
	RzLangPlugin *h = rz_lang_get_by_name(lang, name);
	if (h) {
		lang->cur = h;
		return true;
	}
	return false;
}

// TODO: store in rz_lang and use it from the plugin?
RZ_API bool rz_lang_set_argv(RzLang *lang, int argc, char **argv) {
	if (lang->cur && lang->cur->set_argv) {
		return lang->cur->set_argv(lang, argc, argv);
	}
	return false;
}

RZ_API int rz_lang_run(RzLang *lang, const char *code, int len) {
	if (lang->cur && lang->cur->run) {
		return lang->cur->run(lang, code, len);
	}
	return false;
}

RZ_API int rz_lang_run_string(RzLang *lang, const char *code) {
	return rz_lang_run(lang, code, strlen(code));
}

RZ_API int rz_lang_run_file(RzLang *lang, const char *file) {
	int ret = false;
	if (lang->cur) {
		if (!lang->cur->run_file) {
			if (lang->cur->run) {
				size_t len;
				char *code = rz_file_slurp(file, &len);
				if (!code) {
					eprintf("Could not open '%s'.\n", file);
					return 0;
				}
				ret = lang->cur->run(lang, code, (int)len);
				free(code);
			}
		} else {
			ret = lang->cur->run_file(lang, file);
		}
	}
	return ret;
}

/* TODO: deprecate or make it more modular .. reading from stdin in a lib! */
RZ_API int rz_lang_prompt(RzLang *lang) {
	char buf[1024];
	const char *p;

	if (!lang || !lang->cur) {
		return false;
	}

	if (lang->cur->prompt) {
		if (lang->cur->prompt(lang)) {
			return true;
		}
	}
	/* init line */
	RzLine *line = rz_line_singleton();
	RzLineHistory hist = line->history;
	RzLineHistory histnull = { 0 };
	RzLineCompletion oc = line->completion;
	RzLineCompletion ocnull = { 0 };
	char *prompt = strdup(line->prompt);
	line->completion = ocnull;
	line->history = histnull;

	/* foo */
	for (;;) {
		rz_cons_flush();
		snprintf(buf, sizeof(buf) - 1, "%s> ", lang->cur->name);
		rz_line_set_prompt(buf);
#if 0
		printf ("%s> ", lang->cur->name);
		fflush (stdout);
		fgets (buf, sizeof (buf), stdin);
		if (feof (stdin)) break;
		rz_str_trim_tail (buf);
#endif
		p = rz_line_readline();
		if (!p) {
			break;
		}
		rz_line_hist_add(p);
		strncpy(buf, p, sizeof(buf) - 1);
		if (*buf == '!') {
			if (buf[1]) {
				rz_sys_xsystem(buf + 1);
			} else {
				char *foo, *code = NULL;
				do {
					foo = rz_cons_editor(NULL, code);
					rz_lang_run(lang, foo, 0);
					free(code);
					code = foo;
				} while (rz_cons_yesno('y', "Edit again? (Y/n)"));
				free(foo);
			}
			continue;
		}
		if (!memcmp(buf, ". ", 2)) {
			char *file = rz_file_abspath(buf + 2);
			if (file) {
				rz_lang_run_file(lang, file);
				free(file);
			}
			continue;
		}
		if (!strcmp(buf, "q")) {
			free(prompt);
			return true;
		}
		if (!strcmp(buf, "?")) {
			RzLangDef *def;
			RzListIter *iter;
			eprintf("  ?        - show this help message\n"
				"  !        - run $EDITOR\n"
				"  !command - run system command\n"
				"  . file   - interpret file\n"
				"  q        - quit prompt\n");
			eprintf("%s example:\n", lang->cur->name);
			if (lang->cur->help) {
				eprintf("%s", *lang->cur->help);
			}
			if (!rz_list_empty(lang->defs)) {
				eprintf("variables:\n");
			}
			rz_list_foreach (lang->defs, iter, def) {
				eprintf("  %s %s\n", def->type, def->name);
			}
		} else {
			rz_lang_run(lang, buf, strlen(buf));
		}
	}
	// XXX: leaking history
	rz_line_set_prompt(prompt);
	line->completion = oc;
	line->history = hist;
	clearerr(stdin);
	printf("\n");
	free(prompt);
	return true;
}
