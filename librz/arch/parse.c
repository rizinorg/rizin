// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

#include <rz_types.h>
#include <rz_arch.h>
#include <rz_lib.h>

RZ_API RzParse *rz_parse_new(void) {
	RzParse *p = RZ_NEW0(RzParse);
	if (!p) {
		return NULL;
	}
	p->parsers = rz_list_new();
	if (!p->parsers) {
		rz_parse_free(p);
		return NULL;
	}
	p->notin_flagspace = NULL;
	p->flagspace = NULL;
	p->pseudo = false;
	p->subrel = false;
	p->subtail = false;
	p->minval = 0x100;
	p->localvar_only = false;

	const size_t n_plugins = rz_arch_get_n_plugins();
	for (size_t i = 0; i < n_plugins; i++) {
		RzParsePlugin *plugin = rz_arch_get_parse_plugin(i);
		if (!plugin) {
			continue;
		}
		rz_parse_plugin_add(p, plugin);
	}
	return p;
}

RZ_API void rz_parse_free(RzParse *p) {
	if (!p) {
		return;
	}
	RzListIter *it, *tmp;
	RzParsePlugin *plugin;
	rz_list_foreach_safe (p->parsers, it, tmp, plugin) {
		if (plugin->fini) {
			plugin->fini(p, p->user);
		}
	}
	rz_list_free(p->parsers);
	free(p);
}

RZ_API bool rz_parse_plugin_add(RzParse *p, RZ_NONNULL RzParsePlugin *plugin) {
	rz_return_val_if_fail(p && plugin, false);

	bool itsFine = true;
	if (plugin->init) {
		itsFine = plugin->init(p, p->user);
	}
	if (itsFine) {
		rz_list_append(p->parsers, plugin);
	}
	return true;
}

RZ_API bool rz_parse_plugin_del(RzParse *p, RZ_NONNULL RzParsePlugin *plugin) {
	rz_return_val_if_fail(p && plugin, false);
	if (p->cur == plugin) {
		if (plugin->fini && !plugin->fini(p, p->user)) {
			return false;
		}
		p->cur = NULL;
	}
	return rz_list_delete_data(p->parsers, plugin);
}

RZ_API bool rz_parse_use(RzParse *p, const char *name) {
	RzListIter *iter;
	RzParsePlugin *h;
	rz_return_val_if_fail(p && name, false);
	rz_list_foreach (p->parsers, iter, h) {
		if (!strcmp(h->name, name)) {
			p->cur = h;
			return true;
		}
	}
	p->cur = NULL;
	return false;
}

// this function is a bit confussing, assembles C code into wat?, whehres theh input and wheres the output
// and its unused. so imho it sshould be DEPRECATED this conflicts with rasm.assemble imhoh
RZ_API bool rz_parse_assemble(RzParse *p, char *data, char *str) {
	char *in = rz_str_dup(str);
	bool ret = false;
	char *s, *o;

	data[0] = '\0';
	if (p->cur && p->cur->assemble) {
		o = data + strlen(data);
		do {
			s = strchr(str, ';');
			if (s) {
				*s = '\0';
			}
			ret = p->cur->assemble(p, o, str);
			if (!ret) {
				break;
			}
			if (s) {
				str = s + 1;
				o += strlen(data);
				o[0] = '\n';
				o[1] = '\0';
				o++;
			}
		} while (s);
	}
	free(in);
	return ret;
}

/**
 * \brief Converts the assembly line into pseudocode
 *
 * Converts the assembly line into pseudocode
 * */
RZ_API char *rz_parse_pseudocode(RzParse *p, const char *assembly) {
	rz_return_val_if_fail(p, NULL);
	if (RZ_STR_ISEMPTY(assembly)) {
		return NULL;
	}

	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}

	rz_strbuf_reserve(sb, 128);
	if (!p->cur || !p->cur->parse || !p->cur->parse(p, assembly, sb)) {
		rz_strbuf_free(sb);
		return NULL;
	}

	return rz_strbuf_drain(sb);
}

RZ_API char *rz_parse_immtrim(char *opstr) {
	if (!opstr || !*opstr) {
		return NULL;
	}
	char *n = strstr(opstr, "0x");
	if (n) {
		char *p = n + 2;
		while (IS_HEXCHAR(*p)) {
			p++;
		}
		memmove(n, p, strlen(p) + 1);
	}
	if (strstr(opstr, " - ]")) {
		opstr = rz_str_replace(opstr, " - ]", "]", 1);
	}
	if (strstr(opstr, " + ]")) {
		opstr = rz_str_replace(opstr, " + ]", "]", 1);
	}
	if (strstr(opstr, ", ]")) {
		opstr = rz_str_replace(opstr, ", ]", "]", 1);
	}
	if (strstr(opstr, " - ")) {
		opstr = rz_str_replace(opstr, " - ", "-", 1);
	}
	if (strstr(opstr, " + ")) {
		opstr = rz_str_replace(opstr, " + ", "+", 1);
	}
	return opstr;
}

/*
 * \brief Substitutes register relative accesses with function variable names
 * \param p The parser
 * \param f The function
 * \param op The analysis op of the current instruction
 * \param data The disassembly of the current instruction
 * \param str The string buffer to write the output to
 * \param len The length of the string buffer
 */
RZ_API bool rz_parse_subvar(RzParse *p, RZ_NULLABLE RzAnalysisFunction *f, RZ_NONNULL RzAnalysisOp *op, RZ_NONNULL RZ_IN char *data, RZ_BORROW RZ_NONNULL RZ_OUT char *str, int len) {
	rz_return_val_if_fail(op && data && str, false);
	if (p->cur && p->cur->subvar) {
		return p->cur->subvar(p, f, op, data, str, len);
	}
	return false;
}

/* setters */
RZ_API void rz_parse_set_user_ptr(RzParse *p, void *user) {
	p->user = user;
}
