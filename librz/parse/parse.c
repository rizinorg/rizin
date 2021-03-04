// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 maijin <maijin21@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>

#include <rz_types.h>
#include <rz_parse.h>
#include <config.h>

RZ_LIB_VERSION(rz_parse);

static RzParsePlugin *parse_static_plugins[] = { RZ_PARSE_STATIC_PLUGINS };

RZ_API RzParse *rz_parse_new(void) {
	int i;
	RzParse *p = RZ_NEW0(RzParse);
	if (!p) {
		return NULL;
	}
	p->parsers = rz_list_newf(NULL); // memleak
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
	for (i = 0; parse_static_plugins[i]; i++) {
		rz_parse_add(p, parse_static_plugins[i]);
	}
	return p;
}

RZ_API void rz_parse_free(RzParse *p) {
	rz_list_free(p->parsers);
	free(p);
}

RZ_API bool rz_parse_add(RzParse *p, RzParsePlugin *foo) {
	bool itsFine = true;
	if (foo->init) {
		itsFine = foo->init(p, p->user);
	}
	if (itsFine) {
		rz_list_append(p->parsers, foo);
	}
	return true;
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
	return false;
}

// this function is a bit confussing, assembles C code into wat?, whehres theh input and wheres the output
// and its unused. so imho it sshould be DEPRECATED this conflicts with rasm.assemble imhoh
RZ_API bool rz_parse_assemble(RzParse *p, char *data, char *str) {
	char *in = strdup(str);
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

// data is input disasm, str is output pseudo
// TODO: refactooring, this should return char * instead
RZ_API bool rz_parse_parse(RzParse *p, const char *data, char *str) {
	rz_return_val_if_fail(p && data && str, false);
	return (p && data && *data && p->cur && p->cur->parse)
		? p->cur->parse(p, data, str)
		: false;
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

RZ_API bool rz_parse_subvar(RzParse *p, RzAnalysisFunction *f, ut64 addr, int oplen, char *data, char *str, int len) {
	if (p->cur && p->cur->subvar) {
		return p->cur->subvar(p, f, addr, oplen, data, str, len);
	}
	return false;
}

/* setters */
RZ_API void rz_parse_set_user_ptr(RzParse *p, void *user) {
	p->user = user;
}
