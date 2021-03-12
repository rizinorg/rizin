// SPDX-FileCopyrightText: 2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_lib.h"
#include "rz_core.h"
#include "rz_lang.h"
#define USE_R2 1

static RzLang *Glang = NULL;
#include <spp.h>
#include "spp_rz.inc"

static int lang_spp_init(RzLang *l) {
	Glang = l;
	return true;
}

static int lang_spp_run(RzLang *lang, const char *code, int len) {
	Output out;
	out.fout = NULL;
	out.cout = rz_strbuf_new(NULL);
	rz_strbuf_init(out.cout);
	spp_proc_set(&spp_rz_proc, NULL, 0);
	char *c = strdup(code);
	spp_eval(c, &out);
	free(c);
	char *data = rz_strbuf_drain(out.cout);
	rz_cons_printf("%s\n", data);
	free(data);
	return true;
}

static int lang_spp_file(RzLang *lang, const char *file) {
	size_t len;
	char *code = rz_file_slurp(file, &len);
	if (code) {
		int res = lang_spp_run(lang, code, len);
		free(code);
		return res;
	}
	return 0;
}

static RzLangPlugin rz_lang_plugin_spp = {
	.name = "spp",
	.ext = "spp",
	.license = "MIT",
	.desc = "SPP template programs",
	.run = lang_spp_run,
	.init = (void *)lang_spp_init,
	.run_file = (void *)lang_spp_file,
};
