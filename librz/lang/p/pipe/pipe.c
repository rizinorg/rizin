// SPDX-FileCopyrightText: 2015-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_core.h>
#include <rz_lang.h>
#if __WINDOWS__
#include <windows.h>
#endif
#ifdef _MSC_VER
#include <process.h>
#endif
#include "pipe_helper.h"

static int lang_pipe_file(RzLang *lang, const char *file) {
	return lang_pipe_run(lang, file, -1);
}

RzLangPlugin rz_lang_plugin_pipe = {
	.name = "pipe",
	.ext = "pipe",
	.license = "LGPL",
	.desc = "Use #!pipe node script.js",
	.run = lang_pipe_run,
	.run_file = (void *)lang_pipe_file,
};
