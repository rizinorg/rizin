// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2009-2020 nibble <nibble.ds@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only
#include <stddef.h>
#include <rz_core.h>

typedef void (*DigestHandler)(const char *name, const ut8 *block, int len);

typedef struct {
	const char *name;
	DigestHandler handler;
	RzHashPlugin *plugin;
} MsgDigestCaller;

RZ_IPI RzCmdDescDetail *rz_hash_bang_details_cb(RzCore *core, int argc, const char **argv) {
	RzListIter *iter;
	RzLangPlugin *lp;
	RzCmdDescDetail *details = RZ_NEWS0(RzCmdDescDetail, 2);
	if (!details) {
		return NULL;
	}
	details[0].name = (const char *)rz_str_dup("Available interpreters");
	if (!details->name) {
		goto err;
	}
	RzCmdDescDetailEntry *entries = RZ_NEWS0(RzCmdDescDetailEntry, rz_list_length(core->lang->langs) + 1);
	details[0].entries = (const RzCmdDescDetailEntry *)entries;
	if (!entries) {
		goto err;
	}
	int i = 0;
	rz_list_foreach (core->lang->langs, iter, lp) {
		entries[i].text = (char *)rz_str_dup("#!");
		entries[i].arg_str = (char *)rz_str_dup(lp->name);
		entries[i].comment = (char *)rz_str_newf("%s (%s)", lp->desc, lp->license);
		if (!entries[i].text || !entries[i].arg_str || !entries[i].comment) {
			goto err;
		}
		i++;
	}
	details->entries = (const RzCmdDescDetailEntry *)entries;
	return details;
err:
	rz_cmd_desc_details_free(details);
	return NULL;
}

RZ_IPI RzCmdStatus rz_hash_bang_handler(RzCore *core, int argc, const char **argv) {
	RzLangPlugin *p = rz_lang_get_by_name(core->lang, argv[1]);
	if (!p) {
		RZ_LOG_ERROR("No interpreter with name '%s'\n", argv[1]);
		return RZ_CMD_STATUS_ERROR;
	}
	core->lang->cur = p;
	if (argc > 2) {
		if (rz_lang_set_argv(core->lang, argc - 2, (char **)&argv[2])) {
			rz_lang_run_file(core->lang, argv[2]);
		} else {
			char *run_str = rz_str_array_join(argv + 2, argc - 2, " ");
			rz_lang_run_file(core->lang, run_str);
			free(run_str);
		}
	} else {
		if (rz_cons_is_interactive()) {
			rz_lang_prompt(core->lang);
		} else {
			RZ_LOG_ERROR("scr.interactive required to run the rlang prompt\n");
			return RZ_CMD_STATUS_ERROR;
		}
	}
	return RZ_CMD_STATUS_OK;
}
