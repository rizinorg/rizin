// SPDX-FileCopyrightText: 2009-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2020 ret2libc <sirmy15@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include "rz_config.h"
#include "rz_cons.h"
#include "rz_core.h"

// TODO #7967 help refactor: move to another place
static const char *help_msg_L[] = {
	"Usage:", "L[acio]", "[-name][ file]",
	"L", "", "show this help",
	"L", " blah." RZ_LIB_EXT, "load plugin file",
	"L-", "duk", "unload core plugin by name",
	"Ll", "", "list lang plugins (same as #!)",
	"La", "", "list asm/analysis plugins (aL, e asm.arch="
		  "??"
		  ")",
	"Lc", "", "list core plugins",
	"Ld", "", "list debug plugins (same as dL)",
	"LD", "", "list supported decompilers",
	"Lm", "", "list fs plugins (same as mL)",
	"Lh", "", "list hash plugins (same as ph)",
	"Li", "", "list bin plugins (same as iL)",
	"Lo", "", "list io plugins (same as oL)",
	"Lp", "", "list parser plugins (e asm.parser=?)",
	NULL
};

RZ_IPI int rz_cmd_plugins(void *data, const char *input) {
	RzCore *core = (RzCore *)data;
	switch (input[0]) {
	case 0:
		rz_core_cmd_help(core, help_msg_L);
		// return rz_core_cmd0 (core, "Lc");
		break;
	case '-':
		rz_lib_close(core->lib, rz_str_trim_head_ro(input + 1));
		break;
	case ' ':
		rz_lib_open(core->lib, rz_str_trim_head_ro(input + 1));
		break;
	case '?':
		rz_core_cmd_help(core, help_msg_L);
		break;
	case 'm': // "Lm"
		rz_core_cmdf(core, "mL%s", input + 1);
		break;
	case 'd': // "Ld"
		rz_core_cmdf(core, "dL%s", input + 1);
		break;
	case 'h': // "Lh"
		rz_core_cmd0(core, "ph"); // rz_hash -L is more verbose
		break;
	case 'a': // "La"
		rz_core_cmd0(core, "e asm.arch=??");
		break;
	case 'p': // "Lp"
		rz_core_cmd0(core, "e asm.parser=?");
		break;
	case 'l': // "Ll"
		rz_core_cmd0(core, "#!");
		break;
	case 'o': // "Lo"
	case 'i': // "Li"
		rz_core_cmdf(core, "%cL", input[0]);
		break;
	case 'c': { // "Lc"
		RzListIter *iter;
		RzCorePlugin *cp;
		switch (input[1]) {
		case 'j': {
			rz_cons_printf("[");
			bool is_first_element = true;
			rz_list_foreach (core->plugins, iter, cp) {
				rz_cons_printf("%s{\"Name\":\"%s\",\"Description\":\"%s\"}",
					is_first_element ? "" : ",", cp->name, cp->desc);
				is_first_element = false;
			}
			rz_cons_printf("]\n");
			break;
		}
		case 0:
			rz_lib_list(core->lib);
			rz_list_foreach (core->plugins, iter, cp) {
				rz_cons_printf("%s: %s\n", cp->name, cp->desc);
			}
			break;
		default:
			eprintf("oops\n");
			break;
		}
	} break;
	}
	return 0;
}
