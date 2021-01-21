// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

static int replace(int argc, const char *argv[], char *newstr) {
	int i, j, k;
	struct {
		char *op;
		char *str;
	} ops[] = {
		{ "adc", "1 = 1 + 2" },
		{ "add", "1 = 1 + 2" },
		{ "and", "1 = 1 & 2" },
		{ "cpl", "1 = ~1" },
		{ "ex", "swap(1, 2)" },
		{ "in", "1 = [2]" },
		{ "jp", "goto [1]" },
		{ "jp", "goto 1" },
		{ "jr", "goto +1" },
		{ "ld", "1 = 2" },
		{ "ldd", "1 = 2--" },
		{ "neg", "1 = -1" },
		{ "nop", "" },
		{ "or", "1 = 1 | 2" },
		{ "pop", "pop 1" },
		{ "push", "push 1" },
		{ "rr", "1 = 1 << 2" },
		{ "sbc", "1 = 1 - 2" },
		{ "sla", "1 = 1 << 2" },
		{ "sra", "1 = 1 >> 2" },
		{ "srl", "1 = 1 >> 2" },
		{ "sub", "1 = 1 - 2" },
		{ "xor", "1 = 1 ^ 2" },
		{ NULL }
	};

	for (i = 0; ops[i].op != NULL; i++) {
		if (!strcmp(ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
					if (ops[i].str[j] >= '1' && ops[i].str[j] <= '9') {
						const char *w = argv[ops[i].str[j] - '0'];
						if (w != NULL) {
							strcpy(newstr + k, w);
							k += strlen(w) - 1;
						}
					} else {
						newstr[k] = ops[i].str[j];
					}
				}
				newstr[k] = '\0';
			}
			return true;
		}
	}

	/* TODO: this is slow */
	if (newstr != NULL) {
		newstr[0] = '\0';
		for (i = 0; i < argc; i++) {
			strcat(newstr, argv[i]);
			strcat(newstr, (i == 0 || i == argc - 1) ? " " : ", ");
		}
	}

	return false;
}

RzParsePlugin rz_parse_plugin_z80_pseudo = {
	.name = "z80.pseudo",
	.desc = "z80 pseudo syntax",
	.init = NULL,
	.fini = NULL,
	.replace = replace,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_PARSE,
	.data = &rz_parse_plugin_z80_pseudo,
	.version = RZ_VERSION
};
#endif
