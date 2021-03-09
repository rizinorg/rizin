// SPDX-FileCopyrightText: 2011 pancake <pancake@nopcode.org>
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
		{ "cmpl", "cmp 2, 1" },
		{ "testl", "test 2, 1" },
		{ "leal", "lea 2, 1" },
		{ "movl", "mov 2, 1" },
		{ "xorl", "xor 2, 1" },
		{ "andl", "and 2, 1" },
		{ "orl", "or 2, 1" },
		{ "addl", "add 2, 1" },
		{ "incl", "inc 1" },
		{ "decl", "dec 1" },
		{ "subl", "sub 2, 1" },
		{ "mull", "mul 2, 1" },
		{ "divl", "div 2, 1" },
		{ "pushl", "push 1" },
		{ "popl", "pop 1" },
		{ "ret", "ret" },
		{ NULL }
	};

	for (i = 0; ops[i].op != NULL; i++) {
		if (!strcmp(ops[i].op, argv[0])) {
			if (newstr != NULL) {
				for (j = k = 0; ops[i].str[j] != '\0'; j++, k++) {
					if (ops[i].str[j] >= '0' && ops[i].str[j] <= '9') {
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
			strcat(newstr, (i == 0 || i == argc - 1) ? " " : ",");
		}
	}

	return false;
}

static int parse(RzParse *p, const char *data, char *str) {
	int i, n;
	char w0[32];
	char w1[32];
	char w2[32];
	char w3[32];
	char *buf, *ptr, *optr, *num;

	// malloc can be slow here :?
	buf = strdup(data);
	if (!buf) {
		return false;
	}
	rz_str_trim_head(buf);

	ptr = strchr(buf, '#');
	if (ptr) {
		*ptr = 0;
		rz_str_trim(buf);
	}
	if (*buf == '.' || buf[strlen(buf) - 1] == ':') {
		free(buf);
		strcpy(str, data);
		return true;
	}
	rz_str_replace_char(buf, '$', 0);
	rz_str_replace_char(buf, '%', 0);
	rz_str_replace_char(buf, '\t', ' ');
	rz_str_replace_char(buf, '(', '[');
	rz_str_replace_char(buf, ')', ']');
	ptr = strchr(buf, '[');
	if (ptr) {
		*ptr = 0;
		num = (char *)rz_str_lchr(buf, ' ');
		if (!num) {
			num = (char *)rz_str_lchr(buf, ',');
		}
		if (num) {
			n = atoi(num + 1);
			*ptr = '[';
			rz_str_cpy(num + 1, ptr);
			ptr = (char *)rz_str_lchr(buf, ']');
			if (n && ptr) {
				char *rest = strdup(ptr + 1);
				size_t dist = strlen(data) + 1 - (ptr - buf);
				snprintf(ptr, dist, "%+d]%s", n, rest);
				free(rest);
			}
		} else {
			*ptr = '[';
		}
	}

	if (*buf) {
		*w0 = *w1 = *w2 = *w3 = 0;
		ptr = strchr(buf, ' ');
		if (!ptr) {
			ptr = strchr(buf, '\t');
		}
		if (ptr) {
			*ptr = '\0';
			for (++ptr; *ptr == ' '; ptr++) {
				;
			}
			strncpy(w0, buf, sizeof(w0) - 1);
			strncpy(w1, ptr, sizeof(w1) - 1);

			optr = ptr;
			ptr = strchr(ptr, ',');
			if (ptr) {
				*ptr = '\0';
				for (++ptr; *ptr == ' '; ptr++) {
					;
				}
				strncpy(w1, optr, sizeof(w1) - 1);
				strncpy(w2, ptr, sizeof(w2) - 1);
				ptr = strchr(ptr, ',');
				if (ptr) {
					*ptr = '\0';
					for (++ptr; *ptr == ' '; ptr++) {
						;
					}
					strncpy(w2, optr, sizeof(w2) - 1);
					strncpy(w3, ptr, sizeof(w3) - 1);
				}
			}
		}
		{
			const char *wa[] = { w0, w1, w2, w3 };
			int nw = 0;
			for (i = 0; i < 4; i++) {
				if (wa[i][0] != '\0') {
					nw++;
				}
			}
			replace(nw, wa, str);
		}
	}
	free(buf);
	return true;
}

RzParsePlugin rz_parse_plugin_att2intel = {
	.name = "att2intel",
	.desc = "X86 att 2 intel plugin",
	.init = NULL,
	.fini = NULL,
	.parse = &parse,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_PARSE,
	.data = &rz_parse_plugin_att2intel,
	.version = RZ_VERSION
};
#endif
