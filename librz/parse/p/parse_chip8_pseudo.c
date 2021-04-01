// SPDX-FileCopyrightText: 2019 Vasilij Schneidermann <mail@vasilij.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_lib.h>
#include <rz_util.h>
#include <rz_flag.h>
#include <rz_analysis.h>
#include <rz_parse.h>

#define MAXARGS 4
#define BUFSIZE 64

static void concat(char *buf, size_t len, char **args) {
	char *arg;
	char *dest = buf;
	int arg_len;

	while ((arg = *args++)) {
		if (snprintf(dest, len, "%s", arg) >= len) {
			break;
		}
		arg_len = strlen(arg);
		dest += arg_len;
		len -= arg_len;
	}
}

static int replace(int argc, char *argv[], char *newstr, size_t len) {
	int i;
	struct {
		char *op;
		char **res;
	} ops[] = {
		{ "add", (char *[]){ argv[1], " += ", argv[2], NULL } },
		{ "and", (char *[]){ argv[1], " &= ", argv[2], NULL } },
		{ "cls", (char *[]){ "clear_screen()", NULL } },
		{ "drw", (char *[]){ "draw(", argv[1], ", ", argv[2], ", ", argv[3], ")", NULL } },
		{ "exit", (char *[]){ "exit()", NULL } },
		{ "high", (char *[]){ "high_res()", NULL } },
		{ "jp", (char *[]){ "goto ", argv[1], NULL } },
		{ "ld", (char *[]){ argv[1], " = ", argv[2], NULL } },
		{ "low", (char *[]){ "low_res()", NULL } },
		{ "or", (char *[]){ argv[1], " |= ", argv[2], NULL } },
		{ "rnd", (char *[]){ argv[1], " = random(256) & ", argv[2], NULL } },
		{ "scd", (char *[]){ "scroll_down(", argv[1], ")", NULL } },
		{ "scl", (char *[]){ "scroll_left()", NULL } },
		{ "scr", (char *[]){ "scroll_right()", NULL } },
		{ "se", (char *[]){ "skip_next_instr if ", argv[1], " == ", argv[2], NULL } },
		{ "shl", (char *[]){ argv[1], " <<= 1", NULL } },
		{ "shr", (char *[]){ argv[1], " >>= 1", NULL } },
		{ "sknp", (char *[]){ "skip_next_instr if !key_pressed(", argv[1], ")", NULL } },
		{ "skp", (char *[]){ "skip_next_instr if key_pressed(", argv[1], ")", NULL } },
		{ "sne", (char *[]){ "skip_next_instr if ", argv[1], " != ", argv[2], NULL } },
		{ "sub", (char *[]){ argv[1], " -= ", argv[2], NULL } },
		{ "subn", (char *[]){ argv[1], " = ", argv[2], " - ", argv[1], NULL } },
		{ "xor", (char *[]){ argv[1], " ^= ", argv[2], NULL } },
		{ NULL }
	};

	for (i = 0; ops[i].op; i++) {
		if (!strcmp(ops[i].op, argv[0]) && newstr) {
			concat(newstr, len, ops[i].res);
			return true;
		}
	}

	return false;
}

static int tokenize(const char *in, char *out[]) {
	int len = strlen(in), count = 0, i = 0, tokenlen = 0, seplen = 0;
	char *token, *buf = (char *)in;
	const char *tokcharset = ", \t\n";

	while (i < len) {
		tokenlen = strcspn(buf, tokcharset);
		token = calloc(tokenlen + 1, sizeof(char));
		memcpy(token, buf, tokenlen);
		out[count] = token;
		i += tokenlen;
		buf += tokenlen;
		count++;

		seplen = strspn(buf, tokcharset);
		i += seplen;
		buf += seplen;
	}

	return count;
}

static int parse(RzParse *p, const char *data, char *str) {
	int i;
	char *argv[MAXARGS] = { NULL, NULL, NULL, NULL };
	int argc = tokenize(data, argv);

	if (!replace(argc, argv, str, BUFSIZE)) {
		strcpy(str, data);
	}

	for (i = 0; i < MAXARGS; i++) {
		free(argv[i]);
	}

	return true;
}

RzParsePlugin rz_parse_plugin_chip8_pseudo = {
	.name = "chip8.pseudo",
	.desc = "chip8 pseudo syntax",
	.parse = parse,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_PARSE,
	.data = &rz_parse_plugin_chip8_pseudo,
	.version = RZ_VERSION
};
#endif
