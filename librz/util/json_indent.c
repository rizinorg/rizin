// SPDX-FileCopyrightText: 2012-2017 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <rz_util.h>

static void doIndent(int idt, char **o, const char *tab) {
	int i;
	char *x;
	for (i = 0; i < idt; i++) {
		for (x = (char *)tab; *x; x++) {
			*(*o)++ = *x;
		}
	}
}

#define EMIT_ESC(s, code) \
	do { \
		if (color) { \
			const char *p = code; \
			while (*p) { \
				*(s)++ = *p++; \
			} \
		} \
	} while (0);

enum {
	JC_FALSE, // 31m
	JC_TRUE, // 32m
	JC_KEY, // 33m
	JC_VAL, // 34m
	JC_RESET,
};

/**
 * \brief Default colors for json printing.
 */
static const char *default_colors[] = {
	"\x1b[31m",
	"\x1b[32m",
	"\x1b[33m",
	"\x1b[34m",
	"\x1b[0m",
};

RZ_API char *rz_print_json_human(const char *s) {
	int indent = 0;
	const char *tab = "  ";
	const int indentSize = strlen(tab);
	int instr = 0;
	char *o, *OE, *tmp;
	if (!s) {
		return NULL;
	}
	int osz = (1 + strlen(s)) * 20;
	if (osz < 1) {
		return NULL;
	}

	char *O = malloc(osz);
	if (!O) {
		return NULL;
	}
	OE = O + osz;
	for (o = O; *s; s++) {
		if (o + (indent * indentSize) + 10 > OE) {
			int delta = o - O;
			osz += 0x1000 + (indent * indentSize);
			if (osz < 1) {
				free(O);
				return NULL;
			}
			tmp = realloc(O, osz);
			if (!tmp) {
				free(O);
				return NULL;
			}
			O = tmp;
			OE = tmp + osz;
			o = O + delta;
		}
		if (instr) {
			if (s[0] == '"') {
				instr = 0;
			} else if (s[0] == '\\' && s[1] == '"') {
				// XXX maybe buggy
				*o++ = *s++;
			}
			if (*s != '"') {
				*o++ = *s;
			}
			continue;
		}
		if (indent <= 0) {
			// non-JSON part
			if (s[0] != '{' && s[0] != '[') {
				*o++ = *s;
				continue;
			}
		}

		if (s[0] == '"') {
			instr = 1;
		}
		if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ') {
			continue;
		}
		switch (*s) {
		case ':':
			*o++ = *s;
			*o++ = ' ';
			break;
		case ',':
			*o++ = '\n';
			doIndent(indent - 1, &o, tab);
			break;
		case '{':
		case '[':
			if (indent > 0) {
				*o++ = (indent != -1) ? '\n' : ' ';
			}
			if (indent > 128) {
				eprintf("JSON indentation is too deep\n");
				indent = 0;
			} else {
				indent++;
			}
			doIndent(indent - 1, &o, tab);
			break;
		case '}':
		case ']':
			indent--;
			doIndent(indent - 1, &o, tab);
			break;
		default:
			if (!instr) {
				*o++ = *s;
			}
		}
	}
	*o = 0;
	return O;
}

/**
 * \brief Formats the JSON string at \p s with indentation.
 *
 * \param s The JSON string to format.
 * \param color Format with color?
 * \param tab The string to use as indentation tab.
 * \param palette The color palette to use. If NULL and \p color == true, a default color palatte is used.
 *
 * \return The formatted JSON string or NULL in case of failure.
 */
RZ_API RZ_OWN char *rz_print_json_indent(RZ_NULLABLE const char *s, bool color, const char *tab, RZ_NULLABLE const char **palette) {
	rz_return_val_if_fail(tab, NULL);
	int indent = 0;
	const int indentSize = strlen(tab);
	int instr = 0;
	bool isValue = false;
	char *o, *OE, *tmp;
	if (!s) {
		return NULL;
	}
	const char **colors = palette ? palette : default_colors;
	int osz = (1 + strlen(s)) * 20;
	if (osz < 1) {
		return NULL;
	}

	char *O = RZ_NEWS0(char, osz);
	if (!O) {
		return NULL;
	}
	OE = O + osz;
	for (o = O; *s; s++) {
		if (o + (indent * indentSize) + 10 > OE) {
			int delta = o - O;
			osz += 0x1000 + (indent * indentSize);
			if (osz < 1) {
				free(O);
				return NULL;
			}
			tmp = realloc(O, osz);
			if (!tmp) {
				free(O);
				return NULL;
			}
			O = tmp;
			OE = tmp + osz;
			o = O + delta;
		}
		if (instr) {
			if (s[0] == '"') {
				instr = 0;
			} else if (s[0] == '\\' && s[1] == '"') {
				*o++ = *s++;
			}
			if (instr) {
				if (isValue) {
					// TODO: do not emit color in every char
					EMIT_ESC(o, colors[JC_VAL]);
				} else {
					EMIT_ESC(o, colors[JC_KEY]);
				}
			} else {
				EMIT_ESC(o, colors[JC_RESET]);
			}
			*o++ = *s;
			continue;
		}
		if (indent <= 0) {
			// non-JSON part, skip it
			if (s[0] != '{' && s[0] != '[') {
				if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ') {
					*o++ = *s;
				}
				continue;
			}
		}

		if (s[0] == '"') {
			instr = 1;
		}
		if (*s == '\n' || *s == '\r' || *s == '\t' || *s == ' ' || !IS_PRINTABLE(*s)) {
			continue;
		}
		switch (*s) {
		case ':':
			*o++ = *s;
			*o++ = ' ';
			s = rz_str_trim_head_ro(s + 1);
			if (!strncmp(s, "true", 4)) {
				EMIT_ESC(o, colors[JC_TRUE]);
			} else if (!strncmp(s, "false", 5)) {
				EMIT_ESC(o, colors[JC_FALSE]);
			}
			s--;
			isValue = true;
			break;
		case ',':
			EMIT_ESC(o, colors[JC_RESET]);
			*o++ = *s;
			*o++ = '\n';
			isValue = false;
			doIndent(indent, &o, tab);
			break;
		case '{':
		case '[':
			isValue = false;
			*o++ = *s;
			*o++ = (indent != -1) ? '\n' : ' ';
			if (indent > 128) {
				eprintf("JSON indentation is too deep\n");
				indent = 0;
			} else {
				indent++;
			}
			doIndent(indent, &o, tab);
			break;
		case '}':
		case ']':
			EMIT_ESC(o, colors[JC_RESET]);
			isValue = false;
			*o++ = '\n';
			indent--;
			doIndent(indent, &o, tab);
			*o++ = *s;
			break;
		default:
			*o++ = *s;
		}
	}
	*o = 0;
	return O;
}

#undef EMIT_ESC
