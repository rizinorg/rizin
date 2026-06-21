/* $OpenBSD: magic-load.c,v 1.26 2017/07/02 10:58:15 brynet Exp $ */

/*
 * Copyright (c) 2015 Nicholas Marriott <nicm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "rz_util.h"
#include "magic.h"

static int magic_odigit(ut8 c) {
	if (c >= '0' && c <= '7')
		return (c - '0');
	return (-1);
}

static int magic_xdigit(ut8 c) {
	if (c >= '0' && c <= '9')
		return (c - '0');
	if (c >= 'a' && c <= 'f')
		return (10 + c - 'a');
	if (c >= 'A' && c <= 'F')
		return (10 + c - 'A');
	return (-1);
}

static void magic_mark_text(RzMagicLine *ml, int text) {
	do {
		ml->text = text;
		ml = ml->parent;
	} while (ml != NULL);
}

static int magic_make_pattern(RzMagicLine *ml, const char *name, RzRegex **re,
	const char *p) {

	if (!re) {
		return (-1);
	}

	if (*re) {
		RZ_FREE_CUSTOM(*re, rz_regex_free);
	}

	*re = rz_regex_new(p, RZ_REGEX_EXTENDED, RZ_REGEX_DEFAULT, NULL);
	if (!(*re)) {
		RZ_LOG_WARN("bad %s pattern\n", name);
		return (-1);
	}
	return (0);
}

static int magic_set_result(RzMagicLine *ml, const char *s) {
	const char *fmt, *endfmt, *cp;
	RzRegex *re = NULL;
	size_t fmtlen;

	while (isspace((ut8)*s))
		s++;
	if (*s == '\0') {
		ml->result = NULL;
		return (0);
	}
	ml->result = rz_str_dup(s);

	fmt = NULL;
	for (cp = s; *cp != '\0'; cp++) {
		if (cp[0] == '%' && cp[1] != '%') {
			if (fmt != NULL) {
				RZ_LOG_WARN("multiple formats\n");
				return (-1);
			}
			fmt = cp;
		}
	}
	if (fmt == NULL)
		return (0);
	fmt++;

	for (endfmt = fmt; *endfmt != '\0'; endfmt++) {
		if (strchr("diouxXeEfFgGsc", *endfmt) != NULL)
			break;
	}
	if (*endfmt == '\0') {
		RZ_LOG_WARN("unterminated format\n");
		return (-1);
	}
	fmtlen = endfmt + 1 - fmt;
	if (fmtlen > 32) {
		RZ_LOG_WARN("format too long\n");
		return (-1);
	}

	if (*endfmt == 's') {
		switch (ml->type) {
		case MAGIC_TYPE_DATE:
		case MAGIC_TYPE_LDATE:
		case MAGIC_TYPE_UDATE:
		case MAGIC_TYPE_ULDATE:
		case MAGIC_TYPE_BEDATE:
		case MAGIC_TYPE_BELDATE:
		case MAGIC_TYPE_UBEDATE:
		case MAGIC_TYPE_UBELDATE:
		case MAGIC_TYPE_QDATE:
		case MAGIC_TYPE_QLDATE:
		case MAGIC_TYPE_UQDATE:
		case MAGIC_TYPE_UQLDATE:
		case MAGIC_TYPE_BEQDATE:
		case MAGIC_TYPE_BEQLDATE:
		case MAGIC_TYPE_UBEQDATE:
		case MAGIC_TYPE_UBEQLDATE:
		case MAGIC_TYPE_LEQDATE:
		case MAGIC_TYPE_LEQLDATE:
		case MAGIC_TYPE_ULEQDATE:
		case MAGIC_TYPE_ULEQLDATE:
		case MAGIC_TYPE_LEDATE:
		case MAGIC_TYPE_LELDATE:
		case MAGIC_TYPE_ULEDATE:
		case MAGIC_TYPE_ULELDATE:
		case MAGIC_TYPE_MEDATE:
		case MAGIC_TYPE_MELDATE:
		case MAGIC_TYPE_STRING:
		case MAGIC_TYPE_PSTRING:
		case MAGIC_TYPE_BESTRING16:
		case MAGIC_TYPE_LESTRING16:
		case MAGIC_TYPE_REGEX:
		case MAGIC_TYPE_SEARCH:
			break;
		default:
			ml->stringify = 1;
			break;
		}
	}

	if (!ml->root->compiled) {
		/*
		 * XXX %ld (and %lu and so on) is invalid on 64-bit platforms
		 * with byte, short, long. We get lucky because our first and
		 * only argument ends up in a register. Accept it for now.
		 */
		if (magic_make_pattern(ml, "short", &ml->root->format_short,
			    "^-?[0-9]*(\\.[0-9]*)?(c|(l|h|hh)?[iduxX])$") != 0)
			return (-1);
		if (magic_make_pattern(ml, "long", &ml->root->format_long,
			    "^-?[0-9]*(\\.[0-9]*)?(c|(l|h|hh)?[iduxX])$") != 0)
			return (-1);
		if (magic_make_pattern(ml, "quad", &ml->root->format_quad,
			    "^-?[0-9]*(\\.[0-9]*)?ll[iduxX]$") != 0)
			return (-1);
		if (magic_make_pattern(ml, "float", &ml->root->format_float,
			    "^-?[0-9]*(\\.[0-9]*)?[eEfFgG]$") != 0)
			return (-1);
		if (magic_make_pattern(ml, "string", &ml->root->format_string,
			    "^-?[0-9]*(\\.[0-9]*)?s$") != 0)
			return (-1);
		ml->root->compiled = 1;
	}

	if (ml->stringify)
		re = ml->root->format_string;
	else {
		switch (ml->type) {
		case MAGIC_TYPE_NONE:
		case MAGIC_TYPE_BESTRING16:
		case MAGIC_TYPE_LESTRING16:
		case MAGIC_TYPE_NAME:
		case MAGIC_TYPE_USE:
			return (0); /* don't use result */
		case MAGIC_TYPE_BYTE:
		case MAGIC_TYPE_UBYTE:
		case MAGIC_TYPE_SHORT:
		case MAGIC_TYPE_USHORT:
		case MAGIC_TYPE_BESHORT:
		case MAGIC_TYPE_UBESHORT:
		case MAGIC_TYPE_LESHORT:
		case MAGIC_TYPE_ULESHORT:
			re = ml->root->format_short;
			break;
		case MAGIC_TYPE_LONG:
		case MAGIC_TYPE_ULONG:
		case MAGIC_TYPE_BELONG:
		case MAGIC_TYPE_UBELONG:
		case MAGIC_TYPE_LELONG:
		case MAGIC_TYPE_ULELONG:
		case MAGIC_TYPE_MELONG:
			re = ml->root->format_long;
			break;
		case MAGIC_TYPE_QUAD:
		case MAGIC_TYPE_UQUAD:
		case MAGIC_TYPE_BEQUAD:
		case MAGIC_TYPE_UBEQUAD:
		case MAGIC_TYPE_LEQUAD:
		case MAGIC_TYPE_ULEQUAD:
			re = ml->root->format_quad;
			break;
		case MAGIC_TYPE_FLOAT:
		case MAGIC_TYPE_BEFLOAT:
		case MAGIC_TYPE_LEFLOAT:
		case MAGIC_TYPE_DOUBLE:
		case MAGIC_TYPE_BEDOUBLE:
		case MAGIC_TYPE_LEDOUBLE:
			re = ml->root->format_float;
			break;
		case MAGIC_TYPE_DATE:
		case MAGIC_TYPE_LDATE:
		case MAGIC_TYPE_UDATE:
		case MAGIC_TYPE_ULDATE:
		case MAGIC_TYPE_BEDATE:
		case MAGIC_TYPE_BELDATE:
		case MAGIC_TYPE_UBEDATE:
		case MAGIC_TYPE_UBELDATE:
		case MAGIC_TYPE_QDATE:
		case MAGIC_TYPE_QLDATE:
		case MAGIC_TYPE_UQDATE:
		case MAGIC_TYPE_UQLDATE:
		case MAGIC_TYPE_BEQDATE:
		case MAGIC_TYPE_BEQLDATE:
		case MAGIC_TYPE_UBEQDATE:
		case MAGIC_TYPE_UBEQLDATE:
		case MAGIC_TYPE_LEQDATE:
		case MAGIC_TYPE_LEQLDATE:
		case MAGIC_TYPE_ULEQDATE:
		case MAGIC_TYPE_ULEQLDATE:
		case MAGIC_TYPE_LEDATE:
		case MAGIC_TYPE_LELDATE:
		case MAGIC_TYPE_ULEDATE:
		case MAGIC_TYPE_ULELDATE:
		case MAGIC_TYPE_MEDATE:
		case MAGIC_TYPE_MELDATE:
		case MAGIC_TYPE_STRING:
		case MAGIC_TYPE_PSTRING:
		case MAGIC_TYPE_REGEX:
		case MAGIC_TYPE_SEARCH:
		case MAGIC_TYPE_DEFAULT:
		case MAGIC_TYPE_CLEAR:
			re = ml->root->format_string;
			break;
		}
	}

	bool res = (rz_regex_match(re, fmt, fmtlen, 0, RZ_REGEX_DEFAULT) > 0);
	if (!res) {
		RZ_LOG_WARN("bad format for %s: %%%.*s\n", ml->type_string,
			(int)fmtlen, fmt);
		return (-1);
	}

	return (0);
}

static ut32 magic_get_strength(RzMagicLine *ml) {
	int n;
	size_t size;

	if (ml->type == MAGIC_TYPE_NONE)
		return (0);

	if (ml->test_not || ml->test_operator == 'x') {
		n = 1;
		goto skip;
	}

	n = 2 * MAGIC_STRENGTH_MULTIPLIER;
	switch (ml->type) {
	case MAGIC_TYPE_NONE:
	case MAGIC_TYPE_DEFAULT:
		return (0);
	case MAGIC_TYPE_CLEAR:
	case MAGIC_TYPE_NAME:
	case MAGIC_TYPE_USE:
		break;
	case MAGIC_TYPE_BYTE:
	case MAGIC_TYPE_UBYTE:
		n += 1 * MAGIC_STRENGTH_MULTIPLIER;
		break;
	case MAGIC_TYPE_SHORT:
	case MAGIC_TYPE_USHORT:
	case MAGIC_TYPE_BESHORT:
	case MAGIC_TYPE_UBESHORT:
	case MAGIC_TYPE_LESHORT:
	case MAGIC_TYPE_ULESHORT:
		n += 2 * MAGIC_STRENGTH_MULTIPLIER;
		break;
	case MAGIC_TYPE_LONG:
	case MAGIC_TYPE_ULONG:
	case MAGIC_TYPE_FLOAT:
	case MAGIC_TYPE_DATE:
	case MAGIC_TYPE_LDATE:
	case MAGIC_TYPE_UDATE:
	case MAGIC_TYPE_ULDATE:
	case MAGIC_TYPE_BELONG:
	case MAGIC_TYPE_UBELONG:
	case MAGIC_TYPE_BEFLOAT:
	case MAGIC_TYPE_BEDATE:
	case MAGIC_TYPE_BELDATE:
	case MAGIC_TYPE_UBEDATE:
	case MAGIC_TYPE_UBELDATE:
		n += 4 * MAGIC_STRENGTH_MULTIPLIER;
		break;
	case MAGIC_TYPE_QUAD:
	case MAGIC_TYPE_UQUAD:
	case MAGIC_TYPE_DOUBLE:
	case MAGIC_TYPE_QDATE:
	case MAGIC_TYPE_QLDATE:
	case MAGIC_TYPE_UQDATE:
	case MAGIC_TYPE_UQLDATE:
	case MAGIC_TYPE_BEQUAD:
	case MAGIC_TYPE_UBEQUAD:
	case MAGIC_TYPE_BEDOUBLE:
	case MAGIC_TYPE_BEQDATE:
	case MAGIC_TYPE_BEQLDATE:
	case MAGIC_TYPE_UBEQDATE:
	case MAGIC_TYPE_UBEQLDATE:
	case MAGIC_TYPE_LEQUAD:
	case MAGIC_TYPE_ULEQUAD:
	case MAGIC_TYPE_LEDOUBLE:
	case MAGIC_TYPE_LEQDATE:
	case MAGIC_TYPE_LEQLDATE:
	case MAGIC_TYPE_ULEQDATE:
	case MAGIC_TYPE_ULEQLDATE:
	case MAGIC_TYPE_LELONG:
	case MAGIC_TYPE_ULELONG:
	case MAGIC_TYPE_LEFLOAT:
	case MAGIC_TYPE_LEDATE:
	case MAGIC_TYPE_LELDATE:
	case MAGIC_TYPE_ULEDATE:
	case MAGIC_TYPE_ULELDATE:
	case MAGIC_TYPE_MELONG:
	case MAGIC_TYPE_MEDATE:
	case MAGIC_TYPE_MELDATE:
		n += 8 * MAGIC_STRENGTH_MULTIPLIER;
		break;
	case MAGIC_TYPE_STRING:
	case MAGIC_TYPE_PSTRING:
		n += ml->test_string_size * MAGIC_STRENGTH_MULTIPLIER;
		break;
	case MAGIC_TYPE_BESTRING16:
	case MAGIC_TYPE_LESTRING16:
		n += ml->test_string_size * MAGIC_STRENGTH_MULTIPLIER / 2;
		break;
	case MAGIC_TYPE_REGEX:
	case MAGIC_TYPE_SEARCH:
		size = MAGIC_STRENGTH_MULTIPLIER / ml->test_string_size;
		if (size < 1)
			size = 1;
		n += ml->test_string_size * size;
		break;
	}
	switch (ml->test_operator) {
	case '=':
		n += MAGIC_STRENGTH_MULTIPLIER;
		break;
	case '<':
	case '>':
	case '[':
	case ']':
		n -= 2 * MAGIC_STRENGTH_MULTIPLIER;
		break;
	case '^':
	case '&':
		n -= MAGIC_STRENGTH_MULTIPLIER;
		break;
	}

skip:
	switch (ml->strength_operator) {
	case '+':
		n += ml->strength_value;
		break;
	case '-':
		n -= ml->strength_value;
		break;
	case '*':
		n *= ml->strength_value;
		break;
	case '/':
		n /= ml->strength_value;
		break;
	}
	return (n <= 0 ? 1 : n);
}

static int magic_get_string(char **line, char *out, size_t *outlen) {
	char *start, *cp, c;
	int d0, d1, d2;

	start = out;
	for (cp = *line; *cp != '\0' && !isspace((ut8)*cp); cp++) {
		if (*cp != '\\') {
			*out++ = *cp;
			continue;
		}

		switch (c = *++cp) {
		case '\0': /* end of line */
			return (-1);
		case ' ':
			*out++ = ' ';
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
			d0 = magic_odigit(cp[0]);
			if (cp[0] != '\0')
				d1 = magic_odigit(cp[1]);
			else
				d1 = -1;
			if (cp[0] != '\0' && cp[1] != '\0')
				d2 = magic_odigit(cp[2]);
			else
				d2 = -1;

			if (d0 != -1 && d1 != -1 && d2 != -1) {
				*out = d2 | (d1 << 3) | (d0 << 6);
				cp += 2;
			} else if (d0 != -1 && d1 != -1) {
				*out = d1 | (d0 << 3);
				cp++;
			} else if (d0 != -1)
				*out = d0;
			else
				return (-1);
			out++;
			break;
		case 'x':
			d0 = magic_xdigit(cp[1]);
			if (cp[1] != '\0')
				d1 = magic_xdigit(cp[2]);
			else
				d1 = -1;

			if (d0 != -1 && d1 != -1) {
				*out = d1 | (d0 << 4);
				cp += 2;
			} else if (d0 != -1) {
				*out = d0;
				cp++;
			} else
				return (-1);
			out++;

			break;
		case 'a':
			*out++ = '\a';
			break;
		case 'b':
			*out++ = '\b';
			break;
		case 't':
			*out++ = '\t';
			break;
		case 'f':
			*out++ = '\f';
			break;
		case 'n':
			*out++ = '\n';
			break;
		case 'r':
			*out++ = '\r';
			break;
		case '\\':
			*out++ = '\\';
			break;
		case '\'':
			*out++ = '\'';
			break;
		case '\"':
			*out++ = '\"';
			break;
		default:
			*out++ = c;
			break;
		}
	}
	*out = '\0';
	*outlen = out - start;

	*line = cp;
	return (0);
}

static int magic_parse_offset(RzMagicLine *ml, char **line) {
	char *copy, *s, *cp, *endptr;

	while (isspace((ut8) * *line))
		(*line)++;
	copy = s = cp = malloc(strlen(*line) + 1);
	while (**line != '\0' && !isspace((ut8) * *line))
		*cp++ = *(*line)++;
	*cp = '\0';

	ml->offset = 0;
	ml->offset_relative = 0;

	ml->indirect_type = ' ';
	ml->indirect_relative = 0;
	ml->indirect_offset = 0;
	ml->indirect_operator = ' ';
	ml->indirect_operand = 0;

	if (*s == '&') {
		ml->offset_relative = 1;
		s++;
	}

	if (*s != '(') {
		endptr = magic_strtoll(s, &ml->offset);
		if (endptr == NULL || *endptr != '\0') {
			RZ_LOG_WARN("missing closing bracket\n");
			goto fail;
		}
		if (ml->offset < 0 && !ml->offset_relative) {
			RZ_LOG_WARN("negative absolute offset\n");
			goto fail;
		}
		goto done;
	}
	s++;

	if (*s == '&') {
		ml->indirect_relative = 1;
		s++;
	}

	endptr = magic_strtoll(s, &ml->indirect_offset);
	if (endptr == NULL) {
		RZ_LOG_WARN("can't parse offset: %s\n", s);
		goto fail;
	}
	s = endptr;
	if (*s == ')')
		goto done;

	if (*s == '.') {
		s++;
		if (*s == '\0' || strchr("bslBSL", *s) == NULL) {
			RZ_LOG_WARN("unknown offset type: %c\n", *s);
			goto fail;
		}
		ml->indirect_type = *s;
		s++;
		if (*s == ')')
			goto done;
	}

	if (*s == '\0' || strchr("+-*", *s) == NULL) {
		RZ_LOG_WARN("unknown offset operator: %c\n", *s);
		goto fail;
	}
	ml->indirect_operator = *s;
	s++;
	if (*s == ')')
		goto done;

	if (*s == '(') {
		s++;
		endptr = magic_strtoll(s, &ml->indirect_operand);
		if (endptr == NULL || *endptr != ')') {
			RZ_LOG_WARN("missing closing bracket\n");
			goto fail;
		}
		if (*++endptr != ')') {
			RZ_LOG_WARN("missing closing bracket\n");
			goto fail;
		}
	} else {
		endptr = magic_strtoll(s, &ml->indirect_operand);
		if (endptr == NULL || *endptr != ')') {
			RZ_LOG_WARN("missing closing bracket\n");
			goto fail;
		}
	}

done:
	free(copy);
	return (0);

fail:
	free(copy);
	return (-1);
}

static int magic_parse_type(RzMagicLine *ml, char **line) {
	char *copy, *s, *cp, *endptr;

	while (isspace((ut8) * *line))
		(*line)++;
	copy = s = cp = malloc(strlen(*line) + 1);
	while (**line != '\0' && !isspace((ut8) * *line))
		*cp++ = *(*line)++;
	*cp = '\0';

	ml->type = MAGIC_TYPE_NONE;
	ml->type_operator = ' ';
	ml->type_operand = 0;

	if (strcmp(s, "name") == 0) {
		ml->type = MAGIC_TYPE_NAME;
		ml->type_string = rz_str_dup(s);
		goto done;
	}
	if (strcmp(s, "use") == 0) {
		ml->type = MAGIC_TYPE_USE;
		ml->type_string = rz_str_dup(s);
		goto done;
	}

	if (strncmp(s, "string", (sizeof "string") - 1) == 0 ||
		strncmp(s, "ustring", (sizeof "ustring") - 1) == 0) {
		if (*s == 'u')
			ml->type_string = rz_str_dup(s + 1);
		else
			ml->type_string = rz_str_dup(s);
		ml->type = MAGIC_TYPE_STRING;
		magic_mark_text(ml, 0);
		goto done;
	}
	if (strncmp(s, "pstring", (sizeof "pstring") - 1) == 0 ||
		strncmp(s, "upstring", (sizeof "upstring") - 1) == 0) {
		if (*s == 'u')
			ml->type_string = rz_str_dup(s + 1);
		else
			ml->type_string = rz_str_dup(s);
		ml->type = MAGIC_TYPE_PSTRING;
		magic_mark_text(ml, 0);
		goto done;
	}
	if (strncmp(s, "search", (sizeof "search") - 1) == 0 ||
		strncmp(s, "usearch", (sizeof "usearch") - 1) == 0) {
		if (*s == 'u')
			ml->type_string = rz_str_dup(s + 1);
		else
			ml->type_string = rz_str_dup(s);
		ml->type = MAGIC_TYPE_SEARCH;
		goto done;
	}
	if (strncmp(s, "regex", (sizeof "regex") - 1) == 0 ||
		strncmp(s, "uregex", (sizeof "uregex") - 1) == 0) {
		if (*s == 'u')
			ml->type_string = rz_str_dup(s + 1);
		else
			ml->type_string = rz_str_dup(s);
		ml->type = MAGIC_TYPE_REGEX;
		goto done;
	}
	ml->type_string = rz_str_dup(s);

	cp = &s[strcspn(s, "+-&/%*")];
	if (*cp != '\0') {
		ml->type_operator = *cp;
		endptr = magic_strtoull(cp + 1, (ut64 *)&ml->type_operand);
		if (endptr == NULL || *endptr != '\0') {
			RZ_LOG_WARN("can't parse operand: %s\n", cp + 1);
			goto fail;
		}
		*cp = '\0';
	}

	if (strcmp(s, "byte") == 0)
		ml->type = MAGIC_TYPE_BYTE;
	else if (strcmp(s, "short") == 0)
		ml->type = MAGIC_TYPE_SHORT;
	else if (strcmp(s, "long") == 0)
		ml->type = MAGIC_TYPE_LONG;
	else if (strcmp(s, "quad") == 0)
		ml->type = MAGIC_TYPE_QUAD;
	else if (strcmp(s, "ubyte") == 0)
		ml->type = MAGIC_TYPE_UBYTE;
	else if (strcmp(s, "ushort") == 0)
		ml->type = MAGIC_TYPE_USHORT;
	else if (strcmp(s, "ulong") == 0)
		ml->type = MAGIC_TYPE_ULONG;
	else if (strcmp(s, "uquad") == 0)
		ml->type = MAGIC_TYPE_UQUAD;
	else if (strcmp(s, "float") == 0 || strcmp(s, "ufloat") == 0)
		ml->type = MAGIC_TYPE_FLOAT;
	else if (strcmp(s, "double") == 0 || strcmp(s, "udouble") == 0)
		ml->type = MAGIC_TYPE_DOUBLE;
	else if (strcmp(s, "date") == 0)
		ml->type = MAGIC_TYPE_DATE;
	else if (strcmp(s, "qdate") == 0)
		ml->type = MAGIC_TYPE_QDATE;
	else if (strcmp(s, "ldate") == 0)
		ml->type = MAGIC_TYPE_LDATE;
	else if (strcmp(s, "qldate") == 0)
		ml->type = MAGIC_TYPE_QLDATE;
	else if (strcmp(s, "udate") == 0)
		ml->type = MAGIC_TYPE_UDATE;
	else if (strcmp(s, "uqdate") == 0)
		ml->type = MAGIC_TYPE_UQDATE;
	else if (strcmp(s, "uldate") == 0)
		ml->type = MAGIC_TYPE_ULDATE;
	else if (strcmp(s, "uqldate") == 0)
		ml->type = MAGIC_TYPE_UQLDATE;
	else if (strcmp(s, "beshort") == 0)
		ml->type = MAGIC_TYPE_BESHORT;
	else if (strcmp(s, "belong") == 0)
		ml->type = MAGIC_TYPE_BELONG;
	else if (strcmp(s, "bequad") == 0)
		ml->type = MAGIC_TYPE_BEQUAD;
	else if (strcmp(s, "ubeshort") == 0)
		ml->type = MAGIC_TYPE_UBESHORT;
	else if (strcmp(s, "ubelong") == 0)
		ml->type = MAGIC_TYPE_UBELONG;
	else if (strcmp(s, "ubequad") == 0)
		ml->type = MAGIC_TYPE_UBEQUAD;
	else if (strcmp(s, "befloat") == 0 || strcmp(s, "ubefloat") == 0)
		ml->type = MAGIC_TYPE_BEFLOAT;
	else if (strcmp(s, "bedouble") == 0 || strcmp(s, "ubedouble") == 0)
		ml->type = MAGIC_TYPE_BEDOUBLE;
	else if (strcmp(s, "bedate") == 0)
		ml->type = MAGIC_TYPE_BEDATE;
	else if (strcmp(s, "beqdate") == 0)
		ml->type = MAGIC_TYPE_BEQDATE;
	else if (strcmp(s, "beldate") == 0)
		ml->type = MAGIC_TYPE_BELDATE;
	else if (strcmp(s, "beqldate") == 0)
		ml->type = MAGIC_TYPE_BEQLDATE;
	else if (strcmp(s, "ubedate") == 0)
		ml->type = MAGIC_TYPE_UBEDATE;
	else if (strcmp(s, "ubeqdate") == 0)
		ml->type = MAGIC_TYPE_UBEQDATE;
	else if (strcmp(s, "ubeldate") == 0)
		ml->type = MAGIC_TYPE_UBELDATE;
	else if (strcmp(s, "ubeqldate") == 0)
		ml->type = MAGIC_TYPE_UBEQLDATE;
	else if (strcmp(s, "bestring16") == 0 || strcmp(s, "ubestring16") == 0)
		ml->type = MAGIC_TYPE_BESTRING16;
	else if (strcmp(s, "leshort") == 0)
		ml->type = MAGIC_TYPE_LESHORT;
	else if (strcmp(s, "lelong") == 0)
		ml->type = MAGIC_TYPE_LELONG;
	else if (strcmp(s, "lequad") == 0)
		ml->type = MAGIC_TYPE_LEQUAD;
	else if (strcmp(s, "uleshort") == 0)
		ml->type = MAGIC_TYPE_ULESHORT;
	else if (strcmp(s, "ulelong") == 0)
		ml->type = MAGIC_TYPE_ULELONG;
	else if (strcmp(s, "ulequad") == 0)
		ml->type = MAGIC_TYPE_ULEQUAD;
	else if (strcmp(s, "lefloat") == 0 || strcmp(s, "ulefloat") == 0)
		ml->type = MAGIC_TYPE_LEFLOAT;
	else if (strcmp(s, "ledouble") == 0 || strcmp(s, "uledouble") == 0)
		ml->type = MAGIC_TYPE_LEDOUBLE;
	else if (strcmp(s, "ledate") == 0)
		ml->type = MAGIC_TYPE_LEDATE;
	else if (strcmp(s, "leqdate") == 0)
		ml->type = MAGIC_TYPE_LEQDATE;
	else if (strcmp(s, "leldate") == 0)
		ml->type = MAGIC_TYPE_LELDATE;
	else if (strcmp(s, "leqldate") == 0)
		ml->type = MAGIC_TYPE_LEQLDATE;
	else if (strcmp(s, "uledate") == 0)
		ml->type = MAGIC_TYPE_ULEDATE;
	else if (strcmp(s, "uleqdate") == 0)
		ml->type = MAGIC_TYPE_ULEQDATE;
	else if (strcmp(s, "uleldate") == 0)
		ml->type = MAGIC_TYPE_ULELDATE;
	else if (strcmp(s, "uleqldate") == 0)
		ml->type = MAGIC_TYPE_ULEQLDATE;
	else if (strcmp(s, "lestring16") == 0 || strcmp(s, "ulestring16") == 0)
		ml->type = MAGIC_TYPE_LESTRING16;
	else if (strcmp(s, "melong") == 0 || strcmp(s, "umelong") == 0)
		ml->type = MAGIC_TYPE_MELONG;
	else if (strcmp(s, "medate") == 0 || strcmp(s, "umedate") == 0)
		ml->type = MAGIC_TYPE_MEDATE;
	else if (strcmp(s, "meldate") == 0 || strcmp(s, "umeldate") == 0)
		ml->type = MAGIC_TYPE_MELDATE;
	else if (strcmp(s, "default") == 0 || strcmp(s, "udefault") == 0)
		ml->type = MAGIC_TYPE_DEFAULT;
	else if (strcmp(s, "clear") == 0 || strcmp(s, "uclear") == 0)
		ml->type = MAGIC_TYPE_CLEAR;
	else {
		RZ_LOG_WARN("unknown type: %s\n", s);
		goto fail;
	}
	magic_mark_text(ml, 0);

done:
	free(copy);
	return (0);

fail:
	free(copy);
	return (-1);
}

static int magic_parse_value(RzMagicLine *ml, char **line) {
	char *copy, *s, *cp, *endptr;
	size_t slen;
	ut64 u;

	while (isspace((ut8) * *line))
		(*line)++;

	ml->test_operator = '=';
	ml->test_not = 0;
	ml->test_string = NULL;
	ml->test_string_size = 0;
	ml->test_unsigned = 0;
	ml->test_signed = 0;

	if (**line == '\0')
		return (0);

	s = *line;
	if (s[0] == 'x' && (s[1] == '\0' || isspace((ut8)s[1]))) {
		(*line)++;
		ml->test_operator = 'x';
		return (0);
	}

	if (ml->type == MAGIC_TYPE_DEFAULT || ml->type == MAGIC_TYPE_CLEAR) {
		RZ_LOG_DEBUG("test specified for default or clear\n");
		ml->test_operator = 'x';
		return (0);
	}

	if (**line == '!') {
		ml->test_not = 1;
		(*line)++;
	}

	switch (ml->type) {
	case MAGIC_TYPE_NAME:
	case MAGIC_TYPE_USE:
		copy = s = malloc(strlen(*line) + 1);
		if (magic_get_string(line, s, &slen) != 0 || slen == 0) {
			RZ_LOG_WARN("can't parse string\n");
			goto fail;
		}
		if (slen == 0 || *s == '\0' || strcmp(s, "^") == 0) {
			RZ_LOG_WARN("invalid name\n");
			goto fail;
		}
		ml->name = s;
		return (0); /* do not free */
	case MAGIC_TYPE_STRING:
	case MAGIC_TYPE_PSTRING:
	case MAGIC_TYPE_SEARCH:
		if (**line == '>' || **line == '<' || **line == '=') {
			ml->test_operator = **line;
			(*line)++;
		}
		/* FALLTHROUGH */
	case MAGIC_TYPE_REGEX:
		if (**line == '=')
			(*line)++;
		copy = s = malloc(strlen(*line) + 1);
		if (magic_get_string(line, s, &slen) != 0) {
			RZ_LOG_WARN("can't parse string\n");
			goto fail;
		}
		ml->test_string_size = slen;
		ml->test_string = s;
		return (0); /* do not free */
	default:
		break;
	}

	while (isspace((ut8) * *line))
		(*line)++;
	if ((*line)[0] == '<' && (*line)[1] == '=') {
		ml->test_operator = '[';
		(*line) += 2;
	} else if ((*line)[0] == '>' && (*line)[1] == '=') {
		ml->test_operator = ']';
		(*line) += 2;
	} else if (**line != '\0' && strchr("=<>&^", **line) != NULL) {
		ml->test_operator = **line;
		(*line)++;
	}

	while (isspace((ut8) * *line))
		(*line)++;
	copy = cp = malloc(strlen(*line) + 1);
	while (**line != '\0' && !isspace((ut8) * *line))
		*cp++ = *(*line)++;
	*cp = '\0';

	switch (ml->type) {
	case MAGIC_TYPE_FLOAT:
	case MAGIC_TYPE_DOUBLE:
	case MAGIC_TYPE_BEFLOAT:
	case MAGIC_TYPE_BEDOUBLE:
	case MAGIC_TYPE_LEFLOAT:
	case MAGIC_TYPE_LEDOUBLE:
		errno = 0;
		ml->test_double = strtod(copy, &endptr);
		if (errno == ERANGE)
			endptr = NULL;
		break;
	default:
		if (*ml->type_string == 'u')
			endptr = magic_strtoull(copy, &ml->test_unsigned);
		else {
			endptr = magic_strtoll(copy, &ml->test_signed);
			if (endptr == NULL || *endptr != '\0') {
				/*
				 * If we can't parse this as a signed number,
				 * try as unsigned instead.
				 */
				endptr = magic_strtoull(copy, &u);
				if (endptr != NULL && *endptr == '\0')
					ml->test_signed = (int64_t)u;
			}
		}
		break;
	}
	if (endptr == NULL || *endptr != '\0') {
		RZ_LOG_WARN("can't parse number: %s\n", copy);
		goto fail;
	}

	free(copy);
	return (0);

fail:
	free(copy);
	return (-1);
}

int magic_compare(const void *incoming, const RBNode *in_tree, void *user) {
	RzMagicLine *ml1 = (RzMagicLine *)incoming;
	const RzMagicLine *ml2 = container_of(in_tree, const RzMagicLine, rb);

	if (ml1->strength < ml2->strength)
		return (1);
	if (ml1->strength > ml2->strength)
		return (-1);

	/*
	 * The original file depends on the (undefined!) qsort(3) behaviour
	 * when the strength is equal. This is impossible to reproduce with an
	 * RB tree so just use the line number and hope for the best.
	 */
	if (ml1->line < ml2->line)
		return (-1);
	if (ml1->line > ml2->line)
		return (1);

	return (0);
}

int magic_named_compare(const void *incoming, const RBNode *in_tree, void *user) {
	RzMagicLine *ml1 = (RzMagicLine *)incoming;
	const RzMagicLine *ml2 = container_of(in_tree, const RzMagicLine, rb);

	return strcmp(ml1->name, ml2->name);
}

static void magic_adjust_strength(RzMagic *m, ut32 at, RzMagicLine *ml,
	char *line) {
	char *cp, *s;
	int64_t value;

	cp = line + (sizeof "!:strength") - 1;
	while (isspace((ut8)*cp))
		cp++;
	s = cp;

	cp = strchr(s, '#');
	if (cp != NULL)
		*cp = '\0';
	cp = s;

	if (*s == '\0' || strchr("+-*/", *s) == NULL) {
		RZ_LOG_DEBUG("invalid strength operator: %s\n", s);
		return;
	}
	ml->strength_operator = *cp++;

	while (isspace((ut8)*cp))
		cp++;
	cp = magic_strtoll(cp, &value);
	while (cp != NULL && isspace((ut8)*cp))
		cp++;
	if (cp == NULL || *cp != '\0' || value < 0 || value > 255) {
		RZ_LOG_DEBUG("invalid strength value: %s\n", s);
		return;
	}
	ml->strength_value = value;
}

static void magic_set_mimetype(RzMagic *m, ut32 at, RzMagicLine *ml, char *line) {
	char *mimetype, *cp;

	mimetype = line + (sizeof "!:mime") - 1;
	while (isspace((ut8)*mimetype))
		mimetype++;

	cp = strchr(mimetype, '#');
	if (cp != NULL)
		*cp = '\0';

	if (*mimetype != '\0') {
		cp = mimetype + strlen(mimetype) - 1;
		while (cp != mimetype && isspace((ut8)*cp))
			*cp-- = '\0';
	}

	cp = mimetype;
	while (*cp != '\0') {
		if (!isalnum((ut8)*cp) && strchr("/-.+", *cp) == NULL)
			break;
		cp++;
	}
	if (*mimetype == '\0' || *cp != '\0') {
		RZ_LOG_DEBUG("invalid MIME type: %s\n", mimetype);
		return;
	}
	if (ml == NULL) {
		RZ_LOG_DEBUG("stray MIME type: %s\n", mimetype);
		return;
	}
	ml->mimetype = rz_str_dup(mimetype);
}

bool magic_load(RZ_NONNULL RZ_BORROW RzMagic *m, RZ_NONNULL FILE *f) {
	rz_return_val_if_fail(m, false);
	rz_return_val_if_fail(f, false);

	RzMagicLine *ml = NULL, *parent, *parent0;
	size_t size = 4092;
	char *tmp = RZ_NEWS0(char, size);
	char *line = NULL;
	ut32 at, level, n, i;

	parent = NULL;
	parent0 = NULL;
	level = 0;

	at = 0;

	while (fgets(tmp, size, f)) {
		at++;
		line = tmp;
		while (isspace((ut8)*line))
			line++;

		if (*line == '\0' || *line == '#')
			continue;

		char *newline_remover = line;
		while (*newline_remover != '\n')
			newline_remover++;
		*newline_remover = '\0';

		if (strncmp(line, "!:mime", 6) == 0) {
			magic_set_mimetype(m, at, ml, line);
			continue;
		}
		if (strncmp(line, "!:strength", 10) == 0) {
			magic_adjust_strength(m, at, ml, line);
			continue;
		}
		if (strncmp(line, "!:", 2) == 0) {
			for (i = 0; i < 64 && line[i] != '\0'; i++) {
				if (isspace((ut8)line[i]))
					break;
			}
			RZ_LOG_DEBUG("%.*s not supported\n", i, line);
			continue;
		}

		n = 0;
		for (; *line == '>'; line++)
			n++;

		ml = rz_magic_line_new();

		if (!ml) {
			free(tmp);
			return false;
		}

		ml->root = m;
		ml->line = at;
		ml->type = MAGIC_TYPE_NONE;
		ml->text = 1;

		/*
		 * At this point n is the level we want, level is the current
		 * level. parent0 is the last line at the same level and parent
		 * is the last line at the previous level.
		 */
		if (n == level + 1) {
			parent = parent0;
		} else if (n < level) {
			for (i = n; i < level && parent != NULL; i++)
				parent = parent->parent;
		} else if (n != level) {
			RZ_LOG_DEBUG("level skipped (%u->%u)\n", level, n);
			RZ_FREE_CUSTOM(ml, rz_magic_line_free);
			continue;
		}
		ml->parent = parent;
		level = n;

		if (magic_parse_offset(ml, &line) != 0 ||
			magic_parse_type(ml, &line) != 0 ||
			magic_parse_value(ml, &line) != 0 ||
			magic_set_result(ml, line) != 0) {
			/*
			 * An invalid line still needs to appear in the tree in
			 * case it has any children.
			 */
			ml->type = MAGIC_TYPE_NONE;
		}

		ml->strength = magic_get_strength(ml);
		if (ml->parent == NULL) {
			if (ml->name != NULL) {
				rz_rbtree_insert(&m->magic_named_tree, ml, &ml->rb, magic_named_compare, NULL);
			} else {
				rz_rbtree_insert(&m->magic_tree, ml, &ml->rb, magic_compare, NULL);
			}
		} else {
			rz_list_append(ml->parent->children, ml);
		}
		parent0 = ml;
	}
	free(tmp);
	return true;
}
