/* $OpenBSD: magic-test.c,v 1.27 2019/01/15 09:24:59 nicm Exp $ */

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

#include "magic.h"
#include "rz_util.h"

static int file_vprintf(char **s, const char *fmt, va_list ap) {
	va_list ap2;
	char cbuf[4096];
	char *buf, *newstr;

	va_copy(ap2, ap);
	int len = vsnprintf(cbuf, sizeof(cbuf), fmt, ap2);
	va_end(ap2);
	if (len < 0) {
		return -1;
	}
	if (len > sizeof(cbuf)) {
		buf = malloc(len + 1);
		va_copy(ap2, ap);
		(void)vsnprintf(buf, len + 1, fmt, ap2);
		va_end(ap2);
	} else {
		int nullbyte = len;
		if (nullbyte > 0 && nullbyte == sizeof(cbuf)) {
			nullbyte--;
		}
		cbuf[nullbyte] = 0;
		buf = strdup(cbuf);
	}
	if (!buf) {
		return -1;
	}

	int buflen = len;
	if (*s) {
		char *iter = *s;
		while (*iter != '\n') {
			iter++;
		}
		*iter = '\0';

		int obuflen = strlen(*s);
		len = obuflen + buflen + 1;
		newstr = malloc(len);
		if (!newstr) {
			free(buf);
			return -1;
		}
		memcpy(newstr, *s, obuflen);
		memcpy(newstr + obuflen, buf, buflen);
		newstr[len - 1] = 0;
		free(buf);
		free(*s);
		if (len < 0) {
			free(newstr);
			return -1;
		}
		buf = newstr;
	}
	*s = buf;
	return 0;
}

/*
 * Like printf, only we append to a buffer.
 */
int file_printf(char **s, const char *fmt, ...) {
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = file_vprintf(s, fmt, ap);
	va_end(ap);
	return ret;
}

static int magic_test_line(RzMagicLine *, RzMagicState *);

static RzMagicLine *magic_get_named(RzMagic *m, char *name) {
	RzMagicLine ml;

	ml.name = name;

	RBNode *node = rz_rbtree_find(m->magic_named_tree, &ml, magic_named_compare, NULL);
	if (!node) {
		return NULL;
	}
	RzMagicLine *var = container_of(node, RzMagicLine, rb);
	if (!var) {
		return NULL;
	}
	return var;
}

static enum magic_type magic_reverse_type(RzMagicState *ms, enum magic_type type) {
	if (!ms->reverse)
		return (type);
	switch (type) {
	case MAGIC_TYPE_BESHORT:
		return (MAGIC_TYPE_LESHORT);
	case MAGIC_TYPE_BELONG:
		return (MAGIC_TYPE_LELONG);
	case MAGIC_TYPE_BEQUAD:
		return (MAGIC_TYPE_LEQUAD);
	case MAGIC_TYPE_UBESHORT:
		return (MAGIC_TYPE_ULESHORT);
	case MAGIC_TYPE_UBELONG:
		return (MAGIC_TYPE_ULELONG);
	case MAGIC_TYPE_UBEQUAD:
		return (MAGIC_TYPE_ULEQUAD);
	case MAGIC_TYPE_BEFLOAT:
		return (MAGIC_TYPE_LEFLOAT);
	case MAGIC_TYPE_BEDOUBLE:
		return (MAGIC_TYPE_LEDOUBLE);
	case MAGIC_TYPE_BEDATE:
		return (MAGIC_TYPE_LEDATE);
	case MAGIC_TYPE_BEQDATE:
		return (MAGIC_TYPE_LEQDATE);
	case MAGIC_TYPE_BELDATE:
		return (MAGIC_TYPE_LELDATE);
	case MAGIC_TYPE_BEQLDATE:
		return (MAGIC_TYPE_LEQLDATE);
	case MAGIC_TYPE_UBEDATE:
		return (MAGIC_TYPE_ULEDATE);
	case MAGIC_TYPE_UBEQDATE:
		return (MAGIC_TYPE_ULEQDATE);
	case MAGIC_TYPE_UBELDATE:
		return (MAGIC_TYPE_ULELDATE);
	case MAGIC_TYPE_UBEQLDATE:
		return (MAGIC_TYPE_ULEQLDATE);
	case MAGIC_TYPE_LESHORT:
		return (MAGIC_TYPE_BESHORT);
	case MAGIC_TYPE_LELONG:
		return (MAGIC_TYPE_LELONG);
	case MAGIC_TYPE_LEQUAD:
		return (MAGIC_TYPE_LEQUAD);
	case MAGIC_TYPE_ULESHORT:
		return (MAGIC_TYPE_UBESHORT);
	case MAGIC_TYPE_ULELONG:
		return (MAGIC_TYPE_UBELONG);
	case MAGIC_TYPE_ULEQUAD:
		return (MAGIC_TYPE_UBEQUAD);
	case MAGIC_TYPE_LEFLOAT:
		return (MAGIC_TYPE_BEFLOAT);
	case MAGIC_TYPE_LEDOUBLE:
		return (MAGIC_TYPE_BEDOUBLE);
	case MAGIC_TYPE_LEDATE:
		return (MAGIC_TYPE_BEDATE);
	case MAGIC_TYPE_LEQDATE:
		return (MAGIC_TYPE_BEQDATE);
	case MAGIC_TYPE_LELDATE:
		return (MAGIC_TYPE_BELDATE);
	case MAGIC_TYPE_LEQLDATE:
		return (MAGIC_TYPE_BEQLDATE);
	case MAGIC_TYPE_ULEDATE:
		return (MAGIC_TYPE_UBEDATE);
	case MAGIC_TYPE_ULEQDATE:
		return (MAGIC_TYPE_UBEQDATE);
	case MAGIC_TYPE_ULELDATE:
		return (MAGIC_TYPE_UBELDATE);
	case MAGIC_TYPE_ULEQLDATE:
		return (MAGIC_TYPE_UBEQLDATE);
	default:
		return (type);
	}
}

static int magic_one_eq(char a, char b, int cflag) {
	if (a == b)
		return (1);
	if (cflag && islower((ut8)b) && tolower((ut8)a) == (ut8)b)
		return (1);
	return (0);
}

static int magic_test_eq(const char *ap, size_t asize, const char *bp, size_t bsize,
	int cflag, int bflag, int Bflag) {
	size_t aoff, boff, aspaces, bspaces;

	aoff = boff = 0;
	while (aoff != asize && boff != bsize) {
		if (Bflag && isspace((ut8)ap[aoff])) {
			aspaces = 0;
			while (aoff != asize && isspace((ut8)ap[aoff])) {
				aspaces++;
				aoff++;
			}
			bspaces = 0;
			while (boff != bsize && isspace((ut8)bp[boff])) {
				bspaces++;
				boff++;
			}
			if (bspaces >= aspaces)
				continue;
			return (1);
		}
		if (magic_one_eq(ap[aoff], bp[boff], cflag)) {
			aoff++;
			boff++;
			continue;
		}
		if (bflag && isspace((ut8)bp[boff])) {
			boff++;
			continue;
		}
		if (ap[aoff] < bp[boff])
			return (-1);
		return (1);
	}
	return (0);
}

static int magic_copy_from(RzMagicState *ms, ssize_t offset, void *dst, size_t size) {
	if (offset < 0)
		offset = ms->offset;
	if (offset + size > ms->size)
		return (-1);
	memcpy(dst, ms->base + offset, size);
	return (0);
}

static void magic_add_result(RzMagicState *ms, RzMagicLine *ml,
	const char *fmt, ...) {
	va_list ap;
	int separate;
	char *s = NULL, *tmp = NULL, *add = NULL;

	va_start(ap, fmt);
	if (ml->stringify) {
		if (file_vprintf(&s, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
		if (file_printf(&tmp, ml->result, s) == -1) {
			free(s);
			return;
		}
		free(s);
	} else {
		if (file_vprintf(&tmp, ml->result, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	separate = 1;
	if (tmp[0] == '\\' && tmp[1] == 'b') {
		separate = 0;
		add = tmp + 2;
	} else
		add = tmp;

	if (separate && *ms->out != '\0')
		rz_str_ncat(ms->out, " ", sizeof ms->out);
	rz_str_ncat(ms->out, add, sizeof ms->out);

	free(tmp);
}

static void magic_add_string(RzMagicState *ms, RzMagicLine *ml,
	const char *s, size_t slen) {
	char *out, *safe_s;
	size_t outlen, offset;

	outlen = MAGIC_STRING_SIZE;
	if (outlen > slen)
		outlen = slen;
	for (offset = 0; offset < outlen; offset++) {
		if (s[offset] == '\0' || !isprint((ut8)s[offset])) {
			outlen = offset;
			break;
		}
	}
	safe_s = malloc(outlen + 1);
	if (!safe_s) {
		return;
	}
	memcpy(safe_s, s, outlen);
	safe_s[outlen] = '\0';
	RzStrEscOptions opt = {
		.show_asciidot = true,
		.esc_bslash = true,
		.esc_double_quotes = true,
		.dot_nl = true, // VIS_NL
		.keep_printable = true,
	};
	out = rz_str_escape_utf8(safe_s, &opt);

	magic_add_result(ms, ml, "%s", out);
	free(out);
	free(safe_s);
}

static int magic_test_signed(RzMagicLine *ml, int64_t value, int64_t wanted) {
	switch (ml->test_operator) {
	case 'x':
		return (1);
	case '<':
		return (value < wanted);
	case '[':
		return (value <= wanted);
	case '>':
		return (value > wanted);
	case ']':
		return (value >= wanted);
	case '=':
		return (value == wanted);
	case '&':
		return ((value & wanted) == wanted);
	case '^':
		return ((~value & wanted) == wanted);
	}
	return (-1);
}

static int magic_test_unsigned(RzMagicLine *ml, uint64_t value, uint64_t wanted) {
	switch (ml->test_operator) {
	case 'x':
		return (1);
	case '<':
		return (value < wanted);
	case '[':
		return (value <= wanted);
	case '>':
		return (value > wanted);
	case ']':
		return (value >= wanted);
	case '=':
		return (value == wanted);
	case '&':
		return ((value & wanted) == wanted);
	case '^':
		return ((~value & wanted) == wanted);
	}
	return (-1);
}

static int magic_test_double(RzMagicLine *ml, double value, double wanted) {
	switch (ml->test_operator) {
	case 'x':
		return (1);
	case '=':
		return (value == wanted);
	}
	return (-1);
}

static int magic_test_type_none(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (0);
}

static int magic_test_type_byte(RzMagicLine *ml, RzMagicState *ms) {
	int8_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);

	if (ml->type_operator == '&')
		value &= (int8_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (int8_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (int8_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (int8_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (int8_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (int8_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_signed(ml, value, (int8_t)ml->test_signed);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%c", (int)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_short(RzMagicLine *ml, RzMagicState *ms) {
	int16_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BESHORT))
		value = rz_read_be16(&value);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LESHORT))
		value = rz_read_le16(&value);
	if (ml->type_operator == '&')
		value &= (int16_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (int16_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (int16_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (int16_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (int16_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (int16_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_signed(ml, value, (int16_t)ml->test_signed);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%hd", (int)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_long(RzMagicLine *ml, RzMagicState *ms) {
	int32_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BELONG))
		value = rz_read_be32(&value);

	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LELONG))
		value = rz_read_le32(&value);

	if (ml->type_operator == '&')
		value &= (int32_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (int32_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (int32_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (int32_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (int32_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (int32_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_signed(ml, value, (int32_t)ml->test_signed);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%d", (int)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_quad(RzMagicLine *ml, RzMagicState *ms) {
	int64_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEQUAD))
		value = rz_read_be64(&value);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEQUAD))
		value = rz_read_le64(&value);

	if (ml->type_operator == '&')
		value &= (int64_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (int64_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (int64_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (int64_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (int64_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (int64_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_signed(ml, value, (int64_t)ml->test_signed);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%lld", (long long)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_ubyte(RzMagicLine *ml, RzMagicState *ms) {
	uint8_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);

	if (ml->type_operator == '&')
		value &= (uint8_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (uint8_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (uint8_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (uint8_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (uint8_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (uint8_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_unsigned(ml, value, (uint8_t)ml->test_unsigned);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%c", (unsigned int)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_ushort(RzMagicLine *ml, RzMagicState *ms) {
	uint16_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == MAGIC_TYPE_UBESHORT)
		value = rz_read_be16(&value);
	if (ml->type == MAGIC_TYPE_ULESHORT)
		value = rz_read_le16(&value);

	if (ml->type_operator == '&')
		value &= (uint16_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (uint16_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (uint16_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (uint16_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (uint16_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (uint16_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_unsigned(ml, value, (uint16_t)ml->test_unsigned);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%hu", (unsigned int)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_ulong(RzMagicLine *ml, RzMagicState *ms) {
	uint32_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == MAGIC_TYPE_UBELONG)
		value = rz_read_be32(&value);
	if (ml->type == MAGIC_TYPE_ULELONG)
		value = rz_read_le32(&value);

	if (ml->type_operator == '&')
		value &= (uint32_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (uint32_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (uint32_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (uint32_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (uint32_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (uint32_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_unsigned(ml, value, (uint32_t)ml->test_unsigned);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%u", (unsigned int)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_uquad(RzMagicLine *ml, RzMagicState *ms) {
	uint64_t value;
	int result;

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == MAGIC_TYPE_UBEQUAD)
		value = rz_read_be64(&value);
	if (ml->type == MAGIC_TYPE_ULEQUAD)
		value = rz_read_le64(&value);

	if (ml->type_operator == '&')
		value &= (uint64_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (uint64_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (uint64_t)ml->type_operand;
	else if (ml->type_operator == '/')
		value /= (uint64_t)ml->type_operand;
	else if (ml->type_operator == '%')
		value %= (uint64_t)ml->type_operand;
	else if (ml->type_operator == '*')
		value *= (uint64_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_unsigned(ml, value, (uint64_t)ml->test_unsigned);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%llu", (unsigned long long)value);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_float(RzMagicLine *ml, RzMagicState *ms) {
	uint32_t value0;
	float value;
	int result;

	if (magic_copy_from(ms, -1, &value0, sizeof value0) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEFLOAT))
		value0 = rz_read_be32(&value0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEFLOAT))
		value0 = rz_read_le32(&value0);
	memcpy(&value, &value0, sizeof value);

	if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_double(ml, value, (float)ml->test_double);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%g", value);
		ms->offset += sizeof value0;
	}
	return (1);
}

static int
magic_test_type_double(RzMagicLine *ml, RzMagicState *ms) {
	uint64_t value0;
	double value;
	int result;

	if (magic_copy_from(ms, -1, &value0, sizeof value0) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEDOUBLE))
		value0 = rz_read_be64(&value0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEDOUBLE))
		value0 = rz_read_le64(&value0);
	memcpy(&value, &value0, sizeof value);

	if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_double(ml, value, (double)ml->test_double);
	if (result == !ml->test_not && ml->result != NULL) {
		magic_add_result(ms, ml, "%g", value);
		ms->offset += sizeof value0;
	}
	return (1);
}

static int magic_test_type_string(RzMagicLine *ml, RzMagicState *ms) {
	const char *s, *cp;
	size_t slen;
	int result, cflag = 0, bflag = 0, Bflag = 0;

	cp = &ml->type_string[(sizeof "string") - 1];
	if (*cp != '\0') {
		if (*cp != '/')
			return (-1);
		cp++;
		for (; *cp != '\0'; cp++) {
			switch (*cp) {
			case 'B':
			case 'W':
				Bflag = 1;
				break;
			case 'b':
			case 'w':
				bflag = 1;
				break;
			case 'c':
				cflag = 1;
				break;
			case 't':
				break;
			default:
				return (-1);
			}
		}
	}

	s = ms->base + ms->offset;
	slen = ms->size - ms->offset;
	if (slen < ml->test_string_size)
		return (0);

	result = magic_test_eq(s, slen, ml->test_string, ml->test_string_size,
		cflag, bflag, Bflag);
	switch (ml->test_operator) {
	case 'x':
		result = 1;
		break;
	case '<':
		result = result < 0;
		break;
	case '>':
		result = result > 0;
		break;
	case '=':
		slen = ml->test_string_size; /* only print what was found */
		result = result == 0;
		break;
	default:
		result = -1;
		break;
	}
	if (result == !ml->test_not) {
		if (ml->result != NULL)
			magic_add_string(ms, ml, s, slen);
		if (result && ml->test_operator == '=')
			ms->offset = s - ms->base + ml->test_string_size;
	}
	return (result);
}

static int magic_test_type_pstring(RzMagicLine *ml, RzMagicState *ms) {
	const char *s, *cp;
	size_t slen;
	int result;

	cp = &ml->type_string[(sizeof "pstring") - 1];
	if (*cp != '\0') {
		if (*cp != '/')
			return (-1);
		cp++;
		for (; *cp != '\0'; cp++) {
			switch (*cp) {
			default:
				return (-1);
			}
		}
	}

	s = ms->base + ms->offset;
	if (ms->size - ms->offset < 1)
		return (-1);
	slen = *(ut8 *)s;
	if (slen + 1 > ms->size - ms->offset)
		return (-1);
	s++;

	if (slen < ml->test_string_size)
		result = -1;
	else if (slen > ml->test_string_size)
		result = 1;
	else
		result = memcmp(s, ml->test_string, ml->test_string_size);
	switch (ml->test_operator) {
	case 'x':
		result = 1;
		break;
	case '<':
		result = result < 0;
		break;
	case '>':
		result = result > 0;
		break;
	case '=':
		result = result == 0;
		break;
	default:
		result = -1;
		break;
	}
	if (result == !ml->test_not) {
		if (ml->result != NULL)
			magic_add_string(ms, ml, s, slen);
		if (result && ml->test_operator == '=')
			ms->offset += slen + 1;
	}
	return (result);
}

static int magic_test_type_date(RzMagicLine *ml, RzMagicState *ms) {
	int32_t value;
	int result;
	time_t t;
	char s[64];

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEDATE) ||
		ml->type == magic_reverse_type(ms, MAGIC_TYPE_BELDATE))
		value = rz_read_be32(&value);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEDATE) ||
		ml->type == magic_reverse_type(ms, MAGIC_TYPE_LELDATE))
		value = rz_read_le32(&value);

	if (ml->type_operator == '&')
		value &= (int32_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (int32_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (int32_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_signed(ml, value, (int32_t)ml->test_signed);
	if (result == !ml->test_not && ml->result != NULL) {
		t = value;
		switch (ml->type) {
		case MAGIC_TYPE_LDATE:
		case MAGIC_TYPE_LELDATE:
		case MAGIC_TYPE_BELDATE:
			rz_ctime_r(&t, s);
			break;
		default:
			rz_asctime_r(gmtime(&t), s);
			break;
		}
		s[strcspn(s, "\n")] = '\0';
		magic_add_result(ms, ml, "%s", s);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_qdate(RzMagicLine *ml, RzMagicState *ms) {
	int64_t value;
	int result;
	time_t t;
	char s[64];

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEQDATE) ||
		ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEQLDATE))
		value = rz_read_be64(&value);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEQDATE) ||
		ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEQLDATE))
		value = rz_read_le64(&value);

	if (ml->type_operator == '&')
		value &= (int64_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (int64_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (int64_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_signed(ml, value, (int64_t)ml->test_signed);
	if (result == !ml->test_not && ml->result != NULL) {
		t = value;
		switch (ml->type) {
		case MAGIC_TYPE_QLDATE:
		case MAGIC_TYPE_LEQLDATE:
		case MAGIC_TYPE_BEQLDATE:
			rz_ctime_r(&t, s);
			break;
		default:
			rz_asctime_r(gmtime(&t), s);
			break;
		}
		s[strcspn(s, "\n")] = '\0';
		magic_add_result(ms, ml, "%s", s);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_udate(RzMagicLine *ml, RzMagicState *ms) {
	uint32_t value;
	int result;
	time_t t;
	char s[64];

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_BEDATE) ||
		ml->type == magic_reverse_type(ms, MAGIC_TYPE_BELDATE))
		value = rz_read_be32(&value);
	if (ml->type == magic_reverse_type(ms, MAGIC_TYPE_LEDATE) ||
		ml->type == magic_reverse_type(ms, MAGIC_TYPE_LELDATE))
		value = rz_read_le32(&value);

	if (ml->type_operator == '&')
		value &= (uint32_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (uint32_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (uint32_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_unsigned(ml, value, (uint32_t)ml->test_unsigned);
	if (result == !ml->test_not && ml->result != NULL) {
		t = value;
		switch (ml->type) {
		case MAGIC_TYPE_LDATE:
		case MAGIC_TYPE_LELDATE:
		case MAGIC_TYPE_BELDATE:
			rz_ctime_r(&t, s);
			break;
		default:
			rz_asctime_r(gmtime(&t), s);
			break;
		}
		s[strcspn(s, "\n")] = '\0';
		magic_add_result(ms, ml, "%s", s);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_uqdate(RzMagicLine *ml, RzMagicState *ms) {
	uint64_t value;
	int result;
	time_t t;
	char s[64];

	if (magic_copy_from(ms, -1, &value, sizeof value) != 0)
		return (0);
	if (ml->type == MAGIC_TYPE_UBEQDATE ||
		ml->type == MAGIC_TYPE_UBEQLDATE)
		value = rz_read_be64(&value);
	if (ml->type == MAGIC_TYPE_ULEQDATE ||
		ml->type == MAGIC_TYPE_ULEQLDATE)
		value = rz_read_le64(&value);

	if (ml->type_operator == '&')
		value &= (uint64_t)ml->type_operand;
	else if (ml->type_operator == '-')
		value -= (uint64_t)ml->type_operand;
	else if (ml->type_operator == '+')
		value += (uint64_t)ml->type_operand;
	else if (ml->type_operator != ' ')
		return (-1);

	result = magic_test_unsigned(ml, value, (uint64_t)ml->test_unsigned);
	if (result == !ml->test_not && ml->result != NULL) {
		t = value;
		switch (ml->type) {
		case MAGIC_TYPE_UQLDATE:
		case MAGIC_TYPE_ULEQLDATE:
		case MAGIC_TYPE_UBEQLDATE:
			rz_ctime_r(&t, s);
			break;
		default:
			rz_asctime_r(gmtime(&t), s);
			break;
		}
		s[strcspn(s, "\n")] = '\0';
		magic_add_result(ms, ml, "%s", s);
		ms->offset += sizeof value;
	}
	return (result);
}

static int magic_test_type_bestring16(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (-2);
}

static int magic_test_type_lestring16(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (-2);
}

static int magic_test_type_melong(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (-2);
}

static int magic_test_type_medate(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (-2);
}

static int magic_test_type_meldate(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (-2);
}

static int magic_test_type_regex(RzMagicLine *ml, RzMagicState *ms) {
	const char *cp;
	RzRegex *re;
	int flags = 0, sflag = 0;

	cp = &ml->type_string[(sizeof "regex") - 1];
	if (*cp != '\0') {
		if (*cp != '/')
			return (-1);
		cp++;
		for (; *cp != '\0'; cp++) {
			switch (*cp) {
			case 's':
				sflag = 1;
				break;
			case 'c':
				flags |= RZ_REGEX_CASELESS;
				break;
			default:
				return (-1);
			}
		}
	}
	re = rz_regex_new(ml->test_string, RZ_REGEX_EXTENDED | RZ_REGEX_MULTILINE | flags, RZ_REGEX_DEFAULT, NULL);
	if (!re) {
		return -1;
	}

	bool res = true;
	RzPVector *matches = rz_regex_match_first(re, ms->base, ms->size, ms->offset, RZ_REGEX_DEFAULT);
	if (!matches || rz_pvector_empty(matches)) {
		res = false;
	}
	if (res == !ml->test_not) {
		RzRegexMatch *match = NULL;
		if (ml->result != NULL && res) {
			match = rz_pvector_at(matches, 0);
			magic_add_string(ms, ml, ms->base + match->start,
				match->len);
		}
		if (res && match) {
			if (sflag)
				ms->offset = match->start;
			else
				ms->offset = match->start + match->len;
		}
	}
	rz_pvector_free(matches);
	rz_regex_free(re);
	return (res);
}

static int magic_test_type_search(RzMagicLine *ml, RzMagicState *ms) {
	const char *cp, *endptr, *start, *found;
	size_t size, end, i;
	ut64 range;
	int result, n, cflag = 0, bflag = 0, Bflag = 0;

	cp = &ml->type_string[(sizeof "search") - 1];
	if (*cp != '\0') {
		if (*cp != '/')
			return (-1);
		cp++;

		endptr = magic_strtoull(cp, &range);
		if (endptr == NULL || (*endptr != '/' && *endptr != '\0'))
			return (-1);

		if (*endptr == '/') {
			for (cp = endptr + 1; *cp != '\0'; cp++) {
				switch (*cp) {
				case 'B':
				case 'W':
					Bflag = 1;
					break;
				case 'b':
				case 'w':
					bflag = 1;
					break;
				case 'c':
					cflag = 1;
					break;
				case 't':
					break;
				default:
					return (-1);
				}
			}
		}
	} else
		range = UINT64_MAX;
	if (range > (uint64_t)ms->size - ms->offset)
		range = ms->size - ms->offset;
	size = ml->test_string_size;

	/* Want to search every starting position from up to range + size. */
	end = range + size;
	if (end > ms->size - ms->offset) {
		if (size > ms->size - ms->offset)
			end = 0;
		else
			end = ms->size - ms->offset - size;
	}

	/*
	 * < and > and the flags are only in /etc/magic with search/1 so don't
	 * support them with anything else.
	 */
	start = ms->base + ms->offset;
	if (end == 0)
		found = NULL;
	else if (ml->test_operator == 'x')
		found = start;
	else if (range == 1) {
		n = magic_test_eq(start, ms->size - ms->offset, ml->test_string,
			size, cflag, bflag, Bflag);
		if (n == -1 && ml->test_operator == '<')
			found = start;
		else if (n == 1 && ml->test_operator == '>')
			found = start;
		else if (n == 0 && ml->test_operator == '=')
			found = start;
		else
			found = NULL;
	} else {
		if (ml->test_operator != '=')
			return (-2);
		for (i = 0; i < end; i++) {
			n = magic_test_eq(start + i, ms->size - ms->offset - i,
				ml->test_string, size, cflag, bflag, Bflag);
			if (n == 0) {
				found = start + i;
				break;
			}
		}
		if (i == end)
			found = NULL;
	}
	result = (found != NULL);

	if (result == !ml->test_not) {
		if (ml->result != NULL)
			magic_add_string(ms, ml, found, ms->size - ms->offset);
		if (result && found != NULL && ml->test_operator == '=')
			ms->offset = (found + size) - ms->base;
	}
	return (result);
}

static int magic_test_type_default(RzMagicLine *ml, RzMagicState *ms) {
	if (!ms->matched && ml->result != NULL)
		magic_add_result(ms, ml, "%s", "");
	return (!ms->matched);
}

static int magic_test_type_clear(RzMagicLine *ml, RzMagicState *ms) {
	if (ml->result != NULL)
		magic_add_result(ms, ml, "%s", "");
	return (1);
}

static int magic_test_type_name(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (-1);
}

static int magic_test_type_use(RZ_UNUSED RzMagicLine *ml,
	RZ_UNUSED RzMagicState *ms) {
	return (1);
}

static int (*magic_test_functions[])(RzMagicLine *,
	RzMagicState *) = {
	magic_test_type_none,
	magic_test_type_byte,
	magic_test_type_short,
	magic_test_type_long,
	magic_test_type_quad,
	magic_test_type_ubyte,
	magic_test_type_ushort,
	magic_test_type_ulong,
	magic_test_type_uquad,
	magic_test_type_float,
	magic_test_type_double,
	magic_test_type_string,
	magic_test_type_pstring,
	magic_test_type_date,
	magic_test_type_qdate,
	magic_test_type_date,
	magic_test_type_qdate,
	magic_test_type_udate,
	magic_test_type_uqdate,
	magic_test_type_udate,
	magic_test_type_qdate,
	magic_test_type_short,
	magic_test_type_long,
	magic_test_type_quad,
	magic_test_type_ushort,
	magic_test_type_ulong,
	magic_test_type_uquad,
	magic_test_type_float,
	magic_test_type_double,
	magic_test_type_date,
	magic_test_type_qdate,
	magic_test_type_date,
	magic_test_type_qdate,
	magic_test_type_udate,
	magic_test_type_uqdate,
	magic_test_type_udate,
	magic_test_type_uqdate,
	magic_test_type_bestring16,
	magic_test_type_short,
	magic_test_type_long,
	magic_test_type_quad,
	magic_test_type_ushort,
	magic_test_type_ulong,
	magic_test_type_uquad,
	magic_test_type_float,
	magic_test_type_double,
	magic_test_type_date,
	magic_test_type_qdate,
	magic_test_type_date,
	magic_test_type_qdate,
	magic_test_type_udate,
	magic_test_type_uqdate,
	magic_test_type_udate,
	magic_test_type_uqdate,
	magic_test_type_lestring16,
	magic_test_type_melong,
	magic_test_type_medate,
	magic_test_type_meldate,
	magic_test_type_regex,
	magic_test_type_search,
	magic_test_type_default,
	magic_test_type_clear,
	magic_test_type_name,
	magic_test_type_use,
};

static void magic_test_children(RzMagicLine *ml, RzMagicState *ms, size_t start,
	int reverse) {
	RzMagicLine *child;
	size_t saved_start, saved_offset;
	int saved_reverse;

	saved_start = ms->start;
	saved_reverse = ms->reverse;
	saved_offset = ms->offset;

	ms->matched = 0; /* no need to save, caller will set too */

	RzListIter *iter;
	rz_list_foreach (ml->children, iter, child) {
		ms->start = start;
		ms->reverse = reverse;
		ms->offset = saved_offset;

		magic_test_line(child, ms);
	}

	ms->start = saved_start;
	ms->reverse = saved_reverse;
	ms->offset = saved_offset;
}

static int magic_test_line(RzMagicLine *ml, RzMagicState *ms) {
	RzMagic *m = ml->root;
	RzMagicLine *named;
	st64 offset, wanted, next;
	int result;
	ut8 b;
	ut16 s;
	ut32 l;

	if (ml->indirect_type == ' ')
		wanted = ms->start + ml->offset;
	else {
		wanted = ml->indirect_offset;
		if (ml->indirect_relative) {
			if (wanted < 0 && (size_t)-wanted > ms->offset)
				return (0);
			if (wanted > 0 && ms->offset + wanted > ms->size)
				return (0);
			next = ms->offset + ml->indirect_offset;
		} else
			next = wanted;

		switch (ml->indirect_type) {
		case 'b':
		case 'B':
			if (magic_copy_from(ms, next, &b, sizeof b) != 0)
				return (0);
			wanted = b;
			break;
		case 's':
			if (magic_copy_from(ms, next, &s, sizeof s) != 0)
				return (0);
			wanted = rz_read_le16(&s);
			break;
		case 'S':
			if (magic_copy_from(ms, next, &s, sizeof s) != 0)
				return (0);
			wanted = rz_read_be16(&s);
			break;
		case 'l':
			if (magic_copy_from(ms, next, &l, sizeof l) != 0)
				return (0);
			wanted = rz_read_le16(&l);
			break;
		case 'L':
			if (magic_copy_from(ms, next, &l, sizeof l) != 0)
				return (0);
			wanted = rz_read_be16(&l);
			break;
		}

		switch (ml->indirect_operator) {
		case '+':
			wanted += ml->indirect_operand;
			break;
		case '-':
			wanted -= ml->indirect_operand;
			break;
		case '*':
			wanted *= ml->indirect_operand;
			break;
		}
	}

	if (ml->offset_relative) {
		if (wanted < 0 && (size_t)-wanted > ms->offset)
			return (0);
		if (wanted > 0 && ms->offset + wanted > ms->size)
			return (0);
		offset = ms->offset + wanted;
	} else
		offset = wanted;
	if (offset < 0 || (size_t)offset > ms->size)
		return (0);
	ms->offset = offset; /* test function may update */

	result = magic_test_functions[ml->type](ml, ms);
	if (result == -1) {
		RZ_LOG_DEBUG("test %s/%c failed\n", ml->type_string,
			ml->test_operator);
		return (0);
	}
	if (result == -2) {
		RZ_LOG_DEBUG("test %s/%c not implemented\n", ml->type_string,
			ml->test_operator);
		return (0);
	}
	if (result == ml->test_not)
		return (0);
	if (ml->mimetype != NULL)
		ms->mimetype = ml->mimetype;

	RZ_LOG_DEBUG("test %s/%c matched at offset %" PFMT64d " (now %zu): "
		     "'%s'\n",
		ml->type_string, ml->test_operator, offset,
		ms->offset, ml->result == NULL ? "" : ml->result);

	if (ml->type == MAGIC_TYPE_USE) {
		if (*ml->name == '^')
			named = magic_get_named(m, ml->name + 1);
		else
			named = magic_get_named(m, ml->name);
		if (named == NULL) {
			RZ_LOG_DEBUG("no name found for use %s\n", ml->name);
			return (0);
		}
		RZ_LOG_DEBUG("use %s at offset %" PFMT64d "\n", ml->name, offset);
		magic_test_children(named, ms, offset, *ml->name == '^');
	}

	magic_test_children(ml, ms, ms->start, ms->reverse);

	if (ml->type == MAGIC_TYPE_CLEAR)
		ms->matched = 0;
	else
		ms->matched = 1;
	return (ml->result != NULL);
}

RZ_OWN char *magic_test(RZ_NONNULL const RzMagic *m, RZ_NONNULL const void *base, size_t size, int flags) {
	rz_return_val_if_fail(m && base, NULL);

	RzMagicLine *ml;
	RzMagicState ms = { 0 };

	ms.base = base;
	ms.size = size;

	ms.text = !!(flags & MAGIC_TEST_TEXT);

	RBIter rbiter;
	rz_rbtree_foreach (m->magic_tree, rbiter, ml, RzMagicLine, rb) {
		ms.offset = 0;
		if (ml->text == ms.text && magic_test_line(ml, &ms))
			break;
	}

	if (*ms.out != '\0') {
		if (flags & MAGIC_TEST_MIME) {
			if (ms.mimetype != NULL) {
				char *mimetype = rz_str_dup(ms.mimetype);
				return mimetype;
			}
			return (NULL);
		}
		char *out = rz_str_dup(ms.out);
		return out;
	}
	return (NULL);
}
