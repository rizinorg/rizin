// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <math.h> /* for ceill */
#include <rz_util.h>

static ut64 rz_num_tailff(RzNum *num, const char *hex);

/**
 * \brief Checks if the first two chars of \p p equal "0x".
 *
 * \param p The string which potentially represents a hex number.
 * \return bool True if p[0] == '0' && p[1] == 'x'. False otherwise.
 */
RZ_API bool rz_num_is_hex_prefix(const char *p) {
	rz_return_val_if_fail(p, false);
	if (!isascii(*p)) {
		return false; // UTF-8
	}
	return (p[0] == '0' && p[1] == 'x');
}

static void rz_num_srand(int seed) {
#if HAVE_ARC4RANDOM_UNIFORM
	// no-op
	(void)seed;
#else
	srand(seed);
#endif
}

static ut32 rz_rand32(ut32 mod) {
#if HAVE_ARC4RANDOM_UNIFORM
	return (ut32)arc4random_uniform(mod);
#else
	return (ut32)rand() % mod;
#endif
}

static ut64 rz_rand64(ut64 mod) {
#if HAVE_ARC4RANDOM_UNIFORM && HAVE_ARC4RANDOM
	if (mod <= UT32_MAX) {
		return (ut64)arc4random_uniform(mod);
	}
	ut64 high_mod = mod >> 32;
	ut64 value;
	do {
		value = (ut64)arc4random_uniform(high_mod) << 32 | (ut64)arc4random();
	} while (value >= mod);

	return value;
#else
	return ((ut64)rand() << 32 | (ut64)rand()) % mod;
#endif
}

/**
 * \brief Seed the random number generator.
 **/
RZ_API void rz_num_irand(void) {
	rz_num_srand(rz_time_now());
}

// NOTE: The random generator will be seeded twice
// but I don't think that'll be a problem since it'll
// be seeded twice at max

/**
 * \brief Generate 32 bit random numbers.
 *
 * \param max Maximum value of generated random numbers.
 * \return Random value between 0 to max.
 **/
RZ_API ut32 rz_num_rand32(ut32 max) {
	static bool rand_initialized = false;
	if (!rand_initialized) {
		rz_num_irand();
		rand_initialized = true;
	}
	if (!max) {
		max = 1;
	}
	return rz_rand32(max);
}

/**
 * \brief Generate 64 bit random numbers.
 *
 * \param max Maximum value of generated random numbers.
 * \return Random value between 0 to max.
 **/
RZ_API ut64 rz_num_rand64(ut64 max) {
	static bool rand_initialized = false;
	if (!rand_initialized) {
		rz_num_irand();
		rand_initialized = true;
	}
	if (!max) {
		max = 1;
	}
	return rz_rand64(max);
}

/**
 * \brief Swap a and b if a is greater than b.
 * 64-bit version.
 *
 * \param a Pointer to first value.
 * \param b Pointer to second value.
 **/
RZ_API void rz_num_minmax_swap(ut64 *a, ut64 *b) {
	if (*a > *b) {
		ut64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

/**
 * \brief Swap a and b if a is greater than b.
 * 32bit integer version.
 *
 * \param a Pointer to first value.
 * \param b Pointer to second value.
 **/
RZ_API void rz_num_minmax_swap_i(int *a, int *b) {
	if (*a > *b) {
		ut64 tmp = *a;
		*a = *b;
		*b = tmp;
	}
}

/**
 * \brief Create a new RzNum for handling numerical expressions.
 *
 * \param cb Callback.
 * \param cb2 Second callback.
 * \param ptr User defined data.
 * \return Created RzNum pointer on success, NULL otherwise.
 **/
RZ_API RzNum *rz_num_new(RzNumCallback cb, RzNumCallback2 cb2, void *ptr) {
	RzNum *num = RZ_NEW0(RzNum);
	if (!num) {
		return NULL;
	}
	num->value = 0LL;
	num->callback = cb;
	num->cb_from_value = cb2;
	num->userptr = ptr;
	return num;
}

/**
 * \brief Destroy the RzNum object.
 *
 * \param RzNum to be destroy.
 **/
RZ_API void rz_num_free(RzNum *num) {
	free(num);
}

#define KB (1ULL << 10)
#define MB (1ULL << 20)
#define GB (1ULL << 30)
#define TB (1ULL << 40)
#define PB (1ULL << 50)
#define EB (1ULL << 60)

/**
 * Convert size in bytes to human-readable string
 *
 * Result is stored in buf (buf should be at least 8 bytes in size).
 * If buf is NULL, memory for the new string is obtained with malloc(3),
 * and can be freed with free(3).
 *
 * On success, returns a pointer to buf. It returns NULL if
 * insufficient memory was available.
 */
RZ_API char *rz_num_units(char *buf, size_t len, ut64 num) {
	long double fnum;
	char unit;
	const char *fmt_str;
	if (!buf) {
		buf = malloc(len + 1);
		if (!buf) {
			return NULL;
		}
	}
	fnum = (long double)num;
	if (num >= EB) {
		unit = 'E';
		fnum /= EB;
	} else if (num >= PB) {
		unit = 'P';
		fnum /= PB;
	} else if (num >= TB) {
		unit = 'T';
		fnum /= TB;
	} else if (num >= GB) {
		unit = 'G';
		fnum /= GB;
	} else if (num >= MB) {
		unit = 'M';
		fnum /= MB;
	} else if (num >= KB) {
		unit = 'K';
		fnum /= KB;
	} else {
		unit = '\0';
	}
	fmt_str = ((double)ceill(fnum) == (double)fnum)
		? "%.0" LDBLFMTf "%c"
		: "%.1" LDBLFMTf "%c";
	snprintf(buf, len, fmt_str, fnum, unit);
	return buf;
}

static void error(RzNum *num, const char *err_str) {
	if (num) {
		num->nc.errors++;
	}
}

// TODO: try to avoid the use of sscanf
/* old get_offset */
RZ_API ut64 rz_num_get(RZ_NULLABLE RzNum *num, RZ_NULLABLE const char *str) {
	int i, j, ok;
	char lch, len;
	ut64 ret = 0LL;
	ut32 s, a;

	if (num && !num->nc.under_calc) {
		num->nc.errors = 0;
	}
	if (!str) {
		return 0;
	}
	for (; *str == ' ';) {
		str++;
	}
	if (!*str) {
		return 0;
	}
	if (!strncmp(str, "1u", 2)) { // '1' is captured by op :(
		if (num && num->value == UT64_MAX) {
			num->value = 0;
		}
		switch (atoi(str + 2)) {
		case 64: return (ut64)UT64_MAX;
		case 32: return (ut64)UT32_MAX;
		case 16: return (ut64)UT16_MAX;
		case 8: return (ut64)UT8_MAX;
		}
	}
	/* resolve string with an external callback */
	if (num && num->callback) {
		ok = 0;
		ret = num->callback(num->userptr, str, &ok);
		if (ok) {
			return ret;
		}
	}

	if (str[0] && str[1] && str[2]) {
		if (str[0] == '\'' && str[2] == '\'') {
			return (ut64)str[1];
		}
	}

	len = strlen(str);
	if (len > 3 && str[4] == ':') {
		if (sscanf(str, "%04x", &s) == 1) {
			if (sscanf(str + 5, "%04x", &a) == 1) {
				return (ut64)((s << 4) + a);
			}
		}
	} else if (len > 6 && str[6] == ':') {
		if (sscanf(str, "0x%04x:0x%04x", &s, &a) == 2) {
			return (ut64)((s << 4) + a);
		}
		if (sscanf(str, "0x%04x:%04x", &s, &a) == 2) {
			return (ut64)((s << 4) + a);
		}
	}
	if (str[0] == '0' && str[1] == 'b') {
		ret = 0;
		for (j = 0, i = strlen(str) - 1; i > 0; i--, j++) {
			if (str[i] == '1') {
				ret |= 1ULL << j;
			} else if (str[i] != '0') {
				break;
			}
		}
		sscanf(str, "0x%" PFMT64x, &ret);
	} else if (str[0] == '\'') {
		ret = str[1] & 0xff;
		// needs refactoring
	} else if (!strncmp(str, "0xff..", 6) || !strncmp(str, "0xFF..", 6)) {
		ret = rz_num_tailff(num, str + 6);
		// needs refactoring
	} else if (!strncmp(str, "0o", 2)) {
		if (sscanf(str + 2, "%" PFMT64o, &ret) != 1) {
			error(num, "invalid octal number");
		}
	} else if (!strncmp(str, "0xf..", 5) || !strncmp(str, "0xF..", 5)) {
		ret = rz_num_tailff(num, str + 5);
	} else if (str[0] == '0' && tolower(str[1]) == 'x') {
		const char *lodash = strchr(str + 2, '_');
		if (lodash) {
			// Support 0x1000_f000_4000
			// TODO: Only take underscores separated every 4 chars starting at the end
			char *s = strdup(str + 2);
			if (s) {
				rz_str_replace_char(s, '_', 0);
				errno = 0;
				ret = strtoull(s, NULL, 16);
				free(s);
			}
		} else {
			errno = 0;
			ret = strtoull(str + 2, NULL, 16);
			// sscanf (str+2, "%"PFMT64x, &ret);
		}
		if (errno == ERANGE) {
			error(num, "number won't fit into 64 bits");
		}
	} else {
		char *endptr;
		int len_num = len > 0 ? len - 1 : 0;
		// Trim separators on the right
		while (len_num > 0 && IS_SEPARATOR(str[len_num])) {
			len_num--;
		}
		int chars_read = len_num;
		bool zero_read = false;
		lch = str[len_num];
		if (*str == '0' && IS_DIGIT(*(str + 1)) && lch != 'b' && lch != 'h' && lch != 'H') {
			lch = 'o';
			len_num++;
		}
		switch (lch) {
		case 'H':
		case 'h': // hexa
			if (!sscanf(str, "%" PFMT64x "%n", &ret, &chars_read) || chars_read != len_num) {
				error(num, "invalid hex number");
			}
			break;
		case 'o': // octal
			if (!sscanf(str, "%" PFMT64o "%n", &ret, &chars_read) || chars_read != len_num) {
				error(num, "invalid octal number");
			}
			break;
		case 'b': // binary
			ret = 0;
			ok = true;
			if (strlen(str) <= 65) { // 64 bit + the 'b' suffix
				for (j = 0, i = strlen(str) - 2; i >= 0; i--, j++) {
					if (str[i] == '1') {
						ret |= (1ULL << j);
					} else if (str[i] != '0') {
						// eprintf ("Unexpected char in binary number string '%c'\n", str[i]);
						ok = false;
						break;
					}
				}
			} else {
				ok = false;
				// eprintf ("Binary number is too large to fit in ut64\n");
			}
			if (!ok || !len_num) {
				error(num, "invalid binary number");
			}
			break;
		case 't': // ternary
			ret = 0;
			ok = true;
			ut64 x = 1;
			for (i = strlen(str) - 2; i >= 0; i--) {
				if (str[i] < '0' || '2' < str[i]) {
					ok = false;
					break;
				}
				ret += x * (str[i] - '0');
				x *= 3;
			}
			if (!ok || !len_num) {
				error(num, "invalid ternary number");
			}
			break;
		case 'K':
		case 'k':
			if (strchr(str, '.')) {
				double d = 0;
				if (sscanf(str, "%lf%n", &d, &chars_read)) {
					ret = (ut64)(d * KB);
				} else {
					zero_read = true;
				}
			} else {
				if (sscanf(str, "%" PFMT64d "%n", &ret, &chars_read)) {
					ret *= KB;
				} else {
					zero_read = true;
				}
			}
			if (zero_read || chars_read != len_num) {
				error(num, "invalid kilobyte number");
			}
			break;
		case 'M':
		case 'm':
			if (strchr(str, '.')) {
				double d = 0;
				if (sscanf(str, "%lf%n", &d, &chars_read)) {
					ret = (ut64)(d * MB);
				} else {
					zero_read = true;
				}
			} else {
				if (sscanf(str, "%" PFMT64d "%n", &ret, &chars_read)) {
					ret *= MB;
				} else {
					zero_read = true;
				}
			}
			if (zero_read || chars_read != len_num) {
				error(num, "invalid megabyte number");
			}
			break;
		case 'G':
		case 'g':
			if (strchr(str, '.')) {
				double d = 0;
				if (sscanf(str, "%lf%n", &d, &chars_read)) {
					ret = (ut64)(d * GB);
				} else {
					zero_read = true;
				}
			} else {
				if (sscanf(str, "%" PFMT64d "%n", &ret, &chars_read)) {
					ret *= GB;
				} else {
					zero_read = true;
				}
			}
			if (zero_read || chars_read != len_num) {
				error(num, "invalid gigabyte number");
			}
			break;
		default:
			errno = 0;
			ret = strtoull(str, &endptr, 10);
			if (errno == ERANGE) {
				error(num, "number won't fit into 64 bits");
			}
			if (!IS_DIGIT(*str) || (*endptr && *endptr != lch)) {
				error(num, "unknown symbol");
			}
			break;
		}
	}
	if (num) {
		num->value = ret;
	}
	return ret;
}

/**
 * \brief Compute an numerical expression.
 *
 * \param num RzNum instance.
 * \param str Numerical expression.
 * \return Evaluated expression's value.
 **/
RZ_API ut64 rz_num_math(RzNum *num, const char *str) {
	ut64 ret;
	const char *err = NULL;
	if (!str || !*str) {
		return 0LL;
	}
	// if (!str || !*str) return 0LL;
	if (num) {
		num->dbz = 0;
	}
	ret = rz_num_calc(num, str, &err);
	if (err) {
		eprintf("rz_num_calc error: (%s) in (%s)\n", err, str);
	}
	if (num) {
		num->value = ret;
	}
	return ret;
}

RZ_API double rz_num_get_float(RzNum *num, const char *str) {
	double d = 0.0f;
	(void)sscanf(str, "%lf", &d);
	return d;
}

RZ_API int rz_num_to_bits(char *out, ut64 num) {
	int size = 64, i;

	if (num >> 32) {
		size = 64;
	} else if (num & 0xff000000) {
		size = 32;
	} else if (num & 0xff0000) {
		size = 24;
	} else if (num & 0xff00) {
		size = 16;
	} else if (num & 0xff) {
		size = 8;
	}
	if (out) {
		int pos = 0;
		int realsize = 0;
		int hasbit = 0;
		for (i = 0; i < size; i++) {
			char bit = ((num >> (size - i - 1)) & 1) ? '1' : '0';
			if (hasbit || bit == '1') {
				out[pos++] = bit; // size - 1 - i] = bit;
			}
			if (!hasbit && bit == '1') {
				hasbit = 1;
				realsize = size - i;
			}
		}
		if (realsize == 0) {
			out[realsize++] = '0';
		}
		out[realsize] = '\0'; // Maybe not nesesary?
	}
	return size;
}

RZ_API int rz_num_to_trits(char *out, ut64 num) {
	if (out == NULL) {
		return false;
	}
	int i;
	for (i = 0; num; i++, num /= 3) {
		out[i] = (char)('0' + num % 3);
	}
	if (i == 0) {
		out[0] = '0';
		i++;
	}
	out[i] = '\0';

	rz_str_reverse(out);
	return true;
}

RZ_API int rz_num_conditional(RzNum *num, const char *str) {
	char *lgt, *t, *p, *s = strdup(str);
	int res = 0;
	ut64 n, a, b;
	p = s;
	do {
		t = strchr(p, ',');
		if (t) {
			*t = 0;
		}
		lgt = strchr(p, '<');
		if (lgt) {
			*lgt = 0;
			a = rz_num_math(num, p);
			if (lgt[1] == '=') {
				b = rz_num_math(num, lgt + 2);
				if (a > b) {
					goto fail;
				}
			} else {
				b = rz_num_math(num, lgt + 1);
				if (a >= b) {
					goto fail;
				}
			}
		} else {
			lgt = strchr(p, '>');
			if (lgt) {
				*lgt = 0;
				a = rz_num_math(num, p);
				if (lgt[1] == '=') {
					b = rz_num_math(num, lgt + 2);
					if (a < b) {
						goto fail;
					}
				} else {
					b = rz_num_math(num, lgt + 1);
					if (a <= b) {
						goto fail;
					}
				}
			} else {
				lgt = strchr(p, '=');
				if (lgt && lgt > p) {
					lgt--;
					if (*lgt == '!') {
						rz_str_replace_char(p, '!', ' ');
						rz_str_replace_char(p, '=', '-');
						n = rz_num_math(num, p);
						if (!n) {
							goto fail;
						}
					}
				}
				lgt = strstr(p, "==");
				if (lgt) {
					*lgt = ' ';
				}
				rz_str_replace_char(p, '=', '-');
				n = rz_num_math(num, p);
				if (n) {
					goto fail;
				}
			}
		}
		p = t + 1;
	} while (t);
	res = 1;
fail:
	free(s);
	return res;
}

RZ_API int rz_num_is_valid_input(RzNum *num, const char *input_value) {
	ut64 value = input_value ? rz_num_math(num, input_value) : 0;
	return !(value == 0 && input_value && *input_value != '0') || !(value == 0 && input_value && *input_value != '@');
}

RZ_API ut64 rz_num_get_input_value(RzNum *num, const char *input_value) {
	ut64 value = input_value ? rz_num_math(num, input_value) : 0;
	return value;
}

#define NIBBLE_TO_HEX(n) (((n)&0xf) > 9 ? 'a' + ((n)&0xf) - 10 : '0' + ((n)&0xf))
static int escape_char(char *dst, char byte) {
	const char escape_map[] = "abtnvfr";
	if (byte >= 7 && byte <= 13) {
		*(dst++) = '\\';
		*(dst++) = escape_map[byte - 7];
		*dst = 0;
		return 2;
	} else if (byte) {
		*(dst++) = '\\';
		*(dst++) = 'x';
		*(dst++) = NIBBLE_TO_HEX(byte >> 4);
		*(dst++) = NIBBLE_TO_HEX(byte);
		*dst = 0;
		return 4;
	}
	return 0;
}

RZ_API char *rz_num_as_string(RzNum *___, ut64 n, bool printable_only) {
	char str[34]; // 8 byte * 4 chars in \x?? format
	int stri, ret = 0, off = 0;
	int len = sizeof(ut64);
	ut64 num = n;
	str[stri = 0] = 0;
	while (len--) {
		char ch = (num & 0xff);
		if (ch >= 32 && ch < 127) {
			str[stri++] = ch;
			str[stri] = 0;
		} else if (!printable_only && (off = escape_char(str + stri, ch)) != 0) {
			stri += off;
		} else {
			if (ch) {
				return NULL;
			}
		}
		ret |= (num & 0xff);
		num >>= 8;
	}
	if (ret) {
		return strdup(str);
	}
	if (!printable_only) {
		return strdup("\\0");
	}
	return NULL;
}

RZ_API bool rz_is_valid_input_num_value(RzNum *num, const char *input_value) {
	if (!input_value) {
		return false;
	}
	ut64 value = rz_num_math(num, input_value);
	return !(value == 0 && *input_value != '0');
}

RZ_API ut64 rz_get_input_num_value(RzNum *num, const char *str) {
	return (str && *str) ? rz_num_math(num, str) : 0;
}

static inline ut64 __nth_nibble(ut64 n, ut32 i) {
	int sz = (sizeof(n) << 1) - 1;
	int s = (sz - i) * 4;
	return (n >> s) & 0xf;
}

RZ_API ut64 rz_num_tail_base(RzNum *num, ut64 addr, ut64 off) {
	int i;
	bool ready = false;
	ut64 res = 0;
	for (i = 0; i < 16; i++) {
		ut64 o = __nth_nibble(off, i);
		if (!ready) {
			bool iseq = __nth_nibble(addr, i) == o;
			if (i == 0 && !iseq) {
				return UT64_MAX;
			}
			if (iseq) {
				continue;
			}
		}
		ready = true;
		ut8 pos = (15 - i) * 4;
		res |= (o << pos);
	}
	return res;
}

RZ_API ut64 rz_num_tail(RzNum *num, ut64 addr, const char *hex) {
	ut64 mask = 0LL;
	ut64 n = 0;
	char *p;
	int i;

	while (*hex && (*hex == ' ' || *hex == '.')) {
		hex++;
	}
	i = strlen(hex) * 4;
	p = malloc(strlen(hex) + 10);
	if (p) {
		strcpy(p, "0x");
		strcpy(p + 2, hex);
		if (isxdigit((ut8)hex[0])) {
			n = rz_num_math(num, p);
		} else {
			eprintf("Invalid argument\n");
			free(p);
			return addr;
		}
		free(p);
	}
	mask = UT64_MAX << i;
	return (addr & mask) | n;
}

static ut64 rz_num_tailff(RzNum *num, const char *hex) {
	ut64 n = 0;

	while (*hex && (*hex == ' ' || *hex == '.')) {
		hex++;
	}
	int i = strlen(hex) * 4;
	char *p = malloc(strlen(hex) + 10);
	if (p) {
		strcpy(p, "0x");
		strcpy(p + 2, hex);
		if (isxdigit((ut8)hex[0])) {
			n = rz_num_get(num, p);
		} else {
			eprintf("Invalid argument\n");
			free(p);
			return UT64_MAX;
		}
		free(p);
	}
	ut64 left = ((UT64_MAX >> i) << i);
	return left | n;
}

RZ_API int rz_num_between(RzNum *num, const char *input_value) {
	int i;
	ut64 ns[3];
	char *const str = strdup(input_value);
	RzList *nums = rz_num_str_split_list(str);
	int len = rz_list_length(nums);
	if (len < 3) {
		free(str);
		rz_list_free(nums);
		return -1;
	}
	if (len > 3) {
		len = 3;
	}
	for (i = 0; i < len; i++) {
		ns[i] = rz_num_math(num, rz_list_pop_head(nums));
	}
	free(str);
	rz_list_free(nums);
	return num->value = RZ_BETWEEN(ns[0], ns[1], ns[2]);
}

static bool char_is_op(const char c) {
	return c == '/' || c == '+' || c == '-' || c == '*' ||
		c == '%' || c == '&' || c == '^' || c == '|';
}

// Assumed *str is parsed as an expression correctly
RZ_API int rz_num_str_len(const char *str) {
	int i = 0, len = 0, st;
	st = 0; // 0: number, 1: op
	if (str[0] == '(') {
		i++;
	}
	while (str[i] != '\0') {
		switch (st) {
		case 0: // number
			while (!char_is_op(str[i]) && str[i] != ' ' && str[i] != '\0') {
				i++;
				if (str[i] == '(') {
					i += rz_num_str_len(str + i);
				}
			}
			len = i;
			st = 1;
			break;
		case 1: // op
			while (str[i] != '\0' && str[i] == ' ') {
				i++;
			}
			if (!char_is_op(str[i])) {
				return len;
			}
			if (str[i] == ')') {
				return i + 1;
			}
			i++;
			while (str[i] != '\0' && str[i] == ' ') {
				i++;
			}
			st = 0;
			break;
		}
	}
	return len;
}

RZ_API int rz_num_str_split(char *str) {
	int i = 0, count = 0;
	const int len = strlen(str);
	while (i < len) {
		i += rz_num_str_len(str + i);
		str[i] = '\0';
		i++;
		count++;
	}
	return count;
}

RZ_API RzList /*<char *>*/ *rz_num_str_split_list(char *str) {
	int i, count = rz_num_str_split(str);
	RzList *list = rz_list_new();
	for (i = 0; i < count; i++) {
		rz_list_append(list, str);
		str += strlen(str) + 1;
	}
	return list;
}

RZ_API void *rz_num_dup(ut64 n) {
	ut64 *hn = malloc(sizeof(ut64));
	if (!hn) {
		return NULL;
	}
	*hn = n;
	return (void *)hn;
}

/**
 * \brief Convert the base suffix to the numeric value
 */
RZ_API size_t rz_num_base_of_string(RzNum *num, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(num && str, 10);
	size_t base = 10;
	if (rz_str_startswith(str, "10u") || rz_str_startswith(str, "du")) {
		base = 11;
	} else {
		switch (str[0]) {
		case 's':
			base = 1;
			break;
		case 'b':
			base = 2;
			break;
		case 'p':
			base = 3;
			break;
		case 'o':
			base = 8;
			break;
		case 'd':
			base = 10;
			break;
		case 'h':
			base = 16;
			break;
		case 'i':
			base = 32;
			break;
		case 'q':
			base = 64;
			break;
		case 'S':
			// IPv4 address
			base = 80;
			break;
		default:
			// syscall
			base = rz_num_math(num, str);
		}
	}
	return base;
}
