// SPDX-FileCopyrightText: 2007-2020 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <errno.h>
#include <math.h> /* for ceill */
#include <rz_util.h>

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

/**
 * \brief Classify the base prefix of a numeric literal.
 *
 * Only the prefix is inspected; whether any digits follow, and whether they
 * are valid for the base, is left to the caller.
 *
 * \param p          The literal text, without a leading sign.
 * \param base       If non-NULL, set to the base the prefix selects, 10 when there is none.
 * \param prefix_len If non-NULL, set to the number of characters to skip to reach the digits.
 *                   This is 0 for RZ_NUM_BASE_PREFIX_OCTAL_C, whose leading zero is itself
 *                   an octal digit.
 * \return The prefix kind.
 */
RZ_API RzNumBasePrefix rz_num_base_prefix(RZ_NONNULL const char *p, RZ_NULLABLE RZ_OUT ut32 *base,
	RZ_NULLABLE RZ_OUT size_t *prefix_len) {
	rz_return_val_if_fail(p, RZ_NUM_BASE_PREFIX_NONE);
	RzNumBasePrefix kind = RZ_NUM_BASE_PREFIX_NONE;
	ut32 b = 10;
	size_t len = 0;
	if (p[0] == '0') {
		switch (p[1]) {
		case 'x':
		case 'X':
			kind = RZ_NUM_BASE_PREFIX_HEX;
			b = 16;
			len = 2;
			break;
		case 'b':
		case 'B':
			kind = RZ_NUM_BASE_PREFIX_BINARY;
			b = 2;
			len = 2;
			break;
		case 'o':
		case 'O':
			kind = RZ_NUM_BASE_PREFIX_OCTAL;
			b = 8;
			len = 2;
			break;
		case 't':
		case 'T':
			kind = RZ_NUM_BASE_PREFIX_TERNARY;
			b = 3;
			len = 2;
			break;
		default:
			if (IS_DIGIT(p[1])) {
				kind = RZ_NUM_BASE_PREFIX_OCTAL_C;
				b = 8;
			}
			break;
		}
	}
	if (base) {
		*base = b;
	}
	if (prefix_len) {
		*prefix_len = len;
	}
	return kind;
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
	if (!num) {
		return;
	}
	rz_num_value_store_free(num->expr_vars);
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

RZ_API ut64 rz_num_get(RZ_NULLABLE RzNum *num, RZ_NULLABLE const char *str) {
	// Thin compatibility wrapper over the real ut64 entry point.
	return rz_num_math_ut64(num, str);
}

/**
 * \brief Evaluate the numeric literal at the head of \p str.
 *
 * Consumes the leading run that forms a single literal - an optional sign, an
 * optional 0x/0o/0b/0t base prefix and its digits, or a decimal body - and
 * evaluates only that, leaving any operator, separator or comment that follows
 * untouched (so the comma in "0x111,0x222" ends the first literal). This spares
 * callers from hard-coding which delimiters can terminate a number.
 *
 * \param num Optional RzNum context for host symbol resolution.
 * \param str String whose head is a numeric literal.
 * \param endptr If non-NULL, set to the first character past the literal.
 * \return The evaluated value, or 0 when no literal is present.
 */
RZ_API ut64 rz_num_get_leading(RZ_NULLABLE RzNum *num, RZ_NONNULL const char *str, RZ_NULLABLE const char **endptr) {
	rz_return_val_if_fail(str, 0);
	const char *p = str;
	if (*p == '+' || *p == '-') {
		p++;
	}
	const char *digits = p;
	if (p[0] == '0' && p[1] && strchr("xXoObBtT", p[1])) {
		p += 2;
		digits = p;
		while (IS_HEXCHAR(*p)) {
			p++;
		}
	} else {
		while (IS_DIGIT(*p)) {
			p++;
		}
	}
	if (p == digits) {
		if (endptr) {
			*endptr = str;
		}
		return 0;
	}
	char buf[128];
	size_t len = (size_t)(p - str);
	if (len >= sizeof(buf)) {
		len = sizeof(buf) - 1;
	}
	memcpy(buf, str, len);
	buf[len] = '\0';
	if (endptr) {
		*endptr = p;
	}
	return rz_num_math_ut64(num, buf);
}

RZ_API const char *rz_num_calc_index(RZ_NULLABLE RzNum *num, RZ_NULLABLE const char *p) {
	// Cursor bookkeeping for rz_core's `[...]` index syntax. This never
	// belonged to the legacy expression parser - it only tracks an
	// offset into the nc buffer so the caller can save and restore its
	// parse position around a nested evaluation.
	if (!num) {
		return NULL;
	}
	if (p) {
		num->nc.calc_buf = p;
		num->nc.calc_len = strlen(p);
		num->nc.calc_i = 0;
	}
	return num->nc.calc_buf + num->nc.calc_i;
}

// Substitute every balanced [inner] dereference in `str` with the value
// num_callback's '[' case reads for it (it evaluates `inner` recursively
// through rz_num_math and reads a word from IO). The grammar has no
// bracket rule, so a deref used as a sub-term - [0]/2, 5+[0], [0]+[4] -
// would otherwise fold to 0; this lets the strict parser see the value in
// its place. Returns a newly allocated string, or NULL when
// there is nothing to substitute or a deref cannot be resolved, in which
// case the caller evaluates the original string (and so still errors on a
// genuinely malformed input).
static char *num_subst_derefs(RzNum *num, const char *str) {
	if (!strchr(str, '[')) {
		return NULL;
	}
	RzStrBuf sb;
	rz_strbuf_init(&sb);
	bool any = false;
	for (const char *p = str; *p;) {
		if (*p != '[') {
			rz_strbuf_append_n(&sb, p, 1);
			p++;
			continue;
		}
		// find the ']' matching this '[', honouring nested brackets
		int depth = 0;
		const char *q = p;
		for (; *q; q++) {
			if (*q == '[') {
				depth++;
			} else if (*q == ']') {
				if (--depth == 0) {
					break;
				}
			}
		}
		if (depth != 0 || *q != ']') {
			// unbalanced: leave it for the strict parser to reject
			rz_strbuf_fini(&sb);
			return NULL;
		}
		char *sub = rz_str_ndup(p, (size_t)(q - p) + 1);
		int dok = 0;
		ut64 dv = sub ? num->callback(num->userptr, sub, &dok) : 0;
		free(sub);
		if (!dok) {
			rz_strbuf_fini(&sb);
			return NULL;
		}
		rz_strbuf_appendf(&sb, "0x%" PFMT64x, dv);
		any = true;
		p = q + 1;
	}
	if (!any) {
		rz_strbuf_fini(&sb);
		return NULL;
	}
	return rz_strbuf_drain_nofree(&sb);
}

/**
 * \brief Read the leading numeric literal of \p str, calc.c style.
 *
 * The legacy parser the typed evaluator replaced read the leading number
 * of an input and ignored whatever operand syntax trailed it - a ']', a
 * second operand, a stray ')', a comment. Callers that hand rz_num a raw
 * token rely on this: the per-architecture assemblers, the disassembler's
 * address/flag substitution, the java operand validator. The leading token
 * is re-parsed through the strict evaluator, so a literal that is malformed
 * for its base (the octal "383o", the binary "121b") is still rejected
 * rather than read as a truncated decimal. Returns true and writes \p out
 * when the leading token is a valid number.
 */
static bool num_leading_value(const char *str, ut64 *out) {
	if (!str) {
		return false;
	}
	while (*str == ' ' || *str == '\t') {
		str++;
	}
	const char *p = str;
	if (*p == '+' || *p == '-') {
		p++;
	}
	// Take the run that can form a number literal (digits, base markers and
	// hex letters, '.') and stop at the first operand character - operator,
	// bracket, separator. The run is validated below, so over-including a
	// stray letter only costs a rejected re-parse, never a wrong value.
	size_t toklen = 0;
	while (p[toklen]) {
		char c = p[toklen];
		bool numeric = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || c == '.';
		if (!numeric) {
			break;
		}
		toklen++;
	}
	if (!toklen) {
		return false;
	}
	char *tok = rz_str_ndup(str, (size_t)(p - str) + toklen);
	if (!tok) {
		return false;
	}
	RzNumValue tv;
	rz_num_value_init(&tv);
	char *terr = NULL;
	bool ok = rz_num_math_value(NULL, tok, &tv, &terr);
	free(terr);
	free(tok);
	if (ok) {
		*out = rz_num_value_to_ut64(&tv);
	}
	rz_num_value_fini(&tv);
	return ok;
}

// Parse a complete hexadecimal number from [s, s+len) into *out. A leading
// "0x"/"0X" is accepted but not required - segment:offset notation is hex on
// both sides by convention. The whole span must be consumed: a non-hex tail
// fails rather than parsing a prefix and ignoring the rest. The first
// character is required to be a hex digit so a sign or whitespace (which
// strtoull would otherwise accept) is rejected.
static bool num_parse_hex_span(const char *s, size_t len, ut64 *out) {
	if (!len || len >= 24) {
		return false;
	}
	char c0 = s[0];
	bool first_is_hex = (c0 >= '0' && c0 <= '9') ||
		(c0 >= 'a' && c0 <= 'f') || (c0 >= 'A' && c0 <= 'F');
	if (!first_is_hex) {
		return false;
	}
	char buf[24];
	memcpy(buf, s, len);
	buf[len] = '\0';
	char *end = NULL;
	ut64 v = (ut64)strtoull(buf, &end, 16);
	if (end != buf + len) {
		return false;
	}
	*out = v;
	return true;
}

// Real-mode segment:offset address ("SSSS:OOOO", e.g. "0000:000d",
// "0x1000:0x20", "0x7c0:0"). Computes (seg << 4) + offset, matching x86
// real-mode linearisation (and the dev calc.c path). The grammar reserves
// ':' for typed reads (addr:width, where width is a decimal bit-count -
// 8/16/32/64 - or a type name), so a genuine typed read parses strictly and
// never reaches this parse-error fallback; only the seg:off forms the
// grammar rejects land here. Both sides are parsed as whole hex numbers, so
// non-4-digit segments such as "0x7c0:0" or "0:0x7c00" linearise correctly
// instead of dropping through to the leading-number fallback (which used to
// return just the segment). A token carrying a second ':' (a C++ "a::b"
// symbol, say) is not a seg:off and is left for the other fallbacks.
static bool num_segoff_value(const char *str, ut64 *out) {
	const char *colon = strchr(str, ':');
	if (!colon || colon == str || !colon[1]) {
		return false;
	}
	if (strchr(colon + 1, ':')) {
		return false;
	}
	ut64 seg, off;
	if (!num_parse_hex_span(str, (size_t)(colon - str), &seg) ||
		!num_parse_hex_span(colon + 1, strlen(colon + 1), &off)) {
		return false;
	}
	*out = (seg << 4) + off;
	return true;
}

// Leading-zero octal literal whose run contains a non-octal digit, e.g.
// "02345678" (the '8' is invalid). calc.c read it with sscanf("%o"),
// which consumes the valid octal prefix ("0234567" -> 0o234567) and
// returns that value while flagging an error. The strict grammar rejects
// such a literal outright, so this recovers the same partial value in the
// parse-error fallback. The caller keeps nc.errors set, so a consumer that
// gates on it (the seek command: `s 0187` must not move) still treats the
// literal as a failure, while one that does not (`ar reg=02345678`) gets
// the historical partial value. Only the leading-zero octal form needs
// this; an explicit-suffix form ("383o") simply folds to 0 as before.
static bool num_partial_octal_value(const char *str, ut64 *out) {
	const char *p = str;
	bool neg = false;
	if (*p == '+' || *p == '-') {
		neg = (*p == '-');
		p++;
	}
	// "0" followed by a decimal digit (not the 0x/0b/0o/0t prefixes).
	if (p[0] != '0' || p[1] < '0' || p[1] > '9') {
		return false;
	}
	char *endp = NULL;
	unsigned long long v = strtoull(p, &endp, 8);
	// A fully valid octal run parses strictly and never reaches this
	// fallback, so require that strtoull stopped on a non-octal digit -
	// a genuine partial read rather than a complete one.
	if (endp == p || *endp == '\0') {
		return false;
	}
	*out = neg ? (ut64)(-(long long)v) : (ut64)v;
	return true;
}

// True when str is a single bare token of flag/identifier characters that
// also contains a ':' - e.g. "str.Password:" or "sym.Test::callMeNot". The
// grammar reserves ':' for typed reads (addr:width), so such a name fails
// to parse and reaches the fallback; the legacy parser treated ':' as an
// ordinary symbol character and resolved the whole token through the host
// callback. Requiring a single token (no operators, brackets or spaces)
// keeps a real expression like "sym.a + 4" - which the grammar parses
// fine anyway - out of this path.
static bool num_is_flagname_token(const char *str) {
	bool has_colon = false;
	for (const char *p = str; *p; p++) {
		char c = *p;
		bool ident = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') || c == '_' || c == '.' || c == '$';
		if (c == ':') {
			has_colon = true;
		} else if (!ident) {
			return false;
		}
	}
	return has_colon;
}

/**
 * \brief Check whether \p str is a bare integer literal, and parse it.
 *
 * A bare integer literal is an optional base prefix (see \ref rz_num_base_prefix)
 * followed only by digits valid in that base, and nothing else. Signs,
 * whitespace, operators, radix points, exponents, bit-vector widths, unit
 * suffixes and the deprecated trailing base suffixes all make \p str not a
 * bare literal.
 *
 * This is the cheap path around rz_num_math(): it needs no expression parser.
 *
 * \param str Text to examine.
 * \param value Set to the parsed value when the function returns true.
 * \param overflow Set to true when \p str is a valid integer literal too large
 *                 for a ut64. The function still returns false; a caller that
 *                 supports arbitrary precision can use this to promote it.
 *
 * \return true if \p str is a bare integer literal that fits in a ut64.
 */
RZ_API bool rz_num_is_int_literal(RZ_NONNULL const char *str, RZ_NULLABLE RZ_OUT ut64 *value,
	RZ_NULLABLE RZ_OUT bool *overflow) {
	rz_return_val_if_fail(str, false);
	ut32 base = 10;
	size_t prefix_len = 0;
	rz_num_base_prefix(str, &base, &prefix_len);
	const char *digits = str + prefix_len;
	if (!*digits) {
		return false;
	}
	for (const char *p = digits; *p; p++) {
		ut8 v = 0;
		if (rz_hex_to_byte(&v, (ut8)*p) || v >= base) {
			return false;
		}
	}
	errno = 0;
	char *endp = NULL;
	unsigned long long v = strtoull(digits, &endp, base);
	if (errno == ERANGE) {
		if (overflow) {
			*overflow = true;
		}
		return false;
	}
	if (*endp) {
		return false;
	}
	if (value) {
		*value = (ut64)v;
	}
	return true;
}

/**
 * \brief Compute a numerical expression yielding a ut64.
 *
 * \param num RzNum instance.
 * \param str Numerical expression.
 * \return Evaluated expression's value.
 *
 * Evaluation is performed by the typed tree-sitter parser
 * (rz_num_math_value). When that parse fails syntactically, the leading
 * numeric literal is recovered the way the legacy calc.c parser did, so
 * callers that hand over a number followed by trailing operand syntax keep
 * working. Only an input with no leading number (or a genuine evaluation
 * error such as division by zero) folds to 0 and bumps num->nc.errors so
 * callers that gate on it (e.g. the seek command) do not act on the result.
 *
 * \note The ut64 return cannot on its own tell a genuine failure apart from
 * a result that is legitimately 0 (e.g. "1-1"): num->nc.errors disambiguates
 * when \p num is non-NULL, and code that needs the typed error should call
 * rz_num_math_value() directly.
 */
RZ_API ut64 rz_num_math_ut64(RzNum *num, const char *str) {
	ut64 ret;
	if (!str || !*str) {
		return 0LL;
	}
	if (num) {
		num->dbz = 0;
		// The new evaluator does not use the legacy calc's error
		// counter, but callers (e.g. the seek command) still test
		// num->nc.errors to decide whether the expression evaluated
		// cleanly. Reset it here so a stale count from an earlier
		// legacy evaluation cannot make a successful parse look failed.
		// The error paths below set it back on a genuine failure.
		num->nc.errors = 0;
		// Likewise expose the source expression through nc.calc_buf the
		// way the legacy load_token() does, so a caller reporting a
		// failure (again, the seek command) names the actual input
		// rather than a stale or null buffer.
		num->nc.calc_buf = str;
	}

	ut64 plain = 0;
	// Bare integer literals are the common input here and need no
	// expression parser; see rz_num_is_int_literal().
	if (rz_num_is_int_literal(str, &plain, NULL)) {
		if (num) {
			num->value = plain;
		}
		return plain;
	}

	// Legacy `[addr]` dereference. The bracket read predates the typed
	// `addr:width` syntax but is still widely used - both on its own
	// (`s [ptr]`) and as a sub-term (`[0]/2`, `5+[0]`, `[0]+[4]`) - and
	// the grammar deliberately has no bracket rule, so any bracket would
	// otherwise fold to 0 here. Replace each balanced `[inner]` with the
	// value num_callback's '[' case reads for it, then evaluate the result
	// strictly. A malformed bracket (unbalanced, or an inner expression the
	// callback cannot resolve) is left in place so the strict parser still
	// rejects it.
	if (num && num->callback) {
		char *subst = num_subst_derefs(num, str);
		if (subst) {
			ut64 dv = rz_num_math_ut64(num, subst);
			free(subst);
			// the recursive call pointed nc.calc_buf at the now-freed
			// substituted buffer; restore the original
			num->nc.calc_buf = str;
			return dv;
		}
	}

	// Brace-form special variables ($r{reg}, ${cfg}, $e{flag}, $s{flag},
	// $k{kv}, ...). The grammar's special_variable rule matches only the
	// bare `$X` token, so the `{arg}` tail would be left as trailing text
	// and fold the whole expression to 0. Route a complete `$...{...}`
	// through the same callback the variable path uses: its '$' case
	// understands every brace form. As with the bracket read, only a
	// fully-`}`-terminated form is taken, so other input parses strictly.
	if (num && num->callback && str[0] == '$' && strchr(str, '{')) {
		size_t slen = strlen(str);
		if (str[slen - 1] == '}') {
			int dok = 0;
			ut64 dv = num->callback(num->userptr, str, &dok);
			if (dok) {
				num->value = dv;
				num->fvalue = (double)dv;
				return dv;
			}
		}
	}

	// $? - the value of the last command (its return code, or the last
	// computed result, both surfaced through num->value). num_callback's
	// '?' case returns it, but the grammar's special_variable set omits
	// $?, so route a bare $? through the same callback the brace forms use.
	if (num && num->callback && str[0] == '$' && str[1] == '?' && !str[2]) {
		int dok = 0;
		ut64 dv = num->callback(num->userptr, str, &dok);
		if (dok) {
			num->value = dv;
			num->fvalue = (double)dv;
			return dv;
		}
	}

	// Try the new parser first.
	RzNumValue v;
	rz_num_value_init(&v);
	char *new_err = NULL;
	bool ok = rz_num_math_value(num, str, &v, &new_err);
	if (ok) {
		// Project to ut64; num->fvalue mirrors the result's floating
		// value (signed for integers) as the legacy path did, so the
		// last-evaluated value is observable through both fields.
		ret = rz_num_value_to_ut64(&v);
		if (num) {
			num->fvalue = rz_num_value_to_double(&v);
		}
		rz_num_value_fini(&v);
		if (num) {
			num->value = ret;
		}
		return ret;
	}

	// New parser failed. Dispatch on the error category v.err
	// rather than text-matching the diagnostic.
	//
	//   * Parse error  -> retry through the legacy code path. Some
	//     idiosyncratic input the old parser accepts may not yet
	//     be implemented in the new grammar.
	//   * Empty input  -> return 0 silently (legacy behaviour).
	//   * Reserved-word "variable" (bare `mod`, `log`, `le`, `be`) ->
	//     return 0 silently. Calling code outside the interactive
	//     command path commonly tokenises input on whitespace and
	//     hands each token to rz_num_math_ut64() individually; a
	//     bare reserved word ought not to spam the error stream in
	//     that case. Callers that want strict diagnostics should
	//     use rz_num_math_value() directly, which carries the
	//     RzNumError on the returned value.
	//   * Any other evaluation error -> report and stop.
	switch (v.err) {
	case RZ_NUM_ERR_PARSE:
		// A syntactic failure. The legacy calc.c parser read the leading
		// numeric literal of such input and ignored the trailing operand
		// syntax; callers like the assemblers, the disassembler's address
		// substitution and the java operand validator still depend on
		// that, so recover the leading number rather than folding to 0.
		// Only when there is no leading number do we fold to 0 and flag
		// nc.errors, so callers that gate on it (e.g. the seek command,
		// for a genuinely unparseable expression) leave their state put.
		{
			// A flag/symbol name containing ':' or '::' ("str.Password:",
			// "sym.Test::callMeNot") fails the grammar, which reserves ':'
			// for typed reads. The legacy parser treated ':' as an
			// identifier character and resolved the whole token through the
			// callback, so try that here before the seg:off / leading-
			// number fallbacks. A genuine typed read or seg:off literal is
			// not a flag, so the callback declines it and we fall through.
			if (num && num->callback && num_is_flagname_token(str)) {
				int cbok = 0;
				ut64 fv = num->callback(num->userptr, str, &cbok);
				if (cbok) {
					free(new_err);
					rz_num_value_fini(&v);
					num->value = fv;
					num->fvalue = (double)fv;
					return fv;
				}
			}
			// Segment:offset form ("0000:000d") is not covered by the
			// grammar's colon rule (typed reads), so recover it here -
			// before the leading-number fallback, which would otherwise
			// stop at the ':' and return just the segment.
			ut64 segoff;
			if (num_segoff_value(str, &segoff)) {
				free(new_err);
				rz_num_value_fini(&v);
				if (num) {
					num->fvalue = (double)segoff;
					num->value = segoff;
				}
				return segoff;
			}
			ut64 lead;
			if (num_leading_value(str, &lead)) {
				free(new_err);
				rz_num_value_fini(&v);
				if (num) {
					num->fvalue = (double)lead;
					num->value = lead;
				}
				return lead;
			}
			// Invalid-octal leading-zero literal ("02345678"): recover the
			// valid octal prefix the way calc.c did, but keep nc.errors set
			// below so seek-style callers still gate on it. Consumers that
			// do not gate (e.g. `ar reg=val`) get the historical value.
			ut64 partial;
			if (num_partial_octal_value(str, &partial)) {
				free(new_err);
				rz_num_value_fini(&v);
				if (num) {
					num->fvalue = (double)partial;
					num->value = partial;
					num->nc.errors = 1;
				}
				return partial;
			}
		}
		if (num) {
			num->nc.errors = 1;
		}
		// A genuine unparseable expression with no recoverable leading
		// number. nc.errors is set above; also log at debug level so the
		// failure is not entirely silent for callers that do not gate on
		// nc.errors, while staying quiet on the hot token-at-a-time path.
		RZ_LOG_DEBUG("rz_num_math_ut64: could not evaluate \"%s\" (%s)\n",
			str, new_err ? new_err : "parse error");
		free(new_err);
		ret = 0;
		break;
	case RZ_NUM_ERR_EMPTY:
	case RZ_NUM_ERR_RESERVED_WORD:
		// Empty input or a bare reserved word (`mod`, `log`, `le`, `be`)
		// stays silent and folds to 0 - calling code that whitespace-
		// tokenises its input and feeds each token here should not be
		// spammed, and unlike a parse error this is not a stray number.
		free(new_err);
		ret = 0;
		break;
	default:
		eprintf("rz_num_math error: (%s) in (%s)\n",
			new_err ? new_err : "unknown", str);
		free(new_err);
		ret = 0;
		// A genuine evaluation error (division by zero, uncomputable,
		// ...). Signal it the way the legacy path did so callers that
		// gate on num->nc.errors (e.g. `s <expr>`) do not act on the 0.
		if (num) {
			num->nc.errors = 1;
		}
		break;
	}
	rz_num_value_fini(&v);
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
	char *lgt, *t, *p, *s = rz_str_dup(str);
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
			a = rz_num_math_ut64(num, p);
			if (lgt[1] == '=') {
				b = rz_num_math_ut64(num, lgt + 2);
				if (a > b) {
					goto fail;
				}
			} else {
				b = rz_num_math_ut64(num, lgt + 1);
				if (a >= b) {
					goto fail;
				}
			}
		} else {
			lgt = strchr(p, '>');
			if (lgt) {
				*lgt = 0;
				a = rz_num_math_ut64(num, p);
				if (lgt[1] == '=') {
					b = rz_num_math_ut64(num, lgt + 2);
					if (a < b) {
						goto fail;
					}
				} else {
					b = rz_num_math_ut64(num, lgt + 1);
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
						n = rz_num_math_ut64(num, p);
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
				n = rz_num_math_ut64(num, p);
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
	ut64 value = input_value ? rz_num_math_ut64(num, input_value) : 0;
	return !(value == 0 && input_value && *input_value != '0') || !(value == 0 && input_value && *input_value != '@');
}

RZ_API ut64 rz_num_get_input_value(RzNum *num, const char *input_value) {
	ut64 value = input_value ? rz_num_math_ut64(num, input_value) : 0;
	return value;
}

#define NIBBLE_TO_HEX(n) (((n) & 0xf) > 9 ? 'a' + ((n) & 0xf) - 10 : '0' + ((n) & 0xf))
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
		return rz_str_dup(str);
	}
	if (!printable_only) {
		return rz_str_dup("\\0");
	}
	return NULL;
}

RZ_API bool rz_is_valid_input_num_value(RzNum *num, const char *input_value) {
	if (!input_value) {
		return false;
	}
	ut64 value = rz_num_math_ut64(num, input_value);
	return !(value == 0 && *input_value != '0');
}

RZ_API ut64 rz_get_input_num_value(RzNum *num, const char *str) {
	return (str && *str) ? rz_num_math_ut64(num, str) : 0;
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
			n = rz_num_math_ut64(num, p);
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

RZ_API int rz_num_between(RzNum *num, const char *input_value) {
	int i;
	ut64 ns[3];
	char *const str = rz_str_dup(input_value);
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
		ns[i] = rz_num_math_ut64(num, rz_list_pop_head(nums));
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
			base = rz_num_math_ut64(num, str);
		}
	}
	return base;
}
