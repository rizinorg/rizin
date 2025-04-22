// SPDX-FileCopyrightText: 2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PARSE_HELPER_H
#define PARSE_HELPER_H

#include <rz_parse.h>

typedef struct {
	const char *mnemonic;
	size_t mnemonic_length;
	const char *grammar;
} RzPseudoGrammar;

typedef struct {
	const char *expected;
	const char *pseudo;
} RzPseudoDirect;

typedef struct {
	const char *expected;
	const char *replace;
	int flag; // 0 for first match, 1 for all matches
} RzPseudoReplace;

typedef struct {
	const RzPseudoDirect *direct;
	size_t direct_length;
	const RzPseudoReplace *replace;
	size_t replace_length;
	const RzPseudoGrammar *lexicon;
	size_t lexicon_length;
	int max_args;
	RzList /*<char *>*/ *(*tokenize)(const char *assembly, size_t length);
} RzPseudoConfig;

#define RZ_PSEUDO_DEFINE_GRAMMAR(x, y) \
	{ .mnemonic = x, .mnemonic_length = sizeof(x) - 1, .grammar = y }

#define RZ_PSEUDO_DEFINE_DIRECT(x, y) \
	{ .expected = x, .pseudo = y }

#define RZ_PSEUDO_DEFINE_REPLACE(x, y, f) \
	{ .expected = x, .replace = y, .flag = f }

#define RZ_PSEUDO_DEFINE_CONFIG(d, l, r, m, t) \
	{ \
		.direct = d, \
		.direct_length = RZ_ARRAY_SIZE(d), \
		.replace = r, \
		.replace_length = RZ_ARRAY_SIZE(r), \
		.lexicon = l, \
		.lexicon_length = RZ_ARRAY_SIZE(l), \
		.max_args = m, \
		.tokenize = t, \
	}

#define RZ_PSEUDO_DEFINE_CONFIG_NO_DIRECT(l, r, m, t) \
	{ \
		.direct = NULL, \
		.direct_length = 0, \
		.replace = r, \
		.replace_length = RZ_ARRAY_SIZE(r), \
		.lexicon = l, \
		.lexicon_length = RZ_ARRAY_SIZE(l), \
		.max_args = m, \
		.tokenize = t, \
	}

#define RZ_PSEUDO_DEFINE_CONFIG_ONLY_LEXICON(l, m, t) \
	{ \
		.direct = NULL, \
		.direct_length = 0, \
		.replace = NULL, \
		.replace_length = 0, \
		.lexicon = l, \
		.lexicon_length = RZ_ARRAY_SIZE(l), \
		.max_args = m, \
		.tokenize = t, \
	}

RZ_IPI bool rz_pseudo_convert(const RzPseudoConfig *config, const char *assembly, RzStrBuf *sb);

#endif /* PARSE_HELPER_H */
