// SPDX-FileCopyrightText: 2018-2024 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "parse_helper.h"

/** \file parse_helper.c
 * This file contains a common code that can be used to convert any asm code
 * into a pseudo code, via a generic grammar.
 *
 * The grammar is quite simple; Let's take a simple example
 *
 * Let's take the following assembly
 * ; intel x86 asm
 * ; rax = rax + 10
 *   add rax, 10
 *
 * The associated grammar will be "1 += 2" the number 1 will be changed to "rax" and 2 with "10"
 *
 * another example:
 *
 * ; mips asm
 * ; t0 = 4097 << 16
 *   lui t0, 4097
 *
 * The associated grammar will be "1 = 2 << #16" to notice the `#` symbol.
 * The `#` symbol is used to ignore any set of chars after this till next whitespace/end of the line
 *
 * the developer has to provide a tokenize method to split the assembly in various token strings
 * and
 */

RZ_IPI bool rz_pseudo_convert(const RzPseudoConfig *config, const char *assembly, RzStrBuf *sb) {
	rz_return_val_if_fail(config && config->tokenize && config->lexicon, false);

	size_t i, p;
	const char *tmp = NULL;
	const RzPseudoGrammar *gr = NULL;
	const RzPseudoReplace *rp = NULL;

	if (!strcmp(assembly, "invalid")) {
		return true;
	} else if (!strncmp(assembly, "trunc", 5)) {
		return true;
	} else if (!strcmp(assembly, "nop")) {
		return true;
	}
	size_t length = strlen(assembly);

	for (i = 0; i < config->direct_length; ++i) {
		tmp = config->direct[i].expected;
		if (!strcmp(assembly, tmp)) {
			rz_strbuf_set(sb, config->direct[i].pseudo);
			return true;
		}
	}

	size_t mnemonic_length = length;
	if ((tmp = strchr(assembly, ' '))) {
		mnemonic_length = tmp - assembly;
	}
	for (i = 0; i < config->lexicon_length; ++i) {
		gr = &config->lexicon[i];
		if (gr->mnemonic_length == mnemonic_length && !strncmp(gr->mnemonic, assembly, mnemonic_length)) {
			break;
		}
		gr = NULL;
	}
	if (!gr) {
		rz_strbuf_setf(sb, "asm(\"%s\")", assembly);
		return true;
	}

	RzList *tokens = config->tokenize(assembly, length);
	if (!tokens) {
		rz_strbuf_setf(sb, "asm(\"%s\")", assembly);
		return true;
	}

	for (i = 0, p = 0; gr->grammar[p]; ++p) {
		int index = gr->grammar[p] - '0';
		if (index > 0 && index < config->max_args) {
			tmp = (const char *)rz_list_get_n(tokens, index);
			if (!tmp) {
				tmp = "?";
			}
			rz_strbuf_append_n(sb, gr->grammar + i, p - i);
			i = p + 1;
			rz_strbuf_append(sb, tmp);
		} else if (gr->grammar[p] == '#') {
			rz_strbuf_append_n(sb, gr->grammar + i, p - i);
			i = p + 1;
			// Fast-forward so after the next p++ done by the for loop p points to the next
			// whitespace (or the end of the string)
			while (gr->grammar[p + 1] && !IS_WHITESPACE(gr->grammar[p + 1])) {
				++p;
			}
		}
	}

	if (i < p) {
		rz_strbuf_append_n(sb, gr->grammar + i, p - i);
	}

	char *result = rz_strbuf_drain_nofree(sb);
	for (int i = 0; i < config->replace_length; ++i) {
		rp = &config->replace[i];
		result = rz_str_replace(result, rp->expected, rp->replace, rp->flag);
	}
	rz_strbuf_set(sb, result);
	free(result);

	rz_list_free(tokens);
	return true;
}
