// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 LemonBoy <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_search.h"
#include <rz_vector.h>
#include <rz_util/rz_regex.h>

/**
 * \return -1 on failure.
 */
RZ_API int rz_search_regexp_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	RzSearchKeyword *kw;
	RzListIter *iter;
	RzPVector *matches = NULL;
	RzRegex *compiled = NULL;
	const int old_nhits = s->nhits;
	int ret = 0;
	RzRegexCompContext *ccontext = rz_regex_compile_context_new();
	rz_regex_set_nul_as_newline(ccontext);

	rz_list_foreach (s->kws, iter, kw) {
		int cflags = RZ_REGEX_EXTENDED | RZ_REGEX_MULTILINE;

		if (kw->icase) {
			cflags |= RZ_REGEX_CASELESS;
		}

		compiled = rz_regex_new((char *)kw->bin_keyword, cflags, 0, ccontext);
		if (!compiled) {
			eprintf("Cannot compile '%s' regexp\n", kw->bin_keyword);
			return -1;
		}

		matches = rz_regex_match_all_not_grouped(compiled, (const char *)buf, len, 0, RZ_REGEX_DEFAULT);
		void **it;
		rz_pvector_foreach (matches, it) {
			RzRegexMatch *m = *it;
			kw->keyword_length = m->len; // For a regex search, the keyword can be of variable length
			int t = rz_search_hit_new(s, kw, from + m->start);
			if (t == 0) {
				ret = -1;
				rz_pvector_free(matches);
				goto beach;
			}
			// Max hits reached
			if (t > 1) {
				rz_pvector_free(matches);
				goto beach;
			}
		}
		rz_pvector_free(matches);
	}

beach:
	rz_regex_compile_context_free(ccontext);
	rz_regex_free(compiled);
	if (!ret) {
		ret = s->nhits - old_nhits;
	}
	return ret;
}
