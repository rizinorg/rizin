// SPDX-FileCopyrightText: 2008-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2008-2020 TheLemonMan <thatlemon@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "rz_search.h"
#include <rz_regex.h>

RZ_API int rz_search_regexp_update(RzSearch *s, ut64 from, const ut8 *buf, int len) {
	RzSearchKeyword *kw;
	RzListIter *iter;
	RzRegexMatch match;
	RzRegex compiled = { 0 };
	const int old_nhits = s->nhits;
	int ret = 0;

	rz_list_foreach (s->kws, iter, kw) {
		int reflags = RZ_REGEX_EXTENDED;

		if (kw->icase) {
			reflags |= RZ_REGEX_ICASE;
		}

		if (rz_regex_comp(&compiled, (char *)kw->bin_keyword, reflags)) {
			eprintf("Cannot compile '%s' regexp\n", kw->bin_keyword);
			return -1;
		}

		match.rm_so = 0;
		match.rm_eo = len;

		while (!rz_regex_exec(&compiled, (char *)buf, 1, &match, RZ_REGEX_STARTEND)) {
			int t = rz_search_hit_new(s, kw, from + match.rm_so);
			if (!t) {
				ret = -1;
				goto beach;
			}
			if (t > 1) {
				goto beach;
			}
			/* Setup the boundaries for RZ_REGEX_STARTEND */
			match.rm_so = match.rm_eo;
			match.rm_eo = len;
		}
	}

beach:
	rz_regex_fini(&compiled);
	if (!ret) {
		ret = s->nhits - old_nhits;
	}
	return ret;
}
