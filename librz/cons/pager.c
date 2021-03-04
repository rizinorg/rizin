// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_regex.h>
#include <rz_util.h>
#include <rz_cons.h>
#include "pager_private.h"

RZ_IPI void pager_color_line(const char *line, RzStrpool *p, RzList *ml) {
	int m_len, offset = 0;
	char *m_addr;
	RzListIter *it;
	RzRegexMatch *m;
	char *inv[2] = {
		RZ_CONS_INVERT(true, true),
		RZ_CONS_INVERT(false, true)
	};
	int linv[2] = {
		strlen(inv[0]),
		strlen(inv[1])
	};
	rz_strpool_empty(p);
	rz_list_foreach (ml, it, m) {
		/* highlight a match */
		rz_strpool_memcat(p, line + offset, m->rm_so - offset);
		rz_strpool_memcat(p, inv[0], linv[0]);
		m_len = m->rm_eo - m->rm_so;
		if (m_len < 0) {
			m_len = 0;
		}
		m_addr = rz_str_ndup(line + m->rm_so, m_len);
		if (m_addr) {
			/* in case there's a CSI in the middle of this match*/
			m_len = rz_str_ansi_filter(m_addr, NULL, NULL, m_len);
			if (m_len < 0) {
				m_len = 0;
			}
			rz_strpool_memcat(p, m_addr, m_len);
			rz_strpool_memcat(p, inv[1], linv[1]);
			offset = m->rm_eo;
			free(m_addr);
		}
	}
	/* append final part of string w/o matches */
	rz_strpool_append(p, line + offset);
}

RZ_IPI void pager_printpage(const char *line, int *index, RzList **mla, int from, int to, int w) {
	int i;

	rz_cons_clear00();
	if (from < 0 || to < 0) {
		return;
	}

	RzStrpool *p = rz_strpool_new(0);
	if (!p) {
		return;
	}
	for (i = from; i < to; i++) {
		pager_color_line(line + index[i], p, mla[i]);
		rz_strpool_ansi_chop(p, w);
		rz_cons_reset_colors();
		if (i + 1 == to) {
			rz_cons_print(p->str);
		} else {
			rz_cons_println(p->str);
		}
	}
	rz_strpool_free(p);
	rz_cons_flush();
}

RZ_IPI int pager_next_match(int from, RzList **mla, int lcount) {
	int l;
	if (from > lcount - 2) {
		return from;
	}
	for (l = from + 1; l < lcount; l++) {
		/* if there's at least one match on the line */
		if (rz_list_first(mla[l])) {
			return l;
		}
	}
	return from;
}

RZ_IPI int pager_prev_match(int from, RzList **mla) {
	int l;
	if (from < 1) {
		return from;
	}
	for (l = from - 1; l > 0; l--) {
		if (rz_list_first(mla[l])) {
			return l;
		}
	}
	return from;
}

RZ_IPI bool pager_all_matches(const char *s, RzRegex *rx, RzList **mla, int *lines, int lcount) {
	bool res = false;
	RzRegexMatch m = { 0 };
	int l, slen;
	for (l = 0; l < lcount; l++) {
		m.rm_so = 0;
		const char *loff = s + lines[l]; /* current line offset */
		char *clean = strdup(loff);
		if (!clean) {
			return false;
		}
		int *cpos = NULL;
		int ncpos = rz_str_ansi_filter(clean, NULL, &cpos, -1);
		m.rm_eo = slen = strlen(clean);
		rz_list_purge(mla[l]);
		while (!rz_regex_exec(rx, clean, 1, &m, RZ_REGEX_STARTEND)) {
			if (!cpos || m.rm_so >= ncpos) {
				break;
			}
			RzRegexMatch *ms = RZ_NEW0(RzRegexMatch);
			if (ms && cpos) {
				ms->rm_so = cpos[m.rm_so];
				ms->rm_eo = cpos[m.rm_eo];
				rz_list_append(mla[l], ms);
			}
			m.rm_so = m.rm_eo;
			m.rm_eo = slen;
			res = true;
		}
		free(cpos);
		free(clean);
	}
	return res;
}

RZ_IPI int *pager_splitlines(char *s, int *lines_count) {
	int lines_size = 128;
	int *lines = NULL;
	int i, row = 0;
	int sidx = 0;

	if (lines_size * sizeof(int) < lines_size) {
		return NULL;
	}
	lines = malloc(lines_size * sizeof(int));
	if (lines) {
		lines[row++] = 0;
		for (i = 0; s[i]; i++) {
			if (row >= lines_size) {
				int *tmp;
				lines_size += 128;
				if (lines_size * sizeof(int) < lines_size) {
					free(lines);
					return NULL;
				}
				tmp = realloc(lines, lines_size * sizeof(int));
				if (!tmp) {
					free(lines);
					return NULL;
				}
				lines = tmp;
			}
			if (s[i] == '\n') {
				s[i] = 0;
				lines[row++] = i + 1;
			}
			sidx++;
		}
		*lines_count = row;
	}
	return lines;
}
