// SPDX-FileCopyrightText: 2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_regex.h>
#include <rz_util.h>
#include <rz_cons.h>
#include "pager_private.h"
#include "rz_vector.h"

RZ_IPI void pager_color_line(const char *line, RzStrpool *p, RzPVector /*<RzRegexMatch *>*/ *ml) {
	int m_len, offset = 0;
	char *m_addr;
	char *inv[2] = {
		RZ_CONS_INVERT(true, true),
		RZ_CONS_INVERT(false, true)
	};
	int linv[2] = {
		strlen(inv[0]),
		strlen(inv[1])
	};
	rz_strpool_empty(p);
	void **it;
	rz_pvector_foreach (ml, it) {
		RzRegexMatch *m = *it;
		/* highlight a match */
		rz_strpool_memcat(p, line + offset, m->start - offset);
		rz_strpool_memcat(p, inv[0], linv[0]);
		m_len = m->len;
		if (m_len < 0) {
			m_len = 0;
		}
		m_addr = rz_str_ndup(line + m->start, m_len);
		if (m_addr) {
			/* in case there's a CSI in the middle of this match*/
			m_len = rz_str_ansi_filter(m_addr, NULL, NULL, m_len);
			if (m_len < 0) {
				m_len = 0;
			}
			rz_strpool_memcat(p, m_addr, m_len);
			rz_strpool_memcat(p, inv[1], linv[1]);
			offset = m->start + m->len;
			free(m_addr);
		}
	}
	/* append final part of string w/o matches */
	rz_strpool_append(p, line + offset);
}

RZ_IPI void pager_printpage(const char *line, int *index, RzPVector /*<RzRegexMatch *>*/ **mla, int from, int to, int w) {
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

RZ_IPI int pager_next_match(int from, RzPVector /*<RzRegexMatch *>*/ **mla, int lcount) {
	int l;
	if (from > lcount - 2) {
		return from;
	}
	for (l = from + 1; l < lcount; l++) {
		/* if there's at least one match on the line */
		if (!rz_pvector_empty(mla[l])) {
			return l;
		}
	}
	return from;
}

RZ_IPI int pager_prev_match(int from, RzPVector /*<RzRegexMatch *>*/ **mla) {
	int l;
	if (from < 1) {
		return from;
	}
	for (l = from - 1; l > 0; l--) {
		if (!rz_pvector_empty(mla[l])) {
			return l;
		}
	}
	return from;
}

RZ_IPI int *pager_splitlines(char *s, int *lines_count) {
	int lines_size = 128;
	int *lines = NULL;
	int i, row = 0;

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
		}
		*lines_count = row;
	}
	return lines;
}
