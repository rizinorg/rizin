// SPDX-FileCopyrightText: 2018 bart1e
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef PAGER_PRIVATE_H
#define PAGER_PRIVATE_H

RZ_IPI void pager_color_line(const char *line, RzStrpool *p, RzPVector /*<RzRegexMatch *>*/ *ml);
RZ_IPI void pager_printpage(const char *line, int *index, RzPVector /*<RzRegexMatch *>*/ **mla, int from, int to, int w);
RZ_IPI int pager_next_match(int from, RzPVector /*<RzRegexMatch *>*/ **mla, int lcount);
RZ_IPI int pager_prev_match(int from, RzPVector /*<RzRegexMatch *>*/ **mla);
RZ_IPI int *pager_splitlines(char *s, int *lines_count);

#endif
