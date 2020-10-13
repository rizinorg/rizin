#ifndef PAGER_PRIVATE_H
#define PAGER_PRIVATE_H

RZ_IPI void pager_color_line(const char *line, RzStrpool *p, RzList *ml);
RZ_IPI void pager_printpage(const char *line, int *index, RzList **mla, int from, int to, int w);
RZ_IPI int pager_next_match(int from, RzList **mla, int lcount);
RZ_IPI int pager_prev_match(int from, RzList **mla);
RZ_IPI bool pager_all_matches(const char *s, RzRegex *rx, RzList **mla, int *lines, int lcount);
RZ_IPI int *pager_splitlines(char *s, int *lines_count);

#endif
