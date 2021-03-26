// SPDX-FileCopyrightText: 2005, 2006 Matt Mackall <mpm@selenic.com>
// SPDX-FileCopyrightText: 2009-2010 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: GPL-2.0-or-later

/* Adapted code from:

 bdiff.c - efficient binary diff extension for Mercurial

 Copyright 2005, 2006 Matt Mackall <mpm@selenic.com>

 This software may be used and distributed according to the terms of
 the GNU General Public License, incorporated herein by reference.

 Based roughly on Python difflib
*/

#include <rz_util.h>
#include <rz_diff.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>



RZ_API int splitlines(const char * a) {
    int count = rz_str_char_count(a, '\n') + rz_str_char_count(a, '\0') + 1;
    struct rz_diff_line *l = (struct rz_diff_line *)malloc(sizeof(struct rz_diff_line) * count);
    int hash = 0;
    const char* b = a;
    if (!a) {
        RZ_LOG_DEBUG("Null pointer recieved\n");
        return 0;
    }
    if (!l) {
        return -1;
    } 
    int len = rz_str_len_utf8(a);
    for (const char* p = a; *p < len ; p++) {
       hash = (hash * 1664525) + *p + 1013904223;
       if (*p == '\n' || *p == '\0') { 
			l->hash = hash; 					
			hash = 0;						
			l->len = p - b + 1; 		
			l->line = b;
			l->next = INT_MAX;
			l++;
			b = p + 1;
		}
    }
    l->hash = l->len = 0;
    l->line = a + len;
    return len-1;
}


static int cmp (struct rz_diff_line *a, struct rz_diff_line *b) {
    return a->hash != b->hash || a->line != b->line || memcmp(a->line, b->line, a->len);
}

static int equatelines(struct rz_diff_line *a, int an, struct rz_diff_line *b, int bn) {
	int i, j, t;
	size_t scale, buckets = 1;
	struct rz_pos *h = NULL;

	/* build a hash table of the next highest power of 2 */
	while (buckets < bn + 1) { /* bn: bucket number */
		buckets *= 2;
	}

	/* try to allocate a large hash table to avoid collisions */
	for (scale = 4; scale; scale /= 2) {
		h = (struct rz_pos *)malloc(scale * buckets * sizeof(struct rz_pos));
		if (h) {
			break;
		}
	}

	if (!h) {
		return 0;
	}

	buckets = buckets * scale - 1;  

	/* clear the hash table */
	for (i = 0; i <= buckets; i++) {  
		h[i].pos = INT_MAX;
		h[i].len = 0;
	}
	/* add lines to the hash table chains */
	for (i = bn - 1; i >= 0; i--) { /* for i in buckets[::-1] */
		/* find the equivalence class */
		for (j = b[i].hash & buckets; h[j].pos != INT_MAX; j = (j + 1) & buckets) {
			if (!cmp (b + i, b + h[j].pos)) {
				break;
			}
		}
		/* add to the head of the equivalence class */
		b[i].next = h[j].pos;
		b[i].e = j;
		h[j].pos = i;
		h[j].len++; /* keep track of popularity */
	}

	/* compute popularity threshold */
	t = (bn >= 4000) ? bn / 1000 : bn + 1;

	/* match items in a to their equivalence class in b */
	for (i = 0; i < an; i++) {
		/* find the equivalence class */
		for (j = a[i].hash & buckets; h[j].pos != INT_MAX;
			j = (j + 1) & buckets) {
			if (!cmp (a + i, b + h[j].pos)) {
				break;
			}
		}

		a[i].e = j; /* use equivalence class for quick compare */
		if (h[j].len <= t) {
			a[i].next = h[j].pos; /* point to head of match list */
		} else {
			a[i].next = INT_MAX; /* too popular */
		}
	}
	/* discard hash tables */
	free(h);
	return 1;
}

static int longest_match(struct rz_diff_line *a, struct rz_diff_line *b, struct rz_pos *pos,
			 int a1, int a2, int b1, int b2, int *omi, int *omj)
{
	int mi = a1, mj = b1, mk = 0, mb = 0, i, j, k;

	for (i = a1; i < a2; i++) {
		/* skip things before the current block */
		for (j = a[i].next; j < b1; j = b[j].next) {
			;
		}

		/* loop through all lines match a[i] in b */
		for (; j < b2; j = b[j].next) {
			/* does this extend an earlier match? */
			if (i > a1 && j > b1 && pos[j - 1].pos == i - 1) {
				k = pos[j - 1].len + 1;
			} else {
				k = 1;
			}
			pos[j].pos = i;
			pos[j].len = k;

			/* best match so far? */
			if (k > mk) {
				mi = i;
				mj = j;
				mk = k;
			}
		}
	}

	if (mk) {
		mi = mi - mk + 1;
		mj = mj - mk + 1;
	}

	/* expand match to include neighboring popular lines */
	while (mi - mb > a1 && mj - mb > b1 &&
		a[mi - mb - 1].e == b[mj - mb - 1].e) {
		mb++;
	}
	while (mi + mk < a2 && mj + mk < b2 &&
		a[mi + mk].e == b[mj + mk].e) {
		mk++;
	}

	*omi = mi - mb;
	*omj = mj - mb;

	return mk + mb;
}

static void recurse(struct rz_diff_line *a, struct rz_diff_line *b, struct rz_pos *pos,
		    int a1, int a2, int b1, int b2, struct rz_hunklist *l)
{
	int i, j, k;

	/* find the longest match in this chunk */
	k = longest_match(a, b, pos, a1, a2, b1, b2, &i, &j);
	if (!k) {
		return;
	}

	/* and recurse on the remaining chunks on either side */
	recurse(a, b, pos, a1, i, b1, j, l);
	l->head->a1 = i;
	l->head->a2 = i + k;
	l->head->b1 = j;
	l->head->b2 = j + k;
	l->head++;
	recurse(a, b, pos, i + k, a2, j + k, b2, l);
}

static struct rz_hunklist diff(struct rz_diff_line *a, int an, struct rz_diff_line *b, int bn)
{
	struct rz_hunklist l;
	struct rz_hunk *curr;
	struct rz_pos *pos;
	int t;

	/* allocate and fill arrays */
	t = equatelines(a, an, b, bn);
	pos = (struct rz_pos *)calloc(bn ? bn : 1, sizeof(struct rz_pos));
	/* we can't have more matches than lines in the shorter file */
	l.head = l.base = (struct rz_hunk *)malloc(sizeof(struct rz_hunk) *
	                                        ((an<bn ? an:bn) + 1));

	if (pos && l.base && t) {
		/* generate the matching block list */
		recurse(a, b, pos, 0, an, 0, bn, &l);
		l.head->a1 = l.head->a2 = an;
		l.head->b1 = l.head->b2 = bn;
		l.head++;
	}

	free(pos);

	/* normalize the hunk list, try to push each hunk towards the end */
	for (curr = l.base; curr != l.head; curr++) {
		struct rz_hunk *next = curr+1;
		int shift = 0;

		if (next == l.head) {
			break;
		}

		if (curr->a2 == next->a1) {
			while (curr->a2 + shift < an && curr->b2 + shift < bn && !cmp (a + curr->a2 + shift, b + curr->b2 + shift)) {
				shift++;
			}
		} else if (curr->b2 == next->b1) {
			while (curr->b2 + shift < bn && curr->a2 + shift < an && !cmp (b + curr->b2 + shift, a + curr->a2 + shift)) {
				shift++;
			}
		}
		if (!shift) {
			continue;
		}
		curr->b2 += shift;
		next->b1 += shift;
		curr->a2 += shift;
		next->a1 += shift;
	}

	return l;
}

// TODO: implement the rz_diff_lines // we need to implement rz_file_line_at (file, off);
RZ_API int rz_diff_buffers_delta(RzDiff *d, const ut8 *sa, int la, const ut8 *sb, int lb) {
	RzDiffOp dop;
	struct rz_diff_line *al = NULL;
	struct rz_diff_line *bl = NULL;
	struct rz_hunklist l = { NULL, NULL };
	struct rz_hunk *h;
	int an, bn, offa, rlen, offb, len = 0;
	int hits = -1;

	an = splitlines ((const char *)sa);
	if (an<0) {
		free (al);
		return -1;
	}
	bn = splitlines ((const char *)sb);
	if (bn<0) {
		free (al);
		free (bl);
		return -1;
	}
	if (!al || !bl) {
		eprintf ("bindiff_buffers: Out of memory.\n");
		goto beach;
	}

	l = diff (al, an, bl, bn);
	if (!l.head) {
		eprintf ("bindiff_buffers: Out of memory.\n");
		goto beach;
	}

	hits = la = lb = 0;
	for (h = l.base; h != l.head; h++) {
		if (h->a1 != la || h->b1 != lb) {
			len = bl[h->b1].len - bl[lb].len;
			offa = al[la].line - al->line;
			offb = al[h->a1].line - al->line;
			rlen = offb-offa;

			if (d->callback) {
				/* source file */
				dop.a_off = offa;
				dop.a_buf = (ut8 *)al[la].line;
				dop.a_len = rlen;

				/* destination file */
				dop.b_off = offa; // XXX offb not used??
				dop.b_buf = (ut8 *)bl[lb].line;
				dop.b_len = len;
				if (!d->callback (d, d->user, &dop)) {
					break;
				}
			}
#if 0	
			if (rlen > 0) {
				//printf ("Remove %d byte(s) at %d\n", rlen, offa);
				printf ("r-%d @ 0x%"PFMT64x"\n", rlen, (ut64)offa);
			}
			printf ("e file.write=true\n"); // XXX
			printf ("wx ");
			for(i=0;i<len;i++)
				printf ("%02x", bl[lb].l[i]);
			printf (" @ 0x%"PFMT64x"\n", (ut64)offa);
			rb += 12 + len;
#endif
		}
		la = h->a2;
		lb = h->b2;
	}
	beach:
	free (al);
	free (bl);
	free (l.base);

	return hits;
}
