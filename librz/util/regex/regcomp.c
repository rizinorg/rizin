/*	$OpenBSD: regcomp.c,v 1.20 2010/11/21 00:02:30 tedu Exp $ */
/*-
 * Copyright (c) 1992, 1993, 1994 Henry Spencer.
 * Copyright (c) 1992, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Henry Spencer.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)regcomp.c	8.5 (Berkeley) 3/20/94
 */

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include "rz_regex.h"
#include "rz_util/rz_str.h"
#include "rz_util/rz_assert.h"

#include "utils.h"
#include "regex2.h"

#include "cclass.h"
#include "cname.h"

/*
 * parse structure, passed up and down to avoid global variables and
 * other clumsinesses
 */
struct parse {
	char *next; /* next character in RE */
	char *end; /* end of string (-> NUL normally) */
	int error; /* has an error been seen? */
	sop *strip; /* malloced strip */
	sopno ssize; /* malloced strip size (allocated) */
	sopno slen; /* malloced strip length (used) */
	int ncsalloc; /* number of csets allocated */
	struct re_guts *g;
#define NPAREN 10 /* we need to remember () 1-9 for back refs */
	sopno pbegin[NPAREN]; /* -> ( ([0] unused) */
	sopno pend[NPAREN]; /* -> ) ([0] unused) */
};

static void p_ere(struct parse *, int);
static void p_ere_exp(struct parse *);
static void p_str(struct parse *);
static void p_bre(struct parse *, int, int);
static int p_simp_re(struct parse *, int);
static int p_count(struct parse *);
static void p_bracket(struct parse *);
static void p_b_term(struct parse *, cset *);
static void p_b_cclass(struct parse *, cset *);
static void p_b_eclass(struct parse *, cset *);
static char p_b_symbol(struct parse *);
static char p_b_coll_elem(struct parse *, int);
static char othercase(int);
static void bothcases(struct parse *, int);
static void ordinary(struct parse *, int);
static void special(struct parse *, int);
static void nonnewline(struct parse *);
static void repeat(struct parse *, sopno, int, int);
static int seterr(struct parse *, int);
static cset *allocset(struct parse *);
static void freeset(struct parse *, cset *);
static int freezeset(struct parse *, cset *);
static int firstch(struct parse *, cset *);
static int nch(struct parse *, cset *);
static void mcadd(struct parse *, cset *, char *);
static void mcinvert(struct parse *, cset *);
static void mccase(struct parse *, cset *);
static int isinsets(struct re_guts *, int);
static int samesets(struct re_guts *, int, int);
static void categorize(struct parse *, struct re_guts *);
static sopno dupl(struct parse *, sopno, sopno);
static void doemit(struct parse *, sop, size_t);
static void doinsert(struct parse *, sop, size_t, sopno);
static void dofwd(struct parse *, sopno, sop);
static void enlarge(struct parse *, sopno);
static void stripsnug(struct parse *, struct re_guts *);
static void findmust(struct parse *, struct re_guts *);
static sopno pluscount(struct parse *, struct re_guts *);

static char nuls[10]; /* place to point scanner in event of error */

/*
 * macros for use with parse structure
 * BEWARE:  these know that the parse structure is named `p' !!!
 */
#define PEEK()           (*p->next)
#define PEEK2()          (*(p->next + 1))
#define MORE()           (p->next < p->end)
#define MORE2()          (p->next + 1 < p->end)
#define SEE(c)           (MORE() && PEEK() == (c))
#define SEETWO(a, b)     (MORE() && MORE2() && PEEK() == (a) && PEEK2() == (b))
#define EAT(c)           ((SEE(c)) ? (NEXT(), 1) : 0)
#define EATTWO(a, b)     ((SEETWO(a, b)) ? (NEXT2(), 1) : 0)
#define NEXT()           (p->next++)
#define NEXT2()          (p->next += 2)
#define NEXTn(n)         (p->next += (n))
#define GETNEXT()        (*p->next++)
#define SETERROR(e)      seterr(p, (e))
#define REQUIRE(co, e)   (void)((co) || SETERROR(e))
#define MUSTSEE(c, e)    (REQUIRE(MORE() && PEEK() == (c), e))
#define MUSTEAT(c, e)    (REQUIRE(MORE() && GETNEXT() == (c), e))
#define MUSTNOTSEE(c, e) (REQUIRE(!MORE() || PEEK() != (c), e))
#define EMIT(op, sopnd)  doemit(p, (sop)(op), (size_t)(sopnd))
#define INSERT(op, pos)  doinsert(p, (sop)(op), HERE() - (pos) + 1, pos)
#define AHEAD(pos)       dofwd(p, pos, HERE() - (pos))
#define ASTERN(sop, pos) EMIT(sop, HERE() - (pos))
#define HERE()           (p->slen)
#define THERE()          (p->slen - 1)
#define THERETHERE()     (p->slen - 2)
#define DROP(n)          (p->slen -= (n))

RZ_API int rz_regex_match(const char *pattern, const char *flags, const char *text) {
	int ret;
	RzRegex rx;
	int re_flags = rz_regex_flags(flags);
	if (rz_regex_comp(&rx, pattern, re_flags)) {
		eprintf("FAIL TO COMPILE %s\n", pattern);
		return 0;
	}
	ret = rz_regex_exec(&rx, text, 0, 0, re_flags);
	rz_regex_fini(&rx);
	return ret ? 0 : 1;
}

RZ_API RzList *rz_regex_get_match_list(const char *pattern, const char *flags, const char *text) {
	RzList *list = rz_list_newf(free);
	RzRegex rx;
	RzRegexMatch match;
	char *entry;
	size_t entry_len = 0;
	int re_flags = rz_regex_flags(flags);
	if (rz_regex_comp(&rx, pattern, re_flags)) {
		eprintf("Failed to compile regexp: %s\n", pattern);
		return NULL;
	}

	/* Initialize the boundaries for RZ_REGEX_STARTEND */
	match.rm_so = 0;
	match.rm_eo = strlen(text);
	while (!rz_regex_exec(&rx, text, 1, &match, re_flags | RZ_REGEX_STARTEND)) {
		entry_len = match.rm_eo - match.rm_so + 1;
		entry = RZ_NEWS0(char, entry_len);
		rz_str_ncpy(entry, text + match.rm_so, entry_len);
		rz_list_append(list, entry);
		/* Update the boundaries for RZ_REGEX_STARTEND */
		match.rm_so = match.rm_eo;
		match.rm_eo = strlen(text);
	}
	rz_regex_fini(&rx);
	return list;
}

RZ_API RzRegex *rz_regex_new(const char *pattern, const char *flags) {
	rz_return_val_if_fail(pattern, NULL);
	RzRegex *r, rx = { 0 };
	if (rz_regex_comp(&rx, pattern, rz_regex_flags(flags))) {
		return NULL;
	}
	r = RZ_NEW(RzRegex);
	if (!r) {
		return NULL;
	}
	memcpy(r, &rx, sizeof(RzRegex));
	return r;
}

RZ_API int rz_regex_flags(const char *f) {
	int flags = 0;
	if (!f || !*f) {
		return 0;
	}
	if (strchr(f, 'e')) {
		flags |= RZ_REGEX_EXTENDED;
	}
	if (strchr(f, 'i')) {
		flags |= RZ_REGEX_ICASE;
	}
	if (strchr(f, 's')) {
		flags |= RZ_REGEX_NOSUB;
	}
	if (strchr(f, 'n')) {
		flags |= RZ_REGEX_NEWLINE;
	}
	if (strchr(f, 'N')) {
		flags |= RZ_REGEX_NOSPEC;
	}
	if (strchr(f, 'p')) {
		flags |= RZ_REGEX_PEND;
	}
	if (strchr(f, 'd')) {
		flags |= RZ_REGEX_DUMP;
	}
	return flags;
}

RZ_API void rz_regex_fini(RzRegex *preg) {
	struct re_guts *g;
	if (!preg) {
		return;
	}
	if (preg->re_magic != MAGIC1) { /* oops */
		return; /* nice to complain, but hard */
	}

	g = preg->re_g;
	if (!g || g->magic != MAGIC2) { /* oops again */
		return;
	}
	preg->re_magic = 0; /* mark it invalid */
	g->magic = 0; /* mark it invalid */

	free(g->strip);
	free(g->sets);
	free(g->setbits);
	free(g->must);
	free(g);
}

RZ_API void rz_regex_free(RzRegex *preg) {
	rz_regex_fini(preg);
	free(preg);
}

/*
 - regcomp - interface for parser and compilation
 - 0 success, otherwise RZ_REGEX_something
 */
RZ_API int rz_regex_comp(RzRegex *preg, const char *pattern, int cflags) {
	struct parse pa;
	struct re_guts *g;
	struct parse *p = &pa;
	int i;
	size_t len;
#ifdef REDEBUG
#define GOODFLAGS(f) (f)
#else
#define GOODFLAGS(f) ((f) & ~RZ_REGEX_DUMP)
#endif
	cflags = GOODFLAGS(cflags);
	if (!preg || ((cflags & RZ_REGEX_EXTENDED) && (cflags & RZ_REGEX_NOSPEC))) {
		return RZ_REGEX_INVARG;
	}
	if (cflags & RZ_REGEX_PEND) {
		if (preg->re_endp < pattern) {
			return RZ_REGEX_INVARG;
		}
		len = preg->re_endp - pattern;
	} else {
		len = strlen((char *)pattern);
	}
	/* do the mallocs early so failure handling is easy */
	g = calloc(1, sizeof(struct re_guts) + (NC - 1));
	if (!g) {
		return RZ_REGEX_ESPACE;
	}
	/*
	 * Limit the pattern space to avoid a 32-bit overflow on buffer
	 * extension.  Also avoid any signed overflow in case of conversion
	 * so make the real limit based on a 31-bit overflow.
	 *
	 * Likely not applicable on 64-bit systems but handle the case
	 * generically (who are we to stop people from using ~715MB+
	 * patterns?).
	 */
	size_t maxlen = ((size_t)-1 >> 1) / sizeof(sop) * 2 / 3;
	if (len >= maxlen) {
		free(g);
		return RZ_REGEX_ESPACE;
	}
	preg->re_flags = cflags;
	p->ssize = len / (size_t)2 * (size_t)3 + (size_t)1; /* ugh */
	if (p->ssize < len) {
		free(g);
		return RZ_REGEX_ESPACE;
	}

	p->strip = (sop *)calloc(p->ssize, sizeof(sop));
	if (!p->strip) {
		free(g);
		return RZ_REGEX_ESPACE;
	}
	p->slen = 0;
	if (!p->strip) {
		free(g);
		return RZ_REGEX_ESPACE;
	}

	/* set things up */
	p->g = g;
	p->next = (char *)pattern; /* convenience; we do not modify it */
	p->end = p->next + len;
	p->error = 0;
	p->ncsalloc = 0;
	for (i = 0; i < NPAREN; i++) {
		p->pbegin[i] = 0;
		p->pend[i] = 0;
	}
	g->csetsize = NC;
	g->sets = NULL;
	g->setbits = NULL;
	g->ncsets = 0;
	g->cflags = cflags;
	g->iflags = 0;
	g->nbol = 0;
	g->neol = 0;
	g->must = NULL;
	g->mlen = 0;
	g->nsub = 0;
	g->ncategories = 1; /* category 0 is "everything else" */
	g->categories = &g->catspace[-(CHAR_MIN)];
	(void)memset((char *)g->catspace, 0, NC * sizeof(cat_t));
	g->backrefs = 0;

	/* do it */
	EMIT(OEND, 0);
	g->firststate = THERE();
	if (cflags & RZ_REGEX_EXTENDED) {
		p_ere(p, OUT);
	} else if (cflags & RZ_REGEX_NOSPEC) {
		p_str(p);
	} else {
		p_bre(p, OUT, OUT);
	}
	EMIT(OEND, 0);
	g->laststate = THERE();

	/* tidy up loose ends and fill things in */
	categorize(p, g);
	stripsnug(p, g);
	findmust(p, g);
	g->nplus = pluscount(p, g);
	g->magic = MAGIC2;
	preg->re_nsub = g->nsub;
	preg->re_g = g;
	preg->re_magic = MAGIC1;
#ifndef REDEBUG
	/* not debugging, so can't rely on the asssert() in regexec() */
	if (g->iflags & BAD) {
		SETERROR(RZ_REGEX_ASSERT);
	}
#endif
	if (p->error) {
		rz_regex_fini(preg);
	}
	return p->error;
}

/*
 - p_ere - ERE parser top level, concatenation and alternation
 */
static void p_ere(struct parse *p, int stop) { /* character this ERE should end at */
	bool isFirst = true;
	sopno prevback = 0;
	sopno prevfwd = 0;
	sopno conc = 0;
	char c;

	for (;;) {
		/* do a bunch of concatenated expressions */
		conc = HERE();
		while (MORE() && (c = PEEK()) != '|' && c != stop) {
			p_ere_exp(p);
		}
		REQUIRE(HERE() != conc, RZ_REGEX_EMPTY); /* require nonempty */

		if (!EAT('|')) {
			break; /* NOTE BREAK OUT */
		}
		if (isFirst) {
			INSERT(OCH_, conc); /* offset is wrong */
			prevfwd = conc;
			prevback = conc;
			isFirst = false;
		}
		ASTERN(OOR1, prevback);
		prevback = THERE();
		AHEAD(prevfwd); /* fix previous offset */
		prevfwd = HERE();
		EMIT(OOR2, 0); /* offset is very wrong */
	}

	if (!isFirst) { /* tail-end fixups */
		AHEAD(prevfwd);
		ASTERN(O_CH, prevback);
	}
	//asert(!MORE() || SEE(stop));
}

/*
 - p_ere_exp - parse one subERE, an atom possibly followed by a repetition op
 */
static void p_ere_exp(struct parse *p) {
	char c;
	sopno pos;
	int count;
	int count2;
	sopno subno;
	int wascaret = 0;

	if (!MORE()) { /* caller should have ensured this */
		return;
	}
	c = GETNEXT();

	pos = HERE();
	switch (c) {
	case '(':
		REQUIRE(MORE(), RZ_REGEX_EPAREN);
		p->g->nsub++;
		subno = p->g->nsub;
		if (subno < NPAREN) {
			p->pbegin[subno] = HERE();
		}
		EMIT(OLPAREN, subno);
		if (!SEE(')')) {
			p_ere(p, ')');
		}
		if (subno < NPAREN) {
			p->pend[subno] = HERE();
			if (!p->pend[subno]) {
				break;
			}
		}
		EMIT(ORPAREN, subno);
		MUSTEAT(')', RZ_REGEX_EPAREN);
		break;
	case '^':
		EMIT(OBOL, 0);
		p->g->iflags |= USEBOL;
		p->g->nbol++;
		wascaret = 1;
		break;
	case '$':
		EMIT(OEOL, 0);
		p->g->iflags |= USEEOL;
		p->g->neol++;
		break;
	case '|':
		SETERROR(RZ_REGEX_EMPTY);
		break;
	case '*':
	case '+':
	case '?':
		SETERROR(RZ_REGEX_BADRPT);
		break;
	case '.':
		if (p->g->cflags & RZ_REGEX_NEWLINE) {
			nonnewline(p);
		} else {
			EMIT(OANY, 0);
		}
		break;
	case '[':
		p_bracket(p);
		break;
	case '\\':
		REQUIRE(MORE(), RZ_REGEX_EESCAPE);
		c = GETNEXT();
		if (!isalpha(c)) {
			ordinary(p, c);
		} else {
			special(p, c);
		}
		break;
	case '{': /* okay as ordinary except if digit follows */
		REQUIRE(!MORE() || !isdigit((ut8)PEEK()), RZ_REGEX_BADRPT);
		/* FALLTHROUGH */
	default:
		ordinary(p, c);
		break;
	}

	if (!MORE()) {
		return;
	}
	c = PEEK();
	/* we call { a repetition if followed by a digit */
	if (!(c == '*' || c == '+' || c == '?' ||
		    (c == '{' && MORE2() && isdigit((ut8)PEEK2())))) {
		return; /* no repetition, we're done */
	}
	NEXT();

	REQUIRE(!wascaret, RZ_REGEX_BADRPT);
	switch (c) {
	case '*': /* implemented as +? */
		/* this case does not require the (y|) trick, noKLUDGE */
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
		break;
	case '+':
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		break;
	case '?':
		/* KLUDGE: emit y? as (y|) until subtle bug gets fixed */
		INSERT(OCH_, pos); /* offset slightly wrong */
		ASTERN(OOR1, pos); /* this one's right */
		AHEAD(pos); /* fix the OCH_ */
		EMIT(OOR2, 0); /* offset very wrong... */
		AHEAD(THERE()); /* ...so fix it */
		ASTERN(O_CH, THERETHERE());
		break;
	case '{':
		count = p_count(p);
		if (EAT(',')) {
			if (isdigit((ut8)PEEK())) {
				count2 = p_count(p);
				REQUIRE(count <= count2, RZ_REGEX_BADBR);
			} else { /* single number with comma */
				count2 = INTFINITY;
			}
		} else { /* just a single number */
			count2 = count;
		}
		repeat(p, pos, count, count2);
		if (!EAT('}')) { /* error heuristics */
			while (MORE() && PEEK() != '}') {
				NEXT();
			}
			REQUIRE(MORE(), RZ_REGEX_EBRACE);
			SETERROR(RZ_REGEX_BADBR);
		}
		break;
	}

	if (!MORE()) {
		return;
	}
	c = PEEK();
	if (!(c == '*' || c == '+' || c == '?' ||
		    (c == '{' && MORE2() && isdigit((ut8)PEEK2())))) {
		return;
	}
	SETERROR(RZ_REGEX_BADRPT);
}

/*
 - p_str - string (no metacharacters) "parser"
 */
static void p_str(struct parse *p) {
	REQUIRE(MORE(), RZ_REGEX_EMPTY);
	while (MORE()) {
		ordinary(p, GETNEXT());
	}
}

/*
 - p_bre - BRE parser top level, anchoring and concatenation
 * Giving end1 as OUT essentially eliminates the end1/end2 check.
 *
 * This implementation is a bit of a kludge, in that a trailing $ is first
 * taken as an ordinary character and then revised to be an anchor.  The
 * only undesirable side effect is that '$' gets included as a character
 * category in such cases.  This is fairly harmless; not worth fixing.
 * The amount of lookahead needed to avoid this kludge is excessive.
 */
static void p_bre(struct parse *p,
	int end1, /* first terminating character */
	int end2) /* second terminating character */
{
	sopno start = HERE();
	int first = 1; /* first subexpression? */
	int wasdollar = 0;

	if (EAT('^')) {
		EMIT(OBOL, 0);
		p->g->iflags |= USEBOL;
		p->g->nbol++;
	}
	while (MORE() && !SEETWO(end1, end2)) {
		wasdollar = p_simp_re(p, first);
		first = 0;
	}
	if (wasdollar) { /* oops, that was a trailing anchor */
		DROP(1);
		EMIT(OEOL, 0);
		p->g->iflags |= USEEOL;
		p->g->neol++;
	}

	REQUIRE(HERE() != start, RZ_REGEX_EMPTY); /* require nonempty */
}

/*
 - p_simp_re - parse a simple RE, an atom possibly followed by a repetition
 */
static int /* was the simple RE an unbackslashed $? */
p_simp_re(struct parse *p,
	int starordinary) /* is a leading * an ordinary character? */
{
	int c;
	int count;
	int count2;
	sopno pos;
	int i;
	sopno subno;
#define BACKSL (1 << CHAR_BIT)

	pos = HERE(); /* repetion op, if any, covers from here */

	if (!MORE()) { /* caller should have ensured this */
		return 0;
	}
	c = GETNEXT();
	if (c == '\\') {
		REQUIRE(MORE(), RZ_REGEX_EESCAPE);
		c = BACKSL | GETNEXT();
	}
	switch (c) {
	case '.':
		if (p->g->cflags & RZ_REGEX_NEWLINE) {
			nonnewline(p);
		} else {
			EMIT(OANY, 0);
		}
		break;
	case '[':
		p_bracket(p);
		break;
	case BACKSL | '{':
		SETERROR(RZ_REGEX_BADRPT);
		break;
	case BACKSL | '(':
		p->g->nsub++;
		subno = p->g->nsub;
		if (subno < NPAREN) {
			p->pbegin[subno] = HERE();
		}
		EMIT(OLPAREN, subno);
		/* the MORE here is an error heuristic */
		if (MORE() && !SEETWO('\\', ')')) {
			p_bre(p, '\\', ')');
		}
		if (subno < NPAREN) {
			p->pend[subno] = HERE();
			if (!p->pend[subno]) {
				break;
			}
		}
		EMIT(ORPAREN, subno);
		REQUIRE(EATTWO('\\', ')'), RZ_REGEX_EPAREN);
		break;
	case BACKSL | ')': /* should not get here -- must be user */
	case BACKSL | '}':
		SETERROR(RZ_REGEX_EPAREN);
		break;
	case BACKSL | '1':
	case BACKSL | '2':
	case BACKSL | '3':
	case BACKSL | '4':
	case BACKSL | '5':
	case BACKSL | '6':
	case BACKSL | '7':
	case BACKSL | '8':
	case BACKSL | '9':
		i = (c & ~BACKSL) - '0';
		if (p->pend[i] != 0) {
			if (i <= p->g->nsub) {
				EMIT(OBACK_, i);
				if (p->pbegin[i] != 0 && OP(p->strip[p->pbegin[i]]) == OLPAREN &&
					OP(p->strip[p->pend[i]]) == ORPAREN) {
					(void)dupl(p, p->pbegin[i] + 1, p->pend[i]);
					EMIT(O_BACK, i);
				}
			}
		} else {
			SETERROR(RZ_REGEX_ESUBREG);
		}
		p->g->backrefs = 1;
		break;
	case '*':
		REQUIRE(starordinary, RZ_REGEX_BADRPT);
		/* FALLTHROUGH */
	default:
		ordinary(p, (char)c);
		break;
	}

	if (EAT('*')) { /* implemented as +? */
		/* this case does not require the (y|) trick, noKLUDGE */
		INSERT(OPLUS_, pos);
		ASTERN(O_PLUS, pos);
		INSERT(OQUEST_, pos);
		ASTERN(O_QUEST, pos);
	} else if (EATTWO('\\', '{')) {
		count = p_count(p);
		if (EAT(',')) {
			if (MORE() && isdigit((ut8)PEEK())) {
				count2 = p_count(p);
				REQUIRE(count <= count2, RZ_REGEX_BADBR);
			} else { /* single number with comma */
				count2 = INTFINITY;
			}
		} else { /* just a single number */
			count2 = count;
		}
		repeat(p, pos, count, count2);
		if (!EATTWO('\\', '}')) { /* error heuristics */
			while (MORE() && !SEETWO('\\', '}')) {
				NEXT();
			}
			REQUIRE(MORE(), RZ_REGEX_EBRACE);
			SETERROR(RZ_REGEX_BADBR);
		}
	} else if (c == '$') { /* $ (but not \$) ends it */
		return (1);
	}

	return (0);
}

/*
 - p_count - parse a repetition count
 */
static int /* the value */
p_count(struct parse *p) {
	int count = 0;
	int ndigits = 0;

	while (MORE() && isdigit((ut8)PEEK()) && count <= DUPMAX) {
		count = count * 10 + (GETNEXT() - '0');
		ndigits++;
	}

	REQUIRE(ndigits > 0 && count <= DUPMAX, RZ_REGEX_BADBR);
	return (count);
}

/*
 - p_bracket - parse a bracketed character list
 *
 * Note a significant property of this code:  if the allocset() did SETERROR,
 * no set operations are done.
 */
static void p_bracket(struct parse *p) {
	cset *cs;
	int invert = 0;

	/* Dept of Truly Sickening Special-Case Kludges */
	if (p->next + 5 < p->end && strncmp(p->next, "[:<:]]", 6) == 0) {
		EMIT(OBOW, 0);
		NEXTn(6);
		return;
	}
	if (p->next + 5 < p->end && strncmp(p->next, "[:>:]]", 6) == 0) {
		EMIT(OEOW, 0);
		NEXTn(6);
		return;
	}

	if (!(cs = allocset(p))) {
		/* allocset did set error status in p */
		return;
	}

	if (EAT('^')) {
		invert++; /* make note to invert set at end */
	}
	if (EAT(']')) {
		CHadd(cs, ']');
	} else if (EAT('-')) {
		CHadd(cs, '-');
	}
	while (MORE() && PEEK() != ']' && !SEETWO('-', ']')) {
		p_b_term(p, cs);
	}
	if (EAT('-')) {
		CHadd(cs, '-');
	}
	MUSTEAT(']', RZ_REGEX_EBRACK);

	if (p->error != 0) { /* don't mess things up further */
		freeset(p, cs);
		return;
	}

	if (p->g->cflags & RZ_REGEX_ICASE) {
		int i;
		int ci;

		for (i = p->g->csetsize - 1; i >= 0; i--) {
			if (CHIN(cs, i) && isalpha(i)) {
				ci = othercase(i);
				if (ci != i) {
					CHadd(cs, ci);
				}
			}
		}
		if (cs->multis != NULL) {
			mccase(p, cs);
		}
	}
	if (invert) {
		int i;

		for (i = p->g->csetsize - 1; i >= 0; i--) {
			if (CHIN(cs, i)) {
				CHsub(cs, i);
			} else {
				CHadd(cs, i);
			}
		}
		if (p->g->cflags & RZ_REGEX_NEWLINE) {
			CHsub(cs, '\n');
		}
		if (cs->multis != NULL) {
			mcinvert(p, cs);
		}
	}

	if (cs->multis) { /* xxx */
		return;
	}

	if (nch(p, cs) == 1) { /* optimize singleton sets */
		ordinary(p, firstch(p, cs));
		freeset(p, cs);
	} else {
		EMIT(OANYOF, freezeset(p, cs));
	}
}

/*
 - p_b_term - parse one term of a bracketed character list
 */
static void p_b_term(struct parse *p, cset *cs) {
	char c;
	char start = 0, finish;
	int i;

	/* classify what we've got */
	switch ((MORE()) ? PEEK() : '\0') {
	case '[':
		c = (MORE2()) ? PEEK2() : '\0';
		break;
	case '-':
		SETERROR(RZ_REGEX_ERANGE);
		return; /* NOTE RETURN */
		break;
	default:
		c = '\0';
		break;
	}

	switch (c) {
	case ':': /* character class */
		NEXT2();
		REQUIRE(MORE(), RZ_REGEX_EBRACK);
		c = PEEK();
		REQUIRE(c != '-' && c != ']', RZ_REGEX_ECTYPE);
		p_b_cclass(p, cs);
		REQUIRE(MORE(), RZ_REGEX_EBRACK);
		REQUIRE(EATTWO(':', ']'), RZ_REGEX_ECTYPE);
		break;
	case '=': /* equivalence class */
		NEXT2();
		REQUIRE(MORE(), RZ_REGEX_EBRACK);
		c = PEEK();
		REQUIRE(c != '-' && c != ']', RZ_REGEX_ECOLLATE);
		p_b_eclass(p, cs);
		REQUIRE(MORE(), RZ_REGEX_EBRACK);
		REQUIRE(EATTWO('=', ']'), RZ_REGEX_ECOLLATE);
		break;
	default: /* symbol, ordinary character, or range */
		/* xxx revision needed for multichar stuff */
		start = p_b_symbol(p);
		if (SEE('-') && MORE2() && PEEK2() != ']') {
			/* range */
			NEXT();
			if (EAT('-')) {
				finish = '-';
			} else {
				finish = p_b_symbol(p);
			}
		} else {
			finish = start;
		}
		/* xxx what about signed chars here... */
		REQUIRE(start <= finish, RZ_REGEX_ERANGE);
		for (i = start; i <= finish; i++) {
			CHadd(cs, i);
		}
		break;
	}
}

/*
 - p_b_cclass - parse a character-class name and deal with it
 */
static void p_b_cclass(struct parse *p, cset *cs) {
	char *sp = p->next;
	struct cclass *cp;
	size_t len;
	char *u;
	char c;

	while (MORE() && isalpha((unsigned char)PEEK())) {
		NEXT();
	}
	len = p->next - sp;
	for (cp = cclasses; cp->name != NULL; cp++) {
		if (strncmp(cp->name, sp, len) == 0 && cp->name[len] == '\0') {
			break;
		}
	}
	if (!cp->name) {
		/* oops, didn't find it */
		SETERROR(RZ_REGEX_ECTYPE);
		return;
	}

	u = cp->chars;
	while ((c = *u++) != '\0') {
		CHadd(cs, c);
	}
	for (u = cp->multis; *u != '\0'; u += strlen(u) + 1) {
		MCadd(p, cs, u);
	}
}

/*
 - p_b_eclass - parse an equivalence-class name and deal with it
 *
 * This implementation is incomplete. xxx
 */
static void p_b_eclass(struct parse *p, cset *cs) {
	char c;

	c = p_b_coll_elem(p, '=');
	CHadd(cs, c);
}

/*
 - p_b_symbol - parse a character or [..]ed multicharacter collating symbol
 */
static char /* value of symbol */
p_b_symbol(struct parse *p) {
	char value;

	REQUIRE(MORE(), RZ_REGEX_EBRACK);
	if (!EATTWO('[', '.')) {
		return (GETNEXT());
	}

	/* collating symbol */
	value = p_b_coll_elem(p, '.');
	REQUIRE(EATTWO('.', ']'), RZ_REGEX_ECOLLATE);
	return (value);
}

/*
 - p_b_coll_elem - parse a collating-element name and look it up
 */
static char /* value of collating element */
p_b_coll_elem(struct parse *p,
	int endc) /* name ended by endc,']' */
{
	char *sp = p->next;
	struct cname *cp;
	int len;

	while (MORE() && !SEETWO(endc, ']')) {
		NEXT();
	}
	if (!MORE()) {
		SETERROR(RZ_REGEX_EBRACK);
		return (0);
	}
	len = p->next - sp;
	for (cp = cnames; cp->name != NULL; cp++) {
		if (strncmp(cp->name, sp, len) == 0 && cp->name[len] == '\0') {
			return (cp->code); /* known name */
		}
	}
	if (len == 1) {
		return (*sp); /* single character */
	}
	SETERROR(RZ_REGEX_ECOLLATE); /* neither */
	return (0);
}

/*
 - othercase - return the case counterpart of an alphabetic
 */
static char /* if no counterpart, return ch */
othercase(int ch) {
	ch = (ut8)ch;
	if (isalpha(ch)) {
		if (isupper(ch)) {
			return ((ut8)tolower(ch));
		} else if (islower(ch)) {
			return ((ut8)toupper(ch));
		} else { /* peculiar, but could happen */
			return (ch);
		}
	}
	return ch;
}

/*
 - bothcases - emit a dualcase version of a two-case character
 *
 * Boy, is this implementation ever a kludge...
 */
static void bothcases(struct parse *p, int ch) {
	char *oldnext = p->next;
	char *oldend = p->end;
	char bracket[3];

	ch = (ut8)ch;
	if (othercase(ch) != ch) { /* p_bracket() would recurse */
		p->next = bracket;
		p->end = bracket + 2;
		bracket[0] = ch;
		bracket[1] = ']';
		bracket[2] = '\0';
		p_bracket(p);
		if (p->next == bracket + 2) {
			p->next = oldnext;
			p->end = oldend;
		}
	}
}

/*
 - ordinary - emit an ordinary character
 */
static void
ordinary(struct parse *p, int ch) {
	cat_t *cap = p->g->categories;

	if ((p->g->cflags & RZ_REGEX_ICASE) && isalpha((ut8)ch) && othercase(ch) != ch) {
		bothcases(p, ch);
	} else {
		EMIT(OCHAR, (ut8)ch);
		if (cap[ch] == 0) {
			cap[ch] = p->g->ncategories++;
		}
	}
}

static void
special(struct parse *p, int ch) {
	char *oldnext = p->next;
	char *oldend = p->end;
	char bracket[16] = { 0 };
	char digits[3] = { 0 };
	char c;
	int num = 0;
	switch (ch) {
	case 'x':
		digits[0] = GETNEXT();
		digits[1] = GETNEXT();
		c = (char)strtol(digits, NULL, 16);
		ordinary(p, c);
		return;
	case 'n':
		ordinary(p, '\n');
		return;
	case 't':
		ordinary(p, '\t');
		return;
	case 'r':
		ordinary(p, '\r');
		return;
	case 's':
		num = 5;
		memcpy(bracket, "\t\r\n ]", num);
		break;
	case 'd':
		num = 4;
		memcpy(bracket, "0-9]", num);
		break;
	case 'w':
		num = 4;
		memcpy(bracket, "a-z]", num);
		break;
	default:
		SETERROR(RZ_REGEX_INVARG);
		return;
	}

	p->next = bracket;
	p->end = bracket + num;

	p_bracket(p);

	if (p->next == bracket + num) {
		p->next = oldnext;
		p->end = oldend;
	}
}

/*
 - nonnewline - emit RZ_REGEX_NEWLINE version of OANY
 *
 * Boy, is this implementation ever a kludge...
 */
static void
nonnewline(struct parse *p) {
	char *oldnext = p->next;
	char *oldend = p->end;
	char bracket[4];

	p->next = bracket;
	p->end = bracket + 3;
	bracket[0] = '^';
	bracket[1] = '\n';
	bracket[2] = ']';
	bracket[3] = '\0';
	p_bracket(p);
	if (p->next == bracket + 3) {
		p->next = oldnext;
		p->end = oldend;
	}
}

/*
 - repeat - generate code for a bounded repetition, recursively if needed
 */
static void
repeat(struct parse *p,
	sopno start, /* operand from here to end of strip */
	int from, /* repeated from this number */
	int to) /* to this number of times (maybe INTFINITY) */
{
	sopno finish = HERE();
#define N         2
#define INF       3
#define REP(f, t) ((f)*8 + (t))
#define MAP(n)    (((n) <= 1) ? (n) : ((n) == INTFINITY) ? INF \
							 : N)
	sopno copy;

	if (p->error != 0) { /* head off possible runaway recursion */
		return;
	}

	if (from > to) {
		return;
	}

	switch (REP(MAP(from), MAP(to))) {
	case REP(0, 0): /* must be user doing this */
		DROP(finish - start); /* drop the operand */
		break;
	case REP(0, 1): /* as x{1,1}? */
	case REP(0, N): /* as x{1,n}? */
	case REP(0, INF): /* as x{1,}? */
		/* KLUDGE: emit y? as (y|) until subtle bug gets fixed */
		INSERT(OCH_, start); /* offset is wrong... */
		repeat(p, start + 1, 1, to);
		ASTERN(OOR1, start);
		AHEAD(start); /* ... fix it */
		EMIT(OOR2, 0);
		AHEAD(THERE());
		ASTERN(O_CH, THERETHERE());
		break;
	case REP(1, 1): /* trivial case */
		/* done */
		break;
	case REP(1, N): /* as x?x{1,n-1} */
		/* KLUDGE: emit y? as (y|) until subtle bug gets fixed */
		INSERT(OCH_, start);
		ASTERN(OOR1, start);
		AHEAD(start);
		EMIT(OOR2, 0); /* offset very wrong... */
		AHEAD(THERE()); /* ...so fix it */
		ASTERN(O_CH, THERETHERE());
		copy = dupl(p, start + 1, finish + 1);
		if (copy == finish + 4) {
			repeat(p, copy, 1, to - 1);
		}
		break;
	case REP(1, INF): /* as x+ */
		INSERT(OPLUS_, start);
		ASTERN(O_PLUS, start);
		break;
	case REP(N, N): /* as xx{m-1,n-1} */
		copy = dupl(p, start, finish);
		repeat(p, copy, from - 1, to - 1);
		break;
	case REP(N, INF): /* as xx{n-1,INF} */
		copy = dupl(p, start, finish);
		repeat(p, copy, from - 1, to);
		break;
	default: /* "can't happen" */
		SETERROR(RZ_REGEX_ASSERT); /* just in case */
		break;
	}
}

/*
 - seterr - set an error condition
 */
static int /* useless but makes type checking happy */
seterr(struct parse *p, int e) {
	if (p->error == 0) { /* keep earliest error condition */
		p->error = e;
	}
	p->next = nuls; /* try to bring things to a halt */
	p->end = nuls;
	return (0); /* make the return value well-defined */
}

/*
 - allocset - allocate a set of characters for []
 */
static cset *allocset(struct parse *p) {
	int no = p->g->ncsets++;
	size_t nc;
	size_t nbytes;
	cset *cs;
	size_t css = (size_t)p->g->csetsize;
	int i;

	if (no >= p->ncsalloc) { /* need another column of space */
		void *ptr;

		p->ncsalloc += CHAR_BIT;
		nc = p->ncsalloc;
		if (nc % CHAR_BIT) {
			goto nomem;
		}
		nbytes = nc / CHAR_BIT * css;

		ptr = (cset *)realloc((char *)p->g->sets, nc * sizeof(cset));
		if (!ptr) {
			goto nomem;
		}
		p->g->sets = ptr;

		ptr = (ut8 *)realloc((char *)p->g->setbits, nbytes);
		if (!ptr) {
			goto nomem;
		}
		p->g->setbits = ptr;

		for (i = 0; i < no; i++) {
			p->g->sets[i].ptr = p->g->setbits + css * (i / CHAR_BIT);
		}

		(void)memset((char *)p->g->setbits + (nbytes - css), 0, css);
	}
	/* XXX should not happen */
	if (!p->g->sets || !p->g->setbits) {
		goto nomem;
	}

	cs = &p->g->sets[no];
	cs->ptr = p->g->setbits + css * ((no) / CHAR_BIT);
	cs->mask = 1 << ((no) % CHAR_BIT);
	cs->hash = 0;
	cs->smultis = 0;
	cs->multis = NULL;

	return (cs);
nomem:
	RZ_FREE(p->g->sets);
	RZ_FREE(p->g->setbits);

	SETERROR(RZ_REGEX_ESPACE);
	/* caller's responsibility not to do set ops */
	return (NULL);
}

/*
 - freeset - free a now-unused set
 */
static void freeset(struct parse *p, cset *cs) {
	int i;
	cset *top = &p->g->sets[p->g->ncsets];
	size_t css = (size_t)p->g->csetsize;

	for (i = 0; i < css; i++) {
		CHsub(cs, i);
	}
	if (cs == top - 1) { /* recover only the easy case */
		p->g->ncsets--;
	}
}

/*
 - freezeset - final processing on a set of characters
 *
 * The main task here is merging identical sets.  This is usually a waste
 * of time (although the hash code minimizes the overhead), but can win
 * big if RZ_REGEX_ICASE is being used.  RZ_REGEX_ICASE, by the way, is why the hash
 * is done using addition rather than xor -- all ASCII [aA] sets xor to
 * the same value!
 */
static int /* set number */
freezeset(struct parse *p, cset *cs) {
	ut8 h = cs->hash;
	int i;
	cset *top = &p->g->sets[p->g->ncsets];
	cset *cs2;
	size_t css = (size_t)p->g->csetsize;

	/* look for an earlier one which is the same */
	for (cs2 = &p->g->sets[0]; cs2 < top; cs2++) {
		if (cs2->hash == h && cs2 != cs) {
			/* maybe */
			for (i = 0; i < css; i++) {
				if (!!CHIN(cs2, i) != !!CHIN(cs, i)) {
					break; /* no */
				}
			}
			if (i == css) {
				break; /* yes */
			}
		}
	}

	if (cs2 < top) { /* found one */
		freeset(p, cs);
		cs = cs2;
	}

	return ((int)(cs - p->g->sets));
}

/*
 - firstch - return first character in a set (which must have at least one)
 */
static int /* character; there is no "none" value */
firstch(struct parse *p, cset *cs) {
	int i;
	size_t css = (size_t)p->g->csetsize;

	for (i = 0; i < css; i++) {
		if (CHIN(cs, i)) {
			return ((char)i);
		}
	}
	return (0); /* arbitrary */
}

/*
 - nch - number of characters in a set
 */
static int nch(struct parse *p, cset *cs) {
	int i;
	size_t css = (size_t)p->g->csetsize;
	int n = 0;

	for (i = 0; i < css; i++) {
		if (CHIN(cs, i)) {
			n++;
		}
	}
	return (n);
}

/*
 - mcadd - add a collating element to a cset
 */
static void mcadd(struct parse *p, cset *cs, char *cp) {
	size_t oldend = cs->smultis;
	void *np;

	cs->smultis += strlen(cp) + 1;
	np = realloc(cs->multis, cs->smultis);
	if (!np) {
		if (cs->multis) {
			free(cs->multis);
		}
		cs->multis = NULL;
		SETERROR(RZ_REGEX_ESPACE);
		return;
	}
	cs->multis = np;

	STRLCPY(cs->multis + oldend - 1, cp, cs->smultis - oldend + 1);
}

/*
 - mcinvert - invert the list of collating elements in a cset
 *
 * This would have to know the set of possibilities.  Implementation
 * is deferred.
 */
/* ARGSUSED */
static void mcinvert(struct parse *p, cset *cs) {
	//asert(!cs->multis);	/* xxx */
	return;
}

/*
 - mccase - add case counterparts of the list of collating elements in a cset
 *
 * This would have to know the set of possibilities.  Implementation
 * is deferred.
 */
/* ARGSUSED */
static void mccase(struct parse *p, cset *cs) {
	//asert(!cs->multis);	/* xxx */
	return;
}

/*
 - isinsets - is this character in any sets?
 */
static int /* predicate */
isinsets(struct re_guts *g, int c) {
	ut8 *col;
	int i;
	int ncols = (g->ncsets + (CHAR_BIT - 1)) / CHAR_BIT;
	unsigned uc = (ut8)c;

	for (i = 0, col = g->setbits; i < ncols; i++, col += g->csetsize) {
		if (col[uc] != 0) {
			return (1);
		}
	}
	return (0);
}

/*
 - samesets - are these two characters in exactly the same sets?
 */
static int /* predicate */
samesets(struct re_guts *g, int c1, int c2) {
	ut8 *col;
	int i;
	int ncols = (g->ncsets + (CHAR_BIT - 1)) / CHAR_BIT;
	unsigned uc1 = (ut8)c1;
	unsigned uc2 = (ut8)c2;

	for (i = 0, col = g->setbits; i < ncols; i++, col += g->csetsize) {
		if (col[uc1] != col[uc2]) {
			return (0);
		}
	}
	return (1);
}

/*
 - categorize - sort out character categories
 */
static void
categorize(struct parse *p, struct re_guts *g) {
	cat_t *cats = g ? g->categories : NULL;
	int c;
	int c2;
	cat_t cat;

	/* avoid making error situations worse */
	if (!p || p->error != 0 || !cats) {
		return;
	}

	for (c = CHAR_MIN; c <= CHAR_MAX; c++) {
		if (*(cats + c) && isinsets(g, c)) {
			cat = g->ncategories++;
			cats[c] = cat;
			for (c2 = c + 1; c2 <= CHAR_MAX; c2++) {
				if (cats[c2] == 0 && samesets(g, c, c2)) {
					cats[c2] = cat;
				}
			}
		}
	}
}

/*
 - dupl - emit a duplicate of a bunch of sops
 */
static sopno /* start of duplicate */
dupl(struct parse *p,
	sopno start, /* from here */
	sopno finish) /* to this less one */
{
	sopno ret = HERE();
	sopno len = finish - start;

	if (finish >= start) {
		if (len == 0) {
			return (ret);
		}
		enlarge(p, p->ssize + len); /* this many unexpected additions */
		if (p->ssize >= p->slen + len) {
			(void)memcpy((char *)(p->strip + p->slen),
				(char *)(p->strip + start), (size_t)len * sizeof(sop));
			p->slen += len;
			return (ret);
		}
	}
	return ret;
}

/*
 - doemit - emit a strip operator
 *
 * It might seem better to implement this as a macro with a function as
 * hard-case backup, but it's just too big and messy unless there are
 * some changes to the data structures.  Maybe later.
 */
static void
doemit(struct parse *p, sop op, size_t opnd) {
	/* avoid making error situations worse */
	if (p->error != 0) {
		return;
	}

	/* deal with oversize operands ("can't happen", more or less) */
	if (opnd < 1 << OPSHIFT) {

		/* deal with undersized strip */
		if (p->slen >= p->ssize) {
			enlarge(p, (p->ssize + 1) / 2 * 3); /* +50% */
		}
		if (p->slen < p->ssize) {
			/* finally, it's all reduced to the easy case */
			p->strip[p->slen++] = SOP(op, opnd);
		}
	}
}

/*
 - doinsert - insert a sop into the strip
 */
static void
doinsert(struct parse *p, sop op, size_t opnd, sopno pos) {
	sopno sn;
	sop s;
	int i;

	/* avoid making error situations worse */
	if (p->error != 0) {
		return;
	}

	sn = HERE();
	EMIT(op, opnd); /* do checks, ensure space */
	if (HERE() != sn + 1) {
		return;
	}
	s = p->strip[sn];

	/* adjust paren pointers */
	if (pos > 0) {
		for (i = 1; i < NPAREN; i++) {
			if (p->pbegin[i] >= pos) {
				p->pbegin[i]++;
			}
			if (p->pend[i] >= pos) {
				p->pend[i]++;
			}
		}
	}

	memmove((char *)&p->strip[pos + 1], (char *)&p->strip[pos],
		(HERE() - pos - 1) * sizeof(sop));
	p->strip[pos] = s;
}

/*
 - dofwd - complete a forward reference
 */
static void
dofwd(struct parse *p, sopno pos, sop value) {
	/* avoid making error situations worse */
	if (p->error != 0) {
		return;
	}

	if (value < 1 << OPSHIFT) {
		p->strip[pos] = OP(p->strip[pos]) | value;
	}
}

/*
 - enlarge - enlarge the strip
 */
static void
enlarge(struct parse *p, sopno size) {
	sop *sp;

	if (p->ssize >= size) {
		return;
	}

	sp = (sop *)realloc(p->strip, size * sizeof(sop));
	if (!sp) {
		SETERROR(RZ_REGEX_ESPACE);
		return;
	}
	p->strip = sp;
	p->ssize = size;
}

/*
 - stripsnug - compact the strip
 */
static void
stripsnug(struct parse *p, struct re_guts *g) {
	g->nstates = p->slen;
	g->strip = (sop *)realloc((char *)p->strip, p->slen * sizeof(sop));
	if (!g->strip) {
		SETERROR(RZ_REGEX_ESPACE);
		g->strip = p->strip;
	}
}

/*
 - findmust - fill in must and mlen with longest mandatory literal string
 *
 * This algorithm could do fancy things like analyzing the operands of |
 * for common subsequences.  Someday.  This code is simple and finds most
 * of the interesting cases.
 *
 * Note that must and mlen got initialized during setup.
 */
static void
findmust(struct parse *p, struct re_guts *g) {
	sop *scan;
	sop *start = NULL; /* start initialized in the default case, after that */
	sop *newstart = NULL; /* newstart was initialized in the OCHAR case */
	sopno newlen;
	sop s;
	char *cp;
	sopno i;

	/* avoid making error situations worse */
	if (p->error != 0) {
		return;
	}

	/* find the longest OCHAR sequence in strip */
	newlen = 0;
	start = scan = g->strip + 1;
	do {
		s = *scan++;
		switch (OP(s)) {
		case OCHAR: /* sequence member */
			if (newlen == 0) { /* new sequence */
				newstart = scan - 1;
			}
			newlen++;
			break;
		case OPLUS_: /* things that don't break one */
		case OLPAREN:
		case ORPAREN:
			break;
		case OQUEST_: /* things that must be skipped */
		case OCH_:
			scan--;
			do {
				scan += OPND(s);
				s = *scan;
				/* asert() interferes w debug printouts */
				if (OP(s) != O_QUEST && OP(s) != O_CH &&
					OP(s) != OOR2) {
					g->iflags |= BAD;
					return;
				}
			} while (OP(s) != O_QUEST && OP(s) != O_CH);
			/* fallthrough */
		default: /* things that break a sequence */
			if (newlen > g->mlen) { /* ends one */
				start = newstart;
				g->mlen = newlen;
			}
			newlen = 0;
			break;
		}
	} while (OP(s) != OEND);

	if (g->mlen == 0) { /* there isn't one */
		return;
	}

	/* turn it into a character string */
	g->must = malloc((size_t)g->mlen + 1);
	if (!g->must) { /* argh; just forget it */
		g->mlen = 0;
		return;
	}
	cp = g->must;
	scan = start;
	for (i = g->mlen; i > 0; i--) {
		while (OP(s = *scan++) != OCHAR) {
			continue;
		}
		if (cp < g->must + g->mlen) {
			*cp++ = (char)OPND(s);
		}
	}
	if (cp == g->must + g->mlen) {
		*cp++ = '\0'; /* just on general principles */
	}
}

/*
 - pluscount - count + nesting
 */
static sopno /* nesting depth */
pluscount(struct parse *p, struct re_guts *g) {
	sop *scan;
	sop s;
	sopno plusnest = 0;
	sopno maxnest = 0;

	if (p->error != 0) {
		return (0); /* there may not be an OEND */
	}

	scan = g->strip + 1;
	do {
		s = *scan++;
		switch (OP(s)) {
		case OPLUS_:
			plusnest++;
			break;
		case O_PLUS:
			if (plusnest > maxnest) {
				maxnest = plusnest;
			}
			plusnest--;
			break;
		}
	} while (OP(s) != OEND);
	if (plusnest != 0) {
		g->iflags |= BAD;
	}
	return (maxnest);
}
