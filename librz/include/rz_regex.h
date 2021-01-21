#ifndef RZ_REGEX_H
#define RZ_REGEX_H

#include <rz_types.h>
#include <rz_list.h>
#include <sys/types.h>

typedef struct rz_regex_t {
	int re_magic;
	size_t re_nsub; /* number of parenthesized subexpressions */
	const char *re_endp; /* end pointer for RZ_REGEX_PEND */
	struct re_guts *re_g; /* none of your business :-) */
	int re_flags;
} RzRegex;

typedef struct rz_regmatch_t {
	st64 rm_so; /* start of match */
	st64 rm_eo; /* end of match */
} RzRegexMatch;

/* regcomp() flags */
#define RZ_REGEX_BASIC    0000
#define RZ_REGEX_EXTENDED 0001
#define RZ_REGEX_ICASE    0002
#define RZ_REGEX_NOSUB    0004
#define RZ_REGEX_NEWLINE  0010
#define RZ_REGEX_NOSPEC   0020
#define RZ_REGEX_PEND     0040
#define RZ_REGEX_DUMP     0200

/* regerror() flags */
#define RZ_REGEX_ENOSYS   (-1) /* Reserved */
#define RZ_REGEX_NOMATCH  1
#define RZ_REGEX_BADPAT   2
#define RZ_REGEX_ECOLLATE 3
#define RZ_REGEX_ECTYPE   4
#define RZ_REGEX_EESCAPE  5
#define RZ_REGEX_ESUBREG  6
#define RZ_REGEX_EBRACK   7
#define RZ_REGEX_EPAREN   8
#define RZ_REGEX_EBRACE   9
#define RZ_REGEX_BADBR    10
#define RZ_REGEX_ERANGE   11
#define RZ_REGEX_ESPACE   12
#define RZ_REGEX_BADRPT   13
#define RZ_REGEX_EMPTY    14
#define RZ_REGEX_ASSERT   15
#define RZ_REGEX_INVARG   16
#define RZ_REGEX_ILLSEQ   17
#define RZ_REGEX_ATOI     255 /* convert name to number (!) */
#define RZ_REGEX_ITOA     0400 /* convert number to name (!) */

/* regexec() flags */
#define RZ_REGEX_NOTBOL   00001
#define RZ_REGEX_NOTEOL   00002
#define RZ_REGEX_STARTEND 00004
#define RZ_REGEX_TRACE    00400 /* tracing of execution */
#define RZ_REGEX_LARGE    01000 /* force large representation */
#define RZ_REGEX_BACKR    02000 /* force use of backref code */

RZ_API RzRegex *rz_regex_new(const char *pattern, const char *cflags);
RZ_API int rz_regex_run(const char *pattern, const char *flags, const char *text);
RZ_API int rz_regex_match(const char *pattern, const char *flags, const char *text);
RZ_API RzList *rz_regex_get_match_list(const char *pattern, const char *flags, const char *text);
RZ_API int rz_regex_flags(const char *flags);
RZ_API int rz_regex_comp(RzRegex *, const char *, int);
RZ_API size_t rz_regex_error(int, const RzRegex *, char *, size_t);
/*
 * gcc under c99 mode won't compile "[]" by itself.  As a workaround,
 * a dummy argument name is added.
 */
RZ_API bool rz_regex_check(const RzRegex *rr, const char *str);
RZ_API int rz_regex_exec(const RzRegex *preg, const char *string, size_t nmatch, RzRegexMatch __pmatch[], int eflags);
RZ_API void rz_regex_free(RzRegex *);
RZ_API void rz_regex_fini(RzRegex *);

#endif /* !_REGEX_H_ */
