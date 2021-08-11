// SPDX-FileCopyrightText: 2001-2004 Fabrice Bellard
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <rz_types.h>
#include <rz_list.h>
#include <rz_util/rz_file.h>
#include <rz_util.h>
#include <math.h>
#include "c_preprocessor.h"
#include "c_preprocessor_tokens.h"

CPreprocessorState *c_preprocessor_state_new() {
	return NULL;
}

void c_preprocessor_state_free(CPreprocessorState *state) {
}

int c_preprocessor_open_file(CPreprocessorState *state, const char *path) {
	return -1;
}

int c_preprocessor_open_string(CPreprocessorState *state, const char *code, size_t size) {
	return -1;
}

void preprocessor_debug(CPreprocessorState *state, const char *fmt, ...) {
	rz_return_if_fail(state && fmt);
	if (state->verbose) {
		va_list ap;
		va_start(ap, fmt);
		rz_strbuf_vappendf(state->debug, fmt, ap);
		va_end(ap);
	}
}

void preprocessor_error(CPreprocessorState *state, const char *fmt, ...) {
	rz_return_if_fail(state && fmt);
	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vappendf(state->errors, fmt, ap);
	va_end(ap);
	state->nb_errors++;
}

void preprocessor_warning(CPreprocessorState *state, const char *fmt, ...) {
	rz_return_if_fail(state && fmt);
	va_list ap;
	va_start(ap, fmt);
	rz_strbuf_vappendf(state->warnings, fmt, ap);
	va_end(ap);
}

/* field 'Sym.t' for macros */
#define MACRO_OBJ  0 /* object like macro */
#define MACRO_FUNC 1 /* function like macro */

/********************************************************/
#define CH_EOB '\\' /* end of buffer or '\0' char in file */
#define CH_EOF (-1) /* end of file */

#define TOK_HASH_SIZE  8192 /* must be a power of two */
#define TOK_ALLOC_INCR 512 /* must be a power of two */
#define TOK_MAX_SIZE   4 /* token max size in int unit when stored in string */

/* additional informations about token */
#define TOK_FLAG_BOL   0x0001 /* beginning of line before */
#define TOK_FLAG_BOF   0x0002 /* beginning of file before */
#define TOK_FLAG_ENDIF 0x0004 /* a endif was found matching starting #ifdef */
#define TOK_FLAG_EOF   0x0008 /* end of file */

#define PARSE_FLAG_PREPROCESS 0x0001 /* activate preprocessing */
#define PARSE_FLAG_TOK_NUM    0x0002 /* return numbers instead of TOK_PPNUM */
#define PARSE_FLAG_LINEFEED   0x0004 /* line feed is returned as a \
				     token. line feed is also \
				     returned at eof */
#define PARSE_FLAG_ASM_COMMENTS 0x0008 /* '#' can be used for line comment */
#define PARSE_FLAG_SPACES       0x0010 /* next() returns space tokens (for -E) */

#define SYM_FIELD      0x20000000 /* struct/union field symbol space */
#define SYM_FIRST_ANOM 0x10000000 /* first anonymous sym */

typedef int nwchar_t;

// FIXME: These should go into the CPreprocessorState
static struct BufferedFile *file;
static const int *macro_ptr;

// Identificator hashtable
static int tok_ident;
static TokenSym **table_ident;

/* ------------------------------------------------------------------------- */

// FIXME: These should be part of the "unget" state
static int *macro_ptr_allocated;
static const int *unget_saved_macro_ptr;
static int unget_saved_buffer[TOK_MAX_SIZE + 1];
static int unget_buffer_enabled;

// FIXME: Use the ht_pp_ API here
static TokenSym *hash_ident[TOK_HASH_SIZE];
static char token_buf[STRING_MAX_SIZE + 1];

/* true if isid(c) || isnum(c) || isdot(c) */
static unsigned char isidnum_table[256 - CH_EOF];

/* WARNING: the content of this string encodes token numbers */
static const unsigned char tok_two_chars[] =
	"<=\236>=\235!=\225&&\240||\241++\244--\242==\224<<\1>>\2+=\253"
	"-=\255*=\252/=\257%=\245&=\246^=\336|=\374->\313..\250##\266";

/* space exlcuding newline */
static inline int is_space(int ch) {
	return ch == ' ' || ch == '\t' || ch == '\v' || ch == '\f' || ch == '\r';
}

static inline int isid(int c) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static inline int isnum(int c) {
	return c >= '0' && c <= '9';
}

static inline int isdot(int c) {
	return c == '.';
}

static inline int isoct(int c) {
	return c >= '0' && c <= '7';
}

static inline int toup(int c) {
	return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}

/* ------------------------------------------------------------------------- */

/*
 * \brief Opens the file for buffered access and adds it in the stack
 */
static BufferedFile *preprocessor_open_file_buffered(CPreprocessorState *state, BufferedFile *prev, const char *filename, int initlen) {
	BufferedFile *bf;
	int buflen = initlen ? initlen : IO_BUF_SIZE;

	bf = malloc(sizeof(BufferedFile) + buflen);
	if (!bf) {
		return NULL;
	}
	bf->buf_ptr = bf->buffer;
	bf->buf_end = bf->buffer + initlen;
	bf->buf_end[0] = CH_EOB; /* put eob symbol */
	rz_str_ncpy(bf->filename, filename, sizeof(bf->filename));
	// FIXME: Use Rizin's RzUtil function
#ifdef __WINDOWS__
	normalize_slashes(bf->filename);
#endif
	bf->line_num = 1;
	bf->ifndef_macro = 0;
	bf->ifdef_stack_ptr = state->ifdef_stack_ptr;
	bf->fd = -1;
	bf->prev = prev;
	return bf;
}

/*
 * \brief Closes the buffered file and returns previous in the stack
 */
static BufferedFile *preprocessor_close_file(BufferedFile *bf) {
	rz_return_val_if_fail(bf, NULL);
	BufferedFile *prev = bf->prev;
	if (bf->fd > 0) {
		close(bf->fd);
	}
	free(bf);
	return prev;
}

/* ------------------------------------------------------------------------- */

long long expr_const(CPreprocessorState *state);
static char *get_tok_str(CPreprocessorState *state, int v, CValue *cv);
void next(CPreprocessorState *state);
static void next_nomacro_spc(CPreprocessorState *state);
static void next_nomacro(CPreprocessorState *state);

static void macro_subst(
	CPreprocessorState *state,
	TokenString *tok_str,
	Sym **nested_list,
	const int *macro_str,
	struct macro_level **can_read_stream);

static inline void skip(CPreprocessorState *state, int c) {
	if (state->cur->tok != c) {
		preprocessor_error(state, "'%c' expected (got \"%s\")",
			c, get_tok_str(state, state->cur->tok, &state->cur->tokc));
	}
	next(state);
}

static inline void expect(CPreprocessorState *state, const char *msg) {
	preprocessor_error(state, "%s expected", msg);
}

static inline int pp_nerr(CPreprocessorState *state) {
	return state->nb_errors;
}

/* ------------------------------------------------------------------------- */
/* CString handling */
static void cstr_realloc(CString *cstr, int new_size) {
	int size;
	void *data;

	size = cstr->size_allocated;
	if (size == 0) {
		size = 8; /* no need to allocate a too small first string */
	}
	while (size < new_size) {
		size = size * 2;
	}
	data = realloc(cstr->data_allocated, size);
	cstr->data_allocated = data;
	cstr->size_allocated = size;
	cstr->data = data;
}

/* add a byte */
static void cstr_ccat(CString *cstr, int ch) {
	int size;
	size = cstr->size + 1;
	if (size > cstr->size_allocated) {
		cstr_realloc(cstr, size);
	}
	unsigned char *uchar = ((unsigned char *)cstr->data);
	if (uchar) {
		uchar[size - 1] = ch;
		cstr->size = size;
	}
}

static void cstr_cat(CString *cstr, const char *str) {
	int c;
	for (;;) {
		c = *str;
		if (c == '\0') {
			break;
		}
		cstr_ccat(cstr, c);
		str++;
	}
}

/* add a wide char */
static void cstr_wccat(CString *cstr, int ch) {
	int size;
	size = cstr->size + sizeof(nwchar_t);
	if (size > cstr->size_allocated) {
		cstr_realloc(cstr, size);
	}
	*(nwchar_t *)(((unsigned char *)cstr->data) + size - sizeof(nwchar_t)) = ch;
	cstr->size = size;
}

static void cstr_new(CString *cstr) {
	memset(cstr, 0, sizeof(CString));
}

/* free string and reset it to NULL */
static void cstr_free(CString *cstr) {
	free(cstr->data_allocated);
	cstr_new(cstr);
}

/* reset string to empty */
static void cstr_reset(CString *cstr) {
	cstr->size = 0;
}

/* XXX: unicode ? */
static void add_char(CString *cstr, int c) {
	if (c == '\'' || c == '\"' || c == '\\') {
		/* XXX: could be more precise if char or string */
		cstr_ccat(cstr, '\\');
	}
	if (c >= 32 && c <= 126) {
		cstr_ccat(cstr, c);
	} else {
		cstr_ccat(cstr, '\\');
		if (c == '\n') {
			cstr_ccat(cstr, 'n');
		} else {
			cstr_ccat(cstr, '0' + ((c >> 6) & 7));
			cstr_ccat(cstr, '0' + ((c >> 3) & 7));
			cstr_ccat(cstr, '0' + (c & 7));
		}
	}
}

/* ------------------------------------------------------------------------- */

#define SYM_POOL_NB (8192 / sizeof(Sym))

static Sym *__sym_malloc(CPreprocessorState *state) {
	Sym *sym, *last_sym;
	int i;
	int sym_pool_size = SYM_POOL_NB * sizeof(Sym);
	Sym *sym_pool = malloc(sym_pool_size);

	memset(sym_pool, 0, sym_pool_size);

	last_sym = state->sym_free_first;
	sym = sym_pool;
	for (i = 0; i < SYM_POOL_NB; i++) {
		sym->next = last_sym;
		last_sym = sym;
		sym++;
	}
	state->sym_free_first = last_sym;
	return last_sym;
}

static inline Sym *sym_malloc(CPreprocessorState *state) {
	Sym *sym = state->sym_free_first;
	if (!sym) {
		sym = __sym_malloc(state);
	}
	state->sym_free_first = sym->next;
	return sym;
}

static inline void sym_free(CPreprocessorState *state, Sym *sym) {
	sym->next = state->sym_free_first;
	state->sym_free_first = sym;
}

/* find a symbol and return its associated structure. 's' is the top
   of the symbol stack */
static inline Sym *sym_find2(Sym *s, int v) {
	while (s) {
		if (s->v == v) {
			return s;
		}
		s = s->prev;
	}
	return NULL;
}

// TODO: Convert it to the RzVector
/* push, without hashing */
static Sym *sym_push2(CPreprocessorState *state, Sym **ps, int v, int t, long long c) {
	Sym *s;
	// printf (" %d %ld set symbol '%s'\n", t, c, get_tok_str(v, NULL));
	// s = *ps;
	s = sym_malloc(state);
	s->v = v;
	s->t = t;
#ifdef _WIN64
	s->d = NULL;
#endif
	s->c = c;
	s->next = NULL;
	/* add in stack */
	s->prev = *ps;
	*ps = s;
	return s;
}

/* ------------------------------------------------------------------------- */

/* allocate a new token */
static TokenSym *tok_alloc_new(CPreprocessorState *state, TokenSym **pts, const char *str, int len) {
	TokenSym *ts, **ptable;
	int i;

	if (tok_ident >= SYM_FIRST_ANOM) {
		preprocessor_error(state, "memory full");
	}

	// TODO: Use ht_up_* API here
	/* expand token table if needed */
	i = tok_ident - TOK_IDENT;
	if ((i % TOK_ALLOC_INCR) == 0) {
		ptable = realloc(table_ident, (i + TOK_ALLOC_INCR) * sizeof(TokenSym *));
		table_ident = ptable;
	}
	ts = malloc(sizeof(TokenSym) + len);
	table_ident[i] = ts;
	ts->tok = tok_ident++;
	ts->sym_define = NULL;
	ts->sym_identifier = NULL;
	ts->len = len;
	ts->hash_next = NULL;
	memcpy(ts->str, str, len);
	ts->str[len] = '\0';
	*pts = ts;
	return ts;
}

// TODO: Use ht_pp_ API here
#define TOK_HASH_INIT       1
#define TOK_HASH_FUNC(h, c) ((h)*263 + (c))

/* find a token and add it if not found */
static TokenSym *tok_alloc(CPreprocessorState *state, const char *str, int len) {
	TokenSym *ts, **pts;
	int i;
	unsigned int h;

	// FIXME: Use ht_pp_* API here
	h = TOK_HASH_INIT;
	for (i = 0; i < len; i++) {
		h = TOK_HASH_FUNC(h, ((unsigned char *)str)[i]);
	}
	h &= (TOK_HASH_SIZE - 1);

	pts = &hash_ident[h];
	for (;;) {
		ts = *pts;
		if (!ts) {
			break;
		}
		if (ts->len == len && !memcmp(ts->str, str, len)) {
			return ts;
		}
		pts = &(ts->hash_next);
	}
	return tok_alloc_new(state, pts, str, len);
}

/* XXX: buffer overflow */
/* XXX: float tokens */
static char *get_tok_str(CPreprocessorState *state, int v, CValue *cv) {
	static char buf[STRING_MAX_SIZE + 1];
	static CString cstr_buf;
	CString *cstr;
	char *p;
	int i, len;

	/* NOTE: to go faster, we give a fixed buffer for small strings */
	cstr_reset(&cstr_buf);
	cstr_buf.data = buf;
	cstr_buf.size_allocated = sizeof(buf);
	p = buf;

	switch (v) {
	case TOK_CINT:
	case TOK_CUINT:
		/* XXX: not quite exact, but only useful for testing */
		if (cv) {
			sprintf(p, "%u", cv->ui);
		}
		break;
	case TOK_CLLONG:
	case TOK_CULLONG:
		/* XXX: not quite exact, but only useful for testing  */
		if (cv) {
			sprintf(p, "%" PFMT64u, cv->ull);
		}
		break;
	case TOK_LCHAR:
		cstr_ccat(&cstr_buf, 'L');
	case TOK_CCHAR:
		cstr_ccat(&cstr_buf, '\'');
		if (cv) {
			add_char(&cstr_buf, cv->i);
		}
		cstr_ccat(&cstr_buf, '\'');
		cstr_ccat(&cstr_buf, '\0');
		break;
	case TOK_PPNUM:
		if (cv) {
			cstr = cv->cstr;
			len = cstr->size - 1;
			for (i = 0; i < len; i++) {
				add_char(&cstr_buf, ((unsigned char *)cstr->data)[i]);
			}
			cstr_ccat(&cstr_buf, '\0');
		} else {
			preprocessor_error(state, "cv = nil\n");
		}
		break;
	case TOK_LSTR:
		cstr_ccat(&cstr_buf, 'L');
	case TOK_STR:
		if (cv) {
			cstr = cv->cstr;
			cstr_ccat(&cstr_buf, '\"');
			if (v == TOK_STR) {
				len = cstr->size - 1;
				for (i = 0; i < len; i++) {
					add_char(&cstr_buf, ((unsigned char *)cstr->data)[i]);
				}
			} else {
				len = (cstr->size / sizeof(nwchar_t)) - 1;
				for (i = 0; i < len; i++) {
					add_char(&cstr_buf, ((nwchar_t *)cstr->data)[i]);
				}
			}
			cstr_ccat(&cstr_buf, '\"');
			cstr_ccat(&cstr_buf, '\0');
		} else {
			preprocessor_error(state, "cv = nil\n");
		}
		break;
	case TOK_LT:
		v = '<';
		goto addv;
	case TOK_GT:
		v = '>';
		goto addv;
	case TOK_DOTS:
		return strcpy(p, "...");
	case TOK_A_SHL:
		return strcpy(p, "<<=");
	case TOK_A_SAR:
		return strcpy(p, ">>=");
	default:
		if (v < TOK_IDENT) {
			/* search in two bytes table */
			const unsigned char *q = tok_two_chars;
			while (*q) {
				if (q[2] == v) {
					*p++ = q[0];
					*p++ = q[1];
					*p = '\0';
					return buf;
				}
				q += 3;
			}
		addv:
			*p++ = v;
			*p = '\0';
		} else if (v < tok_ident) {
			// TODO: Use ht_up_* API here
			return table_ident[v - TOK_IDENT]->str;
		} else if (v >= SYM_FIRST_ANOM) {
			/* special name for anonymous symbol */
			sprintf(p, "%u", v - SYM_FIRST_ANOM);
		} else {
			/* should never happen */
			return NULL;
		}
		break;
	}
	return cstr_buf.data;
}

/* return the number of additional 'ints' necessary to store the
   token */
static inline int tok_ext_size(CPreprocessorState *state, int t) {
	switch (t) {
	/* 4 bytes */
	case TOK_CINT:
	case TOK_CUINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
	case TOK_CFLOAT:
	case TOK_LINENUM:
		return 1;
	case TOK_STR:
	case TOK_LSTR:
	case TOK_PPNUM:
		preprocessor_error(state, "unsupported token");
		return 1;
	case TOK_CDOUBLE:
	case TOK_CLLONG:
	case TOK_CULLONG:
		return 2;
	case TOK_CLDOUBLE:
		return 4;
	default:
		return 0;
	}
}

/* token string handling */

static inline void tok_str_new(TokenString *s) {
	s->str = NULL;
	s->len = 0;
	s->allocated_len = 0;
	s->last_line_num = -1;
}

static void tok_str_free(int *str) {
	free(str);
}

static int *tok_str_realloc(TokenString *s) {
	int *str, len;

	if (s->allocated_len == 0) {
		len = 8;
	} else {
		len = s->allocated_len * 2;
	}
	str = realloc(s->str, len * sizeof(int));
	s->allocated_len = len;
	s->str = str;
	return str;
}

static void tok_str_add(TokenString *s, int t) {
	int len, *str;

	len = s->len;
	str = s->str;
	if (len >= s->allocated_len) {
		str = tok_str_realloc(s);
	}
	str[len++] = t;
	s->len = len;
}

static void tok_str_add2(TokenString *s, int t, CValue *cv) {
	int len, *str;

	len = s->len;
	str = s->str;

	/* allocate space for worst case */
	if (len + TOK_MAX_SIZE > s->allocated_len) {
		str = tok_str_realloc(s);
	}
	str[len++] = t;
	switch (t) {
	case TOK_CINT:
	case TOK_CUINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
	case TOK_CFLOAT:
	case TOK_LINENUM:
		str[len++] = cv->tab[0];
		break;
	case TOK_PPNUM:
	case TOK_STR:
	case TOK_LSTR: {
		int nb_words;

		nb_words = (sizeof(CString) + cv->cstr->size + 3) >> 2;
		while ((len + nb_words) > s->allocated_len) {
			str = tok_str_realloc(s);
		}
		CString cstr = { 0 };
		cstr.data = NULL;
		cstr.size = cv->cstr->size;
		cstr.data_allocated = NULL;
		cstr.size_allocated = cstr.size;

		ut8 *p = (ut8 *)(str + len);
		memcpy(p, &cstr, sizeof(CString));
		memcpy(p + sizeof(CString),
			cv->cstr->data, cstr.size);
		len += nb_words;
	} break;
	case TOK_CDOUBLE:
	case TOK_CLLONG:
	case TOK_CULLONG:
		str[len++] = cv->tab[0];
		str[len++] = cv->tab[1];
		break;
	case TOK_CLDOUBLE:
		str[len++] = cv->tab[0];
		str[len++] = cv->tab[1];
		str[len++] = cv->tab[2];
		str[len++] = cv->tab[3];
		break;
	default:
		break;
	}
	s->len = len;
}

/* add the current parse token in token string 's' */
static void tok_str_add_tok(CPreprocessorState *state, TokenString *s) {
	CValue cval;
	CPreprocessorCursorState *cur = state->cur;

	/* save line number info */
	if (file->line_num != s->last_line_num) {
		s->last_line_num = file->line_num;
		cval.i = s->last_line_num;
		tok_str_add2(s, TOK_LINENUM, &cval);
	}
	tok_str_add2(s, cur->tok, &cur->tokc);
}

/* get a token from an integer array and increment pointer
   accordingly. we code it as a macro to avoid pointer aliasing. */
static inline void TOK_GET(int *t, const int **pp, CValue *cv) {
	const int *p = *pp;
	int n, *tab;

	tab = cv->tab;
	switch (*t = *p++) {
	case TOK_CINT:
	case TOK_CUINT:
	case TOK_CCHAR:
	case TOK_LCHAR:
	case TOK_CFLOAT:
	case TOK_LINENUM:
		tab[0] = *p++;
		break;
	case TOK_STR:
	case TOK_LSTR:
	case TOK_PPNUM:
		cv->cstr = (CString *)p;
		cv->cstr->data = (char *)p + sizeof(CString);
		p += (sizeof(CString) + cv->cstr->size + 3) >> 2;
		break;
	case TOK_CDOUBLE:
	case TOK_CLLONG:
	case TOK_CULLONG:
		n = 2;
		goto copy;
	case TOK_CLDOUBLE:
		n = 4;
	copy:
		do {
			*tab++ = *p++;
		} while (--n);
		break;
	default:
		break;
	}
	*pp = p;
}

/* ------------------------------------------------------------------------- */

/* fill input buffer and peek next char */
static int tcc_peekc_slow(BufferedFile *bf) {
	int len;
	/* only tries to read if really end of buffer */
	if (bf->buf_ptr >= bf->buf_end) {
		if (bf->fd != -1) {
			len = read(bf->fd, bf->buffer, IO_BUF_SIZE);
			if (len < 0) {
				len = 0;
			}
		} else {
			len = 0;
		}
		bf->buf_ptr = bf->buffer;
		bf->buf_end = bf->buffer + len;
		*bf->buf_end = CH_EOB;
	}
	if (bf->buf_ptr < bf->buf_end) {
		return bf->buf_ptr[0];
	} else {
		bf->buf_ptr = bf->buf_end;
		return CH_EOF;
	}
}

/* return the current character, handling end of block if necessary
   (but not stray) */
static int handle_eob(void) {
	return tcc_peekc_slow(file);
}

/* read next char from current input file and handle end of input buffer */
static inline void inp(CPreprocessorState *state) {
	CPreprocessorCursorState *cur = state->cur;
	cur->ch = *(++(file->buf_ptr));
	/* end of buffer/file handling */
	if (cur->ch == CH_EOB) {
		cur->ch = handle_eob();
	}
}

/* handle '\[\r]\n' */
static int handle_stray_noerror(CPreprocessorState *state) {
	CPreprocessorCursorState *cur = state->cur;
	while (cur->ch == '\\') {
		inp(state);
		if (cur->ch == '\n') {
			file->line_num++;
			inp(state);
		} else if (cur->ch == '\r') {
			inp(state);
			if (cur->ch != '\n') {
				goto fail;
			}
			file->line_num++;
			inp(state);
		} else {
		fail:
			return 1;
		}
	}
	return 0;
}

static void handle_stray(CPreprocessorState *state) {
	if (handle_stray_noerror(state)) {
		preprocessor_error(state, "stray '\\' in program");
	}
}

/* skip the stray and handle the \\n case. Output an error if
   incorrect char after the stray */
static int handle_stray1(CPreprocessorState *state, uint8_t *p) {
	int c;

	if (p >= file->buf_end) {
		file->buf_ptr = p;
		c = handle_eob();
		p = file->buf_ptr;
		if (c == '\\') {
			goto parse_stray;
		}
	} else {
	parse_stray:
		file->buf_ptr = p;
		state->cur->ch = *p;
		handle_stray(state);
		p = file->buf_ptr;
		c = *p;
	}
	return c;
}

/* handle just the EOB case, but not stray */
#define PEEKC_EOB(c, p) \
	{ \
		p++; \
		c = *p; \
		if (c == '\\') { \
			file->buf_ptr = p; \
			c = handle_eob(); \
			p = file->buf_ptr; \
		} \
	}

/* handle the complicated stray case */
#define PEEKC(state, c, p) \
	{ \
		p++; \
		c = *p; \
		if (c == '\\') { \
			c = handle_stray1(state, p); \
			p = file->buf_ptr; \
		} \
	}

/* input with '\[\r]\n' handling. Note that this function cannot
   handle other characters after '\', so you cannot call it inside
   strings or comments */
static inline void minp(CPreprocessorState *state) {
	CPreprocessorCursorState *cur = state->cur;
	inp(state);
	if (cur->ch == '\\') {
		handle_stray(state);
	}
}

/* single line C++ comments */
static uint8_t *parse_line_comment(CPreprocessorState *state, uint8_t *p) {
	int c;

	p++;
	for (;;) {
		c = *p;
	redo:
		if (c == '\n' || c == CH_EOF) {
			break;
		} else if (c == '\\') {
			file->buf_ptr = p;
			c = handle_eob();
			p = file->buf_ptr;
			if (c == '\\') {
				PEEKC_EOB(c, p);
				if (c == '\n') {
					file->line_num++;
					PEEKC_EOB(c, p);
				} else if (c == '\r') {
					PEEKC_EOB(c, p);
					if (c == '\n') {
						file->line_num++;
						PEEKC_EOB(c, p);
					}
				}
			} else {
				goto redo;
			}
		} else {
			p++;
		}
	}
	return p;
}

/* C comments */
static uint8_t *parse_comment(CPreprocessorState *state, uint8_t *p) {
	int c;

	p++;
	for (;;) {
		/* fast skip loop */
		for (;;) {
			c = *p;
			if (c == '\n' || c == '*' || c == '\\') {
				break;
			}
			p++;
			c = *p;
			if (c == '\n' || c == '*' || c == '\\') {
				break;
			}
			p++;
		}
		/* now we can handle all the cases */
		if (c == '\n') {
			file->line_num++;
			p++;
		} else if (c == '*') {
			p++;
			for (;;) {
				c = *p;
				if (c == '*') {
					p++;
				} else if (c == '/') {
					goto end_of_comment;
				} else if (c == '\\') {
					file->buf_ptr = p;
					c = handle_eob();
					p = file->buf_ptr;
					if (c == '\\') {
						/* skip '\[\r]\n', otherwise just skip the stray */
						while (c == '\\') {
							PEEKC_EOB(c, p);
							if (c == '\n') {
								file->line_num++;
								PEEKC_EOB(c, p);
							} else if (c == '\r') {
								PEEKC_EOB(c, p);
								if (c == '\n') {
									file->line_num++;
									PEEKC_EOB(c, p);
								}
							} else {
								goto after_star;
							}
						}
					}
				} else {
					break;
				}
			}
		after_star:;
		} else {
			/* stray, eob or eof */
			file->buf_ptr = p;
			c = handle_eob();
			p = file->buf_ptr;
			if (c == CH_EOF) {
				preprocessor_error(state, "unexpected end of file in comment");
			} else if (c == '\\') {
				p++;
			}
		}
	}
end_of_comment:
	p++;
	return p;
}

#define cinp minp

static inline void skip_spaces(CPreprocessorState *state) {
	while (is_space(state->cur->ch)) {
		cinp(state);
	}
}

static inline int check_space(int t, int *spc) {
	if (is_space(t)) {
		if (*spc) {
			return 1;
		}
		*spc = 1;
	} else {
		*spc = 0;
	}
	return 0;
}

/* parse a string without interpreting escapes */
static uint8_t *parse_pp_string(CPreprocessorState *state, uint8_t *p, int sep, CString *str) {
	int c;
	p++;
	while (pp_nerr(state) == 0) {
		c = *p;
		if (c == sep) {
			break;
		} else if (c == '\\') {
			file->buf_ptr = p;
			c = handle_eob();
			p = file->buf_ptr;
			if (c == CH_EOF) {
				goto unterminated_string;
			} else if (c == '\\') {
				/* escape : just skip \[\r]\n */
				PEEKC_EOB(c, p);
				if (c == '\n') {
					file->line_num++;
					p++;
				} else if (c == '\r') {
					PEEKC_EOB(c, p);
					if (c != '\n') {
						expect(state, "'\n' after '\r'");
						return NULL;
					}
					file->line_num++;
					p++;
				} else if (c == CH_EOF) {
					goto unterminated_string;
				} else {
					if (str) {
						cstr_ccat(str, '\\');
						cstr_ccat(str, c);
					}
					p++;
				}
			}
		} else if (c == '\n') {
			file->line_num++;
			goto add_char;
		} else if (c == '\r') {
			PEEKC_EOB(c, p);
			if (c != '\n') {
				if (str) {
					cstr_ccat(str, '\r');
				}
			} else {
				file->line_num++;
				goto add_char;
			}
		} else {
		add_char:
			if (str) {
				cstr_ccat(str, c);
			}
			p++;
		}
	}
	p++;
	return p;

unterminated_string:
	/* XXX: indicate line number of start of string */
	preprocessor_error(state, "missing terminating %c character", sep);
	return NULL;
}

/* skip block of text until #else, #elif or #endif. skip also pairs of
   #if/#endif */
static void preprocess_skip(CPreprocessorState *state) {
	int a, start_of_line, c, in_warn_or_error;
	uint8_t *p;
	CPreprocessorCursorState *cur = state->cur;

	p = file->buf_ptr;
	a = 0;
redo_start:
	start_of_line = 1;
	in_warn_or_error = 0;
	while (pp_nerr(state) == 0) {
	redo_no_start:
		c = *p;
		switch (c) {
		case ' ':
		case '\t':
		case '\f':
		case '\v':
		case '\r':
			p++;
			goto redo_no_start;
		case '\n':
			file->line_num++;
			p++;
			goto redo_start;
		case '\\':
			file->buf_ptr = p;
			c = handle_eob();
			if (c == CH_EOF) {
				expect(state, "#endif");
				return;
			} else if (c == '\\') {
				cur->ch = file->buf_ptr[0];
				handle_stray_noerror(state);
			}
			p = file->buf_ptr;
			goto redo_no_start;
		/* skip strings */
		case '\"':
		case '\'':
			if (in_warn_or_error) {
				goto _default;
			}
			p = parse_pp_string(state, p, c, NULL);
			if (p == NULL) {
				return;
			}
			break;
		/* skip comments */
		case '/':
			if (in_warn_or_error) {
				goto _default;
			}
			file->buf_ptr = p;
			cur->ch = *p;
			minp(state);
			p = file->buf_ptr;
			if (cur->ch == '*') {
				p = parse_comment(state, p);
			} else if (cur->ch == '/') {
				p = parse_line_comment(state, p);
			}
			break;
		case '#':
			p++;
			if (start_of_line) {
				file->buf_ptr = p;
				next_nomacro(state);
				p = file->buf_ptr;
				if (a == 0 &&
					(cur->tok == TOK_ELSE || cur->tok == TOK_ELIF || cur->tok == TOK_ENDIF)) {
					goto the_end;
				}
				if (cur->tok == TOK_IF || cur->tok == TOK_IFDEF || cur->tok == TOK_IFNDEF) {
					a++;
				} else if (cur->tok == TOK_ENDIF) {
					a--;
				} else if (cur->tok == TOK_ERROR || cur->tok == TOK_WARNING) {
					in_warn_or_error = 1;
				} else if (cur->tok == TOK_LINEFEED) {
					goto redo_start;
				}
			}
			break;
		_default:
		default:
			p++;
			break;
		}
		start_of_line = 0;
	}
the_end:;
	file->buf_ptr = p;
}

static int macro_is_equal(CPreprocessorState *state, const int *a, const int *b) {
	char buf[STRING_MAX_SIZE + 1];
	CValue cv;
	int t;
	while (*a && *b) {
		TOK_GET(&t, &a, &cv);
		rz_str_ncpy(buf, get_tok_str(state, t, &cv), sizeof(buf));
		TOK_GET(&t, &b, &cv);
		if (strcmp(buf, get_tok_str(state, t, &cv))) {
			return 0;
		}
	}
	return !(*a || *b);
}

/* defines handling */
static inline Sym *define_find(int v) {
	v -= TOK_IDENT;
	if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT)) {
		return NULL;
	}
	// TODO: Use ht_up_* here
	return table_ident[v]->sym_define;
}

static inline void define_push(CPreprocessorState *state, int v, int macro_type, int *str, Sym *first_arg) {
	Sym *s;

	s = define_find(v);
	if (s && !macro_is_equal(state, s->d, str)) {
		preprocessor_warning(state, "%s redefined", get_tok_str(state, v, NULL));
	}

	// TODO: Use ht_up_* here
	s = sym_push2(state, &state->define_stack, v, macro_type, 0);
	if (!s) {
		return;
	}
	s->d = str;
	s->next = first_arg;
	if (v >= TOK_IDENT) {
		// TODO: Use ht_up_* here
		table_ident[v - TOK_IDENT]->sym_define = s;
	}
}

/* undefined a define symbol. Its name is just set to zero */
static void define_undef(Sym *s) {
	int v;
	v = s->v;
	if (v >= TOK_IDENT && v < tok_ident) {
		// TODO: Use ht_up_* here
		table_ident[v - TOK_IDENT]->sym_define = NULL;
	}
	s->v = 0;
}

/* free define stack until top reaches 'b' */
static void free_defines(CPreprocessorState *state, Sym *b) {
	Sym *top, *top1;
	int v;

	top = state->define_stack;
	while (top != b) {
		top1 = top->prev;
		/* do not free args or predefined defines */
		if (top->d) {
			tok_str_free(top->d);
		}
		v = top->v;
		if (v >= TOK_IDENT && v < tok_ident) {
			// TODO: Use ht_up_* here
			table_ident[v - TOK_IDENT]->sym_define = NULL;
		}
		sym_free(state, top);
		top = top1;
	}
	state->define_stack = b;
}

/* eval an expression for #if/#elif */
static int expr_preprocess(CPreprocessorState *state) {
	int c, t;
	TokenString str;
	CPreprocessorCursorState *cur = state->cur;

	tok_str_new(&str);
	while (cur->tok != TOK_LINEFEED && cur->tok != TOK_EOF) {
		next(state); /* do macro subst */
		if (cur->tok == TOK_DEFINED) {
			next_nomacro(state);
			t = cur->tok;
			if (t == '(') {
				next_nomacro(state);
			}
			c = define_find(cur->tok) != 0;
			if (t == '(') {
				next_nomacro(state);
			}
			cur->tok = TOK_CINT;
			cur->tokc.i = c;
		} else if (cur->tok >= TOK_IDENT) {
			/* if undefined macro */
			cur->tok = TOK_CINT;
			cur->tokc.i = 0;
		}
		tok_str_add_tok(state, &str);
	}
	tok_str_add(&str, -1); /* simulate end of file */
	tok_str_add(&str, 0);
	/* now evaluate C constant expression */
	macro_ptr = str.str;
	next(state);
	c = expr_const(state);
	macro_ptr = NULL;
	tok_str_free(str.str);
	return c != 0;
}

/* parse after #define */
static void parse_define(CPreprocessorState *state) {
	Sym *s, *first, **ps;
	int v, t, varg, is_vaargs, spc;
	TokenString str;
	CPreprocessorCursorState *cur = state->cur;
	CPreprocessorOptions *opts = state->opts;

	v = cur->tok;
	if (v < TOK_IDENT) {
		preprocessor_error(state, "invalid macro name '%s'", get_tok_str(state, cur->tok, &cur->tokc));
	}
	/* XXX: should check if same macro (ANSI) */
	first = NULL;
	t = MACRO_OBJ;
	/* '(' must be just after macro definition for MACRO_FUNC */
	next_nomacro_spc(state);
	if (cur->tok == '(') {
		next_nomacro(state);
		ps = &first;
		while (cur->tok != ')') {
			varg = cur->tok;
			next_nomacro(state);
			is_vaargs = 0;
			if (varg == TOK_DOTS) {
				varg = TOK___VA_ARGS__;
				is_vaargs = 1;
			} else if (cur->tok == TOK_DOTS && opts->gnu_ext) {
				is_vaargs = 1;
				next_nomacro(state);
			}
			if (varg < TOK_IDENT) {
				preprocessor_error(state, "badly punctuated parameter list");
			}
			// TODO: Use the ht_pp_* API here
			s = sym_push2(state, &state->define_stack, varg | SYM_FIELD, is_vaargs, 0);
			if (!s) {
				return;
			}
			*ps = s;
			ps = &s->next;
			if (cur->tok != ',') {
				break;
			}
			next_nomacro(state);
		}
		if (cur->tok == ')') {
			next_nomacro_spc(state);
		}
		t = MACRO_FUNC;
	}
	tok_str_new(&str);
	spc = 2;
	/* EOF testing necessary for '-D' handling */
	while (cur->tok != TOK_LINEFEED && cur->tok != TOK_EOF) {
		/* remove spaces around ## and after '#' */
		if (TOK_TWOSHARPS == cur->tok) {
			if (1 == spc) {
				--str.len;
			}
			spc = 2;
		} else if ('#' == cur->tok) {
			spc = 2;
		} else if (check_space(cur->tok, &spc)) {
			goto skip;
		}
		tok_str_add2(&str, cur->tok, &cur->tokc);
	skip:
		next_nomacro_spc(state);
	}
	if (spc == 1) {
		--str.len; /* remove trailing space */
	}
	tok_str_add(&str, 0);
	preprocessor_debug(state, "define %s %d: ", get_tok_str(state, v, NULL), t);
	define_push(state, v, t, str.str, first);
}

static CachedInclude *search_cached_include(CPreprocessorState *state, const char *filename) {
	bool found = false;
	CachedInclude *e = ht_pp_find(state->includes, filename, &found);
	if (!found || !e) {
		return NULL;
	}
	return e;
}

static inline void add_cached_include(CPreprocessorState *state, const char *filename, int ifndef_macro) {
	CachedInclude *e;

	if (search_cached_include(state, filename)) {
		return;
	}
	preprocessor_debug(state, "adding cached '%s' %s\n", filename, get_tok_str(state, ifndef_macro, NULL));
	// Form a cached include structure
	e = malloc(sizeof(CachedInclude) + strlen(filename));
	strcpy(e->filename, filename);
	e->ifndef_macro = ifndef_macro;

	// Add in hash table
	ht_pp_insert(state->includes, filename, e);
}

static void pragma_parse(CPreprocessorState *state) {
	int val;
	CPreprocessorCursorState *cur = state->cur;

	next(state);
	if (cur->tok == TOK_pack) {
		/*
		  This may be:
		  #pragma pack(1) // set
		  #pragma pack() // reset to default
		  #pragma pack(push,1) // push & set
		  #pragma pack(pop) // restore previous
		*/
		next(state);
		skip(state, '(');
		if (cur->tok == TOK_ASM_pop) {
			next(state);
			if (state->pack_stack_ptr <= state->pack_stack) {
			stk_error:
				preprocessor_error(state, "out of pack stack");
			}
			state->pack_stack_ptr--;
		} else {
			val = 0;
			if (cur->tok != ')') {
				if (cur->tok == TOK_ASM_push) {
					next(state);
					if (state->pack_stack_ptr >= state->pack_stack + PACK_STACK_SIZE - 1) {
						goto stk_error;
					}
					state->pack_stack_ptr++;
					skip(state, ',');
				}
				if (cur->tok != TOK_CINT) {
				pack_error:
					preprocessor_error(state, "invalid pack pragma");
				}
				val = cur->tokc.i;
				if (val < 1 || val > 16 || (val & (val - 1)) != 0) {
					goto pack_error;
				}
				next(state);
			}
			*state->pack_stack_ptr = val;
			skip(state, ')');
		}
	}
}

static bool load_includes(CPreprocessorState *state, BufferedFile *file, const char *name, const char *dir, int c) {
	int i;
	CPreprocessorCursorState *cur = state->cur;
	size_t nb_include_paths = rz_pvector_len(state->include_paths);
	size_t nb_sysinclude_paths = rz_pvector_len(state->sysinclude_paths);
	size_t n = nb_include_paths + nb_sysinclude_paths;
	for (i = -2; i < n; ++i) {
		// FIXME: Remove VLA here!
		char buf1[sizeof(file->filename)];
		CachedInclude *e;
		BufferedFile **f;
		const char *path;

		if (i == -2) {
			/* check absolute include path */
			if (!rz_file_is_abspath(buf1)) {
				continue;
			}
			buf1[0] = 0;
			i = n; /* force end loop */

		} else if (i == -1) {
			/* search in current dir if "header.h" */
			if (c != '\"') {
				continue;
			}
			path = file->filename;
			rz_str_ncpy(buf1, path, rz_file_basename(path) - path);

		} else {
			/* search in all the include paths */
			if (i < nb_include_paths) {
				path = rz_pvector_at(state->include_paths, i);
			} else {
				path = rz_pvector_at(state->sysinclude_paths, i - nb_sysinclude_paths);
			}
			rz_str_ncpy(buf1, path, sizeof(buf1));
			strncat(buf1, "/", sizeof(buf1) - 1);
		}

		strncat(buf1, name, sizeof(buf1));

		if (cur->tok == TOK_INCLUDE_NEXT) {
			for (f = state->include_stack_ptr; f >= state->include_stack; --f) {
				if (0 == rz_str_casecmp((*f)->filename, buf1)) {
					preprocessor_debug(state, "%s: #include_next skipping %s\n", file->filename, buf1);
					goto include_trynext;
				}
			}
		}

		e = search_cached_include(state, buf1);
		if (e && define_find(e->ifndef_macro)) {
			/* no need to parse the include because the 'ifndef macro'
			   is defined */
			preprocessor_debug(state, "%s: skipping cached %s\n", file->filename, buf1);
			return false;
		}

		if (c_preprocessor_open_file(state, buf1) < 0) {
		include_trynext:
			continue;
		}
		preprocessor_error(state, "#include \"%s\"\n", buf1);
		preprocessor_debug(state, "%s: including %s\n", file->prev->filename, file->filename);
		/* push current file in stack */
		++state->include_stack_ptr;
		cur->tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
		cur->ch = file->buf_ptr[0];
		return true;
	}
	/* load include file from the same directory as the parent */
	char filepath[1024];
	int filepath_len;
	char *e = file->filename + strlen(file->filename);
	while (e > file->filename) {
		if (*e == RZ_SYS_DIR[0]) {
			break;
		}
		e--;
	}
	filepath_len = RZ_MIN((size_t)(e - file->filename) + 1, sizeof(filepath) - 1);
	memcpy(filepath, file->filename, filepath_len);
	strcpy(filepath + filepath_len, name);
	if (c_preprocessor_open_file(state, filepath) < 0) {
		// FIXME: Do not use this hardcoded value
		if (!dir) {
			dir = "/usr/include";
		}
		int len = snprintf(filepath, sizeof(filepath), "%s/%s", dir, name);
		if (len >= sizeof(filepath) || c_preprocessor_open_file(state, filepath) < 0) {
			preprocessor_error(state, "include file '%s' not found", filepath);
		} else {
			preprocessor_debug(state, "#include \"%s\"\n", filepath);
			++state->include_stack_ptr;
			cur->tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
			cur->ch = file->buf_ptr[0];
			return true;
		}
	} else {
		preprocessor_error(state, "#include \"%s\"\n", filepath);
		++state->include_stack_ptr;
		cur->tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
		cur->ch = file->buf_ptr[0];
		return true;
	}
	return false;
}

/* is_bof is true if first non space token at beginning of file */
static void preprocess(CPreprocessorState *state, int is_bof) {
	int i, c, n, saved_parse_flags;
	char buf[1024], *q;
	Sym *s;
	CPreprocessorCursorState *cur = state->cur;

	saved_parse_flags = cur->parse_flags;
	cur->parse_flags = PARSE_FLAG_PREPROCESS | PARSE_FLAG_TOK_NUM |
		PARSE_FLAG_LINEFEED;
	next_nomacro(state);
redo:
	switch (cur->tok) {
	case TOK_DEFINE:
		next_nomacro(state);
		parse_define(state);
		break;
	case TOK_UNDEF:
		next_nomacro(state);
		s = define_find(cur->tok);
		/* undefine symbol by putting an invalid name */
		if (s) {
			define_undef(s);
		}
		break;
	case TOK_INCLUDE:
	case TOK_INCLUDE_NEXT:
		cur->ch = file->buf_ptr[0];
		/* XXX: incorrect if comments : use next_nomacro with a special mode */
		skip_spaces(state);
		if (cur->ch == '<') {
			c = '>';
			goto read_name;
		} else if (cur->ch == '\"') {
			c = cur->ch;
		read_name:
			inp(state);
			q = buf;
			while (cur->ch != c && cur->ch != '\n' && cur->ch != CH_EOF) {
				if ((q - buf) < sizeof(buf) - 1) {
					*q++ = cur->ch;
				}
				if (cur->ch == '\\') {
					if (handle_stray_noerror(state) == 0) {
						--q;
					}
				} else {
					inp(state);
				}
			}
			*q = '\0';
			minp(state);
		} else {
			/* computed #include : either we have only strings or
			   we have anything enclosed in '<>' */
			next(state);
			buf[0] = '\0';
			if (cur->tok == TOK_STR) {
				while (cur->tok != TOK_LINEFEED) {
					if (cur->tok != TOK_STR) {
					include_syntax:
						preprocessor_error(state, "'#include' expects \"FILENAME\" or <FILENAME>");
					}
					strncat(buf, (char *)cur->tokc.cstr->data, sizeof(buf));
					next(state);
				}
				c = '\"';
			} else {
				int len;
				while (cur->tok != TOK_LINEFEED) {
					strncat(buf, get_tok_str(state, cur->tok, &cur->tokc), sizeof(buf));
					next(state);
				}
				len = strlen(buf);
				/* check syntax and remove '<>' */
				if (len < 2 || buf[0] != '<' || buf[len - 1] != '>') {
					goto include_syntax;
				}
				memmove(buf, buf + 1, len - 2);
				buf[len - 2] = '\0';
				c = '>';
			}
		}

		if (state->include_stack_ptr >= state->include_stack + INCLUDE_STACK_SIZE) {
			preprocessor_error(state, "#include recursion too deep");
		}
		/* store current file in stack, but increment stack later below */
		*state->include_stack_ptr = file;
		if (load_includes(state, file, buf, file->dirname, c)) {
			goto the_end;
		}
		// Otherwise, we stop processing includes and break
		break;
	case TOK_IFNDEF:
		c = 1;
		goto do_ifdef;
	case TOK_IF:
		c = expr_preprocess(state);
		goto do_if;
	case TOK_IFDEF:
		c = 0;
	do_ifdef:
		next_nomacro(state);
		if (cur->tok < TOK_IDENT) {
			preprocessor_error(state, "invalid argument for '#if%sdef'", c ? "n" : "");
		}
		if (is_bof) {
			if (c) {
				preprocessor_debug(state, "#ifndef %s\n", get_tok_str(state, cur->tok, NULL));
				file->ifndef_macro = cur->tok;
			}
		}
		c = (define_find(cur->tok) != 0) ^ c;
	do_if:
		if (state->ifdef_stack_ptr >= state->ifdef_stack + state->opts->ifdef_stack_size) {
			preprocessor_error(state, "memory full");
		}
		*state->ifdef_stack_ptr++ = c;
		goto test_skip;
	case TOK_ELSE:
		if (state->ifdef_stack_ptr == state->ifdef_stack) {
			preprocessor_error(state, "#else without matching #if");
		}
		if (state->ifdef_stack_ptr[-1] & 2) {
			preprocessor_error(state, "#else after #else");
		}
		c = (state->ifdef_stack_ptr[-1] ^= 3);
		goto test_else;
	case TOK_ELIF:
		if (state->ifdef_stack_ptr == state->ifdef_stack) {
			preprocessor_error(state, "#elif without matching #if");
		}
		c = state->ifdef_stack_ptr[-1];
		if (c > 1) {
			preprocessor_error(state, "#elif after #else");
		}
		/* last #if/#elif expression was true: we skip */
		if (c == 1) {
			goto skip;
		}
		c = expr_preprocess(state);
		state->ifdef_stack_ptr[-1] = c;
	test_else:
		if (state->ifdef_stack_ptr == file->ifdef_stack_ptr + 1) {
			file->ifndef_macro = 0;
		}
	test_skip:
		if (!(c & 1)) {
		skip:
			preprocess_skip(state);
			is_bof = 0;
			goto redo;
		}
		break;
	case TOK_ENDIF:
		if (state->ifdef_stack_ptr <= file->ifdef_stack_ptr) {
			preprocessor_error(state, "#endif without matching #if");
		}
		state->ifdef_stack_ptr--;
		/* '#ifndef macro' was at the start of file. Now we check if
		   an '#endif' is exactly at the end of file */
		if (file->ifndef_macro &&
			state->ifdef_stack_ptr == file->ifdef_stack_ptr) {
			file->ifndef_macro_saved = file->ifndef_macro;
			/* need to set to zero to avoid false matches if another
			   #ifndef at middle of file */
			file->ifndef_macro = 0;
			while (cur->tok != TOK_LINEFEED) {
				next_nomacro(state);
			}
			cur->tok_flags |= TOK_FLAG_ENDIF;
			goto the_end;
		}
		break;
	case TOK_LINE:
		next(state);
		if (cur->tok != TOK_CINT) {
			preprocessor_error(state, "#line");
		}
		file->line_num = cur->tokc.i - 1; /* the line number will be incremented after */
		next(state);
		if (cur->tok != TOK_LINEFEED) {
			if (cur->tok != TOK_STR) {
				preprocessor_error(state, "#line");
			}
			rz_str_ncpy(file->filename, (char *)cur->tokc.cstr->data, sizeof(file->filename));
		}
		break;
	case TOK_ERROR:
	case TOK_WARNING:
		c = cur->tok;
		cur->ch = file->buf_ptr[0];
		skip_spaces(state);
		q = buf;
		while (cur->ch != '\n' && cur->ch != CH_EOF) {
			if ((q - buf) < sizeof(buf) - 1) {
				*q++ = cur->ch;
			}
			if (cur->ch == '\\') {
				if (handle_stray_noerror(state) == 0) {
					--q;
				}
			} else {
				inp(state);
			}
		}
		*q = '\0';
		preprocessor_warning(state, "#%s %s", c == TOK_ERROR ? "error" : "warning", buf);
		break;
	case TOK_PRAGMA:
		pragma_parse(state);
		break;
	default:
		if (cur->tok == TOK_LINEFEED || cur->tok == '!' || cur->tok == TOK_PPNUM) {
			/* '!' is ignored to allow C scripts. numbers are ignored
			   to emulate cpp behaviour */
		} else {
			if (!(saved_parse_flags & PARSE_FLAG_ASM_COMMENTS)) {
				preprocessor_warning(state, "Ignoring unknown preprocessing directive #%s",
					get_tok_str(state, cur->tok, &cur->tokc));
			} else {
				/* this is a gas line comment in an 'S' file. */
				file->buf_ptr = parse_line_comment(state, file->buf_ptr);
				goto the_end;
			}
		}
		break;
	}
	/* ignore other preprocess commands or #! for C scripts */
	while (cur->tok != TOK_LINEFEED)
		next_nomacro(state);
the_end:
	cur->parse_flags = saved_parse_flags;
}

/* evaluate escape codes in a string. */
static void parse_escape_string(CPreprocessorState *state, CString *outstr, const uint8_t *buf, int is_long) {
	int c, n;
	const uint8_t *p;
	CPreprocessorOptions *opts = state->opts;

	p = buf;
	for (;;) {
		c = *p;
		if (c == '\0') {
			break;
		}
		if (c == '\\') {
			p++;
			/* escape */
			c = *p;
			switch (c) {
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				/* at most three octal digits */
				n = c - '0';
				p++;
				c = *p;
				if (isoct(c)) {
					n = n * 8 + c - '0';
					p++;
					c = *p;
					if (isoct(c)) {
						n = n * 8 + c - '0';
						p++;
					}
				}
				c = n;
				goto add_char_nonext;
			case 'x':
			case 'u':
			case 'U':
				p++;
				n = 0;
				for (;;) {
					c = *p;
					if (c >= 'a' && c <= 'f') {
						c = c - 'a' + 10;
					} else if (c >= 'A' && c <= 'F') {
						c = c - 'A' + 10;
					} else if (isnum(c)) {
						c = c - '0';
					} else {
						break;
					}
					n = n * 16 + c;
					p++;
				}
				c = n;
				goto add_char_nonext;
			case 'a':
				c = '\a';
				break;
			case 'b':
				c = '\b';
				break;
			case 'f':
				c = '\f';
				break;
			case 'n':
				c = '\n';
				break;
			case 'r':
				c = '\r';
				break;
			case 't':
				c = '\t';
				break;
			case 'v':
				c = '\v';
				break;
			case 'e':
				if (!opts->gnu_ext) {
					goto invalid_escape;
				}
				c = 27;
				break;
			case '\'':
			case '\"':
			case '\\':
			case '?':
				break;
			default:
			invalid_escape:
				if (c >= '!' && c <= '~') {
					preprocessor_warning(state, "unknown escape sequence: \'\\%c\'", c);
				} else {
					preprocessor_warning(state, "unknown escape sequence: \'\\x%x\'", c);
				}
				break;
			}
		}
		p++;
	add_char_nonext:
		if (!is_long) {
			cstr_ccat(outstr, c);
		} else {
			cstr_wccat(outstr, c);
		}
	}
	/* add a trailing '\0' */
	if (!is_long) {
		cstr_ccat(outstr, '\0');
	} else {
		cstr_wccat(outstr, '\0');
	}
}

/* we use 64 bit numbers */
#define BN_SIZE 2

/* bn = (bn << shift) | or_val */
static void bn_lshift(unsigned int *bn, int shift, int or_val) {
	int i;
	unsigned int v;
	for (i = 0; i < BN_SIZE; i++) {
		v = bn[i];
		bn[i] = (v << shift) | or_val;
		or_val = v >> (32 - shift);
	}
}

static void bn_zero(unsigned int *bn) {
	int i;
	for (i = 0; i < BN_SIZE; i++) {
		bn[i] = 0;
	}
}

// FIXME: Use `rz_num` API instead
/* parse number in null terminated string 'p' and return it in the
   current token */
static void parse_number(CPreprocessorState *state, const char *p) {
	int b, t, shift, frac_bits, s, exp_val, ch;
	char *q;
	unsigned int bn[BN_SIZE];
	double d;
	CPreprocessorCursorState *cur = state->cur;
	CPreprocessorOptions *opts = state->opts;

	/* number */
	q = token_buf;
	ch = *p++;
	t = ch;
	ch = *p++;
	*q++ = t;
	b = 10;
	if (t == '.') {
		goto float_frac_parse;
	} else if (t == '0') {
		// hexadecimal numbers e.g. 0x345345
		if (ch == 'x' || ch == 'X') {
			q--;
			ch = *p++;
			b = 16;
			// binary numbers e.g. 0b111011
		} else if (opts->tcc_ext && (ch == 'b' || ch == 'B')) {
			q--;
			ch = *p++;
			b = 2;
		}
	}
	/* parse all digits. cannot check octal numbers at this stage
	   because of floating point constants */
	while (1) {
		if (ch >= 'a' && ch <= 'f') {
			t = ch - 'a' + 10;
		} else if (ch >= 'A' && ch <= 'F') {
			t = ch - 'A' + 10;
		} else if (isnum(ch)) {
			t = ch - '0';
		} else {
			break;
		}
		if (t >= b) {
			break;
		}
		if (q >= token_buf + STRING_MAX_SIZE) {
		num_too_long:
			preprocessor_error(state, "number too long");
		}
		*q++ = ch;
		ch = *p++;
	}
	if (ch == '.' ||
		((ch == 'e' || ch == 'E') && b == 10) ||
		((ch == 'p' || ch == 'P') && (b == 16 || b == 2))) {
		if (b != 10) {
			/* NOTE: strtox should support that for hexa numbers, but
			   non ISOC99 libcs do not support it, so we prefer to do
			   it by hand */
			/* hexadecimal or binary floats */
			/* XXX: handle overflows */
			*q = '\0';
			if (b == 16) {
				shift = 4;
			} else {
				shift = 2;
			}
			bn_zero(bn);
			q = token_buf;
			while (1) {
				t = *q++;
				if (t == '\0') {
					break;
				} else if (t >= 'a') {
					t = t - 'a' + 10;
				} else if (t >= 'A') {
					t = t - 'A' + 10;
				} else {
					t = t - '0';
				}
				bn_lshift(bn, shift, t);
			}
			frac_bits = 0;
			if (ch == '.') {
				ch = *p++;
				while (1) {
					t = ch;
					if (t >= 'a' && t <= 'f') {
						t = t - 'a' + 10;
					} else if (t >= 'A' && t <= 'F') {
						t = t - 'A' + 10;
					} else if (t >= '0' && t <= '9') {
						t = t - '0';
					} else {
						break;
					}
					if (t >= b) {
						preprocessor_error(state, "invalid digit");
					}
					bn_lshift(bn, shift, t);
					frac_bits += shift;
					ch = *p++;
				}
			}
			if (ch != 'p' && ch != 'P') {
				expect(state, "exponent");
				return;
			}
			ch = *p++;
			s = 1;
			exp_val = 0;
			if (ch == '+') {
				ch = *p++;
			} else if (ch == '-') {
				s = -1;
				ch = *p++;
			}
			if (ch < '0' || ch > '9') {
				expect(state, "exponent digits");
				return;
			}
			while (ch >= '0' && ch <= '9') {
				exp_val = exp_val * 10 + ch - '0';
				ch = *p++;
			}
			exp_val = exp_val * s;

			/* now we can generate the number */
			/* XXX: should patch directly float number */
			d = (double)bn[1] * 4294967296.0 + (double)bn[0];
			d = ldexp(d, exp_val - frac_bits);
			t = toup(ch);
			if (t == 'F') {
				ch = *p++;
				cur->tok = TOK_CFLOAT;
				/* float : should handle overflow */
				cur->tokc.f = (float)d;
			} else if (t == 'L') {
				ch = *p++;
				cur->tok = TOK_CLDOUBLE;
				/* FIXME: not large enough */
				cur->tokc.ld = (long double)d;
			} else {
				cur->tok = TOK_CDOUBLE;
				cur->tokc.d = d;
			}
		} else {
			/* decimal floats */
			if (ch == '.') {
				if (q >= token_buf + STRING_MAX_SIZE) {
					goto num_too_long;
				}
				*q++ = ch;
				ch = *p++;
			float_frac_parse:
				while (ch >= '0' && ch <= '9') {
					if (q >= token_buf + STRING_MAX_SIZE) {
						goto num_too_long;
					}
					*q++ = ch;
					ch = *p++;
				}
			}
			if (ch == 'e' || ch == 'E') {
				if (q >= token_buf + STRING_MAX_SIZE) {
					goto num_too_long;
				}
				*q++ = ch;
				ch = *p++;
				if (ch == '-' || ch == '+') {
					if (q >= token_buf + STRING_MAX_SIZE) {
						goto num_too_long;
					}
					*q++ = ch;
					ch = *p++;
				}
				if (ch < '0' || ch > '9') {
					expect(state, "exponent digits");
					return;
				}
				while (ch >= '0' && ch <= '9') {
					if (q >= token_buf + STRING_MAX_SIZE) {
						goto num_too_long;
					}
					*q++ = ch;
					ch = *p++;
				}
			}
			*q = '\0';
			t = toup(ch);
			errno = 0;
			if (t == 'F') {
				ch = *p++;
				cur->tok = TOK_CFLOAT;
				cur->tokc.f = strtof(token_buf, NULL);
			} else if (t == 'L') {
				ch = *p++;
				cur->tok = TOK_CDOUBLE;
				cur->tokc.d = strtod(token_buf, NULL);
			} else {
				cur->tok = TOK_CDOUBLE;
				cur->tokc.d = strtod(token_buf, NULL);
			}
		}
	} else {
		unsigned long long n, n1;
		int lcount, ucount;

		/* integer number */
		*q = '\0';
		q = token_buf;
		if (b == 10 && *q == '0') {
			b = 8;
			q++;
		}
		n = 0;
		while (1) {
			t = *q++;
			/* no need for checks except for base 10 / 8 errors */
			if (t == '\0') {
				break;
			} else if (t >= 'a') {
				t = t - 'a' + 10;
			} else if (t >= 'A') {
				t = t - 'A' + 10;
			} else {
				t = t - '0';
				if (t >= b) {
					preprocessor_error(state, "invalid digit");
				}
			}
			n1 = n;
			n = n * b + t;
			/* detect overflow */
			/* XXX: this test is not reliable */
			if (n < n1) {
				preprocessor_error(state, "integer constant overflow");
			}
		}

		/* XXX: not exactly ANSI compliant */
		if ((n & 0xffffffff00000000LL) != 0) {
			if ((n >> 63) != 0) {
				cur->tok = TOK_CULLONG;
			} else {
				cur->tok = TOK_CLLONG;
			}
		} else if (n > 0x7fffffff) {
			cur->tok = TOK_CUINT;
		} else {
			cur->tok = TOK_CINT;
		}
		lcount = 0;
		ucount = 0;
		for (;;) {
			t = toup(ch);
			if (t == 'L') {
				if (lcount >= 2) {
					preprocessor_error(state, "three 'l's in integer constant");
				}
				lcount++;
				if (cur->tok == TOK_CINT) {
					cur->tok = TOK_CLLONG;
				} else if (cur->tok == TOK_CUINT) {
					cur->tok = TOK_CULLONG;
				}
				ch = *p++;
			} else if (t == 'U') {
				if (ucount >= 1) {
					preprocessor_error(state, "two 'u's in integer constant");
				}
				ucount++;
				if (cur->tok == TOK_CINT) {
					cur->tok = TOK_CUINT;
				} else if (cur->tok == TOK_CLLONG) {
					cur->tok = TOK_CULLONG;
				}
				ch = *p++;
			} else {
				break;
			}
		}
		if (cur->tok == TOK_CINT || cur->tok == TOK_CUINT) {
			cur->tokc.ui = n;
		} else {
			cur->tokc.ull = n;
		}
	}
	if (ch) {
		preprocessor_error(state, "invalid number\n");
	}
}

#define PARSE2(state, c1, tok1, c2, tok2) \
	case c1: \
		PEEKC(state, c, p); \
		if (c == c2) { \
			p++; \
			state->cur->tok = tok2; \
		} else { \
			state->cur->tok = tok1; \
		} \
		break;

/* return next token without macro substitution */
static inline void next_nomacro1(CPreprocessorState *state) {
	int t, c, is_long;
	TokenSym *ts;
	uint8_t *p, *p1;
	unsigned int h;
	CPreprocessorCursorState *cur = state->cur;

	p = file->buf_ptr;
redo_no_start:
	c = *p;
	switch (c) {
	case ' ':
	case '\t':
		cur->tok = c;
		p++;
		goto keep_tok_flags;
	case '\f':
	case '\v':
	case '\r':
		p++;
		goto redo_no_start;
	case '\\':
		/* first look if it is in fact an end of buffer */
		if (p >= file->buf_end) {
			file->buf_ptr = p;
			handle_eob();
			p = file->buf_ptr;
			if (p >= file->buf_end) {
				goto parse_eof;
			} else {
				goto redo_no_start;
			}
		} else {
			file->buf_ptr = p;
			cur->ch = *p;
			handle_stray(state);
			p = file->buf_ptr;
			goto redo_no_start;
		}
	parse_eof : {
		if ((cur->parse_flags & PARSE_FLAG_LINEFEED) && !(cur->tok_flags & TOK_FLAG_EOF)) {
			cur->tok_flags |= TOK_FLAG_EOF;
			cur->tok = TOK_LINEFEED;
			goto keep_tok_flags;
		} else if (!(cur->parse_flags & PARSE_FLAG_PREPROCESS)) {
			cur->tok = TOK_EOF;
		} else if (state->ifdef_stack_ptr != file->ifdef_stack_ptr) {
			preprocessor_error(state, "missing #endif");
		} else if (state->include_stack_ptr == state->include_stack) {
			/* no include left : end of file. */
			cur->tok = TOK_EOF;
		} else {
			cur->tok_flags &= ~TOK_FLAG_EOF;
			/* pop include file */

			/* test if previous '#endif' was after a #ifdef at
				   start of file */
			if (cur->tok_flags & TOK_FLAG_ENDIF) {
				preprocessor_debug(state, "#endif %s\n", get_tok_str(state, file->ifndef_macro_saved, NULL));
				add_cached_include(state, file->filename, file->ifndef_macro_saved);
				cur->tok_flags &= ~TOK_FLAG_ENDIF;
			}

			/* pop include stack */
			file = preprocessor_close_file(file);
			state->include_stack_ptr--;
			p = file->buf_ptr;
			goto redo_no_start;
		}
	} break;

	case '\n':
		file->line_num++;
		cur->tok_flags |= TOK_FLAG_BOL;
		p++;
	maybe_newline:
		if (0 == (cur->parse_flags & PARSE_FLAG_LINEFEED)) {
			goto redo_no_start;
		}
		cur->tok = TOK_LINEFEED;
		goto keep_tok_flags;

	case '#':
		/* XXX: simplify */
		PEEKC(state, c, p);
		if ((cur->tok_flags & TOK_FLAG_BOL) &&
			(cur->parse_flags & PARSE_FLAG_PREPROCESS)) {
			file->buf_ptr = p;
			preprocess(state, cur->tok_flags & TOK_FLAG_BOF);
			p = file->buf_ptr;
			goto maybe_newline;
		} else {
			if (c == '#') {
				p++;
				cur->tok = TOK_TWOSHARPS;
			} else {
				if (cur->parse_flags & PARSE_FLAG_ASM_COMMENTS) {
					p = parse_line_comment(state, p - 1);
					goto redo_no_start;
				} else {
					cur->tok = '#';
				}
			}
		}
		break;

	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
	case 'g':
	case 'h':
	case 'i':
	case 'j':
	case 'k':
	case 'l':
	case 'm':
	case 'n':
	case 'o':
	case 'p':
	case 'q':
	case 'r':
	case 's':
	case 't':
	case 'u':
	case 'v':
	case 'w':
	case 'x':
	case 'y':
	case 'z':
	case 'A':
	case 'B':
	case 'C':
	case 'D':
	case 'E':
	case 'F':
	case 'G':
	case 'H':
	case 'I':
	case 'J':
	case 'K':
	case 'M':
	case 'N':
	case 'O':
	case 'P':
	case 'Q':
	case 'R':
	case 'S':
	case 'T':
	case 'U':
	case 'V':
	case 'W':
	case 'X':
	case 'Y':
	case 'Z':
	case '_':
	case '.':
	parse_ident_fast:
		// FIXME: Use ht_pp_* API here for the hashtable
		p1 = p;
		h = TOK_HASH_INIT;
		h = TOK_HASH_FUNC(h, c);
		p++;
		for (;;) {
			c = *p;
			if (!isidnum_table[*p - CH_EOF]) {
				break;
			}
			// dot handling here too
			if (isdot(c)) {
				PEEKC(state, c, p);
				if (isnum(c)) {
					cstr_reset(&cur->tokcstr);
					cstr_ccat(&cur->tokcstr, '.');
					goto parse_num;
				} else if (isdot(c)) {
					goto parse_dots;
				}
			}
			h = TOK_HASH_FUNC(h, *p);
			p++;
		}
		if (c != '\\') {
			TokenSym **pts;
			int len;
			// FIXME: Use ht_pp_* API here

			/* fast case : no stray found, so we have the full token
			   and we have already hashed it */
			len = p - p1;
			h &= (TOK_HASH_SIZE - 1);
			pts = &hash_ident[h];
			for (;;) {
				ts = *pts;
				if (!ts) {
					break;
				}
				if (ts->len == len && !memcmp(ts->str, p1, len)) {
					goto token_found;
				}
				pts = &(ts->hash_next);
			}
			ts = tok_alloc_new(state, pts, (const char *)p1, len);
		token_found:;
		} else {
			/* slower case */
			cstr_reset(&cur->tokcstr);

			while (p1 < p) {
				cstr_ccat(&cur->tokcstr, *p1);
				p1++;
			}
			p--;
			PEEKC(state, c, p);
		parse_ident_slow:
			while (isidnum_table[((c > 255) ? 255 : c) - CH_EOF]) {
				cstr_ccat(&cur->tokcstr, c);
				PEEKC(state, c, p);
			}
			ts = tok_alloc(state, cur->tokcstr.data, cur->tokcstr.size);
		}
		cur->tok = ts->tok;
		break;
	case 'L':
		t = p[1];
		if (t != '\\' && t != '\'' && t != '\"') {
			/* fast case */
			goto parse_ident_fast;
		} else {
			PEEKC(state, c, p);
			if (c == '\'' || c == '\"') {
				is_long = 1;
				goto str_const;
			} else {
				cstr_reset(&cur->tokcstr);
				cstr_ccat(&cur->tokcstr, 'L');
				goto parse_ident_slow;
			}
		}
		break;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':

		cstr_reset(&cur->tokcstr);
		/* after the first digit, accept digits, alpha, '.' or sign if
		   prefixed by 'eEpP' */
	parse_num:
		for (;;) {
			t = c;
			cstr_ccat(&cur->tokcstr, c);
			PEEKC(state, c, p);
			if (!(isnum(c) || isid(c) || isdot(c) ||
				    ((c == '+' || c == '-') &&
					    (t == 'e' || t == 'E' || t == 'p' || t == 'P')))) {
				break;
			}
		}
		/* We add a trailing '\0' to ease parsing */
		cstr_ccat(&cur->tokcstr, '\0');
		cur->tokc.cstr = &cur->tokcstr;
		cur->tok = TOK_PPNUM;
		break;
		/* special dot handling because it can also start a number */
	parse_dots:
		if (!isdot(c)) {
			expect(state, "'.'");
			return;
		}
		PEEKC(state, c, p);
		cur->tok = TOK_DOTS;
		break;
	case '\'':
	case '\"':
		is_long = 0;
	str_const : {
		CString str;
		int sep;

		sep = c;

		/* parse the string */
		cstr_new(&str);
		p = parse_pp_string(state, p, sep, &str);
		if (!p) {
			return;
		}
		cstr_ccat(&str, '\0');

		/* eval the escape (should be done as TOK_PPNUM) */
		cstr_reset(&cur->tokcstr);
		parse_escape_string(state, &cur->tokcstr, str.data, is_long);
		cstr_free(&str);

		if (sep == '\'') {
			int char_size;
			/* XXX: make it portable */
			if (!is_long) {
				char_size = 1;
			} else {
				char_size = sizeof(nwchar_t);
			}
			if (cur->tokcstr.size <= char_size) {
				preprocessor_error(state, "empty character constant");
			}
			if (cur->tokcstr.size > 2 * char_size) {
				preprocessor_warning(state, "multi-character character constant");
			}
			if (!is_long) {
				cur->tokc.i = *(int8_t *)cur->tokcstr.data;
				cur->tok = TOK_CCHAR;
			} else {
				cur->tokc.i = *(nwchar_t *)cur->tokcstr.data;
				cur->tok = TOK_LCHAR;
			}
		} else {
			cur->tokc.cstr = &cur->tokcstr;
			if (!is_long) {
				cur->tok = TOK_STR;
			} else {
				cur->tok = TOK_LSTR;
			}
		}
	} break;

	case '<':
		PEEKC(state, c, p);
		if (c == '=') {
			p++;
			cur->tok = TOK_LE;
		} else if (c == '<') {
			PEEKC(state, c, p);
			if (c == '=') {
				p++;
				cur->tok = TOK_A_SHL;
			} else {
				cur->tok = TOK_SHL;
			}
		} else {
			cur->tok = TOK_LT;
		}
		break;

	case '>':
		PEEKC(state, c, p);
		if (c == '=') {
			p++;
			cur->tok = TOK_GE;
		} else if (c == '>') {
			PEEKC(state, c, p);
			if (c == '=') {
				p++;
				cur->tok = TOK_A_SAR;
			} else {
				cur->tok = TOK_SAR;
			}
		} else {
			cur->tok = TOK_GT;
		}
		break;

	case '&':
		PEEKC(state, c, p);
		if (c == '&') {
			p++;
			cur->tok = TOK_LAND;
		} else if (c == '=') {
			p++;
			cur->tok = TOK_A_AND;
		} else {
			cur->tok = '&';
		}
		break;

	case '|':
		PEEKC(state, c, p);
		if (c == '|') {
			p++;
			cur->tok = TOK_LOR;
		} else if (c == '=') {
			p++;
			cur->tok = TOK_A_OR;
		} else {
			cur->tok = '|';
		}
		break;

	case '+':
		PEEKC(state, c, p);
		if (c == '+') {
			p++;
			cur->tok = TOK_INC;
		} else if (c == '=') {
			p++;
			cur->tok = TOK_A_ADD;
		} else {
			cur->tok = '+';
		}
		break;

	case '-':
		PEEKC(state, c, p);
		if (c == '-') {
			p++;
			cur->tok = TOK_DEC;
		} else if (c == '=') {
			p++;
			cur->tok = TOK_A_SUB;
		} else if (c == '>') {
			p++;
			cur->tok = TOK_ARROW;
		} else {
			cur->tok = '-';
		}
		break;

		PARSE2(state, '!', '!', '=', TOK_NE)
		PARSE2(state, '=', '=', '=', TOK_EQ)
		PARSE2(state, '*', '*', '=', TOK_A_MUL)
		PARSE2(state, '%', '%', '=', TOK_A_MOD)
		PARSE2(state, '^', '^', '=', TOK_A_XOR)

	/* comments or operator */
	case '/':
		PEEKC(state, c, p);
		if (c == '*') {
			p = parse_comment(state, p);
			/* comments replaced by a blank */
			cur->tok = ' ';
			goto keep_tok_flags;
		} else if (c == '/') {
			p = parse_line_comment(state, p);
			cur->tok = ' ';
			goto keep_tok_flags;
		} else if (c == '=') {
			p++;
			cur->tok = TOK_A_DIV;
		} else {
			cur->tok = '/';
		}
		break;

	/* simple tokens */
	case '(':
	case ')':
	case '[':
	case ']':
	case '{':
	case '}':
	case ',':
	case ';':
	case ':':
	case '?':
	case '~':
	case '$': /* only used in assembler */
	case '@': /* dito */
		cur->tok = c;
		p++;
		break;
	default:
		preprocessor_error(state, "unrecognized character \\x%02x", c);
		break;
	}
	cur->tok_flags = 0;
keep_tok_flags:
	file->buf_ptr = p;
	preprocessor_debug(state, "token = %s\n", get_tok_str(state, cur->tok, &cur->tokc));
}

/* return next token without macro substitution. Can read input from
   macro_ptr buffer */
static void next_nomacro_spc(CPreprocessorState *state) {
	if (!file) {
		preprocessor_error(state, "file = null\n");
		return;
	}
	CPreprocessorCursorState *cur = state->cur;
	if (macro_ptr) {
	redo:
		cur->tok = *macro_ptr;
		if (cur->tok) {
			TOK_GET(&cur->tok, &macro_ptr, &cur->tokc);
			if (cur->tok == TOK_LINENUM) {
				file->line_num = cur->tokc.i;
				goto redo;
			}
		}
	} else {
		next_nomacro1(state);
	}
}

static void next_nomacro(CPreprocessorState *state) {
	do {
		next_nomacro_spc(state);
	} while (pp_nerr(state) == 0 && is_space(state->cur->tok));
}

/* substitute args in macro_str and return allocated string */
static int *macro_arg_subst(CPreprocessorState *state, Sym **nested_list, const int *macro_str, Sym *args) {
	int last_tok, t, spc;
	const int *st;
	Sym *s;
	CValue cval;
	TokenString str;
	CString cstr;
	CPreprocessorOptions *opts = state->opts;

	tok_str_new(&str);
	last_tok = 0;
	while (pp_nerr(state) == 0) {
		TOK_GET(&t, &macro_str, &cval);
		if (!t) {
			break;
		}
		if (t == '#') {
			/* stringize */
			TOK_GET(&t, &macro_str, &cval);
			if (!t) {
				break;
			}
			s = sym_find2(args, t);
			if (s) {
				cstr_new(&cstr);
				st = s->d;
				spc = 0;
				while (*st) {
					TOK_GET(&t, &st, &cval);
					if (!check_space(t, &spc)) {
						cstr_cat(&cstr, get_tok_str(state, t, &cval));
					}
				}
				cstr.size -= spc;
				cstr_ccat(&cstr, '\0');
				preprocessor_debug(state, "stringize: %s\n", (char *)cstr.data);
				/* add string */
				cval.cstr = &cstr;
				tok_str_add2(&str, TOK_STR, &cval);
				cstr_free(&cstr);
			} else {
				tok_str_add2(&str, t, &cval);
			}
		} else if (t >= TOK_IDENT) {
			s = sym_find2(args, t);
			if (s) {
				st = s->d;
				/* if '##' is present before or after, no arg substitution */
				if (*macro_str == TOK_TWOSHARPS || last_tok == TOK_TWOSHARPS) {
					/* special case for var arg macros : ## eats the
					   ',' if empty VA_ARGS variable. */
					/* XXX: test of the ',' is not 100%
					   reliable. should fix it to avoid security
					   problems */
					if (opts->gnu_ext && s->t &&
						last_tok == TOK_TWOSHARPS &&
						str.len >= 2 && str.str[str.len - 2] == ',') {
						if (*st == 0) {
							/* suppress ',' '##' */
							str.len -= 2;
						} else {
							/* suppress '##' and add variable */
							str.len--;
							goto add_var;
						}
					} else {
						int t1;
					add_var:
						for (;;) {
							TOK_GET(&t1, &st, &cval);
							if (!t1) {
								break;
							}
							tok_str_add2(&str, t1, &cval);
						}
					}
				} else {
					/* NOTE: the stream cannot be read when macro
					   substituing an argument */
					macro_subst(state, &str, nested_list, st, NULL);
				}
			} else {
				tok_str_add(&str, t);
			}
		} else {
			tok_str_add2(&str, t, &cval);
		}
		last_tok = t;
	}
	tok_str_add(&str, 0);
	return str.str;
}

static char const ab_month_name[12][4] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* do macro substitution of current token with macro 's' and add
   result to (tok_str,tok_len). 'nested_list' is the list of all
   macros we got inside to avoid recursing. Return non zero if no
   substitution needs to be done */
static int macro_subst_tok(CPreprocessorState *state, TokenString *tok_str,
	Sym **nested_list, Sym *s, struct macro_level **can_read_stream) {

	Sym *args, *sa, *sa1;
	int mstr_allocated, parlevel, *mstr, t, t1, spc;
	const int *p;
	TokenString str;
	char *cstrval;
	CValue cval;
	CString cstr;
	char buf[32];
	CPreprocessorCursorState *cur = state->cur;
	CPreprocessorOptions *opts = state->opts;

	/* if symbol is a macro, prepare substitution */
	/* special macros */
	if (cur->tok == TOK___LINE__) {
		snprintf(buf, sizeof(buf), "%d", file->line_num);
		cstrval = buf;
		t1 = TOK_PPNUM;
		goto add_cstr1;
	} else if (cur->tok == TOK___FILE__) {
		cstrval = file->filename;
		goto add_cstr;
	} else if (cur->tok == TOK___DATE__ || cur->tok == TOK___TIME__) {
		// FIXME: Use RzUtil API to print time
		time_t ti;
		struct tm tminfo;

		time(&ti);
		rz_localtime_r(&ti, &tminfo);
		if (cur->tok == TOK___DATE__) {
			snprintf(buf, sizeof(buf), "%s %2d %d",
				ab_month_name[tminfo.tm_mon], tminfo.tm_mday, tminfo.tm_year + 1900);
		} else {
			snprintf(buf, sizeof(buf), "%02d:%02d:%02d",
				tminfo.tm_hour, tminfo.tm_min, tminfo.tm_sec);
		}
		cstrval = buf;
	add_cstr:
		t1 = TOK_STR;
	add_cstr1:
		cstr_new(&cstr);
		cstr_cat(&cstr, cstrval);
		cstr_ccat(&cstr, '\0');
		cval.cstr = &cstr;
		tok_str_add2(tok_str, t1, &cval);
		cstr_free(&cstr);
	} else {
		mstr = s->d;
		mstr_allocated = 0;
		if (s->t == MACRO_FUNC) {
			/* NOTE: we do not use next_nomacro to avoid eating the
			   next token. XXX: find better solution */
		redo:
			if (macro_ptr) {
				p = macro_ptr;
				while (is_space(t = *p) || TOK_LINEFEED == t)
					++p;
				if (t == 0 && can_read_stream) {
					/* end of macro stream: we must look at the token
					   after in the file */
					struct macro_level *ml = *can_read_stream;
					macro_ptr = NULL;
					if (ml) {
						macro_ptr = ml->p;
						ml->p = NULL;
						*can_read_stream = ml->prev;
					}
					/* also, end of scope for nested defined symbol */
					(*nested_list)->v = -1;
					goto redo;
				}
			} else {
				cur->ch = file->buf_ptr[0];
				while (is_space(cur->ch) || cur->ch == '\n' || cur->ch == '/') {
					if (cur->ch == '/') {
						int c;
						uint8_t *p = file->buf_ptr;
						PEEKC(state, c, p);
						if (c == '*') {
							p = parse_comment(state, p);
							file->buf_ptr = p - 1;
						} else if (c == '/') {
							p = parse_line_comment(state, p);
							file->buf_ptr = p - 1;
						} else {
							break;
						}
					}
					cinp(state);
				}
				t = cur->ch;
			}
			if (t != '(') { /* no macro subst */
				return -1;
			}

			/* argument macro */
			next_nomacro(state);
			next_nomacro(state);
			args = NULL;
			sa = s->next;
			/* NOTE: empty args are allowed, except if no args */
			while (pp_nerr(state) == 0) {
				/* handle '()' case */
				if (!args && !sa && cur->tok == ')') {
					break;
				}
				if (!sa) {
					preprocessor_error(state, "macro '%s' used with too many args",
						get_tok_str(state, s->v, 0));
				}
				tok_str_new(&str);
				parlevel = spc = 0;
				/* NOTE: non zero sa->t indicates VA_ARGS */
				while ((parlevel > 0 ||
					       (cur->tok != ')' &&
						       (cur->tok != ',' || (sa && sa->t)))) &&
					cur->tok != -1) {
					if (cur->tok == '(') {
						parlevel++;
					} else if (cur->tok == ')') {
						parlevel--;
					}
					if (cur->tok == TOK_LINEFEED) {
						cur->tok = ' ';
					}
					if (!check_space(cur->tok, &spc)) {
						tok_str_add2(&str, cur->tok, &cur->tokc);
					}
					next_nomacro_spc(state);
				}
				str.len -= spc;
				tok_str_add(&str, 0);
				sa1 = sa ? sym_push2(state, &args, sa->v & ~SYM_FIELD, sa->t, 0) : NULL;
				if (!sa1) {
					return -1;
				}
				sa1->d = str.str;
				sa = sa->next;
				if (cur->tok == ')') {
					/* special case for gcc var args: add an empty
					   var arg argument if it is omitted */
					if (sa && sa->t && opts->gnu_ext) {
						continue;
					} else {
						break;
					}
				}
				if (cur->tok != ',') {
					expect(state, ",");
					return 1;
				}
				next_nomacro(state);
			}
			if (sa) {
				preprocessor_error(state, "macro '%s' used with too few args",
					get_tok_str(state, s->v, 0));
			}

			/* now subst each arg */
			mstr = macro_arg_subst(state, nested_list, mstr, args);
			/* free memory */
			sa = args;
			while (sa) {
				sa1 = sa->prev;
				tok_str_free(sa->d);
				sym_free(state, sa);
				sa = sa1;
			}
			mstr_allocated = 1;
		}
		if (sym_push2(state, nested_list, s->v, 0, 0) == 0) {
			return -1;
		}
		macro_subst(state, tok_str, nested_list, mstr, can_read_stream);
		/* pop nested defined symbol */
		sa1 = *nested_list;
		*nested_list = sa1->prev;
		sym_free(state, sa1);
		if (mstr_allocated) {
			tok_str_free(mstr);
		}
	}
	return 0;
}

/* handle the '##' operator. Return NULL if no '##' seen. Otherwise
   return the resulting string (which must be freed). */
static inline int *macro_twosharps(CPreprocessorState *state, const int *macro_str) {
	const int *ptr;
	int t;
	TokenString macro_str1;
	CString cstr;
	int n, start_of_nosubsts;
	CPreprocessorCursorState *cur = state->cur;

	/* we search the first '##' */
	for (ptr = macro_str;;) {
		CValue cval;
		TOK_GET(&t, &ptr, &cval);
		if (t == TOK_TWOSHARPS) {
			break;
		}
		/* nothing more to do if end of string */
		if (t == 0) {
			return NULL;
		}
	}

	/* we saw '##', so we need more processing to handle it */
	start_of_nosubsts = -1;
	tok_str_new(&macro_str1);
	for (ptr = macro_str;;) {
		TOK_GET(&cur->tok, &ptr, &cur->tokc);
		if (cur->tok == 0) {
			break;
		}
		if (cur->tok == TOK_TWOSHARPS) {
			continue;
		}
		if (cur->tok == TOK_NOSUBST && start_of_nosubsts < 0) {
			start_of_nosubsts = macro_str1.len;
		}
		while (*ptr == TOK_TWOSHARPS) {
			/* given 'a##b', remove nosubsts preceding 'a' */
			if (start_of_nosubsts >= 0) {
				macro_str1.len = start_of_nosubsts;
			}
			/* given 'a##b', skip '##' */
			t = *++ptr;
			/* given 'a##b', remove nosubsts preceding 'b' */
			while (t == TOK_NOSUBST)
				t = *++ptr;
			if (t && t != TOK_TWOSHARPS) {
				CValue cval;
				TOK_GET(&t, &ptr, &cval);
				/* We concatenate the two tokens */
				cstr_new(&cstr);
				cstr_cat(&cstr, get_tok_str(state, cur->tok, &cur->tokc));
				n = cstr.size;
				cstr_cat(&cstr, get_tok_str(state, t, &cval));
				cstr_ccat(&cstr, '\0');

				c_preprocessor_open_string(state, ":paste:", cstr.size);
				memcpy(file->buffer, cstr.data, cstr.size);
				while (pp_nerr(state) == 0) {
					next_nomacro1(state);
					if (0 == *file->buf_ptr) {
						break;
					}
					tok_str_add2(&macro_str1, cur->tok, &cur->tokc);
					preprocessor_warning(state, "pasting \"%.*s\" and \"%s\" does not give a valid preprocessing token",
						n, (char *)cstr.data, (char *)cstr.data + n);
				}
				file = preprocessor_close_file(file);
				cstr_free(&cstr);
			}
		}
		if (cur->tok != TOK_NOSUBST) {
			start_of_nosubsts = -1;
		}
		tok_str_add2(&macro_str1, cur->tok, &cur->tokc);
	}
	tok_str_add(&macro_str1, 0);
	return macro_str1.str;
}

/* do macro substitution of macro_str and add result to
   (tok_str,tok_len). 'nested_list' is the list of all macros we got
   inside to avoid recursing. */
static void macro_subst(CPreprocessorState *state, TokenString *tok_str, Sym **nested_list,
	const int *macro_str, struct macro_level **can_read_stream) {
	Sym *s;
	int *macro_str1;
	const int *ptr;
	int t, ret, spc;
	CValue cval;
	struct macro_level ml;
	int force_blank;
	CPreprocessorCursorState *cur = state->cur;

	/* first scan for '##' operator handling */
	ptr = macro_str;
	macro_str1 = macro_twosharps(state, ptr);

	if (macro_str1) {
		ptr = macro_str1;
	}
	spc = 0;
	force_blank = 0;

	while (pp_nerr(state) == 0) {
		/* NOTE: ptr == NULL can only happen if tokens are read from
		   file stream due to a macro function call */
		if (ptr == NULL) {
			break;
		}
		TOK_GET(&t, &ptr, &cval);
		if (t == 0) {
			break;
		}
		if (t == TOK_NOSUBST) {
			/* following token has already been subst'd. just copy it on */
			tok_str_add2(tok_str, TOK_NOSUBST, NULL);
			TOK_GET(&t, &ptr, &cval);
			goto no_subst;
		}
		s = define_find(t);
		if (s != NULL) {
			/* if nested substitution, do nothing */
			if (sym_find2(*nested_list, t)) {
				/* and mark it as TOK_NOSUBST, so it doesn't get subst'd again */
				tok_str_add2(tok_str, TOK_NOSUBST, NULL);
				goto no_subst;
			}
			ml.p = macro_ptr;
			if (can_read_stream) {
				ml.prev = *can_read_stream, *can_read_stream = &ml;
			}
			macro_ptr = (int *)ptr;
			cur->tok = t;
			ret = macro_subst_tok(state, tok_str, nested_list, s, can_read_stream);
			ptr = (int *)macro_ptr;
			macro_ptr = ml.p;
			if (can_read_stream && *can_read_stream == &ml) {
				*can_read_stream = ml.prev;
			}
			if (ret != 0) {
				goto no_subst;
			}
			if (cur->parse_flags & PARSE_FLAG_SPACES) {
				force_blank = 1;
			}
		} else {
		no_subst:
			if (force_blank) {
				tok_str_add(tok_str, ' ');
				spc = 1;
				force_blank = 0;
			}
			if (!check_space(t, &spc)) {
				tok_str_add2(tok_str, t, &cval);
			}
		}
	}
	if (macro_str1) {
		tok_str_free(macro_str1);
	}
}

/* return next token with macro substitution */
void next(CPreprocessorState *state) {
	Sym *nested_list, *s;
	TokenString str;
	struct macro_level *ml;
	CPreprocessorCursorState *cur = state->cur;

redo:
	if (cur->parse_flags & PARSE_FLAG_SPACES) {
		next_nomacro_spc(state);
	} else {
		next_nomacro(state);
	}
	if (!macro_ptr) {
		/* if not reading from macro substituted string, then try
		   to substitute macros */
		if (cur->tok >= TOK_IDENT &&
			(cur->parse_flags & PARSE_FLAG_PREPROCESS)) {
			s = define_find(cur->tok);
			if (s) {
				/* we have a macro: we try to substitute */
				tok_str_new(&str);
				nested_list = NULL;
				ml = NULL;
				if (macro_subst_tok(state, &str, &nested_list, s, &ml) == 0) {
					/* substitution done, NOTE: maybe empty */
					tok_str_add(&str, 0);
					macro_ptr = str.str;
					macro_ptr_allocated = str.str;
					goto redo;
				}
			}
		}
	} else {
		if (cur->tok == 0) {
			/* end of macro or end of unget buffer */
			if (unget_buffer_enabled) {
				macro_ptr = unget_saved_macro_ptr;
				unget_buffer_enabled = 0;
			} else {
				/* end of macro string: free it */
				tok_str_free(macro_ptr_allocated);
				macro_ptr_allocated = NULL;
				macro_ptr = NULL;
			}
			goto redo;
		} else if (cur->tok == TOK_NOSUBST) {
			/* discard preprocessor's nosubst markers */
			goto redo;
		}
	}

	/* convert preprocessor tokens into C tokens */
	if (cur->tok == TOK_PPNUM &&
		(cur->parse_flags & PARSE_FLAG_TOK_NUM)) {
		parse_number(state, (char *)cur->tokc.cstr->data);
	}
}

/* push back current token and set current token to 'last_tok'. Only
   identifier case handled for labels. */
static inline void unget_tok(CPreprocessorState *state, int last_tok) {
	int i, n;
	int *q;
	CPreprocessorCursorState *cur = state->cur;

	if (unget_buffer_enabled) {
		/* assert(macro_ptr == unget_saved_buffer + 1);
		   assert(*macro_ptr == 0);  */
	} else {
		unget_saved_macro_ptr = macro_ptr;
		unget_buffer_enabled = 1;
	}
	q = unget_saved_buffer;
	macro_ptr = q;
	*q++ = cur->tok;
	n = tok_ext_size(state, cur->tok) - 1;
	for (i = 0; i < n; i++) {
		*q++ = cur->tokc.tab[i];
	}
	*q = 0; /* end of token string */
	cur->tok = last_tok;
}

void preprocess_init(CPreprocessorState *state) {
	state->include_stack_ptr = state->include_stack;
	state->ifdef_stack_ptr = state->ifdef_stack;
	file->ifdef_stack_ptr = state->ifdef_stack_ptr;
	state->pack_stack[0] = 0;
	state->pack_stack_ptr = state->pack_stack;
}

void preprocess_new(CPreprocessorState *state) {
	int i, c;
	const char *p, *r;

	/* init isid table */
	for (i = CH_EOF; i < 256; i++) {
		isidnum_table[i - CH_EOF] = isid(i) || isnum(i) || isdot(i);
	}

	/* add all tokens */
	// TODO: Initialize hashtable
	// TODO: Use ht_pp_* API here
	table_ident = NULL;
	memset(hash_ident, 0, TOK_HASH_SIZE * sizeof(TokenSym *));

	tok_ident = TOK_IDENT;

	// Skip all C keywords here
	for (i = 0; i < sizeof(preprocessor_tokens); i++) {
		tok_alloc(state, preprocessor_tokens[i], strlen(preprocessor_tokens[i]));
	}
}

/* define a preprocessor symbol. A value can also be provided with the '=' operator */
static void preprocessor_define_symbol(CPreprocessorState *state, const char *symbol, const char *value) {
	/* default value */
	if (!value) {
		value = "1";
	}
	int len1 = strlen(symbol);
	int len2 = strlen(value);

	/* init file structure */
	file = preprocessor_open_file_buffered(state, file, "<define>", len1 + len2 + 1);
	if (!file) {
		return;
	}
	memcpy(file->buffer, symbol, len1);
	file->buffer[len1] = ' ';
	memcpy(file->buffer + len1 + 1, value, len2);

	/* parse with define parser */
	state->cur->ch = file->buf_ptr[0];
	next_nomacro(state);
	parse_define(state);

	file = preprocessor_close_file(file);
}

/* undefine a preprocessor symbol */
static void preprocessor_undefine_symbol(CPreprocessorState *state, const char *symbol) {
	TokenSym *ts;
	Sym *s;
	ts = tok_alloc(state, symbol, strlen(symbol));
	s = define_find(ts->tok);
	/* undefine symbol by putting an invalid name */
	if (s) {
		define_undef(s);
	}
}

/* Preprocess the current file */
// TODO: Add an output file/stream?
int c_preprocess_string(CPreprocessorState *state, const char *code) {
	rz_return_val_if_fail(state && code, -1);
	if (!code) {
		preprocessor_error(state, "Empty code\n");
		return -1;
	}

	Sym *define_start;
	BufferedFile *file_ref, **iptr, **iptr_new;
	int token_seen, line_ref, d;
	const char *s;

	// Setup the preprocessor state
	preprocess_init(state);

	CPreprocessorCursorState *cur = state->cur;

	// An start of the defines stack to free everything after it
	define_start = state->define_stack;
	cur->ch = file->buf_ptr[0];
	// Set the default token and parsing flags
	cur->tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
	cur->parse_flags = PARSE_FLAG_ASM_COMMENTS | PARSE_FLAG_PREPROCESS |
		PARSE_FLAG_LINEFEED | PARSE_FLAG_SPACES;
	token_seen = 0;
	line_ref = 0;
	file_ref = NULL;
	iptr = state->include_stack_ptr;

	while (pp_nerr(state) == 0) {
		next(state);
		if (cur->tok == TOK_EOF) {
			break;
		} else if (file != file_ref) {
			goto print_line;
		} else if (cur->tok == TOK_LINEFEED) {
			if (!token_seen) {
				continue;
			}
			++line_ref;
			token_seen = 0;
		} else if (!token_seen) {
			d = file->line_num - line_ref;
			if (file != file_ref || d < 0 || d >= 8) {
			print_line:
				iptr_new = state->include_stack_ptr;
				s = iptr_new > iptr                       ? " 1"
					: iptr_new < iptr                 ? " 2"
					: iptr_new > state->include_stack ? " 3"
									  : "";
				iptr = iptr_new;
				preprocessor_debug(state, "# %d \"%s\"%s\n", file->line_num, file->filename, s);
			} else {
				while (d) {
					preprocessor_debug(state, "\n"), --d;
				}
			}
			line_ref = (file_ref = file)->line_num;
			token_seen = cur->tok != TOK_LINEFEED;
			if (!token_seen) {
				continue;
			}
		}
		preprocessor_debug(state, get_tok_str(state, cur->tok, &cur->tokc));
	}
	// Purge everything after the start
	free_defines(state, define_start);
	return 0;
}
