// SPDX-FileCopyrightText: 2019-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_table.h>
#include "rz_cons.h"

// cant do that without globals because RzList doesnt have void *user :(
static int Gnth = 0;
static RzListComparator Gcmp = NULL;

static int sortString(const void *a, const void *b) {
	return strcmp(a, b);
}

static int sortNumber(const void *a, const void *b) {
	return rz_num_get(NULL, a) - rz_num_get(NULL, b);
}

// maybe just index by name instead of exposing those symbols as global
static RzTableColumnType rz_table_type_string = { "string", sortString };
static RzTableColumnType rz_table_type_number = { "number", sortNumber };
static RzTableColumnType rz_table_type_bool = { "bool", sortNumber };

RZ_API RzTableColumnType *rz_table_type(const char *name) {
	if (!strcmp(name, "bool")) {
		return &rz_table_type_bool;
	}
	if (!strcmp(name, "boolean")) {
		return &rz_table_type_bool;
	}
	if (!strcmp(name, "string")) {
		return &rz_table_type_string;
	}
	if (!strcmp(name, "number")) {
		return &rz_table_type_number;
	}
	return NULL;
}

// TODO: unused for now, maybe good to call after filter :?
static void __table_adjust(RzTable *t) {
	RzListIter *iter, *iter2;
	RzTableColumn *col;
	RzTableRow *row;
	rz_list_foreach (t->cols, iter, col) {
		int itemLength = rz_str_len_utf8_ansi(col->name) + 1;
		col->width = itemLength;
	}
	rz_list_foreach (t->rows, iter, row) {
		const char *item;
		int ncol = 0;
		rz_list_foreach (row->items, iter2, item) {
			int itemLength = rz_str_len_utf8_ansi(item) + 1;
			RzTableColumn *c = rz_list_get_n(t->cols, ncol);
			if (c) {
				c->width = RZ_MAX(c->width, itemLength);
			}
			ncol++;
		}
	}
}

RZ_API void rz_table_row_free(void *_row) {
	RzTableRow *row = _row;
	rz_list_free(row->items);
	free(row);
}

RZ_API void rz_table_column_free(void *_col) {
	RzTableColumn *col = _col;
	free(col->name);
	free(col);
}

RZ_API RzTableColumn *rz_table_column_clone(RzTableColumn *col) {
	RzTableColumn *c = RZ_NEW0(RzTableColumn);
	if (!c) {
		return NULL;
	}
	memcpy(c, col, sizeof(*c));
	c->name = strdup(c->name);
	return c;
}

RZ_API RzTable *rz_table_new(void) {
	RzTable *t = RZ_NEW0(RzTable);
	if (t) {
		t->showHeader = true;
		t->cols = rz_list_newf(rz_table_column_free);
		t->rows = rz_list_newf(rz_table_row_free);
		t->showSum = false;
	}
	return t;
}

RZ_API void rz_table_free(RzTable *t) {
	if (!t) {
		return;
	}
	rz_list_free(t->cols);
	rz_list_free(t->rows);
	free(t);
}

RZ_API void rz_table_add_column(RzTable *t, RzTableColumnType *type, const char *name, int maxWidth) {
	RzTableColumn *c = RZ_NEW0(RzTableColumn);
	if (c) {
		c->name = strdup(name);
		c->maxWidth = maxWidth;
		c->type = type;
		int itemLength = rz_str_len_utf8_ansi(name) + 1;
		c->width = itemLength;
		rz_list_append(t->cols, c);
		c->total = -1;
	}
}

RZ_API RzTableRow *rz_table_row_new(RzList *items) {
	RzTableRow *row = RZ_NEW(RzTableRow);
	row->items = items;
	return row;
}

static bool __addRow(RzTable *t, RzList *items, const char *arg, int col) {
	int itemLength = rz_str_len_utf8_ansi(arg) + 1;
	RzTableColumn *c = rz_list_get_n(t->cols, col);
	if (c) {
		c->width = RZ_MAX(c->width, itemLength);
		rz_list_append(items, strdup(arg));
		return true;
	}
	return false;
}

RZ_API void rz_table_add_row_list(RzTable *t, RzList *items) {
	RzTableRow *row = rz_table_row_new(items);
	rz_list_append(t->rows, row);
	// throw warning if not enough columns defined in header
	t->totalCols = RZ_MAX(t->totalCols, rz_list_length(items));
}

/**
 * \brief Specify the types and names of the referenced table.
 *
 * \param t Referenced \p RzTable
 * \param fmt String containing the numer and types of the columns
 * \param ap Variable number of strings that specify the names of the columns.
 *           There should be enough string as characters in \p fmt .
 */
RZ_API void rz_table_set_vcolumnsf(RzTable *t, const char *fmt, va_list ap) {
	RzTableColumnType *typeString = rz_table_type("string");
	RzTableColumnType *typeNumber = rz_table_type("number");
	RzTableColumnType *typeBool = rz_table_type("bool");
	const char *name;
	const char *f = fmt;
	for (; *f; f++) {
		name = va_arg(ap, const char *);
		if (!name) {
			break;
		}
		switch (*f) {
		case 'b':
			rz_table_add_column(t, typeBool, name, 0);
			break;
		case 's':
		case 'z':
			rz_table_add_column(t, typeString, name, 0);
			break;
		case 'i':
		case 'd':
		case 'n':
		case 'x':
		case 'X':
			rz_table_add_column(t, typeNumber, name, 0);
			break;
		default:
			eprintf("Invalid format string char '%c', use 's' or 'n'\n", *f);
			break;
		}
	}
}

/**
 * \brief Specify the types and names of the referenced table.
 *
 * \param t Referenced \p RzTable
 * \param fmt String containing the numer and types of the columns
 * \param ... Variable number of strings that specify the names of the columns.
 *            There should be enough string as characters in \p fmt .
 */
RZ_API void rz_table_set_columnsf(RzTable *t, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	rz_table_set_vcolumnsf(t, fmt, ap);
	va_end(ap);
}

#define add_column_to_rowf(row, fmt, ap) do { \
		const char *arg = NULL; \
		switch (fmt) { \
		case 's': \
		case 'z': \
			arg = va_arg(ap, const char *); \
			rz_list_append(row, strdup(arg ? arg : "")); \
			break; \
		case 'b': \
			rz_list_append(row, rz_str_new(rz_str_bool(va_arg(ap, int)))); \
			break; \
		case 'i': \
		case 'd': \
			rz_list_append(row, rz_str_newf("%d", va_arg(ap, int))); \
			break; \
		case 'n': \
			rz_list_append(row, rz_str_newf("%" PFMT64d, va_arg(ap, ut64))); \
			break; \
		case 'u': \
			rz_list_append(row, rz_num_units(NULL, 32, va_arg(ap, ut64))); \
			break; \
		case 'x': \
		case 'X': { \
			ut64 n = va_arg(ap, ut64); \
			if (n == UT64_MAX) { \
				if (fmt == 'X') { \
					rz_list_append(row, strdup("----------")); \
				} else { \
					rz_list_append(row, strdup("-1")); \
				} \
			} else { \
				if (fmt == 'X') { \
					rz_list_append(row, rz_str_newf("0x%08" PFMT64x, n)); \
				} else { \
					rz_list_append(row, rz_str_newf("0x%" PFMT64x, n)); \
				} \
			} \
		} break; \
		default: \
			eprintf("Invalid format string char '%c', use 's' or 'n'\n", fmt); \
			break; \
		} \
	} while(0)

/**
 * Add some columns values to the last created row, if any, or create a new row otherwise.
 */
RZ_API void rz_table_add_row_columnsf(RzTable *t, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	RzTableRow *row = rz_list_last(t->rows);
	RzList *list;
	bool add_row;
	if (row) {
		list = row->items;
		add_row = false;
	} else {
		list = rz_list_newf(free);
		add_row = true;
	}
	for (const char *f = fmt; *f; f++) {
		add_column_to_rowf(list, *f, ap);
	}
	va_end(ap);
	if (add_row) {
		rz_table_add_row_list(t, list);
	}
}

/**
 * Add a new row with the specified columns values.
 */
RZ_API void rz_table_add_rowf(RzTable *t, const char *fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	RzList *list = rz_list_newf(free);
	for (const char *f = fmt; *f; f++) {
		add_column_to_rowf(list, *f, ap);
	}
	va_end(ap);
	rz_table_add_row_list(t, list);
}

RZ_API void rz_table_add_row(RzTable *t, const char *name, ...) {
	va_list ap;
	va_start(ap, name);
	int col = 0;
	RzList *items = rz_list_newf(free);
	__addRow(t, items, name, col++);
	for (;;) {
		const char *arg = va_arg(ap, const char *);
		if (!arg) {
			break;
		}
		__addRow(t, items, arg, col);
		// TODO: assert if number of columns doesnt match t->cols
		col++;
	}
	va_end(ap);
	RzTableRow *row = rz_table_row_new(items);
	rz_list_append(t->rows, row);
	// throw warning if not enough columns defined in header
	t->totalCols = RZ_MAX(t->totalCols, rz_list_length(items));
}

// import / export

static int __strbuf_append_col_aligned_fancy(RzTable *t, RzStrBuf *sb, RzTableColumn *col, char *str) {
	RzCons *cons = (RzCons *)t->cons;
	const char *v_line = (cons && (cons->use_utf8 || cons->use_utf8_curvy)) ? RUNE_LINE_VERT : "|";
	int ll = rz_strbuf_length(sb);
	switch (col->align) {
	case RZ_TABLE_ALIGN_LEFT:
		rz_strbuf_appendf(sb, "%s %-*s ", v_line, col->width, str);
		break;
	case RZ_TABLE_ALIGN_RIGHT:
		rz_strbuf_appendf(sb, "%s %*s ", v_line, col->width, str);
		break;
	case RZ_TABLE_ALIGN_CENTER: {
		int len = rz_str_len_utf8(str);
		int pad = (col->width - len) / 2;
		int left = col->width - (pad * 2 + len);
		rz_strbuf_appendf(sb, "%s %-*s ", v_line, pad, " ");
		rz_strbuf_appendf(sb, "%-*s ", pad + left, str);
		break;
	}
	}
	return rz_strbuf_length(sb) - ll;
}

static void __computeTotal(RzTable *t) {
	RzTableRow *row;
	RzListIter *iter, *iter2;
	rz_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		rz_list_foreach (row->items, iter2, item) {
			RzTableColumn *col = rz_list_get_n(t->cols, c);
			if (!rz_str_cmp(col->type->name, "number", rz_str_ansi_len("number")) && rz_str_isnumber(item)) {
				if (col->total < 0) {
					col->total = 0;
				}
				col->total += sdb_atoi(item);
			}
			c++;
		}
	}
}

RZ_API char *rz_table_tofancystring(RzTable *t) {
	if (rz_list_length(t->cols) == 0) {
		return strdup("");
	}
	RzStrBuf *sb = rz_strbuf_new("");
	RzTableRow *row;
	RzTableColumn *col;
	RzCons *cons = (RzCons *)t->cons;
	RzListIter *iter, *iter2;
	bool useUtf8 = (cons && cons->use_utf8);
	bool useUtf8Curvy = (cons && cons->use_utf8_curvy);
	const char *v_line = useUtf8 || useUtf8Curvy ? RUNE_LINE_VERT : "|";
	const char *h_line = useUtf8 || useUtf8Curvy ? RUNE_LINE_HORIZ : "-";
	const char *l_intersect = useUtf8 || useUtf8Curvy ? RUNE_LINE_VERT : ")";
	const char *rz_intersect = useUtf8 || useUtf8Curvy ? RUNE_LINE_VERT : "(";
	const char *tl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_TL : RUNE_CORNER_TL) : ".";
	const char *tr_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_TR : RUNE_CORNER_TR) : ".";
	const char *bl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BL : RUNE_CORNER_BL) : "`";
	const char *br_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BR : RUNE_CORNER_BR) : "'";
	__table_adjust(t);

	rz_list_foreach (t->cols, iter, col) {
		__strbuf_append_col_aligned_fancy(t, sb, col, col->name);
	}
	int len = rz_str_len_utf8_ansi(rz_strbuf_get(sb)) - 1;
	int maxlen = len;
	char *h_line_str = rz_str_repeat(h_line, maxlen);
	{
		char *s = rz_str_newf("%s%s%s\n", tl_corner, h_line_str, tr_corner);
		rz_strbuf_prepend(sb, s);
		free(s);
	}

	rz_strbuf_appendf(sb, "%s\n%s%s%s\n", v_line, l_intersect, h_line_str, rz_intersect);
	rz_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		rz_list_foreach (row->items, iter2, item) {
			RzTableColumn *col = rz_list_get_n(t->cols, c);
			if (col) {
				int l = __strbuf_append_col_aligned_fancy(t, sb, col, item);
				len = RZ_MAX(len, l);
			}
			c++;
		}
		rz_strbuf_appendf(sb, "%s\n", v_line);
	}

	if (t->showSum) {
		char tmp[64];
		__computeTotal(t);
		rz_strbuf_appendf(sb, "%s%s%s\n", l_intersect, h_line_str, rz_intersect);
		rz_list_foreach (t->cols, iter, col) {
			char *num = col->total == -1 ? "" : sdb_itoa(col->total, tmp, 10);
			int l = __strbuf_append_col_aligned_fancy(t, sb, col, num);
			len = RZ_MAX(len, l);
		}
		rz_strbuf_appendf(sb, "%s\n", v_line);
	}
	rz_strbuf_appendf(sb, "%s%s%s\n", bl_corner, h_line_str, br_corner);
	free(h_line_str);
	return rz_strbuf_drain(sb);
}

static int __strbuf_append_col_aligned(RzStrBuf *sb, RzTableColumn *col, const char *str, bool nopad) {
	int ll = rz_strbuf_length(sb);
	if (nopad) {
		rz_strbuf_appendf(sb, "%s", str);
	} else {
		char *pad = "";
		int padlen = 0;
		int len1 = rz_str_len_utf8(str);
		int len2 = rz_str_len_utf8_ansi(str);
		if (len1 > len2) {
			if (len2 < col->width) {
				padlen = col->width - len2;
			}
		}
		switch (col->align) {
		case RZ_TABLE_ALIGN_LEFT:
			pad = rz_str_repeat(" ", padlen);
			rz_strbuf_appendf(sb, "%-*s%s", col->width, str, pad);
			free(pad);
			break;
		case RZ_TABLE_ALIGN_RIGHT:
			pad = rz_str_repeat(" ", padlen);
			rz_strbuf_appendf(sb, "%s%*s ", pad, col->width, str);
			free(pad);
			break;
		case RZ_TABLE_ALIGN_CENTER: {
			int pad = (col->width - len2) / 2;
			int left = col->width - (pad * 2 + len2);
			rz_strbuf_appendf(sb, "%-*s", pad, " ");
			rz_strbuf_appendf(sb, "%-*s ", pad + left, str);
			break;
		}
		}
	}
	return rz_strbuf_length(sb) - ll;
}

RZ_API char *rz_table_tostring(RzTable *t) {
	if (t->showCSV) {
		return rz_table_tocsv(t);
	}
	if (t->showJSON) {
		char *s = rz_table_tojson(t);
		char *q = rz_str_newf("%s\n", s);
		;
		free(s);
		return q;
	}
	if (t->showFancy) {
		return rz_table_tofancystring(t);
	}
	return rz_table_tosimplestring(t);
}

RZ_API char *rz_table_tosimplestring(RzTable *t) {
	RzStrBuf *sb = rz_strbuf_new("");
	RzTableRow *row;
	RzTableColumn *col;
	RzListIter *iter, *iter2;
	RzCons *cons = (RzCons *)t->cons;
	const char *h_line = (cons && (cons->use_utf8 || cons->use_utf8_curvy)) ? RUNE_LONG_LINE_HORIZ : "-";
	__table_adjust(t);
	int maxlen = 0;
	if (t->showHeader) {
		rz_list_foreach (t->cols, iter, col) {
			int ll = __strbuf_append_col_aligned(sb, col, col->name, false);
			maxlen = RZ_MAX(maxlen, ll);
		}
		int len = rz_str_len_utf8_ansi(rz_strbuf_get(sb));
		char *l = rz_str_repeat(h_line, RZ_MAX(maxlen, len));
		if (l) {
			rz_strbuf_appendf(sb, "\n%s\n", l);
			free(l);
		}
	}
	rz_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		rz_list_foreach (row->items, iter2, item) {
			bool nopad = !iter2->n;
			RzTableColumn *col = rz_list_get_n(t->cols, c);
			if (col) {
				(void)__strbuf_append_col_aligned(sb, col, item, nopad);
			}
			c++;
		}
		rz_strbuf_append(sb, "\n");
	}
	if (t->showSum) {
		char tmp[64];
		__computeTotal(t);
		if (maxlen > 0) {
			char *l = rz_str_repeat(h_line, maxlen);
			if (l) {
				rz_strbuf_appendf(sb, "\n%s\n", l);
				free(l);
			}
		}
		rz_list_foreach (t->cols, iter, col) {
			bool nopad = !iter->n;
			(void)__strbuf_append_col_aligned(sb, col, sdb_itoa(col->total, tmp, 10), nopad);
		}
	}
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_table_tocsv(RzTable *t) {
	RzStrBuf *sb = rz_strbuf_new("");
	RzTableRow *row;
	RzTableColumn *col;
	RzListIter *iter, *iter2;
	if (t->showHeader) {
		const char *comma = "";
		rz_list_foreach (t->cols, iter, col) {
			if (strchr(col->name, ',')) {
				// TODO. escaped string?
				rz_strbuf_appendf(sb, "%s\"%s\"", comma, col->name);
			} else {
				rz_strbuf_appendf(sb, "%s%s", comma, col->name);
			}
			comma = ",";
		}
		rz_strbuf_append(sb, "\n");
	}
	rz_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		const char *comma = "";
		rz_list_foreach (row->items, iter2, item) {
			RzTableColumn *col = rz_list_get_n(t->cols, c);
			if (col) {
				if (strchr(col->name, ',')) {
					rz_strbuf_appendf(sb, "%s\"%s\"", comma, col->name);
				} else {
					rz_strbuf_appendf(sb, "%s%s", comma, item);
				}
				comma = ",";
			}
			c++;
		}
		rz_strbuf_append(sb, "\n");
	}
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_table_tojson(RzTable *t) {
	PJ *pj = pj_new();
	RzTableRow *row;
	RzListIter *iter, *iter2;
	pj_a(pj);
	rz_list_foreach (t->rows, iter, row) {
		char *item;
		int c = 0;
		pj_o(pj);
		rz_list_foreach (row->items, iter2, item) {
			RzTableColumn *col = rz_list_get_n(t->cols, c);
			if (col) {
				if (col->type == &rz_table_type_number) {
					ut64 n = rz_num_get(NULL, item);
					if (n) {
						pj_kn(pj, col->name, n);
					} else if (*item && *item != '0') {
						pj_ks(pj, col->name, item);
					}
				} else {
					if (*item) {
						pj_ks(pj, col->name, item);
					}
				}
			}
			c++;
		}
		pj_end(pj);
	}
	pj_end(pj);
	return pj_drain(pj);
}

RZ_API void rz_table_filter(RzTable *t, int nth, int op, const char *un) {
	rz_return_if_fail(t && un);
	RzTableRow *row;
	RzListIter *iter, *iter2;
	ut64 uv = rz_num_math(NULL, un);
	ut64 sum = 0;
	size_t page = 0, page_items = 0;
	size_t lrow = 0;
	if (op == 't') {
		size_t ll = rz_list_length(t->rows);
		if (ll > uv) {
			uv = ll - uv;
		}
	}
	if (op == 'p') {
		sscanf(un, "%zd/%zd", &page, &page_items);
		if (page < 1) {
			page = 1;
		}
		lrow = page_items * (page - 1);
		uv = page_items * (page);
	}
	size_t nrow = 0;
	rz_list_foreach_safe (t->rows, iter, iter2, row) {
		const char *nn = rz_list_get_n(row->items, nth);
		ut64 nv = rz_num_math(NULL, nn);
		bool match = true;
		switch (op) {
		case 'p':
			nrow++;
			if (nrow < lrow) {
				match = false;
			}
			if (nrow > uv) {
				match = false;
			}
			break;
		case 't':
			nrow++;
			if (nrow < uv) {
				match = false;
			}
			break;
		case 'h':
			nrow++;
			if (nrow > uv) {
				match = false;
			}
			break;
		case '+':
			// "sum"
			sum += nv;
			match = false;
			break;
		case '>':
			match = (nv > uv);
			break;
		case ')':
			// ">="
			match = (nv >= uv);
			break;
		case '<':
			match = (nv < uv);
			break;
		case '(':
			// "<="
			match = (nv <= uv);
			break;
		case '=':
			if (nv == 0) {
				match = !strcmp(nn, un);
			} else {
				match = (nv == uv);
			}
			break;
		case '!':
			if (nv == 0) {
				match = strcmp(nn, un);
			} else {
				match = (nv != uv);
			}
			break;
		case '~':
			match = strstr(nn, un) != NULL;
			break;
		case 's':
			match = strlen(nn) == atoi(un);
			break;
		case 'l':
			match = strlen(nn) > atoi(un);
			break;
		case 'L':
			match = strlen(nn) < atoi(un);
			break;
		case '\0':
			break;
		}
		if (!match) {
			rz_list_delete(t->rows, iter);
		}
	}
	if (op == '+') {
		rz_table_add_rowf(t, "u", sum);
	}
}

static int cmp(const void *_a, const void *_b) {
	RzTableRow *a = (RzTableRow *)_a;
	RzTableRow *b = (RzTableRow *)_b;
	const char *wa = rz_list_get_n(a->items, Gnth);
	const char *wb = rz_list_get_n(b->items, Gnth);
	int res = Gcmp(wa, wb);
	return res;
}

RZ_API void rz_table_sort(RzTable *t, int nth, bool dec) {
	RzTableColumn *col = rz_list_get_n(t->cols, nth);
	if (col) {
		Gnth = nth;
		if (col->type && col->type->cmp) {
			Gcmp = col->type->cmp;
			t->rows->sorted = false; //force sorting
			rz_list_sort(t->rows, cmp);
			if (dec) {
				rz_list_reverse(t->rows);
			}
		}
		Gnth = 0;
		Gcmp = NULL;
	}
}

static int cmplen(const void *_a, const void *_b) {
	RzTableRow *a = (RzTableRow *)_a;
	RzTableRow *b = (RzTableRow *)_b;
	const char *wa = rz_list_get_n(a->items, Gnth);
	const char *wb = rz_list_get_n(b->items, Gnth);
	int res = strlen(wa) - strlen(wb);
	return res;
}

RZ_API void rz_table_sortlen(RzTable *t, int nth, bool dec) {
	RzTableColumn *col = rz_list_get_n(t->cols, nth);
	if (col) {
		Gnth = nth;
		t->rows->sorted = false; //force sorting
		rz_list_sort(t->rows, cmplen);
		if (dec) {
			rz_list_reverse(t->rows);
		}
		Gnth = 0;
	}
}

static int rz_rows_cmp(RzList *lhs, RzList *rhs, RzList *cols, int nth) {
	RzListIter *iter_lhs;
	RzListIter *iter_rhs;
	RzListIter *iter_col;
	RzTableColumn *item_col;

	void *item_lhs;
	void *item_rhs;
	int tmp;
	int i = 0;

	for (iter_lhs = lhs->head, iter_rhs = rhs->head, iter_col = cols->head;
		iter_lhs && iter_rhs && iter_col;
		iter_lhs = iter_lhs->n, iter_rhs = iter_rhs->n, iter_col = iter_col->n) {

		item_lhs = iter_lhs->data;
		item_rhs = iter_rhs->data;
		item_col = iter_col->data;

		if (nth == -1 || i == nth) {
			tmp = item_col->type->cmp(item_lhs, item_rhs);

			if (tmp) {
				return tmp;
			}
		}

		i++;
	}

	if (iter_lhs) {
		return 1;
	}

	if (iter_rhs) {
		return -1;
	}

	return 0;
}

RZ_API void rz_table_uniq(RzTable *t) {
	rz_table_group(t, -1, NULL);
}

RZ_API void rz_table_group(RzTable *t, int nth, RzTableSelector fcn) {
	RzListIter *iter;
	RzListIter *tmp;
	RzTableRow *row;

	RzListIter *iter_inner;
	RzTableRow *uniq_row;

	RzList *rows = t->rows;

	rz_list_foreach_safe (rows, iter, tmp, row) {
		for (iter_inner = rows->head;
			iter_inner && iter_inner != iter;
			iter_inner = iter_inner->n) {

			uniq_row = iter_inner->data;

			if (!rz_rows_cmp(uniq_row->items, row->items, t->cols, nth)) {
				if (fcn) {
					fcn(uniq_row, row, nth);
				}
				rz_list_delete(rows, iter);
				break;
			}
		}
	}
}

RZ_API int rz_table_column_nth(RzTable *t, const char *name) {
	RzListIter *iter;
	RzTableColumn *col;
	int n = 0;
	rz_list_foreach (t->cols, iter, col) {
		if (!strcmp(name, col->name)) {
			return n;
		}
		n++;
	}
	return -1;
}

static int __resolveOperation(const char *op) {
	if (!strcmp(op, "gt")) {
		return '>';
	}
	if (!strcmp(op, "ge")) {
		return ')';
	}
	if (!strcmp(op, "lt")) {
		return '<';
	}
	if (!strcmp(op, "le")) {
		return '(';
	}
	if (!strcmp(op, "eq")) {
		return '=';
	}
	if (!strcmp(op, "ne")) {
		return '!';
	}
	return -1;
}

static void __table_column_free(void *_col) {
	RzTableColumn *col = (RzTableColumn *)_col;
	free(col);
}

RZ_API void rz_table_columns(RzTable *t, RzList *col_names) {
	// 1 bool per OLD column to indicate whether it should be freed (masked out)
	bool *free_cols = malloc(sizeof(bool) * rz_list_length(t->cols));
	if (!free_cols) {
		return;
	}
	size_t i;
	for (i = 0; i < rz_list_length(t->cols); i++) {
		free_cols[i] = true;
	}

	// 1 value per NEW column to indicate from which OLD column to take the info from and whether to dup it
	struct col_source {
		int oldcol;
		bool dup;
	} *col_sources = calloc(rz_list_length(col_names), sizeof(struct col_source));
	if (!col_sources) {
		free(free_cols);
		return;
	}

	// First create the plan which new columns to take from which old, which ones to dup or free.
	RzListIter *it;
	const char *col_name;
	size_t new_count = 0;
	rz_list_foreach (col_names, it, col_name) {
		int fc = rz_table_column_nth(t, col_name);
		if (fc < 0) {
			continue;
		}
		col_sources[new_count].oldcol = fc;
		col_sources[new_count].dup = !free_cols[fc]; // if we already used the same old column for another new column before, we must dup it for all following!
		free_cols[fc] = false;
		new_count++;
	}

	RzTableRow *row;
	rz_list_foreach (t->rows, it, row) {
		RzList *old_items = row->items;
		RzList *new_items = rz_list_newf(free);
		for (i = 0; i < new_count; i++) {
			char *item = rz_list_get_n(old_items, col_sources[i].oldcol);
			if (!item) {
				continue;
			}
			if (col_sources[i].dup) {
				item = strdup(item);
			}
			rz_list_append(new_items, item);
		}
		row->items = new_items;

		// Free dropped items
		char *item;
		i = 0;
		RzListIter *fit;
		rz_list_foreach (old_items, fit, item) {
			if (free_cols[i]) {
				free(item);
			}
			i++;
		}
		old_items->free = NULL;
		rz_list_free(old_items);
	}

	RzList *old_cols = t->cols;
	RzList *new_cols = rz_list_newf(rz_table_column_free);
	for (i = 0; i < new_count; i++) {
		RzTableColumn *col = rz_list_get_n(old_cols, col_sources[i].oldcol);
		if (!col) {
			continue;
		}
		if (col_sources[i].dup) {
			col = rz_table_column_clone(col);
		}
		rz_list_append(new_cols, col);
	}
	t->cols = new_cols;

	// Free dropped columns
	RzTableColumn *col;
	i = 0;
	rz_list_foreach (old_cols, it, col) {
		if (free_cols[i]) {
			rz_table_column_free(col);
		}
		i++;
	}
	old_cols->free = NULL;
	rz_list_free(old_cols);

	free(col_sources);
	free(free_cols);
}

RZ_API void rz_table_filter_columns(RzTable *t, RzList *list) {
	const char *col;
	RzListIter *iter;
	RzList *cols = t->cols;
	t->cols = rz_list_newf(__table_column_free);
	rz_list_foreach (list, iter, col) {
		int ncol = rz_table_column_nth(t, col);
		if (ncol != -1) {
			RzTableColumn *c = rz_list_get_n(cols, ncol);
			if (c) {
				rz_table_add_column(t, c->type, col, 0);
			}
		}
	}
}

static bool set_table_format(RzTable *t, const char *q) {
	if (!strcmp(q, "quiet")) {
		t->showHeader = false;
		t->showFancy = false;
	} else if (!strcmp(q, "fancy")) {
		t->showFancy = true;
	} else if (!strcmp(q, "simple")) {
		t->showFancy = false;
	} else if (!strcmp(q, "csv")) {
		t->showCSV = true;
	} else if (!strcmp(q, "json")) {
		t->showJSON = true;
	} else {
		return false;
	}
	return true;
}

RZ_API bool rz_table_query(RzTable *t, const char *q) {
	rz_return_val_if_fail(t, false);
	q = rz_str_trim_head_ro(q);
	// TODO support parenthesis and (or)||
	// split by "&&" (or comma) -> run .filter on each
	// addr/gt/200,addr/lt/400,addr/sort/dec,offset/sort/inc
	if (!q || !*q) {
		__table_adjust(t);
		return true;
	}
	if (*q == '?') {
		eprintf("RzTableQuery> comma separated. 'c' stands for column name.\n");
		eprintf(" c/sort/inc        sort rows by given colname\n");
		eprintf(" c/sortlen/inc     sort rows by strlen()\n");
		eprintf(" c/cols/c1/c2      only show selected columns\n");
		eprintf(" c                 only show column c\n");
		eprintf(" c/gt/0x800        grep rows matching col0 > 0x800\n");
		eprintf(" c/ge/0x800        grep rows matching col0 >= 0x800\n");
		eprintf(" c/lt/0x800        grep rows matching col0 < 0x800\n");
		eprintf(" c/le/0x800        grep rows matching col0 <= 0x800\n");
		eprintf(" c/eq/0x800        grep rows matching col0 == 0x800\n");
		eprintf(" c/ne/0x800        grep rows matching col0 != 0x800\n");
		eprintf(" */uniq            get the first row of each that col0 is unique\n");
		eprintf(" */head/10         same as | head -n 10\n");
		eprintf(" */tail/10         same as | tail -n 10\n");
		eprintf(" */page/1/10       show the first 10 rows (/page/2/10 will show the 2nd)\n");
		eprintf(" c/str/warn        grep rows matching col(name).str(warn)\n");
		eprintf(" c/strlen/3        grep rows matching strlen(col) == X\n");
		eprintf(" c/minlen/3        grep rows matching strlen(col) > X\n");
		eprintf(" c/maxlen/3        grep rows matching strlen(col) < X\n");
		eprintf(" c/sum             sum all the values of given column\n");
		eprintf(" :csv              .tostring() == .tocsv()\n");
		eprintf(" :json             .tostring() == .tojson()\n");
		eprintf(" :fancy            fancy table output with lines\n");
		eprintf(" :simple           simple table output without lines\n");
		eprintf(" :quiet            do not print column names header, implies :simple\n");
		return false;
	}

	RzListIter *iter;
	char *qq = strdup(q);
	RzList *queries = rz_str_split_list(qq, ":", 0);
	char *query;
	rz_list_foreach (queries, iter, query) {
		bool is_formatter = set_table_format(t, query);

		RzList *q = rz_str_split_list(query, "/", 2);
		if (rz_list_length(q) < 2 && (is_formatter || !*query)) {
			rz_list_free(q);
			continue;
		}

		const char *columnName = rz_list_get_n(q, 0);
		if (!columnName) {
			eprintf("Column name is NULL for (%s)\n", query);
			rz_list_free(q);
			continue;
		}
		const char *operation = rz_list_get_n(q, 1);
		const char *operand = rz_list_get_n(q, 2);

		int col = rz_table_column_nth(t, columnName);
		if (col == -1) {
			if (*columnName == '[') {
				col = atoi(columnName + 1);
			}
		}
		if (!operation) {
			RzList *list = rz_list_new();
			if (list) {
				rz_list_append(list, strdup(columnName));
				rz_table_columns(t, list);
				rz_list_free(list);
			}
		} else if (!strcmp(operation, "sort")) {
			rz_table_sort(t, col, operand && !strcmp(operand, "dec"));
		} else if (!strcmp(operation, "uniq")) {
			rz_table_group(t, col, NULL);
		} else if (!strcmp(operation, "sortlen")) {
			rz_table_sortlen(t, col, operand && !strcmp(operand, "dec"));
		} else if (!strcmp(operation, "join")) {
			// TODO: implement join operation with other command's tables
		} else if (!strcmp(operation, "sum")) {
			char *op = strdup(operand ? operand : "");
			RzList *list = rz_str_split_list(op, "/", 0);
			rz_list_prepend(list, strdup(columnName));
			rz_table_columns(t, list); // select/reorder columns
			rz_list_free(list);
			rz_table_filter(t, 0, '+', op);
			free(op);
		} else if (!strcmp(operation, "strlen")) {
			if (operand) {
				rz_table_filter(t, col, 's', operand);
			}
		} else if (!strcmp(operation, "minlen")) {
			if (operand) {
				rz_table_filter(t, col, 'l', operand);
			}
		} else if (!strcmp(operation, "maxlen")) {
			if (operand) {
				rz_table_filter(t, col, 'L', operand);
			}
		} else if (!strcmp(operation, "page")) {
			if (operand) {
				rz_table_filter(t, col, 'p', operand);
			}
		} else if (!strcmp(operation, "tail")) {
			if (operand) {
				rz_table_filter(t, col, 't', operand);
			}
		} else if (!strcmp(operation, "head")) {
			if (operand) {
				rz_table_filter(t, col, 'h', operand);
			}
		} else if (!strcmp(operation, "str")) {
			if (operand) {
				rz_table_filter(t, col, '~', operand);
			}
		} else if (!strcmp(operation, "cols")) {
			char *op = strdup(operand ? operand : "");
			RzList *list = rz_str_split_list(op, "/", 0);
			rz_list_prepend(list, strdup(columnName));
			rz_table_columns(t, list); // select/reorder columns
			rz_list_free(list);
			free(op);
			// TODO	rz_table_filter_columns (t, q);
		} else {
			int op = __resolveOperation(operation);
			if (op == -1) {
				eprintf("Invalid operation (%s)\n", operation);
			} else {
				rz_table_filter(t, col, op, operand);
			}
		}
		rz_list_free(q);
	}
	rz_list_free(queries);
	free(qq);
	__table_adjust(t);
	return true;
}

RZ_API bool rz_table_align(RzTable *t, int nth, int align) {
	RzTableColumn *col = rz_list_get_n(t->cols, nth);
	if (col) {
		col->align = align;
		return true;
	}
	return false;
}

RZ_API void rz_table_hide_header(RzTable *t) {
	t->showHeader = false;
}

RZ_API void rz_table_visual_list(RzTable *table, RzList *list, ut64 seek, ut64 len, int width, bool va) {
	ut64 mul, min = -1, max = -1;
	RzListIter *iter;
	RzListInfo *info;
	RzCons *cons = (RzCons *)table->cons;
	table->showHeader = false;
	const char *h_line = cons->use_utf8 ? RUNE_LONG_LINE_HORIZ : "-";
	const char *block = cons->use_utf8 ? UTF_BLOCK : "#";
	int j, i;
	width -= 80;
	if (width < 1) {
		width = 30;
	}

	rz_table_set_columnsf(table, "sssssss", "No.", "offset", "blocks", "offset", "perms", "extra", "name");
	rz_list_foreach (list, iter, info) {
		if (min == -1 || info->pitv.addr < min) {
			min = info->pitv.addr;
		}
		if (max == -1 || info->pitv.addr + info->pitv.size > max) {
			max = info->pitv.addr + info->pitv.size;
		}
	}
	mul = (max - min) / width;
	if (min != -1 && mul > 0) {
		i = 0;
		rz_list_foreach (list, iter, info) {
			RzStrBuf *buf = rz_strbuf_new("");
			for (j = 0; j < width; j++) {
				ut64 pos = min + j * mul;
				ut64 npos = min + (j + 1) * mul;
				const char *arg = (info->pitv.addr < npos && (info->pitv.addr + info->pitv.size) > pos)
					? block
					: h_line;
				rz_strbuf_append(buf, arg);
			}
			char *b = rz_strbuf_drain(buf);
			if (va) {
				rz_table_add_rowf(table, "sssssss",
					sdb_fmt("%d%c", i, rz_itv_contain(info->vitv, seek) ? '*' : ' '),
					sdb_fmt("0x%" PFMT64x, info->vitv.addr),
					b,
					sdb_fmt("0x%" PFMT64x, rz_itv_end(info->vitv)),
					(info->perm != -1) ? rz_str_rwx_i(info->perm) : "",
					(info->extra) ? info->extra : "",
					(info->name) ? info->name : "");
			} else {
				rz_table_add_rowf(table, "sssssss", sdb_fmt("%d%c", i, rz_itv_contain(info->pitv, seek) ? '*' : ' '),
					sdb_fmt("0x%" PFMT64x, info->pitv.addr), b,
					sdb_fmt("0x%" PFMT64x, rz_itv_end(info->pitv)),
					(info->perm != -1) ? rz_str_rwx_i(info->perm) : "", (info->extra) ? info->extra : "", (info->name) ? info->name : "");
			}
			free(b);
			i++;
		}
		RzStrBuf *buf = rz_strbuf_new("");
		/* current seek */
		if (i > 0 && len != 0) {
			if (seek == UT64_MAX) {
				seek = 0;
			}
			for (j = 0; j < width; j++) {
				rz_strbuf_append(buf, ((j * mul) + min >= seek && (j * mul) + min <= seek + len) ? "^" : h_line);
			}
			rz_table_add_rowf(table, "sssssss", "=>", sdb_fmt("0x%08" PFMT64x, seek),
				rz_strbuf_drain(buf), sdb_fmt("0x%08" PFMT64x, seek + len), "", "", "");
		} else {
			rz_strbuf_free(buf);
		}
	}
}

/**
 * /brief Generates the transpose of RzTable.
 *
 * /param t Referenced \p RzTable
 * /return t Referenced \p RzTable
 *
 * This function returns the transpose of the RzTable passed to the table. 
 */
RZ_OWN RZ_API RzTable *rz_table_transpose(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);
	RzListIter *iter1;
	RzListIter *iter;
	RzListIter *trrow_iter; // transpose row iter
	RzList *row_name = rz_list_new();
	RzList *row_list;
	RzTable *transpose = rz_table_new();
	RzTableColumn *col;
	RzTableRow *row;
	RzTableColumnType *typeString = rz_table_type("string");
	char *item;

	// getting table column names to add to row head
	rz_table_add_column(transpose, typeString, "Name", 0);

	// adding rows to transpose table rows * (number of columns in the table)
	for (int i = 0; i < t->rows->length; i++) {
		rz_table_add_column(transpose, typeString, "Value", 0);
	}

	// column names to row heads
	rz_list_foreach (t->cols, iter1, col) {
		rz_list_append(row_name, col->name);
	}

	// adding rows with name alone
	if (row_name && t->rows) {
		iter = row_name->head;
		if (iter) {
			item = iter->data;
			for (int i = 0; i < t->totalCols; i++) {
				rz_table_add_row(transpose, item, NULL);
				if (iter->n) {
					iter = iter->n;
					item = iter->data;
				}
			}
		}
	}

	if (transpose->rows) {
		row_list = transpose->rows;
		trrow_iter = row_list->head;
		RzTableRow *trans_row = trrow_iter->data;
		rz_list_foreach (t->rows, iter, row) {
			trrow_iter = row_list->head;
			if (trrow_iter) {
				trans_row = trrow_iter->data;
				rz_list_foreach (row->items, iter1, item) {
					if (trrow_iter && trans_row->items) {
						trans_row = trrow_iter->data;
						rz_list_append(trans_row->items, strdup(item));
						trrow_iter = trrow_iter->n;
					}
				}
			}
		}
		//free(item);
	}
	return transpose;
}

#if 0
// TODO: to be implemented
RZ_API RzTable *rz_table_clone(RzTable *t) {
	// TODO: implement
	return NULL;
}

RZ_API RzTable *rz_table_push(RzTable *t) {
	// TODO: implement
	return NULL;
}

RZ_API RzTable *rz_table_pop(RzTable *t) {
	// TODO: implement
	return NULL;
}

RZ_API void rz_table_fromjson(RzTable *t, const char *csv) {
	//  TODO
}

RZ_API void rz_table_fromcsv(RzTable *t, const char *csv) {
	//  TODO
}

RZ_API char *rz_table_tohtml(RzTable *t) {
	// TODO
	return NULL;
}

RZ_API void rz_table_transpose(RzTable *t) {
	// When the music stops rows will be cols and cols... rows!
}

RZ_API void rz_table_format(RzTable *t, int nth, RzTableColumnType *type) {
	// change the format of a specific column
	// change imm base, decimal precission, ...
}

// to compute sum result of all the elements in a column
RZ_API ut64 rz_table_reduce(RzTable *t, int nth) {
	// When the music stops rows will be cols and cols... rows!
	return 0;
}
#endif
