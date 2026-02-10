// SPDX-FileCopyrightText: 2019-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_table.h>
#include "rz_cons.h"

typedef struct row_info {
	size_t nth;
	RzTableColumnTypeComparator cmp;
} row_info_t;

static int cmp_string(const void *a, const void *b) {
	return strcmp((const char *)a, (const char *)b);
}

static int cmp_number(const void *a, const void *b) {
	return rz_num_get(NULL, a) - rz_num_get(NULL, b);
}

static RzTableColumnTypeComparator table_type_to_comparator(const RzTableColumnType type) {
	switch (type) {
	case RZ_TABLE_COLUMN_TYPE_STRING:
		return cmp_string;
	case RZ_TABLE_COLUMN_TYPE_NUMBER:
		return cmp_number;
	case RZ_TABLE_COLUMN_TYPE_BOOL:
		return cmp_number;
	default:
		return NULL;
	}
}

static void table_adjust(RzTable *t) {
	RzTableColumn *col;
	RzTableRow *row;
	int length = 0;
	if (t->showHeader) {
		rz_vector_foreach (t->cols, col) {
			int length = rz_str_utf8_ansi_cols(col->name) + 1;
			col->width = length;
		}
	}
	rz_vector_foreach (t->rows, row) {
		void **pitem;
		char *item;
		int ncol = 0;
		rz_pvector_foreach (row->items, pitem) {
			item = *pitem;
			length = rz_str_utf8_ansi_cols(item) + 1;
			col = rz_vector_index_ptr(t->cols, ncol);
			if (col) {
				col->width = RZ_MAX(col->width, length);
			}
			ncol++;
		}
	}
}

static void table_row_fini(RZ_NULLABLE RzTableRow *row) {
	if (!row) {
		return;
	}
	rz_pvector_free(row->items);
}

static void table_column_fini(RzTableColumn *col) {
	if (!col) {
		return;
	}
	free(col->name);
}

static void table_row_fini_wrapper(void *_row, void *user) {
	table_row_fini((RzTableRow *)_row);
}

static void table_column_fini_wrapper(void *_col, void *user) {
	table_column_fini((RzTableColumn *)_col);
}

/**
 * \brief      Allocates and initialize an RzTable structure
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzTable *rz_table_new(void) {
	RzTable *t = RZ_NEW0(RzTable);
	if (!t) {
		return NULL;
	}

	t->showHeader = true;
	t->cols = rz_vector_new(sizeof(RzTableColumn), table_column_fini_wrapper, NULL);
	t->rows = rz_vector_new(sizeof(RzTableRow), table_row_fini_wrapper, NULL);
	t->showSum = false;
	return t;
}

/**
 * \brief      Frees an given RzTable structure
 *
 * \param      t Referenced \p RzTable
 */
RZ_API void rz_table_free(RZ_NULLABLE RzTable *t) {
	if (!t) {
		return;
	}
	rz_vector_free(t->cols);
	rz_vector_free(t->rows);
	free(t);
}

static bool table_index_of_column(RzTable *t, const char *name, size_t *index) {
	RzTableColumn *col;
	size_t n = 0;
	rz_vector_enumerate (t->cols, col, n) {
		if (RZ_STR_NE(name, col->name)) {
			continue;
		}
		if (index) {
			*index = n;
		}
		return true;
	}
	return false;
}

static bool table_add_column(RzTable *t, const RzTableColumnType type, RzTableColumnTypeComparator cmp, const char *name) {
	if (table_index_of_column(t, name, NULL)) {
		return false;
	}

	RzTableColumn c = { 0 };
	c.type_cmp = cmp;
	c.type = type;
	c.name = rz_str_dup(name);
	c.width = rz_str_utf8_ansi_cols(name) + 1;
	c.total = -1;
	if (c.type == RZ_TABLE_COLUMN_TYPE_NUMBER) {
		c.align = RZ_TABLE_ALIGN_RIGHT;
	}
	rz_vector_push(t->cols, &c);
	return true;
}

/**
 * \brief      Adds a new column to a RzTable structure
 *
 * \param      t          The RzTable to use
 * \param[in]  type       The column type
 * \param[in]  name       The column name
 * \param[in]  max_width  The column maximum width
 */
RZ_API void rz_table_add_column(RZ_NONNULL RzTable *t, const RzTableColumnType type, RZ_NONNULL const char *name) {
	rz_return_if_fail(t && type < RZ_TABLE_COLUMN_TYPE_ENUM_MAX && RZ_STR_ISNOTEMPTY(name));
	RzTableColumnTypeComparator cmp = table_type_to_comparator(type);
	table_add_column(t, type, cmp, name);
}

static bool table_add_row(RzTable *t, RzPVector /*<char *>*/ *items, const char *arg, int col) {
	int itemLength = rz_str_utf8_ansi_cols(arg);
	RzTableColumn *c = rz_vector_index_ptr(t->cols, col);
	if (c) {
		char *str = rz_str_dup(arg);
		c->width = RZ_MAX(c->width, itemLength);
		rz_pvector_push(items, str);
		return true;
	}
	return false;
}

/**
 * \brief Add a new row to RzTable
 *
 * \param t pointer to RzTable
 * \param items pointer to RzPVector which contains row elements
 */
RZ_API void rz_table_add_row_vec(RZ_NONNULL RzTable *t, RZ_NONNULL RZ_OWN RzPVector /*<char *>*/ *items) {
	rz_return_if_fail(t && items);

	RzTableRow row = { 0 };
	row.items = items;
	rz_vector_push(t->rows, &row);

	// throw warning if not enough columns defined in header
	t->totalCols = RZ_MAX(t->totalCols, rz_pvector_len(items));
}

/**
 * \brief Specify the types and names of the referenced table.
 *
 * \param t Referenced \p RzTable
 * \param fmt String containing the numer and types of the columns
 * \param ap Variable number of strings that specify the names of the columns.
 *           There should be enough string as characters in \p fmt .
 */
RZ_API void rz_table_set_vcolumnsf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, va_list ap) {
	rz_return_if_fail(t && RZ_STR_ISNOTEMPTY(fmt));

	const char *name;
	const char *f = fmt;
	for (; *f; f++) {
		name = va_arg(ap, const char *);
		if (!name) {
			break;
		}
		switch (*f) {
		case 'b':
			table_add_column(t, RZ_TABLE_COLUMN_TYPE_BOOL, cmp_number, name);
			break;
		case 's':
		case 'z':
			table_add_column(t, RZ_TABLE_COLUMN_TYPE_STRING, cmp_string, name);
			break;
		case 'i':
		case 'd':
		case 'n':
		case 'x':
		case 'X':
			table_add_column(t, RZ_TABLE_COLUMN_TYPE_NUMBER, cmp_number, name);
			break;
		default:
			RZ_LOG_ERROR("table: invalid format string char '%c'\n", *f);
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
RZ_API void rz_table_set_columnsf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, ...) {
	rz_return_if_fail(t && RZ_STR_ISNOTEMPTY(fmt));

	va_list ap;
	va_start(ap, fmt);
	rz_table_set_vcolumnsf(t, fmt, ap);
	va_end(ap);
}

/**
 * \brief Given a row in \c RzTable, append a new column with given format
 *        by pulling out value of that type form given va_list
 *
 * Possible values for format are :
 * - s, z : String (const char*)
 * - b    : Boolean (bool)
 * - i, d : Integer (int, int32_t)
 * - n    : Number (unsigned long long int, uint64_t)
 * - u    : Size (B, KB, MB, GB, etc...)
 * - f    : Double
 * - x, X : Hex value (x means all smal, X means all CAPS)
 *
 * \param row \p RzPVector to append the new column into
 * \param fmt Character representing the type of value to be stored in last column of given row.
 * \param ap Variadic argument list. Will be used to pull out value based on given fmt.
 */
#define add_column_to_rowf(row, fmt, ap) \
	do { \
		const char *arg = NULL; \
		switch (fmt) { \
		case 's': \
		case 'z': \
			arg = va_arg(ap, const char *); \
			rz_pvector_push(row, rz_str_dup(arg ? arg : "")); \
			break; \
		case 'b': \
			rz_pvector_push(row, rz_str_dup(rz_str_bool(va_arg(ap, int)))); \
			break; \
		case 'i': \
		case 'd': \
			rz_pvector_push(row, rz_str_newf("%d", va_arg(ap, int))); \
			break; \
		case 'n': \
			rz_pvector_push(row, rz_str_newf("%" PFMT64d, va_arg(ap, ut64))); \
			break; \
		case 'u': \
			rz_pvector_push(row, rz_num_units(NULL, 32, va_arg(ap, ut64))); \
			break; \
		case 'f': \
			rz_pvector_push(row, rz_str_newf("%8lf", va_arg(ap, double))); \
			break; \
		case 'x': \
		case 'X': { \
			ut64 n = va_arg(ap, ut64); \
			if (n == UT64_MAX) { \
				if (fmt == 'X') { \
					rz_pvector_push(row, rz_str_dup("----------")); \
				} else { \
					rz_pvector_push(row, rz_str_dup("-1")); \
				} \
			} else { \
				if (fmt == 'X') { \
					rz_pvector_push(row, rz_str_newf("0x%08" PFMT64x, n)); \
				} else { \
					rz_pvector_push(row, rz_str_newf("0x%" PFMT64x, n)); \
				} \
			} \
		} break; \
		default: \
			RZ_LOG_ERROR("table: Invalid format string char '%c'\n", fmt); \
			break; \
		} \
	} while (0)

/**
 * \brief      Add some columns values to the last created row, if any, or create a new row otherwise.
 *
 * \param      t          The RzTable to use
 * \param[in]  fmt        The format to decode
 * \param[in]  ...        The var args to use as arguments.
 */
RZ_API void rz_table_add_row_columnsf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, ...) {
	rz_return_if_fail(t && RZ_STR_ISNOTEMPTY(fmt));

	va_list ap;
	va_start(ap, fmt);
	RzTableRow *row = rz_vector_tail(t->rows);
	RzPVector *vec;
	bool add_row;
	if (row) {
		vec = row->items;
		add_row = false;
	} else {
		vec = rz_pvector_new(free);
		add_row = true;
	}
	for (const char *f = fmt; *f; f++) {
		add_column_to_rowf(vec, *f, ap);
	}
	va_end(ap);
	if (add_row) {
		rz_table_add_row_vec(t, vec);
	}
}

/**
 * \brief Add a new row with given format and variadic list of values.
 *
 * \param t Table to add new row into
 * \param fmt Format string to define column ordering and type of given row.
 * \param ap Variadic argument list to pull values for each column in row from.
 *
 * \sa rz_table_append_column_to_vrowf
 */
RZ_API void rz_table_add_vrowf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, va_list ap) {
	rz_return_if_fail(t && RZ_STR_ISNOTEMPTY(fmt));

	RzPVector *vec = rz_pvector_new(free);
	for (const char *f = fmt; *f; f++) {
		add_column_to_rowf(vec, *f, ap);
	}
	rz_table_add_row_vec(t, vec);
}

/**
 * \brief      Add a new row with the specified columns values.
 *
 * \param      t          The RzTable to use
 * \param[in]  fmt        The format to decode
 * \param[in]  ...        The var args to use as arguments.
 */
RZ_API void rz_table_add_rowf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, ...) {
	rz_return_if_fail(t && RZ_STR_ISNOTEMPTY(fmt));

	va_list ap;
	va_start(ap, fmt);
	rz_table_add_vrowf(t, fmt, ap);
	va_end(ap);
}

/**
 * \brief      Add a new row with the specified column name and values.
 *
 * \param      t          The RzTable to use
 * \param[in]  name       The column name
 * \param[in]  ...        The var args to use as values.
 */
RZ_API void rz_table_add_row(RZ_NONNULL RzTable *t, RZ_NONNULL const char *name, ...) {
	rz_return_if_fail(t && RZ_STR_ISNOTEMPTY(name));

	RzTableRow row = { 0 };
	va_list ap;
	va_start(ap, name);

	size_t col = 0;
	RzPVector *items = rz_pvector_new(free);
	table_add_row(t, items, name, col++);
	for (;;) {
		const char *arg = va_arg(ap, const char *);
		if (!arg) {
			break;
		}
		table_add_row(t, items, arg, col);
		// TODO: assert if number of columns doesnt match t->cols
		col++;
	}
	va_end(ap);
	row.items = items;
	rz_vector_push(t->rows, &row);

	// throw warning if not enough columns defined in header
	t->totalCols = RZ_MAX(t->totalCols, rz_pvector_len(items));
}

static const char *table_get_color(RzTable *t, const char *value, const RzTableColumn *col, size_t n_col) {
	if (!t->color) {
		return NULL;
	}
	return t->color(value, col->name, n_col, col->type, t->color_user);
}

static int table_strbuf_append_col_aligned_fancy(RzTable *t, RzStrBuf *sb, RzTableColumn *col, char *str, const char *color) {
	const char *v_line = t->char_mode != RZ_TABLE_CHAR_MODE_ASCII ? RUNE_LINE_VERT : "|";
	int ll = rz_strbuf_length(sb);
	int pad = 0;
	int len = rz_str_utf8_ansi_cols(str);
	if (len < rz_str_utf8_cols(str) && len < col->width) {
		pad = col->width - len;
	}

	switch (col->align) {
	default:
		/* fall-thru */
	case RZ_TABLE_ALIGN_LEFT:
		if (color) {
			rz_strbuf_appendf(sb, "%s %s%-*s" Color_RESET, v_line, color, col->width, str);
		} else {
			rz_strbuf_appendf(sb, "%s %-*s", v_line, col->width, str);
		}
		rz_strbuf_appendf(sb, "%*s", pad, "");
		break;
	case RZ_TABLE_ALIGN_RIGHT:
		if (color) {
			rz_strbuf_appendf(sb, "%s%s%*s" Color_RESET " ", v_line, color, col->width, str);
		} else {
			rz_strbuf_appendf(sb, "%s%*s ", v_line, col->width, str);
		}
		rz_strbuf_appendf(sb, "%*s", pad, "");
		break;
	case RZ_TABLE_ALIGN_CENTER: {
		pad = (col->width - len) / 2;
		int left = col->width - (pad * 2 + len);
		rz_strbuf_appendf(sb, "%s %-*s", v_line, pad, " ");
		if (color) {
			rz_strbuf_appendf(sb, "%s%-*s" Color_RESET, color, pad + left, str);
		} else {
			rz_strbuf_appendf(sb, "%-*s", pad + left, str);
		}
		break;
	}
	}
	return rz_strbuf_length(sb) - ll;
}

static void table_compute_total(RzTable *t) {
	RzTableRow *row;
	rz_vector_foreach (t->rows, row) {
		void **pitem;
		char *item;
		int c = 0;
		rz_pvector_foreach (row->items, pitem) {
			item = *pitem;
			RzTableColumn *col = rz_vector_index_ptr(t->cols, c);
			if (col->type == RZ_TABLE_COLUMN_TYPE_NUMBER && rz_str_isnumber(item)) {
				if (col->total < 0) {
					col->total = 0;
				}
				col->total += sdb_atoi(item);
			}
			c++;
		}
	}
}

/**
 * \brief Convert the content of RzTable to string
 *
 * \param t pointer to RzTable
 * \return string containing content of RzTable
 */
RZ_API RZ_OWN char *rz_table_tofancystring(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);

	if (rz_vector_len(t->cols) == 0) {
		return rz_str_dup("");
	}
	RzStrBuf *sb = rz_strbuf_new("");
	RzTableRow *row;
	RzTableColumn *col;
	bool useUtf8 = t->char_mode != RZ_TABLE_CHAR_MODE_ASCII;
	bool useUtf8Curvy = t->char_mode == RZ_TABLE_CHAR_MODE_UTF8_CURVY;
	const char *v_line = useUtf8 ? RUNE_LINE_VERT : "|";
	const char *h_line = useUtf8 ? RUNE_LINE_HORIZ : "-";
	const char *l_intersect = useUtf8 ? RUNE_LINE_VERT : ")";
	const char *rz_intersect = useUtf8 ? RUNE_LINE_VERT : "(";
	const char *tl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_TL : RUNE_CORNER_TL) : ".";
	const char *tr_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_TR : RUNE_CORNER_TR) : ".";
	const char *bl_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BL : RUNE_CORNER_BL) : "`";
	const char *br_corner = useUtf8 ? (useUtf8Curvy ? RUNE_CURVE_CORNER_BR : RUNE_CORNER_BR) : "'";
	table_adjust(t);

	rz_vector_foreach (t->cols, col) {
		table_strbuf_append_col_aligned_fancy(t, sb, col, col->name, NULL);
	}
	int len = rz_str_utf8_ansi_cols(rz_strbuf_get(sb)) - 1;
	int maxlen = len;
	char *h_line_str = rz_str_repeat(h_line, maxlen);
	{
		char *s = rz_str_newf("%s%s%s\n", tl_corner, h_line_str, tr_corner);
		rz_strbuf_prepend(sb, s);
		free(s);
	}

	rz_strbuf_appendf(sb, "%s\n%s%s%s\n", v_line, l_intersect, h_line_str, rz_intersect);
	rz_vector_foreach (t->rows, row) {
		void **pitem;
		char *item;
		size_t n_col = 0;
		rz_pvector_foreach (row->items, pitem) {
			item = *pitem;
			if (n_col >= rz_vector_len(t->cols)) {
				break;
			}
			RzTableColumn *col = rz_vector_index_ptr(t->cols, n_col);
			const char *color = table_get_color(t, item, col, n_col);
			(void)table_strbuf_append_col_aligned_fancy(t, sb, col, item, color);
			n_col++;
		}
		rz_strbuf_appendf(sb, "%s\n", v_line);
	}

	if (t->showSum) {
		char tmp[64];
		table_compute_total(t);
		rz_strbuf_appendf(sb, "%s%s%s\n", l_intersect, h_line_str, rz_intersect);
		rz_vector_foreach (t->cols, col) {
			char *num = col->total == -1 ? "" : sdb_itoa(col->total, tmp, 10);
			(void)table_strbuf_append_col_aligned_fancy(t, sb, col, num, NULL);
		}
		rz_strbuf_appendf(sb, "%s\n", v_line);
	}
	rz_strbuf_appendf(sb, "%s%s%s\n", bl_corner, h_line_str, br_corner);
	free(h_line_str);
	return rz_strbuf_drain(sb);
}

static int table_strbuf_append_col_aligned(RzStrBuf *sb, RzTableColumn *col, const char *str, bool nopad, const char *color) {
	int ll = rz_strbuf_length(sb);
	char *pad = "";
	int padlen = 0;
	int len1 = rz_str_utf8_cols(str);
	int len2 = rz_str_utf8_ansi_cols(str);
	if (!nopad) {
		if (len1 > len2) {
			if (len2 < col->width) {
				padlen = col->width - len2;
			}
		}
	}
	switch (col->align) {
	default:
		/* fall-thru */
	case RZ_TABLE_ALIGN_LEFT:
		if (nopad) {
			if (color) {
				rz_strbuf_appendf(sb, "%s%s" Color_RESET, color, str);
			} else {
				rz_strbuf_appendf(sb, "%s", str);
			}
		} else {
			pad = rz_str_repeat(" ", padlen);
			if (color) {
				rz_strbuf_appendf(sb, "%s%-*s" Color_RESET "%s", color, col->width, str, pad);
			} else {
				rz_strbuf_appendf(sb, "%-*s%s", col->width, str, pad);
			}
			free(pad);
		}
		break;
	case RZ_TABLE_ALIGN_RIGHT:
		if (!nopad) {
			padlen++;
		}
		pad = rz_str_repeat(" ", padlen);
		if (color) {
			rz_strbuf_appendf(sb, "%s%*s" Color_RESET "%s", color, col->width - 1, str, pad);
		} else {
			rz_strbuf_appendf(sb, "%*s%s", col->width - 1, str, pad);
		}
		free(pad);
		break;
	case RZ_TABLE_ALIGN_CENTER: {
		int pad = (col->width - len2) / 2;
		int left = col->width - (pad * 2 + len2);
		rz_strbuf_appendf(sb, "%-*s", pad, " ");
		if (color) {
			rz_strbuf_appendf(sb, "%s%-*s" Color_RESET " ", color, pad + left, str);
		} else {
			rz_strbuf_appendf(sb, "%-*s ", pad + left, str);
		}
		break;
	}
	}
	return rz_strbuf_length(sb) - ll;
}

/**
 * \brief      Stringifies a given RzTable (the output depends by the table configuration)
 *
 * \param      t     The RzTable to use
 *
 * \return     On success returns a valid C string, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_table_tostring(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);

	if (t->showCSV) {
		return rz_table_tocsv(t);
	}
	if (t->showJSON) {
		char *s = rz_table_tojson(t);
		char *q = rz_str_newf("%s\n", s);
		free(s);
		return q;
	}
	if (t->showFancy) {
		return rz_table_tofancystring(t);
	}
	return rz_table_tosimplestring(t);
}

/**
 * \brief      Stringifies a given RzTable using the simplified format
 *
 * \param      t     The RzTable to use
 *
 * \return     On success returns a valid C string, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_table_tosimplestring(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);

	if (rz_vector_len(t->cols) == 0) {
		return rz_str_dup("");
	}

	RzStrBuf *sb = rz_strbuf_new("");
	RzTableRow *row;
	RzTableColumn *col;
	const char *h_line = t->char_mode != RZ_TABLE_CHAR_MODE_ASCII ? RUNE_LONG_LINE_HORIZ : "-";
	table_adjust(t);
	int maxlen = 0;
	if (t->showHeader) {
		rz_vector_foreach (t->cols, col) {
			int ll = table_strbuf_append_col_aligned(sb, col, col->name, false, NULL);
			maxlen = RZ_MAX(maxlen, ll);
		}
		int len = rz_str_utf8_ansi_cols(rz_strbuf_get(sb));
		char *l = rz_str_repeat(h_line, RZ_MAX(maxlen, len));
		if (l) {
			rz_strbuf_appendf(sb, "\n%s\n", l);
			free(l);
		}
	}
	rz_vector_foreach (t->rows, row) {
		void **pitem;
		char *item;
		size_t n_col = 0;
		rz_pvector_foreach (row->items, pitem) {
			item = *pitem;
			if (n_col >= rz_vector_len(t->cols)) {
				break;
			}
			RzTableColumn *col = rz_vector_index_ptr(t->cols, n_col);
			bool nopad = (item == rz_pvector_tail(row->items));
			const char *color = table_get_color(t, item, col, n_col);
			(void)table_strbuf_append_col_aligned(sb, col, item, nopad, color);
			n_col++;
		}
		rz_strbuf_append(sb, "\n");
	}
	if (t->showSum) {
		char tmp[64];
		table_compute_total(t);
		if (maxlen > 0) {
			char *l = rz_str_repeat(h_line, maxlen);
			if (l) {
				rz_strbuf_appendf(sb, "\n%s\n", l);
				free(l);
			}
		}
		rz_vector_foreach (t->cols, col) {
			bool nopad = (col == rz_vector_tail(t->cols));
			(void)table_strbuf_append_col_aligned(sb, col, sdb_itoa(col->total, tmp, 10), nopad, NULL);
		}
	}
	return rz_strbuf_drain(sb);
}

/**
 * \brief      Stringifies a given RzTable to CSV
 *
 * \param      t     The RzTable to use
 *
 * \return     On success returns a valid C string, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_table_tocsv(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);

	if (rz_vector_len(t->cols) == 0) {
		return rz_str_dup("");
	}

	RzStrBuf *sb = rz_strbuf_new("");
	RzTableRow *row;
	RzTableColumn *col;
	if (t->showHeader) {
		const char *comma = "";
		rz_vector_foreach (t->cols, col) {
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
	rz_vector_foreach (t->rows, row) {
		void **pitem;
		char *item;
		int c = 0;
		const char *comma = "";
		rz_pvector_foreach (row->items, pitem) {
			item = *pitem;
			RzTableColumn *col = rz_vector_index_ptr(t->cols, c);
			if (col) {
				if (strchr(item, ',')) {
					rz_strbuf_appendf(sb, "%s\"%s\"", comma, item);
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

/**
 * \brief      Stringifies a given RzTable to JSON
 *
 * \param      t     The RzTable to use
 *
 * \return     On success returns a valid C string, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_table_tojson(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);

	if (rz_vector_len(t->cols) == 0) {
		return rz_str_dup("[]");
	}

	PJ *pj = pj_new();
	RzTableRow *row;
	pj_a(pj);
	rz_vector_foreach (t->rows, row) {
		void **pitem;
		char *item;
		int c = 0;
		pj_o(pj);
		rz_pvector_foreach (row->items, pitem) {
			item = *pitem;
			RzTableColumn *col = rz_vector_index_ptr(t->cols, c);
			if (col) {
				if (col->type == RZ_TABLE_COLUMN_TYPE_NUMBER) {
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

static void table_filter(RZ_NONNULL RzTable *t, size_t nth, int op, RZ_NONNULL const char *un) {
	if (nth >= rz_vector_len(t->cols)) {
		return;
	}

	RzTableRow *row;
	ut64 uv = rz_num_math(NULL, un);
	ut64 sum = 0;
	size_t page = 0, page_items = 0;
	size_t lrow = 0;
	if (op == 't') {
		size_t ll = rz_vector_len(t->rows);
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
	ut32 i;
	for (i = 0; i < rz_vector_len(t->rows); i++) {
		row = rz_vector_index_ptr(t->rows, i);
		const char *nn = rz_pvector_at(row->items, nth);
		ut64 nv = rz_num_math(NULL, nn);
		bool match = true;
		RzTableRow *del_row = RZ_NEW(RzTableRow);
		if (!del_row) {
			RZ_LOG_ERROR("Failed to allocate memory.\n");
			return;
		}
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
			if (nv == 0 && nn != NULL) {
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
			if (nn != NULL && un != NULL) {
				match = strstr(nn, un) != NULL;
			}
			break;
		case 's':
			if (nn != NULL && un != NULL) {
				match = strlen(nn) == atoi(un);
			}
			break;
		case 'l':
			if (nn != NULL && un != NULL) {
				match = strlen(nn) > atoi(un);
			}
			break;
		case 'L':
			if (nn != NULL && un != NULL) {
				match = strlen(nn) < atoi(un);
			}
			break;
		case '\0':
			break;
		}
		if (!match) {
			rz_vector_remove_at(t->rows, i--, del_row);
			table_row_fini(del_row);
		}
		RZ_FREE(del_row);
	}
	if (op == '+') {
		rz_table_add_rowf(t, "u", sum);
	}
}

static int cmp(const void *_a, const void *_b, void *user) {
	row_info_t *info = (row_info_t *)user;
	RzTableRow *a = (RzTableRow *)_a;
	RzTableRow *b = (RzTableRow *)_b;
	const char *wa = rz_pvector_at(a->items, info->nth);
	const char *wb = rz_pvector_at(b->items, info->nth);
	return info->cmp(wa, wb);
}

/**
 * \brief      Sorts the rows of a given RzTable by the selected column type
 *
 * \param[in]  t        The RzTable to use
 * \param[in]  nth      The nth column to use for sorting
 * \param[in]  reverse  When true, the table is sorted in reverse order
 */
RZ_API void rz_table_sort(RZ_NONNULL RzTable *t, size_t nth, bool reverse) {
	rz_return_if_fail(t);

	if (nth >= rz_vector_len(t->cols)) {
		return;
	}

	RzTableColumn *col = rz_vector_index_ptr(t->cols, nth);
	if (!(col && col->type_cmp)) {
		return;
	}

	row_info_t info = { 0 };
	info.nth = nth;
	info.cmp = col->type_cmp;
	rz_vector_sort(t->rows, cmp, reverse, &info);
}

static int cmplen(const void *_a, const void *_b, void *user) {
	row_info_t *info = (row_info_t *)user;
	RzTableRow *a = (RzTableRow *)_a;
	RzTableRow *b = (RzTableRow *)_b;
	const char *wa = rz_pvector_at(a->items, info->nth);
	const char *wb = rz_pvector_at(b->items, info->nth);
	return strlen(wa) - strlen(wb);
}

/**
 * \brief      Sorts the rows of a given RzTable by the selected column value length
 *
 * \param[in]  t        The RzTable to use
 * \param[in]  nth      The nth column to use for sorting
 * \param[in]  reverse  When true, the table is sorted in reverse order
 */
RZ_API void rz_table_sortlen(RZ_NONNULL RzTable *t, size_t nth, bool reverse) {
	rz_return_if_fail(t);

	if (nth >= rz_vector_len(t->cols)) {
		return;
	}

	RzTableColumn *col = rz_vector_index_ptr(t->cols, nth);
	if (!col) {
		return;
	}

	row_info_t info = { 0 };
	info.nth = nth;
	rz_vector_sort(t->rows, cmplen, reverse, &info);
}

static int table_rows_cmp_value_at(RzPVector /*<char *>*/ *lhs, RzPVector /*<char *>*/ *rhs, RzVector /*<RzTableColumn>*/ *cols, size_t nth) {
	if (nth >= rz_vector_len(cols)) {
		return 0;
	}

	RzTableColumn *item_col = rz_vector_index_ptr(cols, nth);
	void *item_lhs = rz_pvector_at(lhs, nth);
	void *item_rhs = rz_pvector_at(rhs, nth);

	int pos = item_col->type_cmp(item_lhs, item_rhs);
	if (pos != 0) {
		return pos;
	}

	if (rz_pvector_len(lhs) > rz_pvector_len(rhs)) {
		return 1;
	} else if (rz_pvector_len(lhs) < rz_pvector_len(rhs)) {
		return -1;
	}

	return 0;
}

static int table_rows_cmp_all(RzPVector /*<char *>*/ *lhs, RzPVector /*<char *>*/ *rhs, RzVector /*<RzTableColumn>*/ *cols) {
	void *item_lhs, *item_rhs;
	RzTableColumn *item_col;

	for (size_t i = 0; i < rz_pvector_len(lhs) && i < rz_pvector_len(rhs) && i < rz_vector_len(cols); i++) {
		item_lhs = rz_pvector_at(lhs, i);
		item_rhs = rz_pvector_at(rhs, i);
		item_col = rz_vector_index_ptr(cols, i);

		int pos = item_col->type_cmp(item_lhs, item_rhs);
		if (pos) {
			return pos;
		}
	}

	if (rz_pvector_len(lhs) > rz_pvector_len(rhs)) {
		return 1;
	} else if (rz_pvector_len(lhs) < rz_pvector_len(rhs)) {
		return -1;
	}

	return 0;
}

/**
 * \brief      Removes from the RzTable any duplicated rows
 *
 * \param      t     The RzTable to use
 */
RZ_API void rz_table_uniq(RZ_NONNULL RzTable *t) {
	rz_return_if_fail(t);

	RzTableRow *row = NULL;
	RzTableRow *uniq_row = NULL;
	RzVector *rows = t->rows;

	for (size_t i = 0; i < rz_vector_len(rows); i++) {
		row = rz_vector_index_ptr(rows, i);
		for (size_t j = 0; j < i; j++) {
			uniq_row = rz_vector_index_ptr(rows, j);
			if (table_rows_cmp_all(uniq_row->items, row->items, t->cols)) {
				continue;
			}

			RzTableRow del_row = { 0 };
			rz_vector_remove_at(rows, i--, &del_row);
			// free the deleted row
			table_row_fini(&del_row);
			break;
		}
	}
}

/**
 * \brief      Removes from the RzTable any grouped row via its column
 *
 * \param      t         The RzTable to use
 * \param      nth       The column to select
 * \param      selector  The selector to apply (can be null)
 */
RZ_API void rz_table_group(RZ_NONNULL RzTable *t, size_t nth, RZ_NULLABLE RzTableSelector selector) {
	rz_return_if_fail(t);

	if (nth >= rz_vector_len(t->cols)) {
		return;
	}

	RzTableRow *row = NULL;
	RzTableRow *uniq_row = NULL;
	RzVector *rows = t->rows;

	for (size_t i = 0; i < rz_vector_len(rows); i++) {
		row = rz_vector_index_ptr(rows, i);
		for (size_t j = 0; j < i; j++) {
			uniq_row = rz_vector_index_ptr(rows, j);
			if (table_rows_cmp_value_at(uniq_row->items, row->items, t->cols, nth)) {
				continue;
			}

			if (selector) {
				selector(uniq_row, row, nth);
			}

			RzTableRow del_row = { 0 };
			rz_vector_remove_at(rows, i--, &del_row);
			// free the deleted row
			table_row_fini(&del_row);
			break;
		}
	}
}

static int table_resolve_operation(const char *op) {
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

typedef struct col_source {
	size_t prev_index;
	bool dup;
} col_source_t;

/**
 * \brief Select specific columns in RzTable
 *
 * \param  t          The RzTable to use
 * \param  col_names  pointer to RzList containing column names
 */
RZ_API void rz_table_columns_select(RZ_NONNULL RzTable *t, RZ_NONNULL RzList /*<char *>*/ *col_names) {
	rz_return_if_fail(t && col_names);

	// 1 bool per OLD column to indicate whether it should be freed (masked out)
	bool *free_cols = RZ_NEWS0(bool, rz_vector_len(t->cols));
	if (!free_cols) {
		return;
	}

	for (size_t i = 0; i < rz_vector_len(t->cols); i++) {
		free_cols[i] = true;
	}

	// 1 value per NEW column to indicate from which OLD column to take the info from and whether to dup it
	col_source_t *col_sources = RZ_NEWS0(col_source_t, rz_list_length(col_names));
	if (!col_sources) {
		free(free_cols);
		return;
	}

	// First create the plan which new columns to take from which old, which ones to dup or free.
	RzListIter *it;
	const char *col_name;
	size_t new_count = 0;
	rz_list_foreach (col_names, it, col_name) {
		size_t index = 0;
		if (!table_index_of_column(t, col_name, &index)) {
			continue;
		}
		col_sources[new_count].prev_index = index;
		col_sources[new_count].dup = !free_cols[index]; // if we already used the same old column for another new column before, we must dup it for all following!
		free_cols[index] = false;
		new_count++;
	}

	RzTableRow *row;
	rz_vector_foreach (t->rows, row) {
		RzPVector *old_items = row->items;
		RzPVector *new_items = rz_pvector_new(free);

		for (size_t i = 0; i < new_count; i++) {
			char *item = rz_pvector_at(old_items, col_sources[i].prev_index);
			if (!item) {
				continue;
			}
			if (col_sources[i].dup) {
				item = rz_str_dup(item);
			}
			rz_pvector_push(new_items, item);
		}
		row->items = new_items;

		// Free dropped items
		void **item;
		size_t i = 0;
		rz_pvector_enumerate (old_items, item, i) {
			if (free_cols[i]) {
				free(*item);
			}
		}
		// Set old_items->free = NULL to avoid useful items are freed
		old_items->v.free = NULL;
		rz_pvector_free(old_items);
	}

	RzVector *old_cols = t->cols;
	RzVector *new_cols = rz_vector_new(sizeof(RzTableColumn), table_column_fini_wrapper, NULL);
	for (size_t i = 0; i < new_count; i++) {
		RzTableColumn *col = rz_vector_index_ptr(old_cols, col_sources[i].prev_index);
		if (!col) {
			continue;
		}
		if (!col_sources[i].dup) {
			rz_vector_push(new_cols, col);
			continue;
		}

		RzTableColumn copy;
		memcpy(&copy, col, sizeof(RzTableColumn));
		copy.name = rz_str_dup(col->name);
		rz_vector_push(new_cols, &copy);
	}
	t->cols = new_cols;

	// Free dropped columns
	RzTableColumn *col;
	size_t i = 0;
	rz_vector_enumerate (old_cols, col, i) {
		if (free_cols[i]) {
			table_column_fini(col);
		}
	}
	// Set old_cols->free = NULL to avoid useful columns are freed
	old_cols->free = NULL;
	rz_vector_free(old_cols);

	free(col_sources);
	free(free_cols);
}

static bool set_table_format(RzTable *t, const char *q) {
	// CSV and JSON modes are mutually exclusive
	if (!strcmp(q, "quiet")) {
		t->showHeader = false;
		t->showFancy = false;
	} else if (!strcmp(q, "fancy")) {
		t->showFancy = true;
	} else if (!strcmp(q, "simple")) {
		t->showFancy = false;
	} else if (!strcmp(q, "csv")) {
		t->showCSV = true;
		t->showJSON = false;
	} else if (!strcmp(q, "json")) {
		t->showJSON = true;
		t->showCSV = false;
	} else {
		return false;
	}
	return true;
}

/**
 * \brief Applies a given table query syntax to an RzTable (some values may be lost based on the query)
 *
 * \param  t   The RzTable to use
 * \param  q   Query syntax to apply
 */
RZ_API bool rz_table_query(RZ_NONNULL RzTable *t, RZ_NULLABLE const char *q) {
	rz_return_val_if_fail(t, false);
	if (q) {
		q = rz_str_trim_head_ro(q);
	}
	// TODO support parenthesis and (or)||
	// split by "&&" (or comma) -> run .filter on each
	// addr/gt/200,addr/lt/400,addr/sort/dec,offset/sort/rev
	if (RZ_STR_ISEMPTY(q)) {
		table_adjust(t);
		return true;
	}
	if (*q == '?') {
		eprintf("RzTableQuery> comma separated. 'c' stands for column name.\n");
		eprintf(" c/sort/rev        sort rows by given colname\n");
		eprintf(" c/sortlen/rev     sort rows by strlen()\n");
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
	char *qq = rz_str_dup(q);
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
			RZ_LOG_ERROR("table: Column name is NULL for (%s)\n", query);
			rz_list_free(q);
			continue;
		}
		const char *operation = rz_list_get_n(q, 1);
		const char *operand = rz_list_get_n(q, 2);

		size_t col = 0;
		if (!table_index_of_column(t, columnName, &col)) {
			if (*columnName == '[') {
				int signed_col = atoi(columnName + 1);
				if (signed_col >= 0) {
					col = signed_col;
				}
			}
		}
		if (!operation) {
			RzList *list = rz_list_new();
			if (list) {
				rz_list_append(list, rz_str_dup(columnName));
				rz_table_columns_select(t, list);
				rz_list_free(list);
			}
		} else if (!strcmp(operation, "sort")) {
			rz_table_sort(t, col, operand && RZ_STR_EQ(operand, "rev"));
		} else if (!strcmp(operation, "uniq")) {
			rz_table_group(t, col, NULL);
		} else if (!strcmp(operation, "sortlen")) {
			rz_table_sortlen(t, col, operand && RZ_STR_EQ(operand, "rev"));
		} else if (!strcmp(operation, "join")) {
			// TODO: implement join operation with other command's tables
		} else if (!strcmp(operation, "sum")) {
			char *op = rz_str_dup(operand ? operand : "");
			RzList *list = rz_str_split_list(op, "/", 0);
			rz_list_prepend(list, rz_str_dup(columnName));
			rz_table_columns_select(t, list); // select/reorder columns
			rz_list_free(list);
			table_filter(t, 0, '+', op);
			free(op);
		} else if (!strcmp(operation, "strlen")) {
			if (operand) {
				table_filter(t, col, 's', operand);
			}
		} else if (!strcmp(operation, "minlen")) {
			if (operand) {
				table_filter(t, col, 'l', operand);
			}
		} else if (!strcmp(operation, "maxlen")) {
			if (operand) {
				table_filter(t, col, 'L', operand);
			}
		} else if (!strcmp(operation, "page")) {
			if (operand) {
				table_filter(t, col, 'p', operand);
			}
		} else if (!strcmp(operation, "tail")) {
			if (operand) {
				table_filter(t, col, 't', operand);
			}
		} else if (!strcmp(operation, "head")) {
			if (operand) {
				table_filter(t, col, 'h', operand);
			}
		} else if (!strcmp(operation, "str")) {
			if (operand) {
				table_filter(t, col, '~', operand);
			}
		} else if (!strcmp(operation, "cols")) {
			char *op = rz_str_dup(operand ? operand : "");
			RzList *list = rz_str_split_list(op, "/", 0);
			rz_list_prepend(list, rz_str_dup(columnName));
			rz_table_columns_select(t, list); // select/reorder columns
			rz_list_free(list);
			free(op);
		} else {
			int op = table_resolve_operation(operation);
			if (op == -1) {
				RZ_LOG_ERROR("table: Invalid operation (%s)\n", operation);
			} else {
				table_filter(t, col, op, operand);
			}
		}
		rz_list_free(q);
	}
	rz_list_free(queries);
	free(qq);
	table_adjust(t);
	return true;
}

/**
 * \brief      Sets the a given column alignment
 *
 * \param      t      The RzTable to use
 * \param[in]  nth    The nth column to set the alignment to.
 * \param[in]  align  The column alignment to use
 *
 * \return     On success returns true, othewise false
 */
RZ_API bool rz_table_align(RZ_NONNULL RzTable *t, size_t nth, RzTableAlign align) {
	rz_return_val_if_fail(t && align < RZ_TABLE_ALIGN_ENUM_MAX, false);

	if (nth >= rz_vector_len(t->cols)) {
		return false;
	}

	RzTableColumn *col = rz_vector_index_ptr(t->cols, nth);
	if (col) {
		col->align = align;
		return true;
	}
	return false;
}

/**
 * \brief      Sets/unsets if the header should be part of the table or not
 *
 * \param      t            The RzTable to use
 * \param[in]  show_header  The boolean to set
 */
RZ_API void rz_table_show_header(RZ_NONNULL RzTable *t, bool show_header) {
	rz_return_if_fail(t);

	t->showHeader = show_header;
}

/**
 * \brief      Sets the charset mode to use (ascii, utf8 or utf8 curvy)
 *
 * \param      t     The RzTable to use
 * \param[in]  mode  The mode to set
 */
RZ_API void rz_table_set_char_mode(RZ_NONNULL RzTable *t, RzTableCharMode mode) {
	rz_return_if_fail(t);

	t->char_mode = mode;
}

/**
 * \brief      Sets the color callback, called by rz_table_tofancystring and rz_table_tosimplestring
 *
 * \param      t         The RzTable to use
 * \param[in]  color_cb  The color cb to set/unset
 * \param      user      The user context to pass to the callback
 */
RZ_API void rz_table_set_color_selector(RZ_NONNULL RzTable *t, RZ_NULLABLE RzTableColorSelector color_cb, void *user) {
	rz_return_if_fail(t);

	t->color = color_cb;
	t->color_user = user;
}

/**
 * \brief Generates the transpose of RzTable.
 *
 * /param t Referenced \p RzTable
 * /return t Referenced \p RzTable
 *
 * This function returns the transpose of the RzTable passed to the table.
 */
RZ_API RZ_OWN RzTable *rz_table_transpose(RZ_NONNULL RzTable *t) {
	rz_return_val_if_fail(t, NULL);
	RzListIter *iter;
	RzList *row_name = rz_list_new();
	RzTable *transpose = rz_table_new();
	RzTableColumn *col;
	RzTableRow *row;
	void **pitem;
	char *item;
	ut32 i;

	// getting table column names to add to row head
	table_add_column(transpose, RZ_TABLE_COLUMN_TYPE_STRING, cmp_string, "Name");

	// adding rows to transpose table rows * (number of columns in the table)
	for (i = 0; i < rz_vector_len(t->rows); i++) {
		char name[20];
		if (rz_vector_len(t->rows) == 1) {
			table_add_column(transpose, RZ_TABLE_COLUMN_TYPE_STRING, cmp_string, "Value");
		} else {
			table_add_column(transpose, RZ_TABLE_COLUMN_TYPE_STRING, cmp_string, rz_strf(name, "Value%d", i + 1));
		}
	}

	// column names to row heads
	rz_vector_foreach (t->cols, col) {
		rz_list_append(row_name, col->name);
	}

	// adding rows with name alone
	if (row_name && t->rows) {
		iter = row_name->head;
		if (iter) {
			item = rz_list_val(iter);
			for (i = 0; i < t->totalCols; i++) {
				rz_table_add_row(transpose, item, NULL);
				if (rz_list_has_next(iter)) {
					iter = rz_list_next(iter);
					item = rz_list_val(iter);
				}
			}
		}
	}

	if (transpose->rows) {
		rz_vector_foreach (t->rows, row) {
			if (!row) {
				RZ_LOG_WARN("Invalid row while doing transpose.\n");
				continue;
			}
			i = 0;
			rz_pvector_foreach (row->items, pitem) {
				item = *pitem;
				RzTableRow *tr_row = rz_vector_index_ptr(transpose->rows, i++);
				RzPVector *tr_items = tr_row->items;
				rz_pvector_push(tr_items, rz_str_dup(item));
			}
		}
	}

	rz_list_free(row_name);
	return transpose;
}
