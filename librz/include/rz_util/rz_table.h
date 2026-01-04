#ifndef RZ_UTIL_TABLE_H
#define RZ_UTIL_TABLE_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	RZ_TABLE_ALIGN_LEFT = 0,
	RZ_TABLE_ALIGN_RIGHT,
	RZ_TABLE_ALIGN_CENTER,
	// size
	RZ_TABLE_ALIGN_ENUM_MAX,
} RzTableAlign;

typedef enum {
	RZ_TABLE_COLUMN_TYPE_STRING = 0,
	RZ_TABLE_COLUMN_TYPE_NUMBER,
	RZ_TABLE_COLUMN_TYPE_BOOL,
	// size
	RZ_TABLE_COLUMN_TYPE_ENUM_MAX,
} RzTableColumnType;

typedef int (*RzTableColumnTypeComparator)(const void *a, const void *b);

typedef struct {
	char *name; ///< Column name
	RzTableColumnType type; ///< Inferred type of the data
	RzTableColumnTypeComparator type_cmp; ///< Column comparator used for sorting
	RzTableAlign align; ///< Column alignment left, right, center
	int width; ///< Computed column width
	int total; ///< Sum of the rows associated to this column.
} RzTableColumn;

typedef struct {
	RzPVector /*<char *>*/ *items;
} RzTableRow;

typedef void (*RzTableSelector)(RzTableRow *acc, RzTableRow *new_row, size_t nth);
typedef const char *(*RzTableColorSelector)(const char *value, const char *column, const size_t column_n, const RzTableColumnType type, void *user);

typedef enum {
	RZ_TABLE_CHAR_MODE_ASCII = 0,
	RZ_TABLE_CHAR_MODE_UTF8,
	RZ_TABLE_CHAR_MODE_UTF8_CURVY,
	// size
	RZ_TABLE_CHAR_MODE_ENUM_MAX,
} RzTableCharMode;

typedef struct {
	RzVector /*<RzTableRow>*/ *rows; ///< Rows data
	RzVector /*<RzTableColumn>*/ *cols; ///< Columns data
	size_t totalCols; ///< Total number of columns
	bool showHeader; ///< When true, upon call of rz_table_tostring, it will show the header
	bool showFancy; ///< When true, upon call of rz_table_tostring, it will use the fancy table output
	bool showJSON; ///< When true, upon call of rz_table_tostring, it will return a json structure
	bool showCSV; ///< When true, upon call of rz_table_tostring, it will return a csv structure
	bool showSum; ///< When true, upon call of rz_table_tostring, it will show the toal sum of each row
	RzTableCharMode char_mode; ///< Sets the charset type used for the string output
	RzTableColorSelector color; ///< It is used to retrieve a color palette to use in each column data.
	void *color_user; ///< Additional data that is passed via RzTableColorSelector()
} RzTable;

RZ_API RZ_OWN RzTable *rz_table_new(void);
RZ_API void rz_table_free(RZ_NULLABLE RzTable *t);
RZ_API void rz_table_add_column(RZ_NONNULL RzTable *t, const RzTableColumnType type, RZ_NONNULL const char *name);
RZ_API void rz_table_set_columnsf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, ...);
RZ_API void rz_table_set_vcolumnsf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, va_list ap);
RZ_API void rz_table_add_row(RZ_NONNULL RzTable *t, RZ_NONNULL const char *name, ...);
RZ_API void rz_table_add_vrowf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, va_list ap);
RZ_API void rz_table_add_rowf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, ...);
RZ_API void rz_table_add_row_columnsf(RZ_NONNULL RzTable *t, RZ_NONNULL const char *fmt, ...);
RZ_API void rz_table_add_row_vec(RZ_NONNULL RzTable *t, RZ_NONNULL RZ_OWN RzPVector /*<char *>*/ *items);
RZ_API RZ_OWN char *rz_table_tofancystring(RZ_NONNULL RzTable *t);
RZ_API RZ_OWN char *rz_table_tosimplestring(RZ_NONNULL RzTable *t);
RZ_API RZ_OWN char *rz_table_tostring(RZ_NONNULL RzTable *t);
RZ_API RZ_OWN char *rz_table_tocsv(RZ_NONNULL RzTable *t);
RZ_API RZ_OWN char *rz_table_tojson(RZ_NONNULL RzTable *t);
RZ_API void rz_table_sort(RZ_NONNULL RzTable *t, size_t nth, bool reverse);
RZ_API void rz_table_sortlen(RZ_NONNULL RzTable *t, size_t nth, bool reverse);
RZ_API void rz_table_uniq(RZ_NONNULL RzTable *t);
RZ_API void rz_table_group(RZ_NONNULL RzTable *t, size_t nth, RZ_NULLABLE RzTableSelector selector);
RZ_API bool rz_table_query(RZ_NONNULL RzTable *t, RZ_NULLABLE const char *q);
RZ_API bool rz_table_align(RZ_NONNULL RzTable *t, size_t nth, RzTableAlign align);
RZ_API RZ_OWN RzTable *rz_table_transpose(RZ_NONNULL RzTable *t);
RZ_API void rz_table_columns_select(RZ_NONNULL RzTable *t, RZ_NONNULL RzList /*<char *>*/ *col_names);
RZ_API void rz_table_show_header(RZ_NONNULL RzTable *t, bool show_header);
RZ_API void rz_table_set_char_mode(RZ_NONNULL RzTable *t, RzTableCharMode mode);
RZ_API void rz_table_set_color_selector(RZ_NONNULL RzTable *t, RZ_NULLABLE RzTableColorSelector color_cb, void *user);

#ifdef __cplusplus
}
#endif

#endif
