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
	char *name;
	RzTableColumnType type;
	RzTableColumnTypeComparator type_cmp;
	int align; // left, right, center
	int width; // computed
	int maxWidth;
	bool forceUppercase;
	int total;
} RzTableColumn;

typedef struct {
	RzPVector /*<char *>*/ *items;
} RzTableRow;

typedef void (*RzTableSelector)(RzTableRow *acc, RzTableRow *new_row, size_t nth);

typedef struct {
	RzVector /*<RzTableRow>*/ *rows;
	RzVector /*<RzTableColumn>*/ *cols;
	size_t totalCols;
	bool showHeader;
	bool showFancy;
	bool showJSON;
	bool showCSV;
	bool showSum;
	bool adjustedCols;
	void *cons;
} RzTable;

typedef struct {
	char *name;
	RzInterval pitv;
	RzInterval vitv;
	int perm;
	char *extra;
} RzListInfo;

RZ_API RzListInfo *rz_listinfo_new(const char *name, RzInterval pitv, RzInterval vitv, int perm, const char *extra);
RZ_API void rz_listinfo_free(RzListInfo *info);
RZ_API void rz_table_visual_list(RzTable *table, RzList /*<RzListInfo *>*/ *list, ut64 seek, ut64 len, int width, bool va);

RZ_API RZ_OWN RzTable *rz_table_new(void);
RZ_API void rz_table_free(RZ_NULLABLE RzTable *t);
RZ_API void rz_table_add_column(RZ_NONNULL RzTable *t, const RzTableColumnType type, RZ_NONNULL const char *name, size_t max_width);
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
RZ_API void rz_table_filter(RZ_NONNULL RzTable *t, size_t nth, int op, RZ_NONNULL const char *un);
RZ_API void rz_table_sort(RZ_NONNULL RzTable *t, size_t nth, bool reverse);
RZ_API void rz_table_sortlen(RZ_NONNULL RzTable *t, size_t nth, bool reverse);
RZ_API void rz_table_uniq(RZ_NONNULL RzTable *t);
RZ_API void rz_table_group(RZ_NONNULL RzTable *t, size_t nth, RZ_NULLABLE RzTableSelector selector);
RZ_API bool rz_table_query(RZ_NONNULL RzTable *t, RZ_NULLABLE const char *q);
RZ_API void rz_table_show_header(RZ_NONNULL RzTable *t, bool show_header);
RZ_API bool rz_table_align(RZ_NONNULL RzTable *t, size_t nth, RzTableAlign align);

RZ_API RZ_OWN RzTable *rz_table_transpose(RZ_NONNULL RzTable *t);
RZ_API void rz_table_columns(RZ_NONNULL RzTable *t, RZ_NONNULL RzList /*<char *>*/ *cols);

#ifdef __cplusplus
}
#endif

#endif
