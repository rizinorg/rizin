#ifndef RZ_UTIL_TABLE_H
#define RZ_UTIL_TABLE_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *name;
	RzListComparator cmp;
} RzTableColumnType;

typedef struct {
	char *name;
	RzTableColumnType *type;
	int align; // left, right, center (TODO: unused)
	int width; // computed
	int maxWidth;
	bool forceUppercase;
	int total;
} RzTableColumn;

typedef struct {
	char *name;
	RzInterval pitv;
	RzInterval vitv;
	int perm;
	char *extra;
} RzListInfo;

enum {
	RZ_TABLE_ALIGN_LEFT,
	RZ_TABLE_ALIGN_RIGHT,
	RZ_TABLE_ALIGN_CENTER
};

typedef struct {
	RzPVector /*<char *>*/ *items;
} RzTableRow;

typedef struct {
	RzVector /*<RzTableRow>*/ *rows;
	RzVector /*<RzTableColumn>*/ *cols;
	int totalCols;
	bool showHeader;
	bool showFancy;
	bool showJSON;
	bool showCSV;
	bool showSum;
	bool adjustedCols;
	void *cons;
} RzTable;

typedef void (*RzTableSelector)(RzTableRow *acc, RzTableRow *new_row, int nth);

RZ_API RzListInfo *rz_listinfo_new(const char *name, RzInterval pitv, RzInterval vitv, int perm, const char *extra);
RZ_API void rz_listinfo_free(RzListInfo *info);

RZ_API void rz_table_row_fini(RZ_NONNULL void *_row);
RZ_API void rz_table_column_fini(RZ_NONNULL void *_col);
RZ_API RzTableColumn *rz_table_column_clone(RzTableColumn *col);
RZ_API RzTableColumnType *rz_table_type(const char *name);
RZ_API RzTable *rz_table_new(void);
RZ_API void rz_table_free(RzTable *t);
RZ_API int rz_table_column_nth(RzTable *t, const char *name);
RZ_API void rz_table_add_column(RzTable *t, RzTableColumnType *type, const char *name, int maxWidth);
RZ_API void rz_table_set_columnsf(RzTable *t, const char *fmt, ...);
RZ_API void rz_table_set_vcolumnsf(RzTable *t, const char *fmt, va_list ap);
RZ_API RzTableRow *rz_table_row_new(RzPVector /*<char *>*/ *items);
RZ_API void rz_table_add_row(RZ_NONNULL RzTable *t, const char *name, ...);
RZ_API void rz_table_add_vrowf(RZ_NONNULL RzTable *t, const char *fmt, va_list ap);
RZ_API void rz_table_add_rowf(RzTable *t, const char *fmt, ...);
RZ_API void rz_table_add_row_columnsf(RzTable *t, const char *fmt, ...);
RZ_API void rz_table_add_row_vec(RZ_NONNULL RzTable *t, RZ_NONNULL RzPVector /*<char *>*/ *items);
RZ_API RZ_OWN char *rz_table_tofancystring(RZ_NONNULL RzTable *t);
RZ_API char *rz_table_tosimplestring(RzTable *t);
RZ_API char *rz_table_tostring(RzTable *t);
RZ_API char *rz_table_tocsv(RzTable *t);
RZ_API RZ_OWN char *rz_table_tojson(RzTable *t);
RZ_API void rz_table_filter(RzTable *t, int nth, int op, const char *un);
RZ_API void rz_table_sort(RzTable *t, int nth, bool inc);
RZ_API void rz_table_uniq(RzTable *t);
RZ_API void rz_table_group(RzTable *t, int nth, RzTableSelector fcn);
RZ_API bool rz_table_query(RzTable *t, const char *q);
RZ_API void rz_table_hide_header(RzTable *t);
RZ_API bool rz_table_align(RzTable *t, int nth, int align);
RZ_API void rz_table_visual_list(RzTable *table, RzList /*<RzListInfo *>*/ *list, ut64 seek, ut64 len, int width, bool va);
RZ_API RZ_OWN RzTable *rz_table_transpose(RZ_NONNULL RzTable *t);
RZ_API void rz_table_columns(RzTable *t, RzList /*<char *>*/ *cols); // const char *name, ...);
#ifdef __cplusplus
}
#endif

#endif
