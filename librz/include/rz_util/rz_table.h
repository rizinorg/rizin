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
	// TODO: use RzVector
	RzList *items;
} RzTableRow;

typedef struct {
	RzList *rows;
	RzList *cols;
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

RZ_API void rz_table_row_free(void *_row);
RZ_API void rz_table_column_free(void *_col);
RZ_API RzTableColumn *rz_table_column_clone(RzTableColumn *col);
RZ_API RzTableColumnType *rz_table_type(const char *name);
RZ_API RzTable *rz_table_new(void);
RZ_API void rz_table_free(RzTable *t);
RZ_API int rz_table_column_nth(RzTable *t, const char *name);
RZ_API void rz_table_add_column(RzTable *t, RzTableColumnType *type, const char *name, int maxWidth);
RZ_API void rz_table_set_columnsf(RzTable *t, const char *fmt, ...);
RZ_API void rz_table_set_vcolumnsf(RzTable *t, const char *fmt, va_list ap);
RZ_API RzTableRow *rz_table_row_new(RzList *items);
RZ_API void rz_table_add_row(RzTable *t, const char *name, ...);
RZ_API void rz_table_add_rowf(RzTable *t, const char *fmt, ...);
RZ_API void rz_table_add_row_columnsf(RzTable *t, const char *fmt, ...);
RZ_API void rz_table_add_row_list(RzTable *t, RzList *items);
RZ_API char *rz_table_tofancystring(RzTable *t);
RZ_API char *rz_table_tosimplestring(RzTable *t);
RZ_API char *rz_table_tostring(RzTable *t);
RZ_API char *rz_table_tocsv(RzTable *t);
RZ_API char *rz_table_tojson(RzTable *t);
RZ_API void rz_table_filter(RzTable *t, int nth, int op, const char *un);
RZ_API void rz_table_sort(RzTable *t, int nth, bool inc);
RZ_API void rz_table_uniq(RzTable *t);
RZ_API void rz_table_group(RzTable *t, int nth, RzTableSelector fcn);
RZ_API bool rz_table_query(RzTable *t, const char *q);
RZ_API void rz_table_hide_header(RzTable *t);
RZ_API bool rz_table_align(RzTable *t, int nth, int align);
RZ_API void rz_table_visual_list(RzTable *table, RzList *list, ut64 seek, ut64 len, int width, bool va);
RZ_API RzTable *rz_table_clone(RzTable *t);
RZ_API RzTable *rz_table_push(RzTable *t);
RZ_API RzTable *rz_table_pop(RzTable *t);
RZ_API void rz_table_fromjson(RzTable *t, const char *csv);
RZ_API void rz_table_fromcsv(RzTable *t, const char *csv);
RZ_API char *rz_table_tohtml(RzTable *t);
RZ_API RzTable *rz_table_transpose(RzTable *t);
RZ_API void rz_table_format(RzTable *t, int nth, RzTableColumnType *type);
RZ_API ut64 rz_table_reduce(RzTable *t, int nth);
RZ_API void rz_table_columns(RzTable *t, RzList *cols); // const char *name, ...);
#ifdef __cplusplus
}
#endif

#endif
