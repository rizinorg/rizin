#ifndef RZ_UTIL_TABLE_H
#define RZ_UTIL_TABLE_H

#include <rz_util.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	const char *name;
	RzListComparator cmp;
} RTableColumnType;

typedef struct {
	char *name;
	RTableColumnType *type;
	int align; // left, right, center (TODO: unused)
	int width; // computed
	int maxWidth;
	bool forceUppercase;
	int total;
} RTableColumn;

typedef struct {
	char *name;
	RInterval pitv;
	RInterval vitv;
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
} RTableRow;

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
} RTable;

typedef void (*RTableSelector)(RTableRow *acc, RTableRow *new_row, int nth);

RZ_API void rz_table_row_free(void *_row);
RZ_API void rz_table_column_free(void *_col);
RZ_API RTableColumn *rz_table_column_clone(RTableColumn *col);
RZ_API RTableColumnType *rz_table_type(const char *name);
RZ_API RTable *rz_table_new(void);
RZ_API void rz_table_free(RTable *t);
RZ_API int rz_table_column_nth(RTable *t, const char *name);
RZ_API void rz_table_add_column(RTable *t, RTableColumnType *type, const char *name, int maxWidth);
RZ_API void rz_table_set_columnsf(RTable *t, const char *fmt, ...);
RZ_API RTableRow *rz_table_row_new(RzList *items);
RZ_API void rz_table_add_row(RTable *t, const char *name, ...);
RZ_API void rz_table_add_rowf(RTable *t, const char *fmt, ...);
RZ_API void rz_table_add_row_list(RTable *t, RzList *items);
RZ_API char *rz_table_tofancystring(RTable *t);
RZ_API char *rz_table_tosimplestring(RTable *t);
RZ_API char *rz_table_tostring(RTable *t);
RZ_API char *rz_table_tocsv(RTable *t);
RZ_API char *rz_table_tojson(RTable *t);
RZ_API void rz_table_filter(RTable *t, int nth, int op, const char *un);
RZ_API void rz_table_sort(RTable *t, int nth, bool inc);
RZ_API void rz_table_uniq(RTable *t);
RZ_API void rz_table_group(RTable *t, int nth, RTableSelector fcn);
RZ_API bool rz_table_query(RTable *t, const char *q);
RZ_API void rz_table_hide_header(RTable *t);
RZ_API bool rz_table_align(RTable *t, int nth, int align);
RZ_API void rz_table_visual_list(RTable *table, RzList* list, ut64 seek, ut64 len, int width, bool va);
RZ_API RTable *rz_table_clone(RTable *t);
RZ_API RTable *rz_table_push(RTable *t);
RZ_API RTable *rz_table_pop(RTable *t);
RZ_API void rz_table_fromjson(RTable *t, const char *csv);
RZ_API void rz_table_fromcsv(RTable *t, const char *csv);
RZ_API char *rz_table_tohtml(RTable *t);
RZ_API void rz_table_transpose(RTable *t);
RZ_API void rz_table_format(RTable *t, int nth, RTableColumnType *type);
RZ_API ut64 rz_table_reduce(RTable *t, int nth);
RZ_API void rz_table_columns(RTable *t, RzList *cols); // const char *name, ...);

#ifdef __cplusplus
}
#endif

#endif
