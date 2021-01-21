#ifndef RZ_CF_DICT_H
#define RZ_CF_DICT_H

#define RZ_CF_OPTION_NONE        0
#define RZ_CF_OPTION_SKIP_NSDATA 1

typedef enum {
	RZ_CF_INVALID,
	RZ_CF_DICT,
	RZ_CF_ARRAY,
	RZ_CF_STRING,
	RZ_CF_INTEGER,
	RZ_CF_DATA,
	RZ_CF_NULL,
	RZ_CF_TRUE,
	RZ_CF_FALSE
} RCFValueType;

typedef struct _CFValue {
	RCFValueType type;
} RCFValue;

typedef struct _CFKeyValue {
	char *key;
	RCFValue *value;
} RCFKeyValue;

typedef struct _CFValueDict {
	RCFValueType type;
	RzList *pairs; //_CFKeyValue
} RCFValueDict;

typedef struct _CFValueArray {
	RCFValueType type;
	RzList *values; //_CFValue
} RCFValueArray;

typedef struct _CFValueString {
	RCFValueType type;
	char *value;
} RCFValueString;

typedef struct _CFValueInteger {
	RCFValueType type;
	ut64 value;
} RCFValueInteger;

typedef struct _CFValueData {
	RCFValueType type;
	RzBuffer *value;
} RCFValueData;

typedef struct _CFValueBool {
	RCFValueType type;
} RCFValueBool;

typedef struct _CFValueNULL {
	RCFValueType type;
} RCFValueNULL;

RZ_API RCFValueDict *rz_cf_value_dict_parse(RzBuffer *file_buf, ut64 offset, ut64 size, int options);
RZ_API void rz_cf_value_dict_free(RCFValueDict *dict);
RZ_API void rz_cf_value_print(RCFValue *value);

#endif
