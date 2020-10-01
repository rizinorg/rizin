#ifndef R_CF_DICT_H
#define R_CF_DICT_H

#define R_CF_OPTION_NONE 0
#define R_CF_OPTION_SKIP_NSDATA 1

typedef enum {
	R_CF_INVALID,
	R_CF_DICT,
	R_CF_ARRAY,
	R_CF_STRING,
	R_CF_INTEGER,
	R_CF_DATA,
	R_CF_NULL,
	R_CF_TRUE,
	R_CF_FALSE
} RCFValueType;

typedef struct _CFValue {
	RCFValueType type;
} RCFValue;

typedef struct _CFKeyValue {
	char * key;
	RCFValue * value;
} RCFKeyValue;

typedef struct _CFValueDict {
	RCFValueType type;
	RzList * pairs; //_CFKeyValue
} RCFValueDict;

typedef struct _CFValueArray {
	RCFValueType type;
	RzList * values; //_CFValue
} RCFValueArray;

typedef struct _CFValueString {
	RCFValueType type;
	char * value;
} RCFValueString;

typedef struct _CFValueInteger {
	RCFValueType type;
	ut64 value;
} RCFValueInteger;

typedef struct _CFValueData {
	RCFValueType type;
	RBuffer * value;
} RCFValueData;

typedef struct _CFValueBool {
	RCFValueType type;
} RCFValueBool;

typedef struct _CFValueNULL {
	RCFValueType type;
} RCFValueNULL;

RZ_API RCFValueDict * rz_cf_value_dict_parse(RBuffer * file_buf, ut64 offset, ut64 size, int options);
RZ_API void rz_cf_value_dict_free(RCFValueDict * dict);
RZ_API void rz_cf_value_print(RCFValue * value);

#endif
