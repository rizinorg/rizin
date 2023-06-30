// SPDX-FileCopyrightText: 2019 Francesco Tamagni <mrmacete@protonmail.ch>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_CF_DICT_H
#define RZ_CF_DICT_H

#define RZ_CF_OPTION_NONE          0
#define RZ_CF_OPTION_SKIP_NSDATA   1
#define RZ_CF_OPTION_SUPPORT_IDREF 2

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
} RzCFValueType;

typedef struct rz_cf_Value {
	RzCFValueType type;
} RzCFValue;

typedef struct rz_cf_KeyValue {
	char *key;
	RzCFValue *value;
} RzCFKeyValue;

typedef struct rz_cf_value_dict {
	RzCFValueType type;
	RzList /*<RzCFKeyValue *>*/ *pairs;
} RzCFValueDict;

typedef struct rz_cf_value_array {
	RzCFValueType type;
	RzList /*<RzCFValue *>*/ *values;
} RzCFValueArray;

typedef struct rz_cf_value_string {
	RzCFValueType type;
	char *value;
} RzCFValueString;

typedef struct rz_cf_value_integer {
	RzCFValueType type;
	ut64 value;
} RzCFValueInteger;

typedef struct rz_cf_value_data {
	RzCFValueType type;
	RzBuffer *value;
} RzCFValueData;

typedef struct rz_cf_value_bool {
	RzCFValueType type;
} RzCFValueBool;

typedef struct rz_cf_value_null {
	RzCFValueType type;
} RzCFValueNULL;

RZ_API RzCFValueDict *rz_cf_value_dict_parse(RzBuffer *file_buf, ut64 offset, ut64 size, int options);
RZ_API void rz_cf_value_dict_free(RzCFValueDict *dict);
RZ_API void rz_cf_value_print(RzCFValue *value);

#endif
