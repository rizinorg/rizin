// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_JSON_H
#define RZ_JSON_H

#include <rz_types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * rz_json is a JSON parsing API,
 * heavily based on nxjson by Yaroslav Stavnichiy <yarosla@gmail.com>,
 * which is available under LGPLv3 or later.
 *
 * rz_json does NOT format json, it only parses. To format json, see pj.h instead.
 * It operates in-place, which means the parsed string will be MODIFIED.
 * This means all string values in RJson point directly into the input string,
 * removing the need to copy them.
 *
 * It also supports both line and block style comments.
 */

typedef enum rz_json_type_t {
	RZ_JSON_NULL,
	RZ_JSON_OBJECT, // properties can be found in child nodes
	RZ_JSON_ARRAY, // items can be found in child nodes
	RZ_JSON_STRING, // value can be found in the str_value field
	RZ_JSON_INTEGER, // value can be found in the num.u_value/num.s_value fields
	RZ_JSON_DOUBLE, // value can be found in the num.dbl_value field
	RZ_JSON_BOOLEAN // value can be found in the num.u_value field
} RJsonType;

typedef struct rz_json_t {
	RJsonType type; // type of json node, see above
	const char *key; // key of the property; for object's children only
	union {
		const char *str_value; // text value of STRING node
		struct {
			union {
				ut64 u_value; // the value of INTEGER or BOOLEAN node
				st64 s_value;
			};
			double dbl_value; // the value of DOUBLE node
		} num;
		struct { // children of OBJECT or ARRAY
			size_t count;
			struct rz_json_t *first;
			struct rz_json_t *last;
		} children;
	};
	struct rz_json_t *next; // points to next child
} RJson;

RZ_API RJson *rz_json_parse(char *text);

RZ_API void rz_json_free(RJson *js);

RZ_API const RJson *rz_json_get(const RJson *json, const char *key); // get object's property by key
RZ_API const RJson *rz_json_item(const RJson *json, size_t idx); // get array element by index

#ifdef __cplusplus
}
#endif

#endif /* NXJSON_H */
