// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_CONSTANT_POOL_H
#define RZ_BIN_JAVA_CLASS_CONSTANT_POOL_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

typedef enum {
	CONSTANT_POOL_ZERO /*               */ = 0,
	CONSTANT_POOL_UTF8 /*               */ = 1,
	CONSTANT_POOL_UNICODE /*            */ = 2,
	CONSTANT_POOL_INTEGER /*            */ = 3,
	CONSTANT_POOL_FLOAT /*              */ = 4,
	CONSTANT_POOL_LONG /*               */ = 5,
	CONSTANT_POOL_DOUBLE /*             */ = 6,
	CONSTANT_POOL_CLASS /*              */ = 7,
	CONSTANT_POOL_STRING /*             */ = 8,
	CONSTANT_POOL_FIELDREF /*           */ = 9,
	CONSTANT_POOL_METHODREF /*          */ = 10,
	CONSTANT_POOL_INTERFACEMETHODREF /* */ = 11,
	CONSTANT_POOL_NAMEANDTYPE /*        */ = 12,
	CONSTANT_POOL_METHODHANDLE /*       */ = 15,
	CONSTANT_POOL_METHODTYPE /*         */ = 16,
	CONSTANT_POOL_DYNAMIC /*            */ = 17,
	CONSTANT_POOL_INVOKEDYNAMIC /*      */ = 18,
	CONSTANT_POOL_MODULE /*             */ = 19,
	CONSTANT_POOL_PACKAGE /*            */ = 20,
} ConstPoolTag;

typedef struct java_constant_pool_t {
	ut64 offset;
	ut8 tag;
	ut32 size;
	ut8 *buffer;
} ConstPool;

ConstPool *java_constant_null_new(ut64 offset);
ConstPool *java_constant_pool_new(RzBuffer *buf, ut64 offset);
void java_constant_pool_free(ConstPool *cpool);
const char *java_constant_pool_tag_name(const ConstPool *cpool);
bool java_constant_pool_is_string(const ConstPool *cpool);
bool java_constant_pool_is_number(const ConstPool *cpool);
bool java_constant_pool_is_import(const ConstPool *cpool);
bool java_constant_pool_requires_null(const ConstPool *cpool);
char *java_constant_pool_stringify(const ConstPool *cpool);
ut32 java_constant_pool_resolve(const ConstPool *cpool, ut16 *arg0, ut16 *arg1);

#endif /* RZ_BIN_JAVA_CLASS_CONSTANT_POOL_H */
