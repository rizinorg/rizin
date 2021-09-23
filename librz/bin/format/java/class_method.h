// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_METHOD_H
#define RZ_BIN_JAVA_CLASS_METHOD_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>
#include "class_attribute.h"

typedef enum {
	METHOD_ACCESS_FLAG_PUBLIC /*      */ = 0x0001,
	METHOD_ACCESS_FLAG_PRIVATE /*     */ = 0x0002,
	METHOD_ACCESS_FLAG_PROTECTED /*   */ = 0x0004,
	METHOD_ACCESS_FLAG_STATIC /*      */ = 0x0008,
	METHOD_ACCESS_FLAG_FINAL /*       */ = 0x0010,
	METHOD_ACCESS_FLAG_SYNCHRONIZED /**/ = 0x0020,
	METHOD_ACCESS_FLAG_BRIDGE /*      */ = 0x0040,
	METHOD_ACCESS_FLAG_VARARGS /*     */ = 0x0080,
	METHOD_ACCESS_FLAG_NATIVE /*      */ = 0x0100,
	METHOD_ACCESS_FLAG_INTERFACE /*   */ = 0x0200,
	METHOD_ACCESS_FLAG_ABSTRACT /*    */ = 0x0400,
	METHOD_ACCESS_FLAG_STRICT /*      */ = 0x0800,
	METHOD_ACCESS_FLAG_SYNTHETIC /*   */ = 0x1000,
	METHOD_ACCESS_FLAG_ANNOTATION /*  */ = 0x2000,
	METHOD_ACCESS_FLAG_ENUM /*        */ = 0x4000
} MethodAccessFlag;

typedef struct java_method_t {
	ut64 offset;
	ut16 access_flags;
	ut16 name_index;
	ut16 descriptor_index;
	ut16 attributes_count;
	Attribute **attributes;
} Method;

Method *java_method_new(ConstPool **pool, ut32 poolsize, RzBuffer *buf, ut64 offset, bool is_oak);
void java_method_free(Method *method);
char *java_method_access_flags_readable(const Method *method);
bool java_method_is_global(const Method *method);

#endif /* RZ_BIN_JAVA_CLASS_METHOD_H */
