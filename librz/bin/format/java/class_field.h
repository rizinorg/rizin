// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_BIN_JAVA_CLASS_FIELD_H
#define RZ_BIN_JAVA_CLASS_FIELD_H
#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>
#include "class_attribute.h"

typedef enum {
	FIELD_ACCESS_FLAG_PUBLIC /*   */ = 0x0001,
	FIELD_ACCESS_FLAG_PRIVATE /*  */ = 0x0002,
	FIELD_ACCESS_FLAG_PROTECTED /**/ = 0x0004,
	FIELD_ACCESS_FLAG_STATIC /*   */ = 0x0008,
	FIELD_ACCESS_FLAG_FINAL /*    */ = 0x0010,
	FIELD_ACCESS_FLAG_VOLATILE /* */ = 0x0040,
	FIELD_ACCESS_FLAG_TRANSIENT /**/ = 0x0080,
	FIELD_ACCESS_FLAG_SYNTHETIC /**/ = 0x1000,
	FIELD_ACCESS_FLAG_ENUM /*     */ = 0x4000
} FieldAccessFlag;

typedef struct java_field_t {
	ut64 offset;
	ut16 access_flags;
	ut16 name_index;
	ut16 descriptor_index;
	ut16 attributes_count;
	Attribute **attributes;
} Field;

Field *java_field_new(ConstPool **pool, ut32 poolsize, RzBuffer *buf, ut64 offset);
void java_field_free(Field *field);
char *java_field_access_flags_readable(const Field *field);
bool java_field_is_global(const Field *field);

#endif /* RZ_BIN_JAVA_CLASS_FIELD_H */
