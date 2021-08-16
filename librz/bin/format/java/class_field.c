// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "class_field.h"
#include "class_private.h"

#define FIELD_ACCESS_FLAGS_SIZE 16
static const AccessFlagsReadable access_flags_list[FIELD_ACCESS_FLAGS_SIZE] = {
	{ FIELD_ACCESS_FLAG_PUBLIC, "public" },
	{ FIELD_ACCESS_FLAG_PRIVATE, "private" },
	{ FIELD_ACCESS_FLAG_PROTECTED, "protected" },
	{ FIELD_ACCESS_FLAG_STATIC, "static" },
	{ FIELD_ACCESS_FLAG_FINAL, "final" },
	{ FIELD_ACCESS_FLAG_VOLATILE, "volatile" },
	{ FIELD_ACCESS_FLAG_TRANSIENT, "transient" },
	{ FIELD_ACCESS_FLAG_SYNTHETIC, "synthetic" },
	{ FIELD_ACCESS_FLAG_ENUM, "enum" },
};

char *java_field_access_flags_readable(const Field *field) {
	rz_return_val_if_fail(field, NULL);
	RzStrBuf *sb = NULL;

	for (ut32 i = 0; i < FIELD_ACCESS_FLAGS_SIZE; ++i) {
		const AccessFlagsReadable *afr = &access_flags_list[i];
		if (field->access_flags & afr->flag) {
			if (!sb) {
				sb = rz_strbuf_new(afr->readable);
				if (!sb) {
					return NULL;
				}
			} else {
				rz_strbuf_appendf(sb, " %s", afr->readable);
			}
		}
	}

	return sb ? rz_strbuf_drain(sb) : NULL;
}

Field *java_field_new(ConstPool **pool, ut32 poolsize, RzBuffer *buf, ut64 offset) {
	Field *field = RZ_NEW0(Field);
	rz_return_val_if_fail(field, NULL);
	field->offset = offset;
	ut64 base = offset - rz_buf_tell(buf);

	if (!rz_buf_read_be16(buf, &field->access_flags) ||
		!rz_buf_read_be16(buf, &field->name_index) ||
		!rz_buf_read_be16(buf, &field->descriptor_index) ||
		!rz_buf_read_be16(buf, &field->attributes_count)) {
		free(field);
		return NULL;
	}

	if (field->attributes_count < 1) {
		return field;
	}
	field->attributes = RZ_NEWS0(Attribute *, field->attributes_count);
	if (!field->attributes) {
		free(field);
		rz_warn_if_reached();
		return NULL;
	}

	for (ut32 i = 0; i < field->attributes_count; ++i) {
		offset = rz_buf_tell(buf) + base;
		Attribute *attr = java_attribute_new(buf, offset);
		if (attr && java_attribute_resolve(pool, poolsize, attr, buf, false)) {
			field->attributes[i] = attr;
		} else {
			java_attribute_free(attr);
			break;
		}
	}
	return field;
}

void java_field_free(Field *field) {
	if (!field) {
		return;
	}
	if (field->attributes) {
		for (ut32 i = 0; i < field->attributes_count; ++i) {
			java_attribute_free(field->attributes[i]);
		}
		free(field->attributes);
	}
	free(field);
}

bool java_field_is_global(const Field *field) {
	ut16 flag = FIELD_ACCESS_FLAG_PUBLIC | FIELD_ACCESS_FLAG_STATIC | FIELD_ACCESS_FLAG_FINAL;
	return field && (field->access_flags & flag) == flag;
}
