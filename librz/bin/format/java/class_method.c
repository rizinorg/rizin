// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "class_method.h"
#include "class_private.h"

#define METHOD_ACCESS_FLAGS_SIZE 16
static const AccessFlagsReadable access_flags_list[METHOD_ACCESS_FLAGS_SIZE] = {
	{ METHOD_ACCESS_FLAG_PUBLIC, "public" },
	{ METHOD_ACCESS_FLAG_PRIVATE, "private" },
	{ METHOD_ACCESS_FLAG_PROTECTED, "protected" },
	{ METHOD_ACCESS_FLAG_STATIC, "static" },
	{ METHOD_ACCESS_FLAG_FINAL, "final" },
	{ METHOD_ACCESS_FLAG_SYNCHRONIZED, "synchronized" },
	{ METHOD_ACCESS_FLAG_BRIDGE, "bridge" },
	{ METHOD_ACCESS_FLAG_VARARGS, "varargs" },
	{ METHOD_ACCESS_FLAG_NATIVE, "native" },
	{ METHOD_ACCESS_FLAG_INTERFACE, "interface" },
	{ METHOD_ACCESS_FLAG_ABSTRACT, "abstract" },
	{ METHOD_ACCESS_FLAG_STRICT, "strict" },
	{ METHOD_ACCESS_FLAG_SYNTHETIC, "synthetic" },
	{ METHOD_ACCESS_FLAG_ANNOTATION, "annotation" },
	{ METHOD_ACCESS_FLAG_ENUM, "enum" },
};

char *java_method_access_flags_readable(const Method *method) {
	rz_return_val_if_fail(method, NULL);
	RzStrBuf *sb = NULL;

	for (ut32 i = 0; i < METHOD_ACCESS_FLAGS_SIZE; ++i) {
		const AccessFlagsReadable *afr = &access_flags_list[i];
		if (method->access_flags & afr->flag) {
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

static bool java_method_new_aux(RzBuffer *buf, Method *method) {
	return rz_buf_read_be16(buf, &method->access_flags) &&
		rz_buf_read_be16(buf, &method->name_index) &&
		rz_buf_read_be16(buf, &method->descriptor_index) &&
		rz_buf_read_be16(buf, &method->attributes_count);
}

Method *java_method_new(ConstPool **pool, ut32 poolsize, RzBuffer *buf, ut64 offset, bool is_oak) {
	Method *method = RZ_NEW0(Method);
	rz_return_val_if_fail(method, NULL);
	method->offset = offset;
	ut64 base = offset - rz_buf_tell(buf);

	if (!java_method_new_aux(buf, method)) {
		goto err;
	}

	if (method->attributes_count < 1) {
		return method;
	}
	if (method->attributes_count * 6 + rz_buf_tell(buf) >= rz_buf_size(buf)) {
		goto err;
	}

	method->attributes = RZ_NEWS0(Attribute *, method->attributes_count);
	if (!method->attributes) {
		rz_warn_if_reached();
		goto err;
	}

	for (ut32 i = 0; i < method->attributes_count; ++i) {
		offset = rz_buf_tell(buf) + base;
		Attribute *attr = java_attribute_new(buf, offset);
		if (attr && java_attribute_resolve(pool, poolsize, attr, buf, is_oak)) {
			method->attributes[i] = attr;
		} else {
			java_attribute_free(attr);
			break;
		}
	}
	return method;
err:
	free(method);
	return NULL;
}

void java_method_free(Method *method) {
	if (!method) {
		return;
	}
	if (method->attributes) {
		for (ut32 i = 0; i < method->attributes_count; ++i) {
			java_attribute_free(method->attributes[i]);
		}
		free(method->attributes);
	}
	free(method);
}

bool java_method_is_global(const Method *method) {
	ut16 flag = METHOD_ACCESS_FLAG_PUBLIC | METHOD_ACCESS_FLAG_STATIC | METHOD_ACCESS_FLAG_FINAL;
	return method && (method->access_flags & flag) == flag;
}
