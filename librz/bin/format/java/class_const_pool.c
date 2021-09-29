// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "class_const_pool.h"

static ConstPool *constant_pool_copy_from_buffer(RzBuffer *buf, ConstPool *cpool, const st64 size) {
	if (size < 1) {
		return cpool;
	}
	cpool->size = size;
	cpool->buffer = (ut8 *)malloc(size);
	if (!cpool->buffer || rz_buf_read(buf, cpool->buffer, size) != size) {
		free(cpool);
		rz_warn_if_reached();
		return NULL;
	}
	return cpool;
}

ConstPool *java_constant_null_new(ut64 offset) {
	ConstPool *cpool = RZ_NEW0(ConstPool);
	rz_return_val_if_fail(cpool, NULL);
	cpool->offset = offset;
	return cpool;
}

ConstPool *java_constant_pool_new(RzBuffer *buf, ut64 offset) {
	ConstPool *cpool = RZ_NEW0(ConstPool);
	rz_return_val_if_fail(cpool, NULL);

	cpool->offset = offset;
	if (!rz_buf_read8(buf, &cpool->tag)) {
		free(cpool);
		return NULL;
	}

	ut16 string_len;

	switch (cpool->tag) {
	case CONSTANT_POOL_ZERO:
		return cpool;
	case CONSTANT_POOL_UTF8:
	case CONSTANT_POOL_UNICODE:
		if (!rz_buf_read_be16(buf, &string_len)) {
			free(cpool);
			return NULL;
		}
		return constant_pool_copy_from_buffer(buf, cpool, string_len);
	case CONSTANT_POOL_LONG:
	case CONSTANT_POOL_DOUBLE:
		return constant_pool_copy_from_buffer(buf, cpool, 8);
	case CONSTANT_POOL_INTEGER:
	case CONSTANT_POOL_FLOAT:
	case CONSTANT_POOL_FIELDREF:
	case CONSTANT_POOL_METHODREF:
	case CONSTANT_POOL_INTERFACEMETHODREF:
	case CONSTANT_POOL_NAMEANDTYPE:
	case CONSTANT_POOL_DYNAMIC:
	case CONSTANT_POOL_INVOKEDYNAMIC:
		return constant_pool_copy_from_buffer(buf, cpool, 4);
	case CONSTANT_POOL_METHODHANDLE:
		return constant_pool_copy_from_buffer(buf, cpool, 3);
	case CONSTANT_POOL_METHODTYPE:
	case CONSTANT_POOL_CLASS:
	case CONSTANT_POOL_STRING:
	case CONSTANT_POOL_MODULE:
	case CONSTANT_POOL_PACKAGE:
		return constant_pool_copy_from_buffer(buf, cpool, 2);
	default:
		RZ_LOG_ERROR("java bin: invalid constant pool tag: %u at 0x%" PFMT64x "\n", cpool->tag, offset);
		break;
	}
	rz_buf_seek(buf, offset, SEEK_SET);
	free(cpool);
	return NULL;
}

void java_constant_pool_free(ConstPool *cpool) {
	if (!cpool) {
		return;
	}
	free(cpool->buffer);
	free(cpool);
}

const char *java_constant_pool_tag_name(const ConstPool *cpool) {
	rz_return_val_if_fail(cpool, NULL);
	switch (cpool->tag) {
	case CONSTANT_POOL_ZERO:
		return "Zero";
	case CONSTANT_POOL_UTF8:
		return "Utf8";
	case CONSTANT_POOL_UNICODE:
		return "Unicode";
	case CONSTANT_POOL_INTEGER:
		return "Integer";
	case CONSTANT_POOL_FLOAT:
		return "Float";
	case CONSTANT_POOL_LONG:
		return "Long";
	case CONSTANT_POOL_DOUBLE:
		return "Double";
	case CONSTANT_POOL_CLASS:
		return "Class";
	case CONSTANT_POOL_STRING:
		return "String";
	case CONSTANT_POOL_FIELDREF:
		return "Fieldref";
	case CONSTANT_POOL_METHODREF:
		return "Methodref";
	case CONSTANT_POOL_INTERFACEMETHODREF:
		return "InterfaceMethodref";
	case CONSTANT_POOL_NAMEANDTYPE:
		return "NameAndType";
	case CONSTANT_POOL_METHODHANDLE:
		return "MethodHandle";
	case CONSTANT_POOL_METHODTYPE:
		return "MethodType";
	case CONSTANT_POOL_DYNAMIC:
		return "Dynamic";
	case CONSTANT_POOL_INVOKEDYNAMIC:
		return "InvokeDynamic";
	case CONSTANT_POOL_MODULE:
		return "Module";
	case CONSTANT_POOL_PACKAGE:
		return "Package";
	default:
		return NULL;
	}
}

bool java_constant_pool_is_string(const ConstPool *cpool) {
	rz_return_val_if_fail(cpool, false);
	return cpool->tag == CONSTANT_POOL_UTF8 || cpool->tag == CONSTANT_POOL_UNICODE;
}

bool java_constant_pool_is_number(const ConstPool *cpool) {
	rz_return_val_if_fail(cpool, false);
	return cpool->tag == CONSTANT_POOL_INTEGER ||
		cpool->tag == CONSTANT_POOL_FLOAT ||
		cpool->tag == CONSTANT_POOL_LONG ||
		cpool->tag == CONSTANT_POOL_DOUBLE;
}

bool java_constant_pool_is_import(const ConstPool *cpool) {
	rz_return_val_if_fail(cpool, false);
	return cpool->tag == CONSTANT_POOL_METHODREF ||
		cpool->tag == CONSTANT_POOL_INTERFACEMETHODREF ||
		cpool->tag == CONSTANT_POOL_FIELDREF;
}

bool java_constant_pool_requires_null(const ConstPool *cpool) {
	rz_return_val_if_fail(cpool, false);
	// https://github.com/openjdk/jdk/blob/master/src/jdk.jdeps/share/classes/com/sun/tools/javap/ConstantWriter.java#L73
	// https://github.com/openjdk/jdk/blob/master/src/jdk.jdeps/share/classes/com/sun/tools/javap/ConstantWriter.java#L116
	return cpool->tag == CONSTANT_POOL_DOUBLE || cpool->tag == CONSTANT_POOL_LONG;
}

char *java_constant_pool_stringify(const ConstPool *cpool) {
	rz_return_val_if_fail(cpool, NULL);

	switch (cpool->tag) {
	case CONSTANT_POOL_UTF8:
	case CONSTANT_POOL_UNICODE: {
		if (!cpool->size) {
			return NULL;
		}
		return rz_str_escape_mutf8_for_json((const char *)cpool->buffer, cpool->size);
	}
	case CONSTANT_POOL_LONG: {
		st64 value = rz_read_be64(cpool->buffer);
		return rz_str_newf("0x%" PFMT64x, value);
	}
	case CONSTANT_POOL_DOUBLE: {
		double value = rz_read_be_double(cpool->buffer);
		return rz_str_newf("%.16lgd", value);
	}
	case CONSTANT_POOL_INTEGER: {
		st32 value = rz_read_be32(cpool->buffer);
		return rz_str_newf("0x%" PFMT32x, value);
	}
	case CONSTANT_POOL_FLOAT: {
		float value = rz_read_be_float(cpool->buffer);
		return rz_str_newf("%6gf", value);
	}
	case CONSTANT_POOL_METHODHANDLE: {
		ut16 kind = cpool->buffer[0];
		ut16 index = rz_read_be16(cpool->buffer + 1);
		return rz_str_newf("%u:#%u", kind, index);
	}
	case CONSTANT_POOL_FIELDREF:
	case CONSTANT_POOL_METHODREF:
	case CONSTANT_POOL_INTERFACEMETHODREF:
	case CONSTANT_POOL_NAMEANDTYPE:
	case CONSTANT_POOL_DYNAMIC:
	case CONSTANT_POOL_INVOKEDYNAMIC: {
		ut16 arg0 = rz_read_be16(cpool->buffer);
		ut16 arg1 = rz_read_be16(cpool->buffer + 2);
		return rz_str_newf("#%u:#%u", arg0, arg1);
	}
	case CONSTANT_POOL_METHODTYPE:
	case CONSTANT_POOL_CLASS:
	case CONSTANT_POOL_STRING:
	case CONSTANT_POOL_MODULE:
	case CONSTANT_POOL_PACKAGE: {
		ut16 value = rz_read_be16(cpool->buffer);
		return rz_str_newf("#%u", value);
	}
	default:
		break;
	}
	return NULL;
}

ut32 java_constant_pool_resolve(const ConstPool *cpool, ut16 *arg0, ut16 *arg1) {
	rz_return_val_if_fail(cpool, 0);
	ut16 unused1;
	if (!arg1) {
		arg1 = &unused1;
	}

	switch (cpool->tag) {
	case CONSTANT_POOL_METHODHANDLE: {
		*arg0 = rz_read_be16(cpool->buffer + 1);
		return 1;
	}
	case CONSTANT_POOL_FIELDREF:
	case CONSTANT_POOL_METHODREF:
	case CONSTANT_POOL_INTERFACEMETHODREF:
	case CONSTANT_POOL_NAMEANDTYPE:
	case CONSTANT_POOL_DYNAMIC:
	case CONSTANT_POOL_INVOKEDYNAMIC: {
		*arg0 = rz_read_be16(cpool->buffer);
		*arg1 = rz_read_be16(cpool->buffer + 2);
		return 2;
	}
	case CONSTANT_POOL_METHODTYPE:
	case CONSTANT_POOL_CLASS:
	case CONSTANT_POOL_STRING:
	case CONSTANT_POOL_MODULE:
	case CONSTANT_POOL_PACKAGE: {
		*arg0 = rz_read_be16(cpool->buffer);
		return 1;
	}
	default:
		break;
	}
	return 0;
}
