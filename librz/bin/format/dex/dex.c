// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dex.h"
#include <rz_util.h>

#define DEX_INVALID_CLASS  "Lunknown_class;"
#define DEX_INVALID_METHOD "unknown_method"

#define startswith(a, b) (!strncmp(a, b, strlen(b)))

typedef struct dex_access_flags_readable_t {
	ut32 flag;
	const char *readable;
} DexAccessFlagsReadable;

#define read_le_bits_or_fail(bits, buf, val, fail) \
	do { \
		if (!rz_buf_read_le##bits(buf, &val)) { \
			goto fail; \
		} \
	} while (0)

#define read_le_at_bits_or_fail(bits, buf, val, offset, fail) \
	do { \
		if (!rz_buf_read_le##bits##_at(buf, offset, &val)) { \
			goto fail; \
		} \
	} while (0)

#define read_le32_or_fail(buf, val, fail)            read_le_bits_or_fail(32, buf, val, fail)
#define read_le16_or_fail(buf, val, fail)            read_le_bits_or_fail(16, buf, val, fail)
#define read_le32_at_or_fail(buf, val, offset, fail) read_le_at_bits_or_fail(32, buf, val, offset, fail)
#define read_le16_at_or_fail(buf, val, offset, fail) read_le_at_bits_or_fail(16, buf, val, offset, fail)

#define dex_is_static(a)  (a & ACCESS_FLAG_STATIC)
#define dex_is_varargs(a) (a & ACCESS_FLAG_VARARGS)

#define dex_fail_if_bad_ids(name, z, s, g) \
	do { \
		ut64 end = name##_offset; \
		end += name##_size * (z); \
		if (end >= (s)) { \
			goto g; \
		} \
	} while (0)

#define CLASS_ACCESS_FLAGS_SIZE 18
static const DexAccessFlagsReadable access_flags_list[CLASS_ACCESS_FLAGS_SIZE] = {
	{ ACCESS_FLAG_PUBLIC /*               */, "public" },
	{ ACCESS_FLAG_PRIVATE /*              */, "private" },
	{ ACCESS_FLAG_PROTECTED /*            */, "protected" },
	{ ACCESS_FLAG_STATIC /*               */, "static" },
	{ ACCESS_FLAG_FINAL /*                */, "final" },
	{ ACCESS_FLAG_SYNCHRONIZED /*         */, "synchronized" },
	{ ACCESS_FLAG_BRIDGE /*               */, "bridge" },
	{ ACCESS_FLAG_VARARGS /*              */, "varargs" },
	{ ACCESS_FLAG_NATIVE /*               */, "native" },
	{ ACCESS_FLAG_INTERFACE /*            */, "interface" },
	{ ACCESS_FLAG_ABSTRACT /*             */, "abstract" },
	{ ACCESS_FLAG_STRICT /*               */, "strict" },
	{ ACCESS_FLAG_SYNTHETIC /*            */, "synthetic" },
	{ ACCESS_FLAG_ANNOTATION /*           */, "annotation" },
	{ ACCESS_FLAG_ENUM /*                 */, "enum" },
	{ ACCESS_FLAG_MODULE /*               */, "module" },
	{ ACCESS_FLAG_CONSTRUCTOR /*          */, "constructor" },
	{ ACCESS_FLAG_DECLARED_SYNCHRONIZED /**/, "synchronized" },
};

static void dex_string_free(DexString *string) {
	if (!string) {
		return;
	}
	free(string->data);
	free(string);
}

static DexString *dex_string_new(RzBuffer *buf, ut64 offset, st64 *pread) {
	ut64 size = 0;
	char *data = NULL;
	st64 read;
	DexString *string = NULL;

	read = rz_buf_uleb128(buf, &size);
	if (UT64_ADD_OVFCHK(size, 1)) {
		return NULL;
	}

	data = malloc(size + 1);
	if (!data || rz_buf_read(buf, (ut8 *)data, size) != size) {
		free(data);
		return NULL;
	}
	data[size] = 0;

	string = RZ_NEW0(DexString);
	if (!string) {
		free(data);
		return NULL;
	}

	*pread = read;
	string->size = size;
	string->offset = offset;
	string->data = data;
	return string;
}

static void dex_proto_id_free(DexProtoId *string) {
	if (!string) {
		return;
	}
	free(string->type_list);
	free(string);
}

static DexProtoId *dex_proto_id_new(RzBuffer *buf, ut64 offset) {
	DexProtoId *proto_id = RZ_NEW0(DexProtoId);
	if (!proto_id) {
		return NULL;
	}

	ut32 parameters_offset = 0;
	proto_id->offset = offset;
	read_le32_or_fail(buf, proto_id->shorty_idx, dex_proto_id_new_fail);
	read_le32_or_fail(buf, proto_id->return_type_idx, dex_proto_id_new_fail);

	read_le32_or_fail(buf, parameters_offset, dex_proto_id_new_fail);
	if (parameters_offset > 0) {
		ut32 count = 0;
		read_le32_at_or_fail(buf, count, parameters_offset, dex_proto_id_new_fail);

		proto_id->type_list_size = count;
		proto_id->type_list = RZ_NEWS(ut16, count);
		if (!proto_id->type_list) {
			goto dex_proto_id_new_fail;
		}

		parameters_offset += sizeof(ut32);
		for (ut32 i = 0; i < count; ++i, parameters_offset += sizeof(ut16)) {
			read_le16_at_or_fail(buf, proto_id->type_list[i], parameters_offset, dex_proto_id_new_fail);
		}
	}

	return proto_id;

dex_proto_id_new_fail:
	free(proto_id);
	return NULL;
}

#define dex_field_id_free free
static DexFieldId *dex_field_id_new(RzBuffer *buf, ut64 offset) {
	DexFieldId *field_id = RZ_NEW0(DexFieldId);
	if (!field_id) {
		return NULL;
	}

	read_le16_or_fail(buf, field_id->class_idx, dex_field_id_new_fail);
	read_le16_or_fail(buf, field_id->type_idx, dex_field_id_new_fail);
	read_le32_or_fail(buf, field_id->name_idx, dex_field_id_new_fail);
	field_id->offset = offset;
	return field_id;

dex_field_id_new_fail:
	free(field_id);
	return NULL;
}

#define dex_method_id_free free
static DexMethodId *dex_method_id_new(RzBuffer *buf, ut64 offset) {
	DexMethodId *method_id = RZ_NEW0(DexMethodId);
	if (!method_id) {
		return NULL;
	}

	read_le16_or_fail(buf, method_id->class_idx, dex_method_id_new_fail);
	read_le16_or_fail(buf, method_id->proto_idx, dex_method_id_new_fail);
	read_le32_or_fail(buf, method_id->name_idx, dex_method_id_new_fail);
	method_id->offset = offset;
	return method_id;

dex_method_id_new_fail:
	free(method_id);
	return NULL;
}

static void dex_class_def_free(DexClassDef *class_def) {
	if (!class_def) {
		return;
	}
	rz_list_free(class_def->static_fields);
	rz_list_free(class_def->instance_fields);
	rz_list_free(class_def->direct_methods);
	rz_list_free(class_def->virtual_methods);
	free(class_def->interfaces);
	free(class_def);
}

static DexEncodedField *dex_new_encoded_field(RzBuffer *buf, ut64 base, ut64 *diff_value_prev, bool first) {
	DexEncodedField *encoded_field = RZ_NEW0(DexEncodedField);
	if (!encoded_field) {
		return NULL;
	}
	ut64 diff_value = 0;

	encoded_field->offset = rz_buf_tell(buf) + base;
	rz_buf_uleb128(buf, &diff_value);
	rz_buf_uleb128(buf, &encoded_field->access_flags);

	if (first) {
		encoded_field->field_idx = diff_value;
		*diff_value_prev = diff_value;
	} else {
		encoded_field->field_idx = *diff_value_prev + diff_value;
		*diff_value_prev = encoded_field->field_idx;
	}
	return encoded_field;
}

static DexEncodedMethod *dex_new_encoded_method(RzBuffer *buf, ut64 base, ut64 *diff_value_prev, bool first, RzPVector /*<DexMethodId *>*/ *method_ids) {
	DexEncodedMethod *encoded_method = RZ_NEW0(DexEncodedMethod);
	if (!encoded_method) {
		return NULL;
	}
	ut64 diff_value = 0;
	ut64 code_offset = 0;

	encoded_method->offset = rz_buf_tell(buf) + base;
	rz_buf_uleb128(buf, &diff_value);
	rz_buf_uleb128(buf, &encoded_method->access_flags);
	rz_buf_uleb128(buf, &code_offset);

	if (first) {
		encoded_method->method_idx = diff_value;
		*diff_value_prev = diff_value;
	} else {
		encoded_method->method_idx = *diff_value_prev + diff_value;
		*diff_value_prev = encoded_method->method_idx;
	}

	if (code_offset > 0) {
		read_le16_at_or_fail(buf, encoded_method->registers_size, code_offset, dex_new_encoded_method_fail);
		read_le16_at_or_fail(buf, encoded_method->ins_size, code_offset + 2, dex_new_encoded_method_fail);
		read_le16_at_or_fail(buf, encoded_method->outs_size, code_offset + 4, dex_new_encoded_method_fail);
		read_le16_at_or_fail(buf, encoded_method->tries_size, code_offset + 6, dex_new_encoded_method_fail);
		read_le32_at_or_fail(buf, encoded_method->debug_info_offset, code_offset + 8, dex_new_encoded_method_fail);
		read_le32_at_or_fail(buf, encoded_method->code_size, code_offset + 12, dex_new_encoded_method_fail);
		encoded_method->code_size *= sizeof(ut16); // code ushort[insns_size]
		encoded_method->code_offset = code_offset + 16 + base;

		if (encoded_method->method_idx < rz_pvector_len(method_ids)) {
			DexMethodId *method_id = (DexMethodId *)rz_pvector_at(method_ids, encoded_method->method_idx);
			if (method_id) {
				method_id->code_offset = encoded_method->code_offset;
				method_id->code_size = encoded_method->code_size;
			}
		}
	}
	return encoded_method;

dex_new_encoded_method_fail:
	free(encoded_method);
	return NULL;
}

static DexClassDef *dex_class_def_new(RzBuffer *buf, ut64 offset, ut64 base, RzPVector /*<DexMethodId *>*/ *method_ids) {
	DexClassDef *class_def = RZ_NEW0(DexClassDef);
	if (!class_def) {
		return NULL;
	}

	ut64 static_fields_size = 0;
	ut64 instance_fields_size = 0;
	ut64 direct_methods_size = 0;
	ut64 virtual_methods_size = 0;
	ut64 diff_value_prev;

	class_def->static_fields = /*  */ rz_list_newf((RzListFree)free);
	class_def->instance_fields = /**/ rz_list_newf((RzListFree)free);
	class_def->direct_methods = /* */ rz_list_newf((RzListFree)free);
	class_def->virtual_methods = /**/ rz_list_newf((RzListFree)free);

	read_le16_or_fail(buf, class_def->class_idx, dex_class_def_new_fail);
	read_le16_or_fail(buf, class_def->_padding1, dex_class_def_new_fail);
	read_le32_or_fail(buf, class_def->access_flags, dex_class_def_new_fail);
	read_le16_or_fail(buf, class_def->superclass_idx, dex_class_def_new_fail);
	read_le16_or_fail(buf, class_def->_padding2, dex_class_def_new_fail);
	read_le32_or_fail(buf, class_def->interfaces_offset, dex_class_def_new_fail);
	read_le32_or_fail(buf, class_def->source_file_idx, dex_class_def_new_fail);
	read_le32_or_fail(buf, class_def->annotations_offset, dex_class_def_new_fail);
	read_le32_or_fail(buf, class_def->class_data_offset, dex_class_def_new_fail);
	read_le32_or_fail(buf, class_def->static_values_offset, dex_class_def_new_fail);
	class_def->offset = offset;

	if (class_def->interfaces_offset > 0) {
		if (rz_buf_seek(buf, class_def->interfaces_offset, RZ_BUF_SET) < 0) {
			goto dex_class_def_new_fail;
		}
		read_le32_or_fail(buf, class_def->n_interfaces, dex_class_def_new_fail);
		if (class_def->n_interfaces > 0) {
			class_def->interfaces = RZ_NEWS0(ut16, class_def->n_interfaces);
			if (!class_def->interfaces) {
				goto dex_class_def_new_fail;
			}
			for (ut32 i = 0; i < class_def->n_interfaces; ++i) {
				read_le16_or_fail(buf, class_def->interfaces[i], dex_class_def_new_fail);
			}
		}
	}

	if (!class_def->class_data_offset) {
		return class_def;
	}

	if (rz_buf_seek(buf, class_def->class_data_offset, RZ_BUF_SET) < 0) {
		goto dex_class_def_new_fail;
	}

	rz_buf_uleb128(buf, &static_fields_size);
	rz_buf_uleb128(buf, &instance_fields_size);
	rz_buf_uleb128(buf, &direct_methods_size);
	rz_buf_uleb128(buf, &virtual_methods_size);

	for (ut64 i = 0; i < static_fields_size; ++i) {
		DexEncodedField *encoded_field = dex_new_encoded_field(buf, base, &diff_value_prev, i < 1);
		if (!encoded_field || !rz_list_append(class_def->static_fields, encoded_field)) {
			free(encoded_field);
			goto dex_class_def_new_fail;
		}
	}

	for (ut64 i = 0; i < instance_fields_size; ++i) {
		DexEncodedField *encoded_field = dex_new_encoded_field(buf, base, &diff_value_prev, i < 1);
		if (!encoded_field || !rz_list_append(class_def->instance_fields, encoded_field)) {
			free(encoded_field);
			goto dex_class_def_new_fail;
		}
	}

	for (ut64 i = 0; i < direct_methods_size; ++i) {
		DexEncodedMethod *encoded_method = dex_new_encoded_method(buf, base, &diff_value_prev, i < 1, method_ids);
		if (!encoded_method || !rz_list_append(class_def->direct_methods, encoded_method)) {
			free(encoded_method);
			goto dex_class_def_new_fail;
		}
	}

	for (ut64 i = 0; i < virtual_methods_size; ++i) {
		DexEncodedMethod *encoded_method = dex_new_encoded_method(buf, base, &diff_value_prev, i < 1, method_ids);
		if (!encoded_method || !rz_list_append(class_def->virtual_methods, encoded_method)) {
			free(encoded_method);
			goto dex_class_def_new_fail;
		}
	}

	return class_def;

dex_class_def_new_fail:
	dex_class_def_free(class_def);
	return NULL;
}

static void dex_resolve_virtual_method_code(RzBinDex *dex, DexMethodId *to_resolve, ut32 superclass_idx) {
	DexMethodId *method_id = NULL;
	void **it;

	rz_pvector_foreach (dex->method_ids, it) {
		method_id = (DexMethodId *)*it;
		if (method_id == to_resolve ||
			method_id->class_idx != superclass_idx ||
			method_id->proto_idx != to_resolve->proto_idx ||
			method_id->name_idx != to_resolve->name_idx) {
			continue;
		}
		to_resolve->code_offset = method_id->code_offset;
		to_resolve->code_size = method_id->code_size;
		return;
	}
}

static void dex_resolve_all_virtual_methods(RzBinDex *dex) {
	DexClassDef *class_def;
	DexMethodId *method_id = NULL;
	void **it;
	dex->relocs_size = 0;
	rz_pvector_foreach (dex->method_ids, it) {
		method_id = (DexMethodId *)*it;
		if (method_id->code_offset ||
			method_id->class_idx >= rz_pvector_len(dex->class_defs)) {
			continue;
		}
		class_def = rz_pvector_at(dex->class_defs, method_id->class_idx);
		dex_resolve_virtual_method_code(dex, method_id, class_def->superclass_idx);
	}
}

static bool dex_create_relocations(RzBinDex *dex) {
	void **iter_p0;
	RzListIter *iter_l;
	DexClassDef *class_def;
	DexEncodedMethod *encoded_method = NULL;
	DexMethodId *method_id = NULL;

	dex->relocs_size = 0;
	rz_pvector_foreach (dex->method_ids, iter_p0) {
		method_id = (DexMethodId *)*iter_p0;
		if (method_id->code_offset) {
			continue;
		}
		// patch the imported method.
		method_id->code_offset = dex->relocs_offset + dex->relocs_size;
		method_id->code_size = 2;
		dex->relocs_size += 2;
	}

	// sync classes with method_ids
	rz_pvector_foreach (dex->class_defs, iter_p0) {
		class_def = (DexClassDef *)*iter_p0;
		rz_list_foreach (class_def->direct_methods, iter_l, encoded_method) {
			if (encoded_method->code_offset) {
				continue;
			}
			method_id = NULL;
			if (encoded_method->method_idx < rz_pvector_len(dex->method_ids)) {
				method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);
				if (method_id->code_offset) {
					encoded_method->code_offset = method_id->code_offset;
					encoded_method->code_size = method_id->code_size;
					continue;
				}
			}

			// patch the imported method.
			encoded_method->code_offset = dex->relocs_offset + dex->relocs_size;
			encoded_method->code_size = 2;
			dex->relocs_size += 2;
			if (method_id) {
				method_id->code_offset = encoded_method->code_offset;
				method_id->code_size = encoded_method->code_size;
			}
		}

		rz_list_foreach (class_def->virtual_methods, iter_l, encoded_method) {
			if (encoded_method->code_offset) {
				continue;
			}
			method_id = NULL;
			if (encoded_method->method_idx < rz_pvector_len(dex->method_ids)) {
				method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);
				if (method_id->code_offset) {
					encoded_method->code_offset = method_id->code_offset;
					encoded_method->code_size = method_id->code_size;
					continue;
				}
			}

			// patch the imported method.
			encoded_method->code_offset = dex->relocs_offset + dex->relocs_size;
			encoded_method->code_size = 2;
			dex->relocs_size += 2;
			if (method_id) {
				method_id->code_offset = encoded_method->code_offset;
				method_id->code_size = encoded_method->code_size;
			}
		}
	}

	if (dex->relocs_size < 1) {
		return true;
	}
	dex->relocs_code = malloc(dex->relocs_size);
	if (!dex->relocs_code) {
		return false;
	}
	for (ut32 i = 0; i < dex->relocs_size; i += 2) {
		dex->relocs_code[i] = 0x0e;
		dex->relocs_code[i + 1] = 0x00;
	}
	dex->relocs_buffer = rz_buf_new_with_bytes(dex->relocs_code, dex->relocs_size);
	return dex->relocs_buffer;
}

static bool dex_parse(RzBinDex *dex, ut64 base, RzBuffer *buf) {
	ut64 offset = 0;
	st64 read = 0;
	st64 buffer_size = rz_buf_size(buf);
	if (buffer_size < 116) {
		// 116 bytes is the smalled dex that can be built.
		RZ_LOG_ERROR("dex bin: invalid buffer size (size < 116)\n");
		goto dex_parse_bad;
	}

	dex->header_offset = base;
	dex->relocs_offset = base + RZ_DEX_RELOC_ADDRESS;
	rz_buf_read(buf, dex->magic, sizeof(dex->magic));
	rz_buf_read(buf, dex->version, sizeof(dex->version));
	dex->checksum_offset = rz_buf_tell(buf) + base;
	read_le32_or_fail(buf, dex->checksum, dex_parse_bad);
	dex->signature_offset = rz_buf_tell(buf) + base;
	rz_buf_read(buf, dex->signature, sizeof(dex->signature));
	read_le32_or_fail(buf, dex->file_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->header_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->endian_tag, dex_parse_bad);

	read_le32_or_fail(buf, dex->link_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->link_offset, dex_parse_bad);

	read_le32_or_fail(buf, dex->map_offset, dex_parse_bad);

	read_le32_or_fail(buf, dex->string_ids_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->string_ids_offset, dex_parse_bad);
	// string_ids points to an array of offsets.
	dex_fail_if_bad_ids(dex->string_ids, sizeof(ut32), buffer_size, dex_parse_bad);

	read_le32_or_fail(buf, dex->type_ids_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->type_ids_offset, dex_parse_bad);
	dex_fail_if_bad_ids(dex->type_ids, DEX_TYPE_ID_SIZE, buffer_size, dex_parse_bad);

	read_le32_or_fail(buf, dex->proto_ids_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->proto_ids_offset, dex_parse_bad);
	dex_fail_if_bad_ids(dex->proto_ids, DEX_PROTO_ID_SIZE, buffer_size, dex_parse_bad);

	read_le32_or_fail(buf, dex->field_ids_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->field_ids_offset, dex_parse_bad);
	dex_fail_if_bad_ids(dex->field_ids, DEX_FIELD_ID_SIZE, buffer_size, dex_parse_bad);

	read_le32_or_fail(buf, dex->method_ids_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->method_ids_offset, dex_parse_bad);
	dex_fail_if_bad_ids(dex->method_ids, DEX_METHOD_ID_SIZE, buffer_size, dex_parse_bad);

	read_le32_or_fail(buf, dex->class_defs_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->class_defs_offset, dex_parse_bad);

	read_le32_or_fail(buf, dex->data_size, dex_parse_bad);
	read_le32_or_fail(buf, dex->data_offset, dex_parse_bad);

	/* Strings */
	offset = dex->string_ids_offset;
	if (!rz_pvector_reserve(dex->strings, dex->string_ids_size)) {
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->string_ids_size; ++i, offset += sizeof(ut32)) {
		ut32 string_offset = 0;
		read_le32_at_or_fail(buf, string_offset, offset, dex_parse_bad);

		if (rz_buf_seek(buf, string_offset, RZ_BUF_SET) < 0) {
			goto dex_parse_bad;
		}
		DexString *string = dex_string_new(buf, base + string_offset, &read);
		if (!string) {
			goto dex_parse_bad;
		}
		rz_pvector_push(dex->strings, string);
	}

	/* Type Ids */
	dex->types = RZ_NEWS0(DexTypeId, dex->type_ids_size);
	if (!dex->types) {
		goto dex_parse_bad;
	}
	if (rz_buf_seek(buf, dex->type_ids_offset, RZ_BUF_SET) < 0) {
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->type_ids_size; ++i) {
		read_le32_or_fail(buf, dex->types[i], dex_parse_bad);
	}

	/* Proto Ids */
	offset = dex->proto_ids_offset;
	if (!rz_pvector_reserve(dex->proto_ids, dex->proto_ids_size)) {
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->proto_ids_size; ++i, offset += DEX_PROTO_ID_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			goto dex_parse_bad;
		}
		DexProtoId *proto_id = dex_proto_id_new(buf, base + offset);
		if (!proto_id) {
			goto dex_parse_bad;
		}
		rz_pvector_push(dex->proto_ids, proto_id);
	}

	/* Field Ids */
	offset = dex->field_ids_offset;
	if (!rz_pvector_reserve(dex->field_ids, dex->field_ids_size)) {
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->field_ids_size; ++i, offset += DEX_FIELD_ID_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			goto dex_parse_bad;
		}
		DexFieldId *field_id = dex_field_id_new(buf, base + offset);
		if (!field_id) {
			goto dex_parse_bad;
		}
		rz_pvector_push(dex->field_ids, field_id);
	}

	/* Method Ids */
	offset = dex->method_ids_offset;
	if (!rz_pvector_reserve(dex->method_ids, dex->method_ids_size)) {
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->method_ids_size; ++i, offset += DEX_METHOD_ID_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			goto dex_parse_bad;
		}
		DexMethodId *method_id = dex_method_id_new(buf, base + offset);
		if (!method_id) {
			goto dex_parse_bad;
		}
		rz_pvector_push(dex->method_ids, method_id);
	}

	/* Class Defs */
	offset = dex->class_defs_offset;
	if (!rz_pvector_reserve(dex->class_defs, dex->class_defs_size)) {
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->class_defs_size; ++i, offset += DEX_CLASS_DEF_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			goto dex_parse_bad;
		}
		DexClassDef *class_def = dex_class_def_new(buf, base + offset, base, dex->method_ids);
		if (!class_def) {
			goto dex_parse_bad;
		}
		rz_pvector_push(dex->class_defs, class_def);
	}

	/* Resolve all virtual methods */
	dex_resolve_all_virtual_methods(dex);

	/* generate relocation code buffer this buffer will contain a
	 * sequence of 0e00, i.e 'return-void', which will be used to
	 * resolve imports for the xrefs.
	 */
	if (!dex_create_relocations(dex)) {
		goto dex_parse_bad;
	}

	return true;

dex_parse_bad:
	rz_bin_dex_free(dex);
	return false;
}

/**
 * \brief Frees a RzBinDex struct
 */
RZ_API void rz_bin_dex_free(RZ_NULLABLE RzBinDex *dex) {
	if (!dex) {
		return;
	}

	rz_pvector_free(dex->strings);
	rz_pvector_free(dex->proto_ids);
	rz_pvector_free(dex->field_ids);
	rz_pvector_free(dex->method_ids);
	rz_pvector_free(dex->class_defs);
	rz_buf_free(dex->relocs_buffer);

	free(dex->types);
	free(dex->relocs_code);
	free(dex);
}

/**
 * \brief Parses the dex file and returns a RzBinDex struct
 */
RZ_API RZ_OWN RzBinDex *rz_bin_dex_new(RZ_NONNULL RzBuffer *buf, ut64 base, RZ_NONNULL Sdb *kv) {
	rz_return_val_if_fail(buf, NULL);

	RzBinDex *dex = (RzBinDex *)RZ_NEW0(RzBinDex);
	if (!dex) {
		return NULL;
	}

	dex->strings = rz_pvector_new((RzPVectorFree)dex_string_free);
	if (!dex->strings) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->proto_ids = rz_pvector_new((RzPVectorFree)dex_proto_id_free);
	if (!dex->proto_ids) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->field_ids = rz_pvector_new((RzPVectorFree)dex_field_id_free);
	if (!dex->field_ids) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->method_ids = rz_pvector_new((RzPVectorFree)dex_method_id_free);
	if (!dex->method_ids) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->class_defs = rz_pvector_new((RzPVectorFree)dex_class_def_free);
	if (!dex->class_defs) {
		rz_bin_dex_free(dex);
		return NULL;
	}

	if (!dex_parse(dex, base, buf)) {
		return NULL;
	}

	return dex;
}

RZ_API RZ_OWN char *rz_bin_dex_access_flags_readable(ut32 access_flags) {
	RzStrBuf *sb = NULL;
	for (ut32 i = 0; i < CLASS_ACCESS_FLAGS_SIZE; ++i) {
		const DexAccessFlagsReadable *afr = &access_flags_list[i];
		if (afr->flag == ACCESS_FLAG_VARARGS) {
			continue;
		}
		if (access_flags & afr->flag) {
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

/**
 * \brief Returns a RzPVector<RzBinString*> containing the dex strings
 */
RZ_API RZ_OWN RzPVector /*<RzBinString *>*/ *rz_bin_dex_strings(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexString *string;
	void **it;
	RzPVector *strings = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!strings) {
		return NULL;
	}

	ut32 ordinal = 0;
	rz_pvector_foreach (dex->strings, it) {
		string = (DexString *)*it;
		RzBinString *bstr = RZ_NEW0(RzBinString);
		if (!bstr) {
			continue;
		}
		bstr->paddr = string->offset;
		bstr->vaddr = RZ_DEX_VIRT_ADDRESS + string->offset;
		bstr->ordinal = ordinal;
		bstr->length = string->size;
		bstr->size = string->size;
		bstr->string = rz_str_ndup(string->data, string->size);
		bstr->type = RZ_STRING_ENC_UTF8;
		if (!rz_pvector_push(strings, bstr)) {
			free(bstr);
		}
		ordinal++;
	}
	return strings;
}

static inline DexString *dex_resolve_string_id_native(RzBinDex *dex, ut32 string_idx) {
	if (string_idx >= rz_pvector_len(dex->strings)) {
		return NULL;
	}
	return (DexString *)rz_pvector_at(dex->strings, string_idx);
}

static char *dex_resolve_string_id(RzBinDex *dex, ut32 string_idx) {
	DexString *string = dex_resolve_string_id_native(dex, string_idx);
	if (!string) {
		RZ_LOG_INFO("cannot find string with index %u\n", string_idx);
		return NULL;
	}
	return rz_str_ndup(string->data, string->size);
}

static char *dex_resolve_type_id(RzBinDex *dex, ut32 type_idx) {
	if (type_idx >= dex->type_ids_size) {
		RZ_LOG_INFO("cannot find type_id with index %u\n", type_idx);
		return NULL;
	}
	DexTypeId type_id = dex->types[type_idx];
	return dex_resolve_string_id(dex, type_id);
}

static char *dex_resolve_proto_id(RzBinDex *dex, const char *name, ut32 proto_idx, bool varargs) {
	if (proto_idx >= rz_pvector_len(dex->proto_ids)) {
		RZ_LOG_INFO("cannot find proto_id with index %u\n", proto_idx);
		return NULL;
	}

	DexProtoId *proto_id = (DexProtoId *)rz_pvector_at(dex->proto_ids, proto_idx);
	if (proto_id->return_type_idx >= dex->type_ids_size) {
		RZ_LOG_INFO("cannot find return type id with index %u\n", proto_id->return_type_idx);
		return NULL;
	}

	RzStrBuf *sb = rz_strbuf_new(name);
	if (!sb) {
		return NULL;
	}

	const DexString *return_type = dex_resolve_string_id_native(dex, dex->types[proto_id->return_type_idx]);
	if (!return_type) {
		RZ_LOG_INFO("cannot find return type string with index %u\n", proto_id->return_type_idx);
		rz_strbuf_free(sb);
		return NULL;
	}

	rz_strbuf_append(sb, "(");
	for (ut32 i = 0; i < proto_id->type_list_size; ++i) {
		ut32 type_idx = proto_id->type_list[i];
		if (type_idx >= dex->type_ids_size) {
			continue;
		}

		const DexString *param = dex_resolve_string_id_native(dex, dex->types[type_idx]);
		if (!param) {
			RZ_LOG_INFO("cannot find param string with index %d\n", dex->types[type_idx]);
			rz_strbuf_free(sb);
			return NULL;
		}
		if (varargs && (i + 1) >= proto_id->type_list_size) {
			rz_strbuf_append(sb, "...");
		}
		rz_strbuf_append_n(sb, param->data, param->size);
	}
	rz_strbuf_append(sb, ")");
	rz_strbuf_append_n(sb, return_type->data, return_type->size);
	return rz_strbuf_drain(sb);
}

static ut64 dex_access_flags_to_bin_flags(ut64 access_flags) {
	ut64 flags = 0;
	if (access_flags & ACCESS_FLAG_PUBLIC) {
		flags |= RZ_BIN_METH_PUBLIC;
	}
	if (access_flags & ACCESS_FLAG_PRIVATE) {
		flags |= RZ_BIN_METH_PRIVATE;
	}
	if (access_flags & ACCESS_FLAG_PROTECTED) {
		flags |= RZ_BIN_METH_PROTECTED;
	}
	if (access_flags & ACCESS_FLAG_STATIC) {
		flags |= RZ_BIN_METH_STATIC;
	}
	if (access_flags & ACCESS_FLAG_FINAL) {
		flags |= RZ_BIN_METH_FINAL;
	}
	if (access_flags & ACCESS_FLAG_SYNCHRONIZED) {
		flags |= RZ_BIN_METH_SYNCHRONIZED;
	}
	if (access_flags & ACCESS_FLAG_BRIDGE) {
		flags |= RZ_BIN_METH_BRIDGE;
	}
	if (access_flags & ACCESS_FLAG_VARARGS) {
		flags |= RZ_BIN_METH_VARARGS;
	}
	if (access_flags & ACCESS_FLAG_NATIVE) {
		flags |= RZ_BIN_METH_NATIVE;
	}
	// RZ_BIN_METH_INTERFACE does not exists
	// if (access_flags & ACCESS_FLAG_INTERFACE) {
	//	flags |= RZ_BIN_METH_INTERFACE;
	//}
	if (access_flags & ACCESS_FLAG_ABSTRACT) {
		flags |= RZ_BIN_METH_ABSTRACT;
	}
	if (access_flags & ACCESS_FLAG_STRICT) {
		flags |= RZ_BIN_METH_STRICT;
	}
	if (access_flags & ACCESS_FLAG_SYNTHETIC) {
		flags |= RZ_BIN_METH_SYNTHETIC;
	}
	// RZ_BIN_METH_ANNOTATION does not exists
	// if (access_flags & ACCESS_FLAG_ANNOTATION) {
	//	flags |= RZ_BIN_METH_ANNOTATION;
	//}
	// RZ_BIN_METH_ENUM does not exists
	// if (access_flags & ACCESS_FLAG_ENUM) {
	//	flags |= RZ_BIN_METH_ENUM;
	//}
	// RZ_BIN_METH_MODULE does not exists
	// if (access_flags & ACCESS_FLAG_MODULE) {
	//	flags |= RZ_BIN_METH_MODULE;
	//}
	if (access_flags & ACCESS_FLAG_CONSTRUCTOR) {
		flags |= RZ_BIN_METH_CONSTRUCTOR;
	}
	if (access_flags & ACCESS_FLAG_DECLARED_SYNCHRONIZED) {
		flags |= RZ_BIN_METH_DECLARED_SYNCHRONIZED;
	}
	return flags;
}

static char *demangle_java_and_free(char *mangled) {
	if (!mangled) {
		return NULL;
	}
	char *demangled = rz_demangler_java(mangled, RZ_DEMANGLER_FLAG_ENABLE_ALL);
	free(mangled);
	return demangled;
}

static void set_lib_and_class_name(char *mangled, char **out_class, char **out_lib) {
	if (!mangled) {
		return;
	}
	bool is_java_lang = startswith(mangled, "Ljava/lang");

	char *object = demangle_java_and_free(mangled);
	if (!object) {
		return;
	}

	*out_class = object;
	if (!is_java_lang || startswith(object, "java.lang")) {
		*out_lib = rz_str_dup(object);
	} else {
		*out_lib = rz_str_newf("java.lang.%s", object);
	}
}

static RzBinSymbol *dex_method_to_symbol(RzBinDex *dex, DexEncodedMethod *encoded_method, DexMethodId *method_id, bool is_imported) {
	RzBinSymbol *symbol = RZ_NEW0(RzBinSymbol);
	if (!symbol) {
		return NULL;
	}

	bool varargs = dex_is_varargs(encoded_method->access_flags);
	symbol->name = dex_resolve_string_id(dex, method_id->name_idx);
	char *mangled = dex_resolve_type_id(dex, method_id->class_idx);
	set_lib_and_class_name(mangled, &symbol->classname, &symbol->libname);
	symbol->dname = demangle_java_and_free(dex_resolve_proto_id(dex, symbol->name, method_id->proto_idx, varargs));
	symbol->bind = dex_is_static(encoded_method->access_flags) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
	symbol->is_imported = is_imported;
	symbol->visibility = encoded_method->access_flags & UT32_MAX;
	symbol->visibility_str = rz_bin_dex_access_flags_readable(symbol->visibility);
	symbol->size = encoded_method->code_size;
	if (encoded_method->code_offset < RZ_DEX_RELOC_ADDRESS) {
		symbol->vaddr = RZ_DEX_VIRT_ADDRESS + encoded_method->code_offset;
		symbol->paddr = encoded_method->code_offset;
	} else {
		symbol->vaddr = encoded_method->code_offset;
		symbol->paddr = 0;
	}
	symbol->ordinal = encoded_method->method_idx;
	symbol->method_flags = dex_access_flags_to_bin_flags(encoded_method->access_flags);
	symbol->type = RZ_BIN_TYPE_METH_STR;

	return symbol;
}

static RzList /*<RzBinSymbol *>*/ *dex_resolve_methods_in_class(RzBinDex *dex, DexClassDef *class_def, ut8 *inserted) {
	RzList *methods = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!methods) {
		return NULL;
	}

	DexMethodId *method_id = NULL;
	DexEncodedMethod *encoded_method = NULL;
	RzListIter *it = NULL;

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		if (encoded_method->method_idx >= rz_pvector_len(dex->method_ids)) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		} else if (inserted[encoded_method->method_idx]) {
			continue;
		}
		method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);
		inserted[encoded_method->method_idx] = true;

		RzBinSymbol *symbol = dex_method_to_symbol(dex, encoded_method, method_id, false);
		if (!symbol || !rz_list_append(methods, symbol)) {
			rz_bin_symbol_free(symbol);
			break;
		}
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		if (encoded_method->method_idx >= rz_pvector_len(dex->method_ids)) {
			RZ_LOG_INFO("cannot find virtual method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		} else if (inserted[encoded_method->method_idx]) {
			continue;
		}
		method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);
		inserted[encoded_method->method_idx] = true;

		RzBinSymbol *symbol = dex_method_to_symbol(dex, encoded_method, method_id, false);
		if (!symbol || !rz_list_append(methods, symbol)) {
			rz_bin_symbol_free(symbol);
			break;
		}
	}

	return methods;
}

static RzBinClassField *dex_field_to_bin_field(RzBinDex *dex, DexEncodedField *encoded_field, DexFieldId *field_id, bool is_static) {
	RzBinClassField *field = RZ_NEW0(RzBinClassField);
	if (!field) {
		return NULL;
	}

	ut64 access_flags = encoded_field->access_flags;
	if (is_static) {
		access_flags |= ACCESS_FLAG_STATIC;
	}

	field->vaddr = RZ_DEX_VIRT_ADDRESS + encoded_field->offset;
	field->paddr = encoded_field->offset;
	field->visibility = encoded_field->access_flags & UT32_MAX;
	field->visibility_str = rz_bin_dex_access_flags_readable(access_flags);
	char *mangled = dex_resolve_type_id(dex, field_id->class_idx);
	set_lib_and_class_name(mangled, &field->classname, &field->libname);
	field->name = dex_resolve_string_id(dex, field_id->name_idx);
	field->type = demangle_java_and_free(dex_resolve_type_id(dex, field_id->type_idx));
	field->flags = dex_access_flags_to_bin_flags(access_flags);

	return field;
}

static RzList /*<RzBinClassField *>*/ *dex_resolve_fields_in_class(RzBinDex *dex, DexClassDef *class_def, ut8 *inserted) {
	RzList *fields = rz_list_newf((RzListFree)rz_bin_class_field_free);
	if (!fields) {
		return NULL;
	}
	DexFieldId *field_id = NULL;
	DexEncodedField *encoded_field = NULL;
	RzListIter *it = NULL;

	rz_list_foreach (class_def->static_fields, it, encoded_field) {
		if (encoded_field->field_idx >= rz_pvector_len(dex->field_ids)) {
			RZ_LOG_INFO("cannot find static field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		} else if (inserted[encoded_field->field_idx]) {
			continue;
		}
		inserted[encoded_field->field_idx] = true;
		field_id = (DexFieldId *)rz_pvector_at(dex->field_ids, encoded_field->field_idx);

		RzBinClassField *field = dex_field_to_bin_field(dex, encoded_field, field_id, true);
		if (!field || !rz_list_append(fields, field)) {
			rz_bin_class_field_free(field);
			break;
		}
	}

	rz_list_foreach (class_def->instance_fields, it, encoded_field) {
		if (encoded_field->field_idx >= rz_pvector_len(dex->field_ids)) {
			RZ_LOG_INFO("cannot find instance field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		} else if (inserted[encoded_field->field_idx]) {
			continue;
		}
		inserted[encoded_field->field_idx] = true;
		field_id = (DexFieldId *)rz_pvector_at(dex->field_ids, encoded_field->field_idx);

		RzBinClassField *field = dex_field_to_bin_field(dex, encoded_field, field_id, false);
		if (!field || !rz_list_append(fields, field)) {
			rz_bin_class_field_free(field);
			break;
		}
	}
	return fields;
}

static RzBinSymbol *dex_field_to_symbol(RzBinDex *dex, DexEncodedField *encoded_field, DexFieldId *field_id, bool is_imported) {
	RzBinSymbol *field = RZ_NEW0(RzBinSymbol);
	if (!field) {
		return NULL;
	}

	field->name = dex_resolve_string_id(dex, field_id->name_idx);
	char *mangled = dex_resolve_type_id(dex, field_id->class_idx);
	set_lib_and_class_name(mangled, &field->classname, &field->libname);
	field->bind = dex_is_static(encoded_field->access_flags) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
	field->is_imported = false;
	field->visibility = encoded_field->access_flags & UT32_MAX;
	field->visibility_str = rz_bin_dex_access_flags_readable(encoded_field->access_flags);
	field->vaddr = RZ_DEX_VIRT_ADDRESS + encoded_field->offset;
	field->paddr = encoded_field->offset;
	field->ordinal = encoded_field->field_idx;
	field->method_flags = dex_access_flags_to_bin_flags(encoded_field->access_flags);
	field->type = RZ_BIN_TYPE_FIELD_STR;

	return field;
}

static RzList /*<RzBinSymbol *>*/ *dex_resolve_fields_in_class_as_symbols(RzBinDex *dex, DexClassDef *class_def, ut8 *inserted) {
	RzList *fields = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!fields) {
		return NULL;
	}
	DexFieldId *field_id = NULL;
	DexEncodedField *encoded_field = NULL;
	RzListIter *it = NULL;

	rz_list_foreach (class_def->static_fields, it, encoded_field) {
		if (encoded_field->field_idx >= rz_pvector_len(dex->field_ids)) {
			RZ_LOG_INFO("cannot find static field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		}
		field_id = (DexFieldId *)rz_pvector_at(dex->field_ids, encoded_field->field_idx);
		inserted[encoded_field->field_idx] = true;

		RzBinSymbol *field = dex_field_to_symbol(dex, encoded_field, field_id, false);
		if (!field || !rz_list_append(fields, field)) {
			rz_bin_symbol_free(field);
			break;
		}
	}

	rz_list_foreach (class_def->instance_fields, it, encoded_field) {
		if (encoded_field->field_idx >= rz_pvector_len(dex->field_ids)) {
			RZ_LOG_INFO("cannot find instance field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		}
		field_id = (DexFieldId *)rz_pvector_at(dex->field_ids, encoded_field->field_idx);
		inserted[encoded_field->field_idx] = true;

		RzBinSymbol *field = dex_field_to_symbol(dex, encoded_field, field_id, false);
		if (!field || !rz_list_append(fields, field)) {
			rz_bin_symbol_free(field);
			break;
		}
	}
	return fields;
}

/**
 * \brief Returns a RzPVector<RzBinClass*> containing the dex classes
 */
RZ_API RZ_OWN RzPVector /*<RzBinClass *>*/ *rz_bin_dex_classes(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzBinClass *bclass = NULL;
	RzPVector *classes = NULL;
	void **it;

	ut32 n_methods = rz_pvector_len(dex->method_ids);
	ut32 n_fields = rz_pvector_len(dex->field_ids);

	ut8 *inserted_methods = RZ_NEWS0(ut8, n_methods);
	ut8 *inserted_fields = RZ_NEWS0(ut8, n_fields);
	if ((n_methods > 0 && !inserted_methods) || (n_fields > 0 && !inserted_fields)) {
		free(inserted_fields);
		free(inserted_methods);
		return NULL;
	}

	classes = rz_pvector_new((RzPVectorFree)rz_bin_class_free);
	if (!classes) {
		free(inserted_fields);
		free(inserted_methods);
		return NULL;
	}

	rz_pvector_foreach (dex->class_defs, it) {
		class_def = (DexClassDef *)*it;
		bclass = RZ_NEW0(RzBinClass);
		if (!bclass) {
			break;
		}

		bclass->name = demangle_java_and_free(dex_resolve_type_id(dex, class_def->class_idx));
		bclass->super = demangle_java_and_free(dex_resolve_type_id(dex, class_def->superclass_idx));
		bclass->visibility = class_def->access_flags;
		bclass->visibility_str = rz_bin_dex_access_flags_readable(class_def->access_flags);
		bclass->addr = class_def->offset;
		bclass->methods = dex_resolve_methods_in_class(dex, class_def, inserted_methods);
		bclass->fields = dex_resolve_fields_in_class(dex, class_def, inserted_fields);

		if (!rz_pvector_push(classes, bclass)) {
			rz_bin_class_free(bclass);
			break;
		}
	}
	free(inserted_fields);
	free(inserted_methods);

	return classes;
}

static RzBinSection *section_new(const char *name, ut32 perm, ut32 size, ut64 paddr, ut64 vaddr) {
	RzBinSection *section = RZ_NEW0(RzBinSection);
	if (!section) {
		return NULL;
	}
	section->name = rz_str_dup(name);
	section->paddr = paddr;
	section->vaddr = vaddr;
	section->size = section->vsize = size;
	section->perm = perm;
	return section;
}

/**
 * \brief Returns a RzPVector<RzBinSection*> containing the dex sections
 */
RZ_API RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_dex_sections(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	RzBinSection *section;
	RzPVector *sections = NULL;

	sections = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!sections) {
		return NULL;
	}
	section = section_new("data", RZ_PERM_RWX, dex->data_size, dex->data_offset, RZ_DEX_VIRT_ADDRESS + dex->data_offset);
	if (section && !rz_pvector_push(sections, section)) {
		rz_bin_section_free(section);
	}
	section = section_new("file", RZ_PERM_R, dex->file_size, dex->header_offset, 0);
	if (section && !rz_pvector_push(sections, section)) {
		rz_bin_section_free(section);
	}

	if (dex->relocs_code) {
		section = section_new(RZ_DEX_RELOC_TARGETS, RZ_PERM_RWX, dex->relocs_size, 0, dex->relocs_offset);
		if (section && !rz_pvector_push(sections, section)) {
			rz_bin_section_free(section);
		}
	}

	return sections;
}

/**
 * \brief Returns a RzList<RzBinClassField*> containing the dex fields
 */
RZ_API RZ_OWN RzList /*<RzBinClassField *>*/ *rz_bin_dex_fields(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzList *fields = NULL;
	void **it;
	ut32 n_fields = rz_pvector_len(dex->field_ids);
	ut8 *inserted = RZ_NEWS0(ut8, n_fields);
	if (n_fields > 0 && !inserted) {
		free(inserted);
		return NULL;
	}

	fields = rz_list_newf((RzListFree)rz_bin_class_field_free);
	if (!fields) {
		free(inserted);
		return NULL;
	}

	rz_pvector_foreach (dex->class_defs, it) {
		class_def = (DexClassDef *)*it;
		RzList *class_fields = dex_resolve_fields_in_class(dex, class_def, inserted);
		if (class_fields) {
			rz_list_join(fields, class_fields);
			rz_list_free(class_fields);
		}
	}
	free(inserted);

	return fields;
}

/**
 * \brief Returns a RzPVector<RzBinSymbol*> containing the dex symbols
 */
RZ_API RZ_OWN RzPVector /*<RzBinSymbol *>*/ *rz_bin_dex_symbols(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	DexFieldId *field_id;
	DexMethodId *method_id;
	RzList *class_symbols = NULL;
	RzPVector *symbols = NULL;
	void **vit;
	ut8 *inserted_methods = NULL;
	ut8 *inserted_fields = NULL;
	ut32 n_methods = rz_pvector_len(dex->method_ids);
	ut32 n_fields = rz_pvector_len(dex->field_ids);

	inserted_methods = RZ_NEWS0(ut8, n_methods);
	inserted_fields = RZ_NEWS0(ut8, n_fields);
	if ((n_methods > 0 && !inserted_methods) || (n_fields > 0 && !inserted_fields)) {
		free(inserted_fields);
		free(inserted_methods);
		return NULL;
	}

	symbols = rz_pvector_new((RzPVectorFree)rz_bin_symbol_free);
	if (!symbols) {
		free(inserted_fields);
		free(inserted_methods);
		return NULL;
	}

	rz_pvector_foreach (dex->class_defs, vit) {
		class_def = (DexClassDef *)*vit;
		RzListIter *iter;
		RzBinSymbol *sym;

		class_symbols = dex_resolve_fields_in_class_as_symbols(dex, class_def, inserted_fields);
		if (class_symbols) {
			rz_list_foreach (class_symbols, iter, sym) {
				rz_pvector_push(symbols, sym);
			}
			class_symbols->length = 0;
			class_symbols->head = class_symbols->tail = NULL;
			rz_list_free(class_symbols);
		}

		class_symbols = dex_resolve_methods_in_class(dex, class_def, inserted_methods);
		if (class_symbols) {
			rz_list_foreach (class_symbols, iter, sym) {
				rz_pvector_push(symbols, sym);
			}
			class_symbols->length = 0;
			class_symbols->head = class_symbols->tail = NULL;
			rz_list_free(class_symbols);
		}
	}

	ut32 j = 0;
	rz_pvector_foreach (dex->field_ids, vit) {
		field_id = (DexFieldId *)*vit;
		if (inserted_fields[j++]) {
			continue;
		}

		RzBinSymbol *field = RZ_NEW0(RzBinSymbol);
		if (!field) {
			break;
		}

		field->name = dex_resolve_string_id(dex, field_id->name_idx);
		char *mangled = dex_resolve_type_id(dex, field_id->class_idx);
		set_lib_and_class_name(mangled, &field->classname, &field->libname);
		field->bind = RZ_BIN_BIND_WEAK_STR;
		field->type = RZ_BIN_TYPE_FIELD_STR;
		field->is_imported = true;
		field->vaddr = UT64_MAX;
		field->paddr = UT64_MAX;

		if (!rz_pvector_push(symbols, field)) {
			rz_bin_symbol_free(field);
			break;
		}
	}

	j = 0;
	rz_pvector_foreach (dex->method_ids, vit) {
		method_id = (DexMethodId *)*vit;
		if (inserted_methods[j++]) {
			continue;
		}

		RzBinSymbol *method = RZ_NEW0(RzBinSymbol);
		if (!method) {
			break;
		}

		method->name = dex_resolve_string_id(dex, method_id->name_idx);
		char *mangled = dex_resolve_type_id(dex, method_id->class_idx);
		set_lib_and_class_name(mangled, &method->classname, &method->libname);
		method->dname = demangle_java_and_free(dex_resolve_proto_id(dex, method->name, method_id->proto_idx, false));
		method->bind = RZ_BIN_BIND_WEAK_STR;
		method->is_imported = true;
		method->type = RZ_BIN_TYPE_METH_STR;
		if (method_id->code_offset < RZ_DEX_RELOC_ADDRESS) {
			method->vaddr = RZ_DEX_VIRT_ADDRESS + method_id->code_offset;
			method->paddr = method_id->code_offset;
		} else {
			method->vaddr = method_id->code_offset;
			method->paddr = 0;
		}
		method->size = method_id->code_size;

		if (!rz_pvector_push(symbols, method)) {
			rz_bin_symbol_free(method);
			break;
		}
	}

	free(inserted_fields);
	free(inserted_methods);
	return symbols;
}

/**
 * \brief Returns a RzPVector<RzBinImport*> containing the dex imports
 */
RZ_API RZ_OWN RzPVector /*<RzBinImport *>*/ *rz_bin_dex_imports(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexFieldId *field_id;
	DexMethodId *method_id;
	DexClassDef *class_def;
	RzPVector *imports = NULL;
	ut32 *class_ids = NULL;
	void **vit;

	ut32 n_classes = rz_pvector_len(dex->class_defs);
	if (n_classes < 1) {
		return rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	}

	class_ids = RZ_NEWS0(ut32, n_classes);
	if (!class_ids) {
		return NULL;
	}

	ut32 j = 0;
	rz_pvector_foreach (dex->class_defs, vit) {
		class_def = (DexClassDef *)*vit;
		class_ids[j] = class_def->class_idx;
		j++;
	}

	imports = rz_pvector_new((RzPVectorFree)rz_bin_import_free);
	if (!imports) {
		free(class_ids);
		return NULL;
	}

	ut32 ordinal = 0;
	rz_pvector_foreach (dex->field_ids, vit) {
		field_id = (DexFieldId *)*vit;
		bool class_found = false;
		for (ut32 i = 0; i < n_classes; ++i) {
			if (field_id->class_idx == class_ids[i]) {
				class_found = true;
				break;
			}
		}
		if (class_found) {
			continue;
		}

		RzBinImport *import = RZ_NEW0(RzBinImport);
		if (!import) {
			break;
		}

		import->name = dex_resolve_string_id(dex, field_id->name_idx);
		char *mangled = dex_resolve_type_id(dex, field_id->class_idx);
		set_lib_and_class_name(mangled, &import->classname, &import->libname);
		import->bind = RZ_BIN_BIND_WEAK_STR;
		import->type = RZ_BIN_TYPE_FIELD_STR;
		import->ordinal = ordinal;

		if (!rz_pvector_push(imports, import)) {
			rz_bin_import_free(import);
			break;
		}
		ordinal++;
	}

	rz_pvector_foreach (dex->method_ids, vit) {
		method_id = (DexMethodId *)*vit;
		bool class_found = false;
		for (ut32 i = 0; i < n_classes; ++i) {
			if (method_id->class_idx == class_ids[i]) {
				class_found = true;
				break;
			}
		}
		if (class_found) {
			continue;
		}

		RzBinImport *import = RZ_NEW0(RzBinImport);
		if (!import) {
			break;
		}

		char *name = dex_resolve_string_id(dex, method_id->name_idx);
		import->name = dex_resolve_proto_id(dex, name, method_id->proto_idx, false);
		char *mangled = dex_resolve_type_id(dex, method_id->class_idx);
		set_lib_and_class_name(mangled, &import->classname, &import->libname);
		import->bind = RZ_BIN_BIND_WEAK_STR;
		import->type = RZ_BIN_TYPE_FUNC_STR;
		import->ordinal = ordinal;
		free(name);

		if (!rz_pvector_push(imports, import)) {
			rz_bin_import_free(import);
			break;
		}
		ordinal++;
	}

	free(class_ids);
	return imports;
}

static int compare_strings(const void *a, const void *b, void *user) {
	return strcmp((const char *)a, (const char *)b);
}

/**
 * \brief Returns a RzPVector<char*> containing the dex libraries
 */
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_bin_dex_libraries(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexMethodId *method_id;
	DexClassDef *class_def;
	RzPVector *libraries = NULL;
	ut32 *class_ids = NULL;
	void **vit;

	ut32 n_classes = rz_pvector_len(dex->class_defs);
	if (n_classes < 1) {
		return rz_pvector_new((RzPVectorFree)free);
	}

	class_ids = RZ_NEWS0(ut32, n_classes);
	if (!class_ids) {
		return NULL;
	}

	ut32 j = 0;
	rz_pvector_foreach (dex->class_defs, vit) {
		class_def = (DexClassDef *)*vit;
		class_ids[j] = class_def->class_idx;
		j++;
	}

	libraries = rz_pvector_new((RzPVectorFree)free);
	if (!libraries) {
		free(class_ids);
		return NULL;
	}

	rz_pvector_foreach (dex->method_ids, vit) {
		method_id = (DexMethodId *)*vit;
		bool class_found = false;
		for (ut32 i = 0; i < n_classes; ++i) {
			if (method_id->class_idx == class_ids[i]) {
				class_found = true;
				break;
			}
		}
		if (class_found) {
			continue;
		}

		char *object = dex_resolve_type_id(dex, method_id->class_idx);
		if (RZ_STR_ISEMPTY(object) || *object != 'L' || startswith(object, "Ljava/")) {
			free(object);
			continue;
		}

		char *p = object;
		if ((p = strchr(p, '/')) && (p = strchr(p + 1, '/'))) {
			*p = 0;
			p = rz_str_newf("%s/*;", object);
			free(object);
			object = p;
		}

		if (rz_pvector_find(libraries, object, compare_strings, NULL)) {
			free(object);
			continue;
		}

		if (!rz_pvector_push(libraries, object)) {
			free(object);
			break;
		}
	}

	free(class_ids);
	return libraries;
}

static bool dex_resolve_symbol_in_class_methods(RzBinDex *dex, DexClassDef *class_def, RzBinSpecialSymbol resolve, ut64 *paddr, ut64 *vaddr) {
	RzListIter *it;
	DexEncodedMethod *encoded_method = NULL;

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		if (encoded_method->method_idx >= rz_pvector_len(dex->method_ids)) {
			RZ_LOG_INFO("cannot find virtual method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}
		DexMethodId *method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);

		char *name = dex_resolve_string_id(dex, method_id->name_idx);
		if (!name) {
			continue;
		}
		if (resolve == RZ_BIN_SPECIAL_SYMBOL_ENTRY || resolve == RZ_BIN_SPECIAL_SYMBOL_INIT) {
			if (strcmp(name, "<init>") != 0 && strcmp(name, "<clinit>") != 0) {
				free(name);
				continue;
			}
		} else if (resolve == RZ_BIN_SPECIAL_SYMBOL_MAIN) {
			if (strcmp(name, "main") != 0) {
				free(name);
				continue;
			}
		}
		free(name);
		if (method_id->code_offset < RZ_DEX_RELOC_ADDRESS) {
			*vaddr = RZ_DEX_VIRT_ADDRESS + encoded_method->code_offset;
			*paddr = method_id->code_offset;
		} else {
			*vaddr = encoded_method->code_offset;
			*paddr = 0;
		}
		return true;
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		if (encoded_method->method_idx >= rz_pvector_len(dex->method_ids)) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}
		DexMethodId *method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);

		char *name = dex_resolve_string_id(dex, method_id->name_idx);
		if (!name) {
			continue;
		}
		if (resolve == RZ_BIN_SPECIAL_SYMBOL_ENTRY || resolve == RZ_BIN_SPECIAL_SYMBOL_INIT) {
			if (strcmp(name, "<init>") != 0 && strcmp(name, "<clinit>") != 0) {
				free(name);
				continue;
			}
		} else if (resolve == RZ_BIN_SPECIAL_SYMBOL_MAIN) {
			if (strcmp(name, "main") != 0) {
				free(name);
				continue;
			}
		}
		free(name);

		if (method_id->code_offset < RZ_DEX_RELOC_ADDRESS) {
			*vaddr = RZ_DEX_VIRT_ADDRESS + encoded_method->code_offset;
			*paddr = method_id->code_offset;
		} else {
			*vaddr = encoded_method->code_offset;
			*paddr = 0;
		}
		return true;
	}
	return false;
}

/**
 * \brief Returns a RzBinAddr pointer containing the resolved RzBinSpecialSymbol
 */
RZ_API RZ_OWN RzBinAddr *rz_bin_dex_resolve_symbol(RZ_NONNULL RzBinDex *dex, RzBinSpecialSymbol resolve) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	void **it;

	RzBinAddr *ret = RZ_NEW0(RzBinAddr);
	if (!ret) {
		return NULL;
	}
	ret->paddr = UT64_MAX;
	ret->vaddr = UT64_MAX;

	rz_pvector_foreach (dex->class_defs, it) {
		class_def = (DexClassDef *)*it;
		if (dex_resolve_symbol_in_class_methods(dex, class_def, resolve, &ret->paddr, &ret->vaddr)) {
			break;
		}
	}

	return ret;
}

static RzPVector /*<RzBinAddr *>*/ *dex_resolve_entrypoints_in_class(RzBinDex *dex, DexClassDef *class_def) {
	RzListIter *it;
	DexEncodedMethod *encoded_method = NULL;
	RzPVector *entrypoints = NULL;

	entrypoints = rz_pvector_new((RzPVectorFree)free);
	if (!entrypoints) {
		return NULL;
	}

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		if (!dex_is_static(encoded_method->access_flags)) {
			// entrypoints are static
			continue;
		}

		if (encoded_method->method_idx >= rz_pvector_len(dex->method_ids)) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}
		DexMethodId *method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);

		char *name = dex_resolve_string_id(dex, method_id->name_idx);
		if (!name) {
			continue;
		}

		if (strcmp(name, "main") != 0 && strcmp(name, "<init>") != 0 && strcmp(name, "<clinit>") != 0) {
			free(name);
			continue;
		}
		free(name);

		RzBinAddr *entrypoint = RZ_NEW0(RzBinAddr);
		if (!entrypoint) {
			break;
		}
		if (encoded_method->code_offset < RZ_DEX_RELOC_ADDRESS) {
			entrypoint->vaddr = RZ_DEX_VIRT_ADDRESS + encoded_method->code_offset;
			entrypoint->paddr = encoded_method->code_offset;
		} else {
			entrypoint->vaddr = encoded_method->code_offset;
			entrypoint->paddr = 0;
		}
		if (entrypoint && !rz_pvector_push(entrypoints, entrypoint)) {
			free(entrypoint);
		}
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		if (!dex_is_static(encoded_method->access_flags)) {
			// entrypoints are static
			continue;
		}

		if (encoded_method->method_idx >= rz_pvector_len(dex->method_ids)) {
			RZ_LOG_INFO("cannot find virtual method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

		DexMethodId *method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, encoded_method->method_idx);
		if (method_id->code_offset < 1) {
			// if there is no code, skip
			continue;
		}

		char *name = dex_resolve_string_id(dex, method_id->name_idx);
		if (!name) {
			continue;
		}

		if (strcmp(name, "main") != 0 && strcmp(name, "<init>") != 0 && strcmp(name, "<clinit>") != 0) {
			free(name);
			continue;
		}
		free(name);

		RzBinAddr *entrypoint = RZ_NEW0(RzBinAddr);
		if (!entrypoint) {
			break;
		}
		if (encoded_method->code_offset < RZ_DEX_RELOC_ADDRESS) {
			entrypoint->vaddr = RZ_DEX_VIRT_ADDRESS + encoded_method->code_offset;
			entrypoint->paddr = encoded_method->code_offset;
		} else {
			entrypoint->vaddr = encoded_method->code_offset;
			entrypoint->paddr = 0;
		}
		if (entrypoint && !rz_pvector_push(entrypoints, entrypoint)) {
			free(entrypoint);
		}
	}

	return entrypoints;
}

/**
 * \brief Returns a RzPVector<RzBinAddr*> containing the dex entripoints
 */
RZ_API RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_dex_entrypoints(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzPVector *entrypoints = NULL, *vec = NULL;
	void **it;

	entrypoints = rz_pvector_new((RzPVectorFree)free);
	if (!entrypoints) {
		return NULL;
	}

	rz_pvector_foreach (dex->class_defs, it) {
		class_def = (DexClassDef *)*it;
		vec = dex_resolve_entrypoints_in_class(dex, class_def);
		if (vec) {
			rz_pvector_join(entrypoints, vec);
			rz_pvector_free(vec);
		}
	}

	return entrypoints;
}

/**
 * This method will create a buffer filled with return-void values to mapped
 * to the imports and allow the code to generate xrefs pointing to the imports
 */
RZ_API RZ_BORROW RzBuffer *rz_bin_dex_relocations(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);
	return dex->relocs_buffer;
}

/**
 * \brief Returns the resolved string linked to the given method id
 */
RZ_API RZ_OWN char *rz_bin_dex_resolve_method_by_idx(RZ_NONNULL RzBinDex *dex, ut32 method_idx) {
	rz_return_val_if_fail(dex, NULL);

	if (method_idx >= rz_pvector_len(dex->method_ids)) {
		return NULL;
	}

	DexMethodId *method_id = (DexMethodId *)rz_pvector_at(dex->method_ids, method_idx);
	char *name = dex_resolve_string_id(dex, method_id->name_idx);
	if (!name) {
		return NULL;
	}

	char *proto = dex_resolve_proto_id(dex, name, method_id->proto_idx, false);
	RZ_FREE(name);
	if (!proto) {
		return NULL;
	}

	name = dex_resolve_type_id(dex, method_id->class_idx);
	if (!name) {
		free(proto);
		return NULL;
	}

	char *method = rz_str_newf("%s->%s", name, proto);
	free(name);
	free(proto);
	return method;
}

/**
 * \brief Returns the resolved string linked to the given field id
 */
RZ_API RZ_OWN char *rz_bin_dex_resolve_field_by_idx(RZ_NONNULL RzBinDex *dex, ut32 field_idx) {
	rz_return_val_if_fail(dex, NULL);

	if (field_idx >= rz_pvector_len(dex->field_ids)) {
		return NULL;
	}

	DexFieldId *field_id = (DexFieldId *)rz_pvector_at(dex->field_ids, field_idx);
	char *class_name = dex_resolve_type_id(dex, field_id->class_idx);
	if (!class_name) {
		return NULL;
	}

	char *name = dex_resolve_string_id(dex, field_id->name_idx);
	if (!name) {
		free(class_name);
		return NULL;
	}

	char *type = dex_resolve_type_id(dex, field_id->type_idx);
	if (!type) {
		free(class_name);
		free(name);
		return NULL;
	}

	char *method = rz_str_newf("%s->%s %s", class_name, name, type);

	free(type);
	free(class_name);
	free(name);
	return method;
}

/**
 * \brief Returns the resolved offset linked to the given string id
 */
RZ_API ut64 rz_bin_dex_resolve_string_offset_by_idx(RZ_NONNULL RzBinDex *dex, ut32 string_idx) {
	rz_return_val_if_fail(dex, UT64_MAX);

	DexString *string = dex_resolve_string_id_native(dex, string_idx);
	if (!string) {
		RZ_LOG_INFO("cannot find string with index %u\n", string_idx);
		return UT64_MAX;
	}
	return RZ_DEX_VIRT_ADDRESS + string->offset;
}

/**
 * \brief Returns the resolved offset linked to the given type id
 */
RZ_API ut64 rz_bin_dex_resolve_type_id_offset_by_idx(RZ_NONNULL RzBinDex *dex, ut32 type_idx) {
	rz_return_val_if_fail(dex, UT64_MAX);

	if (type_idx >= dex->type_ids_size) {
		RZ_LOG_INFO("cannot find type_id with index %u\n", type_idx);
		return UT64_MAX;
	}
	DexTypeId type_id = dex->types[type_idx];
	return rz_bin_dex_resolve_string_offset_by_idx(dex, type_id);
}

/**
 * \brief Returns the resolved offset linked to the given method id
 */
RZ_API ut64 rz_bin_dex_resolve_method_offset_by_idx(RZ_NONNULL RzBinDex *dex, ut32 method_idx) {
	rz_return_val_if_fail(dex, UT64_MAX);

	if (method_idx >= rz_pvector_len(dex->method_ids)) {
		RZ_LOG_INFO("cannot find method with index %u\n", method_idx);
		return UT64_MAX;
	}

	DexMethodId *method = (DexMethodId *)rz_pvector_at(dex->method_ids, method_idx);
	if (method->code_offset) {
		if (method->code_offset < RZ_DEX_RELOC_ADDRESS) {
			return RZ_DEX_VIRT_ADDRESS + method->code_offset;
		}
		return method->code_offset;
	}
	return UT64_MAX;
}

/**
 * \brief Returns the resolved string linked to the given type id
 */
RZ_API RZ_OWN char *rz_bin_dex_resolve_type_id_by_idx(RZ_NONNULL RzBinDex *dex, ut32 type_idx) {
	rz_return_val_if_fail(dex, NULL);

	if (type_idx >= dex->type_ids_size) {
		RZ_LOG_INFO("cannot find type_id with index %u\n", type_idx);
		return NULL;
	}
	DexTypeId type_id = dex->types[type_idx];
	return rz_bin_dex_resolve_string_by_idx(dex, type_id);
}

/**
 * \brief Returns the resolved string linked to the given string id
 */
RZ_API RZ_OWN char *rz_bin_dex_resolve_string_by_idx(RZ_NONNULL RzBinDex *dex, ut32 string_idx) {
	rz_return_val_if_fail(dex, NULL);

	return dex_resolve_string_id(dex, string_idx);
}

/**
 * \brief Returns the resolved string linked to the given class id
 */
RZ_API RZ_OWN char *rz_bin_dex_resolve_class_by_idx(RZ_NONNULL RzBinDex *dex, ut32 class_idx) {
	rz_return_val_if_fail(dex, NULL);

	return dex_resolve_type_id(dex, class_idx);
}

/**
 * \brief Returns the resolved string linked to the given prototype id
 */
RZ_API RZ_OWN char *rz_bin_dex_resolve_proto_by_idx(RZ_NONNULL RzBinDex *dex, ut32 proto_idx) {
	rz_return_val_if_fail(dex, NULL);

	return dex_resolve_proto_id(dex, "", proto_idx, false);
}

/**
 * \brief Sets the RzBinHash dex checksum (adler32)
 */
RZ_API void rz_bin_dex_checksum(RZ_NONNULL RzBinDex *dex, RZ_NONNULL RzBinHash *hash) {
	rz_return_if_fail(dex && hash);
	hash->type = "adler32";
	hash->len = sizeof(dex->checksum);
	hash->addr = dex->checksum_offset;
	hash->from = dex->checksum_offset + sizeof(dex->checksum);
	hash->to = dex->file_size - hash->from;
	rz_write_le32(hash->buf, dex->checksum);
}

/**
 * \brief Sets the RzBinHash dex digest (sha1)
 */
RZ_API void rz_bin_dex_sha1(RZ_NONNULL RzBinDex *dex, RZ_NONNULL RzBinHash *hash) {
	rz_return_if_fail(dex && hash);
	hash->type = "sha1";
	hash->len = 20;
	hash->addr = dex->signature_offset;
	hash->from = dex->signature_offset + sizeof(dex->signature);
	hash->to = dex->file_size - hash->from;
	memcpy(hash->buf, dex->signature, sizeof(dex->signature));
}

/**
 * \brief Returns the dex version (string format)
 */
RZ_API RZ_OWN char *rz_bin_dex_version(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);
	// https://cs.android.com/android/platform/superproject/+/master:dalvik/dx/src/com/android/dex/DexFormat.java;l=55;bpv=1;bpt=0
	// https://developer.android.com/studio/releases/platforms
	if (startswith((char *)dex->version, "009")) {
		return rz_str_dup("Android M3 release (Nov-Dec 2007)");
	} else if (startswith((char *)dex->version, "013")) {
		return rz_str_dup("Android M5 release (Feb-Mar 2008)");
	} else if (startswith((char *)dex->version, "035")) {
		return rz_str_dup("Android 3.2 (API level 13 and earlier)");
	} else if (startswith((char *)dex->version, "037")) {
		return rz_str_dup("Android 7 (API level 24 and earlier)");
	} else if (startswith((char *)dex->version, "038")) {
		return rz_str_dup("Android 8 (API level 26 and earlier)");
	} else if (startswith((char *)dex->version, "039")) {
		return rz_str_dup("Android 9 (API level 28 and earlier)");
	} else if (startswith((char *)dex->version, "040")) {
		return rz_str_dup("Android 10+ (Aug 2019)");
	}
	return NULL;
}

/**
 * \brief Returns the dex debug info RzBin values
 */
RZ_API ut64 rz_bin_dex_debug_info(RZ_NONNULL RzBinDex *dex) {
	rz_return_val_if_fail(dex, 0);
	// TODO
	return 0;
}
