// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dex.h"
#include <rz_util.h>

#define DEX_INVALID_CLASS  "Lunknown_class;"
#define DEX_INVALID_METHOD "unknown_method"

typedef struct dex_access_flags_readable_t {
	ut32 flag;
	const char *readable;
} DexAccessFlagsReadable;

#define dex_is_static(a)  (a & ACCESS_FLAG_STATIC)
#define dex_is_varargs(a) (a & ACCESS_FLAG_VARARGS)

#define dex_fail_if_eof(b, o, s, g) \
	do { \
		(o) = rz_buf_tell((b)); \
		if ((o) >= (s)) { \
			goto g; \
		} \
	} while (0)

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
	data = malloc(size + 1);
	if (!data || rz_buf_read(buf, (ut8 *)data, size) != size) {
		rz_warn_if_reached();
		free(data);
		return NULL;
	}
	data[size] = 0;

	string = RZ_NEW0(DexString);
	if (!string) {
		rz_warn_if_reached();
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

	proto_id->shorty_idx = /*       */ rz_buf_read_le32(buf);
	proto_id->return_type_idx = /*  */ rz_buf_read_le32(buf);
	proto_id->offset = offset;

	parameters_offset = rz_buf_read_le32(buf);
	if (parameters_offset > 0) {
		ut32 count = rz_buf_read_le32_at(buf, parameters_offset);

		proto_id->type_list_size = count;
		proto_id->type_list = RZ_NEWS(ut16, count);
		if (!proto_id->type_list) {
			rz_warn_if_reached();
			goto dex_proto_id_new_fail;
		}

		parameters_offset += sizeof(ut32);
		for (ut32 i = 0; i < count; ++i, parameters_offset += sizeof(ut16)) {
			proto_id->type_list[i] = rz_buf_read_le16_at(buf, parameters_offset);
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

	field_id->class_idx = /**/ rz_buf_read_le16(buf);
	field_id->type_idx = /* */ rz_buf_read_le16(buf);
	field_id->name_idx = /* */ rz_buf_read_le32(buf);
	field_id->offset = offset;
	return field_id;
}

#define dex_method_id_free free
static DexMethodId *dex_method_id_new(RzBuffer *buf, ut64 offset) {
	DexMethodId *method_id = RZ_NEW0(DexMethodId);
	if (!method_id) {
		return NULL;
	}

	method_id->class_idx = /**/ rz_buf_read_le16(buf);
	method_id->proto_idx = /**/ rz_buf_read_le16(buf);
	method_id->name_idx = /* */ rz_buf_read_le32(buf);
	method_id->offset = offset;
	return method_id;
}

static void dex_class_def_free(DexClassDef *class_def) {
	if (!class_def) {
		return;
	}
	rz_list_free(class_def->static_fields);
	rz_list_free(class_def->instance_fields);
	rz_list_free(class_def->direct_methods);
	rz_list_free(class_def->virtual_methods);
	free(class_def);
}

static DexClassDef *dex_class_def_new(RzBuffer *buf, ut64 offset, ut64 base) {
	DexClassDef *class_def = RZ_NEW0(DexClassDef);
	if (!class_def) {
		return NULL;
	}

	ut64 static_fields_size = 0;
	ut64 instance_fields_size = 0;
	ut64 direct_methods_size = 0;
	ut64 virtual_methods_size = 0;
	ut64 diff_value;
	ut64 diff_value_prev;
	ut64 code_offset;

	class_def->static_fields = /*  */ rz_list_newf((RzListFree)free);
	class_def->instance_fields = /**/ rz_list_newf((RzListFree)free);
	class_def->direct_methods = /* */ rz_list_newf((RzListFree)free);
	class_def->virtual_methods = /**/ rz_list_newf((RzListFree)free);

	class_def->class_idx = /*           */ rz_buf_read_le32(buf);
	class_def->access_flags = /*        */ rz_buf_read_le32(buf);
	class_def->superclass_idx = /*      */ rz_buf_read_le32(buf);
	class_def->interfaces_offset = /*   */ rz_buf_read_le32(buf);
	class_def->source_file_idx = /*     */ rz_buf_read_le32(buf);
	class_def->annotations_offset = /*  */ rz_buf_read_le32(buf);
	class_def->class_data_offset = /*   */ rz_buf_read_le32(buf);
	class_def->static_values_offset = /**/ rz_buf_read_le32(buf);
	class_def->offset = offset;

	if (rz_buf_seek(buf, class_def->class_data_offset, RZ_BUF_SET) < 0) {
		rz_warn_if_reached();
		goto dex_class_def_new_fail;
	}

	rz_buf_uleb128(buf, &static_fields_size);
	rz_buf_uleb128(buf, &instance_fields_size);
	rz_buf_uleb128(buf, &direct_methods_size);
	rz_buf_uleb128(buf, &virtual_methods_size);

	for (ut64 i = 0; i < static_fields_size; ++i) {
		DexEncodedField *encoded_field = RZ_NEW0(DexEncodedField);
		if (!encoded_field) {
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}

		encoded_field->offset = rz_buf_tell(buf) + base;
		rz_buf_uleb128(buf, &diff_value);
		rz_buf_uleb128(buf, &encoded_field->access_flags);

		if (i < 1) {
			encoded_field->field_idx = diff_value;
			diff_value_prev = diff_value;
		} else {
			encoded_field->field_idx = diff_value_prev + diff_value;
			diff_value_prev = encoded_field->field_idx;
		}

		if (!rz_list_append(class_def->static_fields, encoded_field)) {
			free(encoded_field);
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}
	}

	for (ut64 i = 0; i < instance_fields_size; ++i) {
		DexEncodedField *encoded_field = RZ_NEW0(DexEncodedField);
		if (!encoded_field) {
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}

		encoded_field->offset = rz_buf_tell(buf) + base;
		rz_buf_uleb128(buf, &diff_value);
		rz_buf_uleb128(buf, &encoded_field->access_flags);

		if (i < 1) {
			encoded_field->field_idx = diff_value;
			diff_value_prev = diff_value;
		} else {
			encoded_field->field_idx = diff_value_prev + diff_value;
			diff_value_prev = encoded_field->field_idx;
		}

		if (!rz_list_append(class_def->instance_fields, encoded_field)) {
			free(encoded_field);
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}
	}

	for (ut64 i = 0; i < direct_methods_size; ++i) {
		DexEncodedMethod *encoded_method = RZ_NEW0(DexEncodedMethod);
		if (!encoded_method) {
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}

		encoded_method->offset = rz_buf_tell(buf) + base;
		rz_buf_uleb128(buf, &diff_value);
		rz_buf_uleb128(buf, &encoded_method->access_flags);
		rz_buf_uleb128(buf, &code_offset);

		if (i < 1) {
			encoded_method->method_idx = diff_value;
			diff_value_prev = diff_value;
		} else {
			encoded_method->method_idx = diff_value_prev + diff_value;
			diff_value_prev = encoded_method->method_idx;
		}

		if (code_offset > 0) {
			encoded_method->registers_size = /*   */ rz_buf_read_le16_at(buf, code_offset);
			encoded_method->ins_size = /*         */ rz_buf_read_le16_at(buf, code_offset + 2);
			encoded_method->outs_size = /*        */ rz_buf_read_le16_at(buf, code_offset + 4);
			encoded_method->tries_size = /*       */ rz_buf_read_le16_at(buf, code_offset + 6);
			encoded_method->debug_info_offset = /**/ rz_buf_read_le32_at(buf, code_offset + 8);
			encoded_method->code_size = /*        */ rz_buf_read_le32_at(buf, code_offset + 12);
			encoded_method->code_size *= sizeof(ut16); // code ushort[insns_size]
			encoded_method->code_offset = code_offset + 16 + base;
		}

		if (!rz_list_append(class_def->direct_methods, encoded_method)) {
			free(encoded_method);
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}
	}

	for (ut64 i = 0; i < virtual_methods_size; ++i) {
		DexEncodedMethod *encoded_method = RZ_NEW0(DexEncodedMethod);
		if (!encoded_method) {
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}

		encoded_method->offset = rz_buf_tell(buf) + base;
		rz_buf_uleb128(buf, &diff_value);
		rz_buf_uleb128(buf, &encoded_method->access_flags);
		rz_buf_uleb128(buf, &code_offset);

		if (i < 1) {
			encoded_method->method_idx = diff_value;
			diff_value_prev = diff_value;
		} else {
			encoded_method->method_idx = diff_value_prev + diff_value;
			diff_value_prev = encoded_method->method_idx;
		}

		if (code_offset > 0) {
			encoded_method->registers_size = /*   */ rz_buf_read_le16_at(buf, code_offset);
			encoded_method->ins_size = /*         */ rz_buf_read_le16_at(buf, code_offset + 2);
			encoded_method->outs_size = /*        */ rz_buf_read_le16_at(buf, code_offset + 4);
			encoded_method->tries_size = /*       */ rz_buf_read_le16_at(buf, code_offset + 6);
			encoded_method->debug_info_offset = /**/ rz_buf_read_le32_at(buf, code_offset + 8);
			encoded_method->code_size = /*        */ rz_buf_read_le32_at(buf, code_offset + 12);
			encoded_method->code_size *= sizeof(ut16); // code ushort[insns_size]
			encoded_method->code_offset = code_offset + 16 + base;
		}

		if (!rz_list_append(class_def->virtual_methods, encoded_method)) {
			free(encoded_method);
			rz_warn_if_reached();
			goto dex_class_def_new_fail;
		}
	}

	return class_def;

dex_class_def_new_fail:
	dex_class_def_free(class_def);
	return NULL;
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
	rz_buf_read(buf, dex->magic, sizeof(dex->magic));
	rz_buf_read(buf, dex->version, sizeof(dex->version));
	dex->checksum_offset = rz_buf_tell(buf) + base;
	dex->checksum = rz_buf_read_le32(buf);
	dex->signature_offset = rz_buf_tell(buf) + base;
	rz_buf_read(buf, dex->signature, sizeof(dex->signature));
	dex->file_size = /*        */ rz_buf_read_le32(buf);
	dex->header_size = /*      */ rz_buf_read_le32(buf);
	dex->endian_tag = /*       */ rz_buf_read_le32(buf);

	dex->link_size = /*        */ rz_buf_read_le32(buf);
	dex->link_offset = /*      */ rz_buf_read_le32(buf);
	//dex_fail_if_bad_ids(dex->link, sizeof(ut32), buffer_size, dex_parse_bad);

	dex->map_offset = /*       */ rz_buf_read_le32(buf);

	dex->string_ids_size = /*  */ rz_buf_read_le32(buf);
	dex->string_ids_offset = /**/ rz_buf_read_le32(buf);
	// string_ids points to an array of offsets.
	dex_fail_if_bad_ids(dex->string_ids, sizeof(ut32), buffer_size, dex_parse_bad);

	dex->type_ids_size = /*    */ rz_buf_read_le32(buf);
	dex->type_ids_offset = /*  */ rz_buf_read_le32(buf);
	dex_fail_if_bad_ids(dex->type_ids, DEX_TYPE_ID_SIZE, buffer_size, dex_parse_bad);

	dex->proto_ids_size = /*   */ rz_buf_read_le32(buf);
	dex->proto_ids_offset = /* */ rz_buf_read_le32(buf);
	dex_fail_if_bad_ids(dex->proto_ids, DEX_PROTO_ID_SIZE, buffer_size, dex_parse_bad);

	dex->field_ids_size = /*   */ rz_buf_read_le32(buf);
	dex->field_ids_offset = /* */ rz_buf_read_le32(buf);
	dex_fail_if_bad_ids(dex->field_ids, DEX_FIELD_ID_SIZE, buffer_size, dex_parse_bad);

	dex->method_ids_size = /*  */ rz_buf_read_le32(buf);
	dex->method_ids_offset = /**/ rz_buf_read_le32(buf);
	dex_fail_if_bad_ids(dex->method_ids, DEX_METHOD_ID_SIZE, buffer_size, dex_parse_bad);

	dex->class_defs_size = /*  */ rz_buf_read_le32(buf);
	dex->class_defs_offset = /**/ rz_buf_read_le32(buf);
	//dex_fail_if_bad_ids(dex->class_defs, sizeof(ut32), buffer_size, dex_parse_bad);

	dex->data_size = /*        */ rz_buf_read_le32(buf);
	dex->data_offset = /*      */ rz_buf_read_le32(buf);
	//dex_fail_if_bad_ids(dex->data, sizeof(ut32), buffer_size, dex_parse_bad);

	dex_fail_if_eof(buf, offset, buffer_size, dex_parse_bad);

	/* Strings */
	offset = dex->string_ids_offset;
	for (ut32 i = 0; i < dex->string_ids_size; ++i, offset += sizeof(ut32)) {
		ut32 string_offset = rz_buf_read_le32_at(buf, offset);

		if (rz_buf_seek(buf, string_offset, RZ_BUF_SET) < 0) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		DexString *string = dex_string_new(buf, base + string_offset, &read);
		if (!string) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		if (!rz_list_append(dex->strings, string)) {
			rz_warn_if_reached();
			dex_string_free(string);
			goto dex_parse_bad;
		}
	}

	/* Type Ids */
	dex->types = RZ_NEWS0(DexTypeId, dex->type_ids_size);
	if (!dex->types) {
		rz_warn_if_reached();
		goto dex_parse_bad;
	}
	if (rz_buf_seek(buf, dex->type_ids_offset, RZ_BUF_SET) < 0) {
		rz_warn_if_reached();
		goto dex_parse_bad;
	}
	for (ut32 i = 0; i < dex->type_ids_size; ++i) {
		dex->types[i] = rz_buf_read_le32(buf);
	}

	/* Proto Ids */
	offset = dex->proto_ids_offset;
	for (ut32 i = 0; i < dex->proto_ids_size; ++i, offset += DEX_PROTO_ID_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		DexProtoId *proto_id = dex_proto_id_new(buf, base + offset);
		if (!proto_id) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		if (!rz_list_append(dex->proto_ids, proto_id)) {
			rz_warn_if_reached();
			dex_proto_id_free(proto_id);
			goto dex_parse_bad;
		}
	}

	/* Field Ids */
	offset = dex->field_ids_offset;
	for (ut32 i = 0; i < dex->field_ids_size; ++i, offset += DEX_FIELD_ID_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		DexFieldId *field_id = dex_field_id_new(buf, base + offset);
		if (!field_id) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		if (!rz_list_append(dex->field_ids, field_id)) {
			rz_warn_if_reached();
			dex_field_id_free(field_id);
			goto dex_parse_bad;
		}
	}

	/* Method Ids */
	offset = dex->method_ids_offset;
	for (ut32 i = 0; i < dex->method_ids_size; ++i, offset += DEX_METHOD_ID_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		DexMethodId *method_id = dex_method_id_new(buf, base + offset);
		if (!method_id) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		if (!rz_list_append(dex->method_ids, method_id)) {
			rz_warn_if_reached();
			dex_method_id_free(method_id);
			goto dex_parse_bad;
		}
	}

	/* Class Defs */
	offset = dex->class_defs_offset;
	for (ut32 i = 0; i < dex->class_defs_size; ++i, offset += DEX_CLASS_DEF_SIZE) {
		if (rz_buf_seek(buf, offset, RZ_BUF_SET) < 0) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		DexClassDef *class_def = dex_class_def_new(buf, base + offset, base);
		if (!class_def) {
			rz_warn_if_reached();
			goto dex_parse_bad;
		}
		if (!rz_list_append(dex->class_defs, class_def)) {
			rz_warn_if_reached();
			dex_class_def_free(class_def);
			goto dex_parse_bad;
		}
	}

	return true;

dex_parse_bad:
	rz_bin_dex_free(dex);
	return false;
}

RZ_API void rz_bin_dex_free(RzBinDex *dex) {
	if (!dex) {
		return;
	}

	rz_list_free(dex->map_items);
	rz_list_free(dex->strings);
	rz_list_free(dex->proto_ids);
	rz_list_free(dex->field_ids);
	rz_list_free(dex->method_ids);
	rz_list_free(dex->class_defs);

	free(dex->types);
	free(dex);
}

RZ_API RzBinDex *rz_bin_dex_new(RzBuffer *buf, ut64 base, Sdb *kv) {
	rz_return_val_if_fail(buf, NULL);

	RzBinDex *dex = (RzBinDex *)RZ_NEW0(RzBinDex);
	if (!dex) {
		return NULL;
	}

	dex->strings = rz_list_newf((RzListFree)dex_string_free);
	if (!dex->strings) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->proto_ids = rz_list_newf((RzListFree)dex_proto_id_free);
	if (!dex->proto_ids) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->field_ids = rz_list_newf((RzListFree)dex_field_id_free);
	if (!dex->field_ids) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->method_ids = rz_list_newf((RzListFree)dex_method_id_free);
	if (!dex->method_ids) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	dex->class_defs = rz_list_newf((RzListFree)dex_class_def_free);
	if (!dex->class_defs) {
		rz_bin_dex_free(dex);
		return NULL;
	}
	//dex->map_items

	if (!dex_parse(dex, base, buf)) {
		return NULL;
	}

	return dex;
}

static char *dex_access_flags_readable(ut32 access_flags) {
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

RZ_API RzList /*<RzBinString*>*/ *rz_bin_dex_strings(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexString *string;
	RzListIter *it;
	RzList *strings = rz_list_newf(rz_bin_string_free);
	if (!strings) {
		return NULL;
	}

	ut32 ordinal = 0;
	rz_list_foreach (dex->strings, it, string) {
		RzBinString *bstr = RZ_NEW0(RzBinString);
		if (!bstr) {
			rz_warn_if_reached();
			continue;
		}
		bstr->paddr = string->offset;
		bstr->ordinal = ordinal;
		bstr->length = string->size;
		bstr->size = string->size;
		bstr->string = rz_str_ndup(string->data, string->size);
		bstr->type = RZ_STRING_TYPE_UTF8;
		if (!rz_list_append(strings, bstr)) {
			free(bstr);
		}
		ordinal++;
	}
	return strings;
}

static char *dex_resolve_string_id(RzBinDex *dex, ut32 string_idx) {
	DexString *string = (DexString *)rz_list_get_n(dex->strings, string_idx);
	if (!string) {
		RZ_LOG_ERROR("cannot find string with index %u\n", string_idx);
		return NULL;
	}
	return rz_str_ndup(string->data, string->size);
}

static char *dex_resolve_type_id(RzBinDex *dex, ut32 type_idx) {
	if (type_idx >= dex->type_ids_size) {
		RZ_LOG_ERROR("cannot find type_id with index %u\n", type_idx);
		return NULL;
	}
	DexTypeId type_id = dex->types[type_idx];
	return dex_resolve_string_id(dex, type_id);
}

static char *dex_resolve_proto_id(RzBinDex *dex, const char *name, ut32 proto_idx, bool varargs) {
	DexProtoId *proto_id = (DexProtoId *)rz_list_get_n(dex->proto_ids, proto_idx);
	if (!proto_id) {
		RZ_LOG_ERROR("cannot find proto_id with index %u out of %u\n", proto_idx, rz_list_length(dex->proto_ids));
		return NULL;
	}

	if (proto_id->return_type_idx >= dex->type_ids_size) {
		RZ_LOG_ERROR("cannot find return type id with index %u\n", proto_id->return_type_idx);
		return NULL;
	}

	RzStrBuf *sb = rz_strbuf_new(name);
	if (!sb) {
		rz_warn_if_reached();
		return NULL;
	}

	DexString *return_type = (DexString *)rz_list_get_n(dex->strings, dex->types[proto_id->return_type_idx]);
	if (!return_type) {
		RZ_LOG_ERROR("cannot find return type string with index %u\n", proto_id->return_type_idx);
		rz_strbuf_free(sb);
		return NULL;
	}

	rz_strbuf_append(sb, "(");
	for (ut32 i = 0; i < proto_id->type_list_size; ++i) {
		ut32 type_idx = proto_id->type_list[i];
		const DexString *param = (const DexString *)rz_list_get_n(dex->strings, dex->types[type_idx]);
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
	//if (access_flags & ACCESS_FLAG_INTERFACE) {
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
	//if (access_flags & ACCESS_FLAG_ANNOTATION) {
	//	flags |= RZ_BIN_METH_ANNOTATION;
	//}
	// RZ_BIN_METH_ENUM does not exists
	//if (access_flags & ACCESS_FLAG_ENUM) {
	//	flags |= RZ_BIN_METH_ENUM;
	//}
	// RZ_BIN_METH_MODULE does not exists
	//if (access_flags & ACCESS_FLAG_MODULE) {
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

static char *dex_resolve_library(const char *library) {
	if (!library || library[0] != 'L') {
		return NULL;
	}
	char *demangled = strdup(library + 1);
	rz_str_replace_ch(demangled, '/', '.', 1);
	demangled[strlen(demangled) - 1] = 0;
	return demangled;
}

static RzList /*<RzBinSymbol*>*/ *dex_resolve_methods_in_class(RzBinDex *dex, DexClassDef *class_def) {
	RzList *methods = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!methods) {
		return NULL;
	}
	bool varargs = false;
	DexMethodId *method_id = NULL;
	DexEncodedMethod *encoded_method = NULL;
	RzListIter *it = NULL;

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

		RzBinSymbol *symbol = RZ_NEW0(RzBinSymbol);
		if (!symbol) {
			rz_warn_if_reached();
			break;
		}

		varargs = dex_is_varargs(encoded_method->access_flags);
		symbol->name = dex_resolve_string_id(dex, method_id->name_idx);
		symbol->classname = dex_resolve_type_id(dex, method_id->class_idx);
		symbol->libname = dex_resolve_library(symbol->classname);
		symbol->dname = dex_resolve_proto_id(dex, symbol->name, method_id->proto_idx, varargs);
		symbol->bind = dex_is_static(encoded_method->access_flags) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
		symbol->is_imported = false;
		symbol->visibility = encoded_method->access_flags & UT32_MAX;
		symbol->visibility_str = dex_access_flags_readable(symbol->visibility);
		symbol->vaddr = encoded_method->code_offset;
		symbol->paddr = encoded_method->code_offset;
		symbol->size = encoded_method->code_size;
		symbol->ordinal = encoded_method->method_idx;
		symbol->method_flags = dex_access_flags_to_bin_flags(encoded_method->access_flags);
		symbol->type = RZ_BIN_TYPE_METH_STR;

		if (!rz_list_append(methods, symbol)) {
			rz_bin_symbol_free(symbol);
			rz_warn_if_reached();
			break;
		}
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find virtual method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

		RzBinSymbol *symbol = RZ_NEW0(RzBinSymbol);
		if (!symbol) {
			rz_warn_if_reached();
			break;
		}

		varargs = dex_is_varargs(encoded_method->access_flags);
		symbol->name = dex_resolve_string_id(dex, method_id->name_idx);
		symbol->classname = dex_resolve_type_id(dex, method_id->class_idx);
		symbol->libname = dex_resolve_library(symbol->classname);
		symbol->dname = dex_resolve_proto_id(dex, symbol->name, method_id->proto_idx, varargs);
		symbol->bind = dex_is_static(encoded_method->access_flags) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
		symbol->is_imported = false;
		symbol->visibility = encoded_method->access_flags & UT32_MAX;
		symbol->visibility_str = dex_access_flags_readable(encoded_method->access_flags);
		symbol->vaddr = encoded_method->code_offset;
		symbol->paddr = encoded_method->code_offset;
		symbol->size = encoded_method->code_size;
		symbol->ordinal = encoded_method->method_idx;
		symbol->method_flags = dex_access_flags_to_bin_flags(encoded_method->access_flags);
		symbol->type = RZ_BIN_TYPE_METH_STR;

		if (!rz_list_append(methods, symbol)) {
			rz_bin_symbol_free(symbol);
			rz_warn_if_reached();
			break;
		}
	}
	return methods;
}

static RzList /*<RzBinField*>*/ *dex_resolve_fields_in_class(RzBinDex *dex, DexClassDef *class_def) {
	RzList *fields = rz_list_newf((RzListFree)rz_bin_field_free);
	if (!fields) {
		return NULL;
	}
	DexFieldId *field_id = NULL;
	DexEncodedField *encoded_field = NULL;
	RzListIter *it = NULL;

	rz_list_foreach (class_def->static_fields, it, encoded_field) {
		field_id = (DexFieldId *)rz_list_get_n(dex->field_ids, encoded_field->field_idx);
		if (!field_id) {
			RZ_LOG_INFO("cannot find static field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		}

		RzBinField *field = RZ_NEW0(RzBinField);
		if (!field) {
			rz_warn_if_reached();
			break;
		}

		field->vaddr = encoded_field->offset;
		field->paddr = encoded_field->offset;
		field->visibility = encoded_field->access_flags & UT32_MAX;
		field->visibility_str = dex_access_flags_readable(encoded_field->access_flags | ACCESS_FLAG_STATIC);
		field->name = dex_resolve_string_id(dex, field_id->name_idx);
		field->type = dex_resolve_type_id(dex, field_id->type_idx);
		field->flags = dex_access_flags_to_bin_flags(encoded_field->access_flags | ACCESS_FLAG_STATIC);

		if (!rz_list_append(fields, field)) {
			rz_bin_field_free(field);
			rz_warn_if_reached();
			break;
		}
	}

	rz_list_foreach (class_def->instance_fields, it, encoded_field) {
		field_id = (DexFieldId *)rz_list_get_n(dex->field_ids, encoded_field->field_idx);
		if (!field_id) {
			RZ_LOG_INFO("cannot find instance field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		}

		RzBinField *field = RZ_NEW0(RzBinField);
		if (!field) {
			rz_warn_if_reached();
			break;
		}

		field->vaddr = encoded_field->offset;
		field->paddr = encoded_field->offset;
		field->visibility = encoded_field->access_flags & UT32_MAX;
		field->visibility_str = dex_access_flags_readable(encoded_field->access_flags);
		field->name = dex_resolve_string_id(dex, field_id->name_idx);
		field->type = dex_resolve_type_id(dex, field_id->type_idx);
		field->flags = dex_access_flags_to_bin_flags(encoded_field->access_flags);

		if (!rz_list_append(fields, field)) {
			rz_bin_field_free(field);
			rz_warn_if_reached();
			break;
		}
	}
	return fields;
}

static RzList /*<RzBinSymbol*>*/ *dex_resolve_fields_in_class_as_symbols(RzBinDex *dex, DexClassDef *class_def) {
	RzList *fields = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!fields) {
		return NULL;
	}
	DexFieldId *field_id = NULL;
	DexEncodedField *encoded_field = NULL;
	RzListIter *it = NULL;

	rz_list_foreach (class_def->static_fields, it, encoded_field) {
		field_id = (DexFieldId *)rz_list_get_n(dex->field_ids, encoded_field->field_idx);
		if (!field_id) {
			RZ_LOG_INFO("cannot find static field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		}

		RzBinSymbol *field = RZ_NEW0(RzBinSymbol);
		if (!field) {
			rz_warn_if_reached();
			break;
		}

		field->name = dex_resolve_string_id(dex, field_id->name_idx);
		field->classname = dex_resolve_type_id(dex, field_id->class_idx);
		field->libname = dex_resolve_library(field->classname);
		field->bind = dex_is_static(encoded_field->access_flags) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
		field->is_imported = false;
		field->visibility = encoded_field->access_flags & UT32_MAX;
		field->visibility_str = dex_access_flags_readable(encoded_field->access_flags);
		field->vaddr = encoded_field->offset;
		field->paddr = encoded_field->offset;
		field->ordinal = encoded_field->field_idx;
		field->method_flags = dex_access_flags_to_bin_flags(encoded_field->access_flags);
		field->type = RZ_BIN_TYPE_FIELD_STR;

		if (!rz_list_append(fields, field)) {
			rz_bin_symbol_free(field);
			rz_warn_if_reached();
			break;
		}
	}

	rz_list_foreach (class_def->instance_fields, it, encoded_field) {
		field_id = (DexFieldId *)rz_list_get_n(dex->field_ids, encoded_field->field_idx);
		if (!field_id) {
			RZ_LOG_INFO("cannot find instance field with index %" PFMT64u "\n", encoded_field->field_idx);
			continue;
		}

		RzBinSymbol *field = RZ_NEW0(RzBinSymbol);
		if (!field) {
			rz_warn_if_reached();
			break;
		}

		field->name = dex_resolve_string_id(dex, field_id->name_idx);
		field->classname = dex_resolve_type_id(dex, field_id->class_idx);
		field->libname = dex_resolve_library(field->classname);
		field->bind = dex_is_static(encoded_field->access_flags) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
		field->is_imported = false;
		field->visibility = encoded_field->access_flags & UT32_MAX;
		field->visibility_str = dex_access_flags_readable(encoded_field->access_flags);
		field->vaddr = encoded_field->offset;
		field->paddr = encoded_field->offset;
		field->ordinal = encoded_field->field_idx;
		field->method_flags = dex_access_flags_to_bin_flags(encoded_field->access_flags);
		field->type = RZ_BIN_TYPE_FIELD_STR;

		if (!rz_list_append(fields, field)) {
			rz_bin_symbol_free(field);
			rz_warn_if_reached();
			break;
		}
	}
	return fields;
}

static void free_rz_bin_class(RzBinClass *bclass) {
	if (!bclass) {
		return;
	}
	rz_list_free(bclass->methods);
	rz_list_free(bclass->fields);
	free(bclass->name);
	free(bclass->super);
	free(bclass->visibility_str);
	free(bclass);
}

RZ_API RzList /*<RzBinClass*>*/ *rz_bin_dex_classes(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzBinClass *bclass = NULL;
	RzList *classes = NULL;
	RzListIter *it;

	classes = rz_list_newf((RzListFree)free_rz_bin_class);
	if (!classes) {
		return NULL;
	}

	rz_list_foreach (dex->class_defs, it, class_def) {
		bclass = RZ_NEW0(RzBinClass);
		if (!bclass) {
			rz_warn_if_reached();
			break;
		}

		bclass->name = dex_resolve_type_id(dex, class_def->class_idx);
		bclass->super = dex_resolve_type_id(dex, class_def->superclass_idx);
		bclass->visibility = class_def->access_flags;
		bclass->visibility_str = dex_access_flags_readable(class_def->access_flags);
		bclass->index = class_def->class_idx;
		bclass->addr = class_def->offset;
		bclass->methods = dex_resolve_methods_in_class(dex, class_def);
		bclass->fields = dex_resolve_fields_in_class(dex, class_def);

		if (!rz_list_append(classes, bclass)) {
			free_rz_bin_class(bclass);
			break;
		}
	}

	return classes;
}

static RzBinSection *section_new(const char *name, ut32 perm, ut32 size, ut64 address) {
	RzBinSection *section = RZ_NEW0(RzBinSection);
	if (!section) {
		rz_warn_if_reached();
		return NULL;
	}
	section->name = strdup(name);
	section->paddr = section->vaddr = address;
	section->size = section->vsize = size;
	section->perm = perm;
	return section;
}

static void dex_resolve_code_section_in_class(RzBinDex *dex, DexClassDef *class_def, RzList *sections) {
	DexEncodedMethod *encoded_method = NULL;
	DexMethodId *method_id = NULL;
	RzListIter *it = NULL;
	RzBinSection *section;

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		if (encoded_method->code_size < 1) {
			continue;
		}

		method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

		char *class_name = dex_resolve_type_id(dex, class_def->class_idx);
		if (!class_name) {
			class_name = strdup(DEX_INVALID_CLASS);
		}
		class_name = rz_str_replace(class_name, ";", "", 1);
		rz_str_replace_ch(class_name, '/', '.', 1);

		char *method_name = dex_resolve_string_id(dex, method_id->name_idx);
		if (!method_name) {
			method_name = strdup(DEX_INVALID_METHOD);
		}

		// skipping the L in 'L<class>;' mangled name
		char *section_name = rz_str_newf("code.%s.%s", class_name + 1, method_name);
		if (!section_name) {
			rz_warn_if_reached();
			break;
		}

		section = section_new(section_name, RZ_PERM_RX, encoded_method->code_size, encoded_method->code_offset);
		if (section && !rz_list_append(sections, section)) {
			rz_bin_section_free(section);
		}
		free(section_name);
		free(method_name);
		free(class_name);
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		if (encoded_method->code_size < 1) {
			continue;
		}

		method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find virtual method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

		char *class_name = dex_resolve_type_id(dex, class_def->class_idx);
		if (!class_name) {
			class_name = strdup(DEX_INVALID_CLASS);
		}
		class_name = rz_str_replace(class_name, ";", "", 1);
		rz_str_replace_ch(class_name, '/', '.', 1);

		char *method_name = dex_resolve_string_id(dex, method_id->name_idx);
		if (!method_name) {
			method_name = strdup(DEX_INVALID_METHOD);
		}

		// skipping the L in 'L<class>;' mangled name
		char *section_name = rz_str_newf("code.%s.%s", class_name + 1, method_name);
		if (!section_name) {
			rz_warn_if_reached();
			break;
		}

		section = section_new(section_name, RZ_PERM_RX, encoded_method->code_size, encoded_method->code_offset);
		if (section && !rz_list_append(sections, section)) {
			rz_bin_section_free(section);
		}
		free(section_name);
		free(method_name);
		free(class_name);
	}
}

RZ_API RzList /*<RzBinSection*>*/ *rz_bin_dex_sections(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzBinSection *section;
	RzList *sections = NULL;
	RzListIter *it;

	sections = rz_list_newf((RzListFree)rz_bin_section_free);
	if (!sections) {
		return NULL;
	}
	rz_list_foreach (dex->class_defs, it, class_def) {
		dex_resolve_code_section_in_class(dex, class_def, sections);
	}
	section = section_new("data", RZ_PERM_RX, dex->data_size, dex->data_offset);
	if (section && !rz_list_append(sections, section)) {
		rz_bin_section_free(section);
	}
	section = section_new("file", RZ_PERM_R, dex->file_size, dex->header_offset);
	if (section && !rz_list_append(sections, section)) {
		rz_bin_section_free(section);
	}

	return sections;
}

RZ_API RzList /*<RzBinField*>*/ *rz_bin_dex_fields(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzList *fields = NULL;
	RzListIter *it;

	fields = rz_list_newf((RzListFree)rz_bin_field_free);
	if (!fields) {
		return NULL;
	}

	rz_list_foreach (dex->class_defs, it, class_def) {
		RzList *class_fields = dex_resolve_fields_in_class(dex, class_def);
		if (class_fields) {
			rz_list_join(fields, class_fields);
			rz_list_free(class_fields);
		}
	}

	return fields;
}

RZ_API RzList /*<RzBinSymbol*>*/ *rz_bin_dex_symbols(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	DexFieldId *field_id;
	DexMethodId *method_id;
	RzList *class_symbols = NULL;
	RzList *symbols = NULL;
	RzListIter *it;
	ut32 *class_ids = NULL;
	ut32 n_classes = rz_list_length(dex->class_defs);
	if (n_classes < 1) {
		return rz_list_newf((RzListFree)rz_bin_import_free);
	}

	class_ids = RZ_NEWS0(ut32, n_classes);
	if (!class_ids) {
		return NULL;
	}

	symbols = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!symbols) {
		free(class_ids);
		return NULL;
	}

	ut32 j = 0;
	rz_list_foreach (dex->class_defs, it, class_def) {
		class_ids[j] = class_def->class_idx;
		j++;

		class_symbols = dex_resolve_fields_in_class_as_symbols(dex, class_def);
		if (class_symbols) {
			rz_list_join(symbols, class_symbols);
			rz_list_free(class_symbols);
		}

		class_symbols = dex_resolve_methods_in_class(dex, class_def);
		if (class_symbols) {
			rz_list_join(symbols, class_symbols);
			rz_list_free(class_symbols);
		}
	}

	rz_list_foreach (dex->field_ids, it, field_id) {
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

		RzBinSymbol *field = RZ_NEW0(RzBinSymbol);
		if (!field) {
			rz_warn_if_reached();
			break;
		}

		field->name = dex_resolve_string_id(dex, field_id->name_idx);
		field->classname = dex_resolve_type_id(dex, field_id->class_idx);
		field->libname = dex_resolve_library(field->classname);
		field->bind = RZ_BIN_BIND_WEAK_STR;
		field->type = RZ_BIN_TYPE_FIELD_STR;
		field->is_imported = true;

		if (!rz_list_append(symbols, field)) {
			rz_bin_symbol_free(field);
			rz_warn_if_reached();
			break;
		}
	}

	rz_list_foreach (dex->method_ids, it, method_id) {
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

		RzBinSymbol *method = RZ_NEW0(RzBinSymbol);
		if (!method) {
			rz_warn_if_reached();
			break;
		}

		method->name = dex_resolve_string_id(dex, method_id->name_idx);
		method->classname = dex_resolve_type_id(dex, method_id->class_idx);
		method->libname = dex_resolve_library(method->classname);
		method->dname = dex_resolve_proto_id(dex, method->name, method_id->proto_idx, false);
		method->bind = RZ_BIN_BIND_WEAK_STR;
		method->is_imported = true;
		method->type = RZ_BIN_TYPE_METH_STR;

		if (!rz_list_append(symbols, method)) {
			rz_bin_symbol_free(method);
			rz_warn_if_reached();
			break;
		}
	}

	return symbols;
}

RZ_API RzList /*<RzBinImport*>*/ *rz_bin_dex_imports(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexFieldId *field_id;
	DexMethodId *method_id;
	DexClassDef *class_def;
	RzList *imports = NULL;
	ut32 *class_ids = NULL;
	RzListIter *it;

	ut32 n_classes = rz_list_length(dex->class_defs);
	if (n_classes < 1) {
		return rz_list_newf((RzListFree)rz_bin_import_free);
	}

	class_ids = RZ_NEWS0(ut32, n_classes);
	if (!class_ids) {
		return NULL;
	}

	ut32 j = 0;
	rz_list_foreach (dex->class_defs, it, class_def) {
		class_ids[j] = class_def->class_idx;
		j++;
	}

	imports = rz_list_newf((RzListFree)rz_bin_import_free);
	if (!imports) {
		free(class_ids);
		return NULL;
	}

	ut32 ordinal = 0;
	rz_list_foreach (dex->field_ids, it, field_id) {
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
			rz_warn_if_reached();
			break;
		}

		char *object = dex_resolve_type_id(dex, field_id->class_idx);
		if (!object) {
			break;
		}
		rz_str_replace_char(object, '$', '.');
		rz_str_replace_char(object, ';', 0);

		char *class_name = (char *)rz_str_rchr(object, NULL, '/');
		if (class_name) {
			class_name[0] = 0;
			class_name++;
		}
		rz_str_replace_ch(object, '/', '.', 1);

		import->name = dex_resolve_string_id(dex, field_id->name_idx);
		import->libname = class_name ? strdup(object + 1) : NULL;
		import->classname = strdup(class_name ? class_name : object + 1);
		import->bind = RZ_BIN_BIND_WEAK_STR;
		import->type = RZ_BIN_TYPE_FIELD_STR;
		import->ordinal = ordinal;
		free(object);

		if (!rz_list_append(imports, import)) {
			rz_bin_import_free(import);
			break;
		}
		ordinal++;
	}

	rz_list_foreach (dex->method_ids, it, method_id) {
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
			rz_warn_if_reached();
			break;
		}

		char *object = dex_resolve_type_id(dex, method_id->class_idx);
		if (!object) {
			break;
		}
		rz_str_replace_char(object, '$', '.');
		rz_str_replace_char(object, ';', 0);

		char *class_name = (char *)rz_str_rchr(object, NULL, '/');
		if (class_name) {
			class_name[0] = 0;
			class_name++;
		}
		rz_str_replace_ch(object, '/', '.', 1);

		char *name = dex_resolve_string_id(dex, method_id->name_idx);
		import->name = dex_resolve_proto_id(dex, name, method_id->proto_idx, false);
		import->libname = class_name ? strdup(object + 1) : NULL;
		import->classname = strdup(class_name ? class_name : object + 1);
		import->bind = RZ_BIN_BIND_WEAK_STR;
		import->type = RZ_BIN_TYPE_FUNC_STR;
		import->ordinal = ordinal;
		free(name);
		free(object);

		if (!rz_list_append(imports, import)) {
			rz_bin_import_free(import);
			break;
		}
		ordinal++;
	}

	free(class_ids);
	return imports;
}

static int compare_strings(const void *a, const void *b) {
	return strcmp((const char *)a, (const char *)b);
}

RZ_API RzList /*<char*>*/ *rz_bin_dex_libraries(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexMethodId *method_id;
	DexClassDef *class_def;
	RzList *libraries = NULL;
	ut32 *class_ids = NULL;
	RzListIter *it;

	ut32 n_classes = rz_list_length(dex->class_defs);
	if (n_classes < 1) {
		return rz_list_newf((RzListFree)free);
	}

	class_ids = RZ_NEWS0(ut32, n_classes);
	if (!class_ids) {
		return NULL;
	}

	ut32 j = 0;
	rz_list_foreach (dex->class_defs, it, class_def) {
		class_ids[j] = class_def->class_idx;
		j++;
	}

	libraries = rz_list_newf((RzListFree)free);
	if (!libraries) {
		free(class_ids);
		return NULL;
	}

	rz_list_foreach (dex->method_ids, it, method_id) {
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
		if (RZ_STR_ISEMPTY(object) || rz_list_find(libraries, object, compare_strings)) {
			free(object);
			continue;
		}
		if (!rz_list_append(libraries, object)) {
			free(object);
			break;
		}
	}

	free(class_ids);
	return libraries;
}

static bool dex_resolve_symbol_in_class_methods(RzBinDex *dex, DexClassDef *class_def, RzBinSpecialSymbol resolve, ut64 *address) {
	RzListIter *it;
	DexEncodedMethod *encoded_method = NULL;

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		DexMethodId *method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

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

		*address = encoded_method->code_offset;
		return true;
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		DexMethodId *method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
			continue;
		}

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

		*address = encoded_method->code_offset;
		return true;
	}
	return false;
}

RZ_API RzBinAddr *rz_bin_dex_resolve_symbol(RzBinDex *dex, RzBinSpecialSymbol resolve) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzListIter *it;

	RzBinAddr *ret = RZ_NEW0(RzBinAddr);
	if (!ret) {
		return NULL;
	}
	ret->paddr = UT64_MAX;

	rz_list_foreach (dex->class_defs, it, class_def) {
		if (dex_resolve_symbol_in_class_methods(dex, class_def, resolve, &ret->paddr)) {
			break;
		}
	}

	return ret;
}

static RzList /*<RzBinAddr*>*/ *dex_resolve_entrypoints_in_class(RzBinDex *dex, DexClassDef *class_def) {
	RzListIter *it;
	DexEncodedMethod *encoded_method = NULL;
	RzList *entrypoints = NULL;

	entrypoints = rz_list_newf((RzListFree)free);
	if (!entrypoints) {
		return NULL;
	}

	rz_list_foreach (class_def->direct_methods, it, encoded_method) {
		if (!dex_is_static(encoded_method->access_flags)) {
			// entrypoints are static
			continue;
		}

		DexMethodId *method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
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
			rz_warn_if_reached();
			break;
		}
		entrypoint->vaddr = entrypoint->paddr = encoded_method->code_offset;
		if (entrypoint && !rz_list_append(entrypoints, entrypoint)) {
			free(entrypoint);
		}
	}

	rz_list_foreach (class_def->virtual_methods, it, encoded_method) {
		if (!dex_is_static(encoded_method->access_flags)) {
			// entrypoints are static
			continue;
		} else if (encoded_method->code_offset < 1) {
			// if there is no code, skip
			continue;
		}

		DexMethodId *method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, encoded_method->method_idx);
		if (!method_id) {
			RZ_LOG_INFO("cannot find direct method with index %" PFMT64u "\n", encoded_method->method_idx);
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
			rz_warn_if_reached();
			break;
		}
		entrypoint->vaddr = entrypoint->paddr = encoded_method->code_offset;
		if (entrypoint && !rz_list_append(entrypoints, entrypoint)) {
			free(entrypoint);
		}
	}

	return entrypoints;
}

RZ_API RzList /*<RzBinAddr*>*/ *rz_bin_dex_entrypoints(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexClassDef *class_def;
	RzList *list = NULL;
	RzList *entrypoints = NULL;
	RzListIter *it;

	entrypoints = rz_list_newf((RzListFree)free);
	if (!entrypoints) {
		return NULL;
	}

	rz_list_foreach (dex->class_defs, it, class_def) {
		list = dex_resolve_entrypoints_in_class(dex, class_def);
		if (list) {
			rz_list_join(entrypoints, list);
			rz_list_free(list);
		}
	}

	return entrypoints;
}

RZ_API char *rz_bin_dex_resolve_method_by_idx(RzBinDex *dex, ut32 method_idx) {
	DexMethodId *method_id = (DexMethodId *)rz_list_get_n(dex->method_ids, method_idx);
	if (!method_id) {
		return NULL;
	}

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

	char *method = rz_str_newf("%s.%s", name, proto);
	free(name);
	free(proto);
	return method;
}

RZ_API char *rz_bin_dex_resolve_field_by_idx(RzBinDex *dex, ut32 field_idx) {
	DexFieldId *field_id = (DexFieldId *)rz_list_get_n(dex->field_ids, field_idx);
	if (!field_id) {
		return NULL;
	}

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

RZ_API char *rz_bin_dex_resolve_string_by_idx(RzBinDex *dex, ut32 string_idx) {
	return dex_resolve_string_id(dex, string_idx);
}

RZ_API char *rz_bin_dex_resolve_class_by_idx(RzBinDex *dex, ut32 class_idx) {
	return dex_resolve_type_id(dex, class_idx);
}

RZ_API char *rz_bin_dex_resolve_proto_by_idx(RzBinDex *dex, ut32 proto_idx) {
	return dex_resolve_proto_id(dex, "", proto_idx, false);
}

RZ_API void rz_bin_dex_checksum(RzBinDex *dex, RzBinHash *hash) {
	rz_return_if_fail(dex && hash);
	hash->type = "adler32";
	hash->len = sizeof(dex->checksum);
	hash->addr = dex->checksum_offset;
	hash->from = dex->checksum_offset + sizeof(dex->checksum);
	hash->to = dex->file_size - hash->from;
	rz_write_le32(hash->buf, dex->checksum);
}

RZ_API void rz_bin_dex_sha1(RzBinDex *dex, RzBinHash *hash) {
	rz_return_if_fail(dex && hash);
	hash->type = "sha1";
	hash->len = 20;
	hash->addr = dex->signature_offset;
	hash->from = dex->signature_offset + sizeof(dex->signature);
	hash->to = dex->file_size - hash->from;
	memcpy(hash->buf, dex->signature, sizeof(dex->signature));
}

RZ_API char *rz_bin_dex_version(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);
	// https://cs.android.com/android/platform/superproject/+/master:dalvik/dx/src/com/android/dex/DexFormat.java;l=55;bpv=1;bpt=0
	// https://developer.android.com/studio/releases/platforms
	if (!strncmp((char *)dex->version, "009", 3)) {
		return strdup("Android M3 release (Nov-Dec 2007)");
	} else if (!strncmp((char *)dex->version, "013", 3)) {
		return strdup("Android M5 release (Feb-Mar 2008)");
	} else if (!strncmp((char *)dex->version, "035", 3)) {
		return strdup("Android 3.2 (API level 13 and earlier)");
	} else if (!strncmp((char *)dex->version, "037", 3)) {
		return strdup("Android 7 (API level 24 and earlier)");
	} else if (!strncmp((char *)dex->version, "038", 3)) {
		return strdup("Android 8 (API level 26 and earlier)");
	} else if (!strncmp((char *)dex->version, "039", 3)) {
		return strdup("Android 9 (API level 28 and earlier)");
	} else if (!strncmp((char *)dex->version, "040", 3)) {
		return strdup("Android 10+ (Aug 2019)");
	}
	return NULL;
}

RZ_API ut64 rz_bin_dex_debug_info(RzBinDex *dex) {
	rz_return_val_if_fail(dex, 0);
	//TODO
	return 0;
}
