// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dex.h"

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

static DexString *dex_string_new(RzBuffer *buf, ut64 offset, st64 *pread) {
	ut64 size = 0;
	char *data = NULL;
	st64 read;
	DexString *string = NULL;

	read = rz_buf_uleb128(buf, &size);
	data = malloc(size + 1);
	if (!data || rz_buf_read(buf, (ut8 *)data, size) != size) {
		rz_warn_if_reached();
		free(string);
		return NULL;
	}
	data[size] = 0;

	string = RZ_NEW(DexString);
	if (!string) {
		rz_warn_if_reached();
		free(string);
		return NULL;
	}

	*pread = read;
	string->size = size;
	string->offset = offset;
	string->data = data;
	return string;
}

static void dex_string_free(DexString *string) {
	if (!string) {
		return;
	}
	free(string->data);
	free(string);
}

#define dex_proto_id_free free
static DexProtoId *dex_proto_id_new(RzBuffer *buf, ut64 offset) {
	DexProtoId *proto_id = RZ_NEW(DexProtoId);
	if (!proto_id) {
		return NULL;
	}

	proto_id->shorty_idx = /*       */ rz_buf_read_le32(buf);
	proto_id->return_type_idx = /*  */ rz_buf_read_le32(buf);
	proto_id->parameters_offset = /**/ rz_buf_read_le32(buf);
	proto_id->offset = offset;
	return proto_id;
}

#define dex_field_id_free free
static DexFieldId *dex_field_id_new(RzBuffer *buf, ut64 offset) {
	DexFieldId *field_id = RZ_NEW(DexFieldId);
	if (!field_id) {
		return NULL;
	}

	field_id->class_idx = /**/ rz_buf_read_le32(buf);
	field_id->type_idx = /* */ rz_buf_read_le32(buf);
	field_id->name_idx = /* */ rz_buf_read_le32(buf);
	field_id->offset = offset;
	return field_id;
}

#define dex_method_id_free free
static DexMethodId *dex_method_id_new(RzBuffer *buf, ut64 offset) {
	DexMethodId *method_id = RZ_NEW(DexMethodId);
	if (!method_id) {
		return NULL;
	}

	method_id->class_idx = /**/ rz_buf_read_le32(buf);
	method_id->proto_idx = /* */ rz_buf_read_le32(buf);
	method_id->name_idx = /* */ rz_buf_read_le32(buf);
	method_id->offset = offset;
	return method_id;
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

	rz_buf_read(buf, dex->magic, sizeof(dex->magic));
	rz_buf_read(buf, dex->version, sizeof(dex->version));
	dex->checksum = rz_buf_read_le32(buf);
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
	//dex_fail_if_bad_ids(dex->field_ids, sizeof(ut32), buffer_size, dex_parse_bad);

	dex->method_ids_size = /*  */ rz_buf_read_le32(buf);
	dex->method_ids_offset = /**/ rz_buf_read_le32(buf);
	//dex_fail_if_bad_ids(dex->method_ids, sizeof(ut32), buffer_size, dex_parse_bad);

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
		//eprintf("method_id: 0x%04x 0x%04x 0x%08x\n", method_id->class_idx, method_id->proto_idx, method_id->name_idx);
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
	rz_list_free(dex->method_ids);

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
	//dex->map_items

	if (!dex_parse(dex, base, buf)) {
		return NULL;
	}

	return dex;
}

RZ_API RzList *rz_bin_dex_strings(RzBinDex *dex) {
	rz_return_val_if_fail(dex, NULL);

	DexString *string;
	RzListIter *it;
	RzList *list = rz_list_newf(rz_bin_string_free);
	if (!list) {
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
		if (!rz_list_append(list, bstr)) {
			free(bstr);
		}
		ordinal++;
	}
	return list;
}
