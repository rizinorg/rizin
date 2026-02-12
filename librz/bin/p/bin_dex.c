// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_bin.h>
#include "dex/dex.h"

#define rz_bin_file_get_dex(bf) ((RzBinDex *)bf->o->bin_obj)

static RzBinInfo *info(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	RzBinInfo *binfo = RZ_NEW0(RzBinInfo);
	if (!binfo) {
		return NULL;
	}

	binfo->lang = "java";
	binfo->file = rz_str_dup(bf->file);
	binfo->type = rz_str_dup("DEX CLASS");
	binfo->bclass = rz_bin_dex_version(dex);
	binfo->has_va = true;
	binfo->rclass = rz_str_dup("class");
	binfo->os = rz_str_dup("linux");
	binfo->subsystem = rz_str_dup("any");
	binfo->machine = rz_str_dup("Dalvik VM");
	binfo->arch = rz_str_dup("dalvik");
	binfo->bits = 32;
	binfo->big_endian = false;
	binfo->dbg_info = rz_bin_dex_debug_info(dex);

	rz_bin_dex_checksum(dex, &binfo->sum[0]);
	rz_bin_dex_sha1(dex, &binfo->sum[1]);

	return binfo;
}

static bool load_buffer(RzBinFile *bf, RzBinObject *obj, RzBuffer *buf, Sdb *sdb) {
	RzBinDex *dex = rz_bin_dex_new(buf, obj->opts.loadaddr, sdb);
	if (!dex) {
		return false;
	}
	obj->bin_obj = dex;
	return true;
}

static void destroy(RzBinFile *bf) {
	rz_bin_dex_free(rz_bin_file_get_dex(bf));
}

static bool check_buffer(RzBuffer *b) {
	if (rz_buf_size(b) > 32) {
		ut8 buf[4] = { 0 };
		rz_buf_read_at(b, 0, buf, sizeof(buf));
		return !memcmp(buf, "dex\n", 4);
	}
	return false;
}

static ut64 baddr(RzBinFile *bf) {
	return 0;
}

static Sdb *get_sdb(RzBinFile *bf) {
	return bf->sdb;
}

static RzPVector /*<RzBinClass *>*/ *classes(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_classes(dex);
}

static RzPVector /*<RzBinImport *>*/ *imports(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_imports(dex);
}

static RzPVector /*<RzBinSection *>*/ *sections(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_sections(dex);
}

static RzPVector /*<RzBinSymbol *>*/ *symbols(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_symbols(dex);
}

static RzPVector /*<char *>*/ *libraries(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_libraries(dex);
}

static RzBinAddr *binsym(RzBinFile *bf, RzBinSpecialSymbol sym) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_resolve_symbol(dex, sym);
}

static RzPVector /*<RzBinAddr *>*/ *entrypoints(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_entrypoints(dex);
}

static RzPVector /*<RzBinString *>*/ *strings(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	return rz_bin_dex_strings(dex);
}

static RzPVector /*<RzBinVirtualFile *>*/ *virtual_files(RzBinFile *bf) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}

	RzBuffer *buffer = rz_bin_dex_relocations(dex);
	if (!buffer) {
		return NULL;
	}

	RzPVector *vfiles = rz_pvector_new((RzPVectorFree)rz_bin_virtual_file_free);
	if (!vfiles) {
		return NULL;
	}

	RzBinVirtualFile *vf = RZ_NEW0(RzBinVirtualFile);
	if (!vf) {
		rz_buf_free(buffer);
		return vfiles;
	}
	vf->buf = buffer;
	vf->buf_owned = false;
	vf->name = rz_str_dup(RZ_DEX_RELOC_TARGETS);

	rz_pvector_push(vfiles, vf);
	return vfiles;
}

static int demangle_type(const char *str) {
	return RZ_BIN_LANGUAGE_JAVA;
}

static char *get_name(RzBinFile *bf, int type, int index) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return NULL;
	}
	switch (type) {
	case 'm': // method
		return rz_bin_dex_resolve_method_by_idx(dex, index);
	case 'f': // field
		return rz_bin_dex_resolve_field_by_idx(dex, index);
	case 's': // string
		return rz_bin_dex_resolve_string_by_idx(dex, index);
	case 'c': // class
		return rz_bin_dex_resolve_class_by_idx(dex, index);
	case 'p': // proto
		return rz_bin_dex_resolve_proto_by_idx(dex, index);
	default:
		return NULL;
	}
}

static ut64 get_offset(RzBinFile *bf, int type, int index) {
	RzBinDex *dex = rz_bin_file_get_dex(bf);
	if (!dex) {
		return -1;
	}
	switch (type) {
	case 'm': // method
		return rz_bin_dex_resolve_method_offset_by_idx(dex, index);
	case 's': // strings
		return rz_bin_dex_resolve_string_offset_by_idx(dex, index);
	case 't': // type
		return rz_bin_dex_resolve_type_id_offset_by_idx(dex, index);
	case 'c': // class
		return rz_bin_dex_resolve_type_id_offset_by_idx(dex, index);
	case 'o': // objects
	default:
		return -1;
	}
}

static RzPVector /*<RzBinMap *>*/ *maps(RzBinFile *bf) {
	RzPVector *maps = rz_bin_maps_of_file_sections(bf);
	void **iter;
	RzBinMap *map;

	rz_pvector_foreach (maps, iter) {
		map = *iter;
		if (strcmp(map->name, RZ_DEX_RELOC_TARGETS)) {
			continue;
		}
		map->vfile_name = rz_str_dup(RZ_DEX_RELOC_TARGETS);
	}
	return maps;
}

RzStructuredData *dex_strings_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDex *dex = bf->o->bin_obj;

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	DexString *str;
	void **iter;
	RzPVector *strings = dex->strings;
	if (!strings) {
		rz_structured_data_free(arr);
		return NULL;
	}

	rz_pvector_foreach (strings, iter) {
		str = (DexString *)*iter;

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "size", str->size, false);
		rz_structured_data_map_add_unsigned(m, "offset", str->offset, true);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_proto_ids_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDex *dex = bf->o->bin_obj;

	if (!dex->proto_ids) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	void **iter;
	rz_pvector_foreach (dex->proto_ids, iter) {
		DexProtoId *p = *iter;
		if (!p) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "shorty_idx", p->shorty_idx, false);
		rz_structured_data_map_add_unsigned(m, "return_type_idx", p->return_type_idx, false);
		rz_structured_data_map_add_unsigned(m, "type_list_size", p->type_list_size, false);
		rz_structured_data_map_add_unsigned(m, "offset", p->offset, true);

		if (p->type_list && p->type_list_size) {
			RzStructuredData *types = rz_structured_data_new_array();
			if (!types) {
				rz_structured_data_free(arr);
				return NULL;
			}
			for (ut32 i = 0; i < p->type_list_size; i++) {
				rz_structured_data_array_add_unsigned(types, p->type_list[i], false);
			}
			rz_structured_data_map_add(m, "type_list", types);
		}

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_field_ids_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDex *dex = bf->o->bin_obj;

	if (!dex->field_ids) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	void **iter;
	rz_pvector_foreach (dex->field_ids, iter) {
		DexFieldId *f = *iter;
		if (!f) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "class_idx", f->class_idx, false);
		rz_structured_data_map_add_unsigned(m, "type_idx", f->type_idx, false);
		rz_structured_data_map_add_unsigned(m, "name_idx", f->name_idx, false);
		rz_structured_data_map_add_unsigned(m, "offset", f->offset, true);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_method_ids_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDex *dex = bf->o->bin_obj;

	if (!dex->method_ids) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	void **iter;
	rz_pvector_foreach (dex->method_ids, iter) {
		DexMethodId *mtd = *iter;
		if (!mtd) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "class_idx", mtd->class_idx, false);
		rz_structured_data_map_add_unsigned(m, "proto_idx", mtd->proto_idx, false);
		rz_structured_data_map_add_unsigned(m, "name_idx", mtd->name_idx, false);
		rz_structured_data_map_add_unsigned(m, "offset", mtd->offset, true);

		if (mtd->code_offset) {
			rz_structured_data_map_add_unsigned(m, "code_offset", mtd->code_offset, true);
			rz_structured_data_map_add_unsigned(m, "code_size", mtd->code_size, false);
		}

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_encoded_fields_structure(RzList /*<DexEncodedField *>*/ *fields) {
	if (!fields) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	DexEncodedField *f;

	rz_list_foreach (fields, it, f) {
		if (!f) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "offset", f->offset, true);
		rz_structured_data_map_add_unsigned(m, "field_idx", f->field_idx, false);
		rz_structured_data_map_add_unsigned(m, "access_flags", f->access_flags, false);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_encoded_methods_structure(RzList /*<DexEncodedMethod *>*/ *methods) {
	if (!methods) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	RzListIter *it;
	DexEncodedMethod *mtd;

	rz_list_foreach (methods, it, mtd) {
		if (!mtd) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "offset", mtd->offset, true);
		rz_structured_data_map_add_unsigned(m, "method_idx", mtd->method_idx, false);
		rz_structured_data_map_add_unsigned(m, "access_flags", mtd->access_flags, false);

		/* code-related data */
		rz_structured_data_map_add_unsigned(m, "registers_size", mtd->registers_size, false);
		rz_structured_data_map_add_unsigned(m, "ins_size", mtd->ins_size, false);
		rz_structured_data_map_add_unsigned(m, "outs_size", mtd->outs_size, false);
		rz_structured_data_map_add_unsigned(m, "tries_size", mtd->tries_size, false);
		rz_structured_data_map_add_unsigned(m, "debug_info_offset", mtd->debug_info_offset, true);
		rz_structured_data_map_add_unsigned(m, "code_size", mtd->code_size, false);
		rz_structured_data_map_add_unsigned(m, "code_offset", mtd->code_offset, true);

		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_class_defs_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDex *dex = bf->o->bin_obj;

	if (!dex->class_defs) {
		return NULL;
	}

	RzStructuredData *arr = rz_structured_data_new_array();
	if (!arr) {
		return NULL;
	}

	void **iter;
	rz_pvector_foreach (dex->class_defs, iter) {
		DexClassDef *c = *iter;
		if (!c) {
			continue;
		}

		RzStructuredData *m = rz_structured_data_new_map();
		if (!m) {
			rz_structured_data_free(arr);
			return NULL;
		}

		rz_structured_data_map_add_unsigned(m, "class_idx", c->class_idx, false);
		rz_structured_data_map_add_unsigned(m, "access_flags", c->access_flags, false);
		rz_structured_data_map_add_unsigned(m, "superclass_idx", c->superclass_idx, false);
		rz_structured_data_map_add_unsigned(m, "interfaces_offset", c->interfaces_offset, true);
		rz_structured_data_map_add_unsigned(m, "source_file_idx", c->source_file_idx, false);
		rz_structured_data_map_add_unsigned(m, "annotations_offset", c->annotations_offset, true);
		rz_structured_data_map_add_unsigned(m, "class_data_offset", c->class_data_offset, true);
		rz_structured_data_map_add_unsigned(m, "static_values_offset", c->static_values_offset, true);
		rz_structured_data_map_add_unsigned(m, "offset", c->offset, true);

		if (c->interfaces && c->n_interfaces) {
			RzStructuredData *ifaces = rz_structured_data_new_array();
			if (!ifaces) {
				rz_structured_data_free(arr);
				return NULL;
			}
			for (ut32 i = 0; i < c->n_interfaces; i++) {
				rz_structured_data_array_add_unsigned(ifaces, c->interfaces[i], false);
			}
			rz_structured_data_map_add(m, "interfaces", ifaces);
		}
		if (c->static_fields) {
			RzStructuredData *sf = dex_encoded_fields_structure(c->static_fields);
			if (!sf) {
				rz_structured_data_free(arr);
				return NULL;
			}
			rz_structured_data_map_add(m, "static_fields", sf);
		}

		if (c->instance_fields) {
			RzStructuredData *ifields = dex_encoded_fields_structure(c->instance_fields);
			if (!ifields) {
				rz_structured_data_free(arr);
				return NULL;
			}
			rz_structured_data_map_add(m, "instance_fields", ifields);
		}

		if (c->direct_methods) {
			RzStructuredData *dm = dex_encoded_methods_structure(c->direct_methods);
			if (!dm) {
				rz_structured_data_free(arr);
				return NULL;
			}
			rz_structured_data_map_add(m, "direct_methods", dm);
		}

		if (c->virtual_methods) {
			RzStructuredData *vm = dex_encoded_methods_structure(c->virtual_methods);
			if (!vm) {
				rz_structured_data_free(arr);
				return NULL;
			}
			rz_structured_data_map_add(m, "virtual_methods", vm);
		}
		rz_structured_data_array_add(arr, m);
	}

	return arr;
}

static RzStructuredData *dex_relocs_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);
	RzBinDex *dex = bf->o->bin_obj;

	if (!dex->relocs_size) {
		return NULL;
	}

	RzStructuredData *m = rz_structured_data_new_map();
	if (!m) {
		return NULL;
	}

	rz_structured_data_map_add_unsigned(m, "relocs_offset", dex->relocs_offset, true);
	rz_structured_data_map_add_unsigned(m, "relocs_size", dex->relocs_size, false);

	if (dex->relocs_code && dex->relocs_size) {
		rz_structured_data_map_add_bytes(m, "relocs_code", dex->relocs_code, dex->relocs_size, RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	}

	if (dex->relocs_buffer) {
		ut64 buf_size = rz_buf_size(dex->relocs_buffer);
		ut8 *tmp = malloc(buf_size);
		if (tmp) {
			rz_buf_read_at(dex->relocs_buffer, 0, tmp, buf_size);
			rz_structured_data_map_add_bytes(m, "relocs_buffer", tmp, buf_size, RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
			free(tmp);
		}
	}

	return m;
}

static RzStructuredData *dex_structure(RzBinFile *bf) {
	rz_return_val_if_fail(bf && bf->o && bf->o->bin_obj, NULL);

	RzBinDex *dex = bf->o->bin_obj;

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *dex_sd = rz_structured_data_map_add_map(info, "dex");
	if (!dex_sd) {
		rz_structured_data_free(info);
		return NULL;
	}

	RzStructuredData *identity = rz_structured_data_map_add_map(dex_sd, "identity");
	if (!identity) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(identity, "header_offset", dex->header_offset, true);
	rz_structured_data_map_add_bytes(identity, "magic", dex->magic, sizeof(dex->magic), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_bytes(identity, "version", dex->version, sizeof(dex->version), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(identity, "checksum", dex->checksum, false);
	rz_structured_data_map_add_unsigned(identity, "checksum_offset", dex->checksum_offset, true);
	rz_structured_data_map_add_bytes(identity, "signature", dex->signature, sizeof(dex->signature), RZ_STRUCTURED_DATA_FORMAT_HEXDUMP);
	rz_structured_data_map_add_unsigned(identity, "signature_offset", dex->signature_offset, true);

	RzStructuredData *file_info = rz_structured_data_map_add_map(dex_sd, "file_info");
	if (!file_info) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(file_info, "file_size", dex->file_size, false);
	rz_structured_data_map_add_unsigned(file_info, "header_size", dex->header_size, false);
	rz_structured_data_map_add_unsigned(file_info, "endian_tag", dex->endian_tag, true);

	RzStructuredData *offsets = rz_structured_data_map_add_map(dex_sd, "offsets_and_sizes");
	if (!offsets) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(offsets, "link_size", dex->link_size, false);
	rz_structured_data_map_add_unsigned(offsets, "link_offset", dex->link_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "map_offset", dex->map_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "string_ids_size", dex->string_ids_size, false);
	rz_structured_data_map_add_unsigned(offsets, "string_ids_offset", dex->string_ids_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "type_ids_size", dex->type_ids_size, false);
	rz_structured_data_map_add_unsigned(offsets, "type_ids_offset", dex->type_ids_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "proto_ids_size", dex->proto_ids_size, false);
	rz_structured_data_map_add_unsigned(offsets, "proto_ids_offset", dex->proto_ids_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "field_ids_size", dex->field_ids_size, false);
	rz_structured_data_map_add_unsigned(offsets, "field_ids_offset", dex->field_ids_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "method_ids_size", dex->method_ids_size, false);
	rz_structured_data_map_add_unsigned(offsets, "method_ids_offset", dex->method_ids_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "class_defs_size", dex->class_defs_size, false);
	rz_structured_data_map_add_unsigned(offsets, "class_defs_offset", dex->class_defs_offset, true);
	rz_structured_data_map_add_unsigned(offsets, "data_size", dex->data_size, false);
	rz_structured_data_map_add_unsigned(offsets, "data_offset", dex->data_offset, true);

	RzStructuredData *strings_detail = dex_strings_structure(bf);
	if (!strings_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(dex_sd, "strings_detail", strings_detail);

	RzStructuredData *proto_ids_detail = dex_proto_ids_structure(bf);
	if (!proto_ids_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(dex_sd, "proto_ids_detail", proto_ids_detail);

	RzStructuredData *field_ids_detail = dex_field_ids_structure(bf);
	if (!field_ids_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(dex_sd, "field_ids_detail", field_ids_detail);

	RzStructuredData *method_ids_detail = dex_method_ids_structure(bf);
	if (!method_ids_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(dex_sd, "method_ids_detail", method_ids_detail);

	RzStructuredData *class_defs_detail = dex_class_defs_structure(bf);
	if (!class_defs_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(dex_sd, "class_defs_detail", class_defs_detail);

	RzStructuredData *relocs_detail = dex_relocs_structure(bf);
	if (!relocs_detail) {
		rz_structured_data_free(info);
		return NULL;
	}
	rz_structured_data_map_add(dex_sd, "relocs_detail", relocs_detail);

	return info;
}

RzBinPlugin rz_bin_plugin_dex = {
	.name = "dex",
	.desc = "DEX (Dalvik Executable)",
	.license = "LGPL3",
	.author = "deroad",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entrypoints,
	.virtual_files = &virtual_files,
	.maps = &maps,
	.sections = sections,
	.symbols = symbols,
	.imports = &imports,
	.strings = &strings,
	.get_name = &get_name,
	.get_offset = &get_offset,
	.info = &info,
	.libs = libraries,
	.classes = classes,
	.demangle_type = demangle_type,
	.bin_structure = &dex_structure
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_dex,
	.version = RZ_VERSION
};
#endif
