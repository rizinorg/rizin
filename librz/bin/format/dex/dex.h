// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DEX_H
#define RZ_DEX_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

#define RZ_DEX_RELOC_TARGETS "reloc-targets"
#define RZ_DEX_VIRT_ADDRESS  0x0100000000
#define RZ_DEX_RELOC_ADDRESS 0x8000000000

typedef enum {
	DEX_MAP_ITEM_TYPE_HEADER_ITEM = 0x0000,
	DEX_MAP_ITEM_TYPE_STRING_ID_ITEM = 0x0001,
	DEX_MAP_ITEM_TYPE_TYPE_ID_ITEM = 0x0002,
	DEX_MAP_ITEM_TYPE_PROTO_ID_ITEM = 0x0003,
	DEX_MAP_ITEM_TYPE_FIELD_ID_ITEM = 0x0004,
	DEX_MAP_ITEM_TYPE_METHOD_ID_ITEM = 0x0005,
	DEX_MAP_ITEM_TYPE_CLASS_DEF_ITEM = 0x0006,
	DEX_MAP_ITEM_TYPE_CALL_SITE_ID_ITEM = 0x0007,
	DEX_MAP_ITEM_TYPE_METHOD_HANDLE_ITEM = 0x0008,
	DEX_MAP_ITEM_TYPE_MAP_LIST = 0x1000,
	DEX_MAP_ITEM_TYPE_TYPE_LIST = 0x1001,
	DEX_MAP_ITEM_TYPE_ANNOTATION_SET_REF_LIST = 0x1002,
	DEX_MAP_ITEM_TYPE_ANNOTATION_SET_ITEM = 0x1003,
	DEX_MAP_ITEM_TYPE_CLASS_DATA_ITEM = 0x2000,
	DEX_MAP_ITEM_TYPE_CODE_ITEM = 0x2001,
	DEX_MAP_ITEM_TYPE_STRING_DATA_ITEM = 0x2002,
	DEX_MAP_ITEM_TYPE_DEBUG_INFO_ITEM = 0x2003,
	DEX_MAP_ITEM_TYPE_ANNOTATION_ITEM = 0x2004,
	DEX_MAP_ITEM_TYPE_ENCODED_ARRAY_ITEM = 0x2005,
	DEX_MAP_ITEM_TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006,
	DEX_MAP_ITEM_TYPE_HIDDENAPI_CLASS_DATA_ITEM = 0xF000,
} DexMapItemType;

typedef enum {
	ACCESS_FLAG_PUBLIC /*               */ = 0x00001,
	ACCESS_FLAG_PRIVATE /*              */ = 0x00002,
	ACCESS_FLAG_PROTECTED /*            */ = 0x00004,
	ACCESS_FLAG_STATIC /*               */ = 0x00008,
	ACCESS_FLAG_FINAL /*                */ = 0x00010,
	ACCESS_FLAG_SYNCHRONIZED /*         */ = 0x00020,
	ACCESS_FLAG_BRIDGE /*               */ = 0x00040,
	ACCESS_FLAG_VARARGS /*              */ = 0x00080,
	ACCESS_FLAG_NATIVE /*               */ = 0x00100,
	ACCESS_FLAG_INTERFACE /*            */ = 0x00200,
	ACCESS_FLAG_ABSTRACT /*             */ = 0x00400,
	ACCESS_FLAG_STRICT /*               */ = 0x00800,
	ACCESS_FLAG_SYNTHETIC /*            */ = 0x01000,
	ACCESS_FLAG_ANNOTATION /*           */ = 0x02000,
	ACCESS_FLAG_ENUM /*                 */ = 0x04000,
	ACCESS_FLAG_MODULE /*               */ = 0x08000,
	ACCESS_FLAG_CONSTRUCTOR /*          */ = 0x10000,
	ACCESS_FLAG_DECLARED_SYNCHRONIZED /**/ = 0x20000
} DexAccessFlag;

typedef struct dex_map_item_t {
	ut16 map_type; /* DexMapItemType */
	ut16 unused;
	ut32 map_size;
	ut32 map_offset;
	ut64 offset;
} DexMapItem;
#define DEX_MAP_ITEM_SIZE (12)

typedef struct dex_string_t {
	ut64 size;
	ut64 offset;
	char *data;
} DexString;
// DexString structure size is variable.

typedef ut32 DexTypeId;
#define DEX_TYPE_ID_SIZE (sizeof(DexTypeId))

typedef struct dex_proto_id_t {
	ut32 shorty_idx;
	ut32 return_type_idx;
	ut32 type_list_size;
	ut16 *type_list;
	ut64 offset;
} DexProtoId;
#define DEX_PROTO_ID_SIZE (0xC)

typedef struct dex_field_id_t {
	ut16 class_idx;
	ut16 type_idx;
	ut32 name_idx;
	ut64 offset;
} DexFieldId;
#define DEX_FIELD_ID_SIZE (8)

typedef struct dex_method_id_t {
	ut16 class_idx;
	ut16 proto_idx;
	ut32 name_idx;
	ut64 offset;
	/* code_* values are filled when parsing EncodedMethod */
	ut64 code_offset;
	ut64 code_size;
} DexMethodId;
#define DEX_METHOD_ID_SIZE (8)

typedef struct dex_encoded_field_t {
	ut64 offset;
	ut64 field_idx;
	ut64 access_flags;
} DexEncodedField;

typedef struct dex_encoded_method_t {
	ut64 offset;
	ut64 method_idx;
	ut64 access_flags;

	/* core related data */
	ut16 registers_size;
	ut16 ins_size;
	ut16 outs_size;
	ut16 tries_size;
	ut32 debug_info_offset;
	ut32 code_size;
	ut64 code_offset;
	/*ut16 padding*/
	/*try_item[tries_size]*/
	/*encoded_catch_handler_list handlers */
} DexEncodedMethod;

// small note: on the official documentation all the
// variables are set as uint (aka ut32) but on their
// libdexfile defines some fields within class_def
// as ut16 + padding; to uniform with the real used
// code you will find some useless _padding variables
typedef struct dex_class_def_t {
	ut16 class_idx;
	ut16 _padding1;
	ut32 access_flags;
	ut16 superclass_idx;
	ut16 _padding2;
	ut32 interfaces_offset;
	ut32 source_file_idx;
	ut32 annotations_offset;
	ut32 class_data_offset;
	ut32 static_values_offset;
	ut64 offset;

	ut32 n_interfaces;
	ut16 *interfaces;

	RzList /*<DexEncodedField *>*/ *static_fields;
	RzList /*<DexEncodedField *>*/ *instance_fields;
	RzList /*<DexEncodedMethod *>*/ *direct_methods;
	RzList /*<DexEncodedMethod *>*/ *virtual_methods;
} DexClassDef;
#define DEX_CLASS_DEF_SIZE (0x20)

typedef struct dex_t {
	ut64 header_offset;
	ut8 magic[4];
	ut8 version[4];
	ut32 checksum;
	ut64 checksum_offset;
	ut8 signature[20];
	ut64 signature_offset;
	ut32 file_size;
	ut32 header_size;
	ut32 endian_tag;
	ut32 link_size;
	ut32 link_offset;
	ut32 map_offset;
	ut32 string_ids_size;
	ut32 string_ids_offset;
	ut32 type_ids_size;
	ut32 type_ids_offset;
	ut32 proto_ids_size;
	ut32 proto_ids_offset;
	ut32 field_ids_size;
	ut32 field_ids_offset;
	ut32 method_ids_size;
	ut32 method_ids_offset;
	ut32 class_defs_size;
	ut32 class_defs_offset;
	ut32 data_size;
	ut32 data_offset;

	/* lists */
	RzPVector /*<DexString *>*/ *strings;
	RzPVector /*<DexProtoId *>*/ *proto_ids;
	RzPVector /*<DexFieldId *>*/ *field_ids;
	RzPVector /*<DexMethodId *>*/ *method_ids;
	RzPVector /*<DexClassDef *>*/ *class_defs;

	DexTypeId *types;

	ut64 relocs_offset;
	ut32 relocs_size;
	ut8 *relocs_code;
	RzBuffer *relocs_buffer;
} RzBinDex;

RZ_API RZ_OWN RzBinDex *rz_bin_dex_new(RZ_NONNULL RzBuffer *buf, ut64 base, RZ_NONNULL Sdb *kv);
RZ_API void rz_bin_dex_free(RZ_NULLABLE RzBinDex *dex);

RZ_API RZ_OWN char *rz_bin_dex_version(RZ_NONNULL RzBinDex *dex);
RZ_API ut64 rz_bin_dex_debug_info(RZ_NONNULL RzBinDex *dex);

RZ_API RZ_OWN RzPVector /*<RzBinString *>*/ *rz_bin_dex_strings(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzPVector /*<RzBinClass *>*/ *rz_bin_dex_classes(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzList /*<RzBinClassField *>*/ *rz_bin_dex_fields(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_dex_sections(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzPVector /*<RzBinSymbol *>*/ *rz_bin_dex_symbols(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzPVector /*<RzBinImport *>*/ *rz_bin_dex_imports(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_bin_dex_libraries(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_OWN RzBinAddr *rz_bin_dex_resolve_symbol(RZ_NONNULL RzBinDex *dex, RzBinSpecialSymbol resolve);
RZ_API RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_dex_entrypoints(RZ_NONNULL RzBinDex *dex);
RZ_API RZ_BORROW RzBuffer *rz_bin_dex_relocations(RZ_NONNULL RzBinDex *dex);

RZ_API RZ_OWN char *rz_bin_dex_resolve_method_by_idx(RZ_NONNULL RzBinDex *dex, ut32 method_idx);
RZ_API RZ_OWN char *rz_bin_dex_resolve_field_by_idx(RZ_NONNULL RzBinDex *dex, ut32 field_idx);
RZ_API RZ_OWN char *rz_bin_dex_resolve_class_by_idx(RZ_NONNULL RzBinDex *dex, ut32 class_idx);
RZ_API RZ_OWN char *rz_bin_dex_resolve_string_by_idx(RZ_NONNULL RzBinDex *dex, ut32 string_idx);
RZ_API RZ_OWN char *rz_bin_dex_resolve_proto_by_idx(RZ_NONNULL RzBinDex *dex, ut32 proto_idx);
RZ_API RZ_OWN char *rz_bin_dex_resolve_type_id_by_idx(RZ_NONNULL RzBinDex *dex, ut32 type_idx);
RZ_API RZ_OWN char *rz_bin_dex_access_flags_readable(ut32 access_flags);

RZ_API ut64 rz_bin_dex_resolve_string_offset_by_idx(RZ_NONNULL RzBinDex *dex, ut32 string_idx);
RZ_API ut64 rz_bin_dex_resolve_type_id_offset_by_idx(RZ_NONNULL RzBinDex *dex, ut32 type_idx);
RZ_API ut64 rz_bin_dex_resolve_method_offset_by_idx(RZ_NONNULL RzBinDex *dex, ut32 method_idx);

RZ_API void rz_bin_dex_checksum(RZ_NONNULL RzBinDex *dex, RZ_NONNULL RzBinHash *hash);
RZ_API void rz_bin_dex_sha1(RZ_NONNULL RzBinDex *dex, RZ_NONNULL RzBinHash *hash);

#endif /* RZ_DEX_H */
