// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_DEX_H
#define RZ_DEX_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_bin.h>

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
	ut32 parameters_offset;
	ut64 offset;
} DexProtoId;
#define DEX_PROTO_ID_SIZE (12)

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
} DexMethodId;
#define DEX_METHOD_ID_SIZE (8)

typedef struct dex_t {
	ut8 magic[4];
	ut8 version[4];
	ut32 checksum;
	ut8 signature[20];
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
	RzList /*<DexMapItem>*/ *map_items;
	RzList /*<DexString>*/ *strings;
	RzList /*<DexProtoId>*/ *proto_ids;
	RzList /*<DexFieldId>*/ *field_ids;
	RzList /*<DexMethodId>*/ *method_ids;

	DexTypeId *types;
} RzBinDex;

RZ_API RzBinDex *rz_bin_dex_new(RzBuffer *buf, ut64 base, Sdb *kv);
RZ_API void rz_bin_dex_free(RzBinDex *dex);
RZ_API RzList *rz_bin_dex_strings(RzBinDex *dex);

#endif /* RZ_DEX_H */
