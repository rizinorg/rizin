// SPDX-FileCopyrightText: 2011 earada <pkedurat@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef DEX_H
#define DEX_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>

#define RZ_BIN_DEX_MAXSTR 256
#define DEX_CLASS_SIZE    (32)
#define LEB_MAX_SIZE      6

/* method flags */
#define RZ_DEX_METH_PUBLIC                0x0001
#define RZ_DEX_METH_PRIVATE               0x0002
#define RZ_DEX_METH_PROTECTED             0x0004
#define RZ_DEX_METH_STATIC                0x0008
#define RZ_DEX_METH_FINAL                 0x0010
#define RZ_DEX_METH_SYNCHRONIZED          0x0020
#define RZ_DEX_METH_BRIDGE                0x0040
#define RZ_DEX_METH_VARARGS               0x0080
#define RZ_DEX_METH_NATIVE                0x0100
#define RZ_DEX_METH_ABSTRACT              0x0400
#define RZ_DEX_METH_STRICT                0x0800
#define RZ_DEX_METH_SYNTHETIC             0x1000
#define RZ_DEX_METH_MIRANDA               0x8000
#define RZ_DEX_METH_CONSTRUCTOR           0x10000
#define RZ_DEX_METH_DECLARED_SYNCHRONIZED 0x20000

RZ_PACKED(
	typedef struct dex_header_t {
		ut8 magic[8];
		ut32 checksum;
		ut8 signature[20];
		ut32 size;
		ut32 header_size;
		ut32 endian;
		ut32 linksection_size;
		ut32 linksection_offset;
		ut32 map_offset;
		ut32 strings_size;
		ut32 strings_offset;
		ut32 types_size;
		ut32 types_offset;
		ut32 prototypes_size;
		ut32 prototypes_offset;
		ut32 fields_size;
		ut32 fields_offset;
		ut32 method_size;
		ut32 method_offset;
		ut32 class_size;
		ut32 class_offset;
		ut32 data_size;
		ut32 data_offset;
	})
DexHeader;

RZ_PACKED(
	typedef struct dex_proto_t {
		ut32 shorty_id;
		ut32 return_type_id;
		ut32 parameters_off;
	})
DexProto;

typedef struct dex_type_t {
	ut32 descriptor_id;
} DexType;

// #pragma pack(1)
typedef struct dex_field_t {
	ut16 class_id;
	ut16 type_id;
	ut32 name_id;
} DexField;

RZ_PACKED(
	typedef struct dex_method_t {
		ut16 class_id;
		ut16 proto_id;
		ut32 name_id;
	})
RzBinDexMethod;

RZ_PACKED(
	typedef struct dex_class_t {
		ut32 class_id; // index into typeids
		ut32 access_flags;
		ut32 super_class;
		ut32 interfaces_offset;
		ut32 source_file;
		ut32 anotations_offset;
		ut32 class_data_offset;
		ut32 static_values_offset;
		struct dex_class_data_item_t *class_data;
	})
RzBinDexClass;

RZ_PACKED(
	typedef struct dex_class_data_item_t {
		ut64 static_fields_size;
		ut64 instance_fields_size;
		ut64 direct_methods_size;
		ut64 virtual_methods_size;
	})
RzBinDexClassData;

typedef struct rz_bin_dex_obj_t {
	int size;
	const char *file;
	RzBuffer *b;
	struct dex_header_t header;
	ut32 *strings;
	struct dex_type_t *types;
	struct dex_proto_t *protos;
	struct dex_field_t *fields;
	struct dex_method_t *methods;
	struct dex_class_t *classes;
	RzList *methods_list;
	RzList *trycatch_list;
	RzList *imports_list;
	RzList *classes_list;
	RzList *lines_list;
	ut64 code_from;
	ut64 code_to;
	char *version;
	Sdb *kv;
	char **cal_strings;
} RzBinDexObj;

struct rz_bin_dex_str_t {
	char str[RZ_BIN_DEX_MAXSTR];
	ut64 offset;
	ut64 ordinal;
	int size;
	int last;
};

struct dex_encoded_type_addr_pair_t {
	ut64 type_idx;
	ut64 addr;
};

struct dex_encoded_catch_handler_t {
	st64 size;
	struct dex_encoded_type_addr_pair_t *handlers;
	ut64 catch_all_addr;
};

struct dex_debug_position_t {
	ut32 source_file_idx;
	ut64 address;
	ut64 line;
};

struct dex_debug_local_t {
	const char *name;
	const char *descriptor;
	const char *signature;
	ut16 startAddress;
	bool live;
	int reg;
	ut16 endAddress;
};

char *rz_bin_dex_get_version(struct rz_bin_dex_obj_t *bin);
void rz_bin_dex_free(struct rz_bin_dex_obj_t *bin);
struct rz_bin_dex_obj_t *rz_bin_dex_new_buf(RzBuffer *buf);
struct rz_bin_dex_str_t *rz_bin_dex_get_strings(struct rz_bin_dex_obj_t *bin);

#endif
