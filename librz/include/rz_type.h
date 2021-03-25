// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TYPE_H
#define RZ_TYPE_H

#include <rz_types.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_print.h>
#include <rz_bind.h>
#include <rz_io.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_type);

typedef struct rz_type_target_t {
	const char *cpu;
	int bits;
	const char *os;
	bool big_endian;
} RzTypeTarget;

typedef struct rz_type_t {
	void *user;
	Sdb *sdb_types;
	Sdb *formats; // for `pf` formats
	RzTypeTarget *target;
	RNum *num;
	RzIOBind iob; // for RzIO in formats
} RzType;

typedef struct rz_type_enum_case_t {
	char *name;
	int val;
} RzTypeEnumCase;

typedef struct rz_type_struct_member_t {
	char *name;
	char *type;
	size_t offset; // in bytes
	size_t size; // in bits?
} RzTypeStructMember;

typedef struct rz_type_union_member_t {
	char *name;
	char *type;
	size_t offset; // in bytes
	size_t size; // in bits?
} RzTypeUnionMember;

typedef enum {
	RZ_BASE_TYPE_KIND_STRUCT,
	RZ_BASE_TYPE_KIND_UNION,
	RZ_BASE_TYPE_KIND_ENUM,
	RZ_BASE_TYPE_KIND_TYPEDEF, // probably temporary addition, dev purposes
	RZ_BASE_TYPE_KIND_ATOMIC, // For real atomic base types
} RzBaseTypeKind;

typedef struct rz_base_type_struct_t {
	RzVector /*<RzTypeStructMember>*/ members;
} RzBaseTypeStruct;

typedef struct rz_base_type_union_t {
	RzVector /*<RzTypeUnionMember>*/ members;
} RzBaseTypeUnion;

typedef struct rz_base_type_enum_t {
	RzVector /*<RzTypeEnumCase*/ cases; // list of all the enum casessssss
} RzBaseTypeEnum;

typedef struct rz_base_type_t {
	char *name;
	char *type; // Used by typedef, atomic type, enum
	ut64 size; // size of the whole type in bits
	RzBaseTypeKind kind;
	union {
		RzBaseTypeStruct struct_data;
		RzBaseTypeEnum enum_data;
		RzBaseTypeUnion union_data;
	};
} RzBaseType;

typedef struct rz_type_enum {
	const char *name;
	const char *val;
} RzTypeEnum;

#ifdef RZ_API

RZ_API RzType *rz_type_new();
RZ_API void rz_type_free(RzType *t);
RZ_API void rz_type_load_sdb(RzType *t, const char *dpath);
RZ_API void rz_type_purge(RzType *t);
RZ_API void rz_type_set_bits(RzType *t, int bits);
RZ_API void rz_type_set_os(RzType *t, const char *os);
RZ_API void rz_type_set_cpu(RzType *t, const char *cpu);
RZ_API char *rz_type_kuery(RzType *t, const char *query);

RZ_API void rz_type_db_init(RzType *types, const char *dir_prefix, const char *arch, int bits, const char *os);

// Base types

RZ_API RzBaseType *rz_type_get_base_type(RzType *type, const char *name);
RZ_API void rz_type_base_type(const RzType *t, const RzBaseType *type);
RZ_API void rz_type_base_type_free(RzBaseType *type);
RZ_API RzBaseType *rz_type_base_type_new(RzBaseTypeKind kind);

RZ_API void rz_type_base_enum_case_free(void *e, void *user);
RZ_API void rz_type_base_struct_member_free(void *e, void *user);
RZ_API void rz_type_base_union_member_free(void *e, void *user);
RZ_API void rz_type_save_base_type(const RzType *t, const RzBaseType *type);

/* ctype */
// Parses strings like "const char * [0x42] const * [23]" to RzTypeCTypeType

typedef struct rz_type_ctype_t RzTypeCType;

typedef enum {
	RZ_TYPE_CTYPE_TYPE_KIND_IDENTIFIER,
	RZ_TYPE_CTYPE_TYPE_KIND_POINTER,
	RZ_TYPE_CTYPE_TYPE_KIND_ARRAY
} RzTypeCTypeTypeKind;

typedef enum {
	RZ_TYPE_CTYPE_IDENTIFIER_KIND_UNSPECIFIED,
	RZ_TYPE_CTYPE_IDENTIFIER_KIND_STRUCT,
	RZ_TYPE_CTYPE_IDENTIFIER_KIND_UNION,
	RZ_TYPE_CTYPE_IDENTIFIER_KIND_ENUM
} RzTypeCTypeTypeIdentifierKind;

typedef struct rz_type_ctype_type_t RzTypeCTypeType;
struct rz_type_ctype_type_t {
	RzTypeCTypeTypeKind kind;
	union {
		struct {
			RzTypeCTypeTypeIdentifierKind kind;
			char *name;
			bool is_const;
		} identifier;
		struct {
			RzTypeCTypeType *type;
			bool is_const;
		} pointer;
		struct {
			RzTypeCTypeType *type;
			ut64 count;
		} array;
	};
};

RZ_API RzTypeCType *rz_type_ctype_new(void);
RZ_API void rz_type_ctype_free(RzTypeCType *ctype);
RZ_API RzTypeCTypeType *rz_type_ctype_parse(RzTypeCType *ctype, const char *str, char **error);
RZ_API void rz_type_ctype_type_free(RzTypeCTypeType *type);

/* c */
RZ_API char *rz_type_parse_c_string(RzType *type, const char *code, char **error_msg);
RZ_API char *rz_type_parse_c_file(RzType *type, const char *path, const char *dir, char **error_msg);
RZ_API void rz_type_parse_c_reset(RzType *p);

RZ_API void rz_type_remove_parsed_type(RzType *t, const char *name);
RZ_API void rz_type_save_parsed_type(RzType *t, const char *parsed);

RZ_API const char *rz_type_get(RzType *t, const char *name);
RZ_API bool rz_type_set(RzType *t, ut64 at, const char *field, ut64 val);
RZ_API bool rz_type_del(RzType *t, const char *name);
RZ_API int rz_type_kind(RzType *t, const char *name);
RZ_API char *rz_type_enum_member(RzType *t, const char *name, const char *member, ut64 val);
RZ_API RzList *rz_type_enum_find_member(RzType *t, ut64 val);
RZ_API char *rz_type_enum_getbitfield(RzType *t, const char *name, ut64 val);
RZ_API RzList *rz_type_get_enum(RzType *t, const char *name);
RZ_API ut64 rz_type_get_bitsize(RzType *t, const char *type);
RZ_API RzList *rz_type_get_by_offset(RzType *t, ut64 offset);
RZ_API char *rz_type_get_struct_memb(RzType *t, const char *type, int offset);

// Maintaining type links
RZ_API char *rz_type_link_at(RzType *t, ut64 addr);
RZ_API bool rz_type_set_link(RzType *t, const char *val, ut64 addr);
RZ_API bool rz_type_unlink(RzType *t, ut64 addr);
RZ_API bool rz_type_unlink_all(RzType *t);
RZ_API bool rz_type_link_offset(RzType *t, const char *val, ut64 addr);

// Type formats (`tp` and `pf` commands)
RZ_API const char *rz_type_format_get(RzType *t, const char *name);
RZ_API void rz_type_format_set(RzType *t, const char *name, const char *fmt);
RZ_API RZ_OWN RzList *rz_type_format_all(RzType *t);
RZ_API void rz_type_format_delete(RzType *t, const char *name);
RZ_API void rz_type_format_purge(RzType *t);

RZ_API char *rz_type_format(RzType *type, const char *t);
RZ_API int rz_type_format_struct_size(RzType *t, const char *f, int mode, int n);
RZ_API const char *rz_type_format_byname(RzType *t, const char *name);
RZ_API char *rz_type_format_data(RzType *t, RzPrint *p, ut64 seek, const ut8 *b, const int len,
	const char *formatname, int mode, const char *setval, char *ofield);

// Function prototypes api
RZ_API bool rz_type_func_exist(RzType *t, const char *func_name);
RZ_API const char *rz_type_func_cc(RzType *t, const char *func_name);
RZ_API const char *rz_type_func_ret(RzType *t, const char *func_name);
RZ_API const char *rz_type_func_cc(RzType *t, const char *func_name);
RZ_API int rz_type_func_args_count(RzType *t, RZ_NONNULL const char *func_name);
RZ_API RZ_OWN char *rz_type_func_args_type(RzType *t, RZ_NONNULL const char *func_name, int i);
RZ_API const char *rz_type_func_args_name(RzType *t, RZ_NONNULL const char *func_name, int i);
RZ_API bool rz_type_func_arg_count_set(RzType *t, RZ_NONNULL const char *func_name, int arg_count);
RZ_API bool rz_type_func_arg_set(RzType *t, RZ_NONNULL const char *func_name, int i, RZ_NONNULL const char *arg_name, RZ_NONNULL const char *arg_type);
RZ_API bool rz_type_func_ret_set(RzType *t, const char *func_name, const char *type);
RZ_API RZ_OWN char *rz_type_func_guess(RzType *t, RZ_NONNULL char *func_name);
RZ_API RzList *rz_type_noreturn_functions(RzType *type);

// Listing API
RZ_API RzList *rz_type_enums(RzType *type);
RZ_API RzList *rz_type_typedefs(RzType *type);
RZ_API RzList *rz_type_links(RzType *type);

// Serialization API
RZ_API void rz_serialize_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzType *types);
RZ_API bool rz_serialize_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzType *types, RZ_NULLABLE RzSerializeResultInfo *res);

#endif

#ifdef __cplusplus
}
#endif

#endif
