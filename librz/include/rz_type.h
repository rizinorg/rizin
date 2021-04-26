// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef RZ_TYPE_H
#define RZ_TYPE_H

#include <rz_types.h>
#include <rz_util/rz_num.h>
#include <rz_util/rz_print.h>
#include <rz_bind.h>
#include <rz_io.h>
#include <rz_list.h>

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

typedef struct rz_type_parser_t RzTypeParser;

typedef struct rz_type_db_t {
	void *user;
	HtPP *types; // A hashtable of RzBaseType
	HtPP *formats; // A hashtable of `pf` formats
	Sdb *sdb_types; // for function signatures
	RzTypeTarget *target;
	RzTypeParser *parser;
	RNum *num;
	RzIOBind iob; // for RzIO in formats
} RzTypeDB;

// All types in RzTypeDB module are either concrete,
// "base" types that are types already having the
// concrete size and memory layout
// or the "AST" types that are returned from the parser
// and don't contain the size or memory laoyout

typedef struct rz_type_t RzType;

// Base types

typedef enum {
	RZ_BASE_TYPE_KIND_STRUCT,
	RZ_BASE_TYPE_KIND_UNION,
	RZ_BASE_TYPE_KIND_ENUM,
	RZ_BASE_TYPE_KIND_TYPEDEF, // probably temporary addition, dev purposes
	RZ_BASE_TYPE_KIND_ATOMIC, // For real atomic base types
} RzBaseTypeKind;

typedef struct rz_type_enum_case_t {
	char *name;
	st64 val;
} RzTypeEnumCase;

typedef struct rz_type_struct_member_t {
	char *name;
	RzType *type;
	size_t offset; // in bytes
	size_t size; // in bits?
} RzTypeStructMember;

typedef struct rz_type_union_member_t {
	char *name;
	RzType *type;
	size_t offset; // in bytes
	size_t size; // in bits?
} RzTypeUnionMember;

typedef struct rz_base_type_struct_t {
	RzVector /*<RzTypeStructMember>*/ members;
} RzBaseTypeStruct;

typedef struct rz_base_type_union_t {
	RzVector /*<RzTypeUnionMember>*/ members;
} RzBaseTypeUnion;

typedef struct rz_base_type_enum_t {
	RzVector /*<RzTypeEnumCase*/ cases; // list of all the enum cases
} RzBaseTypeEnum;

typedef struct rz_base_type_t {
	char *name;
	RzType *type; // Used by typedef, atomic type, enum
	ut64 size; // size of the whole type in bits
	RzBaseTypeKind kind;
	union {
		RzBaseTypeStruct struct_data;
		RzBaseTypeEnum enum_data;
		RzBaseTypeUnion union_data;
	};
} RzBaseType;

// AST-level types for C and C++
// Parses strings like "const char * [0x42] const * [23]" to RzType

typedef enum {
	RZ_TYPE_KIND_IDENTIFIER,
	RZ_TYPE_KIND_POINTER,
	RZ_TYPE_KIND_ARRAY,
	RZ_TYPE_KIND_CALLABLE
} RzTypeKind;

typedef enum {
	RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED,
	RZ_TYPE_IDENTIFIER_KIND_STRUCT,
	RZ_TYPE_IDENTIFIER_KIND_UNION,
	RZ_TYPE_IDENTIFIER_KIND_ENUM
} RzTypeIdentifierKind;

typedef struct rz_callable_arg_t {
	RZ_NULLABLE char *name; // optional
	RzType *type;
} RzCallableArg;

typedef struct rz_callable_at {
	RzType *ret;
	RzPVector /* RzCallableArg */ args;
	RZ_NULLABLE const char *cc; // optional
	bool noret; // Does not return
} RzCallable;

struct rz_type_t {
	RzTypeKind kind;
	union {
		struct {
			RzTypeIdentifierKind kind;
			char *name;
			bool is_const;
		} identifier;
		struct {
			RzType *type;
			bool is_const;
		} pointer;
		struct {
			RzType *type;
			ut64 count;
		} array;
		RzCallable callable;
	};
};

#ifdef RZ_API

RZ_API RzTypeDB *rz_type_db_new();
RZ_API void rz_type_db_free(RzTypeDB *typedb);
RZ_API bool rz_type_db_load_sdb(RzTypeDB *typedb, const char *dpath);
RZ_API void rz_type_db_purge(RzTypeDB *typedb);
RZ_API void rz_type_db_set_bits(RzTypeDB *typedb, int bits);
RZ_API void rz_type_db_set_os(RzTypeDB *typedb, const char *os);
RZ_API void rz_type_db_set_cpu(RzTypeDB *typedb, const char *cpu);
RZ_API void rz_type_db_set_endian(RzTypeDB *typedb, bool big_endian);
RZ_API ut8 rz_type_db_pointer_size(RzTypeDB *typedb);

RZ_API char *rz_type_db_kuery(RzTypeDB *typedb, const char *query);

RZ_API bool rz_type_db_del(RzTypeDB *typedb, RZ_NONNULL const char *name);

RZ_API void rz_type_db_init(RzTypeDB *typedb, const char *dir_prefix, const char *arch, int bits, const char *os);

// Base types

RZ_API void rz_type_base_type(const RzTypeDB *typedb, const RzBaseType *type);
RZ_API void rz_type_base_type_free(RzBaseType *type);
RZ_API RzBaseType *rz_type_base_type_new(RzBaseTypeKind kind);

RZ_API void rz_type_base_enum_case_free(void *e, void *user);
RZ_API void rz_type_base_struct_member_free(void *e, void *user);
RZ_API void rz_type_base_union_member_free(void *e, void *user);

RZ_API RZ_BORROW RzBaseType *rz_type_db_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API void rz_type_db_save_base_type(const RzTypeDB *typedb, const RzBaseType *type);
RZ_API bool rz_type_db_delete_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *type);

RZ_API RZ_OWN RzList /* RzBaseType */ *rz_type_db_get_base_types_of_kind(const RzTypeDB *typedb, RzBaseTypeKind kind);
RZ_API RZ_OWN RzList /* RzBaseType */ *rz_type_db_get_base_types(const RzTypeDB *typedb);

RZ_API RZ_OWN char *rz_type_db_base_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);

// Compound types

RZ_API RZ_OWN char *rz_type_as_string(RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API void rz_type_free(RzType *type);
RZ_API bool rz_type_exists(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API int rz_type_kind(RzTypeDB *typedb, const char *name);

// Type parser low-level API

RZ_API RzTypeParser *rz_type_parser_new(void);
RZ_API void rz_type_parser_free(RzTypeParser *parser);
RZ_API void rz_type_parser_free_purge(RzTypeParser *parser);

RZ_API int rz_type_parse_string_stateless(RzTypeParser *parser, const char *code, char **error_msg);
RZ_API int rz_type_parse_file_stateless(RzTypeParser *parser, const char *path, const char *dir, char **error_msg);
RZ_API RZ_OWN RzType *rz_type_parse_string_single(RzTypeParser *parser, const char *code, char **error_msg);

// Type parser high-level API

RZ_API int rz_type_parse_string(RzTypeDB *typedb, const char *code, char **error_msg);
RZ_API int rz_type_parse_file(RzTypeDB *typedb, const char *path, const char *dir, char **error_msg);
RZ_API void rz_type_parse_reset(RzTypeDB *typedb);

// Type-specific APIs

RZ_API RzBaseType *rz_type_db_get_enum(RzTypeDB *typedb, const char *name);
RZ_API RzBaseType *rz_type_db_get_union(RzTypeDB *typedb, const char *name);
RZ_API RzBaseType *rz_type_db_get_struct(RzTypeDB *typedb, const char *name);
RZ_API RzBaseType *rz_type_db_get_typedef(RzTypeDB *typedb, RZ_NONNULL const char *name);

RZ_API int rz_type_db_enum_member_by_name(RzTypeDB *typedb, const char *name, const char *member);
RZ_API char *rz_type_db_enum_member_by_val(RzTypeDB *typedb, const char *name, ut64 val);
RZ_API RZ_OWN RzList *rz_type_db_find_enums_by_val(RzTypeDB *typedb, ut64 val);
RZ_API char *rz_type_db_enum_get_bitfield(RzTypeDB *typedb, const char *name, ut64 val);
RZ_OWN RZ_API char *rz_type_db_get_struct_member(RzTypeDB *typedb, RZ_NONNULL const char *name, int offset);

// Type size calculation
RZ_API ut64 rz_type_db_atomic_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype);
RZ_API ut64 rz_type_db_enum_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype);
RZ_API ut64 rz_type_db_struct_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype);
RZ_API ut64 rz_type_db_union_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype);
RZ_API ut64 rz_type_db_get_bitsize(RzTypeDB *typedb, RZ_NONNULL RzType *type);

RZ_API RzList *rz_type_db_get_by_offset(RzTypeDB *typedb, ut64 offset);

// Various type helpers
RZ_API bool rz_type_atomic_eq(RzTypeDB *typedb, RzType *typ1, RzType *typ2);
RZ_API bool rz_type_atomic_str_eq(RzTypeDB *typedb, RzType *typ1, RZ_NONNULL const char *name);
RZ_API bool rz_type_atomic_is_void(RzTypeDB *typedb, RzType *type);
RZ_API bool rz_type_atomic_is_signed(RzTypeDB *typedb, RzType *type);
RZ_API bool rz_type_atomic_is_const(RzTypeDB *typedb, RzType *type);
RZ_API bool rz_type_atomic_is_num(RzTypeDB *typedb, RzType *type);
RZ_API bool rz_type_atomic_set_sign(RzTypeDB *typedb, RzType *type, bool sign);

RZ_API bool rz_type_is_void_ptr(RzType *type);
RZ_API bool rz_type_is_default(RzTypeDB *typedb, RzType *type);

RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype);
RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type_str(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, bool is_const);
RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type_str(RzTypeDB *typedb, RZ_NONNULL const char *name, bool is_const);
RZ_API RZ_OWN RzType *rz_type_array_of_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, size_t count);
RZ_API RZ_OWN RzType *rz_type_array_of_base_type_str(RzTypeDB *typedb, RZ_NONNULL const char *name, size_t count);
RZ_API RZ_OWN RzType *rz_type_pointer_of_type(RzTypeDB *typedb, RZ_NONNULL RzType *type, bool is_const);

// Type formats (`tp` and `pf` commands)
RZ_API const char *rz_type_db_format_get(RzTypeDB *typedb, const char *name);
RZ_API void rz_type_db_format_set(RzTypeDB *typedb, const char *name, const char *fmt);
RZ_API RZ_OWN RzList *rz_type_db_format_all(RzTypeDB *typedb);
RZ_API void rz_type_db_format_delete(RzTypeDB *typedb, const char *name);
RZ_API void rz_type_db_format_purge(RzTypeDB *typedb);

RZ_API const char *rz_base_type_as_format(RzTypeDB *typedb, RZ_NONNULL RzBaseType *type);
RZ_API const char *rz_type_format(RzTypeDB *typedb, const char *type);
RZ_API int rz_type_format_struct_size(RzTypeDB *typedb, const char *f, int mode, int n);
RZ_API char *rz_type_format_data(RzTypeDB *t, RzPrint *p, ut64 seek, const ut8 *b, const int len,
	const char *formatname, int mode, const char *setval, char *ofield);
RZ_API const char *rz_type_as_format(RzTypeDB *typedb, RZ_NONNULL RzType *type);

// Function prototypes api
RZ_API bool rz_type_func_exist(RzTypeDB *typedb, const char *func_name);
RZ_API const char *rz_type_func_cc(RzTypeDB *typedb, const char *func_name);
RZ_API RZ_OWN RzType *rz_type_func_ret(RzTypeDB *typedb, const char *func_name);
RZ_API const char *rz_type_func_cc(RzTypeDB *typedb, const char *func_name);
RZ_API int rz_type_func_args_count(RzTypeDB *typedb, RZ_NONNULL const char *func_name);
RZ_API RZ_OWN RzType *rz_type_func_args_type(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i);
RZ_API const char *rz_type_func_args_name(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i);
RZ_API bool rz_type_func_arg_count_set(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int arg_count);
RZ_API bool rz_type_func_arg_set(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i, RZ_NONNULL const char *arg_name, RZ_NONNULL RzType *arg_type);
RZ_API bool rz_type_func_ret_set(RzTypeDB *typedb, const char *func_name, RZ_NONNULL RzType *type);
RZ_API RZ_OWN char *rz_type_func_guess(RzTypeDB *typedb, RZ_NONNULL char *func_name);

RZ_API RZ_OWN RzList *rz_type_noreturn_functions(RzTypeDB *typedb);
RZ_API bool rz_type_func_is_noreturn(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API bool rz_type_func_noreturn_add(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API bool rz_type_func_noreturn_drop(RzTypeDB *typedb, RZ_NONNULL const char *name);

// Listing API
RZ_API RzList *rz_type_db_enum_names(RzTypeDB *typedb);
RZ_API RzList *rz_type_db_struct_names(RzTypeDB *typedb);
RZ_API RzList *rz_type_db_union_names(RzTypeDB *typedb);
RZ_API RzList *rz_type_db_typedef_names(RzTypeDB *typedb);
RZ_API RzList *rz_type_db_all(RzTypeDB *typedb);

// Serialization API
RZ_API void rz_serialize_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb);
RZ_API bool rz_serialize_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res);

#endif

#ifdef __cplusplus
}
#endif

#endif
