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
	char *cpu;
	int bits;
	int addr_bits; ///< size of a pointer if > 0, otherwise bits is used.
	char *os;
	bool big_endian;
	const char *default_type;
} RzTypeTarget;

typedef struct rz_type_parser_t RzTypeParser;

typedef struct rz_type_db_t {
	void *user;
	HtPP /*<char *, RzBaseType *>*/ *types; //< name -> base type
	HtPP /*<char *, char *>*/ *formats; //< name -> `pf` format
	HtPP /*<char *, RzCallable *>*/ *callables; //< name -> RzCallable (function type)
	RzTypeTarget *target;
	RzTypeParser *parser;
	RzNum *num;
	RzIOBind iob; // for RzIO in formats
} RzTypeDB;

// All types in RzTypeDB module are either concrete,
// "base" types that are types already having the
// concrete size and memory layout
// or the "AST" types that are returned from the parser
// and don't contain the size or memory laoyout

typedef struct rz_type_t RzType;

// Base types

typedef ut64 RzTypeAttribute;

typedef enum {
	// A first group - typeclasses
	RZ_TYPE_ATTRIBUTE_TYPECLASS_MASK = 0xF, //< to store typeclasses
	// The rest are reserved
} RzTypeAttributeMask;

// Typeclasses for atomic types
typedef enum {
	RZ_TYPE_TYPECLASS_NONE, //< most generic types
	RZ_TYPE_TYPECLASS_NUM, //< all numbers
	RZ_TYPE_TYPECLASS_INTEGRAL, //< all integer numbers
	RZ_TYPE_TYPECLASS_FLOATING, //< all floating point numbers
	RZ_TYPE_TYPECLASS_ADDRESS, //< integer types to work with pointers
	RZ_TYPE_TYPECLASS_INTEGRAL_SIGNED, //< all signed integral types (subclass of Integral)
	RZ_TYPE_TYPECLASS_INTEGRAL_UNSIGNED, //< all unsigned integral types (subclass of Integral)
	RZ_TYPE_TYPECLASS_INVALID
} RzTypeTypeclass;

typedef enum {
	RZ_BASE_TYPE_KIND_STRUCT,
	RZ_BASE_TYPE_KIND_UNION,
	RZ_BASE_TYPE_KIND_ENUM,
	RZ_BASE_TYPE_KIND_TYPEDEF,
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
	RzVector /*<RzTypeEnumCase>*/ cases; // list of all the enum cases
} RzBaseTypeEnum;

typedef struct rz_base_type_t {
	char *name;
	RzType *type; // Used by typedef, atomic type, enum
	ut64 size; // size of the whole type in bits
	RzBaseTypeKind kind;
	RzTypeAttribute attrs;
	union {
		RzBaseTypeStruct struct_data;
		RzBaseTypeEnum enum_data;
		RzBaseTypeUnion union_data;
	};
} RzBaseType;

typedef struct rz_base_type_with_metadata_t {
	RzBaseType *base_type;
	char *cu_name;  // compilation unit name
} RzBaseTypeWithMetadata;

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
	RZ_NULLABLE char *name; // optional
	RZ_NULLABLE RzType *ret; /// optional for the time being
	RzPVector /*<RzCallableArg *>*/ *args;
	RZ_NULLABLE const char *cc; // optional
	bool noret : 1; // Does not return
	bool has_unspecified_parameters : 1;
} RzCallable;

struct rz_type_t {
	RzTypeKind kind;
	union {
		struct {
			RzTypeIdentifierKind kind;
			char *name;
			bool is_const; // const char *
		} identifier;
		struct {
			RzType *type;
			bool is_const; // char * const
		} pointer;
		struct {
			RzType *type;
			ut64 count;
		} array;
		RzCallable *callable;
	};
};

typedef struct rz_type_path_t {
	RzType *typ; ///< type at the leaf
	char *path;
} RzTypePath;

/// A path and the type that the path came from
typedef struct rz_type_path_tuple_t {
	RzTypePath *path;
	RzType *root;
} RzTypePathTuple;

/**
 * \brief Type Conditions
 */
typedef enum {
	RZ_TYPE_COND_AL = 0, ///< Always executed (no condition)
	RZ_TYPE_COND_EQ, ///< Equal
	RZ_TYPE_COND_NE, ///< Not equal
	RZ_TYPE_COND_GE, ///< Greater or equal
	RZ_TYPE_COND_GT, ///< Greater than
	RZ_TYPE_COND_LE, ///< Less or equal
	RZ_TYPE_COND_LT, ///< Less than
	RZ_TYPE_COND_NV, ///< Never executed             must be a nop? :D
	RZ_TYPE_COND_HS, ///< Carry set                  >, ==, or unordered
	RZ_TYPE_COND_LO, ///< Carry clear                Less than
	RZ_TYPE_COND_MI, ///< Minus, negative            Less than
	RZ_TYPE_COND_PL, ///< Plus, positive or zero     >, ==, or unordered
	RZ_TYPE_COND_VS, ///< Overflow                   Unordered
	RZ_TYPE_COND_VC, ///< No overflow                Not unordered
	RZ_TYPE_COND_HI, ///< Unsigned higher            Greater than, or unordered
	RZ_TYPE_COND_LS, ///< Unsigned lower or same     Less than or equal
	RZ_TYPE_COND_HEX_SCL_TRUE, // Hexagon only: Scalar instruction if(Pu)
	RZ_TYPE_COND_HEX_SCL_FALSE, // Hexagon only: Scalar instruction if(!Pu)
	RZ_TYPE_COND_HEX_VEC_TRUE, // Hexagon only: Vector instruction if(Pu)
	RZ_TYPE_COND_HEX_VEC_FALSE, // Hexagon only: Vector instruction if(!Pu)
	RZ_TYPE_COND_EXCEPTION, // when the jump is taken only during an exception
} RzTypeCond;

/**
 * \brief type constrained by the type conditions
 */
typedef struct rz_type_constraint_t {
	RzTypeCond cond;
	ut64 val;
} RzTypeConstraint;

typedef enum {
	RZ_TYPE_PRINT_NO_OPTS = 0, // no options
	RZ_TYPE_PRINT_MULTILINE = 1 << 0, // print multiline string (every single type on a single line)
	RZ_TYPE_PRINT_UNFOLD_ANON_ONLY = 1 << 1, // only unfold anonymous structs/unions/enums (applies only to inner members, not the root member)
	RZ_TYPE_PRINT_UNFOLD_ANON_ONLY_STRICT = 1 << 2, // only unfold anonymous structs/unions/enums
	RZ_TYPE_PRINT_ZERO_VLA = 1 << 3, // use [0] to denote VLA instead of (default) []
	RZ_TYPE_PRINT_NO_END_SEMICOLON = 1 << 4, // return a string without a semicolon at end
	RZ_TYPE_PRINT_ANONYMOUS = 1 << 5, // use "[struct|union|enum] anonymous" as the typename for anonymous structs/unions/enums
	RZ_TYPE_PRINT_END_NEWLINE = 1 << 6, // return a string with a newline at the end
	RZ_TYPE_PRINT_SHOW_TYPEDEF = 1 << 7, // show typedefs wherever found
	RZ_TYPE_PRINT_ALLOW_NON_EXISTENT_BASE_TYPE = 1 << 8 // print identifiers even if there is no base type of that name in the db (otherwise "unknown_t")
} RzTypePrintOpts;

/**
 * \brief structure to save format name and definition
 */
typedef struct rz_type_format_t {
	const char *name;
	const char *body;
} RzTypeFormat;

#ifdef RZ_API

RZ_API RzTypeDB *rz_type_db_new();
RZ_API void rz_type_db_free(RzTypeDB *typedb);
RZ_API bool rz_type_db_load_sdb(RzTypeDB *typedb, RZ_NONNULL const char *path);
RZ_API bool rz_type_db_load_sdb_str(RzTypeDB *typedb, RZ_NONNULL const char *str);
RZ_API bool rz_type_db_load_callables_sdb(RzTypeDB *typedb, RZ_NONNULL const char *path);
RZ_API bool rz_type_db_load_callables_sdb_str(RzTypeDB *typedb, RZ_NONNULL const char *str);
RZ_API void rz_type_db_set_bits(RzTypeDB *typedb, int bits);
RZ_API void rz_type_db_set_address_bits(RzTypeDB *typedb, int addr_bits);
RZ_API void rz_type_db_set_os(RzTypeDB *typedb, const char *os);
RZ_API void rz_type_db_set_cpu(RzTypeDB *typedb, const char *cpu);
RZ_API void rz_type_db_set_endian(RzTypeDB *typedb, bool big_endian);

RZ_API ut8 rz_type_db_pointer_size(const RzTypeDB *typedb);

RZ_API bool rz_type_db_del(RzTypeDB *typedb, RZ_NONNULL const char *name);

RZ_API void rz_type_db_init(RzTypeDB *typedb, const char *dir_prefix, const char *arch, int bits, const char *os);
RZ_API void rz_type_db_reload(RzTypeDB *typedb, const char *dir_prefix);
RZ_API void rz_type_db_purge(RzTypeDB *typedb);

// Base types
RZ_API bool rz_base_type_clone_into(
	RZ_NONNULL RZ_BORROW RZ_OUT RzBaseType *dst,
	RZ_NONNULL RZ_BORROW RZ_IN RzBaseType *src);
RZ_API RZ_OWN RzBaseType *rz_base_type_clone(RZ_NULLABLE RZ_BORROW RzBaseType *b);
RZ_API void rz_type_base_type_free(RzBaseType *type);
RZ_API RZ_OWN RzBaseType *rz_type_base_type_new(RzBaseTypeKind kind);
RZ_API RZ_BORROW const char *rz_type_base_type_kind_as_string(RzBaseTypeKind kind);

RZ_API void rz_type_base_enum_case_free(void *e, void *user);
RZ_API void rz_type_base_struct_member_free(void *e, void *user);
RZ_API void rz_type_base_union_member_free(void *e, void *user);

RZ_API RZ_BORROW RzBaseType *rz_type_db_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API RZ_BORROW RzBaseType *rz_type_db_get_compound_type(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API bool rz_type_db_save_base_type(const RzTypeDB *typedb, RzBaseType *type);
RZ_API bool rz_type_db_update_base_type(const RzTypeDB *typedb, RzBaseType *type);
RZ_API bool rz_type_db_delete_base_type(RzTypeDB *typedb, RZ_NONNULL RzBaseType *type);

RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_db_get_base_types_of_kind(const RzTypeDB *typedb, RzBaseTypeKind kind);
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_db_get_base_types(const RzTypeDB *typedb);

RZ_API RZ_OWN char *rz_type_db_base_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype);
RZ_API RZ_OWN char *rz_type_db_base_type_as_pretty_string(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, unsigned int opts, int unfold_level);
RZ_API bool rz_type_db_edit_base_type(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *typestr);
RZ_API RZ_BORROW RzType *rz_type_db_base_type_unwrap_typedef(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype);

// Compound types

RZ_API RZ_OWN RzType *rz_type_clone(RZ_BORROW RZ_NONNULL const RzType *type);
RZ_API RZ_BORROW const char *rz_type_identifier(RZ_NONNULL const RzType *type);
RZ_API bool rz_types_equal(RZ_NONNULL const RzType *type1, RZ_NONNULL const RzType *type2);
RZ_API RZ_OWN char *rz_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API RZ_OWN char *rz_type_declaration_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API RZ_OWN char *rz_type_identifier_declaration_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NONNULL const char *identifier);
RZ_API RZ_OWN char *rz_type_as_pretty_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NULLABLE const char *identifier, unsigned int opts, int unfold_level);
RZ_API void rz_type_free(RZ_NULLABLE RzType *type);
RZ_API bool rz_type_exists(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API int rz_type_kind(RzTypeDB *typedb, RZ_NONNULL const char *name);

// Type classes
RZ_API RZ_BORROW const char *rz_type_typeclass_as_string(RzTypeTypeclass typeclass);
RZ_API RzTypeTypeclass rz_type_typeclass_from_string(RZ_NONNULL const char *typeclass);
RZ_API RzTypeTypeclass rz_base_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);
RZ_API RzTypeTypeclass rz_type_typeclass(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_base_type_is_num(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);
RZ_API bool rz_type_is_num(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_base_type_is_integral(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);
RZ_API bool rz_type_is_integral(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_base_type_is_floating(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);
RZ_API bool rz_type_is_floating(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_base_type_is_integral_signed(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);
RZ_API bool rz_type_is_integral_signed(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_base_type_is_integral_unsigned(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *type);
RZ_API bool rz_type_is_integral_unsigned(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_typeclass_get_all(const RzTypeDB *typedb, RzTypeTypeclass typeclass);
RZ_API RZ_OWN RzList /*<RzBaseType *>*/ *rz_type_typeclass_get_all_sized(const RzTypeDB *typedb, RzTypeTypeclass typeclass, size_t size);
RZ_API RZ_OWN RzBaseType *rz_type_typeclass_get_default_sized(const RzTypeDB *typedb, RzTypeTypeclass typeclass, size_t size);

// Type paths
RZ_API RZ_OWN RzTypePath *rz_type_path_new(RZ_BORROW RZ_NONNULL RzType *type, RZ_OWN RZ_NONNULL char *path);
RZ_API void rz_type_path_free(RZ_NULLABLE RzTypePath *tpath);
RZ_API st64 rz_type_offset_by_path(const RzTypeDB *typedb, RZ_NONNULL const char *path);
RZ_API RZ_OWN RzList /*<RzTypePath *>*/ *rz_base_type_path_by_offset(const RzTypeDB *typedb, const RzBaseType *btype, ut64 offset, unsigned int max_depth);
RZ_API RZ_OWN RzList /*<RzTypePath *>*/ *rz_type_path_by_offset(const RzTypeDB *typedb, const RzType *type, ut64 offset, unsigned int max_depth);
RZ_API RZ_OWN RzList /*<RzTypePath *>*/ *rz_type_db_get_by_offset(const RzTypeDB *typedb, ut64 offset);
RZ_API ut64 rz_type_db_struct_member_packed_offset(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *member);
RZ_API ut64 rz_type_db_struct_member_offset(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *member);

// Type parser low-level API

RZ_API RZ_OWN RzTypeParser *rz_type_parser_new(void);
RZ_API RZ_OWN RzTypeParser *rz_type_parser_init(HtPP *types, HtPP *callables);
RZ_API void rz_type_parser_free(RZ_NONNULL RzTypeParser *parser);
RZ_API void rz_type_parser_free_purge(RZ_NONNULL RzTypeParser *parser);

RZ_API int rz_type_parse_string_stateless(RzTypeParser *parser, const char *code, char **error_msg);
RZ_API int rz_type_parse_file_stateless(RzTypeParser *parser, const char *path, const char *dir, char **error_msg);
RZ_API RZ_OWN RzType *rz_type_parse_string_single(RzTypeParser *parser, const char *code, char **error_msg);
RZ_API RZ_OWN RzType *rz_type_parse_string_declaration_single(RzTypeParser *parser, const char *code, char **error_msg);

// Type parser high-level API

RZ_API int rz_type_parse_string(RzTypeDB *typedb, const char *code, char **error_msg);
RZ_API int rz_type_parse_file(RzTypeDB *typedb, const char *path, const char *dir, char **error_msg);
RZ_API void rz_type_parse_reset(RzTypeDB *typedb);

// Type-specific APIs

RZ_API RzBaseType *rz_type_db_get_enum(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API RzBaseType *rz_type_db_get_union(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API RzBaseType *rz_type_db_get_struct(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API RzBaseType *rz_type_db_get_typedef(const RzTypeDB *typedb, RZ_NONNULL const char *name);

RZ_API int rz_type_db_enum_member_by_name(const RzTypeDB *typedb, RZ_NONNULL const char *name, const char *member);
RZ_API RZ_BORROW const char *rz_type_db_enum_member_by_val(const RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_find_enums_by_val(const RzTypeDB *typedb, ut64 val);
RZ_API RZ_OWN char *rz_type_db_enum_get_bitfield(const RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val);

// Type size calculation
RZ_API ut64 rz_type_db_base_get_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype);
RZ_API ut64 rz_type_db_get_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzType *type);

// Various type helpers
RZ_API bool rz_type_atomic_eq(const RzTypeDB *typedb, RZ_NONNULL const RzType *typ1, RZ_NONNULL const RzType *typ2);
RZ_API bool rz_type_atomic_str_eq(const RzTypeDB *typedb, RZ_NONNULL const RzType *typ1, RZ_NONNULL const char *name);
RZ_API bool rz_type_atomic_is_void(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_type_atomic_is_const(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_type_integral_set_sign(const RzTypeDB *typedb, RZ_NONNULL RzType **type, bool sign);

RZ_API bool rz_type_is_void_ptr(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_void_ptr_nested(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_char_ptr(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_char_ptr_nested(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_identifier(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_strictly_atomic(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_atomic(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_default(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);
RZ_API RZ_OWN RzType *rz_type_new_default(const RzTypeDB *typedb);

RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, bool is_const);
RZ_API RZ_OWN RzType *rz_type_identifier_of_base_type_str(const RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, bool is_const);
RZ_API RZ_OWN RzType *rz_type_pointer_of_base_type_str(const RzTypeDB *typedb, RZ_NONNULL const char *name, bool is_const);
RZ_API RZ_OWN RzType *rz_type_pointer_of_type(const RzTypeDB *typedb, RZ_NONNULL RzType *type, bool is_const);
RZ_API RZ_OWN RzType *rz_type_array_of_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzBaseType *btype, size_t count);
RZ_API RZ_OWN RzType *rz_type_array_of_base_type_str(const RzTypeDB *typedb, RZ_NONNULL const char *name, size_t count);
RZ_API RZ_OWN RzType *rz_type_array_of_type(const RzTypeDB *typedb, RZ_NONNULL RzType *type, size_t count);
RZ_API RZ_OWN RzType *rz_type_callable(RZ_NONNULL RZ_OWN RzCallable *callable);

RZ_API RZ_BORROW RzBaseType *rz_type_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);

// Type formats (`tp` and `pf` commands)
RZ_API const char *rz_type_db_format_get(const RzTypeDB *typedb, const char *name);
RZ_API void rz_type_db_format_set(RzTypeDB *typedb, const char *name, const char *fmt);
RZ_API RZ_OWN RzList /*<RzTypeFormat *>*/ *rz_type_db_format_all(RzTypeDB *typedb);
RZ_API void rz_type_db_format_delete(RzTypeDB *typedb, const char *name);
RZ_API void rz_type_db_format_purge(RzTypeDB *typedb);

RZ_API RZ_OWN char *rz_base_type_as_format(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *type);
RZ_API RZ_OWN char *rz_type_format(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const char *type);
RZ_API int rz_type_format_struct_size(const RzTypeDB *typedb, const char *f, int mode, int n);
RZ_API RZ_OWN char *rz_type_format_data(const RzTypeDB *t, RzPrint *p, ut64 seek, const ut8 *b, const int len,
	const char *formatname, int mode, const char *setval, char *ofield);
RZ_API RZ_OWN char *rz_type_as_format(const RzTypeDB *typedb, RZ_NONNULL RzType *type);
RZ_API RZ_OWN char *rz_type_as_format_pair(const RzTypeDB *typedb, RZ_NONNULL RzType *type);

// Function prototypes api
RZ_API RZ_OWN RzCallable *rz_type_callable_new(RZ_NULLABLE const char *name);
RZ_API RZ_OWN RzCallable *rz_type_callable_clone(RZ_BORROW RZ_NONNULL const RzCallable *callable);
RZ_API void rz_type_callable_free(RZ_NONNULL RzCallable *callable);

RZ_API RZ_OWN RzCallableArg *rz_type_callable_arg_new(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_OWN RZ_NONNULL RzType *type);
RZ_API RZ_OWN RzCallableArg *rz_type_callable_arg_clone(RZ_BORROW RZ_NONNULL const RzCallableArg *arg);
RZ_API void rz_type_callable_arg_free(RzCallableArg *arg);
RZ_API bool rz_type_callable_arg_add(RZ_NONNULL RzCallable *callable, RZ_OWN RZ_NONNULL RzCallableArg *arg);

RZ_API RZ_OWN RzCallable *rz_type_func_new(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_OWN RZ_NULLABLE RzType *type);
RZ_API bool rz_type_func_save(RzTypeDB *typedb, RZ_NONNULL RzCallable *callable);
RZ_API bool rz_type_func_update(RzTypeDB *typedb, RZ_NONNULL RzCallable *callable);
RZ_API RZ_BORROW RzCallable *rz_type_func_get(RzTypeDB *typedb, RZ_NONNULL const char *func_name);
RZ_API bool rz_type_func_delete(RzTypeDB *typedb, RZ_NONNULL const char *func_name);
RZ_API void rz_type_func_delete_all(RzTypeDB *typedb);
RZ_API bool rz_type_func_exist(RzTypeDB *typedb, RZ_NONNULL const char *func_name);

RZ_API RZ_BORROW RzType *rz_type_func_ret(RzTypeDB *typedb, RZ_NONNULL const char *func_name);
RZ_API bool rz_type_func_ret_set(RzTypeDB *typedb, const char *func_name, RZ_BORROW RZ_NONNULL RzType *type);

RZ_API RZ_BORROW const char *rz_type_func_cc(RzTypeDB *typedb, RZ_NONNULL const char *func_name);
RZ_API bool rz_type_func_cc_set(RzTypeDB *typedb, const char *name, const char *cc);

RZ_API int rz_type_func_args_count(RzTypeDB *typedb, RZ_NONNULL const char *func_name);
RZ_API RZ_BORROW RzType *rz_type_func_args_type(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i);
RZ_API RZ_BORROW const char *rz_type_func_args_name(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i);
RZ_API bool rz_type_func_arg_add(RzTypeDB *typedb, RZ_NONNULL const char *func_name, RZ_NONNULL const char *arg_name, RZ_OWN RZ_NONNULL RzType *arg_type);

RZ_API bool rz_type_is_callable(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_callable_ptr(RZ_NONNULL const RzType *type);
RZ_API bool rz_type_is_callable_ptr_nested(RZ_NONNULL const RzType *type);
RZ_API RZ_OWN char *rz_type_callable_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzCallable *callable);
RZ_API RZ_OWN char *rz_type_callable_ptr_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type);

RZ_API bool rz_type_func_is_noreturn(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API bool rz_type_func_noreturn_add(RzTypeDB *typedb, RZ_NONNULL const char *name);
RZ_API bool rz_type_func_noreturn_drop(RzTypeDB *typedb, RZ_NONNULL const char *name);

RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_function_names(RzTypeDB *typedb);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_noreturn_function_names(RzTypeDB *typedb);

// Listing API
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_enum_names(RzTypeDB *typedb);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_struct_names(RzTypeDB *typedb);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_union_names(RzTypeDB *typedb);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_typedef_names(RzTypeDB *typedb);
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_all(RzTypeDB *typedb);

// Serialization API
RZ_API void rz_serialize_types_save(RZ_NONNULL Sdb *db, RZ_NONNULL const RzTypeDB *typedb);
RZ_API bool rz_serialize_types_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res);
RZ_API void rz_serialize_callables_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb);
RZ_API bool rz_serialize_callables_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res);

// Constrained Type
RZ_API RZ_BORROW const char *rz_type_cond_tostring(RzTypeCond cc);
RZ_API RzTypeCond rz_type_cond_invert(RzTypeCond cond);
RZ_API bool rz_type_cond_eval(RzTypeCond cond, st64 arg0, st64 arg1);
RZ_API bool rz_type_cond_eval_single(RzTypeCond cond, st64 arg0);
#endif

#ifdef __cplusplus
}
#endif

#endif
