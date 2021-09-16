// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2019-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

static void types_ht_free(HtPPKv *kv) {
	free(kv->key);
	rz_type_base_type_free(kv->value);
}

static void formats_ht_free(HtPPKv *kv) {
	free(kv->key);
	free(kv->value);
}

static void callables_ht_free(HtPPKv *kv) {
	free(kv->key);
	rz_type_callable_free(kv->value);
}

/**
 * \brief Creates a new instance of the RzTypeDB
 *
 * Creates the RzTypeDB instance, initializes
 * hashtables for RzBaseType, RzCallable, type formats.
 * Also initializes default "target" (arch, bits, platform) parameters.
 */
RZ_API RzTypeDB *rz_type_db_new() {
	RzTypeDB *typedb = RZ_NEW0(RzTypeDB);
	if (!typedb) {
		return NULL;
	}
	typedb->target = RZ_NEW0(RzTypeTarget);
	if (!typedb->target) {
		free(typedb);
		return NULL;
	}
	typedb->target->default_type = strdup("int");
	typedb->types = ht_pp_new(NULL, types_ht_free, NULL);
	if (!typedb->types) {
		goto rz_type_db_new_fail;
	}
	typedb->formats = ht_pp_new(NULL, formats_ht_free, NULL);
	if (!typedb->formats) {
		goto rz_type_db_new_fail;
	}
	typedb->callables = ht_pp_new(NULL, callables_ht_free, NULL);
	if (!typedb->callables) {
		goto rz_type_db_new_fail;
	}
	typedb->parser = rz_type_parser_init(typedb->types, typedb->callables);
	if (!typedb->parser) {
		goto rz_type_db_new_fail;
	}
	rz_io_bind_init(typedb->iob);
	return typedb;

rz_type_db_new_fail:
	free((void *)typedb->target->default_type);
	free(typedb->target);
	ht_pp_free(typedb->types);
	ht_pp_free(typedb->formats);
	ht_pp_free(typedb->callables);
	free(typedb);
	return NULL;
}

/**
 * \brief Frees the instance of the RzTypeDB
 *
 * Destroys hashtables for RzBaseType, RzCallable, type formats.
 */
RZ_API void rz_type_db_free(RzTypeDB *typedb) {
	rz_type_parser_free(typedb->parser);
	ht_pp_free(typedb->callables);
	ht_pp_free(typedb->types);
	ht_pp_free(typedb->formats);
	free((void *)typedb->target->default_type);
	free(typedb->target->os);
	free(typedb->target->cpu);
	free(typedb->target);
	free(typedb);
}

/**
 * \brief Purges the instance of the RzTypeDB
 *
 * Destroys all loaded base types and callable types.
 */
RZ_API void rz_type_db_purge(RzTypeDB *typedb) {
	ht_pp_free(typedb->callables);
	typedb->callables = ht_pp_new(NULL, callables_ht_free, NULL);
	ht_pp_free(typedb->types);
	typedb->types = ht_pp_new(NULL, types_ht_free, NULL);
	rz_type_parser_free(typedb->parser);
	typedb->parser = rz_type_parser_init(typedb->types, typedb->callables);
}

/**
 * \brief Purges formats in the instance of the RzTypeDB
 */
RZ_API void rz_type_db_format_purge(RzTypeDB *typedb) {
	ht_pp_free(typedb->formats);
	typedb->formats = ht_pp_new(NULL, formats_ht_free, NULL);
}

static void set_default_type(RzTypeTarget *target, int bits) {
	if (target->default_type) {
		free((void *)target->default_type);
	}
	switch (bits) {
	case 8:
		target->default_type = strdup("int8_t");
		break;
	case 16:
		target->default_type = strdup("int16_t");
		break;
	case 32:
		target->default_type = strdup("int32_t");
		break;
	case 64:
		target->default_type = strdup("int64_t");
		break;
	default:
		rz_warn_if_reached();
		target->default_type = strdup("int");
	}
}

/**
 * \brief Set the RzType target architecture bits
 *
 * Important for calculating some types size, especially
 * pointers's size.
 *
 * \param typedb RzTypeDB instance
 * \param bits Architecture bits to set
 */
RZ_API void rz_type_db_set_bits(RzTypeDB *typedb, int bits) {
	typedb->target->bits = bits;
	// Also set the new default type
	set_default_type(typedb->target, bits);
}

/**
 * \brief Set the RzType target architecture operating system
 *
 * Important for calculating some types size, especially
 * pointers's size.
 *
 * \param typedb RzTypeDB instance
 * \param os Operating system name to set
 */
RZ_API void rz_type_db_set_os(RzTypeDB *typedb, const char *os) {
	free(typedb->target->os);
	typedb->target->os = os ? strdup(os) : NULL;
}

/**
 * \brief Set the RzType target architecture CPU
 *
 * Important for calculating some types size, especially
 * pointers's size.
 *
 * \param typedb RzTypeDB instance
 * \param cpu Architecture name to set
 */
RZ_API void rz_type_db_set_cpu(RzTypeDB *typedb, const char *cpu) {
	free(typedb->target->cpu);
	typedb->target->cpu = cpu ? strdup(cpu) : NULL;
}

/**
 * \brief Set the RzType target architecture CPU
 *
 * Important for calculating complex types layout.
 *
 * \param typedb RzTypeDB instance
 * \param big_endian True if the big endian, false if the opposite
 */
RZ_API void rz_type_db_set_endian(RzTypeDB *typedb, bool big_endian) {
	typedb->target->big_endian = big_endian;
}

/**
 * \brief Returns the pointer size for the current RzTypeDB target set
 *
 * \param typedb RzTypeDB instance
 */
RZ_API ut8 rz_type_db_pointer_size(const RzTypeDB *typedb) {
	// TODO: Handle more special cases where the pointer
	// size is different from the target bitness
	return typedb->target->bits;
}

/**
 * \brief Removes the type from the database.
 *
 * Can remove either RzBaseType or RzCallable type
 *
 * \param typedb RzTypeDB instance
 * \param name RzBaseType or RzCallable type name
 */
RZ_API bool rz_type_db_del(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		if (!rz_type_func_exist(typedb, name)) {
			eprintf("Unrecognized type \"%s\"\n", name);
			return false;
		}
		rz_type_func_delete(typedb, name);
		return true;
	}
	rz_type_db_delete_base_type(typedb, btype);
	return true;
}

/**
 * \brief Initializes the types database for specified arch, bits, OS
 *
 * Loads pre-shipped type libraries for base types and function types.
 * Different architectures, operating systems, bitness affects
 * on what exact types are loaded, also some atomic types sizes are different.
 * In some cases the same type, for example, structure type could have
 * a different layout, depending on the operating system or bitness.
 *
 * \param typedb Types Database instance
 * \param dir_prefix Directory where all type libraries are installed
 * \param arch Architecture of the analysis session
 * \param bits Bitness of the analysis session
 * \param os Operating system of the analysis session
 */
RZ_API void rz_type_db_init(RzTypeDB *typedb, const char *dir_prefix, const char *arch, int bits, const char *os) {
	rz_return_if_fail(typedb && typedb->types && typedb->formats);

	// A workaround to fix loading incorrectly detected MacOS binaries
	if (os && RZ_STR_ISNOTEMPTY(os) && !strcmp(os, "darwin")) {
		os = "macos";
	}

	// At first we load the basic types
	// Atomic types
	const char *dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-atomic.sdb"), dir_prefix);
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}
	// C runtime types
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-libc.sdb"), dir_prefix);
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}

	// We do not load further if bits are not specified
	if (bits <= 0) {
		return;
	}

	// Bits-specific types that are independent from architecture or OS
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%d.sdb"),
		dir_prefix, bits);
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}

	// We do not load further if architecture is not specified
	if (!arch) {
		return;
	}

	// Architecture-specific types
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%s.sdb"),
		dir_prefix, arch);
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}

	// Architecture- and bits-specific types
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%s-%d.sdb"),
		dir_prefix, arch, bits);
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}

	if (os) {
		// OS-specific types
		dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%s.sdb"),
			dir_prefix, os);
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%s-%d.sdb"),
			dir_prefix, os, bits);
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%s-%s.sdb"),
			dir_prefix, arch, os);
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "types-%s-%s-%d.sdb"),
			dir_prefix, arch, os, bits);
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
	}

	// Then, after all basic types are initialized, we load function types
	// that use loaded previously base types for return and arguments
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "functions-libc.sdb"), dir_prefix);
	if (rz_type_db_load_callables_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("callable types: loaded \"%s\"\n", dbpath);
	}
	// OS-specific function types
	if (os) {
		dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_TYPES, "functions-%s.sdb"),
			dir_prefix, os);
		if (rz_type_db_load_callables_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("callable types: loaded \"%s\"\n", dbpath);
		}
	}
}

/**
 * \brief Re-initializes the types database for current target
 *
 * Similarly to rz_type_db_init loads pre-shipped type libraries
 * for base types and function types.
 *
 * \param typedb Types Database instance
 * \param dir_prefix Directory where all type libraries are installed
 */
RZ_API void rz_type_db_reload(RzTypeDB *typedb, const char *dir_prefix) {
	rz_type_db_purge(typedb);
	rz_type_db_init(typedb, dir_prefix, typedb->target->cpu, typedb->target->bits, typedb->target->os);
}

// Listing all available types by category

/**
 * \brief Returns the list of all enum names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_db_enum_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *enums = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzList *result = rz_list_new();
	RzListIter *iter;
	RzBaseType *e;
	rz_list_foreach (enums, iter, e) {
		rz_list_append(result, e->name);
	}
	rz_list_free(enums);
	return result;
}

/**
 * \brief Returns the list of all union names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_db_union_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *unions = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_UNION);
	RzList *result = rz_list_new();
	RzListIter *iter;
	RzBaseType *u;
	rz_list_foreach (unions, iter, u) {
		rz_list_append(result, u->name);
	}
	rz_list_free(unions);
	return result;
}

/**
 * \brief Returns the list of all struct names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_db_struct_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *structs = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_STRUCT);
	RzList *result = rz_list_new();
	RzListIter *iter;
	RzBaseType *s;
	rz_list_foreach (structs, iter, s) {
		rz_list_append(result, s->name);
	}
	rz_list_free(structs);
	return result;
}

/**
 * \brief Returns the list of all typedef (type aliases) names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_db_typedef_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *typedefs = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_TYPEDEF);
	RzList *result = rz_list_new();
	RzListIter *iter;
	RzBaseType *t;
	rz_list_foreach (typedefs, iter, t) {
		rz_list_append(result, t->name);
	}
	rz_list_free(typedefs);
	return result;
}

/**
 * \brief Returns the list of all type names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList *rz_type_db_all(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_type_db_get_base_types(typedb);
	RzList *result = rz_list_new();
	RzListIter *iter;
	RzBaseType *t;
	rz_list_foreach (types, iter, t) {
		rz_list_append(result, t->name);
	}
	rz_list_free(types);
	return result;
}

// Type-specific APIs

/**
 * \brief Checks if the type exists in the Type database
 *
 * \param typedb Types Database instance
 * \param name Name of the type
 */
RZ_API bool rz_type_exists(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, -1);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	return btype != NULL;
}

/**
 * \brief Returns the kind (RzBaseTypeKind) of the type
 *
 * \param typedb Types Database instance
 * \param name Name of the type
 */
RZ_API int rz_type_kind(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, -1);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return -1;
	}
	return btype->kind;
}

/**
 * \brief Returns the enum base type matching the specified name
 *
 * \param typedb Types Database instance
 * \param name The name of the enum to match against
 */
RZ_API RzBaseType *rz_type_db_get_enum(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	return btype;
}

/**
 * \brief Returns the enum case name matching the cpecified value
 *
 * \param typedb Types Database instance
 * \param name The name of the enum to search in
 * \param val The value to search for
 */
RZ_API RZ_BORROW char *rz_type_db_enum_member_by_val(const RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	RzTypeEnumCase *cas;
	rz_vector_foreach(&btype->enum_data.cases, cas) {
		if (cas->val == val) {
			return cas->name;
		}
	}
	return NULL;
}

/**
 * \brief Returns the enum case value matched by the enum case name
 *
 * \param typedb Types Database instance
 * \param name The name of the enum to search in
 * \param member The enum case name to search for
 */
RZ_API int rz_type_db_enum_member_by_name(const RzTypeDB *typedb, RZ_NONNULL const char *name, const char *member) {
	rz_return_val_if_fail(typedb && name, -1);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return -1;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return -1;
	}
	RzTypeEnumCase *cas;
	int result = -1;
	rz_vector_foreach(&btype->enum_data.cases, cas) {
		if (!strcmp(cas->name, member)) {
			result = cas->val;
			break;
		}
	}
	return result;
}

/**
 * \brief Returns all enums and cases name matching the specified value
 *
 * \param typedb Types Database instance
 * \param val The value to search for
 */
RZ_API RZ_OWN RzList *rz_type_db_find_enums_by_val(const RzTypeDB *typedb, ut64 val) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *enums = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzList *result = rz_list_newf(free);
	RzListIter *iter;
	RzBaseType *e;
	rz_list_foreach (enums, iter, e) {
		RzTypeEnumCase *cas;
		rz_vector_foreach(&e->enum_data.cases, cas) {
			if (cas->val == val) {
				rz_list_append(result, rz_str_newf("%s.%s", e->name, cas->name));
			}
		}
	}
	rz_list_free(enums);
	return result;
}

/**
 * \brief Returns all matching bitfields as an OR mask given the resulting value
 *
 * \param typedb Types Database instance
 * \param name The name of the bitfield enum
 * \param val The value to search for
 */
RZ_OWN RZ_API char *rz_type_db_enum_get_bitfield(const RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	char *res = NULL;
	int i;
	bool isFirst = true;

	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	char *ret = rz_str_newf("0x%08" PFMT64x " : ", val);
	for (i = 0; i < 32; i++) {
		ut32 n = 1ULL << i;
		if (!(val & n)) {
			continue;
		}
		RzTypeEnumCase *cas;
		rz_vector_foreach(&btype->enum_data.cases, cas) {
			if (cas->val == n) {
				res = cas->name;
				break;
			}
		}
		if (isFirst) {
			isFirst = false;
		} else {
			ret = rz_str_append(ret, " | ");
		}
		if (res) {
			ret = rz_str_append(ret, res);
		} else {
			ret = rz_str_appendf(ret, "0x%x", n);
		}
	}
	return ret;
}

/**
 * \brief Returns the union base type matching the specified name
 *
 * \param typedb Types Database instance
 * \param name The name of the union to match against
 */
RZ_API RzBaseType *rz_type_db_get_union(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_UNION) {
		return NULL;
	}
	return btype;
}

/**
 * \brief returns the struct base type matching the specified name
 *
 * \param typedb types database instance
 * \param name the name of the struct to match against
 */
RZ_API RzBaseType *rz_type_db_get_struct(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		return NULL;
	}
	return btype;
}

/**
 * \brief Returns the typedef base type matching the specified name
 *
 * \param typedb Types Database instance
 * \param name The name of the typedef to match against
 */
RZ_API RzBaseType *rz_type_db_get_typedef(const RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_TYPEDEF) {
		return NULL;
	}
	return btype;
}

/**
 * \brief Returns the atomic type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_atomic_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_ATOMIC, 0);
	return btype->size;
}

/**
 * \brief Returns the enum type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_enum_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_ENUM, 0);
	// FIXME: Need a proper way to determine size of enum
	return 32;
}

/**
 * \brief Returns the struct type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_struct_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_STRUCT, 0);
	RzTypeStructMember *memb;
	ut64 size = 0;
	rz_vector_foreach(&btype->struct_data.members, memb) {
		size += rz_type_db_get_bitsize(typedb, memb->type);
	}
	return size;
}

/**
 * \brief Returns the union type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_union_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_UNION, 0);
	RzTypeUnionMember *memb;
	ut64 size = 0;
	// Union has the size of the maximum size of its elements
	rz_vector_foreach(&btype->union_data.members, memb) {
		size = RZ_MAX(rz_type_db_get_bitsize(typedb, memb->type), size);
	}
	return size;
}

/**
 * \brief Returns the typedef type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_typedef_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF, 0);
	rz_return_val_if_fail(btype->type, 0);
	if (btype->type->kind == RZ_TYPE_KIND_IDENTIFIER && !strcmp(btype->type->identifier.name, btype->name)) {
		return btype->size;
	}
	return rz_type_db_get_bitsize(typedb, btype->type);
}

/**
 * \brief Returns the base type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_base_get_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype, 0);
	if (btype->kind == RZ_BASE_TYPE_KIND_ENUM) {
		return rz_type_db_enum_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		return rz_type_db_struct_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		return rz_type_db_union_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_ATOMIC) {
		return rz_type_db_atomic_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF) {
		return rz_type_db_typedef_bitsize(typedb, btype);
	}
	// Should not happen
	rz_warn_if_reached();
	return 0;
}

/**
 * \brief Returns the type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param type The type
 */
RZ_API ut64 rz_type_db_get_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && type, 0);
	// Detect if the pointer and return the corresponding size
	if (type->kind == RZ_TYPE_KIND_POINTER || type->kind == RZ_TYPE_KIND_CALLABLE) {
		// Note, that function types (RzCallable) are in fact pointers too
		return rz_type_db_pointer_size(typedb);
		// Detect if the pointer is array, then return the bitsize of the base type
		// multiplied to the array size
	} else if (type->kind == RZ_TYPE_KIND_ARRAY) {
		return type->array.count * rz_type_db_get_bitsize(typedb, type->array.type);
	}
	// The rest of the logic is for the normal, identifier types
	RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
	if (!btype) {
		return 0;
	}
	if (btype->kind == RZ_BASE_TYPE_KIND_ENUM && type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_ENUM) {
		return rz_type_db_enum_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT && type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_STRUCT) {
		return rz_type_db_struct_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_UNION && type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNION) {
		return rz_type_db_union_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_ATOMIC) {
		return rz_type_db_atomic_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF) {
		return rz_type_db_typedef_bitsize(typedb, btype);
	}
	// Should not happen
	rz_warn_if_reached();
	return 0;
}

struct HelperBufs {
	RzStrBuf *arraybuf;
	RzStrBuf *ptrbuf;
};

static void helper_bufs_init(struct HelperBufs *hbs) {
	hbs->arraybuf = rz_strbuf_new("");
	hbs->ptrbuf = rz_strbuf_new("");
}

static void helper_bufs_fini(struct HelperBufs *hbs) {
	rz_strbuf_free(hbs->arraybuf);
	rz_strbuf_free(hbs->ptrbuf);
}

static char *type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NONNULL struct HelperBufs *bufs) {
	rz_return_val_if_fail(typedb && type && bufs, NULL);

	RzStrBuf *buf = rz_strbuf_new("");
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		// Here it can be any of the RzBaseType
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			rz_strbuf_append(buf, "unknown_t");
		} else {
			if (type->identifier.is_const) {
				rz_strbuf_append(buf, "const ");
			}
			switch (btype->kind) {
			case RZ_BASE_TYPE_KIND_UNION:
				rz_strbuf_append(buf, "union ");
				break;
			case RZ_BASE_TYPE_KIND_STRUCT:
				rz_strbuf_append(buf, "struct ");
				break;
			default:
				break;
			}
			rz_strbuf_append(buf, btype->name);
		}
		if (!rz_strbuf_is_empty(bufs->ptrbuf) || !rz_strbuf_is_empty(bufs->arraybuf)) {
			rz_strbuf_appendf(buf, " %s%s", rz_strbuf_get(bufs->ptrbuf), rz_strbuf_get(bufs->arraybuf));
		}
		break;
	}
	case RZ_TYPE_KIND_POINTER: {
		// A pointer to the function is a special case
		if (rz_type_is_callable_ptr_nested(type)) {
			char *typestr = rz_type_callable_ptr_as_string(typedb, type);
			rz_strbuf_append(buf, typestr);
			free(typestr);
		} else {
			if (type->pointer.is_const) {
				rz_strbuf_prepend(bufs->ptrbuf, "* const ");
			} else {
				rz_strbuf_prepend(bufs->ptrbuf, "*");
			}
			char *typestr = type_as_string(typedb, type->pointer.type, bufs);
			rz_strbuf_append(buf, typestr);
			free(typestr);
		}
		break;
	}
	case RZ_TYPE_KIND_ARRAY: {
		rz_strbuf_appendf(bufs->arraybuf, "[%" PFMT64d "]", type->array.count);
		char *typestr = type_as_string(typedb, type->array.type, bufs);
		rz_strbuf_append(buf, typestr);
		free(typestr);
		break;
	}
	case RZ_TYPE_KIND_CALLABLE: {
		char *callstr = rz_type_callable_as_string(typedb, type->callable);
		rz_strbuf_append(buf, callstr);
		free(callstr);
		break;
	}
	}
	return rz_strbuf_drain(buf);
}

static char *type_as_string_decl(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NONNULL struct HelperBufs *bufs) {
	rz_return_val_if_fail(typedb && type && bufs, NULL);

	RzStrBuf *buf = rz_strbuf_new("");
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		rz_return_val_if_fail(type->identifier.name, NULL);
		// Here it can be any of the RzBaseType
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			rz_strbuf_append(buf, "unknown_t");
		} else {
			char *btypestr = btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF ? strdup(btype->name) : rz_type_db_base_type_as_string(typedb, btype);
			if (type->identifier.is_const) {
				rz_strbuf_appendf(buf, "const %s", btypestr);
			} else {
				rz_strbuf_append(buf, btypestr);
			}
			free(btypestr);
		}
		if (!rz_strbuf_is_empty(bufs->ptrbuf) || !rz_strbuf_is_empty(bufs->arraybuf)) {
			rz_strbuf_appendf(buf, " %s%s", rz_strbuf_get(bufs->ptrbuf), rz_strbuf_get(bufs->arraybuf));
		}
		break;
	}
	case RZ_TYPE_KIND_POINTER: {
		// A pointer to the function is a special case
		if (rz_type_is_callable_ptr_nested(type)) {
			char *typestr = rz_type_callable_ptr_as_string(typedb, type);
			rz_strbuf_append(buf, typestr);
			free(typestr);
		} else {
			if (type->pointer.is_const) {
				rz_strbuf_prepend(bufs->ptrbuf, "* const ");
			} else {
				rz_strbuf_prepend(bufs->ptrbuf, "*");
			}
			char *typestr = type_as_string_decl(typedb, type->pointer.type, bufs);
			rz_strbuf_append(buf, typestr);
			free(typestr);
		}
		break;
	}
	case RZ_TYPE_KIND_ARRAY: {
		rz_strbuf_appendf(bufs->arraybuf, "[%" PFMT64d "]", type->array.count);
		char *typestr = type_as_string_decl(typedb, type->array.type, bufs);
		rz_strbuf_append(buf, typestr);
		free(typestr);
		break;
	}
	case RZ_TYPE_KIND_CALLABLE: {
		char *callstr = rz_type_callable_as_string(typedb, type->callable);
		rz_strbuf_append(buf, callstr);
		free(callstr);
		break;
	}
	}
	char *result = rz_strbuf_drain(buf);
	return result;
}

static char *type_as_string_identifier_decl(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NONNULL const char *identifier, RZ_NONNULL struct HelperBufs *bufs) {
	rz_return_val_if_fail(typedb && type && identifier && bufs, NULL);

	RzStrBuf *buf = rz_strbuf_new("");
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		rz_return_val_if_fail(type->identifier.name, NULL);
		// Here it can be any of the RzBaseType
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			rz_strbuf_append(buf, "unknown_t");
		} else {
			// If the structure/union is anonymous, then we put declaration inline,
			// if not - just the name
			if (!strncmp(type->identifier.name, "anonymous ", 10)) {
				char *btypestr = btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF ? strdup(btype->name) : rz_type_db_base_type_as_string(typedb, btype);
				if (type->identifier.is_const) {
					rz_strbuf_appendf(buf, "const %s", btypestr);
				} else {
					rz_strbuf_append(buf, btypestr);
				}
				free(btypestr);
			} else {
				if (type->identifier.is_const) {
					rz_strbuf_append(buf, "const ");
				}
				switch (btype->kind) {
				case RZ_BASE_TYPE_KIND_UNION:
					rz_strbuf_append(buf, "union ");
					break;
				case RZ_BASE_TYPE_KIND_STRUCT:
					rz_strbuf_append(buf, "struct ");
					break;
				default:
					break;
				}
				rz_strbuf_append(buf, btype->name);
			}
		}
		rz_strbuf_appendf(buf, " %s%s%s", rz_strbuf_get(bufs->ptrbuf), identifier, rz_strbuf_get(bufs->arraybuf));
		break;
	}
	case RZ_TYPE_KIND_POINTER: {
		// A pointer to the function is a special case
		if (rz_type_is_callable_ptr_nested(type)) {
			char *typestr = rz_type_callable_ptr_as_string(typedb, type);
			rz_strbuf_append(buf, typestr);
			free(typestr);
		} else {
			if (type->pointer.is_const) {
				rz_strbuf_prepend(bufs->ptrbuf, "* const ");
			} else {
				rz_strbuf_prepend(bufs->ptrbuf, "*");
			}
			char *typestr = type_as_string_identifier_decl(typedb, type->pointer.type, identifier, bufs);
			rz_strbuf_append(buf, typestr);
			free(typestr);
		}
		break;
	}
	case RZ_TYPE_KIND_ARRAY: {
		rz_strbuf_appendf(bufs->arraybuf, "[%" PFMT64d "]", type->array.count);
		char *typestr = type_as_string_identifier_decl(typedb, type->array.type, identifier, bufs);
		rz_strbuf_append(buf, typestr);
		free(typestr);
		break;
	}
	case RZ_TYPE_KIND_CALLABLE: {
		char *callstr = rz_type_callable_as_string(typedb, type->callable);
		rz_strbuf_append(buf, callstr);
		free(callstr);
		break;
	}
	}
	return rz_strbuf_drain(buf);
}

/**
 * \brief Returns the type C representation
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	struct HelperBufs bufs;
	helper_bufs_init(&bufs);
	char *r = type_as_string(typedb, type, &bufs);
	helper_bufs_fini(&bufs);
	return r;
}

/**
 * \brief Returns the type C declaration representation
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_declaration_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	struct HelperBufs bufs;
	helper_bufs_init(&bufs);
	char *r = type_as_string_decl(typedb, type, &bufs);
	helper_bufs_fini(&bufs);
	return r;
}

/**
 * \brief Returns the type C representation with identifier
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_identifier_declaration_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NONNULL const char *identifier) {
	rz_return_val_if_fail(typedb && type, NULL);
	struct HelperBufs bufs;
	helper_bufs_init(&bufs);
	char *r = type_as_string_identifier_decl(typedb, type, identifier, &bufs);
	helper_bufs_fini(&bufs);
	return r;
}

/**
 * \brief Returns the type C identifier
 *
 * In case of the compound types it returns the name of identifier
 * For example, for "char **ptr" it will return "char",
 * for "const int **arr[56][76]" it will return "int"
 *
 * \param type RzType type
 */
RZ_API RZ_BORROW const char *rz_type_identifier(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, NULL);

	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		// Here it can be any of the RzBaseType
		return type->identifier.name;
	}
	case RZ_TYPE_KIND_POINTER: {
		return rz_type_identifier(type->pointer.type);
	}
	case RZ_TYPE_KIND_ARRAY: {
		return rz_type_identifier(type->array.type);
		break;
	}
	case RZ_TYPE_KIND_CALLABLE:
		return type->callable->name;
	}
	return NULL;
}

/**
 * \brief Creates an exact clone of the RzType
 *
 * \param type RzType pointer
 */
RZ_API RZ_OWN RzType *rz_type_clone(RZ_BORROW RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, NULL);
	RzType *newtype = RZ_NEW0(RzType);
	if (!newtype) {
		return NULL;
	}
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER:
		newtype->kind = type->kind;
		newtype->identifier.kind = type->identifier.kind;
		newtype->identifier.is_const = type->identifier.is_const;
		newtype->identifier.name = strdup(type->identifier.name);
		break;
	case RZ_TYPE_KIND_ARRAY:
		newtype->kind = RZ_TYPE_KIND_ARRAY;
		newtype->array.count = type->array.count;
		newtype->array.type = rz_type_clone(type->array.type);
		break;
	case RZ_TYPE_KIND_POINTER:
		newtype->kind = RZ_TYPE_KIND_POINTER;
		newtype->pointer.is_const = type->pointer.is_const;
		newtype->pointer.type = rz_type_clone(type->pointer.type);
		break;
	case RZ_TYPE_KIND_CALLABLE:
		newtype->kind = RZ_TYPE_KIND_CALLABLE;
		newtype->callable = rz_type_callable_clone(type->callable);
		break;
	}
	return newtype;
}

/**
 * \brief Checks if two types are identical
 *
 * \param type1 RzType pointer
 * \param type2 RzType pointer
 */
RZ_API bool rz_types_equal(RZ_NONNULL const RzType *type1, RZ_NONNULL const RzType *type2) {
	rz_return_val_if_fail(type1 && type2, false);
	if (type1->kind != type2->kind) {
		return false;
	}
	switch (type1->kind) {
	case RZ_TYPE_KIND_IDENTIFIER:
		return !strcmp(type1->identifier.name, type2->identifier.name);
	case RZ_TYPE_KIND_POINTER:
		rz_return_val_if_fail(type1->pointer.type && type2->pointer.type, false);
		return rz_types_equal(type1->pointer.type, type2->pointer.type);
	case RZ_TYPE_KIND_ARRAY:
		if (type1->array.count != type2->array.count) {
			return false;
		}
		return rz_types_equal(type1->array.type, type2->array.type);
	case RZ_TYPE_KIND_CALLABLE:
		rz_return_val_if_fail(type1->callable && type2->callable, false);
		rz_return_val_if_fail(type1->callable->name && type2->callable->name, false);
		return !strcmp(type1->callable->name, type2->callable->name);
	default:
		rz_warn_if_reached();
		return false;
	}
	return false;
}

/**
 * \brief Returns the RzBaseType for the chosen RzType
 *
 * \param typedb Type Database instance
 * \param type RzType type pointer
 */
RZ_API RZ_BORROW RzBaseType *rz_type_get_base_type(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	const char *identifier = rz_type_identifier(type);
	if (!identifier) {
		return NULL;
	}
	RzBaseType *btype = rz_type_db_get_base_type(typedb, identifier);
	if (!btype) {
		return NULL;
	}
	return btype;
}

/**
 * \brief Frees the RzType
 *
 * Doesn't free the underlying RzBaseType, only the RzType wrapper.
 * Same goes for the RzCallable. Both are stored in the corresponding
 * hashtables and should not be touched until deleted explicitly.
 *
 * \param type RzType type
 */
RZ_API void rz_type_free(RZ_NULLABLE RzType *type) {
	if (!type) {
		return;
	}
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER:
		free(type->identifier.name);
		break;
	case RZ_TYPE_KIND_POINTER:
		rz_type_free(type->pointer.type);
		break;
	case RZ_TYPE_KIND_ARRAY:
		rz_type_free(type->array.type);
		break;
	case RZ_TYPE_KIND_CALLABLE:
		break;
	}
	free(type);
}

/**
 * \brief Edits the existing base type given the new C code
 *
 * Searches the base type in the types database given the \p name.
 * If it exists - parses the \p typestr as the new C type. If there is
 * any error during the parsing it restores the original type in the
 * database.
 *
 * \param typedb Type Database instance
 * \param name Name of the base type
 * \param typestr C string of the new definition of the type
 */
RZ_API bool rz_type_db_edit_base_type(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *typestr) {
	rz_return_val_if_fail(name && typestr, false);
	RzBaseType *t = rz_type_db_get_compound_type(typedb, name);
	if (!t) {
		return false;
	}
	// Remove the original type first
	// but do not free them
	void *freefn = (void *)typedb->types->opt.freefn;
	typedb->types->opt.freefn = NULL;
	ht_pp_delete(typedb->types, t->name);
	typedb->types->opt.freefn = freefn;
	char *error_msg = NULL;
	int result = rz_type_parse_string_stateless(typedb->parser, typestr, &error_msg);
	if (result) {
		if (error_msg) {
			RZ_LOG_ERROR("%s\n", error_msg);
		}
		free(error_msg);
		// There is an error during the parsing thus we restore the old type
		// We insert the type back
		ht_pp_insert(typedb->types, t->name, t);
		return false;
	}
	// Free now unnecessary old base type
	rz_type_base_type_free(t);
	return true;
}
