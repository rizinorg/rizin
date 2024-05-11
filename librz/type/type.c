// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2019-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

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
	typedb->types = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_type_base_type_free);
	if (!typedb->types) {
		goto rz_type_db_new_fail;
	}
	typedb->formats = ht_ss_new(HT_STR_DUP, HT_STR_OWN);
	if (!typedb->formats) {
		goto rz_type_db_new_fail;
	}
	typedb->callables = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_type_callable_free);
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
	ht_sp_free(typedb->types);
	ht_ss_free(typedb->formats);
	ht_sp_free(typedb->callables);
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
	ht_sp_free(typedb->callables);
	ht_sp_free(typedb->types);
	ht_ss_free(typedb->formats);
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
	ht_sp_free(typedb->callables);
	typedb->callables = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_type_callable_free);
	ht_sp_free(typedb->types);
	typedb->types = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_type_base_type_free);
	rz_type_parser_free(typedb->parser);
	typedb->parser = rz_type_parser_init(typedb->types, typedb->callables);
}

/**
 * \brief Purges formats in the instance of the RzTypeDB
 */
RZ_API void rz_type_db_format_purge(RzTypeDB *typedb) {
	ht_ss_free(typedb->formats);
	typedb->formats = ht_ss_new(HT_STR_DUP, HT_STR_OWN);
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
 * \brief Set the RzType target adress size
 *
 * Important for calculating some types size, especially
 * pointers's size.
 *
 * \param typedb RzTypeDB instance
 * \param bits size of an address in bits. If <= 0, then
 *        the value from rz_type_db_set_bits() is used.
 */
RZ_API void rz_type_db_set_address_bits(RzTypeDB *typedb, int addr_bits) {
	rz_return_if_fail(typedb);
	typedb->target->addr_bits = addr_bits;
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
	return typedb->target->addr_bits > 0 ? typedb->target->addr_bits : typedb->target->bits;
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
 * \param types_dir Directory where all type libraries are installed
 * \param arch Architecture of the analysis session
 * \param bits Bitness of the analysis session
 * \param os Operating system of the analysis session
 */
RZ_API void rz_type_db_init(RzTypeDB *typedb, const char *types_dir, const char *arch, int bits, const char *os) {
	rz_return_if_fail(typedb && typedb->types && typedb->formats);

	// A workaround to fix loading incorrectly detected MacOS binaries
	if (RZ_STR_ISNOTEMPTY(os) && !strcmp(os, "darwin")) {
		os = "macos";
	}

	// At first we load the basic types
	// Atomic types
	char *dbpath = rz_file_path_join(types_dir, "types-atomic.sdb");
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}
	free(dbpath);
	// C runtime types
	dbpath = rz_file_path_join(types_dir, "types-libc.sdb");
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}
	free(dbpath);

	// We do not load further if bits are not specified
	if (bits <= 0) {
		return;
	}

	// Bits-specific types that are independent from architecture or OS
	char tmp[100];
	dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%d.sdb", bits));
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}
	free(dbpath);

	// We do not load further if architecture is not specified
	if (!arch) {
		return;
	}

	// Architecture-specific types
	dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%s.sdb", arch));
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}
	free(dbpath);

	// Architecture- and bits-specific types
	dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%s-%d.sdb", arch, bits));
	if (rz_type_db_load_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
	}
	free(dbpath);

	if (os) {
		// OS-specific types
		dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%s.sdb", os));
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		free(dbpath);
		dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%s-%d.sdb", os, bits));
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		free(dbpath);
		dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%s-%s.sdb", arch, os));
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		free(dbpath);
		dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "types-%s-%s-%d.sdb", arch, os, bits));
		if (rz_type_db_load_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("types: loaded \"%s\"\n", dbpath);
		}
		free(dbpath);
	}

	// Then, after all basic types are initialized, we load function types
	// that use loaded previously base types for return and arguments
	dbpath = rz_file_path_join(types_dir, "functions-libc.sdb");
	if (rz_type_db_load_callables_sdb(typedb, dbpath)) {
		RZ_LOG_DEBUG("callable types: loaded \"%s\"\n", dbpath);
	}
	free(dbpath);
	// OS-specific function types
	if (os) {
		dbpath = rz_file_path_join(types_dir, rz_strf(tmp, "functions-%s.sdb", os));
		if (rz_type_db_load_callables_sdb(typedb, dbpath)) {
			RZ_LOG_DEBUG("callable types: loaded \"%s\"\n", dbpath);
		}
		free(dbpath);
	}
}

/**
 * \brief Re-initializes the types database for current target
 *
 * Similarly to rz_type_db_init loads pre-shipped type libraries
 * for base types and function types.
 *
 * \param typedb Types Database instance
 * \param types_dir Directory where all type libraries are installed
 */
RZ_API void rz_type_db_reload(RzTypeDB *typedb, const char *types_dir) {
	rz_type_db_init(typedb, types_dir, typedb->target->cpu, typedb->target->bits, typedb->target->os);
}

// Listing all available types by category

/**
 * \brief Returns the list of all enum names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_enum_names(RzTypeDB *typedb) {
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
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_union_names(RzTypeDB *typedb) {
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
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_struct_names(RzTypeDB *typedb) {
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
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_typedef_names(RzTypeDB *typedb) {
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
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_all(RzTypeDB *typedb) {
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
RZ_API RZ_BORROW const char *rz_type_db_enum_member_by_val(const RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		return NULL;
	}
	if (btype->kind != RZ_BASE_TYPE_KIND_ENUM) {
		return NULL;
	}
	RzTypeEnumCase *cas;
	rz_vector_foreach (&btype->enum_data.cases, cas) {
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
	rz_vector_foreach (&btype->enum_data.cases, cas) {
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
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_db_find_enums_by_val(const RzTypeDB *typedb, ut64 val) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *enums = rz_type_db_get_base_types_of_kind(typedb, RZ_BASE_TYPE_KIND_ENUM);
	RzList *result = rz_list_newf(free);
	RzListIter *iter;
	RzBaseType *e;
	rz_list_foreach (enums, iter, e) {
		RzTypeEnumCase *cas;
		rz_vector_foreach (&e->enum_data.cases, cas) {
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
RZ_API RZ_OWN char *rz_type_db_enum_get_bitfield(const RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
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
		rz_vector_foreach (&btype->enum_data.cases, cas) {
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

static ut64 type_get_bitsize_recurse(const RzTypeDB *typedb, RZ_NONNULL RzType *type, RZ_NULLABLE RzPVector /*<RzBaseType *>*/ *visited_btypes);

static ut64 atomic_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_ATOMIC, 0);
	return btype->size;
}

static ut64 enum_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_ENUM, 0);
	// FIXME: Need a proper way to determine size of enum
	return 32;
}

static ut64 struct_union_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, RZ_NULLABLE RzPVector /*<RzBaseType *>*/ *visited_btypes) {
	rz_return_val_if_fail(typedb && btype && (btype->kind == RZ_BASE_TYPE_KIND_STRUCT || btype->kind == RZ_BASE_TYPE_KIND_UNION), 0);
	RzPVector visited_btypes_owned; // for detecting self-referential typedefs (maybe in multiple steps)
	if (!visited_btypes) {
		// Lazy allocation of the visited_btypes stack, only at this point we will actually need it
		rz_pvector_init(&visited_btypes_owned, NULL);
		visited_btypes = &visited_btypes_owned;
	} else {
		if (rz_pvector_contains(visited_btypes, btype)) {
			// loop detected
			return 0;
		}
	}
	rz_pvector_push(visited_btypes, btype);
	ut64 size = 0;
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		RzTypeStructMember *memb;
		rz_vector_foreach (&btype->struct_data.members, memb) {
			size += type_get_bitsize_recurse(typedb, memb->type, visited_btypes);
		}
	} else {
		RzTypeUnionMember *memb;
		// Union has the size of the maximum size of its elements
		rz_vector_foreach (&btype->union_data.members, memb) {
			size = RZ_MAX(type_get_bitsize_recurse(typedb, memb->type, visited_btypes), size);
		}
	}
	if (visited_btypes == &visited_btypes_owned) {
		rz_pvector_fini(&visited_btypes_owned);
	} else {
		rz_pvector_pop(visited_btypes);
	}
	return size;
}

static ut64 typedef_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, RZ_NULLABLE RzPVector /*<RzBaseType *>*/ *visited_btypes) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF, 0);
	rz_return_val_if_fail(btype->type, 0);
	RzType *unwrapped = rz_type_db_base_type_unwrap_typedef(typedb, btype);
	if (!unwrapped) {
		return 0;
	}
	return type_get_bitsize_recurse(typedb, unwrapped, visited_btypes);
}

/**
 * \param visited_btypes Stack of struct/union types visited higher up in the recursion, for loop detection
 * \return the base type size in bits (target dependent)
 */
static ut64 base_type_get_bitsize_recurse(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype, RZ_NULLABLE RzPVector /*<RzBaseType *>*/ *visited_btypes) {
	rz_return_val_if_fail(typedb && btype, 0);
	if (btype->kind == RZ_BASE_TYPE_KIND_ENUM) {
		return enum_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT || btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		return struct_union_bitsize(typedb, btype, visited_btypes);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_ATOMIC) {
		return atomic_bitsize(typedb, btype);
	} else if (btype->kind == RZ_BASE_TYPE_KIND_TYPEDEF) {
		return typedef_bitsize(typedb, btype, visited_btypes);
	}
	// Should not happen
	rz_warn_if_reached();
	return 0;
}

/**
 * \brief Returns the base type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_base_get_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	return base_type_get_bitsize_recurse(typedb, btype, NULL);
}

/**
 * \param visited_btypes Stack of struct/union types visited higher up in the recursion, for loop detection
 * \return the type size in bits (target dependent)
 */
static ut64 type_get_bitsize_recurse(const RzTypeDB *typedb, RZ_NONNULL RzType *type, RZ_NULLABLE RzPVector /*<RzBaseType *>*/ *visited_btypes) {
	rz_return_val_if_fail(typedb && type, 0);
	// Detect if the pointer and return the corresponding size
	if (type->kind == RZ_TYPE_KIND_POINTER || type->kind == RZ_TYPE_KIND_CALLABLE) {
		// Note, that function types (RzCallable) are in fact pointers too
		return rz_type_db_pointer_size(typedb);
		// Detect if the pointer is array, then return the bitsize of the base type
		// multiplied to the array size
	} else if (type->kind == RZ_TYPE_KIND_ARRAY) {
		return type->array.count * type_get_bitsize_recurse(typedb, type->array.type, visited_btypes);
	}
	// The rest of the logic is for the normal, identifier types
	RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
	if (!btype) {
		return 0;
	}
	return base_type_get_bitsize_recurse(typedb, btype, visited_btypes);
}

/**
 * \brief Returns the type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param type The type
 */
RZ_API ut64 rz_type_db_get_bitsize(const RzTypeDB *typedb, RZ_NONNULL RzType *type) {
	return type_get_bitsize_recurse(typedb, type, NULL);
}

/**
 * \brief Returns the type C representation
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);

	return rz_type_as_pretty_string(typedb, type, NULL, RZ_TYPE_PRINT_ZERO_VLA | RZ_TYPE_PRINT_NO_END_SEMICOLON | RZ_TYPE_PRINT_ANONYMOUS, 0);
}

/**
 * \brief Returns the type C declaration representation
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_declaration_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);

	return rz_type_as_pretty_string(typedb, type, NULL, RZ_TYPE_PRINT_ZERO_VLA | RZ_TYPE_PRINT_NO_END_SEMICOLON, 1); // one level unfold
}

/**
 * \brief Returns the type C representation with identifier
 *
 * \param typedb Types Database instance
 * \param type RzType type
 */
RZ_API RZ_OWN char *rz_type_identifier_declaration_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NONNULL const char *identifier) {
	rz_return_val_if_fail(typedb && type, NULL);

	return rz_type_as_pretty_string(typedb, type, identifier, RZ_TYPE_PRINT_ZERO_VLA | RZ_TYPE_PRINT_NO_END_SEMICOLON | RZ_TYPE_PRINT_UNFOLD_ANON_ONLY_STRICT, 1); // one level unfold (for anonymous only)
}

struct PrettyHelperBufs {
	RzStrBuf *typename;
	RzStrBuf *pointerbuf;
	RzStrBuf *arraybuf;
};

static bool type_decl_as_pretty_string(const RzTypeDB *typedb, const RzType *type, HtSP *used_types, struct PrettyHelperBufs phbuf, bool *self_ref, char **self_ref_typename, bool zero_vla, bool print_anon, bool show_typedefs, bool allow_non_exist) {
	rz_return_val_if_fail(typedb && type && used_types && self_ref, false);

	bool is_anon = false;
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		if (!type->identifier.name) {
			return false;
		}
		is_anon = !strncmp(type->identifier.name, "anonymous ", strlen("anonymous "));
		*self_ref = false;
		ht_sp_find(used_types, type->identifier.name, self_ref);
		*self_ref = *self_ref && !is_anon; // no self_ref for anon types
		*self_ref_typename = *self_ref ? strdup(type->identifier.name) : NULL;

		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype && !allow_non_exist) {
			rz_strbuf_append(phbuf.typename, "unknown_t");
		} else if (!btype || btype->kind == RZ_BASE_TYPE_KIND_ATOMIC) {
			rz_strbuf_appendf(phbuf.typename, "%s%s", type->identifier.is_const ? "const " : "", type->identifier.name);
		} else {
			switch (btype->kind) {
			case RZ_BASE_TYPE_KIND_STRUCT:
				rz_strbuf_appendf(phbuf.typename, "%sstruct", type->identifier.is_const ? "const " : "");
				if (!is_anon || print_anon) {
					rz_strbuf_appendf(phbuf.typename, " %s", btype->name);
				}
				break;
			case RZ_BASE_TYPE_KIND_UNION:
				rz_strbuf_appendf(phbuf.typename, "%sunion", type->identifier.is_const ? "const " : "");
				if (!is_anon || print_anon) {
					rz_strbuf_appendf(phbuf.typename, " %s", btype->name);
				}
				break;
			case RZ_BASE_TYPE_KIND_ENUM:
				rz_strbuf_appendf(phbuf.typename, "%senum", type->identifier.is_const ? "const " : "");
				if (!is_anon || print_anon) {
					rz_strbuf_appendf(phbuf.typename, " %s", btype->name);
				}
				break;
			case RZ_BASE_TYPE_KIND_TYPEDEF: {
				if (show_typedefs) {
					char *typestr = rz_type_as_string(typedb, btype->type);
					if (!typestr) {
						RZ_LOG_ERROR("Failed to get type representation of typedef of base type: %s\n", btype->name);
						return false;
					}
					rz_strbuf_appendf(phbuf.typename, "typedef %s", typestr);
					free(typestr);
				} else {
					rz_strbuf_append(phbuf.typename, btype->name);
				}
				break;
			}
			default:
				rz_warn_if_reached();
				break;
			}
		}
		break;
	}
	case RZ_TYPE_KIND_POINTER:
		if (rz_type_is_callable_ptr_nested(type)) { // function pointers
			char *typestr = rz_type_callable_ptr_as_string(typedb, type);
			rz_strbuf_append(phbuf.typename, typestr);
			free(typestr);
		} else {
			type_decl_as_pretty_string(typedb, type->pointer.type, used_types, phbuf, self_ref, self_ref_typename,
				zero_vla, print_anon, show_typedefs, allow_non_exist);
			rz_strbuf_append(phbuf.pointerbuf, "*");
			rz_strbuf_appendf(phbuf.pointerbuf, "%s", type->pointer.is_const ? " const " : "");
		}
		break;
	case RZ_TYPE_KIND_ARRAY:
		if (type->array.count) {
			rz_strbuf_appendf(phbuf.arraybuf, "[%" PFMT64d "]", type->array.count);
		} else { // variable length arrays
			rz_strbuf_appendf(phbuf.arraybuf, "[%s]", zero_vla ? "0" : "");
		}
		type_decl_as_pretty_string(typedb, type->array.type, used_types, phbuf, self_ref, self_ref_typename,
			zero_vla, print_anon, show_typedefs, allow_non_exist);
		break;
	case RZ_TYPE_KIND_CALLABLE: {
		char *callstr = rz_type_callable_as_string(typedb, type->callable);
		rz_strbuf_append(phbuf.typename, callstr);
		free(callstr);
		break;
	}
	default:
		rz_warn_if_reached();
		break;
	}

	return true;
}

static char *type_as_pretty_string(const RzTypeDB *typedb, const RzType *type, const char *identifier, HtSP *used_types, unsigned int opts, int unfold_level, int indent_level) {
	rz_return_val_if_fail(typedb && type, NULL);

	if (unfold_level < 0) { // recursion base case
		return NULL;
	}
	bool multiline = opts & RZ_TYPE_PRINT_MULTILINE;
	bool anon_only = opts & RZ_TYPE_PRINT_UNFOLD_ANON_ONLY;
	bool anon_only_strict = opts & RZ_TYPE_PRINT_UNFOLD_ANON_ONLY_STRICT;
	bool zero_vla = opts & RZ_TYPE_PRINT_ZERO_VLA;
	bool print_anon = opts & RZ_TYPE_PRINT_ANONYMOUS;
	bool no_end_semicolon = opts & RZ_TYPE_PRINT_NO_END_SEMICOLON;
	no_end_semicolon = no_end_semicolon && (indent_level == 0); // indent_level needs to be zero for the last semicolon
	bool end_newline = opts & RZ_TYPE_PRINT_END_NEWLINE;
	end_newline = end_newline && (indent_level == 0); // only append newline for the outer type
	bool show_typedefs = opts & RZ_TYPE_PRINT_SHOW_TYPEDEF;
	bool allow_non_exist = opts & RZ_TYPE_PRINT_ALLOW_NON_EXISTENT_BASE_TYPE;
	if (indent_level == 0) { // for the root type, disregard anon_only
		anon_only = false;
	}
	anon_only = anon_only || anon_only_strict;
	bool unfold_all = !anon_only && unfold_level;
	bool unfold_anon = unfold_level;
	int indent = 0;
	char *separator = " ";
	if (multiline) {
		indent = indent_level; // indent only if multiline
		separator = "\n";
	}

	RzStrBuf *buf = rz_strbuf_new("");
	for (int i = 0; i < indent; i++) {
		rz_strbuf_append(buf, "\t");
	}
	RzStrBuf *typename = rz_strbuf_new("");
	RzStrBuf *pointer_buf = rz_strbuf_new("");
	RzStrBuf *array_buf = rz_strbuf_new("");
	struct PrettyHelperBufs phbuf = { typename, pointer_buf, array_buf };
	bool self_ref = false;
	char *self_ref_typename = NULL;
	bool decl = type_decl_as_pretty_string(typedb, type, used_types, phbuf, &self_ref, &self_ref_typename,
		zero_vla, print_anon, show_typedefs, allow_non_exist);
	if (!decl) {
		rz_strbuf_free(buf);
		rz_strbuf_free(typename);
		rz_strbuf_free(pointer_buf);
		rz_strbuf_free(array_buf);
		return NULL;
	}
	if (self_ref) { // in case of self referntial type
		unfold_level = 0; // no unfold
		unfold_anon = unfold_all = false;
	} else if (self_ref_typename) {
		ht_sp_insert(used_types, self_ref_typename, NULL, NULL); // add the type to the ht
	}
	RzBaseType *btype = NULL;
	bool is_anon = false;
	if (type->kind == RZ_TYPE_KIND_IDENTIFIER) {
		is_anon = !strncmp(type->identifier.name, "anonymous ", 10);
		btype = rz_type_db_get_base_type(typedb, type->identifier.name);
	} else if ((type->kind == RZ_TYPE_KIND_POINTER && rz_type_is_callable_ptr_nested(type)) || type->kind == RZ_TYPE_KIND_CALLABLE) {
		identifier = NULL; // no need to separately print identifier for function pointers or functions
	}
	char *typename_str = rz_strbuf_drain(phbuf.typename);
	char *pointer_str = rz_strbuf_drain(phbuf.pointerbuf);
	char *array_str = rz_strbuf_drain(phbuf.arraybuf);
	rz_strbuf_append(buf, typename_str);

	if (btype) {
		bool not_empty; // to check if no members are present
		switch (btype->kind) {
		case RZ_BASE_TYPE_KIND_STRUCT:
			if (unfold_all || (is_anon && unfold_anon)) {
				rz_strbuf_append(buf, " {");
				RzTypeStructMember *memb;
				not_empty = rz_vector_len(&btype->struct_data.members);
				if (not_empty) {
					rz_strbuf_appendf(buf, "%s", multiline ? "\n" : " ");
				}
				rz_vector_foreach (&btype->struct_data.members, memb) {
					char *unfold = type_as_pretty_string(typedb, memb->type, memb->name, used_types, opts, unfold_level - 1, indent_level + 1);
					rz_strbuf_appendf(buf, "%s%s", unfold, separator);
					free(unfold);
				}
				for (int i = 0; i < indent; i++) {
					rz_strbuf_append(buf, "\t");
				}
				rz_strbuf_append(buf, "}");
			}
			break;
		case RZ_BASE_TYPE_KIND_UNION:
			if (unfold_all || (is_anon && unfold_anon)) {
				rz_strbuf_append(buf, " {");
				RzTypeUnionMember *memb;
				not_empty = rz_vector_len(&btype->union_data.members);
				if (not_empty) {
					rz_strbuf_appendf(buf, "%s", multiline ? "\n" : " ");
				}
				rz_vector_foreach (&btype->union_data.members, memb) {
					char *unfold = type_as_pretty_string(typedb, memb->type, memb->name, used_types, opts, unfold_level - 1, indent_level + 1);
					rz_strbuf_appendf(buf, "%s%s", unfold, separator);
					free(unfold);
				}
				for (int i = 0; i < indent; i++) {
					rz_strbuf_append(buf, "\t");
				}
				rz_strbuf_append(buf, "}");
			}
			break;
		case RZ_BASE_TYPE_KIND_ENUM:
			if (unfold_all || (is_anon && unfold_anon)) {
				RzTypeEnumCase *cas;
				rz_strbuf_append(buf, " {");
				if (multiline) {
					indent++; // no recursive call, so manually need to update indent
				}
				not_empty = rz_vector_len(&btype->enum_data.cases);
				if (not_empty) {
					rz_strbuf_appendf(buf, "%s", multiline ? "\n" : " ");
				}
				rz_vector_foreach (&btype->enum_data.cases, cas) {
					for (int i = 0; i < indent; i++) {
						rz_strbuf_append(buf, "\t");
					}
					rz_strbuf_appendf(buf, "%s = 0x%" PFMT64x ",%s", cas->name, cas->val, separator);
				}
				if (not_empty) {
					rz_strbuf_slice(buf, 0, rz_strbuf_length(buf) - 2);
					rz_strbuf_append(buf, separator);
				}
				if (multiline) {
					indent--; // restore the original value
				}
				for (int i = 0; i < indent; i++) {
					rz_strbuf_append(buf, "\t");
				}
				rz_strbuf_append(buf, "}");
			}
			break;
		case RZ_BASE_TYPE_KIND_TYPEDEF:
			if (show_typedefs && !rz_type_is_callable_ptr_nested(btype->type)) { // if not a callable
				rz_strbuf_appendf(buf, " %s", btype->name);
			}
			break;
		case RZ_BASE_TYPE_KIND_ATOMIC:
			break;
		default:
			rz_warn_if_reached();
			break;
		}
	}

	if (rz_str_nlen(pointer_str, 1) != 0 || identifier || rz_str_nlen(array_str, 1) != 0) {
		rz_strbuf_append(buf, " "); // add space only if the type is pointer or an array or has an identifier
	}
	rz_strbuf_appendf(buf, "%s%s%s", pointer_str ? pointer_str : "", identifier ? identifier : "", array_str ? array_str : "");
	if (!no_end_semicolon) {
		rz_strbuf_append(buf, ";");
	}
	if (end_newline) {
		rz_strbuf_append(buf, "\n");
	}
	if (self_ref_typename) {
		ht_sp_delete(used_types, self_ref_typename);
		free(self_ref_typename);
	}
	free(typename_str);
	free(pointer_str);
	free(array_str);

	char *pretty_type = rz_strbuf_drain(buf);
	return pretty_type;
}

/**
 * \brief Return a string contining the type pretty printed according to the options provided
 *
 * \param typedb typedb for the current analysis
 * \param type type to be pretty printed
 * \param identifier name of the variable of the given type (RZ_NULLABLE)
 * \param opts options for pretty printing (see RzTypePrintOpts)
 * \param unfold_level level of unfolding to do in case of nested structures/unions (any negative number means maximum unfolding, i.e. INT32_MAX. 0 means no unfolding, just the typename and identifier, if any)
 * \return char* string in pretty printed form
 */
RZ_API RZ_OWN char *rz_type_as_pretty_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type, RZ_NULLABLE const char *identifier, unsigned int opts, int unfold_level) {
	rz_return_val_if_fail(typedb && type, NULL);

	if (unfold_level < 0) { // any negative number means maximum unfolding
		unfold_level = INT32_MAX;
	}
	HtSP *used_types = ht_sp_new(HT_STR_DUP, NULL, NULL); // use a hash table to keep track of unfolded types
	if (!used_types) {
		RZ_LOG_ERROR("Failed to create hashtable while pretty printing types\n")
		return NULL;
	}
	char *pretty_type = type_as_pretty_string(typedb, type, identifier, used_types, opts, unfold_level, 0);
	ht_sp_free(used_types);
	return pretty_type;
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
		newtype->identifier.name = rz_str_dup(type->identifier.name);
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
	HtSPKv *kv = ht_sp_find_kv(typedb->types, t->name, NULL);
	if (!kv || kv->value != t) {
		return false;
	}
	kv->value = NULL;
	ht_sp_delete(typedb->types, t->name);
	char *error_msg = NULL;
	int result = rz_type_parse_string_stateless(typedb->parser, typestr, &error_msg);
	if (result) {
		if (error_msg) {
			RZ_LOG_ERROR("%s\n", error_msg);
		}
		free(error_msg);
		// There is an error during the parsing thus we restore the old type
		// We insert the type back
		ht_sp_insert(typedb->types, t->name, t, NULL);
		return false;
	}
	// Free now unnecessary old base type
	rz_type_base_type_free(t);
	return true;
}
