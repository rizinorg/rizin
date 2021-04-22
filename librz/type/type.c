// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2019-2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

#include "type_internal.h"

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
	typedb->sdb_types = sdb_new0();
	typedb->formats = sdb_new0();
	typedb->parser = rz_ast_parser_new();
	rz_io_bind_init(typedb->iob);
	return typedb;
}

RZ_API void rz_type_db_free(RzTypeDB *typedb) {
	rz_ast_parser_free(typedb->parser);
	sdb_free(typedb->sdb_types);
	sdb_free(typedb->formats);
	free(typedb->target);
	free(typedb);
}

// copypasta from core/cbin.c
static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
	sdb_merge(s, db);
	sdb_close(db);
	sdb_free(db);
}

RZ_API void rz_type_db_load_sdb(RzTypeDB *typedb, const char *path) {
	if (rz_file_exists(path)) {
		sdb_concat_by_path(typedb->sdb_types, path);
	}
}

RZ_API void rz_type_db_purge(RzTypeDB *typedb) {
	sdb_reset(typedb->sdb_types);
}

RZ_API void rz_type_db_set_bits(RzTypeDB *typedb, int bits) {
	typedb->target->bits = bits;
}

RZ_API void rz_type_db_set_os(RzTypeDB *typedb, const char *os) {
	typedb->target->os = os;
}

RZ_API void rz_type_db_set_cpu(RzTypeDB *typedb, const char *cpu) {
	typedb->target->cpu = cpu;
}

RZ_API void rz_type_db_set_endian(RzTypeDB *typedb, bool big_endian) {
	typedb->target->big_endian = big_endian;
}

RZ_API ut8 rz_type_db_pointer_size(RzTypeDB *typedb) {
	// TODO: Handle more special cases where the pointer
	// size is different from the target bitness
	return typedb->target->bits;
}

RZ_API char *rz_type_db_kuery(RzTypeDB *typedb, const char *query) {
	char *output = NULL;
	if (query) {
		output = sdb_querys(typedb->sdb_types, NULL, -1, query);
	} else {
		output = sdb_querys(typedb->sdb_types, NULL, -1, "*");
	}
	return output;
}

static char *is_ctype(char *type) {
	char *name = NULL;
	if ((name = strstr(type, "=type")) ||
		(name = strstr(type, "=struct")) ||
		(name = strstr(type, "=union")) ||
		(name = strstr(type, "=enum")) ||
		(name = strstr(type, "=typedef")) ||
		(name = strstr(type, "=func"))) {
		return name;
	}
	return NULL;
}

RZ_API bool rz_type_db_del(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	Sdb *TDB = typedb->sdb_types;
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype) {
		// TODO: Extract this to the separate type RzCallable:
		// see https://github.com/rizinorg/rizin/issues/373
		const char *kind = sdb_const_get(TDB, name, 0);
		if (!strcmp(kind, "func")) {
			int i, n = sdb_num_get(TDB, sdb_fmt("func.%s.args", name), 0);
			for (i = 0; i < n; i++) {
				sdb_unset(TDB, sdb_fmt("func.%s.arg.%d", name, i), 0);
			}
			sdb_unset(TDB, sdb_fmt("func.%s.ret", name), 0);
			sdb_unset(TDB, sdb_fmt("func.%s.cc", name), 0);
			sdb_unset(TDB, sdb_fmt("func.%s.noreturn", name), 0);
			sdb_unset(TDB, sdb_fmt("func.%s.args", name), 0);
			sdb_unset(TDB, name, 0);
			return true;
		} else {
			eprintf("Unrecognized type kind \"%s\"\n", kind);
		}
		return false;
	}
	rz_type_db_delete_base_type(typedb, btype);
	rz_type_base_type_free(btype);
	return true;
}

RZ_API void rz_type_db_remove_parsed_type(RzTypeDB *typedb, const char *name) {
	rz_return_if_fail(typedb && name);
	Sdb *TDB = typedb->sdb_types;
	SdbKv *kv;
	SdbListIter *iter;
	const char *type = sdb_const_get(TDB, name, 0);
	if (!type) {
		return;
	}
	int tmp_len = strlen(name) + strlen(type);
	char *tmp = malloc(tmp_len + 1);
	rz_type_db_del(typedb, name);
	if (tmp) {
		snprintf(tmp, tmp_len + 1, "%s.%s.", type, name);
		SdbList *l = sdb_foreach_list(TDB, true);
		ls_foreach (l, iter, kv) {
			if (!strncmp(sdbkv_key(kv), tmp, tmp_len)) {
				rz_type_db_del(typedb, sdbkv_key(kv));
			}
		}
		ls_free(l);
		free(tmp);
	}
}

RZ_API void rz_type_db_save_parsed_type(RzTypeDB *typedb, const char *parsed) {
	rz_return_if_fail(typedb && parsed);

	// First, if any parsed types exist, let's remove them.
	char *type = strdup(parsed);
	if (type) {
		char *cur = type;
		while (1) {
			cur = is_ctype(cur);
			if (!cur) {
				break;
			}
			char *name = cur++;
			*name = 0;
			while (name > type && *(name - 1) != '\n') {
				name--;
			}
			rz_type_db_remove_parsed_type(typedb, name);
		}
		free(type);
	}

	// Now add the type to sdb.
	sdb_query_lines(typedb->sdb_types, parsed);
}

RZ_API void rz_type_db_init(RzTypeDB *typedb, const char *dir_prefix, const char *arch, int bits, const char *os) {
	rz_return_if_fail(typedb);
	Sdb *TDB = typedb->sdb_types;

	// make sure they are empty this is initializing
	sdb_reset(TDB);

	const char *dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types.sdb"), dir_prefix);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, arch);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, os);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%d.sdb"),
		dir_prefix, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%d.sdb"),
		dir_prefix, os, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%d.sdb"),
		dir_prefix, arch, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%s.sdb"),
		dir_prefix, arch, os);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
	dbpath = sdb_fmt(RZ_JOIN_3_PATHS("%s", RZ_SDB_FCNSIGN, "types-%s-%s-%d.sdb"),
		dir_prefix, arch, os, bits);
	if (rz_file_exists(dbpath)) {
		sdb_concat_by_path(TDB, dbpath);
	}
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
	RzList *result = rz_list_newf(free);
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
	RzList *result = rz_list_newf(free);
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
	RzList *result = rz_list_newf(free);
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
	RzList *result = rz_list_newf(free);
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
	RzList *result = rz_list_newf(free);
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

/*
static bool structured_member_walker(RzList (RzBaseType) *list, RzBaseType *btype, ut64 offset) {
	rz_return_val_if_fail(list && btype, false);
	bool result = true;
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		RzTypeStructMember *memb;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			if (memb->offset == offset) {
				rz_list_append(list, memb);
			}
			// FIXME: Support nested
			// result &= structured_member_walker(list, NULL, offset);
		}
	} else if (btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		RzTypeUnionMember *memb;
		rz_vector_foreach(&btype->union_data.members, memb) {
			if (memb->offset == offset) {
				rz_list_append(list, memb);
			}
			// FIXME: Support nested
			// result &= structured_member_walker(list, NULL, offset);
		}
	}
	return result;
}
*/

RZ_API RZ_OWN RzList *rz_type_structured_member_by_offset(RzBaseType *btype, ut64 offset) {
	// TODO: Return the whole RzBaseType instead of the string
	//RzList *list = rz_list_newf((RzListFree)rz_type_base_type_free);
	RzList *list = rz_list_newf(free);
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		RzTypeStructMember *memb;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			if (memb->offset == offset) {
				rz_list_append(list, rz_str_newf("%s.%s", btype->name, memb->name));
			}
			// FIXME: Support nested
			// nofail &= structured_member_walker(list, NULL, offset);
		}
	} else if (btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		RzTypeUnionMember *memb;
		rz_vector_foreach(&btype->union_data.members, memb) {
			if (memb->offset == offset) {
				rz_list_append(list, rz_str_newf("%s.%s", btype->name, memb->name));
			}
			// FIXME: Support nested
			// nofail &= structured_member_walker(list, NULL, offset);
		}
	}
	return list;
}

/**
 * \brief Returns the list of all structured types that have members matching the offset
 *
 * \param typedb Types Database instance
 * \param offset The offset of the member to match against
 */
RZ_API RZ_OWN RzList *rz_type_db_get_by_offset(RzTypeDB *typedb, ut64 offset) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_type_db_get_base_types(typedb);
	// TODO: Return the whole RzBaseType instead of the string
	//RzList *list = rz_list_newf((RzListFree)rz_type_base_type_free);
	RzList *result = rz_list_newf(free);
	RzListIter *iter;
	RzBaseType *t;
	rz_list_foreach (types, iter, t) {
		if (t->kind == RZ_BASE_TYPE_KIND_STRUCT || t->kind == RZ_BASE_TYPE_KIND_UNION) {
			RzList *list = rz_type_structured_member_by_offset(t, offset);
			if (list) {
				rz_list_join(result, list);
			}
		}
	}
	rz_list_free(types);
	return result;
}

/**
 * \brief Returns the enum base type matching the specified name
 *
 * \param typedb Types Database instance
 * \param name The name of the enum to match against
 */
RZ_API RzBaseType *rz_type_db_get_enum(RzTypeDB *typedb, RZ_NONNULL const char *name) {
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
RZ_API char *rz_type_db_enum_member_by_val(RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
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
RZ_API int rz_type_db_enum_member_by_name(RzTypeDB *typedb, RZ_NONNULL const char *name, const char *member) {
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
 * \brief Returns all enums and cases name matching the cpecified value
 *
 * \param typedb Types Database instance
 * \param val The value to search for
 */
RZ_API RZ_OWN RzList *rz_type_db_find_enums_by_val(RzTypeDB *typedb, ut64 val) {
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
RZ_OWN RZ_API char *rz_type_db_enum_get_bitfield(RzTypeDB *typedb, RZ_NONNULL const char *name, ut64 val) {
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
RZ_API RzBaseType *rz_type_db_get_union(RzTypeDB *typedb, RZ_NONNULL const char *name) {
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
RZ_API RzBaseType *rz_type_db_get_struct(RzTypeDB *typedb, RZ_NONNULL const char *name) {
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
 * \brief Search for the structure member that has matching offset
 *
 * \param typedb Types Database instance
 * \param name The structure type name
 * \param offset The offset to search for
 */
RZ_OWN RZ_API char *rz_type_db_get_struct_member(RzTypeDB *typedb, RZ_NONNULL const char *name, int offset) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype || btype->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		return NULL;
	}
	RzTypeStructMember *memb;
	char *result = NULL;
	rz_vector_foreach(&btype->struct_data.members, memb) {
		if (memb->offset == offset) {
			result = rz_str_newf("%s.%s", btype->name, memb->name);
			break;
		}
		// FIXME: Support nested
		// nofail &= structured_member_walker(list, NULL, offset);
	}
	return result;
}

/**
 * \brief Returns the typedef base type matching the specified name
 *
 * \param typedb Types Database instance
 * \param name The name of the typedef to match against
 */
RZ_API RzBaseType *rz_type_db_get_typedef(RzTypeDB *typedb, RZ_NONNULL const char *name) {
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
RZ_API ut64 rz_type_db_atomic_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_ATOMIC, 0);
	return btype->size;
}

/**
 * \brief Returns the enum type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_enum_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
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
RZ_API ut64 rz_type_db_struct_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_STRUCT, 0);
	RzTypeStructMember *memb;
	ut64 size = 0;
	rz_vector_foreach(&btype->struct_data.members, memb) {
		size += memb->size;
		// FIXME: Support nested
	}
	return size;
}

/**
 * \brief Returns the union type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_union_bitsize(RzTypeDB *typedb, RZ_NONNULL RzBaseType *btype) {
	rz_return_val_if_fail(typedb && btype && btype->kind == RZ_BASE_TYPE_KIND_UNION, 0);
	RzTypeUnionMember *memb;
	ut64 size = 0;
	// Union has the size of the maximum size of its elements
	rz_vector_foreach(&btype->union_data.members, memb) {
		size = RZ_MAX(memb->size, size);
		// FIXME: Support nested
	}
	return size;
}

/**
 * \brief Returns the type size in bits (target dependent)
 *
 * \param typedb Types Database instance
 * \param btype The base type
 */
RZ_API ut64 rz_type_db_get_bitsize(RzTypeDB *typedb, RZ_NONNULL RzType *type) {
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
	if (type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNSPECIFIED) {
		eprintf("Wrong identifier type - cannot determine its size\n");
		return 0;
	}
	const char *tname = type->identifier.name;
	RzBaseType *btype = rz_type_db_get_base_type(typedb, tname);
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
	}
	// Should not happen
	rz_warn_if_reached();
	return 0;
}
