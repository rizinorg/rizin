// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>

/**
 * \brief Creates a new instance of RzTypePath
 *
 * \param type RzType pointer
 * \param path String representation of type path
 */
RZ_API RZ_OWN RzTypePath *rz_type_path_new(RZ_BORROW RZ_NONNULL RzType *type, RZ_OWN RZ_NONNULL char *path) {
	rz_return_val_if_fail(type && path, NULL);
	RzTypePath *tpath = RZ_NEW0(RzTypePath);
	if (!tpath) {
		return NULL;
	}
	tpath->typ = type;
	tpath->path = path;
	return tpath;
}

/**
 * \brief Frees the RzTypePath
 *
 * Doesn't free the underlying RzBaseType, only the path.
 *
 * \param type RzTypePath
 */
RZ_API void rz_type_path_free(RZ_NULLABLE RzTypePath *tpath) {
	if (!tpath) {
		return;
	}
	free(tpath->path);
	free(tpath);
}

static st64 path_walker(const RzTypeDB *typedb, const char *path) {
	rz_return_val_if_fail(typedb && path, -1);
	const char *member;
	size_t membsize;
	ut64 index;
	st64 offset = 0;
	RzType *parent = NULL;
	const char *path_begin = path;
	while (*path) {
		switch (*path++) {
		case '\0':
			break;
		case '[':
			member = path;
			index = (ut64)strtoull(member, (char **)&path, 10);
			if (member == path || *path != ']') {
				eprintf("Type path: expected ] (\"%s\")", path - 1);
				return -1;
			}
			++path;
			if (parent->kind != RZ_TYPE_KIND_ARRAY) {
				return -1;
			}
			offset += rz_type_db_get_bitsize(typedb, parent) * index;
			break;
		case '.':
			member = path;
			for (membsize = 0; member[membsize]; ++membsize) {
				if (strchr(".[", member[membsize])) {
					break;
				}
			}
			if (membsize == 0) {
				eprintf("Type path: expected member (\"%s\")", path - 1);
				return -1;
			}
			if (!parent) {
				if (member <= path) {
					return -1;
				}
				size_t typenamesize = member - path_begin;
				char *typename = malloc(typenamesize + 1);
				if (!typename) {
					return -1;
				}
				strncpy(typename, path_begin, typenamesize);
				typename[typenamesize] = '\0';
				parent = rz_type_identifier_of_base_type_str(typedb, typename);
				free(typename);
				if (!parent) {
					return -1;
				}
			} else {
				if (parent->kind != RZ_TYPE_KIND_IDENTIFIER) {
					return -1;
				}
				if (parent->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_STRUCT || parent->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNION) {
					return -1;
				}
			}
			offset += rz_type_db_struct_member_offset(typedb, parent->identifier.name, member);
			path = member + membsize;
			break;
		default:
			eprintf("Type path: unexpected char (\"%s\")", path - 1);
			return -1;
		}
	}
	return offset;
}

/**
 * \brief Returns the offset of the member given path
 *
 * Resolves the path in the form of "a.b[20].c" where "b" is
 * a member of "a" and "c" is a member of "b" array and located
 * inside the 20-th element, and calculates the offset.
 * Opposite function of "rz_type_path_by_offset"
 *
 * \param type RzTypePath
 */
RZ_API st64 rz_type_offset_by_path(const RzTypeDB *typedb, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(typedb && path, -1);
	return path_walker(typedb, path);
}

// TODO: Handle arrays
static bool structured_member_walker(const RzTypeDB *typedb, RzList /* RzTypePath */ *list, RzType *parent, RzType *type, char *path, ut64 offset) {
	rz_return_val_if_fail(list && type, false);
	if (type->kind != RZ_TYPE_KIND_IDENTIFIER) {
		return false;
	}
	bool result = true;
	if (type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_STRUCT) {
		// Get the base type
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			return false;
		}
		RzTypeStructMember *memb;
		ut64 memb_offset = 0;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			if (memb_offset == offset) {
				RzTypePath *tpath = rz_type_path_new(parent, rz_str_newf("%s.%s.%s", path, btype->name, memb->name));
				if (tpath) {
					rz_list_append(list, tpath);
				}
			}
			char *newpath = rz_str_newf("%s.%s", path, memb->name);
			result &= structured_member_walker(typedb, list, parent, memb->type, newpath, memb_offset + offset);
			memb_offset += rz_type_db_get_bitsize(typedb, memb->type) / 8;
			free(newpath);
		}
	} else if (type->identifier.kind == RZ_TYPE_IDENTIFIER_KIND_UNION) {
		// Get the base type
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			return false;
		}
		RzTypeUnionMember *memb;
		rz_vector_foreach(&btype->union_data.members, memb) {
			char *newpath = rz_str_newf("%s.%s", path, memb->name);
			result &= structured_member_walker(typedb, list, parent, memb->type, path, offset);
			free(newpath);
		}
	}
	return result;
}

/**
 * \brief Returns the list of all type paths matching the offset
 *
 * \param typedb Types Database instance
 * \param btype The base type
 * \param offset The offset of the path to match against
 */
RZ_API RZ_OWN RzList /* RzTypePath */ *rz_type_path_by_offset(const RzTypeDB *typedb, RzBaseType *btype, ut64 offset) {
	bool nofail = true;
	RzList *list = rz_list_newf((RzListFree)rz_type_path_free);
	if (btype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		RzType *t = rz_type_identifier_of_base_type(typedb, btype, false);
		RzTypeStructMember *memb;
		ut64 memb_offset = 0;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			if (memb_offset == offset) {
				RzType *t = rz_type_identifier_of_base_type(typedb, btype, false);
				RzTypePath *tpath = rz_type_path_new(t, rz_str_newf("%s.%s", btype->name, memb->name));
				if (tpath) {
					rz_list_append(list, tpath);
				}
			}
			// We go into the nested structures/unions if they are members of the structure
			char *path = rz_str_newf("%s.%s", btype->name, memb->name);
			nofail &= structured_member_walker(typedb, list, t, memb->type, path, memb_offset + offset);
			memb_offset += rz_type_db_get_bitsize(typedb, memb->type) / 8;
			free(path);
		}
	} else if (btype->kind == RZ_BASE_TYPE_KIND_UNION) {
		// This function makes sense only for structures since union
		// members have exact same offset
		// But if the union has compound members, e.g. structures, their
		// internal offsets can be different
		RzType *t = rz_type_identifier_of_base_type(typedb, btype, false);
		RzTypeUnionMember *memb;
		rz_vector_foreach(&btype->union_data.members, memb) {
			char *path = rz_str_newf("%s.%s", btype->name, memb->name);
			nofail &= structured_member_walker(typedb, list, t, memb->type, path, offset);
			free(path);
		}
	} else {
		rz_warn_if_reached();
	}
	return list;
}

/**
 * \brief Returns the list of all structured types that have members matching the offset
 *
 * \param typedb Types Database instance
 * \param offset The offset of the member to match against
 */
RZ_API RZ_OWN RzList /* RzTypePath */ *rz_type_db_get_by_offset(const RzTypeDB *typedb, ut64 offset) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_type_db_get_base_types(typedb);
	RzList *result = rz_list_newf((RzListFree)rz_type_path_free);
	RzListIter *iter;
	RzBaseType *t;
	rz_list_foreach (types, iter, t) {
		if (t->kind == RZ_BASE_TYPE_KIND_STRUCT || t->kind == RZ_BASE_TYPE_KIND_UNION) {
			RzList *list = rz_type_path_by_offset(typedb, t, offset);
			if (list) {
				rz_list_join(result, list);
			}
		}
	}
	rz_list_free(types);
	return result;
}

/**
 * \brief Returns the offset of the structure member if there is a match
 *
 * \param typedb Types Database instance
 * \param name The structure type name
 * \param name The structure member name
 */
RZ_API ut64 rz_type_db_struct_member_offset(const RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *member) {
	rz_return_val_if_fail(typedb && name && member, 0);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype || btype->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		return 0;
	}
	RzTypeStructMember *memb;
	ut64 result = 0;
	rz_vector_foreach(&btype->struct_data.members, memb) {
		if (!strcmp(memb->name, member)) {
			return result;
			break;
		}
		result += rz_type_db_get_bitsize(typedb, memb->type);
	}
	return result;
}
