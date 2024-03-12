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

static RzType *path_walker_parse_bracket(const RzTypeDB *typedb, RzType *parent, const char *path, size_t *i, st64 *offset) {
	size_t nd = 0;
	RzType *typd = parent;
	st64 cur_dim_off = 1; // product of all dimension sizes
	while (typd->kind == RZ_TYPE_KIND_ARRAY) {
		++nd;

		if (typd->array.count != 0 && cur_dim_off <= ST64_MAX / typd->array.count) { // check for overflow
			cur_dim_off *= typd->array.count;
		} else {
			RZ_LOG_ERROR("Too many error subscriptions\n");
			*offset = -1;
			return NULL;
		}

		typd = typd->array.type;
	}
	cur_dim_off *= rz_type_get_base_type(typedb, typd)->size; // elem size in bits

	typd = parent;
	for (size_t id = 0; id < nd; ++id) {
		if (path[*i] != '[') {
			RZ_LOG_ERROR("Expected '[' got '%c'\n", path[*i]);
			*offset = -1;
			return NULL;
		}

		++*i;
		size_t tok_beg = *i;
		for (; isdigit(path[*i]); ++*i)
			;

		if (path[*i] != ']') {
			RZ_LOG_ERROR("Expected ']' got '%c'\n", path[*i]);
			*offset = -1;
			return NULL;
		}

		char *idx_str = rz_str_ndup(&path[tok_beg], *i - tok_beg);
		size_t idx = rz_num_math(NULL, idx_str);
		free(idx_str);

		cur_dim_off /= typd->array.count;
		*offset += cur_dim_off * idx;
		typd = typd->array.type;

		// DONT check for "idx < array size"
		// because guy may be exploiting OOB or something else.
		// so just continue.

		++*i; // skip ']'
	}

	return typd;
}

static RzType *path_walker_parse_dot(const RzTypeDB *typedb, RzType *parent, const char *path, size_t *i, st64 *offset) {
	++*i;

	size_t tok_beg = *i;
	for (; isalnum(path[*i]); ++*i)
		;

	char *tok = rz_str_ndup(&path[tok_beg], *i - tok_beg);

	RzBaseType *parent_btype = rz_type_get_base_type(typedb, parent);
	if (!parent_btype) {
		RZ_LOG_ERROR("Could not found btype for parent '%s'\n", parent->identifier.name);
		*offset = -1;
		free(tok);
		return NULL;
	}

	RzTypeStructMember *memb_it;
	RzType *cur_type = NULL;
	size_t cur_offset = -1;
	rz_vector_foreach(&parent_btype->struct_data.members, memb_it) {
		if (!strcmp(memb_it->name, tok)) {
			cur_type = memb_it->type;
			cur_offset = memb_it->offset; // in bytes
			cur_offset *= 8; // in bits
			break;
		}
	}

	if (!cur_type) {
		RZ_LOG_ERROR("Invalid member '%s' for parent type\n", tok);
		*offset = -1;
		free(tok);
		return NULL;
	}

	free(tok);

	*offset += cur_offset;
	if (path[*i] == '[') {
		parent = cur_type;
		if (parent->kind != RZ_TYPE_KIND_ARRAY) {
			RZ_LOG_ERROR("Expected array, got another type\n");
			*offset = -1;
			return NULL;
		}

		path_walker_parse_bracket(typedb, parent, path, i, offset);
		if (*offset == -1) {
			return NULL;
		}

		// unwrap array
		while (parent->kind == RZ_TYPE_KIND_ARRAY) {
			parent = parent->array.type;
		}
		return parent;
	} else if (path[*i] == '.' || path[*i] == '\0') {
		return cur_type;
	} else {
		RZ_LOG_ERROR("Unexpected character '%c' at position %lu\n", path[*i], *i);
		*offset = -1;
		return NULL;
	}
}

static st64 path_walker(const RzTypeDB *typedb, const char *path) {
	rz_return_val_if_fail(typedb && path, -1);

	size_t i;
	for (i = 0; isalnum(path[i]); ++i)
		;

	if (path[i] != '.') {
		RZ_LOG_ERROR("Unexpected character '%c' at position %lu\n", path[i], i);
		return -1;
	}

	char *parent_name = rz_str_ndup(path, i);
	RzType *parent = rz_type_identifier_of_base_type_str(typedb, parent_name);
	free(parent_name);

	st64 offset = 0;
	while (path[i] != '\0') {
		if (path[i] != '.') {
			RZ_LOG_ERROR("Unexpected character '%c' at position %lu\n", path[i], i);
			return -1;
		}

		if (parent->kind != RZ_TYPE_KIND_IDENTIFIER) {
			RZ_LOG_ERROR("parent is not identifier\n");
			return -1;
		}

		if (parent->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_STRUCT && parent->identifier.kind != RZ_TYPE_IDENTIFIER_KIND_UNION) {
			RZ_LOG_ERROR("parent type kind is not struct or union\n");
			return -1;
		}

		parent = path_walker_parse_dot(typedb, parent, path, &i, &offset);
		if (offset == -1) {
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

static void collect_type_paths(const RzTypeDB *typedb, RzList /*<RzTypePath *>*/ *list, const RzType *type, char *prefix, ut64 offset, unsigned int depth);

static void collect_base_type_paths(const RzTypeDB *typedb, RzList /*<RzTypePath *>*/ *list, const RzBaseType *btype, char *prefix, ut64 offset, unsigned int depth) {
	rz_return_if_fail(typedb && list && btype && prefix);
	if (!depth) {
		return;
	}
	switch (btype->kind) {
	case RZ_BASE_TYPE_KIND_STRUCT: {
		RzTypeStructMember *memb;
		ut64 memb_offset = 0;
		rz_vector_foreach(&btype->struct_data.members, memb) {
			if (memb_offset == offset) {
				RzTypePath *tpath = rz_type_path_new(memb->type, rz_str_newf("%s.%s", prefix, memb->name));
				if (tpath) {
					rz_list_append(list, tpath);
				}
			}
			ut64 bytesz = rz_type_db_get_bitsize(typedb, memb->type) / 8;
			if (memb_offset + bytesz > offset) {
				char *newpath = rz_str_newf("%s.%s", prefix, memb->name);
				collect_type_paths(typedb, list, memb->type, newpath, offset - memb_offset, depth - 1);
				free(newpath);
				break;
			}
			memb_offset += bytesz;
		}
		break;
	}
	case RZ_BASE_TYPE_KIND_UNION: {
		RzTypeUnionMember *memb;
		rz_vector_foreach(&btype->union_data.members, memb) {
			char *newpath = rz_str_newf("%s.%s", prefix, memb->name);
			if (offset == 0) {
				RzTypePath *tpath = rz_type_path_new(memb->type, newpath);
				if (tpath) {
					rz_list_append(list, tpath);
				}
			}
			collect_type_paths(typedb, list, memb->type, newpath, offset, depth - 1);
			if (offset != 0) {
				free(newpath);
			}
		}
		break;
	}
	case RZ_BASE_TYPE_KIND_TYPEDEF: {
		RzType *ttype = rz_type_db_base_type_unwrap_typedef(typedb, btype);
		if (!ttype) {
			return;
		}
		collect_type_paths(typedb, list, ttype, prefix, offset, depth); // depth not decreased because this is not a visible step in the path
		break;
	}
	default:
		break;
	}
}

static void collect_type_paths(const RzTypeDB *typedb, RzList /*<RzTypePath *>*/ *list, const RzType *type, char *prefix, ut64 offset, unsigned int depth) {
	rz_return_if_fail(typedb && list && type && prefix);
	if (!depth) {
		return;
	}
	switch (type->kind) {
	case RZ_TYPE_KIND_IDENTIFIER: {
		rz_return_if_fail(type->identifier.name);
		RzBaseType *btype = rz_type_db_get_base_type(typedb, type->identifier.name);
		if (!btype) {
			return;
		}
		collect_base_type_paths(typedb, list, btype, prefix, offset, depth); // depth not decreased because this is not a visible step in the path
		break;
	}
	case RZ_TYPE_KIND_ARRAY: {
		rz_return_if_fail(type->array.type);
		ut64 stride = rz_type_db_get_bitsize(typedb, type->array.type) / 8;
		if (!stride) {
			break;
		}
		ut64 idx = offset / stride;
		if (idx >= type->array.count) {
			break;
		}
		ut64 idx_offset = offset - idx * stride;
		char *newpath = rz_str_newf("%s[%" PFMT64u "]", prefix, idx);
		if (idx_offset == 0) {
			RzTypePath *tpath = rz_type_path_new(type->array.type, newpath);
			if (tpath) {
				rz_list_append(list, tpath);
			}
		}
		collect_type_paths(typedb, list, type->array.type, newpath, idx_offset, depth - 1);
		if (idx_offset != 0) {
			free(newpath);
		}
		break;
	}
	default:
		break;
	}
}

/**
 * \brief Returns the list of all paths into the base type matching the offset
 *
 * \param btype The root type from which paths are searched
 * \param offset The offset into \p btype to match against
 * \param max_depth Maximum number of components a path may have
 */
RZ_API RZ_OWN RzList /*<RzTypePath *>*/ *rz_base_type_path_by_offset(const RzTypeDB *typedb, const RzBaseType *btype, ut64 offset, unsigned int max_depth) {
	rz_return_val_if_fail(typedb && btype && btype->name, NULL);
	RzList *list = rz_list_newf((RzListFree)rz_type_path_free);
	if (!list) {
		return NULL;
	}
	collect_base_type_paths(typedb, list, btype, "", offset, max_depth);
	return list;
}

/**
 * \brief Returns the list of all paths into the type matching the offset
 *
 * \param type The root type from which paths are searched
 * \param offset The offset into \p btype to match against
 * \param max_depth Maximum number of components a path may have
 */
RZ_API RZ_OWN RzList /*<RzTypePath *>*/ *rz_type_path_by_offset(const RzTypeDB *typedb, const RzType *type, ut64 offset, unsigned int max_depth) {
	rz_return_val_if_fail(typedb && type, NULL);
	RzList *list = rz_list_newf((RzListFree)rz_type_path_free);
	if (!list) {
		return NULL;
	}
	collect_type_paths(typedb, list, type, "", offset, max_depth);
	return list;
}

/**
 * \brief Returns the list of all structured types that have members matching the offset
 *
 * \param typedb Types Database instance
 * \param offset The offset of the member to match against
 */
RZ_API RZ_OWN RzList /*<RzTypePath *>*/ *rz_type_db_get_by_offset(const RzTypeDB *typedb, ut64 offset) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *types = rz_type_db_get_base_types(typedb);
	RzList *result = rz_list_newf((RzListFree)rz_type_path_free);
	RzListIter *iter;
	RzBaseType *t;
	rz_list_foreach (types, iter, t) {
		if (t->kind == RZ_BASE_TYPE_KIND_STRUCT || t->kind == RZ_BASE_TYPE_KIND_UNION) {
			collect_base_type_paths(typedb, result, t, t->name, offset, 1);
		}
	}
	rz_list_free(types);
	return result;
}

/**
 * \brief Returns the packed offset in bits of the structure member if there is a match
 *
 * \param typedb Types Database instance
 * \param name The structure type name
 * \param name The structure member name
 */
RZ_API ut64 rz_type_db_struct_member_packed_offset(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *member) {
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

/**
 * \brief Returns the offset in bytes of the structure member if there is a match
 *
 * \param typedb Types Database instance
 * \param name The structure type name
 * \param name The structure member name
 */
RZ_API ut64 rz_type_db_struct_member_offset(RZ_NONNULL const RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_NONNULL const char *member) {
	rz_return_val_if_fail(typedb && name && member, 0);
	RzBaseType *btype = rz_type_db_get_base_type(typedb, name);
	if (!btype || btype->kind != RZ_BASE_TYPE_KIND_STRUCT) {
		return 0;
	}
	RzTypeStructMember *memb;
	rz_vector_foreach(&btype->struct_data.members, memb) {
		if (!strcmp(memb->name, member)) {
			return memb->offset;
		}
	}
	return 0;
}
