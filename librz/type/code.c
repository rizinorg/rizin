// SPDX-FileCopyrightText: 2013-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>

#include "tcc.h"

extern int tcc_sym_push(char *typename, int typesize, int meta);

/* parse C code and return it in key-value form */

static void __appendString(const char *msg, char **s) {
	if (!s) {
		printf("%s\n", msg);
	} else if (*s) {
		char *p = malloc(strlen(msg) + strlen(*s) + 1);
		if (p) {
			strcpy(p, *s);
			free(*s);
			*s = p;
			strcpy(p + strlen(p), msg);
		}
	} else {
		*s = strdup(msg);
	}
}

static bool __typeLoad(void *p, const char *k, const char *v) {
	if (!p) {
		return false;
	}
	RzTypeDB *typedb = (RzTypeDB *)p;
	RzBaseType *basetype = (RzBaseType *)v;
	int btype = 0;
	if (basetype->kind == RZ_BASE_TYPE_KIND_STRUCT) {
		// structure
		btype = VT_STRUCT;
		const char *typename = k;
		int typesize = btype->size;
		RzTypeStructMember *memb;
		rz_vector_foreach(&basetype->struct_data.members, memb) {
			const char *subtype = rz_type_as_string(typedb, memb->type);
			tcc_sym_push(subtype, 0, btype);
			// FIXME: Support nested types
		}
		tcc_sym_push((char *)typename, typesize, btype);
	}
	if (basetype->kind == RZ_BASE_TYPE_KIND_UNION) {
		// union
		btype = VT_UNION;
		const char *typename = k;
		int typesize = btype->size;
		RzTypeUnionMember *memb;
		rz_vector_foreach(&basetype->union_data.members, memb) {
			const char *subtype = rz_type_as_string(typedb, memb->type);
			tcc_sym_push(subtype, 0, btype);
			// FIXME: Support nested types
		}
		tcc_sym_push((char *)typename, typesize, btype);
	}
	return true;
}

static void __errorFunc(void *opaque, const char *msg) {
	__appendString(msg, opaque);
	char **p = (char **)opaque;
	if (p && *p) {
		int n = strlen(*p);
		char *ptr = malloc(n + 2);
		if (!ptr) {
			return;
		}
		strcpy(ptr, *p);
		ptr[n] = '\n';
		ptr[n + 1] = 0;
		free(*p);
		*p = ptr;
	}
}

RZ_API char *rz_type_parse_c_file(RzTypeDB *typedb, const char *path, const char *dir, char **error_msg) {
	char *str = NULL;
	TCCState *T = tcc_new(typedb->target->cpu, typedb->target->bits, typedb->target->os);
	if (!T) {
		return NULL;
	}
	tcc_set_callback(T, &__appendString, &str);
	tcc_set_error_func(T, (void *)error_msg, __errorFunc);
	ht_pp_foreach(typedb->types, __typeLoad, typedb);
	if (tcc_add_file(T, path, dir) == -1) {
		free(str);
		str = NULL;
	}
	tcc_delete(T);
	return str;
}

RZ_API char *rz_type_parse_c_string(RzTypeDB *typedb, const char *code, char **error_msg) {
	char *str = NULL;
	TCCState *T = tcc_new(typedb->target->cpu, typedb->target->bits, typedb->target->os);
	if (!T) {
		return NULL;
	}
	tcc_set_callback(T, &__appendString, &str);
	tcc_set_error_func(T, (void *)error_msg, __errorFunc);
	ht_pp_foreach(typedb->sdb_types, __typeLoad, typedb);
	if (tcc_compile_string(T, code) != 0) {
		free(str);
		str = NULL;
	}
	tcc_delete(T);
	return str;
}

// XXX do not use globals
RZ_API void rz_type_parse_c_reset(RzTypeDB *typedb) {
	anon_sym = SYM_FIRST_ANOM;
}
