// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>
#include <sdb.h>

// Function prototypes api
RZ_API bool rz_type_func_exist(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, false);
	Sdb *TDB = typedb->sdb_types;
	const char *fcn = sdb_const_get(TDB, func_name, 0);
	return fcn && !strcmp(fcn, "func");
}

RZ_API bool rz_type_func_has_args(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, false);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("func.%s.args", func_name);
	const char *fcn = sdb_const_get(TDB, query, 0);
	return (fcn != NULL);
}

RZ_API const char *rz_type_func_ret(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("func.%s.ret", func_name);
	return sdb_const_get(TDB, query, 0);
}

RZ_API const char *rz_type_func_cc(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("func.%s.cc", func_name);
	return sdb_const_get(TDB, query, 0);
}

RZ_API int rz_type_func_args_count(RzTypeDB *typedb, const char *func_name) {
	rz_return_val_if_fail(typedb && func_name, 0);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("func.%s.args", func_name);
	return sdb_num_get(TDB, query, 0);
}

RZ_API RZ_OWN char *rz_type_func_args_type(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("func.%s.arg.%d", func_name, i);
	char *ret = sdb_get(TDB, query, 0);
	if (ret) {
		char *comma = strchr(ret, ',');
		if (comma) {
			*comma = 0;
			return ret;
		}
		free(ret);
	}
	return NULL;
}

RZ_API const char *rz_type_func_args_name(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	const char *query = sdb_fmt("func.%s.arg.%d", func_name, i);
	const char *get = sdb_const_get(TDB, query, 0);
	if (get) {
		char *ret = strchr(get, ',');
		return ret == 0 ? ret : ret + 1;
	}
	return NULL;
}

RZ_API bool rz_type_func_arg_count_set(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int arg_count) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	bool result = false;
	RzStrBuf key, value;
	rz_strbuf_init(&key);
	rz_strbuf_init(&value);
	if (!rz_strbuf_setf(&key, "func.%s.args", func_name) ||
		!rz_strbuf_setf(&value, "%d", arg_count)) {
		goto exit;
	}
	sdb_set(TDB, rz_strbuf_get(&key), rz_strbuf_get(&value), 0);
exit:
	rz_strbuf_fini(&key);
	rz_strbuf_fini(&value);
	return result;
}

RZ_API bool rz_type_func_arg_set(RzTypeDB *typedb, RZ_NONNULL const char *func_name, int i, RZ_NONNULL const char *arg_name, RZ_NONNULL RzType *arg_type) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	bool result = false;
	RzStrBuf key, value;
	rz_strbuf_init(&key);
	rz_strbuf_init(&value);
	// TODO: Figure out if we should save the whole type here or just a name?
	const char *typestr = rz_type_as_string(typedb, arg_type);
	if (!rz_strbuf_setf(&key, "func.%s.arg.%d", func_name, i) ||
		!rz_strbuf_setf(&value, "%s,%s", typestr, arg_name)) {
		goto exit;
	}
	sdb_set(TDB, rz_strbuf_get(&key), rz_strbuf_get(&value), 0);
exit:
	rz_strbuf_fini(&key);
	rz_strbuf_fini(&value);
	return result;
}

RZ_API bool rz_type_func_ret_set(RzTypeDB *typedb, const char *func_name, const char *type) {
	rz_return_val_if_fail(typedb && func_name && type, NULL);
	Sdb *TDB = typedb->sdb_types;
	char *sdb_type = rz_str_newf("type.%s", type);
	if (!sdb_exists(TDB, sdb_type)) {
		free(sdb_type);
		return false;
	}
	free(sdb_type);
	const char *query = sdb_fmt("func.%s.ret=%s", func_name, type);
	return sdb_querys(TDB, NULL, 0, query);
}

#define MIN_MATCH_LEN 4

static inline bool is_function(const char *name) {
	return name && !strcmp("func", name);
}

static RZ_OWN char *type_func_try_guess(Sdb *TDB, RZ_NONNULL char *name) {
	if (strlen(name) < MIN_MATCH_LEN) {
		return NULL;
	}

	const char *res = sdb_const_get(TDB, name, NULL);
	if (is_function(res)) {
		return strdup(name);
	}

	return NULL;
}

static inline bool is_auto_named(char *func_name, size_t slen) {
	return slen > 4 && (rz_str_startswith(func_name, "fcn.") || rz_str_startswith(func_name, "loc."));
}

static inline bool has_rz_prefixes(char *func_name, int offset, size_t slen) {
	return slen > 4 && (offset + 3 < slen) && func_name[offset + 3] == '.';
}

static char *strip_rz_prefixes(char *func_name, size_t slen) {
	// strip r2 prefixes (sym, sym.imp, etc')
	int offset = 0;

	while (has_rz_prefixes(func_name, offset, slen)) {
		offset += 4;
	}

	return func_name + offset;
}

static char *strip_common_prefixes_stdlib(char *func_name) {
	// strip common prefixes from standard lib functions
	if (rz_str_startswith(func_name, "__isoc99_")) {
		func_name += 9;
	} else if (rz_str_startswith(func_name, "__libc_") && !strstr(func_name, "_main")) {
		func_name += 7;
	} else if (rz_str_startswith(func_name, "__GI_")) {
		func_name += 5;
	}

	return func_name;
}

static char *strip_dll_prefix(char *func_name) {
	char *tmp = strstr(func_name, "dll_");
	if (tmp) {
		return tmp + 3;
	}

	return func_name;
}

static void clean_function_name(char *func_name) {
	char *last = (char *)rz_str_lchr(func_name, '_');
	if (!last || !rz_str_isnumber(last + 1)) {
		return;
	}

	*last = '\0';
}

// TODO:
// - symbol names are long and noisy, some of them might not be matched due
//	 to additional information added around name
RZ_API RZ_OWN char *rz_type_func_guess(RzTypeDB *typedb, RZ_NONNULL char *func_name) {
	rz_return_val_if_fail(typedb && func_name, NULL);
	Sdb *TDB = typedb->sdb_types;
	char *str = func_name;
	char *result = NULL;

	size_t slen = strlen(str);
	if (slen < MIN_MATCH_LEN || is_auto_named(str, slen)) {
		return NULL;
	}

	str = strip_rz_prefixes(str, slen);
	str = strip_common_prefixes_stdlib(str);
	str = strip_dll_prefix(str);

	if ((result = type_func_try_guess(TDB, str))) {
		return result;
	}

	str = strdup(str);
	clean_function_name(str);

	if (*str == '_' && (result = type_func_try_guess(TDB, str + 1))) {
		free(str);
		return result;
	}

	free(str);
	return result;
}

RZ_API RZ_OWN RzList *rz_type_noreturn_functions(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *noretl = rz_list_newf(free);
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(typedb->sdb_types, true);
	ls_foreach (l, iter, kv) {
		const char *k = sdbkv_key(kv);
		if (!strncmp(k, "func.", 5) && strstr(k, ".noreturn")) {
			char *s = strdup(k + 5);
			char *d = strchr(s, '.');
			if (d) {
				*d = 0;
			}
			rz_list_append(noretl, strdup(s));
			free(s);
		}
		if (!strncmp(k, "addr.", 5)) {
			char *off;
			if (!(off = strdup(k + 5))) {
				break;
			}
			char *ptr = strstr(off, ".noreturn");
			if (ptr) {
				*ptr = 0;
				char *addr = rz_str_newf("0x%s", off);
				rz_list_append(noretl, addr);
			}
			free(off);
		}
	}
	ls_free(l);
	return noretl;
}

RZ_API bool rz_type_func_is_noreturn(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	return sdb_bool_get(typedb->sdb_types, sdb_fmt("func.%s.noreturn", name), NULL);
}

RZ_API bool rz_type_func_noreturn_add(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	return sdb_bool_set(typedb->sdb_types, sdb_fmt("func.%s.noreturn", name), true, 0);
}

RZ_API bool rz_type_func_noreturn_drop(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	sdb_unset(typedb->sdb_types, sdb_fmt("func.%s.noreturn", name), 0);
	return true;
}
