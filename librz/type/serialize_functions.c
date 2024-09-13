// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_type.h>
#include <sdb.h>

/**
 * Parse a type or take it from the cache if it has been parsed before already.
 * This cache is really only relevant because types are stored in the sdb as their C expression,
 * making them extremely slow to load. If they will be e.g. json in the future, this cache can be removed.
 *
 * \param newly_added list of strings where str is appended if it has been added to the cache in this pass
 */
static RzType *parse_type_string_cached(RzTypeParser *parser, HtSP *cache, const char *str, char **error_msg, RZ_OUT RzList /*<char *>*/ *newly_added) {
	rz_return_val_if_fail(str, NULL);
	RzType *r = ht_sp_find(cache, str, NULL);
	if (r) {
		*error_msg = NULL;
		return rz_type_clone(r);
	}
	r = rz_type_parse_string_single(parser, str, error_msg);
	if (r) {
		char *reminder = rz_str_dup(str);
		if (reminder) {
			ht_sp_insert(cache, str, r);
			rz_list_push(newly_added, reminder);
		}
	}
	return r;
}

static void type_string_cache_rollback(HtSP *cache, RzList /*<char *>*/ *newly_added) {
	RzListIter *it;
	char *s;
	rz_list_foreach (newly_added, it, s) {
		ht_sp_delete(cache, s);
	}
}

static RzCallable *get_callable_type(RzTypeDB *typedb, Sdb *sdb, const char *name, HtSP *type_str_cache) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(name), NULL);

	RzList *cache_newly_added = rz_list_newf(free);
	if (!cache_newly_added) {
		return NULL;
	}

	RzCallable *callable = rz_type_func_new(typedb, name, NULL);
	if (!callable) {
		rz_list_free(cache_newly_added);
		return NULL;
	}

	RzStrBuf key;
	size_t arguments = sdb_num_get(sdb, rz_strbuf_initf(&key, "func.%s.args", name));
	if (arguments > 0 && !rz_pvector_reserve(callable->args, arguments)) {
		goto error;
	}

	int i;
	for (i = 0; i < arguments; i++) {
		char *values = sdb_get(sdb, rz_strbuf_setf(&key, "func.%s.arg.%d", name, i));

		if (!values) {
			goto error;
		}
		char arg_name[32];
		char *argument_name;
		char *argument_type = sdb_anext(values, &argument_name);
		if (!argument_name) {
			// Autoname unnamed arguments
			argument_name = rz_strf(arg_name, "arg%d", i);
		}
		char *error_msg = NULL;
		RzType *ttype = parse_type_string_cached(typedb->parser, type_str_cache, argument_type, &error_msg, cache_newly_added);
		if (!ttype || error_msg) {
			eprintf("error parsing \"%s\" func arg type \"%s\": %s\n", name, argument_type, error_msg);
			free(values);
			goto error;
		}
		RzCallableArg *arg = rz_type_callable_arg_new(typedb, argument_name, ttype);
		if (!arg) {
			free(values);
			rz_type_free(ttype);
			goto error;
		}
		free(values);

		void *element = rz_pvector_push(callable->args, arg); // returns null if no space available
		if (!element) {
			rz_type_callable_arg_free(arg);
			goto error;
		}
	}

	const char *rettype = sdb_const_get(sdb, rz_strbuf_setf(&key, "func.%s.ret", name));
	if (!rettype) {
		// best we can do for a broken database
		rettype = "void";
	}

	char *error_msg = NULL;
	RzType *ttype = parse_type_string_cached(typedb->parser, type_str_cache, rettype, &error_msg, cache_newly_added);
	if (!ttype || error_msg) {
		eprintf("error parsing \"%s\" func return type \"%s\": %s \n", name, rettype, error_msg);
		free(error_msg);
		goto error;
	}
	callable->ret = ttype;

	// Optional "noreturn" attribute
	callable->noret = sdb_bool_get(sdb, rz_strbuf_setf(&key, "func.%s.noreturn", name));

	rz_strbuf_fini(&key);
	rz_list_free(cache_newly_added);
	return callable;

error:
	// remove any types from the cache that will be freed by the callable_free below
	type_string_cache_rollback(type_str_cache, cache_newly_added);
	rz_list_free(cache_newly_added);
	rz_type_callable_free(callable);
	rz_strbuf_fini(&key);
	return NULL;
}

static bool filter_func(void *user, const SdbKv *kv) {
	return sdbkv_value_len(kv) == 4 && !strcmp(sdbkv_value(kv), "func");
}

static bool sdb_load_callables(RzTypeDB *typedb, Sdb *sdb) {
	rz_return_val_if_fail(typedb && sdb, false);
	HtSP *type_str_cache = ht_sp_new(HT_STR_DUP, NULL, NULL); // cache from a known C type extr to its RzType representation for skipping the parser if possible
	if (!type_str_cache) {
		return false;
	}
	void **iter;
	RzPVector *items = sdb_get_items_filter(sdb, filter_func, NULL, false);
	rz_pvector_foreach (items, iter) {
		SdbKv *kv = *iter;
		// eprintf("loading function: \"%s\"\n", sdbkv_key(kv));
		RzCallable *callable = get_callable_type(typedb, sdb, sdbkv_key(kv), type_str_cache);
		if (callable) {
			ht_sp_update(typedb->callables, callable->name, callable);
			RZ_LOG_DEBUG("inserting the \"%s\" callable type\n", callable->name);
		}
	}
	ht_sp_free(type_str_cache);
	rz_pvector_free(items);
	return true;
}

static bool sdb_load_by_path(RZ_NONNULL RzTypeDB *typedb, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(typedb && path, false);
	if (RZ_STR_ISEMPTY(path)) {
		return false;
	}
	Sdb *db = sdb_new(0, path, 0);
	bool result = sdb_load_callables(typedb, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

static bool sdb_load_from_string(RZ_NONNULL RzTypeDB *typedb, RZ_NONNULL const char *string) {
	rz_return_val_if_fail(typedb && string, false);
	if (RZ_STR_ISEMPTY(string)) {
		return false;
	}
	Sdb *db = sdb_new0();
	sdb_query_lines(db, string);
	bool result = sdb_load_callables(typedb, db);
	sdb_close(db);
	sdb_free(db);
	return result;
}

static void save_callable(const RzTypeDB *typedb, Sdb *sdb, const RzCallable *callable) {
	rz_return_if_fail(typedb && sdb && callable && callable->name);
	/*
		C:
		type name (type param1, type param2, type paramN);
		Sdb:
		name=func
		func.name.args=N
		func.name.arg.0=type,param1
		func.name.arg.1=type,param2
		func.name.arg.N=type,paramN
		func.name.ret=type
	*/
	const char *cname = callable->name;
	// name=func
	sdb_set(sdb, cname, "func");

	// func.name.args=N
	char *key = rz_str_newf("func.%s.args", cname);
	sdb_num_set(sdb, key, rz_pvector_len(callable->args));
	free(key);

	RzStrBuf param_key;
	RzStrBuf param_val;
	rz_strbuf_init(&param_key);
	rz_strbuf_init(&param_val);

	size_t i = 0;
	void **it;
	rz_pvector_foreach (callable->args, it) {
		RzCallableArg *arg = *it;
		// func.name.arg.N=type,paramN
		char *arg_name = rz_str_sanitize_sdb_key(arg->name);
		char *arg_type = rz_type_as_string(typedb, arg->type);
		sdb_set(sdb,
			rz_strbuf_setf(&param_key, "func.%s.arg.%zu", cname, i),
			rz_strbuf_setf(&param_val, "%s,%s", arg_type, arg_name));
		free(arg_name);
		free(arg_type);
	}
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);

	// func.name.ret=type
	if (callable->ret) {
		key = rz_str_newf("func.%s.ret", cname);
		char *ret_type = rz_type_as_string(typedb, callable->ret);
		sdb_set_owned(sdb, key, ret_type);
		free(key);
	}

	// Optional "noreturn" attribute
	if (callable->noret) {
		char *noreturn_key = rz_str_newf("func.%s.noreturn", cname);
		sdb_bool_set(sdb, noreturn_key, true);
		free(noreturn_key);
	}
}

struct typedb_sdb {
	const RzTypeDB *typedb;
	Sdb *sdb;
};

static bool export_callable_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	struct typedb_sdb *s = user;
	RzCallable *callable = (RzCallable *)v;
	save_callable(s->typedb, s->sdb, callable);
	return true;
}

static bool callable_export_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL const RzTypeDB *typedb) {
	struct typedb_sdb tdb = { typedb, db };
	ht_sp_foreach(typedb->callables, export_callable_cb, &tdb);
	return true;
}

/**
 * \brief Loads the callable types from compiled SDB specified by path
 *
 * \param typedb RzTypeDB instance
 * \param path A path to the compiled SDB containing serialized types
 */
RZ_API bool rz_type_db_load_callables_sdb(RzTypeDB *typedb, RZ_NONNULL const char *path) {
	rz_return_val_if_fail(typedb && path, false);
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_by_path(typedb, path);
}

/**
 * \brief Loads the callable types from SDB KV string
 *
 * \param typedb RzTypeDB instance
 * \param str A string in Key-Value format as for non-compiled SDB
 */
RZ_API bool rz_type_db_load_callables_sdb_str(RzTypeDB *typedb, RZ_NONNULL const char *str) {
	rz_return_val_if_fail(typedb && str, false);
	if (RZ_STR_ISEMPTY(str)) {
		return false;
	}
	return sdb_load_from_string(typedb, str);
}

/**
 * \brief Saves the callable types into SDB
 *
 * \param db A SDB database object
 * \param typedb RzTypeDB instance
 */
RZ_API void rz_serialize_callables_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb) {
	rz_return_if_fail(db && typedb);
	callable_export_sdb(db, typedb);
}

/**
 * \brief Loads the callable types from SDB
 *
 * \param db A SDB database object
 * \param typedb RzTypeDB instance
 * \param res A structure where the result is stored
 */
RZ_API bool rz_serialize_callables_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res) {
	rz_return_val_if_fail(db && typedb, false);
	return sdb_load_callables(typedb, db);
}
