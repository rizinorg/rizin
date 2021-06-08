// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util/rz_serialize.h>
#include <rz_list.h>
#include <rz_vector.h>
#include <rz_type.h>
#include <sdb.h>

static RzCallable *get_callable_type(RzTypeDB *typedb, Sdb *sdb, const char *name) {
	rz_return_val_if_fail(typedb && sdb && RZ_STR_ISNOTEMPTY(name), NULL);

	RzCallable *callable = rz_type_func_new(typedb, name, NULL);
	if (!callable) {
		return NULL;
	}

	char *args_key = rz_str_newf("%s.%s.args", "func", name);
	if (!args_key) {
		return NULL;
	}

	size_t arguments = sdb_num_get(sdb, args_key, 0);
	if (arguments > 0 && !rz_pvector_reserve(callable->args, arguments)) {
		goto error;
	}

	int i;
	for (i = 0; i < arguments; i++) {
		char *argument_key = rz_str_newf("func.%s.arg.%d", name, i);
		if (!argument_key) {
			goto error;
		}
		char *values = sdb_get(sdb, argument_key, NULL);
		free(argument_key);

		if (!values) {
			goto error;
		}
		char *argument_name;
		char *argument_type = sdb_anext(values, &argument_name);
		if (!argument_name) {
			// Autoname unnamed arguments
			argument_name = rz_str_newf("arg%d", i);
		}
		char *error_msg = NULL;
		RzType *ttype = rz_type_parse_string_single(typedb->parser, argument_type, &error_msg);
		if (!ttype || error_msg) {
			eprintf("error parsing \"%s\" func arg type \"%s\": %s\n", name, argument_type, error_msg);
			free(values);
			goto error;
		}
		RzCallableArg *arg = RZ_NEW0(RzCallableArg);
		if (!arg) {
			goto error;
		}
		arg->name = strdup(argument_name);
		arg->type = ttype;
		free(values);

		void *element = rz_pvector_push(callable->args, arg); // returns null if no space available
		if (!element) {
			goto error;
		}
	}

	RzStrBuf key;
	const char *rettype = sdb_get(sdb, rz_strbuf_initf(&key, "func.%s.ret", name), 0);
	rz_strbuf_fini(&key);

	char *error_msg = NULL;
	RzType *ttype = rz_type_parse_string_single(typedb->parser, rettype, &error_msg);
	if (!ttype || error_msg) {
		eprintf("error parsing \"%s\" func return type \"%s\": %s \n", name, rettype, error_msg);
		goto error;
	}
	callable->ret = ttype;

	// Optional "noreturn" attribute
	char *noreturn_key = rz_str_newf("%s.%s.noreturn", "func", name);
	if (!noreturn_key) {
		return NULL;
	}

	callable->noret = sdb_bool_get(sdb, noreturn_key, 0);

	return callable;

error:
	rz_type_callable_free(callable);
	return NULL;
}

static bool sdb_load_callables(RzTypeDB *typedb, Sdb *sdb) {
	rz_return_val_if_fail(typedb && sdb, NULL);
	RzCallable *callable;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list(sdb, false);
	ls_foreach (l, iter, kv) {
		if (!strcmp(sdbkv_value(kv), "func")) {
			//eprintf("loading function: \"%s\"\n", sdbkv_key(kv));
			callable = get_callable_type(typedb, sdb, sdbkv_key(kv));
			if (callable) {
				ht_pp_insert(typedb->callables, callable->name, callable);
				RZ_LOG_DEBUG("inserting the \"%s\" callable type\n", callable->name);
			}
		}
	}
	return true;
}

static bool sdb_load_by_path(RZ_NONNULL RzTypeDB *typedb, const char *path) {
	Sdb *db = sdb_new(0, path, 0);
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
	sdb_set(sdb, cname, "func", 0);

	// func.name.args=N
	char *key = rz_str_newf("func.%s.args", cname);
	sdb_num_set(sdb, key, rz_pvector_len(callable->args), 0);
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
			rz_strbuf_setf(&param_val, "%s,%s", arg_type, arg_name), 0ULL);
		free(arg_name);
		free(arg_type);
	}
	rz_strbuf_fini(&param_key);
	rz_strbuf_fini(&param_val);

	// func.name.ret=type
	if (callable->ret) {
		key = rz_str_newf("func.%s.ret", cname);
		char *ret_type = rz_type_as_string(typedb, callable->ret);
		sdb_set(sdb, key, ret_type, 0);
		free(key);
	}

	// Optional "noreturn" attribute
	if (callable->noret) {
		char *noreturn_key = rz_str_newf("func.%s.noreturn", cname);
		sdb_bool_set(sdb, noreturn_key, true, 0);
	}
}

struct typedb_sdb {
	const RzTypeDB *typedb;
	Sdb *sdb;
};

static bool export_callable_cb(void *user, const void *k, const void *v) {
	struct typedb_sdb *s = user;
	RzCallable *callable = (RzCallable *)v;
	save_callable(s->typedb, s->sdb, callable);
	return true;
}

static bool callable_export_sdb(RZ_NONNULL Sdb *db, RZ_NONNULL const RzTypeDB *typedb) {
	struct typedb_sdb tdb = { typedb, db };
	ht_pp_foreach(typedb->callables, export_callable_cb, &tdb);
	return true;
}

RZ_API bool rz_type_db_load_callables_sdb(RzTypeDB *typedb, const char *path) {
	if (!rz_file_exists(path)) {
		return false;
	}
	return sdb_load_by_path(typedb, path);
}

RZ_API void rz_serialize_callables_save(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb) {
	callable_export_sdb(db, typedb);
}

RZ_API bool rz_serialize_callables_load(RZ_NONNULL Sdb *db, RZ_NONNULL RzTypeDB *typedb, RZ_NULLABLE RzSerializeResultInfo *res) {
	sdb_load_callables(typedb, db);
	return true;
}
