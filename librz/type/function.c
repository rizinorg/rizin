// SPDX-FileCopyrightText: 2013-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2013-2020 oddcoder <ahmedsoliman@oddcoder.com>
// SPDX-FileCopyrightText: 2013-2020 sivaramaaa <sivaramaaa@gmail.com>
// SPDX-FileCopyrightText: 2021 Anton Kochkov <anton.kochkov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_type.h>
#include <string.h>

/**
 * \brief Creates a new RzCallable type
 *
 * \param name Name of the callable type
 * \param type A return type of the callable type
 */
RZ_API RZ_OWN RzCallable *rz_type_callable_new(RZ_NULLABLE const char *name) {
	RzCallable *callable = RZ_NEW0(RzCallable);
	if (!callable) {
		return NULL;
	}
	callable->ret = NULL;
	callable->name = name ? strdup(name) : NULL;
	callable->args = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
	return callable;
}

/**
 * \brief Creates an exact clone of the RzCallable type
 *
 * \param callable RzCallable instance to clone
 */
RZ_API RZ_OWN RzCallable *rz_type_callable_clone(RZ_BORROW RZ_NONNULL const RzCallable *callable) {
	rz_return_val_if_fail(callable, NULL);
	RzCallable *newcallable = RZ_NEWCOPY(RzCallable, callable);
	if (!newcallable) {
		return NULL;
	}
	newcallable->ret = callable->ret ? rz_type_clone(callable->ret) : NULL;
	newcallable->name = callable->name ? strdup(callable->name) : NULL;
	newcallable->args = rz_pvector_new((RzPVectorFree)rz_type_callable_arg_free);
	void **it;
	rz_pvector_foreach (callable->args, it) {
		RzCallableArg *arg = *it;
		rz_pvector_push(newcallable->args, rz_type_callable_arg_clone(arg));
	}
	return newcallable;
}

/**
 * \brief Frees the RzCallable
 *
 * \param callable RzCallable type
 */
RZ_API void rz_type_callable_free(RZ_NONNULL RzCallable *callable) {
	rz_type_free(callable->ret);
	rz_pvector_free(callable->args);
	free(callable->name);
	free(callable);
}

/**
 * \brief Creates a new RzCallableArg given the name and type
 *
 * \param typedb RzTypeDB instance
 * \param name Name of the argument
 * \param type RzType type of the argument
 */
RZ_API RZ_OWN RzCallableArg *rz_type_callable_arg_new(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_OWN RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && name && type, NULL);
	RzCallableArg *arg = RZ_NEW0(RzCallableArg);
	if (!arg) {
		return NULL;
	}
	arg->name = strdup(name);
	arg->type = type;
	return arg;
}

/**
 * \brief Creates am exact clone of RzCallableArg
 *
 * \param arg RzCallable argument pointer
 */
RZ_API RZ_OWN RzCallableArg *rz_type_callable_arg_clone(RZ_BORROW RZ_NONNULL const RzCallableArg *arg) {
	rz_return_val_if_fail(arg, NULL);
	RzCallableArg *newarg = RZ_NEW0(RzCallableArg);
	if (!newarg) {
		return NULL;
	}
	newarg->name = strdup(arg->name);
	newarg->type = rz_type_clone(arg->type);
	return newarg;
}

/**
 * \brief Frees the RzCallableArg
 *
 * \param arg RzCallableArg instance
 */
RZ_API void rz_type_callable_arg_free(RzCallableArg *arg) {
	if (!arg) {
		return;
	}
	free(arg->name);
	rz_type_free(arg->type);
	free(arg);
}

/**
 * \brief Adds a new argument to the RzCallable
 *
 * \param callable RzCallable instance
 * \param arg Argument to add
 */
RZ_API bool rz_type_callable_arg_add(RZ_NONNULL RzCallable *callable, RZ_OWN RZ_NONNULL RzCallableArg *arg) {
	rz_return_val_if_fail(callable && arg, false);
	rz_pvector_push(callable->args, arg);
	return true;
}

// Function prototypes api

/**
 * \brief Creates a new RzCallable type
 *
 * \param typedb RzTypeDB instance
 * \param name Name of the callable type
 * \param type A return type of the callable type
 */
RZ_API RZ_OWN RzCallable *rz_type_func_new(RzTypeDB *typedb, RZ_NONNULL const char *name, RZ_OWN RZ_NULLABLE RzType *type) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzCallable *callable = rz_type_callable_new(name);
	if (!callable) {
		return NULL;
	}
	callable->ret = type;
	return callable;
}

/**
 * \brief Stores RzCallable type in the types database
 *
 * \param typedb Type Database instance
 * \param callable RzCallable type to save
 */
RZ_API bool rz_type_func_save(RzTypeDB *typedb, RZ_NONNULL RzCallable *callable) {
	rz_return_val_if_fail(typedb && callable && callable->name, false);
	if (rz_type_func_exist(typedb, callable->name)) {
		return false;
	}
	ht_sp_insert(typedb->callables, callable->name, callable);
	return true;
}

/**
 * \brief Update RzCallable type in the types database
 *
 * \param typedb Type Database instance
 * \param callable RzCallable type to save
 */
RZ_API bool rz_type_func_update(RzTypeDB *typedb, RZ_NONNULL RzCallable *callable) {
	rz_return_val_if_fail(typedb && callable && callable->name, false);
	if (!ht_sp_update(typedb->callables, callable->name, (void *)callable)) {
		rz_type_callable_free(callable);
		return false;
	}
	return true;
}

/**
 * \brief Returns the RzCallable from the database by name
 *
 * \param typedb Type Database instance
 * \param name RzCallable (function) name to search
 */
RZ_API RZ_BORROW RzCallable *rz_type_func_get(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	bool found = false;
	RzCallable *callable = ht_sp_find(typedb->callables, name, &found);
	if (!found || !callable) {
		RZ_LOG_DEBUG("Cannot find function type \"%s\"\n", name);
		return NULL;
	}
	return callable;
}

/**
 * \brief Removes RzCallable type from the types database
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 */
RZ_API bool rz_type_func_delete(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	ht_sp_delete(typedb->callables, name);
	return true;
}

/**
 * \brief Removes all RzCallable types
 */
RZ_API void rz_type_func_delete_all(RzTypeDB *typedb) {
	ht_sp_free(typedb->callables);
	typedb->callables = ht_sp_new(HT_STR_DUP, NULL, (HtSPFreeValue)rz_type_callable_free);
}

/**
 * \brief Checks if the RzCallable type exists in the database given the name
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 */
RZ_API bool rz_type_func_exist(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	bool found = false;
	return ht_sp_find(typedb->callables, name, &found) && found;
}

/**
 * \brief Searches for the RzCallable type in types database and returns return type
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 */
RZ_API RZ_BORROW RzType *rz_type_func_ret(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return NULL;
	}
	return callable->ret;
}

/**
 * \brief Searches for the RzCallable type in types database and returns calling convention
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 */
RZ_API RZ_BORROW const char *rz_type_func_cc(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return NULL;
	}
	return callable->cc;
}

/**
 * \brief Searches for the RzCallable type in types database and set the calling convention
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 * \param name Name of the calling convention to set
 */
RZ_API bool rz_type_func_cc_set(RzTypeDB *typedb, const char *name, const char *cc) {
	rz_return_val_if_fail(typedb && name, false);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return false;
	}
	callable->cc = strdup(cc);
	return true;
}

/**
 * \brief Searches for the RzCallable type in types database and returns arguments' count
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 */
RZ_API int rz_type_func_args_count(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, 0);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return -1;
	}
	return rz_pvector_len(callable->args);
}

/**
 * \brief Searches for the RzCallable type in types database and returns argument type
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 * \param i Index of the argument go get type of
 */
RZ_API RZ_BORROW RzType *rz_type_func_args_type(RzTypeDB *typedb, RZ_NONNULL const char *name, int i) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return NULL;
	}
	if (i >= rz_pvector_len(callable->args)) {
		return NULL;
	}
	RzCallableArg *arg = rz_pvector_at(callable->args, i);
	if (!arg) {
		rz_warn_if_reached(); // should not happen in the types database
		return NULL;
	}
	return arg->type;
}

/**
 * \brief Searches for the RzCallable type in types database and returns argument name
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 * \param i Index of the argument go get type of
 */
RZ_API RZ_BORROW const char *rz_type_func_args_name(RzTypeDB *typedb, RZ_NONNULL const char *name, int i) {
	rz_return_val_if_fail(typedb && name, NULL);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return NULL;
	}
	if (i >= rz_pvector_len(callable->args)) {
		return NULL;
	}
	RzCallableArg *arg = rz_pvector_at(callable->args, i);
	if (!arg) {
		rz_warn_if_reached(); // should not happen in the types database
		return NULL;
	}
	return arg->name;
}

/**
 * \brief Adds a new argument to the RzCallable type at the end of the arguments vector
 *
 * \param typedb Type Database instance
 * \param func_name Name of the callable to search
 * \param arg_name Name of the new argument
 * \param arg_type RzType type of the new argument
 */
RZ_API bool rz_type_func_arg_add(RzTypeDB *typedb, RZ_NONNULL const char *func_name, RZ_NONNULL const char *arg_name, RZ_OWN RZ_NONNULL RzType *arg_type) {
	rz_return_val_if_fail(typedb && func_name, false);
	RzCallable *callable = rz_type_func_get(typedb, func_name);
	if (!callable) {
		return false;
	}
	RzCallableArg *arg = rz_type_callable_arg_new(typedb, arg_name, arg_type);
	if (!arg) {
		return false;
	}
	rz_pvector_push(callable->args, arg);
	return true;
}

/**
 * \brief Sets the new return type for the RzCallable
 *
 * \param typedb Type Database instance
 * \param name Name of the callable to search
 * \param type RzType return type
 */
RZ_API bool rz_type_func_ret_set(RzTypeDB *typedb, const char *name, RZ_BORROW RZ_NONNULL RzType *type) {
	rz_return_val_if_fail(typedb && name && type, false);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return false;
	}
	rz_type_free(callable->ret);
	callable->ret = rz_type_clone(type);
	return true;
}

/**
 * \brief Checks if the RzType is the pointer to the RzCallable
 *
 * \param typedb Types Database instance
 * \param type RzType
 */
RZ_API bool rz_type_is_callable(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	return type->kind == RZ_TYPE_KIND_CALLABLE;
}

/**
 * \brief Checks if the RzType is the pointer to the RzCallable
 *
 * \param typedb Types Database instance
 * \param type RzType
 */
RZ_API bool rz_type_is_callable_ptr(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	if (type->pointer.type->kind == RZ_TYPE_KIND_CALLABLE) {
		return true;
	} else if (type->pointer.type->kind == RZ_TYPE_KIND_POINTER) {
		return rz_type_is_callable_ptr(type->pointer.type);
	}
	return false;
}

/**
 * \brief Checks if the RzType is the nested pointer to the RzCallable
 *
 * For example it could be one of those:
 * - int (*func)(int a, char *b)
 * - int (**func)(int a, char *b)
 * - int (****func)(int a, char *b)
 *
 * \param typedb Types Database instance
 * \param type RzType
 */
RZ_API bool rz_type_is_callable_ptr_nested(RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(type, false);
	if (type->kind != RZ_TYPE_KIND_POINTER) {
		return false;
	}
	// There should not exist pointers to the empty types
	RzType *ptr = type->pointer.type;
	rz_return_val_if_fail(ptr, false);
	if (ptr->kind == RZ_TYPE_KIND_POINTER) {
		return rz_type_is_callable_ptr_nested(ptr);
	}
	return ptr->kind == RZ_TYPE_KIND_CALLABLE;
}

static const RzCallable *callable_ptr_unwrap(RZ_NONNULL const RzType *type, size_t *acc) {
	rz_return_val_if_fail(type && acc, NULL);
	if (type->kind == RZ_TYPE_KIND_POINTER) {
		*acc = *acc + 1;
		return callable_ptr_unwrap(type->pointer.type, acc);
	}
	return type->kind == RZ_TYPE_KIND_CALLABLE ? type->callable : NULL;
}

static inline char *callable_name_or_ptr(RZ_NONNULL const RzCallable *callable, size_t ptr_depth) {
	if (ptr_depth > 0) {
		// Due to the portability issues with other solutions we use this hack to repeat the '*' character
		return rz_str_newf("(%.*s%s)", (int)ptr_depth, "****************", rz_str_get(callable->name));
	} else {
		return strdup(rz_str_get(callable->name));
	}
}

static bool callable_as_string(RzStrBuf *buf, const RzTypeDB *typedb, RZ_NONNULL const RzCallable *callable, size_t ptr_depth) {
	rz_return_val_if_fail(buf && typedb && callable, false);

	if (callable->noret) {
		rz_strbuf_append(buf, "__attribute__((noreturn)) ");
	}
	char *ret_str = callable->ret ? rz_type_as_string(typedb, callable->ret) : NULL;
	char *callable_name = callable_name_or_ptr(callable, ptr_depth);
	rz_strbuf_appendf(buf, "%s %s(", ret_str ? ret_str : "void", callable_name);
	free(ret_str);
	free(callable_name);
	void **it;
	bool first = true;
	rz_pvector_foreach (callable->args, it) {
		RzCallableArg *arg = *it;
		if (arg) {
			char *argstr = rz_type_identifier_declaration_as_string(typedb, arg->type, rz_str_get(arg->name));
			const char *comma = first ? "" : ", ";
			rz_strbuf_appendf(buf, "%s%s", comma, argstr);
			first = false;
			free(argstr);
		}
	}
	if (callable->has_unspecified_parameters) {
		if (rz_pvector_len(callable->args) >= 1) {
			rz_strbuf_append(buf, ", ");
		}
		rz_strbuf_append(buf, "...");
	}
	rz_strbuf_append(buf, ")");
	return true;
}

/**
 * \brief Returns the callable pointer C representation
 *
 * \param typedb Types Database instance
 * \param callable RzCallable instance
 */
RZ_API RZ_OWN char *rz_type_callable_ptr_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzType *type) {
	rz_return_val_if_fail(typedb && type, NULL);
	rz_return_val_if_fail(type->kind == RZ_TYPE_KIND_POINTER, NULL);

	size_t ptr_depth = 0;
	const RzCallable *callable = callable_ptr_unwrap(type, &ptr_depth);
	if (!callable) {
		return NULL;
	}
	RzStrBuf *buf = rz_strbuf_new("");
	if (!callable_as_string(buf, typedb, callable, ptr_depth)) {
		rz_strbuf_free(buf);
		return NULL;
	}
	return rz_strbuf_drain(buf);
}

/**
 * \brief Returns the callable C representation
 *
 * \param typedb Types Database instance
 * \param callable RzCallable instance
 */
RZ_API RZ_OWN char *rz_type_callable_as_string(const RzTypeDB *typedb, RZ_NONNULL const RzCallable *callable) {
	rz_return_val_if_fail(typedb && callable, NULL);
	RzStrBuf *buf = rz_strbuf_new("");
	if (!callable_as_string(buf, typedb, callable, 0)) {
		rz_strbuf_free(buf);
		return NULL;
	}
	return rz_strbuf_drain(buf);
}

/**
 * \brief Checks if the RzCallable type is defined as "noreturn"
 *
 * \param typedb Types Database instance
 * \param name Name of the RzCallable type
 */
RZ_API bool rz_type_func_is_noreturn(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return false;
	}
	return callable->noret;
}

/**
 * \brief Adds the "noreturn" attribute to the RzCallable type
 *
 * \param typedb Types Database instance
 * \param name Name of the RzCallable type
 */
RZ_API bool rz_type_func_noreturn_add(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	// If the function exists with the specified name already, we set the noreturn flag for it
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (callable) {
		callable->noret = true;
	} else {
		// If it doesn't - we create a new dummy RzCallable for it
		// The return type is default and no arguments
		callable = rz_type_func_new(typedb, name, NULL);
		if (!callable) {
			return false;
		}
		callable->noret = true;
		rz_type_func_save(typedb, callable);
	}
	return true;
}

/**
 * \brief Drops the "noreturn" attribute from the RzCallable type
 *
 * \param typedb Types Database instance
 * \param name Name of the RzCallable type
 */
RZ_API bool rz_type_func_noreturn_drop(RzTypeDB *typedb, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(typedb && name, false);
	RzCallable *callable = rz_type_func_get(typedb, name);
	if (!callable) {
		return false;
	}
	callable->noret = false;
	return true;
}

// Listing function types

static bool function_names_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	RzList *l = (RzList *)user;
	RzCallable *callable = (RzCallable *)v;
	rz_list_append(l, strdup(callable->name));
	return true;
}

/**
 * \brief Returns the list of all function type names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_function_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *result = rz_list_newf(free);
	ht_sp_foreach_cb(typedb->callables, function_names_collect_cb, result);
	return result;
}

static bool noreturn_function_names_collect_cb(void *user, RZ_UNUSED const char *k, const void *v) {
	RzList *l = (RzList *)user;
	RzCallable *callable = (RzCallable *)v;
	if (callable->noret) {
		rz_list_append(l, strdup(callable->name));
	}
	return true;
}

/**
 * \brief Returns the list of all noreturn function type names
 *
 * \param typedb Types Database instance
 */
RZ_API RZ_OWN RzList /*<char *>*/ *rz_type_noreturn_function_names(RzTypeDB *typedb) {
	rz_return_val_if_fail(typedb, NULL);
	RzList *noretl = rz_list_newf(free);
	ht_sp_foreach_cb(typedb->callables, noreturn_function_names_collect_cb, noretl);
	return noretl;
}
