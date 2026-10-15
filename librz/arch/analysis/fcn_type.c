// SPDX-FileCopyrightText: 2010-2021 nibble <nibble.ds@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 alvaro <alvaro.felipe91@gmail.com>
// SPDX-FileCopyrightText: 2010-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"

static int typecmp(const void *a, const void *b, void *user) {
	const RzType *t1 = a;
	const RzType *t2 = b;
	return !rz_types_equal(t1, t2);
}

/**
 * \brief Returns vector of all unique types used in a function
 *
 * Accounts for all types used in both arguments and variables, excluding return value type
 */
RZ_API RZ_OWN RzList /*<RzType *>*/ *rz_analysis_types_from_fcn(RzAnalysis *analysis, RzAnalysisFunction *fcn) {
	RzList *type_used = rz_list_new();
	void **it;
	rz_pvector_foreach (&fcn->vars, it) {
		RzAnalysisVar *var = *it;
		rz_list_append(type_used, var->type);
	}
	RzList *uniq = rz_list_uniq(type_used, typecmp, NULL);
	rz_list_free(type_used);
	return uniq;
}

/**
 * \brief Clones the RzCallable type for the given function
 *
 * Searches the types database for the given function and
 * returns a clone of the RzCallable type.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_clone_type(RzAnalysis *analysis, const RzAnalysisFunction *f) {
	rz_return_val_if_fail(analysis && f, NULL);
	// Check first if there is a match with some pre-existing RzCallable type in the database
	char *shortname = rz_analysis_function_name_guess(analysis->typedb, f->name);
	if (!shortname) {
		shortname = rz_str_dup(f->name);
	}
	// At this point the `callable` pointer is *borrowed*
	RzCallable *callable = rz_type_func_get(analysis->typedb, shortname);
	free(shortname);
	if (callable) {
		// TODO: Decide what to do if there is a mismatch between type
		// stored in the RzTypeDB database and the actual type of the
		// RzAnalysisFunction
		return rz_type_callable_clone(callable);
	}
	return NULL;
}

/**
 * \brief Creates the RzCallable type for the given function
 *
 * Creates the RzCallable type for the given function
 * by searching in the types database and returning it.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_create_type(RzAnalysis *analysis, RzAnalysisFunction *f) {
	// TODO: Figure out if we should use shortname or a fullname here
	RzCallable *callable = rz_type_func_new(analysis->typedb, f->name, NULL);
	if (!callable) {
		return NULL;
	}
	return callable;
}

/**
 * \brief Sets the RzCallable return type for the given function
 *
 * Checks if the given function's return type exists
 * and adds it to RzCallable by cloning it.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 * \param callable A function type
 */
RZ_API void rz_analysis_function_derive_return_type(RzAnalysisFunction *f, RzCallable **callable) {
	if (f->ret_type) {
		(*callable)->ret = rz_type_clone(f->ret_type);
	}
}

/**
 * \brief Sets the RzCallable args for the given function
 *
 * Gets the given function's arguments (names and types)
 * and if it has none it simply returns. Otherwise, it
 * creates RzCallableArgs and adds them to RzCallable.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 * \param callable A function type
 */
RZ_API bool rz_analysis_function_derive_args(RzAnalysis *analysis, RzAnalysisFunction *f, RzCallable **callable) {
	RzPVector *args = rz_analysis_function_args(analysis, f);
	if (!args || rz_pvector_empty(args)) {
		rz_pvector_free(args);
		return true;
	}
	void **it;
	rz_pvector_foreach (args, it) {
		RzAnalysisVar *var = *it;
		if (!var) {
			// TODO: maybe create a stub void arg here?
			continue;
		}
		RzType *cloned_type = rz_type_clone(var->type);
		if (!cloned_type) {
			rz_pvector_free(args);
			rz_type_callable_free(*callable);
			RZ_LOG_ERROR("Cannot parse function's argument type\n");
			return false;
		}
		RzCallableArg *arg = rz_type_callable_arg_new(analysis->typedb, var->name, cloned_type);
		if (!arg) {
			rz_pvector_free(args);
			rz_type_callable_free(*callable);
			RZ_LOG_ERROR("Cannot create callable argument\n");
			return false;
		}
		rz_type_callable_arg_add(*callable, arg);
	}
	rz_pvector_free(args);
	return true;
}

/**
 * \brief Derives the RzCallable type for the given function
 *
 * Checks if the type is defined already for this function, if yes -
 * it returns pointer to the one stored in the types database.
 * If not - it creates a new RzCallable instance based on the function name,
 * its arguments' names and types.
 *
 * \param analysis RzAnalysis instance
 * \param f Function to update
 */
RZ_API RZ_OWN RzCallable *rz_analysis_function_derive_type(RzAnalysis *analysis, RzAnalysisFunction *f) {
	RzCallable *callable = rz_analysis_function_clone_type(analysis, f);
	if (!callable) {
		// If there is no match - create a new one.
		callable = rz_analysis_function_create_type(analysis, f);
		if (!callable) {
			return NULL;
		}
		// Derive retvar and args from that function
		rz_analysis_function_derive_return_type(f, &callable);
		if (!rz_analysis_function_derive_args(analysis, f, &callable)) {
			return NULL;
		}
	}
	return callable;
}
