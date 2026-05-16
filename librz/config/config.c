// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "config_internal.h"

#define config_var_assert_return(expr, name, val) \
	do { \
		if (RZ_UNLIKELY(!(expr))) { \
			RZ_LOG_WARN("%s: assertion '%s' failed (line %d); variable %s\n", RZ_FUNCTION, #expr, __LINE__, name); \
			return (val); \
		} \
	} while (0)

static void config_var_fini(RzConfigVar *var) {
	if (!var) {
		return;
	}

	free(var->name);
	free(var->desc);
	rz_list_free(var->options);
	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		// if is bind, we do not own the value.
		return;
	}

	if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_STR)) {
		free(var->value.string);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST)) {
		rz_list_free(var->value.list);
	}
}

static void config_entry_fini(RzConfigEntry *entry) {
	if (!entry) {
		return;
	}
	if (!entry->is_variable) {
		rz_config_node_fini(&entry->node);
	} else {
		config_var_fini(&entry->var);
	}
}

static inline bool config_var_is_bind_without_set(const RzConfigVar *var) {
	return var->flags & RZ_CONFIG_VAR_FLAG_BIND && !var->bind.set_value;
}

static inline bool config_var_set_readonly(RzConfigVar *var, bool read_only) {
	if (config_var_is_bind_without_set(var) && !read_only) {
		// if set_value is not set is always considered RO
		RZ_LOG_ERROR("config: cannot unset '%s' as is an hardcoded read-only variable\n", var->name);
		return false;
	} else if (read_only) {
		ut32 flags = ~RZ_CONFIG_VAR_FLAG_WRITABLE;
		var->flags &= flags;
	} else {
		var->flags |= RZ_CONFIG_VAR_FLAG_WRITABLE;
	}

	return true;
}

static bool config_var_args_to_list(va_list argp, RzList /*<char *>*/ *list) {
	const char *value = va_arg(argp, const char *);
	while (value) {
		char *copy = rz_str_dup(value);
		if (!copy || !rz_list_append(list, copy)) {
			free(copy);
			return false;
		}
		value = va_arg(argp, const char *);
	}
	return true;
}

RZ_IPI RZ_OWN RzList /*<char *>*/ *rz_config_dup_list(RZ_NULLABLE const RzList /*<const char *>*/ *list) {
	RzListIter *it;
	const char *elem;
	RzList *safe_list = rz_list_newf(free);
	if (!safe_list) {
		return NULL;
	}
	rz_list_foreach (list, it, elem) {
		rz_list_append(safe_list, rz_str_dup(elem));
	}
	return safe_list;
}

/**
 * \brief      Allocates and initialize a new RzConfig
 *
 * \param      user  Pointer to the user data (not owned & deprecated)
 *
 * \return     On success returns a valid pointer, otherwise NULL
 */
RZ_API RZ_OWN RzConfig *rz_config_new(RZ_DEPRECATE RZ_BORROW void *user) {
	RzConfig *cfg = RZ_NEW0(RzConfig);
	if (!cfg) {
		return NULL;
	}
	rz_vector_init(&cfg->sorted_vars, sizeof(RzConfigEntry), (RzVectorFree)config_entry_fini, NULL);
	// DEPRECATED
	cfg->user = user;
	return cfg;
}

/**
 * \brief      Frees RzConfig structure
 *
 * \param      cfg   The RzConfig to be freed
 */
RZ_API void rz_config_free(RZ_NULLABLE RzConfig *cfg) {
	if (!cfg) {
		return;
	}

	rz_vector_fini(&cfg->sorted_vars);
	free(cfg);
}

/**
 * \brief      Sets a given variable to readonly or writable mode.
 *
 * \param      cfg        The RzConfig to modify
 * \param      name       The name of the variable to set as RO/RW
 * \param[in]  read_only  When true sets the variable to readonly mode otherwise allows writing.
 *
 * \return     Returns true if the key is readonly, otherwise false.
 */
RZ_API bool rz_config_set_readonly(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, bool read_only) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}

	if (!entry->is_variable) {
		return rz_config_node_set_readonly(&entry->node, read_only);
	}

	return config_var_set_readonly(&entry->var, read_only);
}

/**
 * \brief      Returns boolean describing if a given variable is readonly or not.
 *
 * \param      cfg   The configuration
 * \param[in]  name  The name
 *
 * \return     When true, the queried variable is readonly.
 */
RZ_API bool rz_config_is_readonly(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}

	if (!entry->is_variable) {
		return rz_config_node_is_ro(&entry->node);
	}

	return rz_config_var_is_readonly(&entry->var);
}

/**
 * \brief      Iterates over all the variables set in a give RzConfig struct
 *
 * \param[in]  cfg       The configuration to iterate over.
 * \param[in]  iterator  The iterator to call.
 * \param      user      The user pointer passed to the iterator
 */
RZ_API void rz_config_iterate_over(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL RzConfigIterator iterator, RZ_NULLABLE void *user) {
	rz_return_if_fail(cfg && iterator);

	const RzConfigEntry *entry = NULL;
	rz_vector_foreach (&cfg->sorted_vars, entry) {
		if (!iterator(entry, user)) {
			return;
		}
	}
}

static inline bool config_init_var_bool(RzConfigVar *var, const char *name, const char *desc, bool value) {
	var->name = rz_str_dup(name);
	if (!name) {
		return false;
	}
	var->desc = rz_str_dup(desc);
	var->flags = RZ_CONFIG_VAR_FLAG_WRITABLE | RZ_CONFIG_VAR_TYPE_BOOL;
	var->value.boolean = value;
	return true;
}

static inline bool config_init_var_integer(RzConfigVar *var, const char *name, const char *desc, ut64 value) {
	var->name = rz_str_dup(name);
	if (!name) {
		return false;
	}
	var->desc = rz_str_dup(desc);
	var->flags = RZ_CONFIG_VAR_FLAG_WRITABLE | RZ_CONFIG_VAR_TYPE_INT;
	var->value.integer = value;
	return true;
}

static inline bool config_init_var_string(RzConfigVar *var, const char *name, const char *desc, RZ_NULLABLE const char *value) {
	var->name = rz_str_dup(name);
	var->value.string = rz_str_dup(value);
	if (!var->name) {
		return false;
	}
	var->desc = rz_str_dup(desc);
	var->flags = RZ_CONFIG_VAR_FLAG_WRITABLE | RZ_CONFIG_VAR_TYPE_STR;
	if (!var->value.string && value) {
		return false;
	}
	return true;
}

static inline bool config_init_var_list(RzConfigVar *var, const char *name, const char *desc, RZ_OWN RzList /*<char *>*/ *value) {
	var->name = rz_str_dup(name);
	var->value.list = value;
	if (!var->name || !var->value.list) {
		return false;
	}
	var->desc = rz_str_dup(desc);
	var->flags = RZ_CONFIG_VAR_FLAG_WRITABLE | RZ_CONFIG_VAR_TYPE_LIST;
	return true;
}

static inline bool config_init_var_itv(RzConfigVar *var, const char *name, const char *desc, ut64 from, ut64 to) {
	if (from > to) {
		RZ_LOG_ERROR("config: cannot add '%s' when from > to (0x%08" PFMT64x " > 0x%08" PFMT64x ").\n", name, from, to);
		return false;
	}
	var->name = rz_str_dup(name);
	if (!name) {
		return false;
	}
	var->desc = rz_str_dup(desc);
	var->flags = RZ_CONFIG_VAR_FLAG_WRITABLE | RZ_CONFIG_VAR_TYPE_ITV;
	var->value.interval.addr = from;
	var->value.interval.size = to - from;
	return true;
}

static inline bool config_var_bind_set_options(RzConfigVar *var) {
	if (!var->bind.get_options) {
		return true;
	}

	RzList *options = NULL;
	if (!var->bind.get_options(var->bind.user, &options)) {
		return false;
	}
	rz_list_free(var->options);
	var->options = options;
	return true;
}

static inline bool config_init_var_bind(RzConfigVar *var, const char *name, const char *desc, ut32 flags, RzConfigBindGet get, RzConfigBindSet set, RzConfigBindOpts opts, void *user) {
	var->name = rz_str_dup(name);
	if (!var->name) {
		return false;
	}
	var->desc = rz_str_dup(desc);
	var->flags = RZ_CONFIG_VAR_FLAG_WRITABLE | RZ_CONFIG_VAR_FLAG_BIND | flags;
	var->bind.user = user;
	var->bind.get_value = get;
	var->bind.set_value = set;
	var->bind.get_options = opts;
	return config_var_bind_set_options(var);
}

/**
 * \brief      Adds a boolean variable if doesn't exists.
 *
 * \param      cfg    The configuration where to add the variable
 * \param[in]  name   The name of the variable to add
 * \param[in]  desc   The description of the variable (optional)
 * \param[in]  value  The value to set this variable to
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_bool(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, bool value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	} else if (!config_init_var_bool(&new_entry.var, name, desc, value)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Adds an unsigned integer variable if doesn't exists.
 *
 * \param      cfg    The configuration where to add the variable
 * \param[in]  name   The name of the variable to add
 * \param[in]  desc   The description of the variable (optional)
 * \param[in]  value  The value to set this variable to
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_integer(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ut64 value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	} else if (!config_init_var_integer(&new_entry.var, name, desc, value)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Adds a string variable if doesn't exists.
 *
 * \param      cfg    The configuration where to add the variable
 * \param[in]  name   The name of the variable to add
 * \param[in]  desc   The description of the variable (optional)
 * \param[in]  value  The value to set this variable to
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_string(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, RZ_NULLABLE const char *value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	} else if (!config_init_var_string(&new_entry.var, name, desc, value)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Adds a string variable which accepts only one of specified options
 *
 * \param      cfg    The configuration where to add the variable
 * \param[in]  name   The name of the variable to add
 * \param[in]  desc   The description of the variable (optional)
 * \param[in]  ...    The options to set for this variable (the first option is the default value, terminated by NULL)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_options(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ...) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	}

	va_list argp;
	RzList *list = rz_list_newf(free);
	if (!list) {
		RZ_LOG_ERROR("config: failed to initialize options list for '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	va_start(argp, desc);
	bool ok = config_var_args_to_list(argp, list);
	va_end(argp);
	if (!ok) {
		RZ_LOG_ERROR("config: failed to initialize options list for '%s'.\n", name);
		rz_list_free(list);
		config_var_fini(&new_entry.var);
		return false;
	}

	const char *first = rz_list_first_val(list);
	if (!config_init_var_string(&new_entry.var, name, desc, first)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}
	new_entry.var.options = list;

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Adds a list variable if doesn't exists.
 *
 * \param      cfg    The configuration where to add the variable
 * \param[in]  name   The name of the variable to add
 * \param[in]  desc   The description of the variable (optional)
 * \param[in]  ...    The values to set this variable to (terminated by a NULL)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_list(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ...) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	}

	va_list argp;
	RzList *list = rz_list_newf(free);
	if (!list) {
		return false;
	}

	va_start(argp, desc);
	bool ok = config_var_args_to_list(argp, list);
	va_end(argp);
	if (!ok) {
		rz_list_free(list);
		return false;
	} else if (!config_init_var_list(&new_entry.var, name, desc, list)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Adds a interval variable if doesn't exists.
 *
 * \param      cfg    The configuration where to add the variable
 * \param[in]  name   The name of the variable to add
 * \param[in]  desc   The description of the variable (optional)
 * \param[in]  from   The begin value to set (inclusive, and must be less or equal than "to")
 * \param[in]  to     The end value to set (inclusive, and must be greater or equal than "from")
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_interval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ut64 from, ut64 to) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	} else if (!config_init_var_itv(&new_entry.var, name, desc, from, to)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Adds a string variable (not owned by RzConfig) bound to an external struct, if doesn't exists.
 *
 * \param      cfg   The configuration where to add the variable
 * \param[in]  name  The name of the variable to add
 * \param[in]  desc  The description of the variable (optional)
 * \param[in]  type  The type of the variable (see RzConfigVarFlags)
 * \param[in]  get   The callback used to get the value
 * \param[in]  set   The callback used to set the value
 * \param[in]  opts  The callback used to get the options value (optional)
 * \param[in]  user  The pointer to a user set variable (not owned by RzConfig)
 *
 * \return     On success returns true, otherwise false
 */
RZ_API bool rz_config_add_bind(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *desc, ut32 type, RZ_NONNULL RzConfigBindGet get, RZ_NULLABLE RzConfigBindSet set, RZ_NULLABLE RzConfigBindOpts opts, RZ_NULLABLE void *user) {
	type &= RZ_CONFIG_VAR_TYPE_MASK;
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name) && get && type > 0, false);

	RzConfigEntry new_entry = { 0 };
	if (config_find_entry(cfg, name)) {
		RZ_LOG_ERROR("config: variable '%s' already exists.\n", name);
		return false;
	} else if (!config_init_var_bind(&new_entry.var, name, desc, type, get, set, opts, user)) {
		RZ_LOG_ERROR("config: failed to initialize '%s'.\n", name);
		config_var_fini(&new_entry.var);
		return false;
	}

	config_add_entry(cfg, name, &new_entry, true);
	return true;
}

/**
 * \brief      Converts a given RzConfigVar to json.
 *
 * \param[in]  var   The variable
 * \param      pj    PJ structure to write to
 * \param[in]  key   The key name to assign to the value
 *
 * \return     On success returns true, otherwise false.
 */
RZ_API bool rz_config_var_as_json(RZ_NONNULL const RzConfigVar *var, RZ_NONNULL PJ *pj, RZ_NONNULL const char *key) {
	rz_return_val_if_fail(var && pj && key, false);

	if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_BOOL)) {
		pj_kb(pj, key, rz_config_var_get_bool(var));
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_INT)) {
		pj_kn(pj, key, rz_config_var_get_integer(var));
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_STR)) {
		pj_ks(pj, key, rz_config_var_get_string(var));
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_LIST)) {
		const char *value;
		RzListIter *it;
		RzList *list = rz_config_var_get_list(var);
		pj_ka(pj, key);
		rz_list_foreach (list, it, value) {
			pj_s(pj, value);
		}
		pj_end(pj);
		rz_list_free(list);
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_ITV)) {
		RzInterval itv = rz_config_var_get_interval(var);
		pj_ko(pj, key);
		pj_kn(pj, "addr", rz_itv_begin(itv));
		pj_kn(pj, "size", rz_itv_size(itv));
		pj_end(pj);
	}
	return true;
}

/**
 * \brief      Returns an owned string that describes the variable value
 *
 * \param[in]  var   The RzConfigVar to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_config_var_as_string(RZ_NONNULL const RzConfigVar *var) {
	rz_return_val_if_fail(var, NULL);

	if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_BOOL)) {
		bool b = rz_config_var_get_bool(var);
		return rz_str_dup(rz_str_bool(b));
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_INT)) {
		ut64 i64 = rz_config_var_get_integer(var);
		return rz_str_newf("%" PFMT64u, i64);
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_STR)) {
		const char *str = rz_config_var_get_string(var);
		return rz_str_dup(str);
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_LIST)) {
		RzList *list = rz_config_var_get_list(var);
		char *value = rz_list_to_str(list, ',', false);
		rz_list_free(list);
		return value;
	} else if (rz_config_var_has_type(var, RZ_CONFIG_VAR_TYPE_ITV)) {
		RzInterval itv = rz_config_var_get_interval(var);
		return rz_str_newf("0x%08" PFMT64x ",0x%08" PFMT64x, rz_itv_begin(itv), rz_itv_end(itv));
	}
	return NULL;
}

/**
 * \brief      Returns boolean describing if a given variable is readonly or not.
 *
 * \param      var   The RzConfigVar to use
 *
 * \return     When true, the variable is readonly.
 */
RZ_API bool rz_config_var_is_readonly(RZ_NONNULL const RzConfigVar *var) {
	rz_return_val_if_fail(var, false);
	if (config_var_is_bind_without_set(var)) {
		// if set_value is not set is always considered RO
		return true;
	}
	return !RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_WRITABLE);
}

static inline bool config_var_bind_get_value(const RzConfigVar *var, void *value) {
	return var->bind.get_value(var->bind.user, value);
}

static inline bool config_var_bind_set_value(const RzConfigVar *var, const void *value) {
	return var->bind.set_value(var->bind.user, value);
}

/**
 * \brief      Returns the boolean held by the RzConfigVar (must be a boolean type)
 *
 * \param[in]  var   The RzConfigVar to use
 *
 * \return     Returns the value held by the RzConfigVar
 */
RZ_API bool rz_config_var_get_bool(RZ_NONNULL const RzConfigVar *var) {
	config_var_assert_return(var && RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_BOOL), var ? var->name : "(null)", false);

	if (!(RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND))) {
		return var->value.boolean;
	}

	bool value = false;
	if (!config_var_bind_get_value(var, &value)) {
		return false;
	}
	return value;
}

/**
 * \brief      Returns the unsigned integer held by the RzConfigVar (must be an integer type)
 *
 * \param[in]  var   The RzConfigVar to use
 *
 * \return     Returns the value held by the RzConfigVar
 */
RZ_API ut64 rz_config_var_get_integer(RZ_NONNULL const RzConfigVar *var) {
	config_var_assert_return(var && RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_INT), var ? var->name : "(null)", 0);

	if (!(RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND))) {
		return var->value.integer;
	}

	ut64 value = 0;
	if (!config_var_bind_get_value(var, &value)) {
		return 0;
	}
	return value;
}

/**
 * \brief      Returns the string held by the RzConfigVar (must be a string type)
 *
 * \param[in]  var   The RzConfigVar to use
 *
 * \return     Returns the value held by the RzConfigVar
 */
RZ_API const char *rz_config_var_get_string(RZ_NONNULL const RzConfigVar *var) {
	config_var_assert_return(var && RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_STR), var ? var->name : "(null)", NULL);

	if (!(RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND))) {
		return rz_str_get(var->value.string);
	}

	const char *value = NULL;
	if (!config_var_bind_get_value(var, &value) || !value) {
		return "";
	}
	return value;
}

/**
 * \brief      Returns the list held by the RzConfigVar (must be a list type)
 *
 * \param[in]  var   The RzConfigVar to use
 *
 * \return     Returns the value held by the RzConfigVar
 */
RZ_API RZ_OWN RzList /*<const char *>*/ *rz_config_var_get_list(RZ_NONNULL const RzConfigVar *var) {
	config_var_assert_return(var && RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST), var ? var->name : "(null)", false);

	if (!(RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND))) {
		return rz_list_clone(var->value.list);
	}

	RzList /*<char *>*/ *value = NULL;
	if (!config_var_bind_get_value(var, &value) || !value) {
		return rz_list_new();
	}
	return value;
}

/**
 * \brief      Returns the interval held by the RzConfigVar (must be a interval type)
 *
 * \param[in]  var   The RzConfigVar to use
 *
 * \return     Returns the value held by the RzConfigVar
 */
RZ_API RzInterval rz_config_var_get_interval(RZ_NONNULL const RzConfigVar *var) {
	RzInterval value = { 0 };
	config_var_assert_return(var && RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_ITV), var ? var->name : "(null)", value);

	if (!(RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND))) {
		return var->value.interval;
	}

	if (!config_var_bind_get_value(var, &value)) {
		memset(&value, 0, sizeof(value));
		return value;
	}
	return value;
}

/**
 * \brief      Checks if the expected type matches the one set in the RzConfigVar struct
 *
 * \param[in]  var    The variable to check
 * \param[in]  etype  The type to expect
 *
 * \return     Returns true if the expected type matches the one set in the RzConfigVar struct
 */
RZ_API bool rz_config_var_has_type(RZ_NONNULL const RzConfigVar *var, ut32 etype) {
	rz_return_val_if_fail(var, false);
	return RZ_CONFIG_VAR_IS_TYPE(var->flags, etype);
}

/**
 * \brief      Checks if the expected flags are set in the RzConfigVar struct
 *
 * \param[in]  var     The variable to check
 * \param[in]  eflags  The flags to expect
 *
 * \return     Returns true if the expected flags are set in the RzConfigVar struct
 */
RZ_API bool rz_config_var_has_flags(RZ_NONNULL const RzConfigVar *var, ut32 eflags) {
	rz_return_val_if_fail(var, false);
	return RZ_CONFIG_VAR_HAS_FLAG(var->flags, eflags) == eflags;
}

/**
 * \brief      Returns the encoded flags and type set in RzConfigVar (see RzConfigVarFlags)
 *
 * \param[in]  RzConfigVar  The RzConfigVar to use
 *
 * \return     The variable encoded flags and type
 */
RZ_API ut32 rz_config_var_get_flags(RZ_NONNULL const RzConfigVar *var) {
	rz_return_val_if_fail(var, 0);
	return var->flags;
}

/**
 * \brief      Returns the name set in RzConfigVar
 *
 * \param[in]  RzConfigVar  The RzConfigVar to use
 *
 * \return     The variable name (guaranteed to be always non NULL)
 */
RZ_API const char *rz_config_var_get_name(RZ_NONNULL const RzConfigVar *var) {
	rz_return_val_if_fail(var, "");
	return rz_str_get(var->name);
}

/**
 * \brief      Returns the description set in RzConfigVar
 *
 * \param[in]  RzConfigVar  The RzConfigVar to use
 *
 * \return     The variable description (guaranteed to be always non NULL)
 */
RZ_API const char *rz_config_var_get_desc(RZ_NONNULL const RzConfigVar *var) {
	rz_return_val_if_fail(var, "");
	return rz_str_get(var->desc);
}

/**
 * \brief      Returns the options if set in the RzConfigVar struct
 *
 * \param[in]  RzConfigVar  The RzConfigVar to use
 *
 * \return     The options (can be NULL)
 */
RZ_API const RzList /*<char *>*/ *rz_config_var_get_options(RZ_NONNULL const RzConfigVar *var) {
	rz_return_val_if_fail(var, NULL);
	return var->options;
}

/**
 * \brief      Converts a given encoded to string (see RzConfigVarFlags)
 *
 * \param[in]  flags  The flags to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_config_var_flags_as_string(ut32 flags) {
	RzStrBuf sb;
	rz_strbuf_init(&sb);

	ut32 types = flags & RZ_CONFIG_VAR_TYPE_MASK;
	flags &= RZ_CONFIG_VAR_FLAGS_MASK;

	switch (types) {
	case RZ_CONFIG_VAR_TYPE_BOOL:
		rz_strbuf_append(&sb, "bool");
		break;
	case RZ_CONFIG_VAR_TYPE_INT:
		rz_strbuf_append(&sb, "integer");
		break;
	case RZ_CONFIG_VAR_TYPE_STR:
		rz_strbuf_append(&sb, "string");
		break;
	case RZ_CONFIG_VAR_TYPE_LIST:
		rz_strbuf_append(&sb, "list");
		break;
	case RZ_CONFIG_VAR_TYPE_ITV:
		rz_strbuf_append(&sb, "interval");
		break;
	default:
		rz_strbuf_appendf(&sb, "type_%u", types);
		break;
	}

	if (flags & RZ_CONFIG_VAR_FLAG_BIND) {
		if (rz_strbuf_length(&sb) > 0) {
			rz_strbuf_append(&sb, ",");
		}
		rz_strbuf_append(&sb, "bind");
	}
	if (!(flags & RZ_CONFIG_VAR_FLAG_WRITABLE)) {
		if (rz_strbuf_length(&sb) > 0) {
			rz_strbuf_append(&sb, ",");
		}
		rz_strbuf_append(&sb, "readonly");
	}

	return rz_strbuf_drain_nofree(&sb);
}

static bool config_var_is_valid_value(const RzConfigVar *var, const void *value) {
	if (!var->value.validator) {
		return true;
	}
	return var->value.validator(var->value.validator_user, value);
}

RZ_IPI bool rz_config_var_set_bool(RzConfigVar *var, bool value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_BOOL), var->name, false);
	if (rz_config_var_is_readonly(var)) {
		RZ_LOG_ERROR("config: '%s' is a read only variable\n", var->name);
		return false;
	}

	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		return config_var_bind_set_value(var, &value);
	} else if (!config_var_is_valid_value(var, &value)) {
		return false;
	}
	var->value.boolean = value;
	return true;
}

RZ_IPI bool rz_config_var_set_integer(RzConfigVar *var, ut64 value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_INT), var->name, false);
	if (rz_config_var_is_readonly(var)) {
		RZ_LOG_ERROR("config: '%s' is a read only variable\n", var->name);
		return false;
	}

	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		return config_var_bind_set_value(var, &value);
	} else if (!config_var_is_valid_value(var, &value)) {
		return false;
	}
	var->value.integer = value;
	return true;
}

static bool config_var_has_option(RzConfigVar *var, const char *value) {
	if (rz_list_length(var->options) < 1) {
		// there are no options so the value is always valid.
		return true;
	}
	// we consider NULL as "" (empty string)
	value = rz_str_get(value);

	const char *opt;
	RzListIter *it;
	rz_list_foreach (var->options, it, opt) {
		if (RZ_STR_EQ(opt, value)) {
			return true;
		}
	}
	return false;
}

RZ_IPI bool rz_config_var_set_string(RzConfigVar *var, const char *value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_STR), var->name, false);
	if (rz_config_var_is_readonly(var)) {
		RZ_LOG_ERROR("config: '%s' is a read only variable\n", var->name);
		return false;
	} else if (!config_var_has_option(var, value)) {
		value = rz_str_get(value);
		RZ_LOG_ERROR("config: '%s' does not support option '%s'\n", var->name, value);
		return false;
	}

	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		return config_var_bind_set_value(var, value);
	} else if (!config_var_is_valid_value(var, value)) {
		return false;
	}
	free(var->value.string);
	var->value.string = rz_str_dup(value);
	return true;
}

RZ_IPI bool rz_config_var_set_list(RzConfigVar *var, const RzList /*<const char *>*/ *value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST), var->name, false);
	if (rz_config_var_is_readonly(var)) {
		RZ_LOG_ERROR("config: '%s' is a read only variable\n", var->name);
		return false;
	}

	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		return config_var_bind_set_value(var, value);
	} else if (!config_var_is_valid_value(var, value)) {
		return false;
	}

	rz_list_free(var->value.list);
	var->value.list = rz_config_dup_list(value);
	return true;
}

RZ_IPI bool rz_config_var_set_list2(RzConfigVar *var, RZ_OWN RzList /*<char *>*/ *value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST), var->name, false);
	if (rz_config_var_is_readonly(var)) {
		RZ_LOG_ERROR("config: '%s' is a read only variable\n", var->name);
		return false;
	}

	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		bool ret = config_var_bind_set_value(var, value);
		rz_list_free(value);
		return ret;
	} else if (!config_var_is_valid_value(var, value)) {
		rz_list_free(value);
		return false;
	}

	rz_list_free(var->value.list);
	var->value.list = value;
	return true;
}

RZ_IPI bool rz_config_var_set_interval(RzConfigVar *var, RzInterval value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_ITV), var->name, false);
	if (rz_config_var_is_readonly(var)) {
		RZ_LOG_ERROR("config: '%s' is a read only variable\n", var->name);
		return false;
	}

	if (RZ_CONFIG_VAR_HAS_FLAG(var->flags, RZ_CONFIG_VAR_FLAG_BIND)) {
		return config_var_bind_set_value(var, &value);
	} else if (!config_var_is_valid_value(var, &value)) {
		return false;
	}

	var->value.interval = value;
	return true;
}

static bool config_set_var_list_from_string(RzConfigVar *var, const char *value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST), var->name, false);
	RzList *list = NULL;
	if (value) {
		list = rz_str_split_duplist(value, ",", true);
	} else {
		list = rz_list_new();
	}

	return rz_config_var_set_list2(var, list);
}

static bool config_set_var_interval_from_string(RzConfigVar *var, const char *value) {
	config_var_assert_return(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_ITV), var->name, false);

	RzInterval itv = { 0 };
	RzList *list = rz_str_split_duplist(value, ",", true);
	if (rz_list_length(list) == 2) {
		ut64 from = rz_num_get(NULL, rz_list_first_val(list));
		ut64 to = rz_num_get(NULL, rz_list_last_val(list));
		if (to < from) {
			RZ_LOG_ERROR("config: cannot set '%s' when from > to (0x%08" PFMT64x " > 0x%08" PFMT64x ").\n", var->name, from, to);
			rz_list_free(list);
			return false;
		}
		itv.addr = from;
		itv.size = to - from;
	}
	rz_list_free(list);
	return rz_config_var_set_interval(var, itv);
}

RZ_IPI bool rz_config_var_set_any(RzConfigVar *var, const char *value) {
	if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_BOOL)) {
		bool bvalue = value ? rz_str_is_true(value) : false;
		return rz_config_var_set_bool(var, bvalue);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_INT)) {
		ut64 ivalue = value ? rz_num_get(NULL, value) : 0;
		return rz_config_var_set_integer(var, ivalue);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_STR)) {
		return rz_config_var_set_string(var, value);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST)) {
		return config_set_var_list_from_string(var, value);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_ITV)) {
		return config_set_var_interval_from_string(var, value);
	}
	return false;
}

RZ_IPI bool rz_config_toggle_var_bool(RzConfigVar *var) {
	if (!(RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_BOOL))) {
		RZ_LOG_ERROR("config: variable '%s' is not a boolean.\n", var->name);
		return false;
	}

	bool bvalue = rz_config_var_get_bool(var);
	return rz_config_var_set_bool(var, !bvalue);
}

/**
 * \brief      Inverts the value of a held boolean variable (if was true, becomes false, or viceversa)
 *
 * \param      cfg   The configuration to use
 * \param[in]  name  The name of the boolean variable to invert
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_toggle_bool(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name) {
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}

	return rz_config_toggle_var_bool(&entry->var);
}

/**
 * \brief      Sets the value of a given string variable (must be string type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  value  The value to set
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_string(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		rz_config_set(cfg, name, value);
		return true;
	}

	return rz_config_var_set_string(&entry->var, value);
}

/**
 * \brief      Sets the value of a given unsigned integer variable (must be integer type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  value  The value to set
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_integer(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ut64 value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		rz_config_set_i(cfg, name, value);
		return true;
	}

	return rz_config_var_set_integer(&entry->var, value);
}

/**
 * \brief      Sets the value of a given boolean variable (must be boolean type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  value  The value to set
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_bool(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, bool value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		rz_config_set_b(cfg, name, value);
		return true;
	}

	return rz_config_var_set_bool(&entry->var, value);
}

/**
 * \brief      Sets the value of a given list variable (must be list type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  value  The value to set
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_list(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const RzList /*<const char *>*/ *value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		return false;
	}

	return rz_config_var_set_list(&entry->var, value);
}

/**
 * \brief      Sets the value of a given list variable (must be list type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  ...    The list of values to set (terminated by a NULL)
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_list2(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ...) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		return false;
	}

	va_list argp;
	RzList *list = rz_list_newf(free);
	if (!list) {
		return false;
	}

	va_start(argp, name);
	bool ok = config_var_args_to_list(argp, list);
	va_end(argp);
	if (!ok) {
		RZ_LOG_ERROR("config: failed to initialize list for '%s'.\n", name);
		rz_list_free(list);
		return false;
	}

	return rz_config_var_set_list2(&entry->var, list);
}

/**
 * \brief      Sets the value of a given list variable (must be list type)
 *
 * \param      cfg         The configuration to use
 * \param[in]  name        The name of the variable to change
 * \param[in]  comma_list  The value to set as comma separated (example: `a,b,c,d`)
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_list3(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *comma_list) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		return false;
	}

	return config_set_var_list_from_string(&entry->var, comma_list);
}

/**
 * \brief      Sets the value of a given interval variable (must be interval type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  value  The value to set
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_interval(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RzInterval value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		return false;
	}

	return rz_config_var_set_interval(&entry->var, value);
}

/**
 * \brief      Sets the value of a given interval variable (must be interval type)
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  from   The begin value to set (inclusive, and must be less or equal than "to")
 * \param[in]  to     The end value to set (inclusive, and must be greater or equal than "from")
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_interval2(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ut64 from, ut64 to) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		return false;
	}
	if (to < from) {
		RZ_LOG_ERROR("config: cannot set '%s' when from > to (0x%08" PFMT64x " > 0x%08" PFMT64x ").\n", name, from, to);
		return false;
	}

	RzInterval value = { .addr = from, .size = to - from };
	return rz_config_var_set_interval(&entry->var, value);
}

/**
 * \brief      Sets the value of a given interval variable (must be interval type)
 *
 * \param      cfg        The configuration to use
 * \param[in]  name       The name of the variable to change
 * \param[in]  comma_itv  The value to set as comma separated (example: `0x1000,0x5fff`, `<from>,<to>` are inclusive and from <= to)
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_interval3(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *comma_itv) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}
	if (!entry->is_variable) {
		return false;
	}

	return config_set_var_interval_from_string(&entry->var, comma_itv);
}

/**
 * \brief      Sets the value of a given variable (the string value is converted based on the variable type)
 *
 * 	When type is:
 * 	- bool, the value `true` is set if `rz_str_is_true` returns true, otherwise is false (on NULL is set to false).
 * 	- integer, the value is parsed via RzNum (on NULL is set to 0)
 * 	- string, the value is kept as is (on NULL is set to "")
 * 	- list, the expected value is a comma separated list like `a,b,c` (on NULL is set to empty list)
 * 	- interval, the expected value is a comma separated range (inclusive) like `from,to` where from <= to (on NULL is set to [0,0])
 *
 * \param      cfg    The configuration to use
 * \param[in]  name   The name of the variable to change
 * \param[in]  value  The value to convert before being set in the variable (can be NULL)
 *
 * \return     On success return true, otherwise false
 */
RZ_API bool rz_config_set_any(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE const char *value) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}

	if (!entry->is_variable) {
		return rz_config_set(cfg, name, value) != NULL;
	}

	return rz_config_var_set_any(&entry->var, value);
}

/**
 * \brief      Returns the boolean held by the RzConfig (must be a boolean type)
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the boolean variable
 *
 * \return     Returns the value held by the RzConfig
 */
RZ_API bool rz_config_get_bool(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);

	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}

	if (!entry->is_variable) {
		return rz_config_get_b((RzConfig *)cfg, name);
	}

	return rz_config_var_get_bool(&entry->var);
}

/**
 * \brief      Returns the unsigned integer held by the RzConfig (must be a integer type)
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the integer variable
 *
 * \return     Returns the value held by the RzConfig
 */
RZ_API ut64 rz_config_get_integer(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), 0);

	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return 0;
	}

	if (!entry->is_variable) {
		return rz_config_get_i((RzConfig *)cfg, name);
	}

	return rz_config_var_get_integer(&entry->var);
}

/**
 * \brief      Returns the string held by the RzConfig (must be a string type)
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the string variable
 *
 * \return     Returns the value held by the RzConfig
 */
RZ_API const char *rz_config_get_string(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return NULL;
	}

	if (!entry->is_variable) {
		return rz_config_get((RzConfig *)cfg, name);
	}

	return rz_config_var_get_string(&entry->var);
}

/**
 * \brief      Returns the list held by the RzConfig (must be a list type)
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the list variable
 *
 * \return     Returns the value held by the RzConfig
 */
RZ_API RZ_OWN RzList /*<const char *>*/ *rz_config_get_list(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);

	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return NULL;
	}

	if (!entry->is_variable) {
		rz_warn_if_reached();
		return NULL;
	}

	return rz_config_var_get_list(&entry->var);
}

/**
 * \brief      Returns the interval held by the RzConfig (must be a interval type)
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the interval variable
 *
 * \return     Returns the value held by the RzConfig
 */
RZ_API RzInterval rz_config_get_interval(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	RzInterval zero = { 0 };
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), zero);

	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return zero;
	}

	if (!entry->is_variable) {
		rz_warn_if_reached();
		return zero;
	}

	return rz_config_var_get_interval(&entry->var);
}

/**
 * \brief      Returns an owned string that describes the queried variable value
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the variable to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_config_get_as_string(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);
	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return NULL;
	}

	if (entry->is_variable) {
		return rz_config_var_as_string(&entry->var);
	}

	const char *value = entry->node.value;
	if (rz_config_node_is_bool(&entry->node)) {
		bool b = rz_str_is_true(value);
		value = rz_str_bool(b);
	}
	return rz_str_dup(value);
}

/**
 * \brief      Returns the options held by the queried variable value
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the variable to stringify
 *
 * \return     On success returns a pointer, can be NULL.
 */
RZ_API const RzList /*<char *>*/ *rz_config_get_options(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), NULL);
	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return NULL;
	}

	if (entry->is_variable) {
		return rz_config_var_get_options(&entry->var);
	}
	return entry->node.options;
}

static ut32 config_entry_get_flags(const RzConfigEntry *entry) {
	if (entry->is_variable) {
		return rz_config_var_get_flags(&entry->var);
	}
	return rz_config_node_get_var_flags(&entry->node);
}

/**
 * \brief      Returns the encoded flags and type of the queried variable value (see RzConfigVarFlags)
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the variable to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API ut32 rz_config_get_flags(RZ_NONNULL const RzConfig *cfg, RZ_NONNULL const char *name) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), 0);
	const RzConfigEntry *entry = config_find_entry_ro(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return 0;
	}

	if (entry->is_variable) {
		return rz_config_var_get_flags(&entry->var);
	}
	return rz_config_node_get_var_flags(&entry->node);
}

static bool config_entry_set_options(RzConfigEntry *entry, RZ_NULLABLE RZ_OWN RzList /*<char *>*/ *options) {
	ut32 flags = config_entry_get_flags(entry);
	if (!(RZ_CONFIG_VAR_IS_TYPE(flags, RZ_CONFIG_VAR_TYPE_STR))) {
		const char *name = rz_config_entry_get_name(entry);
		RZ_LOG_ERROR("config: variable '%s' is not a string.\n", name);
		rz_list_free(options);
		return false;
	}

	if (entry->is_variable) {
		rz_list_free(entry->var.options);
		entry->var.options = options;
	} else {
		rz_list_free(entry->node.options);
		entry->node.options = options;
	}

	return true;
}

/**
 * \brief      Sets the options held by the string type variable
 *
 * \param[in]  cfg      The RzConfig to use
 * \param[in]  name     The name of the string type variable to update
 * \param[in]  options  The options to set
 *
 * \return     On success returns a true, otherwise false.
 */
RZ_API bool rz_config_set_options(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE RZ_OWN RzList /*<char *>*/ *options) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		rz_list_free(options);
		return false;
	}

	return config_entry_set_options(entry, options);
}

/**
 * \brief      Sets the options held by the string type variable
 *
 * \param[in]  cfg   The RzConfig to use
 * \param[in]  name  The name of the string type variable to update
 * \param[in]  ...   The list of options to set (NULL terminated)
 *
 * \return     On success returns a true, otherwise false.
 */
RZ_API bool rz_config_set_options2(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, ...) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	}

	va_list argp;
	RzList *options = rz_list_newf(free);
	if (!options) {
		return false;
	}

	va_start(argp, name);
	bool ok = config_var_args_to_list(argp, options);
	va_end(argp);
	if (!ok) {
		rz_list_free(options);
		return false;
	}

	return config_entry_set_options(entry, options);
}

/**
 * \brief      Sets the validator callback for a given RzConfigVar (owned types).
 *
 * \param[in]  cfg        The RzConfig to use
 * \param[in]  name       The name of the string type variable to update
 * \param[in]  validator  The validator callback to set (can be NULL)
 *
 * \return     On success returns a true, otherwise false.
 */
RZ_API bool rz_config_set_validator(RZ_NONNULL RzConfig *cfg, RZ_NONNULL const char *name, RZ_NULLABLE RzConfigBindSet validator, RZ_NULLABLE void *user) {
	rz_return_val_if_fail(cfg && RZ_STR_ISNOTEMPTY(name), false);
	RzConfigEntry *entry = config_find_entry(cfg, name);
	if (!entry) {
		RZ_LOG_ERROR("config: variable '%s' does not exists.\n", name);
		return false;
	} else if (!entry->is_variable) {
		RZ_LOG_ERROR("config: variable '%s' is not an RzConfigVar.\n", name);
		return false;
	} else if (rz_config_var_has_flags(&entry->var, RZ_CONFIG_VAR_FLAG_BIND)) {
		RZ_LOG_ERROR("config: cannot set validator when variable '%s' is a bind.\n", name);
		return false;
	} else if (rz_config_var_get_options(&entry->var)) {
		RZ_LOG_ERROR("config: cannot set validator for '%s' when options are set.\n", name);
		return false;
	}

	entry->var.value.validator = validator;
	entry->var.value.validator_user = user;
	return true;
}

/**
 * \brief      DEPRECATED: returns the RzConfigEntry name
 *
 * \param[in]  entry  The RzConfigEntry to use
 *
 * \return     On success returns a valid pointer (guaranteed to not be NULL)
 */
RZ_API const char *rz_config_entry_get_name(RZ_NONNULL const RzConfigEntry *entry) {
	rz_return_val_if_fail(entry, "");
	if (entry->is_variable) {
		return rz_str_get(entry->var.name);
	}
	return rz_str_get(entry->node.name);
}

/**
 * \brief      DEPRECATED: returns the RzConfigEntry description
 *
 * \param[in]  entry  The RzConfigEntry to use
 *
 * \return     On success returns a valid pointer (guaranteed to not be NULL)
 */
RZ_API const char *rz_config_entry_get_desc(RZ_NONNULL const RzConfigEntry *entry) {
	rz_return_val_if_fail(entry, "");
	if (entry->is_variable) {
		return rz_str_get(entry->var.desc);
	}
	return rz_str_get(entry->node.desc);
}

/**
 * \brief      DEPRECATED: returns the RzConfigEntry variable held unsigned integer
 *
 * \param[in]  entry  The RzConfigEntry to use
 *
 * \return     Returns the value held by the RzConfigEntry struct
 */
RZ_API ut64 rz_config_entry_get_integer(RZ_NONNULL const RzConfigEntry *entry) {
	rz_return_val_if_fail(entry, 0);
	if (entry->is_variable) {
		return rz_config_var_get_integer(&entry->var);
	}
	return entry->node.i_value;
}

/**
 * \brief      DEPRECATED: returns the RzConfigEntry variable held boolean
 *
 * \param[in]  entry  The RzConfigEntry to use
 *
 * \return     Returns the value held by the RzConfigEntry struct
 */
RZ_API bool rz_config_entry_get_bool(RZ_NONNULL const RzConfigEntry *entry) {
	rz_return_val_if_fail(entry, false);
	if (entry->is_variable) {
		return rz_config_var_get_bool(&entry->var);
	}
	return rz_str_is_true(rz_str_get(entry->node.value));
}

/**
 * \brief      DEPRECATED: returns the RzConfigEntry variable held string
 *
 * \param[in]  entry  The RzConfigEntry to use
 *
 * \return     Returns the value held by the RzConfigEntry struct
 */
RZ_API const char *rz_config_entry_get_string(RZ_NONNULL const RzConfigEntry *entry) {
	rz_return_val_if_fail(entry, NULL);
	if (entry->is_variable) {
		return rz_config_var_get_string(&entry->var);
	}

	return rz_str_get(entry->node.value);
}

/**
 * \brief      DEPRECATED: returns the RzConfigEntry variable as owned string
 *
 * \param[in]  entry  The RzConfigEntry to stringify
 *
 * \return     On success returns a valid pointer, otherwise NULL.
 */
RZ_API RZ_OWN char *rz_config_entry_get_as_string(RZ_NONNULL const RzConfigEntry *entry) {
	rz_return_val_if_fail(entry, NULL);
	if (entry->is_variable) {
		return rz_config_var_as_string(&entry->var);
	}

	const char *value = rz_str_get(entry->node.value);
	return rz_str_dup(value);
}
