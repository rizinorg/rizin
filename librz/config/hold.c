// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "config_internal.h"

static RzList /*<char *>*/ *config_hold_dup_safe_list(RzConfigVar *var) {
	// we do not know if the strings returned are
	// safe or not to be owned, so we just dup them
	RzList /*<const char *>*/ *list = rz_config_var_get_list(var);
	RzList *safe_list = rz_config_dup_list(list);
	rz_list_free(list);
	return safe_list;
}

static void config_hold_value_init_from_node(ConfigValue *cv, RzConfigNode *node) {
	cv->name = node->name;
	if (rz_config_node_is_bool(node)) {
		cv->flags = RZ_CONFIG_VAR_TYPE_BOOL;
		cv->value.boolean = rz_str_is_true(node->value);
		return;
	} else if (rz_config_node_is_int(node)) {
		cv->flags = RZ_CONFIG_VAR_TYPE_INT;
		cv->value.integer = node->i_value;
		return;
	}
	cv->flags = RZ_CONFIG_VAR_TYPE_STR;
	cv->value.string = rz_str_dup(node->value);
}

static void config_hold_value_init_from_var(ConfigValue *cv, RzConfigVar *var) {
	cv->name = var->name;
	cv->flags = var->flags & RZ_CONFIG_VAR_TYPE_MASK;
	if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_BOOL)) {
		cv->value.boolean = rz_config_var_get_bool(var);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_STR)) {
		const char *str = rz_config_var_get_string(var);
		cv->value.string = rz_str_dup(str);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_LIST)) {
		cv->value.list = config_hold_dup_safe_list(var);
	} else if (RZ_CONFIG_VAR_IS_TYPE(var->flags, RZ_CONFIG_VAR_TYPE_INT)) {
		cv->value.integer = rz_config_var_get_integer(var);
	} else {
		cv->value.interval = rz_config_var_get_interval(var);
	}
}

static bool config_hold_is_readonly(const RzConfigEntry *entry) {
	if (entry->is_variable) {
		return rz_config_var_is_readonly(&entry->var);
	}
	return rz_config_node_is_readonly(&entry->node);
}

static void config_hold_variable_add(RzConfigHold *hold, const char *name) {
	RzConfigEntry *entry = config_find_entry(hold->cfg, name);
	if (!entry) {
		RZ_LOG_WARN("config-hold: failed to get '%s'\n", name);
		return;
	}

	if (config_hold_is_readonly(entry)) {
		return;
	}

	ConfigValue cv = { 0 };
	if (entry->is_variable) {
		config_hold_value_init_from_var(&cv, &entry->var);
	} else {
		config_hold_value_init_from_node(&cv, &entry->node);
	}

	rz_vector_push(&hold->variables, &cv);
}

/**
 * \brief Save a copy of the current config options.
 *
 * Get the current values of the config and save them in the RzConfigHold object \p h .
 *
 * \param hold  Reference to RzConfigHold instance
 * \param ...   List of config variables to save, terminated by NULL.
 * \return      Returns true if at least one variable is correctly saved, false otherwise
 */
RZ_API bool rz_config_hold_var(RZ_NONNULL RzConfigHold *hold, ...) {
	rz_return_val_if_fail(hold, false);

	va_list ap;
	const char *name;
	va_start(ap, hold);

	while ((name = va_arg(ap, const char *))) {
		config_hold_variable_add(hold, name);
	}

	va_end(ap);
	return rz_vector_len(&hold->variables) > 0;
}

static void config_hold_value_fini(void *e, void *user) {
	if (!e) {
		return;
	}

	ConfigValue *cv = (ConfigValue *)e;
	if (RZ_CONFIG_VAR_IS_TYPE(cv->flags, RZ_CONFIG_VAR_TYPE_STR)) {
		free(cv->value.string);
	} else if (RZ_CONFIG_VAR_IS_TYPE(cv->flags, RZ_CONFIG_VAR_TYPE_LIST)) {
		rz_list_free(cv->value.list);
	}
}

/**
 * \brief Create an opaque object to save/restore some configuration options
 *
 * \param cfg RzConfig reference
 * \return RzConfigHold allocated object
 */
RZ_API RzConfigHold *rz_config_hold_new(RZ_NONNULL RzConfig *cfg) {
	rz_return_val_if_fail(cfg, NULL);

	RzConfigHold *hold = RZ_NEW0(RzConfigHold);
	if (!hold) {
		return false;
	}
	hold->cfg = cfg;
	rz_vector_init(&hold->variables, sizeof(ConfigValue), config_hold_value_fini, NULL);
	return hold;
}

/**
 * \brief Create an opaque object to save/restore some configuration options and saves the given variables.
 *
 * \param cfg RzConfig reference
 * \param ...   List of config variables to save, terminated by NULL.
 * \return RzConfigHold allocated object
 */
RZ_API RzConfigHold *rz_config_hold_new2(RZ_NONNULL RzConfig *cfg, ...) {
	rz_return_val_if_fail(cfg, NULL);
	RzConfigHold *hold = rz_config_hold_new(cfg);
	if (!hold) {
		return NULL;
	}

	va_list ap;
	const char *name;
	va_start(ap, cfg);

	while ((name = va_arg(ap, const char *))) {
		config_hold_variable_add(hold, name);
	}

	va_end(ap);

	if (rz_vector_len(&hold->variables) < 1) {
		rz_config_hold_free(hold);
		return NULL;
	}

	return hold;
}

static bool config_hold_set_bool(RzConfigEntry *entry, bool value, void *user) {
	if (entry->is_variable) {
		return rz_config_var_set_bool(&entry->var, value);
	}
	return rz_config_node_set_bool(&entry->node, value, user);
}

static bool config_hold_set_integer(RzConfigEntry *entry, ut64 value, void *user) {
	if (entry->is_variable) {
		return rz_config_var_set_integer(&entry->var, value);
	}
	return rz_config_node_set_integer(&entry->node, value, user);
}

static bool config_hold_set_string(RzConfigEntry *entry, const char *value, void *user) {
	if (entry->is_variable) {
		return rz_config_var_set_string(&entry->var, value);
	}
	return rz_config_node_set_string(&entry->node, value, user);
}

/**
 * \brief Restore whatever config options were previously saved in \p h
 *
 * \param h Reference to RzConfigHold
 */
RZ_API void rz_config_hold_restore(RZ_NULLABLE RzConfigHold *hold) {
	if (!hold) {
		return;
	}

	void *cfg_user = hold->cfg->user;

	ConfigValue *cv;
	// we iterate from the last to the first as order matters.
	rz_vector_foreach_prev (&hold->variables, cv) {
		if (!cv->name) {
			continue;
		}

		RzConfigEntry *entry = config_find_entry(hold->cfg, cv->name);
		if (!entry) {
			RZ_LOG_WARN("config-hold: failed to get node named '%s'\n", cv->name);
			continue;
		}

		if (RZ_CONFIG_VAR_IS_TYPE(cv->flags, RZ_CONFIG_VAR_TYPE_BOOL)) {
			config_hold_set_bool(entry, cv->value.boolean, cfg_user);
		} else if (RZ_CONFIG_VAR_IS_TYPE(cv->flags, RZ_CONFIG_VAR_TYPE_INT)) {
			config_hold_set_integer(entry, cv->value.integer, cfg_user);
		} else if (RZ_CONFIG_VAR_IS_TYPE(cv->flags, RZ_CONFIG_VAR_TYPE_STR)) {
			config_hold_set_string(entry, cv->value.string, cfg_user);
		} else if (RZ_CONFIG_VAR_IS_TYPE(cv->flags, RZ_CONFIG_VAR_TYPE_LIST)) {
			// ownership of list moved to var.
			rz_config_var_set_list(&entry->var, cv->value.list);
			cv->value.list = NULL;
		} else { /// RZ_CONFIG_VAR_TYPE_ITV
			rz_config_var_set_interval(&entry->var, cv->value.interval);
		}
	}
}

/**
 * \brief Free a RzConfigHold object \p h
 *
 * \param h Reference to RzConfigHold
 */
RZ_API void rz_config_hold_free(RZ_NULLABLE RzConfigHold *h) {
	if (!h) {
		return;
	}
	rz_vector_fini(&h->variables);
	free(h);
}

RZ_API void rz_config_hold_restore_and_free(RZ_NULLABLE RzConfigHold *hold) {
	if (!hold) {
		return;
	}
	rz_config_hold_restore(hold);
	rz_config_hold_free(hold);
}