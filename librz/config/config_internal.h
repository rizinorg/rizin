// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef CONFIG_INTERNAL_H
#define CONFIG_INTERNAL_H

#include <rz_config.h>
#include <rz_util.h>
#include <rz_vector.h>

typedef struct config_value_t {
	const char *name; ///< Variable name
	ut32 flags; ///< Copy of the variable flags (see RzConfigVarFlags)
	union {
		char *string;
		ut64 integer;
		bool boolean;
		RzList /*<char *>*/ *list;
		RzInterval interval;
	} value; ///< Copy of the variable value
} ConfigValue;

struct rz_config_hold_t {
	RzConfig *cfg;
	RzVector /*<ConfigValue>*/ variables;
};

static int find_variable(const char *a_name, const RzConfigEntry *b, void *user) {
	const char *b_name = rz_config_entry_get_name(b);
	return strcmp(a_name, b_name);
}

static inline RzConfigEntry *config_find_entry(RzConfig *cfg, const char *name) {
	size_t length = rz_vector_len(&cfg->sorted_vars);
	size_t index = rz_vector_find_sorted(&cfg->sorted_vars, (void *)name, (RzVectorComparator)find_variable, NULL);
	if (index >= length) {
		return NULL;
	}

	return rz_vector_index_ptr(&cfg->sorted_vars, index);
}

#define config_find_entry_ro(cfg, name) ((const RzConfigEntry *)config_find_entry((RzConfig *)cfg, name))

static int sort_variables(const RzConfigEntry *a, const RzConfigEntry *b, void *user) {
	const char *a_name = rz_config_entry_get_name(a);
	const char *b_name = rz_config_entry_get_name(b);
	return strcmp(a_name, b_name);
}

static inline void config_add_entry(RzConfig *cfg, const char *name, RzConfigEntry *entry, bool is_var) {
	entry->is_variable = is_var;

	rz_vector_insert_sorted(&cfg->sorted_vars, entry, (RzVectorComparator)sort_variables, NULL);
}

RZ_IPI RZ_OWN RzList /*<char *>*/ *rz_config_dup_list(RZ_NULLABLE const RzList /*<const char *>*/ *list);

RZ_IPI bool rz_config_var_set_bool(RzConfigVar *var, bool value);
RZ_IPI bool rz_config_var_set_integer(RzConfigVar *var, ut64 value);
RZ_IPI bool rz_config_var_set_string(RzConfigVar *var, const char *value);
RZ_IPI bool rz_config_var_set_list(RzConfigVar *var, const RzList /*<const char *>*/ *value);
RZ_IPI bool rz_config_var_set_list2(RzConfigVar *var, RZ_OWN RzList /*<char *>*/ *value);
RZ_IPI bool rz_config_var_set_interval(RzConfigVar *var, RzInterval value);
RZ_IPI bool rz_config_var_set_any(RzConfigVar *var, const char *value);
RZ_IPI bool rz_config_toggle_var_bool(RzConfigVar *var);

/* old implementation */
RZ_IPI void rz_config_node_fini(RZ_NULLABLE RzConfigNode *node);
RZ_IPI bool rz_config_node_is_readonly(const RzConfigNode *node);
RZ_IPI bool rz_config_node_set_readonly(RzConfigNode *node, bool read_only);
RZ_IPI bool rz_config_node_set_string(RzConfigNode *node, const char *value, void *user);
RZ_IPI bool rz_config_node_set_integer(RzConfigNode *node, ut64 i, void *user);
RZ_IPI bool rz_config_node_set_bool(RzConfigNode *node, bool value, void *user);

#endif /* CONFIG_INTERNAL_H */
