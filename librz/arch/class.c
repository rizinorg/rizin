// SPDX-FileCopyrightText: 2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_vector.h>
#include <rz_util/rz_graph_drawable.h>
#include <rz_util/rz_table.h>
#include "../include/rz_analysis.h"
#include "../include/rz_util/rz_graph.h"

static void rz_analysis_class_base_delete_class(RzAnalysis *analysis, const char *class_name);
static void rz_analysis_class_method_delete_class(RzAnalysis *analysis, const char *class_name);
static void rz_analysis_class_vtable_delete_class(RzAnalysis *analysis, const char *class_name);
static void rz_analysis_class_base_rename_class(RzAnalysis *analysis, const char *class_name_old, const char *class_name_new);
static void rz_analysis_class_method_rename_class(RzAnalysis *analysis, const char *old_class_name, const char *new_class_name);
static void rz_analysis_class_vtable_rename_class(RzAnalysis *analysis, const char *old_class_name, const char *new_class_name);

static const char *key_class(const char *name) {
	return name;
}

static char *key_attr_types(const char *name) {
	return rz_str_newf("attrtypes.%s", name);
}

static char *key_attr_type_attrs(const char *class_name, const char *attr_type) {
	return rz_str_newf("attr.%s.%s", class_name, attr_type);
}

static char *key_attr_content(const char *class_name, const char *attr_type, const char *attr_id) {
	return rz_str_newf("attr.%s.%s.%s", class_name, attr_type, attr_id);
}

static char *key_attr_content_specific(const char *class_name, const char *attr_type, const char *attr_id) {
	return rz_str_newf("attr.%s.%s.%s.specific", class_name, attr_type, attr_id);
}

typedef enum {
	RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD,
	RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE,
	RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE
} RzAnalysisClassAttrType;

static const char *attr_type_id(RzAnalysisClassAttrType attr_type) {
	switch (attr_type) {
	case RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD:
		return "method";
	case RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE:
		return "vtable";
	case RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE:
		return "base";
	default:
		return NULL;
	}
}

RZ_API void rz_analysis_class_recover_from_rzbin(RzAnalysis *analysis) {
	rz_cons_break_push(NULL, NULL);
	RzBinObject *bin_obj = rz_bin_cur_object(analysis->binb.bin);
	if (!bin_obj) {
		rz_cons_break_pop();
		return;
	}
	const RzPVector *classes = rz_bin_object_get_classes(bin_obj);
	if (classes) {
		void **iter_class;
		RzBinClass *class;
		rz_pvector_foreach (classes, iter_class) {
			class = *iter_class;
			if (rz_cons_is_breaked()) {
				break;
			}
			if (!rz_analysis_class_exists(analysis, class->name)) {
				rz_analysis_class_create(analysis, class->name);
				RzList *methods = class->methods;
				if (methods) {
					rz_analysis_class_method_recover(analysis, class, methods);
				}
			}
		}
	}
	rz_cons_break_pop();
}

RZ_API RzAnalysisClassErr rz_analysis_class_create(RzAnalysis *analysis, const char *name) {
	char *name_sanitized = rz_str_sanitize_sdb_key(name);
	if (!name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err = RZ_ANALYSIS_CLASS_ERR_SUCCESS;
	const char *key = key_class(name_sanitized);
	if (!sdb_exists(analysis->sdb_classes, key)) {
		sdb_set(analysis->sdb_classes, key, "c", 0);
		RzEventClass event = { .name = name_sanitized };
		if (analysis->ev) {
			rz_event_send(analysis->ev, RZ_EVENT_CLASS_NEW, &event);
		}
	} else {
		err = RZ_ANALYSIS_CLASS_ERR_CLASH;
	}

	free(name_sanitized);
	return err;
}

RZ_API void rz_analysis_class_delete(RzAnalysis *analysis, const char *name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(name);
	if (!class_name_sanitized) {
		return;
	}

	rz_analysis_class_base_delete_class(analysis, class_name_sanitized);
	rz_analysis_class_method_delete_class(analysis, class_name_sanitized);
	rz_analysis_class_vtable_delete_class(analysis, class_name_sanitized);

	if (!sdb_remove(analysis->sdb_classes, key_class(class_name_sanitized), 0)) {
		free(class_name_sanitized);
		return;
	}

	char *key = key_attr_types(class_name_sanitized);
	if (!key) {
		free(class_name_sanitized);
		return;
	}
	char *attr_type_array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);

	char *attr_type;
	sdb_aforeach(attr_type, attr_type_array) {
		key = key_attr_type_attrs(class_name_sanitized, attr_type);
		if (!key) {
			continue;
		}
		char *attr_id_array = sdb_get(analysis->sdb_classes_attrs, key, 0);
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		free(key);
		if (attr_id_array) {
			char *attr_id;
			sdb_aforeach(attr_id, attr_id_array) {
				key = key_attr_content(class_name_sanitized, attr_type, attr_id);
				if (key) {
					sdb_remove(analysis->sdb_classes_attrs, key, 0);
					free(key);
				}
				key = key_attr_content_specific(class_name_sanitized, attr_type, attr_id);
				if (key) {
					sdb_remove(analysis->sdb_classes_attrs, key, 0);
					free(key);
				}
				sdb_aforeach_next(attr_id);
			}
			free(attr_id_array);
		}
		sdb_aforeach_next(attr_type);
	}
	free(attr_type_array);

	key = key_attr_types(class_name_sanitized);
	if (key) {
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		free(key);
	}

	RzEventClass event = { .name = class_name_sanitized };
	if (analysis->ev) {
		rz_event_send(analysis->ev, RZ_EVENT_CLASS_DEL, &event);
	}

	free(class_name_sanitized);
}

static bool rz_analysis_class_exists_raw(RzAnalysis *analysis, const char *name) {
	return sdb_exists(analysis->sdb_classes, key_class(name));
}

RZ_API bool rz_analysis_class_exists(RzAnalysis *analysis, const char *name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(name);
	if (!class_name_sanitized) {
		return false;
	}
	bool r = rz_analysis_class_exists_raw(analysis, class_name_sanitized);
	free(class_name_sanitized);
	return r;
}

RZ_API RZ_OWN RzPVector /*<SdbKv *>*/ *rz_analysis_class_get_all(RzAnalysis *analysis, bool sorted) {
	return sdb_get_kv_list(analysis->sdb_classes, sorted);
}

RZ_API void rz_analysis_class_foreach(RzAnalysis *analysis, SdbForeachCallback cb, void *user) {
	sdb_foreach(analysis->sdb_classes, cb, user);
}

static bool rename_key(Sdb *sdb, const char *key_old, const char *key_new) {
	char *content = sdb_get(sdb, key_old, 0);
	if (!content) {
		return false;
	}
	sdb_remove(sdb, key_old, 0);
	sdb_set(sdb, key_new, content, 0);
	free(content);
	return true;
}

RZ_API RzAnalysisClassErr rz_analysis_class_rename(RzAnalysis *analysis, const char *old_name, const char *new_name) {
	if (rz_analysis_class_exists(analysis, new_name)) {
		return RZ_ANALYSIS_CLASS_ERR_CLASH;
	}

	char *old_name_sanitized = rz_str_sanitize_sdb_key(old_name);
	if (!old_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	char *new_name_sanitized = rz_str_sanitize_sdb_key(new_name);
	if (!new_name_sanitized) {
		free(old_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	RzAnalysisClassErr err = RZ_ANALYSIS_CLASS_ERR_SUCCESS;

	rz_analysis_class_base_rename_class(analysis, old_name, new_name);
	rz_analysis_class_method_rename_class(analysis, old_name, new_name);
	rz_analysis_class_vtable_rename_class(analysis, old_name, new_name);

	if (!rename_key(analysis->sdb_classes, key_class(old_name_sanitized), key_class(new_name_sanitized))) {
		err = RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_CLASS;
		goto beach;
	}

	char *key = key_attr_types(old_name_sanitized);
	if (key) {
		char *attr_types = sdb_get(analysis->sdb_classes_attrs, key, 0);
		free(key);
		char *attr_type_cur;
		sdb_aforeach(attr_type_cur, attr_types) {
			char *key = key_attr_type_attrs(old_name, attr_type_cur);
			if (!key) {
				continue;
			}
			char *attr_ids = sdb_get(analysis->sdb_classes_attrs, key, 0);
			free(key);
			char *attr_id_cur;
			sdb_aforeach(attr_id_cur, attr_ids) {
				key = key_attr_content(old_name, attr_type_cur, attr_id_cur);
				char *new_key = key_attr_content(new_name, attr_type_cur, attr_id_cur);
				if (key && new_key) {
					rename_key(analysis->sdb_classes_attrs, key, new_key);
				}
				free(key);
				free(new_key);
				sdb_aforeach_next(attr_id_cur);
			}
			free(attr_ids);
			key = key_attr_type_attrs(old_name, attr_type_cur);
			char *new_key = key_attr_type_attrs(new_name, attr_type_cur);
			if (key && new_key) {
				rename_key(analysis->sdb_classes_attrs, key, new_key);
			}
			sdb_aforeach_next(attr_type_cur);
		}
		free(attr_types);
	}

	key = key_attr_types(old_name_sanitized);
	char *new_key = key_attr_types(new_name_sanitized);
	if (key && new_key) {
		rename_key(analysis->sdb_classes_attrs, key, new_key);
	}
	free(key);
	free(new_key);

	RzEventClassRename event = {
		.name_old = old_name_sanitized,
		.name_new = new_name_sanitized
	};
	if (analysis->ev) {
		rz_event_send(analysis->ev, RZ_EVENT_CLASS_RENAME, &event);
	}

beach:
	free(old_name_sanitized);
	free(new_name_sanitized);
	return err;
}

// all ids must be sanitized
static char *rz_analysis_class_get_attr_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id, bool specific) {
	const char *attr_type_str = attr_type_id(attr_type);
	char *key = specific
		? key_attr_content_specific(class_name, attr_type_str, attr_id)
		: key_attr_content(class_name, attr_type_str, attr_id);
	if (!key) {
		return NULL;
	}
	char *ret = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	return ret;
}

// ids will be sanitized automatically
static char *rz_analysis_class_get_attr(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id, bool specific) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return false;
	}
	char *attr_id_sanitized = rz_str_sanitize_sdb_key(attr_id);
	if (!attr_id_sanitized) {
		free(class_name_sanitized);
		return false;
	}

	char *ret = rz_analysis_class_get_attr_raw(analysis, class_name_sanitized, attr_type, attr_id_sanitized, specific);

	free(class_name_sanitized);
	free(attr_id_sanitized);

	return ret;
}

// all ids must be sanitized
static RzAnalysisClassErr rz_analysis_class_set_attr_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id, const char *content) {
	const char *attr_type_str = attr_type_id(attr_type);

	if (!rz_analysis_class_exists_raw(analysis, class_name)) {
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_CLASS;
	}

	char *key = key_attr_types(class_name);
	if (key) {
		sdb_array_add(analysis->sdb_classes_attrs, key, attr_type_str, 0);
		free(key);
	}
	key = key_attr_type_attrs(class_name, attr_type_str);
	if (key) {
		sdb_array_add(analysis->sdb_classes_attrs, key, attr_id, 0);
		free(key);
	}
	key = key_attr_content(class_name, attr_type_str, attr_id);
	if (key) {
		sdb_set(analysis->sdb_classes_attrs, key, content, 0);
		free(key);
	}

	RzEventClassAttrSet event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id },
		.content = content
	};
	if (analysis->ev) {
		rz_event_send(analysis->ev, RZ_EVENT_CLASS_ATTR_SET, &event);
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

// ids will be sanitized automatically
static RzAnalysisClassErr rz_analysis_class_set_attr(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id, const char *content) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = rz_str_sanitize_sdb_key(attr_id);
	if (!attr_id_sanitized) {
		free(class_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	RzAnalysisClassErr err = rz_analysis_class_set_attr_raw(analysis, class_name_sanitized, attr_type, attr_id_sanitized, content);

	free(class_name_sanitized);
	free(attr_id_sanitized);

	return err;
}

static RzAnalysisClassErr rz_analysis_class_delete_attr_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id) {
	const char *attr_type_str = attr_type_id(attr_type);

	char *key = key_attr_content(class_name, attr_type_str, attr_id);
	if (key) {
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		free(key);
	}
	key = key_attr_content_specific(class_name, attr_type_str, attr_id);
	if (key) {
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		free(key);
	}

	key = key_attr_type_attrs(class_name, attr_type_str);
	if (key) {
		sdb_array_remove(analysis->sdb_classes_attrs, key, attr_id, 0);
		if (!sdb_exists(analysis->sdb_classes_attrs, key)) {
			sdb_array_remove(analysis->sdb_classes_attrs, key_attr_types(class_name), attr_type_str, 0);
		}
		free(key);
	}

	RzEventClassAttr event = {
		.class_name = class_name,
		.attr_type = attr_type,
		.attr_id = attr_id
	};
	if (analysis->ev) {
		rz_event_send(analysis->ev, RZ_EVENT_CLASS_ATTR_DEL, &event);
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static RzAnalysisClassErr rz_analysis_class_delete_attr(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = rz_str_sanitize_sdb_key(attr_id);
	if (!attr_id_sanitized) {
		free(class_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	RzAnalysisClassErr err = rz_analysis_class_delete_attr_raw(analysis, class_name_sanitized, attr_type, attr_id_sanitized);

	free(class_name_sanitized);
	free(attr_id_sanitized);
	return err;
}

static RzAnalysisClassErr rz_analysis_class_rename_attr_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	const char *attr_type_str = attr_type_id(attr_type);
	char *key = key_attr_type_attrs(class_name, attr_type_str);
	if (!key) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	if (sdb_array_contains(analysis->sdb_classes_attrs, key, attr_id_new, 0)) {
		free(key);
		return RZ_ANALYSIS_CLASS_ERR_CLASH;
	}

	if (!sdb_array_remove(analysis->sdb_classes_attrs, key, attr_id_old, 0)) {
		free(key);
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR;
	}

	sdb_array_add(analysis->sdb_classes_attrs, key, attr_id_new, 0);
	free(key);

	key = key_attr_content(class_name, attr_type_str, attr_id_old);
	if (key) {
		char *content = sdb_get(analysis->sdb_classes_attrs, key, 0);
		if (content) {
			sdb_remove(analysis->sdb_classes_attrs, key, 0);
			key = key_attr_content(class_name, attr_type_str, attr_id_new);
			sdb_set(analysis->sdb_classes_attrs, key, content, 0);
			free(content);
		}
		free(key);
	}

	key = key_attr_content_specific(class_name, attr_type_str, attr_id_old);
	if (key) {
		char *content = sdb_get(analysis->sdb_classes_attrs, key, 0);
		if (content) {
			sdb_remove(analysis->sdb_classes_attrs, key, 0);
			key = key_attr_content_specific(class_name, attr_type_str, attr_id_new);
			sdb_set(analysis->sdb_classes_attrs, key, content, 0);
			free(content);
		}
		free(key);
	}

	RzEventClassAttrRename event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id_old },
		.attr_id_new = attr_id_new
	};
	if (analysis->ev) {
		rz_event_send(analysis->ev, RZ_EVENT_CLASS_ATTR_RENAME, &event);
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static RzAnalysisClassErr rz_analysis_class_rename_attr(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	char *attr_id_old_sanitized = rz_str_sanitize_sdb_key(attr_id_old);
	if (!attr_id_old_sanitized) {
		free(class_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	char *attr_id_new_sanitized = rz_str_sanitize_sdb_key(attr_id_new);
	if (!attr_id_new_sanitized) {
		free(class_name_sanitized);
		free(attr_id_old_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr ret = rz_analysis_class_rename_attr_raw(analysis, class_name_sanitized, attr_type, attr_id_old_sanitized, attr_id_new_sanitized);
	free(class_name_sanitized);
	free(attr_id_old_sanitized);
	free(attr_id_new_sanitized);
	return ret;
}

static void rz_analysis_class_unique_attr_id_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, char *out, size_t out_size) {
	ut64 id = 0;
	char *key = key_attr_type_attrs(class_name, attr_type_id(attr_type));
	if (!key) {
		return;
	}
	do {
		snprintf(out, out_size, "%" PFMT64u, id);
		id++;
	} while (sdb_array_contains(analysis->sdb_classes_attrs, key, out, 0));
	free(key);
}

static char *flagname_attr(const char *attr_type, const char *class_name, const char *attr_id) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return NULL;
	}
	char *attr_id_sanitized = rz_str_sanitize_sdb_key(attr_id);
	if (!attr_id_sanitized) {
		free(class_name_sanitized);
		return NULL;
	}
	char *r = rz_str_newf("%s.%s.%s", attr_type, class_name, attr_id);
	free(class_name_sanitized);
	free(attr_id_sanitized);
	return r;
}

static void rz_analysis_class_set_flag(RzAnalysis *analysis, const char *name, ut64 addr, ut32 size) {
	if (!name || !analysis->flg_class_set) {
		return;
	}
	analysis->flg_class_set(analysis->flb.f, name, addr, size);
}

static void rz_analysis_class_unset_flag(RzAnalysis *analysis, const char *name) {
	if (!name || !analysis->flb.unset_name || !analysis->flg_class_get) {
		return;
	}
	if (analysis->flg_class_get(analysis->flb.f, name)) {
		analysis->flb.unset_name(analysis->flb.f, name);
	}
}

static void rz_analysis_class_rename_flag(RzAnalysis *analysis, const char *old_name, const char *new_name) {
	if (!old_name || !new_name || !analysis->flb.unset || !analysis->flg_class_get || !analysis->flg_class_set) {
		return;
	}
	RzFlagItem *flag = analysis->flg_class_get(analysis->flb.f, old_name);
	if (!flag) {
		return;
	}
	ut64 addr = flag->offset;
	analysis->flb.unset(analysis->flb.f, flag);
	analysis->flg_class_set(analysis->flb.f, new_name, addr, 0);
}

static RzAnalysisClassErr rz_analysis_class_add_attr_unique_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char attr_id[16];
	rz_analysis_class_unique_attr_id_raw(analysis, class_name, attr_type, attr_id, sizeof(attr_id));

	RzAnalysisClassErr err = rz_analysis_class_set_attr(analysis, class_name, attr_type, attr_id, content);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}

	if (attr_id_out) {
		rz_str_ncpy(attr_id_out, attr_id, attr_id_out_size);
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static RzAnalysisClassErr rz_analysis_class_add_attr_unique(RzAnalysis *analysis, const char *class_name, RzAnalysisClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	RzAnalysisClassErr err = rz_analysis_class_add_attr_unique_raw(analysis, class_name_sanitized, attr_type, content, attr_id_out, attr_id_out_size);

	free(class_name_sanitized);
	return err;
}

// ---- METHODS ----
// Format: addr,vtable_offset

static char *flagname_method(const char *class_name, const char *meth_name) {
	if (rz_str_startswith(meth_name, "method.")) {
		return rz_str_dup(meth_name);
	}
	return flagname_attr("method", class_name, meth_name);
}

RZ_API void rz_analysis_class_method_fini(RZ_NULLABLE RzAnalysisMethod *meth) {
	if (!meth) {
		return;
	}
	free(meth->name);
	free(meth->real_name);
}

RZ_API void rz_analysis_class_method_recover(RzAnalysis *analysis, RzBinClass *cls, RzList /*<RzBinSymbol *>*/ *methods) {
	RzListIter *iter_method;
	RzBinSymbol *sym;
	rz_list_foreach (methods, iter_method, sym) {
		if (!rz_analysis_class_method_exists(analysis, cls->name, sym->name)) {
			// detect constructor or destructor but not implemented
			// Temporarily set to default
			RzAnalysisMethod method = { 0 };
			method.addr = sym->vaddr;
			method.vtable_offset = -1;
			RzAnalysisFunction *fcn = rz_analysis_get_function_at(analysis, sym->vaddr);
			char *method_name = rz_str_dup(sym->name);
			rz_str_split(method_name, '(');
			method.name = fcn ? rz_str_dup(fcn->name) : rz_str_dup(method_name);
			// this replace is required due SDB using commas to split the stored data.
			// some c++ function names might have templates like foo<char, int>()
			// which breaks the decoding from the SDB data
			method.real_name = rz_str_replace(method_name, ",", "#_#", 1);
			method.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT;
			rz_analysis_class_method_set(analysis, cls->name, &method);
			rz_analysis_class_method_fini(&method);
		}
	}
}

RZ_API bool rz_analysis_class_method_exists(RzAnalysis *analysis, const char *class_name, const char *meth_name) {
	char *content = rz_analysis_class_get_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, meth_name, false);
	if (!content) {
		return false;
	}

	return true;
}

RZ_API bool rz_analysis_class_method_exists_by_addr(RzAnalysis *analysis, const char *class_name, ut64 addr) {
	RzVector *vec = rz_analysis_class_method_get_all(analysis, class_name);
	if (!vec) {
		return false;
	}
	RzAnalysisMethod *meth;
	rz_vector_foreach (vec, meth) {
		if (meth->addr == addr) {
			rz_vector_free(vec);
			return true;
		}
	}
	rz_vector_free(vec);
	return false;
}

RZ_API RzAnalysisClassErr rz_analysis_class_method_get_by_addr(RzAnalysis *analysis, const char *class_name, ut64 addr, RzAnalysisMethod *method) {
	RzVector *vec = rz_analysis_class_method_get_all(analysis, class_name);
	if (!vec) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisMethod *meth;
	rz_vector_foreach (vec, meth) {
		if (meth->addr == addr) {
			method->name = rz_str_dup(meth->name);
			method->addr = meth->addr;
			method->method_type = meth->method_type;
			method->vtable_offset = meth->vtable_offset;
			method->real_name = rz_str_dup(meth->real_name);
			rz_vector_free(vec);
			return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
		}
	}
	rz_vector_free(vec);
	return RZ_ANALYSIS_CLASS_ERR_OTHER;
}

// if the method exists: store it in *meth and return RZ_ANALYSIS_CLASS_ERR_SUCCESS
// else return the error, contents of *meth are undefined
RZ_API RzAnalysisClassErr rz_analysis_class_method_get(RzAnalysis *analysis, const char *class_name, const char *meth_name, RzAnalysisMethod *meth) {
	char *content = rz_analysis_class_get_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, meth_name, false);
	if (!content) {
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext(cur, &next);

	meth->addr = rz_num_math(NULL, cur);
	cur = next;

	if (!cur) {
		free(content);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	sdb_anext(cur, &next);
	meth->vtable_offset = atoll(cur);
	cur = next;

	if (!cur) {
		free(content);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	sdb_anext(cur, &next);
	meth->method_type = rz_num_math(NULL, cur);
	cur = next;

	if (!cur) {
		free(content);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	sdb_anext(cur, NULL);

	meth->real_name = rz_str_dup(cur);
	// this replace is required due SDB using commas to split the stored data.
	// some c++ function names might have templates like foo<char, int>()
	// which breaks the decoding from the SDB data
	meth->real_name = rz_str_replace(meth->real_name, "#_#", ",", 1);

	free(content);

	meth->name = rz_str_sanitize_sdb_key(meth_name);
	if (!meth->name) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_method_fini_proxy(void *e, void *user) {
	(void)user;
	RzAnalysisMethod *meth = e;
	rz_analysis_class_method_fini(meth);
}

RZ_API RzVector /*<RzAnalysisMethod>*/ *rz_analysis_class_method_get_all(RzAnalysis *analysis, const char *class_name) {
	RzVector *vec = rz_vector_new(sizeof(RzAnalysisMethod), rz_analysis_class_method_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		rz_vector_free(vec);
		return NULL;
	}
	char *key = key_attr_type_attrs(class_name_sanitized, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD));
	if (!key) {
		rz_vector_free(vec);
		free(class_name_sanitized);
		return NULL;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	free(class_name_sanitized);

	rz_vector_reserve(vec, (size_t)sdb_alen(array));
	char *cur;
	sdb_aforeach(cur, array) {
		RzAnalysisMethod meth;
		if (rz_analysis_class_method_get(analysis, class_name, cur, &meth) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
			rz_vector_push(vec, &meth);
		}
		sdb_aforeach_next(cur);
	}
	free(array);

	return vec;
}

RZ_API RzAnalysisClassErr rz_analysis_class_method_set(RzAnalysis *analysis, const char *class_name, RzAnalysisMethod *meth) {
	char *content = rz_str_newf("%" PFMT64u "%c%" PFMT64d "%c%" PFMT32u "%c%s", meth->addr, SDB_RS, meth->vtable_offset, SDB_RS, meth->method_type, SDB_RS, meth->real_name);
	if (!content) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err = rz_analysis_class_set_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, meth->name, content);
	free(content);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}
	char *fn = flagname_method(class_name, meth->name);
	if (fn) {
		rz_analysis_class_set_flag(analysis, fn, meth->addr, 0);
		free(fn);
	}
	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

RZ_API RzAnalysisClassErr rz_analysis_class_method_rename(RzAnalysis *analysis, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	RzAnalysisMethod meth;
	if (rz_analysis_class_method_get(analysis, class_name, old_meth_name, &meth) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		meth.real_name = rz_str_dup(new_meth_name);
		rz_analysis_class_method_set(analysis, class_name, &meth);
		rz_analysis_class_method_fini(&meth);
	}

	RzAnalysisClassErr err = rz_analysis_class_rename_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, old_meth_name, new_meth_name);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}
	char *old_fn = flagname_method(class_name, old_meth_name);
	char *new_fn = flagname_method(class_name, new_meth_name);
	if (old_fn && new_fn) {
		rz_analysis_class_rename_flag(analysis, old_fn, new_fn);
	}
	free(old_fn);
	free(new_fn);
	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_method_rename_class(RzAnalysis *analysis, const char *old_class_name, const char *new_class_name) {
	char *key = key_attr_type_attrs(old_class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD));
	if (!key) {
		return;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		char *old_fn = flagname_method(old_class_name, cur);
		char *new_fn = flagname_method(new_class_name, cur);
		if (old_fn && new_fn) {
			rz_analysis_class_rename_flag(analysis, old_fn, new_fn);
		}
		free(old_fn);
		free(new_fn);
		sdb_aforeach_next(cur);
	}
	free(array);
}

static void rz_analysis_class_method_delete_class(RzAnalysis *analysis, const char *class_name) {
	char *key = key_attr_type_attrs(class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD));
	if (!key) {
		return;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		char *fn = flagname_method(class_name, cur);
		if (fn) {
			rz_analysis_class_unset_flag(analysis, fn);
		}
		free(fn);
		sdb_aforeach_next(cur);
	}
	free(array);
}

RZ_API RzAnalysisClassErr rz_analysis_class_method_delete(RzAnalysis *analysis, const char *class_name, const char *meth_name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	char *meth_name_sanitized = rz_str_sanitize_sdb_key(meth_name);
	if (!meth_name_sanitized) {
		free(class_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err = rz_analysis_class_delete_attr_raw(analysis, class_name_sanitized, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, meth_name_sanitized);
	if (err == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		char *fn = flagname_method(class_name_sanitized, meth_name_sanitized);
		if (fn) {
			rz_analysis_class_unset_flag(analysis, fn);
		}
		free(fn);
	}
	free(class_name_sanitized);
	free(meth_name_sanitized);
	return err;
}

// ---- BASE ----

RZ_API void rz_analysis_class_base_fini(RzAnalysisBaseClass *base) {
	free(base->id);
	free(base->class_name);
}

RZ_API RzAnalysisClassErr rz_analysis_class_base_get(RzAnalysis *analysis, const char *class_name, const char *base_id, RzAnalysisBaseClass *base) {
	char *content = rz_analysis_class_get_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE, base_id, false);
	if (!content) {
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext(cur, &next);

	base->class_name = strdup(cur);
	if (!base->class_name) {
		free(content);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	cur = next;
	if (!cur) {
		free(content);
		free(base->class_name);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	sdb_anext(cur, NULL);

	base->offset = rz_num_math(NULL, cur);

	free(content);

	base->id = rz_str_sanitize_sdb_key(base_id);
	if (!base->id) {
		free(base->class_name);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_base_fini_proxy(void *e, void *user) {
	(void)user;
	RzAnalysisBaseClass *base = e;
	rz_analysis_class_base_fini(base);
}

RZ_API RzVector /*<RzAnalysisBaseClass>*/ *rz_analysis_class_base_get_all(RzAnalysis *analysis, const char *class_name) {
	RzVector *vec = rz_vector_new(sizeof(RzAnalysisBaseClass), rz_analysis_class_base_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		rz_vector_free(vec);
		return NULL;
	}
	char *key = key_attr_type_attrs(class_name_sanitized, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE));
	if (!key) {
		rz_vector_free(vec);
		free(class_name_sanitized);
		return NULL;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	free(class_name_sanitized);

	rz_vector_reserve(vec, (size_t)sdb_alen(array));
	char *cur;
	sdb_aforeach(cur, array) {
		RzAnalysisBaseClass base;
		if (rz_analysis_class_base_get(analysis, class_name, cur, &base) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
			rz_vector_push(vec, &base);
		}
		sdb_aforeach_next(cur);
	}
	free(array);

	return vec;
}

static RzAnalysisClassErr rz_analysis_class_base_set_raw(RzAnalysis *analysis, const char *class_name, RzAnalysisBaseClass *base, const char *base_class_name_sanitized) {
	char *content = rz_str_newf("%s" SDB_SS "%" PFMT64u, base_class_name_sanitized, base->offset);
	if (!content) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err;
	if (base->id) {
		err = rz_analysis_class_set_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE, base->id, content);
	} else {
		base->id = malloc(16);
		if (base->id) {
			err = rz_analysis_class_add_attr_unique(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE, content, base->id, 16);
		} else {
			err = RZ_ANALYSIS_CLASS_ERR_OTHER;
		}
	}
	free(content);
	return err;
}

RZ_API RzAnalysisClassErr rz_analysis_class_base_set(RzAnalysis *analysis, const char *class_name, RzAnalysisBaseClass *base) {
	char *base_class_name_sanitized = rz_str_sanitize_sdb_key(base->class_name);
	if (!base_class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	if (!rz_analysis_class_exists_raw(analysis, base_class_name_sanitized)) {
		free(base_class_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_CLASS;
	}
	RzVector /*<RzAnalysisBaseClass>*/ *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *existing_base;
		rz_vector_foreach (bases, existing_base) {
			if (!strcmp(existing_base->class_name, base->class_name)) {
				free(base_class_name_sanitized);
				rz_vector_free(bases);
				return RZ_ANALYSIS_CLASS_ERR_OTHER;
			}
		}
	}
	RzAnalysisClassErr err = rz_analysis_class_base_set_raw(analysis, class_name, base, base_class_name_sanitized);
	free(base_class_name_sanitized);
	rz_vector_free(bases);
	return err;
}

RZ_API RzAnalysisClassErr rz_analysis_class_base_delete(RzAnalysis *analysis, const char *class_name, const char *base_id) {
	return rz_analysis_class_delete_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE, base_id);
}

typedef struct {
	RzAnalysis *analysis;
	const char *class_name;
} DeleteClassCtx;

static bool rz_analysis_class_base_delete_class_cb(void *user, const char *k, ut32 klen, const char *v, ut32 vlen) {
	(void)v;
	DeleteClassCtx *ctx = user;
	RzVector *bases = rz_analysis_class_base_get_all(ctx->analysis, k);
	RzAnalysisBaseClass *base;
	rz_vector_foreach (bases, base) {
		if (base->class_name && strcmp(base->class_name, ctx->class_name) == 0) {
			rz_analysis_class_base_delete(ctx->analysis, k, base->id);
		}
	}
	rz_vector_free(bases);
	return true;
}

static void rz_analysis_class_base_delete_class(RzAnalysis *analysis, const char *class_name) {
	DeleteClassCtx ctx = { analysis, class_name };
	rz_analysis_class_foreach(analysis, rz_analysis_class_base_delete_class_cb, &ctx);
}

typedef struct {
	RzAnalysis *analysis;
	const char *class_name_old;
	const char *class_name_new;
} RenameClassCtx;

static bool rz_analysis_class_base_rename_class_cb(void *user, const char *k, ut32 klen, const char *v, ut32 vlen) {
	(void)v;
	RenameClassCtx *ctx = user;
	RzVector *bases = rz_analysis_class_base_get_all(ctx->analysis, k);
	RzAnalysisBaseClass *base;
	rz_vector_foreach (bases, base) {
		if (base->class_name && strcmp(base->class_name, ctx->class_name_old) == 0) {
			rz_analysis_class_base_set_raw(ctx->analysis, k, base, ctx->class_name_new);
		}
	}
	rz_vector_free(bases);
	return true;
}

static void rz_analysis_class_base_rename_class(RzAnalysis *analysis, const char *class_name_old, const char *class_name_new) {
	RenameClassCtx ctx = { analysis, class_name_old, class_name_new };
	rz_analysis_class_foreach(analysis, rz_analysis_class_base_rename_class_cb, &ctx);
}

// ---- VTABLE ----

static char *flagname_vtable(const char *class_name, const char *vtable_id) {
	return flagname_attr("vtable", class_name, vtable_id);
}

RZ_API void rz_analysis_class_vtable_fini(RzAnalysisVTable *vtable) {
	free(vtable->id);
}

RZ_API RzAnalysisClassErr rz_analysis_class_vtable_get(RzAnalysis *analysis, const char *class_name, const char *vtable_id, RzAnalysisVTable *vtable) {
	char *content = rz_analysis_class_get_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE, vtable_id, false);
	if (!content) {
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext(cur, &next);

	vtable->addr = rz_num_math(NULL, cur);

	cur = next;
	if (!cur) {
		free(content);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	sdb_anext(cur, &next);

	vtable->offset = rz_num_math(NULL, cur);

	if (next) {
		cur = next;
		sdb_anext(cur, NULL);
		vtable->size = rz_num_get(NULL, cur);
	} else {
		vtable->size = 0;
	}

	free(content);

	vtable->id = rz_str_sanitize_sdb_key(vtable_id);
	if (!vtable->id) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_vtable_fini_proxy(void *e, void *user) {
	(void)user;
	RzAnalysisVTable *vtable = e;
	rz_analysis_class_vtable_fini(vtable);
}

RZ_API RzVector /*<RzAnalysisVTable>*/ *rz_analysis_class_vtable_get_all(RzAnalysis *analysis, const char *class_name) {
	RzVector *vec = rz_vector_new(sizeof(RzAnalysisVTable), rz_analysis_class_vtable_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		rz_vector_free(vec);
		return NULL;
	}
	char *key = key_attr_type_attrs(class_name_sanitized, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE));
	if (!key) {
		rz_vector_free(vec);
		free(class_name_sanitized);
		return NULL;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	free(class_name_sanitized);

	rz_vector_reserve(vec, (size_t)sdb_alen(array));
	char *cur;
	sdb_aforeach(cur, array) {
		RzAnalysisVTable vtable;
		if (rz_analysis_class_vtable_get(analysis, class_name, cur, &vtable) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
			rz_vector_push(vec, &vtable);
		}
		sdb_aforeach_next(cur);
	}
	free(array);

	return vec;
}

RZ_API RzAnalysisClassErr rz_analysis_class_vtable_set(RzAnalysis *analysis, const char *class_name, RzAnalysisVTable *vtable) {
	/* Check if vtable exists before setting it */
	RzVector /*<RzAnalysisVTable>*/ *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *existing_vtable;
		rz_vector_foreach (vtables, existing_vtable) {
			if (vtable->addr == existing_vtable->addr) {
				rz_vector_free(vtables);
				return RZ_ANALYSIS_CLASS_ERR_OTHER;
			}
		}
	}
	rz_vector_free(vtables);

	char *content = rz_str_newf("0x%" PFMT64x SDB_SS "%" PFMT64u SDB_SS "%" PFMT64u, vtable->addr, vtable->offset, vtable->size);
	if (!content) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	if (vtable->id) {
		RzAnalysisClassErr r = rz_analysis_class_set_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE, vtable->id, content);
		free(content);
		return r;
	}

	vtable->id = malloc(16);
	if (!vtable->id) {
		free(content);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err = rz_analysis_class_add_attr_unique(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE, content, vtable->id, 16);
	free(content);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}

	rz_analysis_class_set_flag(analysis, flagname_vtable(class_name, vtable->id), vtable->addr, vtable->size);

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_vtable_rename_class(RzAnalysis *analysis, const char *old_class_name, const char *new_class_name) {
	char *key = key_attr_type_attrs(old_class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE));
	if (!key) {
		return;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		char *old_fn = flagname_vtable(old_class_name, cur);
		char *new_fn = flagname_vtable(new_class_name, cur);
		if (old_fn && new_fn) {
			rz_analysis_class_rename_flag(analysis, old_fn, new_fn);
		}
		free(old_fn);
		free(new_fn);
		sdb_aforeach_next(cur);
	}
	free(array);
}

static void rz_analysis_class_vtable_delete_class(RzAnalysis *analysis, const char *class_name) {
	char *key = key_attr_type_attrs(class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE));
	if (!key) {
		return;
	}
	char *array = sdb_get(analysis->sdb_classes_attrs, key, 0);
	free(key);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		rz_analysis_class_unset_flag(analysis, flagname_vtable(class_name, cur));
		sdb_aforeach_next(cur);
	}
	free(array);
}

RZ_API RzAnalysisClassErr rz_analysis_class_vtable_delete(RzAnalysis *analysis, const char *class_name, const char *vtable_id) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	char *vtable_id_sanitized = rz_str_sanitize_sdb_key(vtable_id);
	if (!vtable_id_sanitized) {
		free(class_name_sanitized);
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err = rz_analysis_class_delete_attr_raw(analysis, class_name_sanitized, RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE, vtable_id_sanitized);
	if (err == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		rz_analysis_class_unset_flag(analysis, flagname_vtable(class_name_sanitized, vtable_id_sanitized));
	}
	free(class_name_sanitized);
	free(vtable_id_sanitized);
	return err;
}

/**
 * @brief Creates RzGraph from class inheritance information where
 *        each node has RzGraphNodeInfo as generic data
 *
 * @param analysis
 * @return RzGraph* NULL if failure
 */
RZ_API RzGraph /*<RzGraphNodeInfo *>*/ *rz_analysis_class_get_inheritance_graph(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzGraph *class_graph = rz_graph_new();
	if (!class_graph) {
		return NULL;
	}
	RzPVector *classes = rz_analysis_class_get_all(analysis, true);
	if (!classes) {
		rz_graph_free(class_graph);
		return NULL;
	}
	HtSP /*<char *name, RzGraphNode *node>*/ *hashmap = ht_sp_new(HT_STR_DUP, NULL, NULL);
	if (!hashmap) {
		goto failure;
	}
	void **iter;
	// Traverse each class and create a node and edges
	rz_pvector_foreach (classes, iter) {
		SdbKv *kv = *iter;
		const char *name = sdbkv_key(kv);
		// create nodes
		RzGraphNode *curr_node = ht_sp_find(hashmap, name, NULL);
		if (!curr_node) {
			curr_node = rz_graph_add_node_info(class_graph, name, NULL, 0);
			if (!curr_node) {
				goto failure;
			}
			ht_sp_insert(hashmap, name, curr_node);
		}
		// create edges between node and it's parents
		RzVector *bases = rz_analysis_class_base_get_all(analysis, name);
		RzAnalysisBaseClass *base;
		rz_vector_foreach (bases, base) {
			bool base_found = false;
			RzGraphNode *base_node = ht_sp_find(hashmap, base->class_name, &base_found);
			// If base isn't processed, do it now
			if (!base_found) {
				base_node = rz_graph_add_node_info(class_graph, base->class_name, NULL, 0);
				if (!base_node) {
					goto failure;
				}
				ht_sp_insert(hashmap, base->class_name, base_node);
			}
			rz_graph_add_edge(class_graph, base_node, curr_node);
		}
		rz_vector_free(bases);
	}
	rz_pvector_free(classes);
	ht_sp_free(hashmap);
	return class_graph;

failure:
	rz_pvector_free(classes);
	ht_sp_free(hashmap);
	rz_graph_free(class_graph);
	return NULL;
}

RZ_API void rz_analysis_class_recover_all(RzAnalysis *analysis) {
	rz_analysis_class_recover_from_rzbin(analysis);
	rz_analysis_rtti_recover_all(analysis);
}
