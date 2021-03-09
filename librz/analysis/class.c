// SPDX-FileCopyrightText: 2018 thestr4ng3r <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_vector.h>
#include <rz_util/rz_graph_drawable.h>
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
	return sdb_fmt("attrtypes.%s", name);
}

static char *key_attr_type_attrs(const char *class_name, const char *attr_type) {
	return sdb_fmt("attr.%s.%s", class_name, attr_type);
}

static char *key_attr_content(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt("attr.%s.%s.%s", class_name, attr_type, attr_id);
}

static char *key_attr_content_specific(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt("attr.%s.%s.%s.specific", class_name, attr_type, attr_id);
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

RZ_API void rz_analysis_class_create(RzAnalysis *analysis, const char *name) {
	char *name_sanitized = rz_str_sanitize_sdb_key(name);
	if (!name_sanitized) {
		return;
	}
	const char *key = key_class(name_sanitized);
	if (!sdb_exists(analysis->sdb_classes, key)) {
		sdb_set(analysis->sdb_classes, key, "c", 0);
	}

	RzEventClass event = { .name = name_sanitized };
	rz_event_send(analysis->ev, RZ_EVENT_CLASS_NEW, &event);

	free(name_sanitized);
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
	char *attr_type_array = sdb_get(analysis->sdb_classes_attrs, key, 0);

	char *attr_type;
	sdb_aforeach(attr_type, attr_type_array) {
		key = key_attr_type_attrs(class_name_sanitized, attr_type);
		char *attr_id_array = sdb_get(analysis->sdb_classes_attrs, key, 0);
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		if (attr_id_array) {
			char *attr_id;
			sdb_aforeach(attr_id, attr_id_array) {
				key = key_attr_content(class_name_sanitized, attr_type, attr_id);
				sdb_remove(analysis->sdb_classes_attrs, key, 0);
				key = key_attr_content_specific(class_name_sanitized, attr_type, attr_id);
				sdb_remove(analysis->sdb_classes_attrs, key, 0);
				sdb_aforeach_next(attr_id);
			}
			free(attr_id_array);
		}
		sdb_aforeach_next(attr_type);
	}
	free(attr_type_array);

	sdb_remove(analysis->sdb_classes_attrs, key_attr_types(class_name_sanitized), 0);

	RzEventClass event = { .name = class_name_sanitized };
	rz_event_send(analysis->ev, RZ_EVENT_CLASS_DEL, &event);

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

RZ_API SdbList *rz_analysis_class_get_all(RzAnalysis *analysis, bool sorted) {
	return sdb_foreach_list(analysis->sdb_classes, sorted);
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

	char *attr_types = sdb_get(analysis->sdb_classes_attrs, key_attr_types(old_name_sanitized), 0);
	char *attr_type_cur;
	sdb_aforeach(attr_type_cur, attr_types) {
		char *attr_ids = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(old_name, attr_type_cur), 0);
		char *attr_id_cur;
		sdb_aforeach(attr_id_cur, attr_ids) {
			rename_key(analysis->sdb_classes_attrs,
				key_attr_content(old_name, attr_type_cur, attr_id_cur),
				key_attr_content(new_name, attr_type_cur, attr_id_cur));
			sdb_aforeach_next(attr_id_cur);
		}
		free(attr_ids);
		rename_key(analysis->sdb_classes_attrs,
			key_attr_type_attrs(old_name, attr_type_cur),
			key_attr_type_attrs(new_name, attr_type_cur));
		sdb_aforeach_next(attr_type_cur);
	}
	free(attr_types);

	rename_key(analysis->sdb_classes_attrs, key_attr_types(old_name_sanitized), key_attr_types(new_name_sanitized));

	RzEventClassRename event = {
		.name_old = old_name_sanitized,
		.name_new = new_name_sanitized
	};
	rz_event_send(analysis->ev, RZ_EVENT_CLASS_RENAME, &event);

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
	char *ret = sdb_get(analysis->sdb_classes_attrs, key, 0);
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

	sdb_array_add(analysis->sdb_classes_attrs, key_attr_types(class_name), attr_type_str, 0);
	sdb_array_add(analysis->sdb_classes_attrs, key_attr_type_attrs(class_name, attr_type_str), attr_id, 0);
	sdb_set(analysis->sdb_classes_attrs, key_attr_content(class_name, attr_type_str, attr_id), content, 0);

	RzEventClassAttrSet event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id },
		.content = content
	};
	rz_event_send(analysis->ev, RZ_EVENT_CLASS_ATTR_SET, &event);

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
	sdb_remove(analysis->sdb_classes_attrs, key, 0);
	key = key_attr_content_specific(class_name, attr_type_str, attr_id);
	sdb_remove(analysis->sdb_classes_attrs, key, 0);

	key = key_attr_type_attrs(class_name, attr_type_str);
	sdb_array_remove(analysis->sdb_classes_attrs, key, attr_id, 0);
	if (!sdb_exists(analysis->sdb_classes_attrs, key)) {
		sdb_array_remove(analysis->sdb_classes_attrs, key_attr_types(class_name), attr_type_str, 0);
	}

	RzEventClassAttr event = {
		.class_name = class_name,
		.attr_type = attr_type,
		.attr_id = attr_id
	};
	rz_event_send(analysis->ev, RZ_EVENT_CLASS_ATTR_DEL, &event);

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

	if (sdb_array_contains(analysis->sdb_classes_attrs, key, attr_id_new, 0)) {
		return RZ_ANALYSIS_CLASS_ERR_CLASH;
	}

	if (!sdb_array_remove(analysis->sdb_classes_attrs, key, attr_id_old, 0)) {
		return RZ_ANALYSIS_CLASS_ERR_NONEXISTENT_ATTR;
	}

	sdb_array_add(analysis->sdb_classes_attrs, key, attr_id_new, 0);

	key = key_attr_content(class_name, attr_type_str, attr_id_old);
	char *content = sdb_get(analysis->sdb_classes_attrs, key, 0);
	if (content) {
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		key = key_attr_content(class_name, attr_type_str, attr_id_new);
		sdb_set(analysis->sdb_classes_attrs, key, content, 0);
		free(content);
	}

	key = key_attr_content_specific(class_name, attr_type_str, attr_id_old);
	content = sdb_get(analysis->sdb_classes_attrs, key, 0);
	if (content) {
		sdb_remove(analysis->sdb_classes_attrs, key, 0);
		key = key_attr_content_specific(class_name, attr_type_str, attr_id_new);
		sdb_set(analysis->sdb_classes_attrs, key, content, 0);
		free(content);
	}

	RzEventClassAttrRename event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id_old },
		.attr_id_new = attr_id_new
	};
	rz_event_send(analysis->ev, RZ_EVENT_CLASS_ATTR_RENAME, &event);

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
	do {
		snprintf(out, out_size, "%" PFMT64u, id);
		id++;
	} while (sdb_array_contains(analysis->sdb_classes_attrs, key, out, 0));
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
	char *r = sdb_fmt("%s.%s.%s", attr_type, class_name, attr_id);
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
	return flagname_attr("method", class_name, meth_name);
}

RZ_API void rz_analysis_class_method_fini(RzAnalysisMethod *meth) {
	free(meth->name);
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
	sdb_anext(cur, NULL);

	meth->vtable_offset = atoll(cur);

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
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(class_name_sanitized, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD)), 0);
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
	char *content = sdb_fmt("%" PFMT64u "%c%" PFMT64d, meth->addr, SDB_RS, meth->vtable_offset);
	RzAnalysisClassErr err = rz_analysis_class_set_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, meth->name, content);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}
	rz_analysis_class_set_flag(analysis, flagname_method(class_name, meth->name), meth->addr, 0);
	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

RZ_API RzAnalysisClassErr rz_analysis_class_method_rename(RzAnalysis *analysis, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	RzAnalysisClassErr err = rz_analysis_class_rename_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD, old_meth_name, new_meth_name);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}
	rz_analysis_class_rename_flag(analysis,
		flagname_method(class_name, old_meth_name),
		flagname_method(class_name, new_meth_name));
	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_method_rename_class(RzAnalysis *analysis, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(old_class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		rz_analysis_class_rename_flag(analysis,
			flagname_method(old_class_name, cur),
			flagname_method(new_class_name, cur));
		sdb_aforeach_next(cur);
	}
	free(array);
}

static void rz_analysis_class_method_delete_class(RzAnalysis *analysis, const char *class_name) {
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		rz_analysis_class_unset_flag(analysis, flagname_method(class_name, cur));
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
		rz_analysis_class_unset_flag(analysis, flagname_method(class_name_sanitized, meth_name_sanitized));
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
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(class_name_sanitized, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_BASE)), 0);
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
	char *content = sdb_fmt("%s" SDB_SS "%" PFMT64u, base_class_name_sanitized, base->offset);
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
		rz_vector_foreach(bases, existing_base) {
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

static bool rz_analysis_class_base_delete_class_cb(void *user, const char *k, const char *v) {
	(void)v;
	DeleteClassCtx *ctx = user;
	RzVector *bases = rz_analysis_class_base_get_all(ctx->analysis, k);
	RzAnalysisBaseClass *base;
	rz_vector_foreach(bases, base) {
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

static bool rz_analysis_class_base_rename_class_cb(void *user, const char *k, const char *v) {
	(void)v;
	RenameClassCtx *ctx = user;
	RzVector *bases = rz_analysis_class_base_get_all(ctx->analysis, k);
	RzAnalysisBaseClass *base;
	rz_vector_foreach(bases, base) {
		if (base->class_name && strcmp(base->class_name, ctx->class_name_old) == 0) {
			rz_analysis_class_base_set_raw(ctx->analysis, k, base, ctx->class_name_new);
		}
	}
	rz_vector_free(bases);
	return 1;
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
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(class_name_sanitized, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE)), 0);
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
	char *content = sdb_fmt("0x%" PFMT64x SDB_SS "%" PFMT64u SDB_SS "%" PFMT64u, vtable->addr, vtable->offset, vtable->size);
	if (vtable->id) {
		return rz_analysis_class_set_attr(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE, vtable->id, content);
	}
	vtable->id = malloc(16);
	if (!vtable->id) {
		return RZ_ANALYSIS_CLASS_ERR_OTHER;
	}
	RzAnalysisClassErr err = rz_analysis_class_add_attr_unique(analysis, class_name, RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE, content, vtable->id, 16);
	if (err != RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
		return err;
	}

	rz_analysis_class_set_flag(analysis, flagname_vtable(class_name, vtable->id), vtable->addr, vtable->size);

	return RZ_ANALYSIS_CLASS_ERR_SUCCESS;
}

static void rz_analysis_class_vtable_rename_class(RzAnalysis *analysis, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(old_class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach(cur, array) {
		rz_analysis_class_rename_flag(analysis,
			flagname_vtable(old_class_name, cur),
			flagname_vtable(new_class_name, cur));
		sdb_aforeach_next(cur);
	}
	free(array);
}

static void rz_analysis_class_vtable_delete_class(RzAnalysis *analysis, const char *class_name) {
	char *array = sdb_get(analysis->sdb_classes_attrs, key_attr_type_attrs(class_name, attr_type_id(RZ_ANALYSIS_CLASS_ATTR_TYPE_VTABLE)), 0);
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

// ---- PRINT ----

RZ_API void rz_analysis_class_print(RzAnalysis *analysis, const char *class_name, bool detailed) {
	rz_cons_print(class_name);

	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		bool first = true;
		rz_vector_foreach(bases, base) {
			if (first) {
				rz_cons_print(": ");
				first = false;
			} else {
				rz_cons_print(", ");
			}
			rz_cons_print(base->class_name);
		}
		rz_vector_free(bases);
	}

	rz_cons_print("\n");

	if (detailed) {
		RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
		if (vtables) {
			RzAnalysisVTable *vtable;
			rz_vector_foreach(vtables, vtable) {
				rz_cons_printf("  (vtable at 0x%" PFMT64x, vtable->addr);
				if (vtable->offset > 0) {
					rz_cons_printf(" in class at +0x%" PFMT64x ")\n", vtable->offset);
				} else {
					rz_cons_print(")\n");
				}
			}
			rz_vector_free(vtables);
		}

		RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
		if (methods) {
			RzAnalysisMethod *meth;
			rz_vector_foreach(methods, meth) {
				rz_cons_printf("  %s @ 0x%" PFMT64x, meth->name, meth->addr);
				if (meth->vtable_offset >= 0) {
					rz_cons_printf(" (vtable + 0x%" PFMT64x ")\n", (ut64)meth->vtable_offset);
				} else {
					rz_cons_print("\n");
				}
			}
			rz_vector_free(methods);
		}
	}
}

static void rz_analysis_class_print_cmd(RzAnalysis *analysis, const char *class_name) {
	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		rz_vector_foreach(bases, base) {
			rz_cons_printf("acb %s %s %" PFMT64u "\n", class_name, base->class_name, base->offset);
		}
		rz_vector_free(bases);
	}

	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach(vtables, vtable) {
			rz_cons_printf("acv %s 0x%" PFMT64x " %" PFMT64u "\n", class_name, vtable->addr, vtable->offset);
		}
		rz_vector_free(vtables);
	}

	RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
	if (methods) {
		RzAnalysisMethod *meth;
		rz_vector_foreach(methods, meth) {
			rz_cons_printf("acm %s %s 0x%" PFMT64x " %" PFMT64d "\n", class_name, meth->name, meth->addr, meth->vtable_offset);
		}
		rz_vector_free(methods);
	}
}

RZ_API void rz_analysis_class_json(RzAnalysis *analysis, PJ *j, const char *class_name) {
	pj_o(j);
	pj_ks(j, "name", class_name);

	pj_k(j, "bases");
	pj_a(j);
	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	if (bases) {
		RzAnalysisBaseClass *base;
		rz_vector_foreach(bases, base) {
			pj_o(j);
			pj_ks(j, "id", base->id);
			pj_ks(j, "name", base->class_name);
			pj_kn(j, "offset", base->offset);
			pj_end(j);
		}
		rz_vector_free(bases);
	}
	pj_end(j);

	pj_k(j, "vtables");
	pj_a(j);
	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach(vtables, vtable) {
			pj_o(j);
			pj_ks(j, "id", vtable->id);
			pj_kn(j, "addr", vtable->addr);
			pj_kn(j, "offset", vtable->offset);
			pj_end(j);
		}
	}
	pj_end(j);

	pj_k(j, "methods");
	pj_a(j);
	RzVector *methods = rz_analysis_class_method_get_all(analysis, class_name);
	if (methods) {
		RzAnalysisMethod *meth;
		rz_vector_foreach(methods, meth) {
			pj_o(j);
			pj_ks(j, "name", meth->name);
			pj_kn(j, "addr", meth->addr);
			if (meth->vtable_offset >= 0) {
				pj_kn(j, "vtable_offset", (ut64)meth->vtable_offset);
			}
			pj_end(j);
		}
		rz_vector_free(methods);
	}
	pj_end(j);

	pj_end(j);
}

typedef struct {
	RzAnalysis *analysis;
	PJ *j;
} ListJsonCtx;

static bool rz_analysis_class_list_json_cb(void *user, const char *k, const char *v) {
	ListJsonCtx *ctx = user;
	rz_analysis_class_json(ctx->analysis, ctx->j, k);
	return true;
}

static void rz_analysis_class_list_json(RzAnalysis *analysis) {
	PJ *j = analysis->coreb.pjWithEncoding(analysis->coreb.core);
	if (!j) {
		return;
	}
	pj_a(j);

	ListJsonCtx ctx;
	ctx.analysis = analysis;
	ctx.j = j;
	rz_analysis_class_foreach(analysis, rz_analysis_class_list_json_cb, &ctx);

	pj_end(j);
	rz_cons_printf("%s\n", pj_string(j));
	pj_free(j);
}

RZ_API void rz_analysis_class_list(RzAnalysis *analysis, int mode) {
	if (mode == 'j') {
		rz_analysis_class_list_json(analysis);
		return;
	}

	SdbList *classes = rz_analysis_class_get_all(analysis, mode != '*');
	SdbListIter *iter;
	SdbKv *kv;
	if (mode == '*') {
		ls_foreach (classes, iter, kv) {
			// need to create all classes first, so they can be referenced
			rz_cons_printf("ac %s\n", sdbkv_key(kv));
		}
		ls_foreach (classes, iter, kv) {
			rz_analysis_class_print_cmd(analysis, sdbkv_key(kv));
		}
	} else {
		ls_foreach (classes, iter, kv) {
			rz_analysis_class_print(analysis, sdbkv_key(kv), mode == 'l');
		}
	}
	ls_free(classes);
}

RZ_API void rz_analysis_class_list_bases(RzAnalysis *analysis, const char *class_name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!rz_analysis_class_exists_raw(analysis, class_name_sanitized)) {
		free(class_name_sanitized);
		return;
	}
	rz_cons_printf("%s:\n", class_name_sanitized);
	free(class_name_sanitized);

	RzVector *bases = rz_analysis_class_base_get_all(analysis, class_name);
	RzAnalysisBaseClass *base;
	rz_vector_foreach(bases, base) {
		rz_cons_printf("  %4s %s @ +0x%" PFMT64x "\n", base->id, base->class_name, base->offset);
	}
	rz_vector_free(bases);
}

RZ_API void rz_analysis_class_list_vtables(RzAnalysis *analysis, const char *class_name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!rz_analysis_class_exists_raw(analysis, class_name_sanitized)) {
		free(class_name_sanitized);
		return;
	}
	rz_cons_printf("%s:\n", class_name_sanitized);
	free(class_name_sanitized);

	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	if (vtables) {
		RzAnalysisVTable *vtable;
		rz_vector_foreach(vtables, vtable) {
			rz_cons_printf("  %4s vtable 0x%" PFMT64x " @ +0x%" PFMT64x " size:+0x%" PFMT64x "\n", vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		rz_vector_free(vtables);
	}
}

static void list_all_functions_at_vtable_offset(RzAnalysis *analysis, const char *class_name, ut64 offset) {
	RVTableContext vtableContext;
	rz_analysis_vtable_begin(analysis, &vtableContext);
	ut8 function_ptr_size = vtableContext.word_size;

	ut64 func_address;
	RzVector *vtables = rz_analysis_class_vtable_get_all(analysis, class_name);
	RzAnalysisVTable *vtable;

	if (!vtables) {
		return;
	}

	rz_vector_foreach(vtables, vtable) {
		if (vtable->size < offset + function_ptr_size) {
			continue;
		}

		if (vtableContext.read_addr(analysis, vtable->addr + offset, &func_address))
			rz_cons_printf("Function address: 0x%08" PFMT64x ", in %s vtable %s\n", func_address, class_name, vtable->id);
	}
	rz_vector_free(vtables);
}

RZ_API void rz_analysis_class_list_vtable_offset_functions(RzAnalysis *analysis, const char *class_name, ut64 offset) {
	if (class_name) {
		char *class_name_sanitized = rz_str_sanitize_sdb_key(class_name);
		if (!class_name_sanitized) {
			return;
		}
		if (!rz_analysis_class_exists_raw(analysis, class_name_sanitized)) {
			free(class_name_sanitized);
			return;
		}
		free(class_name_sanitized);

		list_all_functions_at_vtable_offset(analysis, class_name, offset);
	} else {
		SdbList *classes = rz_analysis_class_get_all(analysis, true);
		SdbListIter *iter;
		SdbKv *kv;
		ls_foreach (classes, iter, kv) {
			const char *name = sdbkv_key(kv);
			list_all_functions_at_vtable_offset(analysis, name, offset);
		}
		ls_free(classes);
	}
}

/**
 * @brief Creates RzGraph from class inheritance information where 
 *        each node has RzGraphNodeInfo as generic data
 * 
 * @param analysis 
 * @return RzGraph* NULL if failure
 */
RZ_API RzGraph *rz_analysis_class_get_inheritance_graph(RzAnalysis *analysis) {
	rz_return_val_if_fail(analysis, NULL);
	RzGraph *class_graph = rz_graph_new();
	if (!class_graph) {
		return NULL;
	}
	SdbList *classes = rz_analysis_class_get_all(analysis, true);
	if (!classes) {
		rz_graph_free(class_graph);
		return NULL;
	}
	HtPP /*<char *name, RzGraphNode *node>*/ *hashmap = ht_pp_new0();
	if (!hashmap) {
		rz_graph_free(class_graph);
		ls_free(classes);
		return NULL;
	}
	SdbListIter *iter;
	SdbKv *kv;
	// Traverse each class and create a node and edges
	ls_foreach (classes, iter, kv) {
		const char *name = sdbkv_key(kv);
		// create nodes
		RzGraphNode *curr_node = ht_pp_find(hashmap, name, NULL);
		if (!curr_node) {
			curr_node = rz_graph_add_node_info(class_graph, name, NULL, 0);
			if (!curr_node) {
				goto failure;
			}
			ht_pp_insert(hashmap, name, curr_node);
		}
		// create edges between node and it's parents
		RzVector *bases = rz_analysis_class_base_get_all(analysis, name);
		RzAnalysisBaseClass *base;
		rz_vector_foreach(bases, base) {
			bool base_found = false;
			RzGraphNode *base_node = ht_pp_find(hashmap, base->class_name, &base_found);
			// If base isn't processed, do it now
			if (!base_found) {
				base_node = rz_graph_add_node_info(class_graph, base->class_name, NULL, 0);
				if (!base_node) {
					goto failure;
				}
				ht_pp_insert(hashmap, base->class_name, base_node);
			}
			rz_graph_add_edge(class_graph, base_node, curr_node);
		}
		rz_vector_free(bases);
	}
	ls_free(classes);
	ht_pp_free(hashmap);
	return class_graph;

failure:
	ls_free(classes);
	ht_pp_free(hashmap);
	rz_graph_free(class_graph);
	return NULL;
}
