/* radare - LGPL - Copyright 2018 - thestr4ng3r */

#include <rz_anal.h>
#include <rz_vector.h>
#include <rz_util/rz_graph_drawable.h>
#include "../include/rz_anal.h"
#include "../include/rz_util/rz_graph.h"

static void rz_anal_class_base_delete_class(RzAnal *anal, const char *class_name);
static void rz_anal_class_method_delete_class(RzAnal *anal, const char *class_name);
static void rz_anal_class_vtable_delete_class(RzAnal *anal, const char *class_name);
static void rz_anal_class_base_rename_class(RzAnal *anal, const char *class_name_old, const char *class_name_new);
static void rz_anal_class_method_rename_class(RzAnal *anal, const char *old_class_name, const char *new_class_name);
static void rz_anal_class_vtable_rename_class(RzAnal *anal, const char *old_class_name, const char *new_class_name);

static const char *key_class(const char *name) {
	return name;
}

static char *key_attr_types(const char *name) {
	return sdb_fmt ("attrtypes.%s", name);
}

static char *key_attr_type_attrs(const char *class_name, const char *attr_type) {
	return sdb_fmt ("attr.%s.%s", class_name, attr_type);
}

static char *key_attr_content(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt ("attr.%s.%s.%s", class_name, attr_type, attr_id);
}

static char *key_attr_content_specific(const char *class_name, const char *attr_type, const char *attr_id) {
	return sdb_fmt ("attr.%s.%s.%s.specific", class_name, attr_type, attr_id);
}

typedef enum {
	RZ_ANAL_CLASS_ATTR_TYPE_METHOD,
	RZ_ANAL_CLASS_ATTR_TYPE_VTABLE,
	RZ_ANAL_CLASS_ATTR_TYPE_BASE
} RzAnalClassAttrType;

static const char *attr_type_id(RzAnalClassAttrType attr_type) {
	switch (attr_type) {
	case RZ_ANAL_CLASS_ATTR_TYPE_METHOD:
		return "method";
	case RZ_ANAL_CLASS_ATTR_TYPE_VTABLE:
		return "vtable";
	case RZ_ANAL_CLASS_ATTR_TYPE_BASE:
		return "base";
	default:
		return NULL;
	}
}

RZ_API void rz_anal_class_create(RzAnal *anal, const char *name) {
	char *name_sanitized = rz_str_sanitize_sdb_key (name);
	if (!name_sanitized) {
		return;
	}
	const char *key = key_class (name_sanitized);
	if (!sdb_exists (anal->sdb_classes, key)) {
		sdb_set (anal->sdb_classes, key, "c", 0);
	}

	REventClass event = { .name = name_sanitized };
	rz_event_send (anal->ev, RZ_EVENT_CLASS_NEW, &event);

	free (name_sanitized);
}


RZ_API void rz_anal_class_delete(RzAnal *anal, const char *name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (name);
	if (!class_name_sanitized) {
		return;
	}

	rz_anal_class_base_delete_class (anal, class_name_sanitized);
	rz_anal_class_method_delete_class (anal, class_name_sanitized);
	rz_anal_class_vtable_delete_class (anal, class_name_sanitized);

	if (!sdb_remove (anal->sdb_classes, key_class (class_name_sanitized), 0)) {
		free (class_name_sanitized);
		return;
	}

	char *key = key_attr_types (class_name_sanitized);
	char *attr_type_array = sdb_get (anal->sdb_classes_attrs, key, 0);

	char *attr_type;
	sdb_aforeach (attr_type, attr_type_array) {
		key = key_attr_type_attrs (class_name_sanitized, attr_type);
		char *attr_id_array = sdb_get (anal->sdb_classes_attrs, key, 0);
		sdb_remove (anal->sdb_classes_attrs, key, 0);
		if (attr_id_array) {
			char *attr_id;
			sdb_aforeach (attr_id, attr_id_array) {
				key = key_attr_content (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes_attrs, key, 0);
				key = key_attr_content_specific (class_name_sanitized, attr_type, attr_id);
				sdb_remove (anal->sdb_classes_attrs, key, 0);
				sdb_aforeach_next (attr_id);
			}
			free (attr_id_array);
		}
		sdb_aforeach_next (attr_type);
	}
	free (attr_type_array);

	sdb_remove (anal->sdb_classes_attrs, key_attr_types (class_name_sanitized), 0);

	REventClass event = { .name = class_name_sanitized };
	rz_event_send (anal->ev, RZ_EVENT_CLASS_DEL, &event);

	free (class_name_sanitized);
}

static bool rz_anal_class_exists_raw(RzAnal *anal, const char *name) {
	return sdb_exists (anal->sdb_classes, key_class (name));
}

RZ_API bool rz_anal_class_exists(RzAnal *anal, const char *name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (name);
	if (!class_name_sanitized) {
		return false;
	}
	bool r = rz_anal_class_exists_raw (anal, class_name_sanitized);
	free (class_name_sanitized);
	return r;
}

RZ_API SdbList *rz_anal_class_get_all(RzAnal *anal, bool sorted) {
	return sdb_foreach_list (anal->sdb_classes, sorted);
}

RZ_API void rz_anal_class_foreach(RzAnal *anal, SdbForeachCallback cb, void *user) {
	sdb_foreach (anal->sdb_classes, cb, user);
}

static bool rename_key(Sdb *sdb, const char *key_old, const char *key_new) {
	char *content = sdb_get (sdb, key_old, 0);
	if (!content) {
		return false;
	}
	sdb_remove (sdb, key_old, 0);
	sdb_set (sdb, key_new, content, 0);
	free (content);
	return true;
}

RZ_API RzAnalClassErr rz_anal_class_rename(RzAnal *anal, const char *old_name, const char *new_name) {
	if (rz_anal_class_exists (anal, new_name)) {
		return RZ_ANAL_CLASS_ERR_CLASH;
	}

	char *old_name_sanitized = rz_str_sanitize_sdb_key (old_name);
	if (!old_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	char *new_name_sanitized = rz_str_sanitize_sdb_key (new_name);
	if (!new_name_sanitized) {
		free (old_name_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	RzAnalClassErr err = RZ_ANAL_CLASS_ERR_SUCCESS;

	rz_anal_class_base_rename_class (anal, old_name, new_name);
	rz_anal_class_method_rename_class (anal, old_name, new_name);
	rz_anal_class_vtable_rename_class (anal, old_name, new_name);

	if (!rename_key (anal->sdb_classes, key_class (old_name_sanitized), key_class (new_name_sanitized))) {
		err = RZ_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
		goto beach;
	}

	char *attr_types = sdb_get (anal->sdb_classes_attrs, key_attr_types (old_name_sanitized), 0);
	char *attr_type_cur;
	sdb_aforeach (attr_type_cur, attr_types) {
		char *attr_ids = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (old_name, attr_type_cur), 0);
		char *attr_id_cur;
		sdb_aforeach (attr_id_cur, attr_ids) {
			rename_key (anal->sdb_classes_attrs,
					key_attr_content (old_name, attr_type_cur, attr_id_cur),
					key_attr_content (new_name, attr_type_cur, attr_id_cur));
			sdb_aforeach_next (attr_id_cur);
		}
		free (attr_ids);
		rename_key (anal->sdb_classes_attrs,
				key_attr_type_attrs (old_name, attr_type_cur),
				key_attr_type_attrs (new_name, attr_type_cur));
		sdb_aforeach_next (attr_type_cur);
	}
	free (attr_types);

	rename_key (anal->sdb_classes_attrs, key_attr_types (old_name_sanitized), key_attr_types (new_name_sanitized));

	REventClassRename event = {
		.name_old = old_name_sanitized,
		.name_new = new_name_sanitized
	};
	rz_event_send (anal->ev, RZ_EVENT_CLASS_RENAME, &event);

beach:
	free (old_name_sanitized);
	free (new_name_sanitized);
	return err;
}

// all ids must be sanitized
static char *rz_anal_class_get_attr_raw(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = specific
			? key_attr_content_specific (class_name, attr_type_str, attr_id)
			: key_attr_content (class_name, attr_type_str, attr_id);
	char *ret = sdb_get (anal->sdb_classes_attrs, key, 0);
	return ret;
}

// ids will be sanitized automatically
static char *rz_anal_class_get_attr(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id, bool specific) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return false;
	}
	char *attr_id_sanitized = rz_str_sanitize_sdb_key (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return false;
	}

	char *ret = rz_anal_class_get_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, specific);

	free (class_name_sanitized);
	free (attr_id_sanitized);

	return ret;
}

// all ids must be sanitized
static RzAnalClassErr rz_anal_class_set_attr_raw(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	const char *attr_type_str = attr_type_id (attr_type);

	if (!rz_anal_class_exists_raw (anal, class_name)) {
		return RZ_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}

	sdb_array_add (anal->sdb_classes_attrs, key_attr_types (class_name), attr_type_str, 0);
	sdb_array_add (anal->sdb_classes_attrs, key_attr_type_attrs (class_name, attr_type_str), attr_id, 0);
	sdb_set (anal->sdb_classes_attrs, key_attr_content (class_name, attr_type_str, attr_id), content, 0);

	REventClassAttrSet event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id
		},
		.content = content
	};
	rz_event_send (anal->ev, RZ_EVENT_CLASS_ATTR_SET, &event);

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

// ids will be sanitized automatically
static RzAnalClassErr rz_anal_class_set_attr(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id, const char *content) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = rz_str_sanitize_sdb_key (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	RzAnalClassErr err = rz_anal_class_set_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized, content);

	free (class_name_sanitized);
	free (attr_id_sanitized);

	return err;
}

static RzAnalClassErr rz_anal_class_delete_attr_raw(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id) {
	const char *attr_type_str = attr_type_id (attr_type);

	char *key = key_attr_content (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes_attrs, key, 0);
	key = key_attr_content_specific (class_name, attr_type_str, attr_id);
	sdb_remove (anal->sdb_classes_attrs, key, 0);

	key = key_attr_type_attrs (class_name, attr_type_str);
	sdb_array_remove (anal->sdb_classes_attrs, key, attr_id, 0);
	if (!sdb_exists (anal->sdb_classes_attrs, key)) {
		sdb_array_remove (anal->sdb_classes_attrs, key_attr_types (class_name), attr_type_str, 0);
	}

	REventClassAttr event = {
		.class_name = class_name,
		.attr_type = attr_type,
		.attr_id = attr_id
	};
	rz_event_send (anal->ev, RZ_EVENT_CLASS_ATTR_DEL, &event);

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static RzAnalClassErr rz_anal_class_delete_attr(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	char *attr_id_sanitized = rz_str_sanitize_sdb_key (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	RzAnalClassErr err = rz_anal_class_delete_attr_raw (anal, class_name_sanitized, attr_type, attr_id_sanitized);

	free (class_name_sanitized);
	free (attr_id_sanitized);
	return err;
}

static RzAnalClassErr rz_anal_class_rename_attr_raw(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	const char *attr_type_str = attr_type_id (attr_type);
	char *key = key_attr_type_attrs (class_name, attr_type_str);

	if (sdb_array_contains (anal->sdb_classes_attrs, key, attr_id_new, 0)) {
		return RZ_ANAL_CLASS_ERR_CLASH;
	}

	if (!sdb_array_remove (anal->sdb_classes_attrs, key, attr_id_old, 0)) {
		return RZ_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	sdb_array_add (anal->sdb_classes_attrs, key, attr_id_new, 0);

	key = key_attr_content (class_name, attr_type_str, attr_id_old);
	char *content = sdb_get (anal->sdb_classes_attrs, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes_attrs, key, 0);
		key = key_attr_content (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes_attrs, key, content, 0);
		free (content);
	}

	key = key_attr_content_specific (class_name, attr_type_str, attr_id_old);
	content = sdb_get (anal->sdb_classes_attrs, key, 0);
	if (content) {
		sdb_remove (anal->sdb_classes_attrs, key, 0);
		key = key_attr_content_specific (class_name, attr_type_str, attr_id_new);
		sdb_set (anal->sdb_classes_attrs, key, content, 0);
		free (content);
	}

	REventClassAttrRename event = {
		.attr = {
			.class_name = class_name,
			.attr_type = attr_type,
			.attr_id = attr_id_old
		},
		.attr_id_new = attr_id_new
	};
	rz_event_send (anal->ev, RZ_EVENT_CLASS_ATTR_RENAME, &event);

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static RzAnalClassErr rz_anal_class_rename_attr(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *attr_id_old, const char *attr_id_new) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_old_sanitized = rz_str_sanitize_sdb_key (attr_id_old);
	if (!attr_id_old_sanitized) {
		free (class_name_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	char *attr_id_new_sanitized = rz_str_sanitize_sdb_key (attr_id_new);
	if (!attr_id_new_sanitized) {
		free (class_name_sanitized);
		free (attr_id_old_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	RzAnalClassErr ret = rz_anal_class_rename_attr_raw (anal, class_name_sanitized, attr_type, attr_id_old_sanitized, attr_id_new_sanitized);
	free (class_name_sanitized);
	free (attr_id_old_sanitized);
	free (attr_id_new_sanitized);
	return ret;
}

static void rz_anal_class_unique_attr_id_raw(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, char *out, size_t out_size) {
	ut64 id = 0;
	char *key = key_attr_type_attrs (class_name, attr_type_id (attr_type));
	do {
		snprintf (out, out_size, "%"PFMT64u, id);
		id++;
	} while (sdb_array_contains (anal->sdb_classes_attrs, key, out, 0));
}

static char *flagname_attr(const char *attr_type, const char *class_name, const char *attr_id) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return NULL;
	}
	char *attr_id_sanitized = rz_str_sanitize_sdb_key (attr_id);
	if (!attr_id_sanitized) {
		free (class_name_sanitized);
		return NULL;
	}
	char *r = sdb_fmt ("%s.%s.%s", attr_type, class_name, attr_id);
	free (class_name_sanitized);
	free (attr_id_sanitized);
	return r;
}

static void rz_anal_class_set_flag(RzAnal *anal, const char *name, ut64 addr, ut32 size) {
	if (!name || !anal->flg_class_set) {
		return;
	}
	anal->flg_class_set (anal->flb.f, name, addr, size);
}

static void rz_anal_class_unset_flag(RzAnal *anal, const char *name) {
	if (!name || !anal->flb.unset_name || !anal->flg_class_get) {
		return;
	}
	if (anal->flg_class_get (anal->flb.f, name)) {
		anal->flb.unset_name (anal->flb.f, name);
	}
}

static void rz_anal_class_rename_flag(RzAnal *anal, const char *old_name, const char *new_name) {
	if (!old_name || !new_name || !anal->flb.unset || !anal->flg_class_get || !anal->flg_class_set) {
		return;
	}
	RzFlagItem *flag = anal->flg_class_get (anal->flb.f, old_name);
	if (!flag) {
		return;
	}
	ut64 addr = flag->offset;
	anal->flb.unset (anal->flb.f, flag);
	anal->flg_class_set (anal->flb.f, new_name, addr, 0);
}

static RzAnalClassErr rz_anal_class_add_attr_unique_raw(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char attr_id[16];
	rz_anal_class_unique_attr_id_raw (anal, class_name, attr_type, attr_id, sizeof(attr_id));

	RzAnalClassErr err = rz_anal_class_set_attr (anal, class_name, attr_type, attr_id, content);
	if (err != RZ_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	if (attr_id_out) {
		rz_str_ncpy (attr_id_out, attr_id, attr_id_out_size);
	}

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static RzAnalClassErr rz_anal_class_add_attr_unique(RzAnal *anal, const char *class_name, RzAnalClassAttrType attr_type, const char *content, char *attr_id_out, size_t attr_id_out_size) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	RzAnalClassErr err = rz_anal_class_add_attr_unique_raw (anal, class_name_sanitized, attr_type, content, attr_id_out, attr_id_out_size);

	free (class_name_sanitized);
	return err;
}


// ---- METHODS ----
// Format: addr,vtable_offset

static char *flagname_method(const char *class_name, const char *meth_name) {
	return flagname_attr ("method", class_name, meth_name);
}

RZ_API void rz_anal_class_method_fini(RzAnalMethod *meth) {
	free (meth->name);
}

// if the method exists: store it in *meth and return RZ_ANAL_CLASS_ERR_SUCCESS
// else return the error, contents of *meth are undefined
RZ_API RzAnalClassErr rz_anal_class_method_get(RzAnal *anal, const char *class_name, const char *meth_name, RzAnalMethod *meth) {
	char *content = rz_anal_class_get_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name, false);
	if (!content) {
		return RZ_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	meth->addr = rz_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	meth->vtable_offset = atoi (cur);

	free (content);

	meth->name = rz_str_sanitize_sdb_key (meth_name);
	if (!meth->name) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static void rz_anal_class_method_fini_proxy(void *e, void *user) {
	(void)user;
	RzAnalMethod *meth = e;
	rz_anal_class_method_fini (meth);
}

RZ_API RzVector/*<RzAnalMethod>*/ *rz_anal_class_method_get_all(RzAnal *anal, const char *class_name) {
	RzVector *vec = rz_vector_new (sizeof(RzAnalMethod), rz_anal_class_method_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		rz_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (class_name_sanitized, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	free (class_name_sanitized);

	rz_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RzAnalMethod meth;
		if (rz_anal_class_method_get (anal, class_name, cur, &meth) == RZ_ANAL_CLASS_ERR_SUCCESS) {
			rz_vector_push (vec, &meth);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

RZ_API RzAnalClassErr rz_anal_class_method_set(RzAnal *anal, const char *class_name, RzAnalMethod *meth) {
	char *content = sdb_fmt ("%"PFMT64u"%c%d", meth->addr, SDB_RS, meth->vtable_offset);
	RzAnalClassErr err = rz_anal_class_set_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_METHOD, meth->name, content);
	if (err != RZ_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}
	rz_anal_class_set_flag (anal, flagname_method (class_name, meth->name), meth->addr, 0);
	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

RZ_API RzAnalClassErr rz_anal_class_method_rename(RzAnal *anal, const char *class_name, const char *old_meth_name, const char *new_meth_name) {
	RzAnalClassErr err = rz_anal_class_rename_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_METHOD, old_meth_name, new_meth_name);
	if (err != RZ_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}
	rz_anal_class_rename_flag (anal,
			flagname_method (class_name, old_meth_name),
			flagname_method (class_name, new_meth_name));
	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static void rz_anal_class_method_rename_class(RzAnal *anal, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (old_class_name, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		rz_anal_class_rename_flag (anal,
				flagname_method (old_class_name, cur),
				flagname_method (new_class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

static void rz_anal_class_method_delete_class(RzAnal *anal, const char *class_name) {
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (class_name, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_METHOD)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		rz_anal_class_unset_flag (anal, flagname_method (class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

RZ_API RzAnalClassErr rz_anal_class_method_delete(RzAnal *anal, const char *class_name, const char *meth_name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	char *meth_name_sanitized = rz_str_sanitize_sdb_key (meth_name);
	if (!meth_name_sanitized) {
		free (class_name_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	RzAnalClassErr err = rz_anal_class_delete_attr_raw (anal, class_name_sanitized, RZ_ANAL_CLASS_ATTR_TYPE_METHOD, meth_name_sanitized);
	if (err == RZ_ANAL_CLASS_ERR_SUCCESS) {
		rz_anal_class_unset_flag (anal, flagname_method (class_name_sanitized, meth_name_sanitized));
	}
	free (class_name_sanitized);
	free (meth_name_sanitized);
	return err;
}


// ---- BASE ----

RZ_API void rz_anal_class_base_fini(RzAnalBaseClass *base) {
	free (base->id);
	free (base->class_name);
}

RZ_API RzAnalClassErr rz_anal_class_base_get(RzAnal *anal, const char *class_name, const char *base_id, RzAnalBaseClass *base) {
	char *content = rz_anal_class_get_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_BASE, base_id, false);
	if (!content) {
		return RZ_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	base->class_name = strdup (cur);
	if (!base->class_name) {
		free (content);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	cur = next;
	if (!cur) {
		free (content);
		free (base->class_name);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, NULL);

	base->offset = rz_num_math (NULL, cur);

	free (content);

	base->id = rz_str_sanitize_sdb_key (base_id);
	if (!base->id) {
		free (base->class_name);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static void rz_anal_class_base_fini_proxy(void *e, void *user) {
	(void)user;
	RzAnalBaseClass *base = e;
	rz_anal_class_base_fini (base);
}

RZ_API RzVector/*<RzAnalBaseClass>*/ *rz_anal_class_base_get_all(RzAnal *anal, const char *class_name) {
	RzVector *vec = rz_vector_new (sizeof(RzAnalBaseClass), rz_anal_class_base_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		rz_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (class_name_sanitized, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_BASE)), 0);
	free (class_name_sanitized);

	rz_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RzAnalBaseClass base;
		if (rz_anal_class_base_get (anal, class_name, cur, &base) == RZ_ANAL_CLASS_ERR_SUCCESS) {
			rz_vector_push (vec, &base);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

static RzAnalClassErr rz_anal_class_base_set_raw(RzAnal *anal, const char *class_name, RzAnalBaseClass *base, const char *base_class_name_sanitized) {
	char *content = sdb_fmt ("%s" SDB_SS "%"PFMT64u, base_class_name_sanitized, base->offset);
	RzAnalClassErr err;
	if (base->id) {
		err = rz_anal_class_set_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_BASE, base->id, content);
	} else {
		base->id = malloc(16);
		if (base->id) {
			err = rz_anal_class_add_attr_unique (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_BASE, content, base->id, 16);
		} else {
			err = RZ_ANAL_CLASS_ERR_OTHER;
		}
	}
	return err;
}

RZ_API RzAnalClassErr rz_anal_class_base_set(RzAnal *anal, const char *class_name, RzAnalBaseClass *base) {
	char *base_class_name_sanitized = rz_str_sanitize_sdb_key (base->class_name);
	if (!base_class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	if (!rz_anal_class_exists_raw (anal, base_class_name_sanitized)) {
		free (base_class_name_sanitized);
		return RZ_ANAL_CLASS_ERR_NONEXISTENT_CLASS;
	}
	RzVector /*<RzAnalBaseClass>*/ *bases = rz_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RzAnalBaseClass *existing_base;
		rz_vector_foreach (bases, existing_base) {
			if (!strcmp (existing_base->class_name, base->class_name)) {
				free (base_class_name_sanitized);
				rz_vector_free (bases);
				return RZ_ANAL_CLASS_ERR_OTHER;
			}
		}
	}
	RzAnalClassErr err = rz_anal_class_base_set_raw (anal, class_name, base, base_class_name_sanitized);
	free (base_class_name_sanitized);
	rz_vector_free (bases);
	return err;
}

RZ_API RzAnalClassErr rz_anal_class_base_delete(RzAnal *anal, const char *class_name, const char *base_id) {
	return rz_anal_class_delete_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_BASE, base_id);
}

typedef struct {
	RzAnal *anal;
	const char *class_name;
} DeleteClassCtx;

static bool rz_anal_class_base_delete_class_cb(void *user, const char *k, const char *v) {
	(void)v;
	DeleteClassCtx *ctx = user;
	RzVector *bases = rz_anal_class_base_get_all (ctx->anal, k);
	RzAnalBaseClass *base;
	rz_vector_foreach (bases, base) {
		if (base->class_name && strcmp (base->class_name, ctx->class_name) == 0) {
			rz_anal_class_base_delete (ctx->anal, k, base->id);
		}
	}
	rz_vector_free (bases);
	return true;
}

static void rz_anal_class_base_delete_class(RzAnal *anal, const char *class_name) {
	DeleteClassCtx ctx = { anal, class_name };
	rz_anal_class_foreach (anal, rz_anal_class_base_delete_class_cb, &ctx);
}

typedef struct {
	RzAnal *anal;
	const char *class_name_old;
	const char *class_name_new;
} RenameClassCtx;

static bool rz_anal_class_base_rename_class_cb(void *user, const char *k, const char *v) {
	(void)v;
	RenameClassCtx *ctx = user;
	RzVector *bases = rz_anal_class_base_get_all (ctx->anal, k);
	RzAnalBaseClass *base;
	rz_vector_foreach (bases, base) {
		if (base->class_name && strcmp (base->class_name, ctx->class_name_old) == 0) {
			rz_anal_class_base_set_raw (ctx->anal, k, base, ctx->class_name_new);
		}
	}
	rz_vector_free (bases);
	return 1;
}

static void rz_anal_class_base_rename_class(RzAnal *anal, const char *class_name_old, const char *class_name_new) {
	RenameClassCtx ctx = { anal, class_name_old, class_name_new };
	rz_anal_class_foreach (anal, rz_anal_class_base_rename_class_cb, &ctx);
}

// ---- VTABLE ----

static char *flagname_vtable(const char *class_name, const char *vtable_id) {
	return flagname_attr ("vtable", class_name, vtable_id);
}

RZ_API void rz_anal_class_vtable_fini(RzAnalVTable *vtable) {
	free (vtable->id);
}

RZ_API RzAnalClassErr rz_anal_class_vtable_get(RzAnal *anal, const char *class_name, const char *vtable_id, RzAnalVTable *vtable) {
	char *content = rz_anal_class_get_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable_id, false);
	if (!content) {
		return RZ_ANAL_CLASS_ERR_NONEXISTENT_ATTR;
	}

	char *cur = content;
	char *next;
	sdb_anext (cur, &next);

	vtable->addr = rz_num_math (NULL, cur);

	cur = next;
	if (!cur) {
		free (content);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	sdb_anext (cur, &next);

	vtable->offset = rz_num_math (NULL, cur);

	if (next) {
		cur = next;
		sdb_anext (cur, NULL);
		vtable->size = rz_num_get (NULL, cur);
	} else {
		vtable->size = 0;
	}

	free (content);

	vtable->id = rz_str_sanitize_sdb_key (vtable_id);
	if (!vtable->id) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static void rz_anal_class_vtable_fini_proxy(void *e, void *user) {
	(void)user;
	RzAnalVTable *vtable = e;
	rz_anal_class_vtable_fini (vtable);
}

RZ_API RzVector/*<RzAnalVTable>*/ *rz_anal_class_vtable_get_all(RzAnal *anal, const char *class_name) {
	RzVector *vec = rz_vector_new (sizeof(RzAnalVTable), rz_anal_class_vtable_fini_proxy, NULL);
	if (!vec) {
		return NULL;
	}

	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		rz_vector_free (vec);
		return NULL;
	}
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (class_name_sanitized, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_VTABLE)), 0);
	free (class_name_sanitized);

	rz_vector_reserve (vec, (size_t) sdb_alen (array));
	char *cur;
	sdb_aforeach (cur, array) {
		RzAnalVTable vtable;
		if (rz_anal_class_vtable_get (anal, class_name, cur, &vtable) == RZ_ANAL_CLASS_ERR_SUCCESS) {
			rz_vector_push (vec, &vtable);
		}
		sdb_aforeach_next (cur);
	}
	free (array);

	return vec;
}

RZ_API RzAnalClassErr rz_anal_class_vtable_set(RzAnal *anal, const char *class_name, RzAnalVTable *vtable) {
	char *content = sdb_fmt ("0x%"PFMT64x SDB_SS "%"PFMT64u SDB_SS "%"PFMT64u, vtable->addr, vtable->offset, vtable->size);
	if (vtable->id) {
		return rz_anal_class_set_attr (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable->id, content);
	}
	vtable->id = malloc(16);
	if (!vtable->id) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	RzAnalClassErr err = rz_anal_class_add_attr_unique (anal, class_name, RZ_ANAL_CLASS_ATTR_TYPE_VTABLE, content, vtable->id, 16);
	if (err != RZ_ANAL_CLASS_ERR_SUCCESS) {
		return err;
	}

	rz_anal_class_set_flag (anal, flagname_vtable (class_name, vtable->id), vtable->addr, vtable->size);

	return RZ_ANAL_CLASS_ERR_SUCCESS;
}

static void rz_anal_class_vtable_rename_class(RzAnal *anal, const char *old_class_name, const char *new_class_name) {
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (old_class_name, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_VTABLE)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		rz_anal_class_rename_flag (anal,
				flagname_vtable (old_class_name, cur),
				flagname_vtable (new_class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

static void rz_anal_class_vtable_delete_class(RzAnal *anal, const char *class_name) {
	char *array = sdb_get (anal->sdb_classes_attrs, key_attr_type_attrs (class_name, attr_type_id (RZ_ANAL_CLASS_ATTR_TYPE_VTABLE)), 0);
	if (!array) {
		return;
	}
	char *cur;
	sdb_aforeach (cur, array) {
		rz_anal_class_unset_flag (anal, flagname_vtable (class_name, cur));
		sdb_aforeach_next (cur);
	}
	free (array);
}

RZ_API RzAnalClassErr rz_anal_class_vtable_delete(RzAnal *anal, const char *class_name, const char *vtable_id) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	char *vtable_id_sanitized = rz_str_sanitize_sdb_key (vtable_id);
	if (!vtable_id_sanitized) {
		free (class_name_sanitized);
		return RZ_ANAL_CLASS_ERR_OTHER;
	}
	RzAnalClassErr err = rz_anal_class_delete_attr_raw (anal, class_name_sanitized, RZ_ANAL_CLASS_ATTR_TYPE_VTABLE, vtable_id_sanitized);
	if (err == RZ_ANAL_CLASS_ERR_SUCCESS) {
		rz_anal_class_unset_flag (anal, flagname_vtable (class_name_sanitized, vtable_id_sanitized));
	}
	free (class_name_sanitized);
	free (vtable_id_sanitized);
	return err;
}


// ---- PRINT ----


RZ_API void rz_anal_class_print(RzAnal *anal, const char *class_name, bool detailed) {
	rz_cons_print (class_name);

	RzVector *bases = rz_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RzAnalBaseClass *base;
		bool first = true;
		rz_vector_foreach (bases, base) {
			if (first) {
				rz_cons_print (": ");
				first = false;
			} else {
				rz_cons_print (", ");
			}
			rz_cons_print (base->class_name);
		}
		rz_vector_free (bases);
	}

	rz_cons_print ("\n");


	if (detailed) {
		RzVector *vtables = rz_anal_class_vtable_get_all (anal, class_name);
		if (vtables) {
			RzAnalVTable *vtable;
			rz_vector_foreach (vtables, vtable) {
				rz_cons_printf ("  (vtable at 0x%"PFMT64x, vtable->addr);
				if (vtable->offset > 0) {
					rz_cons_printf (" in class at +0x%"PFMT64x")\n", vtable->offset);
				} else {
					rz_cons_print (")\n");
				}
			}
			rz_vector_free (vtables);
		}

		RzVector *methods = rz_anal_class_method_get_all (anal, class_name);
		if (methods) {
			RzAnalMethod *meth;
			rz_vector_foreach (methods, meth) {
				rz_cons_printf ("  %s @ 0x%"PFMT64x, meth->name, meth->addr);
				if (meth->vtable_offset >= 0) {
					rz_cons_printf (" (vtable + 0x%"PFMT64x")\n", (ut64)meth->vtable_offset);
				} else {
					rz_cons_print ("\n");
				}
			}
			rz_vector_free (methods);
		}
	}
}

static void rz_anal_class_print_cmd(RzAnal *anal, const char *class_name) {
	RzVector *bases = rz_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RzAnalBaseClass *base;
		rz_vector_foreach (bases, base) {
			rz_cons_printf ("acb %s %s %"PFMT64u"\n", class_name, base->class_name, base->offset);
		}
		rz_vector_free (bases);
	}

	RzVector *vtables = rz_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RzAnalVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			rz_cons_printf ("acv %s 0x%"PFMT64x" %"PFMT64u"\n", class_name, vtable->addr, vtable->offset);
		}
		rz_vector_free (vtables);
	}

	RzVector *methods = rz_anal_class_method_get_all (anal, class_name);
	if (methods) {
		RzAnalMethod *meth;
		rz_vector_foreach (methods, meth) {
			rz_cons_printf ("acm %s %s 0x%"PFMT64x" %"PFMT64d"\n", class_name, meth->name, meth->addr, meth->vtable_offset);
		}
		rz_vector_free (methods);
	}
}

RZ_API void rz_anal_class_json(RzAnal *anal, PJ *j, const char *class_name) {
	pj_o (j);
	pj_ks (j, "name", class_name);

	pj_k (j, "bases");
	pj_a (j);
	RzVector *bases = rz_anal_class_base_get_all (anal, class_name);
	if (bases) {
		RzAnalBaseClass *base;
		rz_vector_foreach (bases, base) {
			pj_o (j);
			pj_ks (j, "id", base->id);
			pj_ks (j, "name", base->class_name);
			pj_kn (j, "offset", base->offset);
			pj_end (j);
		}
		rz_vector_free (bases);
	}
	pj_end (j);

	pj_k (j, "vtables");
	pj_a (j);
	RzVector *vtables = rz_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RzAnalVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			pj_o (j);
			pj_ks (j, "id", vtable->id);
			pj_kn (j, "addr", vtable->addr);
			pj_kn (j, "offset", vtable->offset);
			pj_end (j);
		}
	}
	pj_end (j);

	pj_k (j, "methods");
	pj_a (j);
	RzVector *methods = rz_anal_class_method_get_all (anal, class_name);
	if (methods) {
		RzAnalMethod *meth;
		rz_vector_foreach (methods, meth) {
			pj_o (j);
			pj_ks (j, "name", meth->name);
			pj_kn (j, "addr", meth->addr);
			if (meth->vtable_offset >= 0) {
				pj_kn (j, "vtable_offset", (ut64)meth->vtable_offset);
			}
			pj_end (j);
		}
		rz_vector_free (methods);
	}
	pj_end (j);

	pj_end (j);
}

typedef struct {
	RzAnal *anal;
	PJ *j;
} ListJsonCtx;

static bool rz_anal_class_list_json_cb(void *user, const char *k, const char *v) {
	ListJsonCtx *ctx = user;
	rz_anal_class_json (ctx->anal, ctx->j, k);
	return true;
}

static void rz_anal_class_list_json(RzAnal *anal) {
	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	pj_a (j);

	ListJsonCtx ctx;
	ctx.anal = anal;
	ctx.j = j;
	rz_anal_class_foreach (anal, rz_anal_class_list_json_cb, &ctx);

	pj_end (j);
	rz_cons_printf ("%s\n", pj_string (j));
	pj_free (j);
}

RZ_API void rz_anal_class_list(RzAnal *anal, int mode) {
	if (mode == 'j') {
		rz_anal_class_list_json (anal);
		return;
	}

	SdbList *classes = rz_anal_class_get_all (anal, mode != '*');
	SdbListIter *iter;
	SdbKv *kv;
	if (mode == '*') {
		ls_foreach (classes, iter, kv) {
			// need to create all classes first, so they can be referenced
			rz_cons_printf ("ac %s\n", sdbkv_key (kv));
		}
		ls_foreach (classes, iter, kv) {
			rz_anal_class_print_cmd(anal, sdbkv_key (kv));
		}
	} else {
		ls_foreach (classes, iter, kv) {
			rz_anal_class_print (anal, sdbkv_key (kv), mode == 'l');
		}
	}
	ls_free (classes);
}

RZ_API void rz_anal_class_list_bases(RzAnal *anal, const char *class_name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!rz_anal_class_exists_raw (anal, class_name_sanitized)) {
		free (class_name_sanitized);
		return;
	}
	rz_cons_printf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RzVector *bases = rz_anal_class_base_get_all (anal, class_name);
	RzAnalBaseClass *base;
	rz_vector_foreach (bases, base) {
		rz_cons_printf ("  %4s %s @ +0x%"PFMT64x"\n", base->id, base->class_name, base->offset);
	}
	rz_vector_free (bases);
}

RZ_API void rz_anal_class_list_vtables(RzAnal *anal, const char *class_name) {
	char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
	if (!class_name_sanitized) {
		return;
	}
	if (!rz_anal_class_exists_raw (anal, class_name_sanitized)) {
		free (class_name_sanitized);
		return;
	}
	rz_cons_printf ("%s:\n", class_name_sanitized);
	free (class_name_sanitized);

	RzVector *vtables = rz_anal_class_vtable_get_all (anal, class_name);
	if (vtables) {
		RzAnalVTable *vtable;
		rz_vector_foreach (vtables, vtable) {
			rz_cons_printf ("  %4s vtable 0x%"PFMT64x" @ +0x%"PFMT64x" size:+0x%"PFMT64x"\n", vtable->id, vtable->addr, vtable->offset, vtable->size);
		}
		rz_vector_free (vtables);
	}
}

static void list_all_functions_at_vtable_offset(RzAnal *anal, const char *class_name, ut64 offset) {
	RVTableContext vtableContext;
	rz_anal_vtable_begin (anal, &vtableContext);
	ut8 function_ptr_size = vtableContext.word_size; 

	ut64 func_address;
	RzVector *vtables = rz_anal_class_vtable_get_all (anal, class_name);
	RzAnalVTable *vtable;

	if (!vtables) {
		return;
	}

	rz_vector_foreach (vtables, vtable) {
		if (vtable->size < offset + function_ptr_size) {
			continue;
		}

		if (vtableContext.read_addr(anal, vtable->addr+offset, &func_address))
			rz_cons_printf ("Function address: 0x%08"PFMT64x", in %s vtable %s\n", func_address, class_name, vtable->id);
	}
	rz_vector_free (vtables);
}

RZ_API void rz_anal_class_list_vtable_offset_functions(RzAnal *anal, const char *class_name, ut64 offset) {
	if (class_name) {
		char *class_name_sanitized = rz_str_sanitize_sdb_key (class_name);
		if (!class_name_sanitized) {
			return;
		}
		if (!rz_anal_class_exists_raw (anal, class_name_sanitized)) {
			free (class_name_sanitized);
			return;
		}
		free (class_name_sanitized);

		list_all_functions_at_vtable_offset (anal, class_name, offset);
	} else {
		SdbList *classes = rz_anal_class_get_all (anal, true);
		SdbListIter *iter;
		SdbKv *kv;
		ls_foreach (classes, iter, kv) {
			const char *name = sdbkv_key (kv);
			list_all_functions_at_vtable_offset (anal, name, offset);
		}
		ls_free (classes);
	}
}

/**
 * @brief Creates RzGraph from class inheritance information where 
 *        each node has RzGraphNodeInfo as generic data
 * 
 * @param anal 
 * @return RzGraph* NULL if failure
 */
RZ_API RzGraph *rz_anal_class_get_inheritance_graph(RzAnal *anal) {
	rz_return_val_if_fail (anal, NULL);
	RzGraph *class_graph = rz_graph_new ();
	if (!class_graph) {
		return NULL;
	}
	SdbList *classes = rz_anal_class_get_all (anal, true);
	if (!classes) {
		rz_graph_free (class_graph);
		return NULL;
	}
	HtPP /*<char *name, RzGraphNode *node>*/ *hashmap = ht_pp_new0 ();
	if (!hashmap) {
		rz_graph_free (class_graph);
		ls_free (classes);
		return NULL;
	}
	SdbListIter *iter;
	SdbKv *kv;
	// Traverse each class and create a node and edges
	ls_foreach (classes, iter, kv) {
		const char *name = sdbkv_key (kv);
		// create nodes
		RzGraphNode *curr_node = ht_pp_find (hashmap, name, NULL);
		if (!curr_node) {
			curr_node = rz_graph_add_node_info (class_graph, name, NULL, 0);
			if (!curr_node) {
				goto failure;
			}
			ht_pp_insert (hashmap, name, curr_node);
		}
		// create edges between node and it's parents
		RzVector *bases = rz_anal_class_base_get_all (anal, name);
		RzAnalBaseClass *base;
		rz_vector_foreach (bases, base) {
			bool base_found = false;
			RzGraphNode *base_node = ht_pp_find (hashmap, base->class_name, &base_found);
			// If base isn't processed, do it now
			if (!base_found) {
				base_node = rz_graph_add_node_info (class_graph, base->class_name, NULL, 0);
				if (!base_node) {
					goto failure;
				}
				ht_pp_insert (hashmap, base->class_name, base_node);
			}
			rz_graph_add_edge (class_graph, base_node, curr_node);
		}
		rz_vector_free (bases);
	}
	ls_free (classes);
	ht_pp_free (hashmap);
	return class_graph;

failure:
	ls_free (classes);
	ht_pp_free (hashmap);
	rz_graph_free (class_graph);
	return NULL;
}
