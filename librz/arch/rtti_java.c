// SPDX-FileCopyrightText: 2026 historicattle <sirigere.naren@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "analysis_private.h"
#include "../bin/format/java/class_bin.h"

static RZ_OWN char *class_name(RzBinJavaClass *bin, ut16 index) {
	const ConstPool *cls = NULL;
	if (index && index < bin->constant_pool_count && bin->constant_pool) {
		cls = bin->constant_pool[index];
	}
	if (!cls || cls->tag != CONSTANT_POOL_CLASS || cls->size != 2 || !cls->buffer) {
		return NULL;
	}
	index = rz_read_be16(cls->buffer);
	const ConstPool *utf8 = NULL;
	if (index && index < bin->constant_pool_count) {
		utf8 = bin->constant_pool[index];
	}
	if (!utf8 || utf8->tag != CONSTANT_POOL_UTF8 || !utf8->size || !utf8->buffer) {
		return NULL;
	}
	bool component = false;
	for (ut32 i = 0; i < utf8->size; i++) {
		ut8 c = utf8->buffer[i];
		if (!c || c == '.' || c == ';' || c == '[' || (c == '/' && !component)) {
			return NULL;
		}
		component = c != '/';
	}
	char *name = NULL;
	if (component) {
		name = rz_str_ndup((const char *)utf8->buffer, utf8->size);
	}
	if (name) {
		rz_str_replace_char(name, '/', '.');
	}
	return name;
}

static bool create_class(RzAnalysis *analysis, const char *name) {
	char *key = rz_str_sanitize_sdb_key(name);
	char *identity_key = NULL;
	if (key) {
		identity_key = rz_str_newf("java.identity.%s", key);
	}
	if (!identity_key) {
		free(key);
		return false;
	}
	const char *previous = sdb_const_get(analysis->sdb_classes_attrs, identity_key);
	bool collision = previous && strcmp(previous, name);
	RzListIter *iter;
	RzBinFile *file;
	rz_list_foreach (analysis->binb.bin->binfiles, iter, file) {
		if (!file->o || file->o->lang != RZ_BIN_LANGUAGE_JAVA || !file->o->bin_obj) {
			continue;
		}
		char *other = class_name(file->o->bin_obj, ((RzBinJavaClass *)file->o->bin_obj)->this_class);
		char *other_key = rz_str_sanitize_sdb_key(other);
		collision |= other && other_key && !strcmp(key, other_key) && strcmp(name, other);
		free(other_key);
		free(other);
	}
	bool ok = false;
	if (collision) {
		RZ_LOG_WARN("Java class database identity collision: %s\n", name);
	} else {
		RzAnalysisClassErr err = rz_analysis_class_create(analysis, name);
		ok = (err == RZ_ANALYSIS_CLASS_ERR_SUCCESS || err == RZ_ANALYSIS_CLASS_ERR_CLASH) &&
			sdb_set(analysis->sdb_classes_attrs, identity_key, name);
	}
	free(identity_key);
	free(key);
	return ok;
}

static void add_base(RzAnalysis *analysis, const char *class_name, RZ_OWN char *name) {
	if (!name || !strcmp(name, class_name) || !create_class(analysis, name)) {
		free(name);
		return;
	}
	RzAnalysisBaseClass base = {
		.class_name = rz_str_sanitize_sdb_key(name),
	};
	if (base.class_name) {
		rz_analysis_class_base_set(analysis, class_name, &base);
	}
	rz_analysis_class_base_fini(&base);
	free(name);
}

static void replace_methods(RzAnalysis *analysis, RzBinObject *object, RzBinJavaClass *java_class, const char *class_name) {
	RzVector *old = rz_analysis_class_method_get_all(analysis, class_name);
	RzSetS *generic_names = rz_set_s_new(HT_STR_DUP);
	RzSetS *replaced_names = rz_set_s_new(HT_STR_DUP);
	for (ut32 i = 0; i < rz_bin_java_class_method_count(java_class); i++) {
		RzBinJavaMethodInfo info;
		if (!rz_bin_java_class_method(java_class, i, &info)) {
			continue;
		}
		char *identity = rz_str_newf("%s%s", info.name, info.descriptor);
		char *encoded = NULL;
		char *method_name = NULL;
		if (identity) {
			encoded = rz_hex_bin2strdup((const ut8 *)identity, strlen(identity));
		}
		if (encoded) {
			method_name = rz_str_newf("java_%s", encoded);
		}
		RzAnalysisMethod method = {
			.name = method_name,
			.real_name = rz_str_newf("%s.%s%s", class_name, info.name, info.descriptor),
			.addr = info.code_addr,
			.vtable_offset = -1,
			.method_type = RZ_ANALYSIS_CLASS_METHOD_DEFAULT,
		};
		if (method.addr != UT64_MAX) {
			method.addr = rz_bin_object_addr_with_base(object, method.addr);
		}
		if (!strcmp(info.name, "<init>")) {
			method.method_type = RZ_ANALYSIS_CLASS_METHOD_CONSTRUCTOR;
		} else if (!(info.access_flags & (METHOD_ACCESS_FLAG_STATIC | METHOD_ACCESS_FLAG_PRIVATE)) && strcmp(info.name, "<clinit>")) {
			method.method_type = RZ_ANALYSIS_CLASS_METHOD_VIRTUAL;
		}
		if (method.real_name) {
			method.real_name = rz_str_replace(method.real_name, ",", "#_#", 1);
		}
		if (method.name && method.real_name &&
			rz_analysis_class_method_set(analysis, class_name, &method) == RZ_ANALYSIS_CLASS_ERR_SUCCESS) {
			char *generic = rz_str_newf("%s.%s", class_name, info.name);
			if (generic && generic_names) {
				rz_set_s_add(generic_names, generic);
			}
			if (replaced_names) {
				rz_set_s_add(replaced_names, method.real_name);
			}
			free(generic);
		}
		free(encoded);
		free(identity);
		rz_analysis_class_method_fini(&method);
		rz_bin_java_method_info_fini(&info);
	}
	RzAnalysisMethod *existing;
	rz_vector_foreach (old, existing) {
		if (!existing->real_name) {
			continue;
		}
		bool superseded = generic_names && existing->method_type == RZ_ANALYSIS_CLASS_METHOD_DEFAULT &&
			rz_set_s_contains(generic_names, existing->real_name);
		if (replaced_names && rz_set_s_contains(replaced_names, existing->real_name)) {
			const char *identity = existing->real_name + strlen(class_name) + 1;
			char *key = rz_str_sanitize_sdb_key(identity);
			superseded |= key && RZ_STR_EQ(key, existing->name);
			free(key);
		}
		if (superseded) {
			rz_analysis_class_method_delete(analysis, class_name, existing->name);
		}
	}
	rz_set_s_free(replaced_names);
	rz_set_s_free(generic_names);
	rz_vector_free(old);
}

/**
 * \brief Recover the current Java class's declarations and inheritance metadata.
 */
RZ_API void rz_analysis_rtti_java(RZ_NONNULL RzAnalysis *analysis) {
	rz_return_if_fail(analysis);
	RzBinObject *object = rz_bin_cur_object(analysis->binb.bin);
	if (!object || object->lang != RZ_BIN_LANGUAGE_JAVA || !object->bin_obj) {
		return;
	}
	RzBinJavaClass *java_class = object->bin_obj;
	char *name = class_name(java_class, java_class->this_class);
	if (!name) {
		return;
	}
	RzListIter *iter;
	RzBinFile *file;
	rz_list_foreach (analysis->binb.bin->binfiles, iter, file) {
		if (!file->o || file->o == object || file->o->lang != RZ_BIN_LANGUAGE_JAVA || !file->o->bin_obj) {
			continue;
		}
		char *other = class_name(file->o->bin_obj, ((RzBinJavaClass *)file->o->bin_obj)->this_class);
		bool duplicate = RZ_STR_EQ(name, other);
		free(other);
		if (duplicate) {
			RZ_LOG_WARN("Ambiguous loaded Java class: %s\n", name);
			free(name);
			return;
		}
	}
	if (create_class(analysis, name)) {
		if (java_class->super_class && !(java_class->access_flags & ACCESS_FLAG_INTERFACE)) {
			add_base(analysis, name, class_name(java_class, java_class->super_class));
		}
		for (ut32 i = 0; i < rz_bin_java_class_interface_count(java_class); i++) {
			Interface *interface = java_class->interfaces[i];
			if (interface) {
				add_base(analysis, name, class_name(java_class, interface->index));
			}
		}
		replace_methods(analysis, object, java_class, name);
	}
	free(name);
}
