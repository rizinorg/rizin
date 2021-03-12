// SPDX-License-Identifier: LGPL-3.0-only
#include "json.h"

RZ_API bool rz_bin_java_get_bin_obj_json(RzBinJavaObj *bin, PJ *j) {
	rz_return_val_if_fail(bin && j, false);

	RzList *classes = rz_bin_java_get_classes(bin);
	const RzBinClass *class_ = rz_list_get_n(classes, 0);
	pj_o(j);

	if (class_) {
		int dummy = 0;
		RzListIter *iter;
		const RzBinClass *class_v = NULL;
		// add access flags like in methods
		bool is_public = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_PUBLIC) != 0);
		bool is_final = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_FINAL) != 0);
		bool is_super = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_SUPER) != 0);
		bool is_interface = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_INTERFACE) != 0);
		bool is_abstract = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_ABSTRACT) != 0);
		bool is_synthetic = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_SYNTHETIC) != 0);
		bool is_annotation = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_ANNOTATION) != 0);
		bool is_enum = ((class_->visibility & RZ_BIN_JAVA_CLASS_ACC_ENUM) != 0);

		pj_kN(j, "access_flags", class_->visibility);
		pj_kb(j, "is_public", is_public);
		pj_kb(j, "is_final", is_final);
		pj_kb(j, "is_super", is_super);
		pj_kb(j, "is_interface", is_interface);
		pj_kb(j, "is_abstract", is_abstract);
		pj_kb(j, "is_synthetic", is_synthetic);
		pj_kb(j, "is_annotation", is_annotation);
		pj_kb(j, "is_enum", is_enum);
		pj_ks(j, "name", class_->name ? class_->name : "");

		pj_ks(j, "super", class_->super ? class_->super : "");

		pj_ka(j, "interfaces");
		rz_list_foreach (classes, iter, class_v) {
			if (!dummy) {
				dummy++;
				continue;
			}
			// enumerate all interface classes and append them to the interfaces
			if ((class_v->visibility & RZ_BIN_JAVA_CLASS_ACC_INTERFACE) != 0 && class_v->name) {
				pj_s(j, class_v->name);
			}
		}
		pj_end(j);
	}

	rz_list_free(classes);

	pj_k(j, "methods");
	if (!rz_bin_java_get_method_json_definitions(bin, j)) {
		eprintf("[java] failed to insert method defintions in object\n");
	}

	pj_k(j, "fields");
	if (!rz_bin_java_get_field_json_definitions(bin, j)) {
		eprintf("[java] failed to insert field defintions in object\n");
	}

	pj_k(j, "imports");
	if (!rz_bin_java_get_import_json_definitions(bin, j)) {
		eprintf("[java] failed to import field defintions in object\n");
	}

	pj_end(j);
	return true;
}

RZ_API bool rz_bin_java_get_import_json_definitions(RzBinJavaObj *bin, PJ *j) {
	rz_return_val_if_fail(bin && j, false);
	RzList *the_list;
	RzListIter *iter = NULL;
	char *new_str;

	if (!(the_list = rz_bin_java_get_lib_names(bin))) {
		return false;
	}

	pj_a(j);

	rz_list_foreach (the_list, iter, new_str) {
		char *tmp = new_str;
		while (*tmp) {
			if (*tmp == '/') {
				*tmp = '.';
			}
			tmp++;
		}
		pj_s(j, new_str);
	}

	rz_list_free(the_list);
	pj_end(j);
	return true;
}

RZ_API bool rz_bin_java_get_interface_json_definitions(RzBinJavaObj *bin, PJ *j) {
	rz_return_val_if_fail(bin && j, false);
	RzList *the_list;
	RzListIter *iter = NULL;
	char *new_str;

	if (!(the_list = rz_bin_java_get_interface_names(bin))) {
		return false;
	}
	pj_a(j);

	rz_list_foreach (the_list, iter, new_str) {
		char *tmp = new_str;
		while (*tmp) {
			if (*tmp == '/') {
				*tmp = '.';
			}
			tmp++;
		}
		pj_s(j, new_str);
	}

	rz_list_free(the_list);
	pj_end(j);
	return true;
}

RZ_API bool rz_bin_java_get_method_json_definitions(RzBinJavaObj *bin, PJ *j) {
	rz_return_val_if_fail(bin && j, false);
	RzBinJavaField *fm_type = NULL;
	RzListIter *iter = NULL;
	pj_a(j);
	rz_list_foreach (bin->methods_list, iter, fm_type) {
		if (!rz_bin_java_get_method_json_definition(bin, fm_type, j)) {
			eprintf("[java] failed to insert method defintion in array.\n");
		}
	}
	pj_end(j);
	return true;
}

RZ_API bool rz_bin_java_get_field_json_definitions(RzBinJavaObj *bin, PJ *j) {
	rz_return_val_if_fail(bin && j, false);
	RzBinJavaField *fm_type = NULL;
	RzListIter *iter = NULL;
	pj_a(j);
	rz_list_foreach (bin->fields_list, iter, fm_type) {
		if (!rz_bin_java_get_field_json_definition(bin, fm_type, j)) {
			eprintf("[java] failed to insert field defintion in array.\n");
		}
	}
	pj_end(j);
	return true;
}
