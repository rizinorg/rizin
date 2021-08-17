// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#define is_native_type(x) ((x) && !IS_UPPER(x))
#define is_varargs(x)     ((x)[0] == '.' && (x)[1] == '.' && (x)[2] == '.')

static inline bool demangle_type(char *type, RzStrBuf *sb, size_t *used) {
	bool array = false, varargs = false;
	char *end = NULL;
	size_t type_len = 1;
	if (is_varargs(type)) {
		varargs = true;
		type += 3;
	}
	if (type[0] == '[') {
		array = true;
		type++;
	}

	switch (type[0]) {
	case 'L':
		if (!(end = strchr(type, ';'))) {
			return false;
		}
		end[0] = 0;
		type_len = strlen(type);
		rz_strbuf_append_n(sb, type + 1, type_len - 1);
		type_len++;
		break;
	case 'B':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "byte");
		break;
	case 'C':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "char");
		break;
	case 'D':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "double");
		break;
	case 'F':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "float");
		break;
	case 'I':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "int");
		break;
	case 'J':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "long");
		break;
	case 'S':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "short");
		break;
	case 'V':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "void");
		break;
	case 'Z':
		if (is_native_type(type[1])) {
			return false;
		}
		rz_strbuf_append(sb, "boolean");
		break;
	default:
		return false;
	}
	if (varargs) {
		rz_strbuf_append(sb, "...");
		type_len += 3;
	}
	if (array) {
		if (!varargs) {
			rz_strbuf_append(sb, "[]");
		}
		type_len++;
	}
	if (used) {
		*used = type_len;
	}
	return true;
}

static char *demangle_method(char *name, char *arguments, char *return_type) {
	// example: Lsome/class/Object;.myMethod([F)I
	// name = Lsome/class/Object;.myMethod
	// args = [F
	// rett = I
	RzStrBuf *sb = NULL;
	size_t args_length = 0;

	sb = rz_strbuf_new("");
	if (!sb) {
		goto demangle_method_bad;
	}

	arguments[0] = 0;
	arguments++;
	args_length = return_type - arguments;

	return_type[0] = 0;
	return_type++;

	if (!demangle_type(return_type, sb, NULL)) {
		goto demangle_method_bad;
	}

	rz_strbuf_append(sb, " ");

	const char *t = NULL;
	if (name[0] == 'L' && (t = strchr(name, ';')) && !demangle_type(name, sb, NULL)) {
		goto demangle_method_bad;
	} else if (name[0] == 'L') {
		rz_strbuf_append(sb, t + 1);
	} else {
		rz_strbuf_append(sb, name);
	}

	rz_strbuf_append(sb, "(");
	for (size_t pos = 0, used = 0; pos < args_length;) {
		if (!demangle_type(arguments + pos, sb, &used)) {
			goto demangle_method_bad;
		}
		pos += used;
		if (pos < args_length) {
			rz_strbuf_append(sb, ", ");
		}
	}
	rz_strbuf_append(sb, ")");

	free(name);
	rz_str_replace_ch(rz_strbuf_get(sb), '/', '.', 1);
	return rz_strbuf_drain(sb);

demangle_method_bad:
	rz_strbuf_free(sb);
	free(name);
	return NULL;
}

static char *demangle_class_object(char *object, char *name) {
	// example: Lsome/class/Object;.myMethod.I
	// object = Lsome/class/Object;
	// name   = myMethod.I
	RzStrBuf *sb = NULL;
	char *type = NULL;

	sb = rz_strbuf_new("");
	if (!sb) {
		goto demangle_class_object_bad;
	}

	name[0] = 0;
	name++;

	type = strchr(name, '.');

	if (!demangle_type(object, sb, NULL)) {
		goto demangle_class_object_bad;
	}

	if (type) {
		type[0] = 0;
		type++;
		rz_strbuf_appendf(sb, ".%s:", name);
		if (!demangle_type(type, sb, NULL)) {
			goto demangle_class_object_bad;
		}
	} else {
		rz_strbuf_appendf(sb, ".%s", name);
	}

	free(object);
	rz_str_replace_ch(rz_strbuf_get(sb), '/', '.', 1);
	return rz_strbuf_drain(sb);

demangle_class_object_bad:
	rz_strbuf_free(sb);
	free(object);
	return NULL;
}

static char *demangle_object_with_type(char *name, char *object) {
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		goto demangle_object_with_type_bad;
	}

	object[0] = 0;
	object++;

	rz_strbuf_appendf(sb, "%s:", name);
	if (!demangle_type(object, sb, NULL)) {
		goto demangle_object_with_type_bad;
	}

	free(name);
	rz_str_replace_ch(rz_strbuf_get(sb), '/', '.', 1);
	return rz_strbuf_drain(sb);

demangle_object_with_type_bad:
	rz_strbuf_free(sb);
	free(name);
	return NULL;
}

static char *demangle_any(char *mangled) {
	RzStrBuf *sb = rz_strbuf_new("");
	if (!sb) {
		return NULL;
	}

	if (!demangle_type(mangled, sb, NULL)) {
		free(mangled);
		rz_strbuf_free(sb);
		return NULL;
	}
	free(mangled);

	rz_str_replace_ch(rz_strbuf_get(sb), '/', '.', 1);
	return rz_strbuf_drain(sb);
}

RZ_API char *rz_bin_demangle_java(const char *mangled) {
	rz_return_val_if_fail(mangled, NULL);

	char *name = NULL;
	char *arguments = NULL;
	char *return_type = NULL;

	name = strdup(mangled);
	if (!name) {
		return NULL;
	}
	rz_str_trim(name);
	// removes any obvious class like java.lang.String
	rz_str_replace(name, "java/lang/", "", 1);

	if ((arguments = strchr(name, '(')) && (return_type = strchr(arguments, ')'))) {
		return demangle_method(name, arguments, return_type);
	} else if (name[0] == 'L' && (arguments = strchr(name, '.'))) {
		return demangle_class_object(name, arguments);
	} else if ((arguments = strchr(name, '.'))) {
		return demangle_object_with_type(name, arguments);
	}
	return demangle_any(name);
}
