// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>

#define is_varargs(x) ((x)[0] == '.' && (x)[1] == '.' && (x)[2] == '.')

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
		rz_strbuf_append(sb, "byte");
		break;
	case 'C':
		rz_strbuf_append(sb, "char");
		break;
	case 'D':
		rz_strbuf_append(sb, "double");
		break;
	case 'F':
		rz_strbuf_append(sb, "float");
		break;
	case 'I':
		rz_strbuf_append(sb, "int");
		break;
	case 'J':
		rz_strbuf_append(sb, "long");
		break;
	case 'S':
		rz_strbuf_append(sb, "short");
		break;
	case 'V':
		rz_strbuf_append(sb, "void");
		break;
	case 'Z':
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

RZ_API char *rz_bin_demangle_java(const char *mangled) {
	rz_return_val_if_fail(mangled, NULL);
	size_t args_length = 0;
	RzStrBuf *sb = NULL;
	char *name = NULL;
	char *arguments = NULL;
	char *return_type = NULL;

	sb = rz_strbuf_new("");
	if (!sb) {
		goto rz_bin_demangle_java_bad;
	}

	name = strdup(mangled);
	if (!name) {
		goto rz_bin_demangle_java_bad;
	}
	rz_str_trim(name);
	// removes any obvious class like java.lang.String
	rz_str_replace(name, "java/lang/", "", 1);

	arguments = strchr(name, '(');
	if (!arguments) {
		// probably demangling only a type
		if (name[0] != 'L' || !demangle_type(name, sb, NULL)) {
			goto rz_bin_demangle_java_bad;
		}
		goto rz_bin_demangle_java_end;
	}

	arguments[0] = 0;
	arguments++;

	return_type = strchr(arguments, ')');
	if (!return_type || RZ_STR_ISEMPTY(return_type + 1)) {
		goto rz_bin_demangle_java_bad;
	}
	args_length = return_type - arguments;

	return_type[0] = 0;
	return_type++;

	if (!demangle_type(return_type, sb, NULL)) {
		rz_warn_if_reached();
		goto rz_bin_demangle_java_bad;
	}

	rz_strbuf_append(sb, " ");

	if (name[0] != 'L' || !demangle_type(name, sb, NULL)) {
		//name might contain a object name
		rz_strbuf_append(sb, name);
	}

	rz_strbuf_append(sb, "(");

	for (size_t pos = 0, used = 0; pos < args_length;) {
		if (!demangle_type(arguments + pos, sb, &used)) {
			rz_warn_if_reached();
			goto rz_bin_demangle_java_bad;
		}
		pos += used;
		if (pos < args_length) {
			rz_strbuf_append(sb, ", ");
		}
	}
	rz_strbuf_append(sb, ")");

rz_bin_demangle_java_end:
	free(name);
	char *demangled = rz_strbuf_drain(sb);
	rz_str_replace_ch(demangled, '/', '.', 1);
	return demangled;

rz_bin_demangle_java_bad:
	rz_strbuf_free(sb);
	free(name);
	return NULL;
}
