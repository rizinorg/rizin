// SPDX-FileCopyrightText: 2021-2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021-2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "class_bin.h"
#include "class_private.h"

#define startswith(a, b) (!strncmp(a, b, strlen(b)))

#define ACCESS_FLAG_MASK_SRC (ACCESS_FLAG_PUBLIC | ACCESS_FLAG_PRIVATE | ACCESS_FLAG_PROTECTED | ACCESS_FLAG_STATIC | ACCESS_FLAG_FINAL)

#define CLASS_ACCESS_FLAGS_SIZE 16
static const AccessFlagsReadable access_flags_list[CLASS_ACCESS_FLAGS_SIZE] = {
	{ ACCESS_FLAG_PUBLIC, /*    */ "public" },
	{ ACCESS_FLAG_PRIVATE, /*   */ "private" },
	{ ACCESS_FLAG_PROTECTED, /* */ "protected" },
	{ ACCESS_FLAG_STATIC, /*    */ "static" },
	{ ACCESS_FLAG_FINAL, /*     */ "final" },
	{ ACCESS_FLAG_SUPER, /*     */ "super" },
	{ ACCESS_FLAG_BRIDGE, /*    */ "bridge" },
	{ ACCESS_FLAG_VARARGS, /*   */ "varargs" },
	{ ACCESS_FLAG_NATIVE, /*    */ "native" },
	{ ACCESS_FLAG_INTERFACE, /* */ "interface" },
	{ ACCESS_FLAG_ABSTRACT, /*  */ "abstract" },
	{ ACCESS_FLAG_STRICT, /*    */ "strict" },
	{ ACCESS_FLAG_SYNTHETIC, /* */ "synthetic" },
	{ ACCESS_FLAG_ANNOTATION, /**/ "annotation" },
	{ ACCESS_FLAG_ENUM, /*      */ "enum" },
	{ ACCESS_FLAG_MODULE, /*    */ "module" },
};

static ut64 java_access_flags_to_bin_flags(ut64 access_flags) {
	ut64 flags = 0;
	if (access_flags & ACCESS_FLAG_PUBLIC) {
		flags |= RZ_BIN_METH_PUBLIC;
	}
	if (access_flags & ACCESS_FLAG_PRIVATE) {
		flags |= RZ_BIN_METH_PRIVATE;
	}
	if (access_flags & ACCESS_FLAG_PROTECTED) {
		flags |= RZ_BIN_METH_PROTECTED;
	}
	if (access_flags & ACCESS_FLAG_STATIC) {
		flags |= RZ_BIN_METH_STATIC;
	}
	if (access_flags & ACCESS_FLAG_FINAL) {
		flags |= RZ_BIN_METH_FINAL;
	}
	if (access_flags & ACCESS_FLAG_BRIDGE) {
		flags |= RZ_BIN_METH_BRIDGE;
	}
	if (access_flags & ACCESS_FLAG_VARARGS) {
		flags |= RZ_BIN_METH_VARARGS;
	}
	if (access_flags & ACCESS_FLAG_NATIVE) {
		flags |= RZ_BIN_METH_NATIVE;
	}
	if (access_flags & ACCESS_FLAG_ABSTRACT) {
		flags |= RZ_BIN_METH_ABSTRACT;
	}
	if (access_flags & ACCESS_FLAG_STRICT) {
		flags |= RZ_BIN_METH_STRICT;
	}
	if (access_flags & ACCESS_FLAG_SYNTHETIC) {
		flags |= RZ_BIN_METH_SYNTHETIC;
	}
	return flags;
}

static const ConstPool *java_class_constant_pool_at(RzBinJavaClass *bin, ut32 index) {
	if (bin->constant_pool && index < bin->constant_pool_count) {
		return bin->constant_pool[index];
	}
	return NULL;
}

static char *java_class_constant_pool_stringify_at(RzBinJavaClass *bin, ut32 index) {
	const ConstPool *cpool = java_class_constant_pool_at(bin, index);
	if (!cpool) {
		return NULL;
	}
	return java_constant_pool_stringify(cpool);
}

static ut32 sanitize_size(st64 buffer_size, ut64 count, ut32 min_struct_size) {
	ut64 memory_size = count * min_struct_size;
	return memory_size <= buffer_size ? count : 0;
}

static bool java_class_is_oak(RzBinJavaClass *bin) {
	return bin->major_version < (45) || (bin->major_version == 45 && bin->minor_version < 3);
}

static bool is_eob(RzBuffer *buf) {
	st64 size = rz_buf_size(buf);
	st64 position = rz_buf_tell(buf);
	return position >= size;
}

static bool java_class_parse(RzBinJavaClass *bin, ut64 base, Sdb *kv, RzBuffer *buf, ut64 *size) {
	// https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.1
	ut64 offset = 0;
	st64 buffer_size = rz_buf_size(buf);
	if (buffer_size < 1) {
		RZ_LOG_ERROR("java bin: invalid buffer size (size < 1)\n");
		goto java_class_parse_bad;
	}

	if (!rz_buf_read_be32(buf, &bin->magic) ||
		!rz_buf_read_be16(buf, &bin->minor_version) ||
		!rz_buf_read_be16(buf, &bin->major_version) ||
		!rz_buf_read_be16(buf, &bin->constant_pool_count)) {
		goto java_class_parse_bad;
	}

	// Before version 1.0.2 it was called oak
	// which uses a different file structure.
	bool is_oak = java_class_is_oak(bin);

	bin->constant_pool_count = sanitize_size(buffer_size - rz_buf_tell(buf), bin->constant_pool_count, 3);
	bin->constant_pool_offset = base + rz_buf_tell(buf);

	if (bin->constant_pool_count > 0) {
		bin->constant_pool = RZ_NEWS0(ConstPool *, bin->constant_pool_count);
		if (!bin->constant_pool) {
			goto java_class_parse_bad;
		}
		for (ut32 i = 1; i < bin->constant_pool_count; ++i) {
			offset = rz_buf_tell(buf) + base;
			ConstPool *cpool = java_constant_pool_new(buf, offset);
			if (!cpool) {
				RZ_LOG_ERROR("java bin: could not parse the constant pool value at offset %" PFMT64x "\n", offset);
				break;
			}
			bin->constant_pool[i] = cpool;
			if (java_constant_pool_requires_null(cpool)) {
				if (i >= (bin->constant_pool_count - 1)) {
					break;
				}
				i++;
				bin->constant_pool[i] = java_constant_null_new(offset);
			}
		}
		if (is_eob(buf)) {
			rz_warn_if_reached();
			goto java_class_parse_bad;
		}
	}

	if (!rz_buf_read_be16(buf, &bin->access_flags) ||
		!rz_buf_read_be16(buf, &bin->this_class) ||
		!rz_buf_read_be16(buf, &bin->super_class) ||
		!rz_buf_read_be16(buf, &bin->interfaces_count)) {
		goto java_class_parse_bad;
	}

	bin->interfaces_count = sanitize_size(buffer_size - rz_buf_tell(buf), bin->interfaces_count, 2);
	bin->interfaces_offset = base + rz_buf_tell(buf);

	if (bin->interfaces_count > 0) {
		bin->interfaces = RZ_NEWS0(Interface *, bin->interfaces_count);
		if (!bin->interfaces) {
			goto java_class_parse_bad;
		}
		for (ut32 i = 0; i < bin->interfaces_count; ++i) {
			offset = rz_buf_tell(buf) + base;
			bin->interfaces[i] = java_interface_new(buf, offset);
		}
		if (is_eob(buf)) {
			rz_warn_if_reached();
			goto java_class_parse_bad;
		}
	}

	if (!rz_buf_read_be16(buf, &bin->fields_count)) {
		goto java_class_parse_bad;
	}

	bin->fields_count = sanitize_size(buffer_size - rz_buf_tell(buf), bin->fields_count, 8);
	bin->fields_offset = base + rz_buf_tell(buf);

	if (bin->fields_count > 0) {
		bin->fields = RZ_NEWS0(Field *, bin->fields_count);
		if (!bin->fields) {
			goto java_class_parse_bad;
		}
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			offset = rz_buf_tell(buf) + base;
			bin->fields[i] = java_field_new(bin->constant_pool,
				bin->constant_pool_count, buf, offset);
		}
		if (is_eob(buf)) {
			rz_warn_if_reached();
			goto java_class_parse_bad;
		}
	}

	if (!rz_buf_read_be16(buf, &bin->methods_count)) {
		goto java_class_parse_bad;
	}
	bin->methods_count = sanitize_size(buffer_size - rz_buf_tell(buf), bin->methods_count, 8);
	bin->methods_offset = base + rz_buf_tell(buf);

	if (bin->methods_count > 0) {
		bin->methods = RZ_NEWS0(Method *, bin->methods_count);
		if (!bin->methods) {
			goto java_class_parse_bad;
		}
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			if (is_eob(buf)) {
				goto java_class_parse_bad;
			}
			offset = rz_buf_tell(buf) + base;
			bin->methods[i] = java_method_new(bin->constant_pool,
				bin->constant_pool_count, buf, offset, is_oak);
			if (!bin->methods[i]) {
				goto java_class_parse_bad;
			}
		}
	}

	if (!rz_buf_read_be16(buf, &bin->attributes_count)) {
		goto java_class_parse_bad;
	}

	bin->attributes_count = sanitize_size(buffer_size - rz_buf_tell(buf), bin->attributes_count, 6);
	bin->attributes_offset = base + rz_buf_tell(buf);

	if (bin->attributes_count > 0) {
		bin->attributes = RZ_NEWS0(Attribute *, bin->attributes_count);
		if (!bin->attributes) {
			goto java_class_parse_bad;
		}
		for (ut32 i = 0; i < bin->attributes_count; ++i) {
			offset = rz_buf_tell(buf) + base;
			Attribute *attr = java_attribute_new(buf, offset);
			if (attr && java_attribute_resolve(bin->constant_pool, bin->constant_pool_count, attr, buf, false)) {
				bin->attributes[i] = attr;
			} else {
				java_attribute_free(attr);
				break;
			}
		}
	}
	bin->class_end_offset = base + rz_buf_tell(buf);
	if (size) {
		*size = rz_buf_tell(buf);
	}
	return true;

java_class_parse_bad:
	rz_bin_java_class_free(bin);
	return false;
}

static void java_set_sdb(Sdb *kv, RzBinJavaClass *bin, ut64 offset, ut64 size) {
	char *tmp_val;
	char tmp_key[256];

	sdb_num_set(kv, "java_class.offset", offset);
	sdb_num_set(kv, "java_class.size", size);
	sdb_num_set(kv, "java_class.magic", size);
	sdb_num_set(kv, "java_class.minor_version", size);
	sdb_num_set(kv, "java_class.major_version", size);

	tmp_val = rz_bin_java_class_version(bin);
	if (tmp_val) {
		sdb_set(kv, "java_class.version", tmp_val);
		free(tmp_val);
	}

	sdb_num_set(kv, "java_class.constant_pool_count", bin->constant_pool_count);
	for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
		ConstPool *cpool = bin->constant_pool[i];
		if (!cpool) {
			continue;
		}
		tmp_val = java_constant_pool_stringify(cpool);
		if (tmp_val) {
			snprintf(tmp_key, sizeof(tmp_key), "java_class.constant_pool_%d", i);
			sdb_set(kv, tmp_key, tmp_val);
			free(tmp_val);
		}
	}

	sdb_num_set(kv, "java_class.fields_count", bin->fields_count);
	sdb_num_set(kv, "java_class.methods_count", bin->methods_count);
	sdb_num_set(kv, "java_class.attributes_count", bin->attributes_count);
}

/**
 * \brief Parses the java class file and returns a RzBinJavaClass struct
 */
RZ_API RZ_OWN RzBinJavaClass *rz_bin_java_class_new(RZ_NONNULL RzBuffer *buf, ut64 offset, RZ_NONNULL Sdb *kv) {
	RzBinJavaClass *bin = (RzBinJavaClass *)RZ_NEW0(RzBinJavaClass);
	rz_return_val_if_fail(bin, NULL);

	ut64 size;
	if (!java_class_parse(bin, offset, kv, buf, &size)) {
		return NULL;
	}

	java_set_sdb(kv, bin, offset, size);

	return bin;
}

/**
 * \brief Parses the java class file and returns a RzBinJavaClass struct
 */
RZ_API RZ_OWN char *rz_bin_java_class_version(RZ_NONNULL RzBinJavaClass *bin) {
	if (!bin) {
		return NULL;
	}
#define is_version(bin, major, minor) ((bin)->major_version == (major) && (bin)->minor_version >= (minor))
	if (bin->major_version < 45 ||
		(bin->major_version == 45 && bin->minor_version < 3)) {
		return rz_str_dup("Java SE 1.0.2"); // old format
	} else if (is_version(bin, 45, 3)) {
		return rz_str_dup("Java SE 1.1");
	} else if (is_version(bin, 46, 0)) {
		return rz_str_dup("Java SE 1.2");
	} else if (is_version(bin, 47, 0)) {
		return rz_str_dup("Java SE 1.3");
	} else if (is_version(bin, 48, 0)) {
		return rz_str_dup("Java SE 1.4");
	} else if (is_version(bin, 49, 0)) {
		return rz_str_dup("Java SE 1.5"); // enum, generics, annotations
	} else if (is_version(bin, 50, 0)) {
		return rz_str_dup("Java SE 1.6"); // stackmaps
	} else if (is_version(bin, 51, 0)) {
		return rz_str_dup("Java SE 1.7");
	} else if (is_version(bin, 52, 0)) {
		return rz_str_dup("Java SE 1.8"); // lambda, type annos, param names
	} else if (is_version(bin, 53, 0)) {
		return rz_str_dup("Java SE 1.9"); // modules, indy string concat
	} else if (is_version(bin, 54, 0)) {
		return rz_str_dup("Java SE 10");
	} else if (is_version(bin, 55, 0)) {
		return rz_str_dup("Java SE 11"); // constant dynamic, nest mates
	} else if (is_version(bin, 56, 0)) {
		return rz_str_dup("Java SE 12");
	} else if (is_version(bin, 57, 0)) {
		return rz_str_dup("Java SE 13");
	} else if (is_version(bin, 58, 0)) {
		return rz_str_dup("Java SE 14");
	} else if (is_version(bin, 59, 0)) {
		return rz_str_dup("Java SE 15");
	} else if (is_version(bin, 60, 0)) {
		return rz_str_dup("Java SE 16");
	}
#undef is_version
	return rz_str_dup("unknown");
}

RZ_API ut64 rz_bin_java_class_debug_info(RZ_NONNULL RzBinJavaClass *bin) {
	if (!bin) {
		return 0;
	}
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			Method *method = bin->methods[i];
			if (!method || method->attributes_count < 1) {
				continue;
			}
			for (ut32 k = 0; k < method->attributes_count; ++k) {
				Attribute *attr = method->attributes[k];
				if (attr && attr->type == ATTRIBUTE_TYPE_CODE) {
					AttributeCode *ac = (AttributeCode *)attr->info;
					for (ut32 k = 0; k < ac->attributes_count; k++) {
						Attribute *cattr = ac->attributes[k];
						if (cattr && cattr->type == ATTRIBUTE_TYPE_LINENUMBERTABLE) {
							return RZ_BIN_DBG_LINENUMS | RZ_BIN_DBG_SYMS;
						}
					}
				}
			}
		}
	}
	return RZ_BIN_DBG_SYMS;
}

RZ_API RZ_BORROW const char *rz_bin_java_class_language(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);
	const char *language = "java";
	char *string = NULL;
	if (bin->constant_pool) {
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool || !java_constant_pool_is_string(cpool)) {
				continue;
			}
			string = java_constant_pool_stringify(cpool);
			if (string && startswith(string, "kotlin/jvm")) {
				language = "kotlin";
				break;
			} else if (string && startswith(string, "org/codehaus/groovy/runtime")) {
				language = "groovy";
				break;
			}
			free(string);
			string = NULL;
		}
	}
	free(string);
	return language;
}

/**
 * \brief Frees a RzBinJavaClass pointer
 */
RZ_API void rz_bin_java_class_free(RZ_NULLABLE RzBinJavaClass *bin) {
	if (!bin) {
		return;
	}
	if (bin->constant_pool) {
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			java_constant_pool_free(bin->constant_pool[i]);
		}
		free(bin->constant_pool);
	}
	if (bin->interfaces) {
		for (ut32 i = 0; i < bin->interfaces_count; ++i) {
			java_interface_free(bin->interfaces[i]);
		}
		free(bin->interfaces);
	}
	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			java_field_free(bin->fields[i]);
		}
		free(bin->fields);
	}
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			java_method_free(bin->methods[i]);
		}
		free(bin->methods);
	}
	if (bin->attributes) {
		for (ut32 i = 0; i < bin->attributes_count; ++i) {
			java_attribute_free(bin->attributes[i]);
		}
		free(bin->attributes);
	}
	free(bin);
}

/**
 * \brief Returns the class name
 */
RZ_API RZ_OWN char *rz_bin_java_class_name(RZ_NONNULL RzBinJavaClass *bin) {
	ut16 index;
	rz_return_val_if_fail(bin, NULL);
	const ConstPool *cpool = java_class_constant_pool_at(bin, bin->this_class);

	if (!cpool || java_constant_pool_resolve(cpool, &index, NULL) != 1) {
		RZ_LOG_ERROR("java bin: unknown class name at constant pool index %u\n", bin->this_class);
		return rz_str_dup("unknown_class");
	}

	char *tmp = java_class_constant_pool_stringify_at(bin, index);
	char *class_name = rz_str_newf("L%s;", tmp);
	free(tmp);
	return class_name;
}

/**
 * \brief Returns the class super name
 */
RZ_API RZ_OWN char *rz_bin_java_class_super(RZ_NONNULL RzBinJavaClass *bin) {
	ut16 index;
	rz_return_val_if_fail(bin, NULL);
	const ConstPool *cpool = java_class_constant_pool_at(bin, bin->super_class);
	if (!cpool || java_constant_pool_resolve(cpool, &index, NULL) != 1) {
		RZ_LOG_ERROR("java bin: unknown super name at constant pool index %u\n", bin->this_class);
		return rz_str_dup("unknown_super");
	}
	char *tmp = java_class_constant_pool_stringify_at(bin, index);
	if (!tmp) {
		return NULL;
	}
	char *class_name = rz_str_newf("L%s;", tmp);
	free(tmp);
	return class_name;
}

RZ_API ut32 rz_bin_java_class_access_flags(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, 0xffffffff);
	return bin->access_flags;
}

/**
 * \brief Returns the readable class access flags
 */
RZ_API RZ_OWN char *rz_bin_java_class_access_flags_readable(RZ_NONNULL RzBinJavaClass *bin, ut16 mask) {
	rz_return_val_if_fail(bin, NULL);
	RzStrBuf *sb = NULL;
	ut16 access_flags = bin->access_flags & mask;

	for (ut32 i = 0; i < CLASS_ACCESS_FLAGS_SIZE; ++i) {
		const AccessFlagsReadable *afr = &access_flags_list[i];
		if (access_flags & afr->flag) {
			if (!sb) {
				sb = rz_strbuf_new(afr->readable);
				if (!sb) {
					return NULL;
				}
			} else {
				rz_strbuf_appendf(sb, " %s", afr->readable);
			}
		}
	}

	return sb ? rz_strbuf_drain(sb) : NULL;
}

static int calculate_padding_ut16(ut16 count) {
	if (count > 9999) {
		return 5;
	} else if (count > 999) {
		return 4;
	} else if (count > 99) {
		return 3;
	}
	return 2;
}

/**
 * \brief Returns the class info as json
 */
RZ_API void rz_bin_java_class_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j) {
	rz_return_if_fail(bin && j);
	char *tmp = NULL;

	pj_o(j);

	pj_ko(j, "version");
	{
		pj_kn(j, "minor", bin->minor_version);
		pj_kn(j, "major", bin->major_version);
		tmp = rz_bin_java_class_version(bin);
		pj_ks(j, "version", tmp ? tmp : "");
		free(tmp);
	}
	pj_end(j);

	pj_kn(j, "constant_pool_count", bin->constant_pool_count);
	pj_k(j, "constant_pool");
	rz_bin_java_class_const_pool_as_json(bin, j);

	pj_kn(j, "access_flags_n", bin->access_flags);
	tmp = rz_bin_java_class_access_flags_readable(bin, ACCESS_FLAG_MASK_ALL);
	pj_ks(j, "access_flags_s", tmp ? tmp : "");
	free(tmp);

	pj_kn(j, "class_n", bin->this_class);
	tmp = rz_bin_java_class_name(bin);
	pj_ks(j, "class_s", tmp ? tmp : "");
	free(tmp);

	pj_kn(j, "super_n", bin->super_class);
	tmp = rz_bin_java_class_super(bin);
	pj_ks(j, "super_s", tmp ? tmp : "");
	free(tmp);

	pj_kn(j, "interfaces_count", bin->interfaces_count);
	pj_k(j, "interfaces");
	rz_bin_java_class_interfaces_as_json(bin, j);

	pj_kn(j, "methods_count", bin->methods_count);
	pj_k(j, "methods");
	rz_bin_java_class_methods_as_json(bin, j);

	pj_kn(j, "fields_count", bin->fields_count);
	pj_k(j, "fields");
	rz_bin_java_class_fields_as_json(bin, j);

	pj_kn(j, "attributes_count", bin->attributes_count);
	pj_ka(j, "attributes");
	for (ut32 i = 0; i < bin->attributes_count; ++i) {
		Attribute *attr = bin->attributes[i];
		if (!attr) {
			continue;
		}
		pj_o(j);
		pj_kn(j, "offset", attr->offset);
		pj_kn(j, "size", attr->attribute_length);
		pj_kn(j, "name_n", attr->attribute_name_index);
		tmp = java_class_constant_pool_stringify_at(bin, attr->attribute_name_index);
		pj_ks(j, "name_s", tmp ? tmp : "");
		free(tmp);
		pj_end(j);
	}
	pj_end(j);
	pj_end(j);
}

/**
 * \brief Returns the class info as text
 */
RZ_API void rz_bin_java_class_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(bin && sb);
	char number[16];
	char *tmp = NULL;
	int padding;

	tmp = rz_bin_java_class_version(bin);
	rz_strbuf_appendf(sb, "Version: (%u.%u) %s\n", bin->major_version, bin->minor_version, tmp);
	free(tmp);

	tmp = rz_bin_java_class_access_flags_readable(bin, ACCESS_FLAG_MASK_ALL);
	rz_strbuf_appendf(sb, "Flags: (0x%04x) %s\n", bin->access_flags, tmp);
	free(tmp);

	tmp = rz_bin_java_class_name(bin);
	rz_strbuf_appendf(sb, "Class: (#%u) %s\n", bin->this_class, tmp);
	free(tmp);

	tmp = rz_bin_java_class_super(bin);
	rz_strbuf_appendf(sb, "Super: (#%u) %s\n", bin->super_class, tmp);
	free(tmp);

	rz_bin_java_class_const_pool_as_text(bin, sb);
	rz_bin_java_class_interfaces_as_text(bin, sb);
	rz_bin_java_class_methods_as_text(bin, sb);
	rz_bin_java_class_fields_as_text(bin, sb);

	rz_strbuf_appendf(sb, "Attributes: %u\n", bin->attributes_count);
	padding = calculate_padding_ut16(bin->attributes_count) + 1;
	for (ut32 i = 0; i < bin->attributes_count; ++i) {
		Attribute *attr = bin->attributes[i];
		if (!attr) {
			continue;
		}
		snprintf(number, sizeof(number), "#%u", i);
		tmp = java_class_constant_pool_stringify_at(bin, attr->attribute_name_index);
		rz_strbuf_appendf(sb, "  %-*s = #%-5u size: %-5u %s\n", padding, number, attr->attribute_name_index, attr->attribute_length, tmp);
		free(tmp);
	}
}

static inline bool is_dual_index(const ConstPool *cpool) {
	return cpool->tag == CONSTANT_POOL_FIELDREF ||
		cpool->tag == CONSTANT_POOL_METHODREF ||
		cpool->tag == CONSTANT_POOL_INTERFACEMETHODREF ||
		cpool->tag == CONSTANT_POOL_NAMEANDTYPE ||
		cpool->tag == CONSTANT_POOL_DYNAMIC ||
		cpool->tag == CONSTANT_POOL_INVOKEDYNAMIC;
}

/**
 * \brief Returns the string linked to the class const pool index
 */
RZ_API RZ_OWN char *rz_bin_java_class_const_pool_resolve_index(RZ_NONNULL RzBinJavaClass *bin, st32 index) {
	rz_return_val_if_fail(bin && index >= 0, NULL);
	ut16 arg0, arg1;
	char *tmp;
	const ConstPool *cpool = java_class_constant_pool_at(bin, index);

	if (!cpool || !index) {
		return NULL;
	}
	if (java_constant_pool_is_string(cpool) ||
		java_constant_pool_is_number(cpool)) {
		return java_constant_pool_stringify(cpool);
	} else if (cpool->tag == CONSTANT_POOL_CLASS) {
		if (java_constant_pool_resolve(cpool, &arg0, NULL) != 1) {
			RZ_LOG_ERROR("java bin: can't resolve constant pool index %u\n", index);
			return NULL;
		}
		tmp = rz_bin_java_class_const_pool_resolve_index(bin, arg0);
		if (tmp[0] == '[' && tmp[1] == 'L') {
			return tmp;
		}
		char *res = rz_str_newf("L%s;", tmp);
		free(tmp);
		return res;
	} else if (cpool->tag == CONSTANT_POOL_STRING) {
		if (java_constant_pool_resolve(cpool, &arg0, NULL) != 1) {
			RZ_LOG_ERROR("java bin: can't resolve constant pool index %u\n", index);
			return NULL;
		}
		char *s0 = rz_bin_java_class_const_pool_resolve_index(bin, arg0);
		tmp = rz_str_newf("\"%s\"", s0);
		free(s0);
		return tmp;
	} else if (is_dual_index(cpool)) {
		if (java_constant_pool_resolve(cpool, &arg0, &arg1) != 2) {
			RZ_LOG_ERROR("java bin: can't resolve constant pool index %u\n", index);
			return NULL;
		}
		char *s0 = arg0 ? rz_bin_java_class_const_pool_resolve_index(bin, arg0) : NULL;
		char *s1 = rz_bin_java_class_const_pool_resolve_index(bin, arg1);
		if ((arg0 && !s0) || !s1) {
			RZ_LOG_ERROR("java bin: can't resolve constant pool index %u\n", index);
			free(s0);
			free(s1);
			return NULL;
		}
		if (!arg0) {
			return s1;
		}
		if (s1[0] == '(') {
			tmp = rz_str_newf("%s%s", s0, s1);
		} else {
			tmp = rz_str_newf("%s.%s", s0, s1);
		}
		free(s0);
		free(s1);
		return tmp;
	}
	return NULL;
}

/**
 * \brief Returns the class info as text source code
 */
RZ_API void rz_bin_java_class_as_source_code(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(bin && sb);

	char *dem = NULL;
	char *tmp = NULL;
	ut16 index;

	void **iter;
	RzPVector *vec = rz_bin_java_class_as_libraries(bin);
	rz_pvector_foreach (vec, iter) {
		tmp = *iter;
		rz_str_replace_char(tmp, '/', '.');
		rz_strbuf_appendf(sb, "import %s;\n", tmp);
	}
	if (rz_pvector_len(vec) > 0) {
		rz_strbuf_appendf(sb, "\n");
	}
	rz_pvector_free(vec);

	rz_strbuf_append(sb, "class");

	tmp = rz_bin_java_class_access_flags_readable(bin, ACCESS_FLAG_MASK_SRC);
	if (tmp) {
		rz_strbuf_appendf(sb, " %s", tmp);
		free(tmp);
	}

	tmp = rz_bin_java_class_name(bin);
	dem = rz_demangler_java(tmp, RZ_DEMANGLER_FLAG_ENABLE_ALL);
	if (dem) {
		rz_strbuf_appendf(sb, " %s", dem);
		RZ_FREE(dem);
	} else {
		rz_strbuf_appendf(sb, " %s", tmp);
	}

	free(tmp);

	if (bin->access_flags & ACCESS_FLAG_SUPER) {
		tmp = rz_bin_java_class_super(bin);
		if (strcmp(tmp, "Ljava/lang/Object;") != 0) {
			rz_str_replace_char(tmp, '/', '.');
			rz_strbuf_appendf(sb, " extends %s", tmp);
		}
		free(tmp);
	}

	if (bin->interfaces_count > 0) {
		rz_strbuf_append(sb, " implements ");
		ut32 k = 0;
		for (ut32 i = 0; i < bin->interfaces_count; ++i) {
			if (!bin->interfaces[i]) {
				continue;
			}
			const ConstPool *cpool = java_class_constant_pool_at(bin, bin->interfaces[i]->index);
			if (!cpool || java_constant_pool_resolve(cpool, &index, NULL) != 1) {
				RZ_LOG_ERROR("java bin: can't resolve constant pool index %u\n", bin->interfaces[i]->index);
				break;
			}
			tmp = java_class_constant_pool_stringify_at(bin, index);
			if ((dem = rz_demangler_java(tmp, RZ_DEMANGLER_FLAG_ENABLE_ALL))) {
				free(tmp);
				tmp = dem;
			}
			if (k > 0) {
				rz_strbuf_appendf(sb, ", %s", tmp);
			} else {
				rz_strbuf_append(sb, tmp);
			}
			free(tmp);
			k++;
		}
		if (k < 1) {
			rz_strbuf_append(sb, "?");
		}
	}

	rz_strbuf_append(sb, " {\n");

	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			const Method *method = bin->methods[i];
			if (!method) {
				continue;
			}
			rz_strbuf_append(sb, "  ");

			tmp = java_method_access_flags_readable(method);
			if (tmp) {
				rz_strbuf_appendf(sb, "%s ", tmp);
				free(tmp);
			}

			char *name = java_class_constant_pool_stringify_at(bin, method->name_index);
			if (!name) {
				name = rz_str_dup("?");
			}
			char *desc = java_class_constant_pool_stringify_at(bin, method->descriptor_index);
			if (!desc) {
				desc = rz_str_dup("(?)V");
			}

			if (desc[0] == '(') {
				tmp = rz_str_newf("%s%s", name, desc);
			} else {
				tmp = rz_str_dup(name);
			}
			free(desc);
			free(name);

			dem = rz_demangler_java(tmp, RZ_DEMANGLER_FLAG_ENABLE_ALL);
			if (!dem) {
				rz_strbuf_append(sb, tmp);
			} else {
				rz_strbuf_append(sb, dem);
				RZ_FREE(dem);
			}
			free(tmp);
			rz_strbuf_append(sb, ";\n");
		}
	}

	if (bin->methods_count > 0 && bin->fields_count) {
		rz_strbuf_append(sb, "\n");
	}

	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			const Field *field = bin->fields[i];
			if (!field) {
				continue;
			}
			rz_strbuf_append(sb, "  ");

			tmp = java_field_access_flags_readable(field);
			if (tmp) {
				rz_strbuf_appendf(sb, "%s ", tmp);
				free(tmp);
			}

			tmp = java_class_constant_pool_stringify_at(bin, field->name_index);
			if (tmp) {
				rz_str_replace_char(tmp, '/', '.');
				rz_strbuf_appendf(sb, "%s ", tmp);
				free(tmp);
			}

			tmp = java_class_constant_pool_stringify_at(bin, field->descriptor_index);
			if (tmp) {
				rz_str_replace_char(tmp, '/', '.');
				rz_strbuf_append(sb, tmp);
				free(tmp);
			}
			rz_strbuf_append(sb, "\n");
		}
	}

	rz_strbuf_append(sb, "}\n");
}

/**
 * \brief Resolves and returns the RzBinAddr struct linked to the input RzBinSpecialSymbol
 */
RZ_API RZ_OWN RzBinAddr *rz_bin_java_class_resolve_symbol(RZ_NONNULL RzBinJavaClass *bin, RzBinSpecialSymbol resolve) {
	rz_return_val_if_fail(bin, NULL);

	RzBinAddr *ret = RZ_NEW0(RzBinAddr);
	if (!ret) {
		return NULL;
	}
	ret->paddr = UT64_MAX;

	char *name = NULL;
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			const Method *method = bin->methods[i];
			if (!method) {
				continue;
			}

			name = java_class_constant_pool_stringify_at(bin, method->name_index);
			if (!name) {
				continue;
			}

			if (resolve == RZ_BIN_SPECIAL_SYMBOL_ENTRY || resolve == RZ_BIN_SPECIAL_SYMBOL_INIT) {
				if (strcmp(name, "<init>") != 0 && strcmp(name, "<clinit>") != 0) {
					free(name);
					continue;
				}
			} else if (resolve == RZ_BIN_SPECIAL_SYMBOL_MAIN) {
				if (strcmp(name, "main") != 0) {
					free(name);
					continue;
				}
			}
			free(name);
			ut64 addr = UT64_MAX;
			for (ut32 i = 0; i < method->attributes_count; ++i) {
				Attribute *attr = method->attributes[i];
				if (attr && attr->type == ATTRIBUTE_TYPE_CODE) {
					AttributeCode *ac = (AttributeCode *)attr->info;
					addr = ac->code_offset;
					break;
				}
			}
			if (addr == UT64_MAX) {
				RZ_LOG_ERROR("java bin: can't resolve symbol address\n");
				continue;
			}
			ret->paddr = addr;
			break;
		}
	}
	return ret;
}

/**
 * \brief Returns a RzPVector<RzBinAddr*> containing the entrypoints
 */
RZ_API RZ_OWN RzPVector /*<RzBinAddr *>*/ *rz_bin_java_class_entrypoints(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *vec = rz_pvector_new(free);
	if (!vec) {
		return NULL;
	}

	char *name = NULL;
	bool is_static;
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			const Method *method = bin->methods[i];
			if (!method) {
				rz_warn_if_reached();
				continue;
			}
			is_static = method->access_flags & METHOD_ACCESS_FLAG_STATIC;
			if (!is_static) {
				name = java_class_constant_pool_stringify_at(bin, method->name_index);
				if (!name) {
					continue;
				}
				if (strcmp(name, "main") != 0 && strcmp(name, "<init>") != 0 && strcmp(name, "<clinit>") != 0) {
					free(name);
					continue;
				}
				free(name);
			}

			ut64 addr = UT64_MAX;
			for (ut32 i = 0; i < method->attributes_count; ++i) {
				Attribute *attr = method->attributes[i];
				if (attr && attr->type == ATTRIBUTE_TYPE_CODE) {
					AttributeCode *ac = (AttributeCode *)attr->info;
					addr = ac->code_offset;
					break;
				}
			}
			if (addr == UT64_MAX) {
				RZ_LOG_ERROR("java bin: can't resolve entrypoint address\n");
				continue;
			}

			RzBinAddr *entrypoint = RZ_NEW0(RzBinAddr);
			if (!entrypoint) {
				rz_warn_if_reached();
				continue;
			}
			entrypoint->vaddr = entrypoint->paddr = addr;
			rz_pvector_push(vec, entrypoint);
		}
	}
	return vec;
}

/**
 * \brief Returns a RzList<RzBinString*> containing the strings
 */
RZ_API RZ_OWN RzPVector /*<RzBinString *>*/ *rz_bin_java_class_strings(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_bin_string_free);
	if (!vec) {
		return NULL;
	}

	char *string;
	if (bin->constant_pool_count > 0) {
		for (ut32 i = 1; i < bin->constant_pool_count; ++i) {
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool || !java_constant_pool_is_string(cpool) || cpool->size < 1) {
				continue;
			}
			string = java_constant_pool_stringify(cpool);
			if (!string) {
				RZ_LOG_ERROR("java bin: expecting a string, got NULL\n");
				continue;
			}
			RzBinString *bstr = RZ_NEW0(RzBinString);
			if (!bstr) {
				free(string);
				rz_warn_if_reached();
				continue;
			}
			bstr->paddr = cpool->offset;
			bstr->ordinal = i;
			bstr->length = cpool->size;
			bstr->size = cpool->size;
			bstr->string = string;
			bstr->type = RZ_STRING_ENC_MUTF8;
			rz_pvector_push(vec, bstr);
		}
	}

	for (ut32 i = 0; i < bin->attributes_count; ++i) {
		Attribute *attr = bin->attributes[i];
		if (attr && attr->type == ATTRIBUTE_TYPE_SOURCEDEBUGEXTENSION) {
			RzBinString *bstr = RZ_NEW0(RzBinString);
			if (!bstr) {
				rz_warn_if_reached();
				continue;
			}
			bstr->paddr = attr->offset;
			bstr->ordinal = i;
			bstr->length = attr->attribute_length;
			bstr->size = attr->attribute_length;
			bstr->string = rz_str_dup(attr->info);
			bstr->type = RZ_STRING_ENC_UTF8;
			rz_pvector_push(vec, bstr);
		}
	}
	return vec;
}

static char *add_class_name_to_name(char *name, char *classname) {
	if (classname) {
		return rz_str_newf("%s.%s", classname, name);
	}
	return rz_str_dup(name);
}

static char *demangle_java_and_free(char *mangled) {
	if (!mangled) {
		return NULL;
	}
	if (startswith(mangled, "unknown_")) {
		return mangled;
	}
	char *demangled = rz_demangler_java(mangled, RZ_DEMANGLER_FLAG_ENABLE_ALL);
	free(mangled);
	return demangled;
}

static void set_lib_and_class_name(char *mangled, char **out_class, char **out_lib) {
	if (!mangled) {
		return;
	}
	bool is_java_lang = startswith(mangled, "Ljava/lang");

	char *object = demangle_java_and_free(mangled);
	if (!object) {
		return;
	}

	*out_class = object;
	if (is_java_lang && !startswith(object, "java.lang")) {
		*out_lib = rz_str_newf("java.lang.%s", object);
	} else {
		*out_lib = rz_str_dup(object);
	}
}

/**
 * \brief Returns a RzList<RzBinSymbol*> containing the class methods
 */
RZ_API RZ_OWN RzList /*<RzBinSymbol *>*/ *rz_bin_java_class_methods_as_symbols(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzList *list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!list) {
		return NULL;
	}

	char *method_name = NULL;
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			const Method *method = bin->methods[i];
			if (!method) {
				rz_warn_if_reached();
				continue;
			}
			const ConstPool *cpool = java_class_constant_pool_at(bin, method->name_index);
			if (!cpool || !java_constant_pool_is_string(cpool)) {
				RZ_LOG_ERROR("java bin: can't resolve method with constant pool index %u\n", method->name_index);
				continue;
			}
			method_name = java_constant_pool_stringify(cpool);
			if (!method_name) {
				continue;
			}
			ut64 size = 0;
			ut64 addr = UT64_MAX;
			for (ut32 i = 0; i < method->attributes_count; ++i) {
				Attribute *attr = method->attributes[i];
				if (attr && attr->type == ATTRIBUTE_TYPE_CODE) {
					AttributeCode *ac = (AttributeCode *)attr->info;
					addr = ac->code_offset;
					size = attr->attribute_length;
					break;
				}
			}
			RzBinSymbol *symbol = rz_bin_symbol_new(NULL, addr, addr);
			if (!symbol) {
				rz_warn_if_reached();
				free(method_name);
				continue;
			}
			char *desc = java_class_constant_pool_stringify_at(bin, method->descriptor_index);
			if (!desc) {
				desc = rz_str_dup("(?)V");
			}

			set_lib_and_class_name(rz_bin_java_class_name(bin), &symbol->classname, &symbol->libname);
			symbol->dname = demangle_java_and_free(rz_str_newf("%s%s", method_name, desc));
			symbol->name = add_class_name_to_name(method_name, symbol->classname);
			symbol->size = size;
			symbol->bind = java_method_is_global(method) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
			symbol->type = RZ_BIN_TYPE_FUNC_STR;
			symbol->ordinal = rz_list_length(list);
			symbol->visibility = method->access_flags;
			symbol->visibility_str = java_method_access_flags_readable(method);
			symbol->method_flags = java_access_flags_to_bin_flags(method->access_flags);
			free(desc);
			free(method_name);
			rz_list_append(list, symbol);
		}
	}
	return list;
}

/**
 * \brief Returns the methods in text format via RzStrBuf arg
 */
RZ_API void rz_bin_java_class_methods_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(bin && sb);

	rz_strbuf_appendf(sb, "Methods: %u\n", bin->methods_count);
	char number[16];
	char *flags, *name, *descr;
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			const Method *method = bin->methods[i];
			if (!method) {
				rz_warn_if_reached();
				continue;
			}
			flags = java_method_access_flags_readable(method);
			name = java_class_constant_pool_stringify_at(bin, method->name_index);
			descr = java_class_constant_pool_stringify_at(bin, method->descriptor_index);

			if (flags) {
				rz_strbuf_appendf(sb, "  %s %s%s;\n", flags, name, descr);
			} else {
				rz_strbuf_appendf(sb, "  %s%s;\n", name, descr);
			}
			rz_strbuf_appendf(sb, "    name: %s\n", name);
			rz_strbuf_appendf(sb, "    descriptor: %s\n", descr);
			rz_strbuf_appendf(sb, "    flags: (0x%04x) %s\n", method->access_flags, flags ? flags : "");

			free(flags);
			free(name);
			free(descr);
			rz_strbuf_appendf(sb, "    attributes: %u\n", method->attributes_count);
			int padding = calculate_padding_ut16(method->attributes_count) + 1;
			for (ut32 i = 0; i < method->attributes_count; ++i) {
				Attribute *attr = method->attributes[i];
				if (!attr) {
					continue;
				}
				snprintf(number, sizeof(number), "#%u", i);
				name = java_class_constant_pool_stringify_at(bin, attr->attribute_name_index);
				rz_strbuf_appendf(sb, "      %-*s = #%-5u size: %-5u %s\n", padding, number, attr->attribute_name_index, attr->attribute_length, name);
				free(name);
			}
		}
	}
}

/**
 * \brief Returns the methods in json format via PJ arg
 */
RZ_API void rz_bin_java_class_methods_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j) {
	rz_return_if_fail(bin && j);

	pj_a(j);

	char *tmp;
	if (bin->methods) {
		for (ut32 i = 0; i < bin->methods_count; ++i) {
			const Method *method = bin->methods[i];
			if (!method) {
				rz_warn_if_reached();
				continue;
			}
			pj_o(j); // {
			pj_kn(j, "offset", method->offset);

			pj_kn(j, "access_flags_n", method->access_flags);
			tmp = java_method_access_flags_readable(method);
			pj_ks(j, "access_flags_s", tmp ? tmp : "");
			free(tmp);

			pj_kn(j, "name_n", method->name_index);
			tmp = java_class_constant_pool_stringify_at(bin, method->name_index);
			pj_ks(j, "name_s", tmp ? tmp : "");
			free(tmp);

			pj_kn(j, "descriptor_n", method->descriptor_index);
			tmp = java_class_constant_pool_stringify_at(bin, method->descriptor_index);
			pj_ks(j, "descriptor_s", tmp ? tmp : "");
			free(tmp);

			pj_kn(j, "attributes_count", method->attributes_count);
			pj_ka(j, "attributes"); // [
			for (ut32 i = 0; i < method->attributes_count; ++i) {
				Attribute *attr = method->attributes[i];
				if (!attr) {
					rz_warn_if_reached();
					continue;
				}
				pj_o(j);
				pj_kn(j, "offset", attr->offset);
				pj_kn(j, "size", attr->attribute_length);
				pj_kn(j, "name_n", attr->attribute_name_index);
				tmp = java_class_constant_pool_stringify_at(bin, attr->attribute_name_index);
				pj_ks(j, "name_s", tmp ? tmp : "");
				free(tmp);
				pj_end(j);
			}
			pj_end(j); // ]
			pj_end(j); // }
		}
	}
	pj_end(j);
}

/**
 * \brief Returns a RzList<RzBinSymbol*> containing the class fields
 */
RZ_API RZ_OWN RzList /*<RzBinSymbol *>*/ *rz_bin_java_class_fields_as_symbols(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzList *list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!list) {
		return NULL;
	}

	char *field_name = NULL;
	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			const Field *field = bin->fields[i];
			if (!field) {
				rz_warn_if_reached();
				continue;
			}
			const ConstPool *cpool = java_class_constant_pool_at(bin, field->name_index);
			if (!cpool || !java_constant_pool_is_string(cpool)) {
				RZ_LOG_ERROR("java bin: can't resolve field with constant pool index %u\n", field->name_index);
				continue;
			}
			field_name = java_constant_pool_stringify(cpool);
			if (!field_name) {
				continue;
			}
			RzBinSymbol *symbol = rz_bin_symbol_new(NULL, field->offset, field->offset);
			if (!symbol) {
				rz_warn_if_reached();
				free(field_name);
				continue;
			}

			set_lib_and_class_name(rz_bin_java_class_name(bin), &symbol->classname, &symbol->libname);
			symbol->name = add_class_name_to_name(field_name, symbol->classname);
			symbol->dname = rz_demangler_java(symbol->name, RZ_DEMANGLER_FLAG_ENABLE_ALL);
			symbol->size = 0;
			symbol->bind = java_field_is_global(field) ? RZ_BIN_BIND_GLOBAL_STR : RZ_BIN_BIND_LOCAL_STR;
			symbol->type = RZ_BIN_TYPE_OBJECT_STR;
			symbol->ordinal = i;
			symbol->visibility = field->access_flags;
			symbol->visibility_str = java_field_access_flags_readable(field);
			symbol->method_flags = java_access_flags_to_bin_flags(field->access_flags);
			free(field_name);
			rz_list_append(list, symbol);
		}
	}
	return list;
}

/**
 * \brief Returns a RzList<RzBinClassField*> containing the class fields
 */
RZ_API RZ_OWN RzList /*<RzBinClassField *>*/ *rz_bin_java_class_fields_as_binfields(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzList *list = rz_list_newf((RzListFree)rz_bin_class_field_free);
	if (!list) {
		return NULL;
	}

	char *name = NULL;
	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			const Field *field = bin->fields[i];
			if (!field) {
				rz_warn_if_reached();
				continue;
			}
			const ConstPool *cpool = java_class_constant_pool_at(bin, field->name_index);
			if (!cpool || !java_constant_pool_is_string(cpool)) {
				RZ_LOG_ERROR("java bin: can't resolve field with constant pool index %u\n", field->name_index);
				continue;
			}
			name = java_constant_pool_stringify(cpool);
			if (!name) {
				continue;
			}

			char *ftype = demangle_java_and_free(java_class_constant_pool_stringify_at(bin, field->descriptor_index));
			RzBinClassField *bf = rz_bin_class_field_new(field->offset, field->offset, name, NULL, NULL, ftype);
			free(ftype);
			if (bf) {
				set_lib_and_class_name(rz_bin_java_class_name(bin), &bf->classname, &bf->libname);
				bf->visibility = field->access_flags;
				bf->flags = java_access_flags_to_bin_flags(field->access_flags);
				rz_list_append(list, bf);
			}
			free(name);
		}
	}
	return list;
}

/**
 * \brief Returns the fields in text format via RzStrBuf arg
 */
RZ_API void rz_bin_java_class_fields_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(bin && sb);

	rz_strbuf_appendf(sb, "Fields: %u\n", bin->fields_count);
	char number[16];
	char *flags, *name, *descr;
	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			const Field *field = bin->fields[i];
			if (!field) {
				rz_warn_if_reached();
				continue;
			}
			flags = java_field_access_flags_readable(field);
			name = java_class_constant_pool_stringify_at(bin, field->name_index);
			descr = java_class_constant_pool_stringify_at(bin, field->descriptor_index);

			if (flags) {
				rz_strbuf_appendf(sb, "  %s %s%s;\n", flags, name, descr);
			} else {
				rz_strbuf_appendf(sb, "  %s%s;\n", name, descr);
			}
			rz_strbuf_appendf(sb, "    name: %s\n", name);
			rz_strbuf_appendf(sb, "    descriptor: %s\n", descr);
			rz_strbuf_appendf(sb, "    flags: (0x%04x) %s\n", field->access_flags, flags);

			free(flags);
			free(name);
			free(descr);
			rz_strbuf_appendf(sb, "    attributes: %u\n", field->attributes_count);
			int padding = calculate_padding_ut16(field->attributes_count) + 1;
			for (ut32 i = 0; i < field->attributes_count; ++i) {
				Attribute *attr = field->attributes[i];
				if (!attr) {
					continue;
				}
				snprintf(number, sizeof(number), "#%u", i);
				name = java_class_constant_pool_stringify_at(bin, attr->attribute_name_index);
				rz_strbuf_appendf(sb, "      %*s = #%-5u size: %-5u %s\n", padding, number, attr->attribute_name_index, attr->attribute_length, name);
				free(name);
			}
		}
	}
}

/**
 * \brief Returns the fields in json format via PJ arg
 */
RZ_API void rz_bin_java_class_fields_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j) {
	rz_return_if_fail(bin && j);

	pj_a(j);

	char *tmp;
	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			const Field *field = bin->fields[i];
			if (!field) {
				rz_warn_if_reached();
				continue;
			}
			pj_o(j); // {

			pj_kn(j, "offset", field->offset);

			pj_kn(j, "access_flags_n", field->access_flags);
			tmp = java_field_access_flags_readable(field);
			pj_ks(j, "access_flags_s", tmp ? tmp : "");
			free(tmp);

			pj_kn(j, "name_n", field->name_index);
			tmp = java_class_constant_pool_stringify_at(bin, field->name_index);
			pj_ks(j, "name_s", tmp ? tmp : "");
			free(tmp);

			pj_kn(j, "descriptor_n", field->descriptor_index);
			tmp = java_class_constant_pool_stringify_at(bin, field->descriptor_index);
			pj_ks(j, "descriptor_s", tmp ? tmp : "");
			free(tmp);

			pj_kn(j, "attributes_count", field->attributes_count);
			pj_ka(j, "attributes"); // [
			for (ut32 i = 0; i < field->attributes_count; ++i) {
				Attribute *attr = field->attributes[i];
				if (!attr) {
					continue;
				}
				pj_o(j);
				pj_kn(j, "offset", attr->offset);
				pj_kn(j, "size", attr->attribute_length);
				pj_kn(j, "name_n", attr->attribute_name_index);
				tmp = java_class_constant_pool_stringify_at(bin, attr->attribute_name_index);
				pj_ks(j, "name_s", tmp ? tmp : "");
				free(tmp);
				pj_end(j);
			}
			pj_end(j); // ]
			pj_end(j); // }
		}
	}
	pj_end(j);
}

static char *import_type(const ConstPool *cpool) {
	if (cpool->tag == CONSTANT_POOL_METHODREF) {
		return RZ_BIN_TYPE_METH_STR;
	} else if (cpool->tag == CONSTANT_POOL_FIELDREF) {
		return "FIELD";
	} else if (cpool->tag == CONSTANT_POOL_INTERFACEMETHODREF) {
		return "IMETH";
	}
	return RZ_BIN_TYPE_UNKNOWN_STR;
}

/**
 * \brief Returns a RzList<RzBinSymbol*> containing the class const pool
 */
RZ_API RZ_OWN RzList /*<RzBinSymbol *>*/ *rz_bin_java_class_const_pool_as_symbols(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzList *list = rz_list_newf((RzListFree)rz_bin_symbol_free);
	if (!list) {
		return NULL;
	}
	char *method_name, *classname;
	ut16 class_index, name_and_type_index, name_index, descriptor_index, class_name_index;
	if (bin->constant_pool) {
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool || !java_constant_pool_is_import(cpool)) {
				continue;
			}
			if (java_constant_pool_resolve(cpool, &class_index, &name_and_type_index) != 2) {
				RZ_LOG_ERROR("java bin: can't resolve symbol with constant pool index %u\n", i);
				break;
			}
			const ConstPool *nat = java_class_constant_pool_at(bin, name_and_type_index);
			if (!nat ||
				java_constant_pool_resolve(nat, &name_index, &descriptor_index) != 2) {
				RZ_LOG_ERROR("java bin: can't resolve symbol with constant pool index %u\n", i);
				break;
			}
			const ConstPool *pclass = java_class_constant_pool_at(bin, class_index);
			if (!pclass ||
				java_constant_pool_resolve(pclass, &class_name_index, NULL) != 1) {
				RZ_LOG_ERROR("java bin: can't resolve symbol with constant pool index %u\n", i);
				break;
			}
			RzBinSymbol *symbol = rz_bin_symbol_new(NULL, cpool->offset, cpool->offset);
			if (!symbol) {
				rz_warn_if_reached();
				break;
			}

			char *desc = java_class_constant_pool_stringify_at(bin, descriptor_index);
			if (!desc) {
				desc = rz_str_dup("(?)V");
			}

			method_name = java_class_constant_pool_stringify_at(bin, name_index);
			if (!method_name) {
				method_name = rz_str_dup("unknown_method");
			}

			classname = java_class_constant_pool_stringify_at(bin, class_name_index);
			if (!classname) {
				classname = rz_str_dup("unknown_class");
			}

			set_lib_and_class_name(rz_str_newf("L%s;", classname), &symbol->classname, &symbol->libname);
			symbol->name = add_class_name_to_name(method_name, symbol->classname);
			if (desc[0] == '(') {
				symbol->dname = rz_str_newf("%s%s", method_name, desc);
			} else {
				symbol->dname = rz_str_dup(method_name);
			}
			symbol->dname = demangle_java_and_free(symbol->dname);
			symbol->bind = RZ_BIN_BIND_IMPORT_STR;
			symbol->type = !strcmp(method_name, "main") ? RZ_BIN_TYPE_FUNC_STR : import_type(cpool);
			symbol->ordinal = i;
			symbol->is_imported = true;
			free(desc);
			free(classname);
			free(method_name);
			rz_list_append(list, symbol);
		}
	}

	return list;
}

/**
 * \brief Returns a RzPVector<RzBinImport*> containing the class const pool
 */
RZ_API RZ_OWN RzPVector /*<RzBinImport *>*/ *rz_bin_java_class_const_pool_as_imports(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *imports = rz_pvector_new((RzListFree)rz_bin_import_free);
	if (!imports) {
		return NULL;
	}
	bool is_main;
	ut16 class_index, name_and_type_index, name_index, descriptor_index, class_name_index;
	if (bin->constant_pool) {
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool || !java_constant_pool_is_import(cpool)) {
				continue;
			}
			if (java_constant_pool_resolve(cpool, &class_index, &name_and_type_index) != 2) {
				RZ_LOG_ERROR("java bin: can't resolve import with constant pool index %u\n", i);
				continue;
			}
			const ConstPool *nat = java_class_constant_pool_at(bin, name_and_type_index);
			if (!nat ||
				java_constant_pool_resolve(nat, &name_index, &descriptor_index) != 2) {
				RZ_LOG_ERROR("java bin: can't resolve import with constant pool index %u\n", i);
				continue;
			}
			const ConstPool *pclass = java_class_constant_pool_at(bin, class_index);
			if (!pclass ||
				java_constant_pool_resolve(pclass, &class_name_index, NULL) != 1) {
				RZ_LOG_ERROR("java bin: can't resolve import with constant pool index %u\n", i);
				continue;
			}

			char *object = java_class_constant_pool_stringify_at(bin, class_name_index);
			if (!object) {
				continue;
			}

			RzBinImport *import = RZ_NEW0(RzBinImport);
			if (!import) {
				rz_warn_if_reached();
				free(object);
				continue;
			}

			set_lib_and_class_name(rz_str_newf("L%s;", object), &import->classname, &import->libname);
			import->name = java_class_constant_pool_stringify_at(bin, name_index);
			is_main = import->name && !strcmp(import->name, "main");
			import->bind = is_main ? RZ_BIN_BIND_GLOBAL_STR : NULL;
			import->type = is_main ? RZ_BIN_TYPE_FUNC_STR : import_type(cpool);
			import->descriptor = java_class_constant_pool_stringify_at(bin, descriptor_index);
			import->ordinal = i;
			rz_pvector_push(imports, import);
			free(object);
		}
	}

	if (bin->interfaces) {
		for (ut32 i = 0; i < bin->interfaces_count; ++i) {
			if (!bin->interfaces[i]) {
				continue;
			}

			const ConstPool *cpool = java_class_constant_pool_at(bin, bin->interfaces[i]->index);
			if (!cpool || java_constant_pool_resolve(cpool, &class_index, NULL) != 1) {
				RZ_LOG_ERROR("java bin: can't resolve interface with constant pool index %u\n", i);
				continue;
			}

			char *object = java_class_constant_pool_stringify_at(bin, class_index);
			if (!object) {
				continue;
			}

			RzBinImport *import = RZ_NEW0(RzBinImport);
			if (!import) {
				rz_warn_if_reached();
				free(object);
				continue;
			}

			set_lib_and_class_name(rz_str_newf("L%s;", object), &import->classname, &import->libname);
			import->name = rz_str_dup("*");
			import->bind = RZ_BIN_BIND_WEAK_STR;
			import->type = RZ_BIN_TYPE_IFACE_STR;
			import->ordinal = i;
			rz_pvector_push(imports, import);
			free(object);
		}
	}

	return imports;
}

/**
 * \brief Returns the class const pool in text format via RzStrBuf arg
 */
RZ_API void rz_bin_java_class_const_pool_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(bin && sb);

	char number[16];
	const char *tag;
	char *text, *rtext;
	rz_strbuf_appendf(sb, "Constant pool: %u\n", bin->constant_pool_count);
	if (bin->constant_pool) {
		int padding = calculate_padding_ut16(bin->constant_pool_count) + 1;
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			rtext = NULL;
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool) {
				continue;
			}
			tag = java_constant_pool_tag_name(cpool);
			if (!tag) {
				RZ_LOG_ERROR("java bin: invalid tag name for constant pool at index %u\n", i);
				continue;
			}
			snprintf(number, sizeof(number), "#%u", i);
			text = java_constant_pool_stringify(cpool);
			if (i > 0 && !java_constant_pool_is_string(cpool) &&
				!java_constant_pool_is_number(cpool)) {
				rtext = rz_bin_java_class_const_pool_resolve_index(bin, i);
			}
			if (rtext) {
				char *dem = rz_demangler_java(rtext, RZ_DEMANGLER_FLAG_ENABLE_ALL);
				if (dem) {
					free(rtext);
					rtext = dem;
				}
				rz_strbuf_appendf(sb, "  %*s = %-19s %-14s // %s\n", padding, number, tag, text, rtext);
			} else {
				rz_strbuf_appendf(sb, "  %*s = %-19s %s\n", padding, number, tag, text);
			}
			free(text);
			free(rtext);
		}
	}
}

/**
 * \brief Returns the class const pool in json format via PJ arg
 */
RZ_API void rz_bin_java_class_const_pool_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j) {
	rz_return_if_fail(bin && j);
	const char *tag;
	char *text, *rtext;
	pj_a(j);
	if (bin->constant_pool) {
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			rtext = NULL;
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool) {
				continue;
			}
			tag = java_constant_pool_tag_name(cpool);
			if (!tag) {
				RZ_LOG_ERROR("java bin: invalid tag name for constant pool at index %u\n", i);
				continue;
			}
			text = java_constant_pool_stringify(cpool);
			pj_o(j);
			pj_kn(j, "index", i);
			pj_kn(j, "tag_n", cpool->tag);
			pj_ks(j, "tag_s", tag);
			pj_ks(j, "value", text ? text : "");
			if (i > 0 && !java_constant_pool_is_string(cpool) &&
				!java_constant_pool_is_number(cpool)) {
				rtext = rz_bin_java_class_const_pool_resolve_index(bin, i);
				pj_ks(j, "resolved", rtext ? rtext : "");
			}
			pj_end(j);
			free(text);
			free(rtext);
		}
	}
	pj_end(j);
}

static RzBinSection *new_section(const char *name, ut64 start, ut64 end, ut32 perm) {
	RzBinSection *section = RZ_NEW0(RzBinSection);
	if (!section) {
		rz_warn_if_reached();
		return NULL;
	}
	section->name = rz_str_dup(name);
	if (!section->name) {
		rz_warn_if_reached();
		free(section);
		return NULL;
	}
	section->paddr = start;
	section->vaddr = start;
	section->size = end - start;
	section->vsize = section->size;
	section->perm = perm;
	return section;
}

static void section_free(void *u) {
	rz_bin_section_free((RzBinSection *)u);
}

static int compare_section_names(const void *a, const void *b) {
	RzBinSection *sec = (RzBinSection *)b;
	return strcmp((const char *)a, sec->name);
}

/**
 * \brief Returns a RzPVector<RzBinSection*> containing the class sections
 */
RZ_API RZ_OWN RzPVector /*<RzBinSection *>*/ *rz_bin_java_class_as_sections(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *sections = rz_pvector_new(section_free);
	if (!sections) {
		return NULL;
	}
	ut32 iname;
	char *tmp;
	char secname[512];
	ut64 end_offset;
	if (bin->constant_pool) {
		rz_pvector_push(sections,
			new_section("class.constant_pool",
				bin->constant_pool_offset,
				bin->interfaces_offset,
				RZ_PERM_R));
	}
	if (bin->interfaces) {
		rz_pvector_push(sections,
			new_section("class.interfaces",
				bin->interfaces_offset,
				bin->fields_offset,
				RZ_PERM_R));
	}
	if (bin->fields) {
		for (ut32 i = 0; i < bin->fields_count; ++i) {
			Field *field = bin->fields[i];
			if (!field) {
				continue;
			}
			tmp = java_class_constant_pool_stringify_at(bin, field->name_index);
			if (!tmp) {
				rz_warn_if_reached();
				continue;
			}
			snprintf(secname, sizeof(secname), "class.fields.%s.attr", tmp);
			if ((i + 1) < bin->fields_count && bin->fields[i + 1]) {
				end_offset = bin->fields[i + 1]->offset;
			} else {
				end_offset = bin->methods_offset;
			}
			for (iname = 0; rz_pvector_find(sections, secname, (RzPVectorComparator)compare_section_names, NULL); iname++) {
				snprintf(secname, sizeof(secname), "class.fields.%s_%d.attr", tmp, iname);
			}
			free(tmp);
			rz_pvector_push(sections, new_section(secname, field->offset, end_offset, RZ_PERM_R));
		}
		rz_pvector_push(sections,
			new_section("class.fields",
				bin->fields_offset,
				bin->methods_offset,
				RZ_PERM_R));
	}
	if (bin->methods) {
		rz_pvector_push(sections,
			new_section("class.methods",
				bin->methods_offset,
				bin->attributes_offset,
				RZ_PERM_R));

		for (ut32 i = 0; i < bin->methods_count; ++i) {
			Method *method = bin->methods[i];
			if (!method || method->attributes_count < 1) {
				continue;
			}
			tmp = java_class_constant_pool_stringify_at(bin, method->name_index);
			if (!tmp) {
				rz_warn_if_reached();
				continue;
			}
			snprintf(secname, sizeof(secname), "class.methods.%s.attr", tmp);
			for (iname = 0; rz_pvector_find(sections, secname, (RzPVectorComparator)compare_section_names, NULL); iname++) {
				snprintf(secname, sizeof(secname), "class.methods.%s_%d.attr", tmp, iname);
			}

			if ((i + 1) < bin->methods_count && bin->methods[i + 1]) {
				end_offset = bin->methods[i + 1]->offset;
			} else {
				end_offset = bin->attributes_offset;
			}
			if (iname > 0) {
				snprintf(secname, sizeof(secname), "class.methods.%s_%d.attr", tmp, iname);
			} else {
				snprintf(secname, sizeof(secname), "class.methods.%s.attr", tmp);
			}
			rz_pvector_push(sections, new_section(secname, method->offset, end_offset, RZ_PERM_R));

			if (!method->attributes) {
				free(tmp);
				continue;
			}

			for (ut32 k = 0; k < method->attributes_count; ++k) {
				Attribute *attr = method->attributes[k];
				if (attr && attr->type == ATTRIBUTE_TYPE_CODE) {
					AttributeCode *ac = (AttributeCode *)attr->info;
					if (iname > 0) {
						snprintf(secname, sizeof(secname), "class.methods.%s_%d.attr.%d.code", tmp, iname, k);
					} else {
						snprintf(secname, sizeof(secname), "class.methods.%s.attr.%d.code", tmp, k);
					}
					ut64 size = ac->code_offset + attr->attribute_length;
					rz_pvector_push(sections, new_section(secname, ac->code_offset, size, RZ_PERM_R | RZ_PERM_X));
					break;
				}
			}
			free(tmp);
		}
	}
	if (bin->attributes) {
		rz_pvector_push(sections,
			new_section("class.attr",
				bin->attributes_offset,
				bin->class_end_offset,
				RZ_PERM_R));
	}

	return sections;
}

static int compare_strings(const void *a, const void *b, void *user) {
	return strcmp((const char *)a, (const char *)b);
}

/**
 * \brief Returns a RzPVector<char*> containing the class libraries
 */
RZ_API RZ_OWN RzPVector /*<char *>*/ *rz_bin_java_class_as_libraries(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzPVector *vec = rz_pvector_new(free);
	if (!vec) {
		return NULL;
	}
	ut16 arg0, arg1;
	char *tmp;

	if (bin->constant_pool) {
		for (ut32 i = 0; i < bin->constant_pool_count; ++i) {
			tmp = NULL;
			const ConstPool *cpool = bin->constant_pool[i];
			if (!cpool) {
				continue;
			}
			if (cpool->tag == CONSTANT_POOL_CLASS) {
				if (java_constant_pool_resolve(cpool, &arg0, &arg1) != 1) {
					RZ_LOG_ERROR("java bin: can't resolve library with constant pool index %u\n", i);
					break;
				}
				// arg0 is name_index
				tmp = java_class_constant_pool_stringify_at(bin, arg0);
			} else if (java_constant_pool_is_import(cpool)) {
				if (java_constant_pool_resolve(cpool, &arg0, &arg1) != 2) {
					RZ_LOG_ERROR("java bin: can't resolve library with constant pool index %u\n", i);
					break;
				}
				// arg0 is name_and_type_index
				const ConstPool *nat = java_class_constant_pool_at(bin, arg0);
				if (!nat ||
					java_constant_pool_resolve(nat, &arg0, &arg1) != 1) {
					RZ_LOG_ERROR("java bin: can't resolve library with constant pool index %u\n", i);
					break;
				}
				// arg0 is name_index
				tmp = java_class_constant_pool_stringify_at(bin, arg0);
			}
			if (tmp && !rz_pvector_find(vec, tmp, compare_strings, NULL)) {
				rz_pvector_push(vec, tmp);
			} else {
				free(tmp);
			}
		}
	}
	return vec;
}

/**
 * \brief Returns the class interfaces as text via RzStrBuf arg
 */
RZ_API void rz_bin_java_class_interfaces_as_text(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL RzStrBuf *sb) {
	rz_return_if_fail(bin && sb);

	ut16 index;
	char number[16];
	char *tmp = NULL;
	rz_strbuf_appendf(sb, "Interfaces: %u\n", bin->interfaces_count);
	if (bin->interfaces) {
		int padding = calculate_padding_ut16(bin->constant_pool_count) + 1;
		for (ut32 i = 0; i < bin->interfaces_count; ++i) {
			if (!bin->interfaces[i]) {
				continue;
			}
			const ConstPool *cpool = java_class_constant_pool_at(bin, bin->interfaces[i]->index);
			if (!cpool || java_constant_pool_resolve(cpool, &index, NULL) != 1) {
				RZ_LOG_ERROR("java bin: can't resolve interface with constant pool index %u\n", i);
				break;
			}
			snprintf(number, sizeof(number), "#%u", i);
			tmp = java_class_constant_pool_stringify_at(bin, index);
			rz_str_replace_char(tmp, '/', '.');
			rz_strbuf_appendf(sb, "  %*s = #%-5u %s\n", padding, number, index, tmp);
			free(tmp);
		}
	}
}

/**
 * \brief Returns the class interfaces as json via PJ arg
 */
RZ_API void rz_bin_java_class_interfaces_as_json(RZ_NONNULL RzBinJavaClass *bin, RZ_NONNULL PJ *j) {
	rz_return_if_fail(bin && j);
	pj_a(j);
	char *tmp = NULL;
	ut16 index;
	if (bin->interfaces) {
		for (ut32 i = 0; i < bin->interfaces_count; ++i) {
			if (!bin->interfaces[i]) {
				continue;
			}

			const ConstPool *cpool = java_class_constant_pool_at(bin, bin->interfaces[i]->index);
			if (!cpool || java_constant_pool_resolve(cpool, &index, NULL) != 1) {
				RZ_LOG_ERROR("java bin: can't resolve interface with constant pool index %u\n", i);
				continue;
			}
			pj_o(j);
			pj_kn(j, "offset", bin->interfaces[i]->offset);
			pj_kn(j, "name_n", bin->interfaces[i]->index);
			tmp = java_class_constant_pool_stringify_at(bin, index);
			rz_str_replace_char(tmp, '/', '.');
			pj_ks(j, "name_s", tmp ? tmp : "");
			free(tmp);
			pj_end(j);
		}
	}
	pj_end(j);
}

/**
 * \brief Returns a RzPVector<RzBinClass*> containing only the class of the bin
 */
RZ_API RZ_OWN RzPVector /*<RzBinClass *>*/ *rz_bin_java_class_as_classes(RZ_NONNULL RzBinJavaClass *bin) {
	rz_return_val_if_fail(bin, NULL);

	RzBinClass *bclass = NULL;
	RzPVector *vec = rz_pvector_new((RzPVectorFree)rz_bin_class_free);
	if (!vec) {
		return NULL;
	}

	bclass = RZ_NEW0(RzBinClass);
	if (!bclass) {
		rz_pvector_free(vec);
		return NULL;
	}
	rz_pvector_push(vec, bclass);

	bclass->name = demangle_java_and_free(rz_bin_java_class_name(bin));
	bclass->super = demangle_java_and_free(rz_bin_java_class_super(bin));
	bclass->visibility = rz_bin_java_class_access_flags(bin);
	bclass->visibility_str = rz_bin_java_class_access_flags_readable(bin, ACCESS_FLAG_MASK_ALL_NO_SUPER);

	bclass->methods = rz_bin_java_class_methods_as_symbols(bin);
	bclass->fields = rz_bin_java_class_fields_as_binfields(bin);
	if (!bclass->methods || !bclass->fields) {
		rz_pvector_free(vec);
		return NULL;
	}

	return vec;
}
