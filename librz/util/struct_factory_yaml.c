// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

// use the same max depth as pj
#define STRUCT_YAML_PRINTER_DEPTH_MAX (RZ_PRINT_JSON_DEPTH_LIMIT << 1)

typedef struct struct_yaml_printer_t {
	RzStrBuf sb;
	size_t depth;
	ut8 stack[STRUCT_YAML_PRINTER_DEPTH_MAX];
	char pad[STRUCT_YAML_PRINTER_DEPTH_MAX];
} StructYamlPrinter;

#define builder_yaml_is_array(y) (y->stack[y->depth - 1] == RZ_STRUCT_FACTORY_BLOCK_ARRAY)
#define builder_yaml_add_padding(y) \
	do { \
		if (y->depth > 1) { \
			size_t n = (y->depth - 1) << 1; \
			rz_strbuf_append_n(&y->sb, y->pad, n); \
		} \
	} while (0)

static void builder_yaml_new_struct(RZ_NULLABLE void *user, RzStructFactoryBlock block) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (yaml->depth > 0) {
		rz_strbuf_append(&yaml->sb, "\n");
	}

	yaml->depth++;
	yaml->stack[yaml->depth - 1] = (ut8)block;
}

static void builder_yaml_end_struct(RZ_NULLABLE void *user) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;
	yaml->depth--;
}

static void builder_yaml_key(RZ_NULLABLE void *user, RZ_NONNULL const char *key) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	builder_yaml_add_padding(yaml);
	rz_strbuf_appendf(&yaml->sb, "%s:", key);
}

static void builder_yaml_val_unsigned(RZ_NULLABLE void *user, ut64 n) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- %" PFMT64u "\n", n);
	} else {
		rz_strbuf_appendf(&yaml->sb, " %" PFMT64u "\n", n);
	}
}

static void builder_yaml_val_signed(RZ_NULLABLE void *user, st64 n) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- %" PFMT64d "\n", n);
	} else {
		rz_strbuf_appendf(&yaml->sb, " %" PFMT64d "\n", n);
	}
}

static void builder_yaml_val_double(RZ_NULLABLE void *user, double d) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- %f\n", d);
	} else {
		rz_strbuf_appendf(&yaml->sb, " %f\n", d);
	}
}

static void builder_yaml_val_bool(RZ_NULLABLE void *user, bool b) {
	const char *s = b ? "true" : "false";
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- %s\n", s);
	} else {
		rz_strbuf_appendf(&yaml->sb, " %s\n", s);
	}
}

static void builder_yaml_val_string(RZ_NULLABLE void *user, RZ_NONNULL const char *s) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	char *escaped = rz_str_escape_utf8_for_json(s, -1);

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- \"%s\"\n", escaped);
	} else {
		rz_strbuf_appendf(&yaml->sb, " \"%s\"\n", escaped);
	}

	free(escaped);
}

static const RzStructFactoryIterator factory_iterator_yaml = {
	.new_struct = builder_yaml_new_struct,
	.end_struct = builder_yaml_end_struct,
	.key = builder_yaml_key,
	.val_unsigned = builder_yaml_val_unsigned,
	.val_signed = builder_yaml_val_signed,
	.val_double = builder_yaml_val_double,
	.val_bool = builder_yaml_val_bool,
	.val_string = builder_yaml_val_string,
};
