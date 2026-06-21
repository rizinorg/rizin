// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

// use the same max depth as pj
#define STRUCT_YAML_MAX_DEPTH   RZ_PRINT_JSON_DEPTH_LIMIT
#define STRUCT_YAML_MAX_PAD_LEN (STRUCT_YAML_MAX_DEPTH << 1)

typedef struct struct_yaml_printer_t {
	RzStrBuf sb;
	size_t depth;
	bool first;
	ut8 stack[STRUCT_YAML_MAX_DEPTH];
	char pad[STRUCT_YAML_MAX_PAD_LEN];
} StructYamlPrinter;

#define builder_yaml_is_array(y)  (y->stack[y->depth - 1] == RZ_STRUCTURED_DATA_BLOCK_ARRAY)
#define builder_yaml_was_array(y) (y->depth > 2 && y->stack[y->depth - 2] == RZ_STRUCTURED_DATA_BLOCK_ARRAY)
#define builder_yaml_add_padding(y) \
	do { \
		if (y->depth > 1) { \
			size_t n = (y->depth - 1) << 1; \
			if (n > sizeof(y->pad)) { \
				n = sizeof(y->pad); \
			} \
			rz_strbuf_append_n(&y->sb, y->pad, n); \
		} \
	} while (0)

static void builder_yaml_init_printer(StructYamlPrinter *yaml) {
	memset(yaml, 0, sizeof(StructYamlPrinter));
	rz_strbuf_init(&yaml->sb);
	memset(yaml->pad, ' ', sizeof(yaml->pad));
}

static char *builder_yaml_fini_printer(StructYamlPrinter *yaml) {
	return rz_strbuf_drain_nofree(&yaml->sb);
}

static void builder_yaml_new_struct(RZ_NULLABLE void *user, RzStructuredDataBlock block, size_t n_elems) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (yaml->depth > 0) {
		if (n_elems < 1) {
			rz_strbuf_append(&yaml->sb, block == RZ_STRUCTURED_DATA_BLOCK_ARRAY ? " []\n" : " {}\n");
			yaml->first = false;
		} else if (builder_yaml_is_array(yaml)) {
			builder_yaml_add_padding(yaml);
			rz_strbuf_append(&yaml->sb, "-");
			yaml->first = true;
		} else {
			rz_strbuf_append(&yaml->sb, "\n");
			yaml->first = true;
		}
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

	if (yaml->first && builder_yaml_was_array(yaml)) {
		rz_strbuf_appendf(&yaml->sb, " %s:", key);
	} else {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "%s:", key);
	}
	yaml->first = false;
}

static void builder_yaml_val_unsigned(RZ_NULLABLE void *user, ut64 n, bool hex) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		if (hex) {
			rz_strbuf_appendf(&yaml->sb, "- 0x%" PFMT64x "\n", n);
		} else {
			rz_strbuf_appendf(&yaml->sb, "- %" PFMT64u "\n", n);
		}
	} else {
		if (hex) {
			rz_strbuf_appendf(&yaml->sb, " 0x%" PFMT64x "\n", n);
		} else {
			rz_strbuf_appendf(&yaml->sb, " %" PFMT64u "\n", n);
		}
	}
	yaml->first = false;
}

static void builder_yaml_val_signed(RZ_NULLABLE void *user, st64 n) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- %" PFMT64d "\n", n);
	} else {
		rz_strbuf_appendf(&yaml->sb, " %" PFMT64d "\n", n);
	}
	yaml->first = false;
}

static void builder_yaml_val_double(RZ_NULLABLE void *user, double d) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- %f\n", d);
	} else {
		rz_strbuf_appendf(&yaml->sb, " %f\n", d);
	}
	yaml->first = false;
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
	yaml->first = false;
}

static bool builder_yaml_val_string_is_multiline(const char *s) {
	const char *current = strchr(s, '\n');
	if (!current || !current[1]) {
		// there is no new line or is at the end of the line.
		return false;
	}
	return rz_str_trim_head_ro(current) != NULL;
}

static void builder_yaml_val_string_multiline(StructYamlPrinter *yaml, const char *s) {
	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_append(&yaml->sb, "- |\n");
	} else {
		rz_strbuf_append(&yaml->sb, " |\n");
	}

	do {
		builder_yaml_add_padding(yaml);
		rz_strbuf_append(&yaml->sb, "  ");
		const char *newline = strchr(s, '\n');
		if (!newline) {
			rz_strbuf_appendf(&yaml->sb, "%s\n", s);
			break;
		}
		// we append also the newline.
		newline++;
		rz_strbuf_append_n(&yaml->sb, s, newline - s);
		s = newline;
	} while (*s);
	yaml->first = false;
}

static void builder_yaml_val_string_singleline(StructYamlPrinter *yaml, const char *s) {
	char *escaped = rz_str_escape_utf8_for_json(s, -1);

	if (builder_yaml_is_array(yaml)) {
		builder_yaml_add_padding(yaml);
		rz_strbuf_appendf(&yaml->sb, "- \"%s\"\n", escaped);
	} else {
		rz_strbuf_appendf(&yaml->sb, " \"%s\"\n", escaped);
	}
	yaml->first = false;

	free(escaped);
}

static void builder_yaml_val_string(RZ_NULLABLE void *user, RZ_NONNULL const char *s) {
	StructYamlPrinter *yaml = (StructYamlPrinter *)user;

	if (builder_yaml_val_string_is_multiline(s)) {
		builder_yaml_val_string_multiline(yaml, s);
	} else {
		builder_yaml_val_string_singleline(yaml, s);
	}
}

static const RzStructuredDataIterator builder_yaml_iterator = {
	.new_struct = builder_yaml_new_struct,
	.end_struct = builder_yaml_end_struct,
	.key = builder_yaml_key,
	.val_unsigned = builder_yaml_val_unsigned,
	.val_signed = builder_yaml_val_signed,
	.val_double = builder_yaml_val_double,
	.val_bool = builder_yaml_val_bool,
	.val_string = builder_yaml_val_string,
};
