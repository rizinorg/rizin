// SPDX-FileCopyrightText: 2025 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

static void builder_json_new_struct(RZ_NULLABLE void *user, RzStructuredDataBlock block, size_t n_elems) {
	switch (block) {
	case RZ_STRUCTURED_DATA_BLOCK_MAP:
		pj_o((PJ *)user);
		break;
	case RZ_STRUCTURED_DATA_BLOCK_ARRAY:
		pj_a((PJ *)user);
		break;
	default:
		break;
	}
}

static void builder_json_end_struct(RZ_NULLABLE void *user) {
	pj_end((PJ *)user);
}

static void builder_json_key(RZ_NULLABLE void *user, RZ_NONNULL const char *key) {
	pj_k((PJ *)user, key);
}

static void builder_json_val_unsigned(RZ_NULLABLE void *user, ut64 n, bool hex) {
	pj_n((PJ *)user, n);
}

static void builder_json_val_signed(RZ_NULLABLE void *user, st64 n) {
	pj_N((PJ *)user, n);
}

static void builder_json_val_double(RZ_NULLABLE void *user, double d) {
	pj_d((PJ *)user, d);
}

static void builder_json_val_bool(RZ_NULLABLE void *user, bool b) {
	pj_b((PJ *)user, b);
}

static void builder_json_val_string(RZ_NULLABLE void *user, RZ_NONNULL const char *v) {
	pj_s((PJ *)user, v);
}

static const RzStructuredDataIterator builder_json_iterator = {
	.new_struct = builder_json_new_struct,
	.end_struct = builder_json_end_struct,
	.key = builder_json_key,
	.val_unsigned = builder_json_val_unsigned,
	.val_signed = builder_json_val_signed,
	.val_double = builder_json_val_double,
	.val_bool = builder_json_val_bool,
	.val_string = builder_json_val_string,
};
