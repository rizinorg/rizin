// SPDX-FileCopyrightText: 2018-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_util.h>
#include <rz_util/rz_print.h>

RZ_API void pj_raw(PJ *j, const char *msg) {
	rz_return_if_fail(j && msg);
	if (*msg) {
		rz_strbuf_append(&j->sb, msg);
	}
}

static void pj_comma(PJ *j) {
	rz_return_if_fail(j);
	if (!j->is_key) {
		if (!j->is_first) {
			pj_raw(j, ",");
		}
	}
	j->is_first = false;
	j->is_key = false;
}

RZ_API PJ *pj_new(void) {
	PJ *j = RZ_NEW0(PJ);
	if (j) {
		rz_strbuf_init(&j->sb);
		j->is_first = true;
		j->str_encoding = PJ_ENCODING_STR_DEFAULT;
		j->num_encoding = PJ_ENCODING_NUM_DEFAULT;
	}
	return j;
}

RZ_API PJ *pj_new_with_encoding(PJEncodingStr str_encoding, PJEncodingNum num_encoding) {
	PJ *j = pj_new();
	if (j) {
		j->str_encoding = str_encoding;
		j->num_encoding = num_encoding;
	}
	return j;
}

RZ_API void pj_free(PJ *pj) {
	if (pj) {
		rz_strbuf_fini(&pj->sb);
		free(pj);
	}
}

RZ_API void pj_reset(PJ *j) {
	rz_return_if_fail(j);
	rz_strbuf_set(&j->sb, "");
	j->level = 0;
	j->is_first = true;
	j->is_key = false;
}

RZ_API char *pj_drain(PJ *pj) {
	rz_return_val_if_fail(pj && pj->level == 0, NULL);
	char *res = rz_strbuf_drain_nofree(&pj->sb);
	free(pj);
	return res;
}

RZ_API const char *pj_string(PJ *j) {
	return j ? rz_strbuf_get(&j->sb) : NULL;
}

static PJ *pj_begin(PJ *j, char type) {
	if (j) {
		if (!j || j->level >= RZ_PRINT_JSON_DEPTH_LIMIT) {
			return NULL;
		}
		char msg[2] = { type, 0 };
		pj_raw(j, msg);
		j->braces[j->level] = (type == '{') ? '}' : ']';
		j->level++;
		j->is_first = true;
	}
	return j;
}

RZ_API PJ *pj_o(PJ *j) {
	rz_return_val_if_fail(j, j);
	pj_comma(j);
	return pj_begin(j, '{');
}

RZ_API PJ *pj_a(PJ *j) {
	rz_return_val_if_fail(j, j);
	pj_comma(j);
	return pj_begin(j, '[');
}

RZ_API PJ *pj_end(PJ *j) {
	rz_return_val_if_fail(j, j);
	if (j->level < 1) {
		return j;
	}
	if (--j->level < 1) {
		char msg[2] = { j->braces[j->level], 0 };
		pj_raw(j, msg);
		j->level = 0;
		return j;
	}
	j->is_first = false;
	char msg[2] = { j->braces[j->level], 0 };
	pj_raw(j, msg);
	return j;
}

RZ_API PJ *pj_k(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	j->is_key = false;
	pj_s(j, k);
	pj_raw(j, ":");
	j->is_first = false;
	j->is_key = true;
	return j;
}

RZ_API PJ *pj_knull(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_null(j);
	return j;
}

RZ_API PJ *pj_kn(PJ *j, const char *k, ut64 n) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	if (j->num_encoding != PJ_ENCODING_NUM_DEFAULT) {
		pj_ne(j, n);
	} else {
		pj_n(j, n);
	}
	return j;
}

RZ_API PJ *pj_kN(PJ *j, const char *k, st64 n) {
	if (j && k) {
		pj_k(j, k);
		pj_N(j, n);
	}
	return j;
}

RZ_API PJ *pj_kd(PJ *j, const char *k, double d) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_d(j, d);
	return j;
}

RZ_API PJ *pj_kf(PJ *j, const char *k, float d) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_f(j, d);
	return j;
}
RZ_API PJ *pj_ki(PJ *j, const char *k, int i) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_i(j, i);
	return j;
}

RZ_API PJ *pj_ko(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_o(j);
	return j;
}

RZ_API PJ *pj_ka(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_a(j);
	return j;
}

RZ_API PJ *pj_ks(PJ *j, const char *k, const char *v) {
	rz_return_val_if_fail(j && k && v, j);
	pj_k(j, k);
	if (j->str_encoding != PJ_ENCODING_STR_DEFAULT) {
		pj_se(j, v);
	} else {
		pj_s(j, v);
	}
	return j;
}

RZ_API PJ *pj_kb(PJ *j, const char *k, bool v) {
	rz_return_val_if_fail(j && k, j);
	pj_k(j, k);
	pj_b(j, v);
	return j;
}

RZ_API PJ *pj_null(PJ *j) {
	rz_return_val_if_fail(j, j);
	pj_raw(j, "null");
	return j;
}

RZ_API PJ *pj_b(PJ *j, bool v) {
	rz_return_val_if_fail(j, j);
	pj_comma(j);
	pj_raw(j, rz_str_bool(v));
	return j;
}

RZ_API PJ *pj_s(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	pj_comma(j);
	pj_raw(j, "\"");
	char *ek = rz_str_escape_utf8_for_json(k, -1);
	if (ek) {
		pj_raw(j, ek);
		free(ek);
	} else {
		eprintf("cannot escape string\n");
	}
	pj_raw(j, "\"");
	return j;
}

RZ_API PJ *pj_se(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	pj_comma(j);
	if (j->str_encoding == PJ_ENCODING_STR_ARRAY) {
		pj_raw(j, "[");
	} else {
		pj_raw(j, "\"");
	}
	char *en = rz_str_encoded_json(k, -1, j->str_encoding);
	if (en) {
		pj_raw(j, en);
		free(en);
	}
	if (j->str_encoding == PJ_ENCODING_STR_ARRAY) {
		pj_raw(j, "]");
	} else {
		pj_raw(j, "\"");
	}
	return j;
}

RZ_API PJ *pj_r(PJ *j, const unsigned char *v, size_t v_len) {
	rz_return_val_if_fail(j && v, j);
	size_t i;
	pj_a(j);
	for (i = 0; i < v_len; i++) {
		pj_i(j, v[i]);
	}
	pj_end(j);
	return j;
}

RZ_API PJ *pj_kr(PJ *j, const char *k, const unsigned char *v, size_t v_len) {
	rz_return_val_if_fail(j && k && v, j);
	pj_k(j, k);
	pj_r(j, v, v_len);
	return j;
}

RZ_API PJ *pj_j(PJ *j, const char *k) {
	rz_return_val_if_fail(j && k, j);
	if (*k) {
		pj_comma(j);
		pj_raw(j, k);
	}
	return j;
}

RZ_API PJ *pj_n(PJ *j, ut64 n) {
	rz_return_val_if_fail(j, j);
	pj_comma(j);
	pj_raw(j, sdb_fmt("%" PFMT64u, n));
	return j;
}

RZ_API PJ *pj_ne(PJ *j, ut64 n) {
	rz_return_val_if_fail(j, j);
	pj_comma(j);
	if (j->num_encoding == PJ_ENCODING_NUM_STR) {
		pj_raw(j, sdb_fmt("\"%" PFMT64u "\"", n));
	} else if (j->num_encoding == PJ_ENCODING_NUM_HEX) {
		pj_raw(j, sdb_fmt("\"0x%" PFMT64x "\"", n));
	} else {
		pj_n(j, n);
	}
	return j;
}

RZ_API PJ *pj_N(PJ *j, st64 n) {
	rz_return_val_if_fail(j, NULL);
	pj_comma(j);
	pj_raw(j, sdb_fmt("%" PFMT64d, n));
	return j;
}

RZ_API PJ *pj_f(PJ *j, float f) {
	rz_return_val_if_fail(j, NULL);
	pj_comma(j);
	pj_raw(j, sdb_fmt("%f", f));
	return j;
}

RZ_API PJ *pj_d(PJ *j, double d) {
	rz_return_val_if_fail(j, NULL);
	pj_comma(j);
	pj_raw(j, sdb_fmt("%lf", d));
	return j;
}

RZ_API PJ *pj_i(PJ *j, int i) {
	if (j) {
		pj_comma(j);
		pj_raw(j, sdb_fmt("%d", i));
	}
	return j;
}
