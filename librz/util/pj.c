/* radare - LGPL - Copyright 2018-2019 - pancake */

#include <rz_util.h>
#include <rz_util/rz_print.h>

static void pj_raw(PJ *j, const char *msg) {
	rz_return_if_fail (j && msg);
	if (*msg) {
		rz_strbuf_append (&j->sb, msg);
	}
}

static void pj_comma(PJ *j) {
	rz_return_if_fail (j);
	if (!j->is_key) {
		if (!j->is_first) {
			pj_raw (j, ",");
		}
	}
	j->is_first = false;
	j->is_key = false;
}

RZ_API PJ *pj_new(void) {
	PJ *j = R_NEW0 (PJ);
	if (j) {
		rz_strbuf_init (&j->sb);
		j->is_first = true;
	}
	return j;
}

RZ_API void pj_free(PJ *pj) {
	if (pj) {
		rz_strbuf_fini (&pj->sb);
		free (pj);
	}
}

RZ_API void pj_reset(PJ *j) {
	rz_return_if_fail (j);
	rz_strbuf_set (&j->sb, "");
	j->level = 0;
	j->is_first = true;
	j->is_key = false;
}

RZ_API char *pj_drain(PJ *pj) {
	rz_return_val_if_fail (pj && pj->level == 0, NULL);
	char *res = rz_strbuf_drain_nofree (&pj->sb);
	free (pj);
	return res;
}

RZ_API const char *pj_string(PJ *j) {
	return j? rz_strbuf_get (&j->sb): NULL;
}

static PJ *pj_begin(PJ *j, char type) {
	if (j) {
		if (!j || j->level >= R_PRINT_JSON_DEPTH_LIMIT) {
			return NULL;
		}
		char msg[2] = { type, 0 };
		pj_raw (j, msg);
		j->braces[j->level] = (type == '{') ? '}' : ']';
		j->level++;
		j->is_first = true;
	}
	return j;
}

RZ_API PJ *pj_o(PJ *j) {
	rz_return_val_if_fail (j, j);
	pj_comma (j);
	return pj_begin (j, '{');
}

RZ_API PJ *pj_a(PJ *j) {
	rz_return_val_if_fail (j, j);
	pj_comma (j);
	return pj_begin (j, '[');
}

RZ_API PJ *pj_end(PJ *j) {
	rz_return_val_if_fail (j, j);
	if (j->level < 1) {
		return j;
	}
	if (--j->level < 1) {
		char msg[2] = { j->braces[j->level], 0 };
		pj_raw (j, msg);
		j->level = 0;
		return j;
	}
	j->is_first = false;
	char msg[2] = { j->braces[j->level], 0 };
	pj_raw (j, msg);
	return j;
}

RZ_API PJ *pj_k(PJ *j, const char *k) {
	rz_return_val_if_fail (j && k, j);
	j->is_key = false;
	pj_s (j, k);
	pj_raw (j, ":");
	j->is_first = false;
	j->is_key = true;
	return j;
}

RZ_API PJ *pj_knull(PJ *j, const char *k) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_null (j);
	return j;
}

RZ_API PJ *pj_kn(PJ *j, const char *k, ut64 n) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_n (j, n);
	return j;
}

RZ_API PJ *pj_kN(PJ *j, const char *k, st64 n) {
	if (j && k) {
		pj_k (j, k);
		pj_N (j, n);
	}
	return j;
}

RZ_API PJ *pj_kd(PJ *j, const char *k, double d) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_d (j, d);
	return j;
}

RZ_API PJ *pj_kf(PJ *j, const char *k, float d) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_f (j, d);
	return j;
}
RZ_API PJ *pj_ki(PJ *j, const char *k, int i) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_i (j, i);
	return j;
}

RZ_API PJ *pj_ko(PJ *j, const char *k) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_o (j);
	return j;
}

RZ_API PJ *pj_ka(PJ *j, const char *k) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_a (j);
	return j;
}

RZ_API PJ *pj_ks(PJ *j, const char *k, const char *v) {
	rz_return_val_if_fail (j && k && v, j);
	pj_k (j, k);
	pj_s (j, v);
	return j;
}

RZ_API PJ *pj_kb(PJ *j, const char *k, bool v) {
	rz_return_val_if_fail (j && k, j);
	pj_k (j, k);
	pj_b (j, v);
	return j;
}

RZ_API PJ *pj_null(PJ *j) {
	rz_return_val_if_fail (j, j);
	pj_raw (j, "null");
	return j;
}

RZ_API PJ *pj_b(PJ *j, bool v) {
	rz_return_val_if_fail (j, j);
	pj_comma (j);
	pj_raw (j, rz_str_bool (v));
	return j;
}

RZ_API PJ *pj_s(PJ *j, const char *k) {
	rz_return_val_if_fail (j && k, j);
	pj_comma (j);
	pj_raw (j, "\"");
	char *ek = rz_str_escape_utf8_for_json (k, -1);
	if (ek) {
		pj_raw (j, ek);
		free (ek);
	} else {
		eprintf ("cannot escape string\n");
	}
	pj_raw (j, "\"");
	return j;
}

RZ_API PJ *pj_r(PJ *j, const unsigned char *v, size_t v_len) {
	rz_return_val_if_fail (j && v, j);
	size_t i;
	pj_a (j);
	for (i = 0; i < v_len; i++) {
		pj_i (j, v[i]);
	}
	pj_end (j);
	return j;
}

RZ_API PJ *pj_kr(PJ *j, const char *k, const unsigned char *v, size_t v_len) {
	rz_return_val_if_fail (j && k && v, j);
	pj_k (j, k);
	pj_r (j, v, v_len);
	return j;
}

RZ_API PJ *pj_j(PJ *j, const char *k) {
	rz_return_val_if_fail (j && k, j);
	if (*k) {
		pj_comma (j);
		pj_raw (j, k);
	}
	return j;
}

RZ_API PJ *pj_n(PJ *j, ut64 n) {
	rz_return_val_if_fail (j, j);
	pj_comma (j);
	pj_raw (j, sdb_fmt ("%" PFMT64u, n));
	return j;
}

RZ_API PJ *pj_N(PJ *j, st64 n) {
	rz_return_val_if_fail (j, NULL);
	pj_comma (j);
	pj_raw (j, sdb_fmt ("%"PFMT64d, n));
	return j;
}

RZ_API PJ *pj_f(PJ *j, float f) {
	rz_return_val_if_fail (j, NULL);
	pj_comma (j);
	pj_raw (j, sdb_fmt ("%f", f));
	return j;
}

RZ_API PJ *pj_d(PJ *j, double d) {
	rz_return_val_if_fail (j, NULL);
	pj_comma (j);
	pj_raw (j, sdb_fmt ("%lf", d));
	return j;
}

RZ_API PJ *pj_i(PJ *j, int i) {
	if (j) {
		pj_comma (j);
		pj_raw (j, sdb_fmt ("%d", i));
	}
	return j;
}

RZ_API char *pj_fmt(PrintfCallback p, const char *fmt, ...) {
	va_list ap;
	va_start (ap, fmt);

	char ch[2] = { 0 };
	PJ *j = pj_new ();
	while (*fmt) {
		j->is_first = true;
		ch[0] = *fmt;
		switch (*fmt) {
		case '\\':
			fmt++;
			switch (*fmt) {
			// TODO: add \x, and \e
			case 'e':
				pj_raw (j, "\x1b");
				break;
			case 'r':
				pj_raw (j, "\r");
				break;
			case 'n':
				pj_raw (j, "\n");
				break;
			case 'b':
				pj_raw (j, "\b");
				break;
			}
			break;
		case '\'':
			pj_raw (j, "\"");
			break;
		case '%':
			fmt++;
			switch (*fmt) {
			case 'b':
				pj_b (j, va_arg (ap, int));
				break;
			case 's':
				pj_s (j, va_arg (ap, const char *));
				break;
			case 'S': {
				const char *s = va_arg (ap, const char *);
				char *es = rz_base64_encode_dyn (s, -1);
				pj_s (j, es);
				free (es);
			} break;
			case 'n':
				pj_n (j, va_arg (ap, ut64));
				break;
			case 'd':
				pj_d (j, va_arg (ap, double));
				break;
			case 'i':
				pj_i (j, va_arg (ap, int));
				break;
			default:
				eprintf ("Invalid format\n");
				break;
			}
			break;
		default:
			ch[0] = *fmt;
			pj_raw (j, ch);
			break;
		}
		fmt++;
	}
	char *ret = NULL;
	if (p) {
		p ("%s", rz_strbuf_get (&j->sb));
		pj_free (j);
	} else {
		ret = pj_drain (j);
	}
	va_end (ap);
	return ret;
}
