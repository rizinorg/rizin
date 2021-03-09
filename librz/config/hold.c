// SPDX-FileCopyrightText: 2006-2021 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_config.h>

static void rz_config_hold_char_free(RzConfigHoldChar *hc) {
	free(hc->key);
	free(hc->value);
	free(hc);
}

static void rz_config_hold_num_free(RzConfigHoldNum *hc) {
	free(hc->key);
	free(hc);
}

static int key_cmp_hold_s(const void *a, const void *b) {
	const char *a_s = (const char *)a;
	const RzConfigHoldChar *b_s = (const RzConfigHoldChar *)b;
	return strcmp(a_s, b_s->key);
}

static int key_cmp_hold_i(const void *a, const void *b) {
	const char *a_s = (const char *)a;
	const RzConfigHoldNum *b_s = (const RzConfigHoldNum *)b;
	return strcmp(a_s, b_s->key);
}

RZ_API bool rz_config_hold_s(RzConfigHold *h, ...) {
	va_list ap;
	char *key;
	va_start(ap, h);
	if (!h->list_char) {
		h->list_char = rz_list_newf((RzListFree)rz_config_hold_char_free);
		if (!h->list_char) {
			va_end(ap);
			return false;
		}
	}
	while ((key = va_arg(ap, char *))) {
		if (rz_list_find(h->list_char, key, key_cmp_hold_s)) {
			continue;
		}
		const char *val = rz_config_get(h->cfg, key);
		if (!val) {
			continue;
		}
		RzConfigHoldChar *hc = RZ_NEW0(RzConfigHoldChar);
		if (hc) {
			hc->key = strdup(key);
			hc->value = strdup(val);
			rz_list_append(h->list_char, hc);
		}
	}
	va_end(ap);
	return true;
}

RZ_API bool rz_config_hold_i(RzConfigHold *h, ...) {
	va_list ap;
	char *key;
	if (!h) {
		return false;
	}
	if (!h->list_num) {
		h->list_num = rz_list_newf((RzListFree)rz_config_hold_num_free);
		if (!h->list_num) {
			return false;
		}
	}
	va_start(ap, h);
	while ((key = va_arg(ap, char *))) {
		if (rz_list_find(h->list_num, key, key_cmp_hold_i)) {
			continue;
		}
		RzConfigHoldNum *hc = RZ_NEW0(RzConfigHoldNum);
		if (!hc) {
			continue;
		}
		hc->key = strdup(key);
		hc->value = rz_config_get_i(h->cfg, key);
		rz_list_append(h->list_num, hc);
	}
	va_end(ap);
	return true;
}

RZ_API RzConfigHold *rz_config_hold_new(RzConfig *cfg) {
	if (cfg) {
		RzConfigHold *hold = RZ_NEW0(RzConfigHold);
		if (hold) {
			hold->cfg = cfg;
			return hold;
		}
	}
	return NULL;
}

RZ_API void rz_config_hold_restore(RzConfigHold *h) {
	RzListIter *iter;
	RzConfigHoldChar *hchar;
	RzConfigHoldNum *hnum;
	if (h) {
		RzConfig *cfg = h->cfg;
		rz_list_foreach (h->list_num, iter, hnum) {
			(void)rz_config_set_i(cfg, hnum->key, hnum->value);
		}
		rz_list_foreach (h->list_char, iter, hchar) {
			(void)rz_config_set(cfg, hchar->key, hchar->value);
		}
	}
}

RZ_API void rz_config_hold_free(RzConfigHold *h) {
	if (h) {
		rz_list_free(h->list_num);
		rz_list_free(h->list_char);
		RZ_FREE(h);
	}
}
