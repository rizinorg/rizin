// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <rz_asm.h>

RZ_API RzAsmCode *rz_asm_code_new(void) {
	return RZ_NEW0(RzAsmCode);
}

RZ_API void *rz_asm_code_free(RzAsmCode *acode) {
	if (acode) {
		rz_list_free(acode->equs);
		free(acode->bytes);
		free(acode->assembly);
		free(acode);
	}
	return NULL;
}

RZ_API void rz_asm_equ_item_free(RzAsmEqu *equ) {
	if (equ) {
		free(equ->key);
		free(equ->value);
		free(equ);
	}
}

static RzAsmEqu *__asm_equ_new(const char *key, const char *value) {
	RzAsmEqu *equ = RZ_NEW0(RzAsmEqu);
	if (equ) {
		equ->key = rz_str_dup(key);
		equ->value = rz_str_dup(value);
	}
	return equ;
}

RZ_API bool rz_asm_code_set_equ(RzAsmCode *code, const char *key, const char *value) {
	rz_return_val_if_fail(code && key && value, false);

	if (code->equs) {
		RzAsmEqu *equ;
		RzListIter *iter;
		rz_list_foreach (code->equs, iter, equ) {
			if (!strcmp(equ->key, key)) {
				free(equ->value);
				equ->value = rz_str_dup(value);
				return true;
			}
		}
	} else {
		code->equs = rz_list_newf((RzListFree)rz_asm_equ_item_free);
	}
	rz_list_append(code->equs, __asm_equ_new(key, value));
	return true;
}

RZ_API char *rz_asm_code_equ_replace(RzAsmCode *code, char *str) {
	rz_return_val_if_fail(code && str, NULL);
	RzAsmEqu *equ;
	RzListIter *iter;
	rz_list_foreach (code->equs, iter, equ) {
		str = rz_str_replace(str, equ->key, equ->value, true);
	}
	return str;
}

RZ_API char *rz_asm_code_get_hex(RzAsmCode *acode) {
	rz_return_val_if_fail(acode, NULL);
	char *str = calloc(acode->len + 1, 2);
	if (str) {
		rz_hex_bin2str(acode->bytes, acode->len, str);
	}
	return str;
}