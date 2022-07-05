// SPDX-FileCopyrightText: 2011-2016 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: MIT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rz_util/rz_base64.h>
#include "sdb.h"

RZ_API void sdb_encode_raw(char *bout, const ut8 *bin, int len) {
	rz_base64_encode(bout, bin, len);
}

RZ_API int sdb_decode_raw(ut8 *bout, const char *bin, int len) {
	return rz_base64_decode(bout, bin, len);
}

RZ_API char *sdb_encode(const ut8 *bin, int len) {
	char *out;
	if (!bin) {
		return NULL;
	}
	if (len < 0) {
		len = strlen((const char *)bin);
	}
	if (!len) {
		return strdup("");
	}
	out = calloc(8 + (len * 2), sizeof(char));
	if (!out) {
		return NULL;
	}
	sdb_encode_raw(out, bin, len);
	return out;
}

RZ_API ut8 *sdb_decode(const char *in, int *len) {
	ut8 *out;
	ut32 size;
	int olen, ilen;
	if (len) {
		*len = 0;
	}
	if (!in) {
		return NULL;
	}
	ilen = strlen(in);
	if (!ilen) {
		return NULL;
	}
	size = (ilen * 3) + 16;
	if (size < (ut32)ilen) {
		return NULL;
	}
	out = calloc(1, size);
	if (!out) {
		return NULL;
	}
	olen = sdb_decode_raw(out, in, ilen);
	if (!olen) {
		free(out);
		return NULL;
	}
	out[olen] = 0;
	if (len) {
		*len = olen;
	}
	return out;
}
