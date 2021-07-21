// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2021 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include "dex.h"

static bool dex_parse(RzBinDex *dex, ut64 base, RzBuffer *buf) {
	ut64 offset = 0;
	st64 buffer_size = rz_buf_size(buf);
	if (buffer_size < 116) {
		// 116 bytes is the smalled dex that can be built.
		RZ_LOG_ERROR("dex bin: invalid buffer size (size < 116)\n");
		goto dex_parse_bad;
	}

	rz_buf_read(buf, dex->magic, sizeof(dex->magic));

	return true;

dex_parse_bad:
	rz_bin_dex_free(dex);
	return false;
}

RZ_API void rz_bin_dex_free(RzBinDex *dex) {
	if (!dex) {
		return;
	}


	free(dex);
}

RZ_API RzBinDex *rz_bin_dex_new(RzBuffer *buf, ut64 base, Sdb *kv) {
	rz_return_val_if_fail(buf, NULL);

	RzBinDex *dex = (RzBinDex *)RZ_NEW0(RzBinDex);
	if (!dex || !dex_parse(dex, base, buf)) {
		return NULL;
	}

	return dex;
} 
